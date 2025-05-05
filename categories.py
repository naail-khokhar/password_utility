# Maps known website names to user-friendly categories for vault entries.
# Uses LLM via OpenRouter API for unknown sites if a URL is provided.

import requests
import json
import logging
import os
from breach_utils import load_api_keys 

logger = logging.getLogger(__name__)

# Load API keys once when the module is imported
API_KEYS = load_api_keys()
OPENROUTER_API_KEY = API_KEYS.get('OPENROUTER_API_KEY')

# Dictionary mapping website names to their organizational categories
# Used to group similar services together in the vault display
WEBSITE_CATEGORIES = {
    # Social Networking
    "Facebook": "Social Networking",
    "Twitter": "Social Networking",
    "Instagram": "Social Networking",
    "LinkedIn": "Social Networking",
    "Reddit": "Social Networking",
    "X": "Social Networking",
    "Bluesky": "Social Networking",
    "TikTok": "Social Networking",
    "Discord": "Social Networking",

    # Entertainment
    "YouTube": "Entertainment",
    "Spotify": "Entertainment",
    "Netflix": "Entertainment",
    "Disney": "Entertainment",
    "Twitch": "Entertainment",

    # Shopping
    "Amazon": "Shopping",
    "eBay": "Shopping",
    "Alibaba": "Shopping",
    "Etsy": "Shopping",

    # Banking
    "PayPal": "Banking",
    "Chase": "Banking",
    "HSBC": "Banking",
    "Barclays": "Banking",
    "HL": "Banking",
    "Schwab": "Banking",
    
    # Productivity
    "Microsoft": "Productivity",
    "Google": "Productivity",
    "Zoom": "Productivity",
    "Slack": "Productivity",
    "Dropbox": "Productivity",
    "Shopify": "Productivity",
    "GitHub": "Productivity",
    "Yahoo": "Productivity",
    "Notion": "Productivity",
    "Trello": "Productivity",
    "Canva": "Productivity",

    # Default catch‑all for unmapped sites
    "Other": "Other"
}

# Dictionary mapping site names to their URLs
# Used to auto-populate the URL field when adding a known site
SITE_URLS = {
    "Google": "google.com",
    "Yahoo": "yahoo.com",
    "X": "x.com",
    "Facebook": "facebook.com",
    "Instagram": "instagram.com",
    "LinkedIn": "linkedin.com",
    "Reddit": "reddit.com",
    "Bluesky": "bsky.app",
    "TikTok": "tiktok.com",
    "YouTube": "youtube.com",
    "Spotify": "spotify.com",
    "Netflix": "netflix.com",
    "Disney": "disneyplus.com",
    "Twitch": "twitch.tv",
    "Amazon": "amazon.com",
    "eBay": "ebay.com",
    "Alibaba": "alibaba.com",
    "Etsy": "etsy.com",
    "PayPal": "paypal.com",
    "Chase": "chase.com",
    "HSBC": "hsbc.com",
    "Barclays": "barclays.com",
    "HL": "hl.co.uk",
    "Schwab": "schwab.com",
    "Microsoft": "microsoft.com",
    "Zoom": "zoom.us",
    "Slack": "slack.com",
    "Dropbox": "dropbox.com",
    "Discord": "discord.com",
    "Shopify": "shopify.com",
    "GitHub": "github.com",
    "Notion": "notion.com",
    "Trello": "trello.com",
    "Canva": "canva.com",
}

def get_category(website, url=None):
    """
    Returns a category label for a given website name.
    Uses LLM classification for unknown sites if a URL is provided and API key is available.
    """
    # Handle special cases for API and WiFi.
    if website.startswith("API"):
        return "APIs"
    if website == "WiFi":
        return "WiFi" # Explicitly handle WiFi

    # Check predefined categories.
    category = WEBSITE_CATEGORIES.get(website)
    if category:
        return category

    # If unknown and URL is provided, try LLM classification.
    if url and OPENROUTER_API_KEY:
        try:
            logger.debug(f"Classifying URL via LLM: {url}")
            response = requests.post(
                url="https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                    "Content-Type": "application/json",
                },
                data=json.dumps({
                    "model": "qwen/qwen-2.5-7b-instruct:free",
                    "messages": [{
                        "role": "user",
                        "content": f"Classify the website \"{url}\" into one of these exact categories: Social Networking, Banking, Entertainment, Shopping, Productivity, Other. Respond with only the category name."
                    }]
                }),
                timeout=10 # Add a timeout
            )
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            
            reply = response.json()["choices"][0]["message"]["content"].strip()
            logger.debug(f"LLM classification result for {url}: {reply}")

            # Check if the reply matches one of the predefined categories (case-insensitive)
            valid_categories = ["Social Networking", "Banking", "Entertainment", "Shopping", "Productivity", "Other"]
            for cat in valid_categories:
                if cat.lower() == reply.lower():
                    return cat # Return the correctly capitalized category name
            
            # Fallback if LLM response is not a valid category
            logger.warning(f"LLM response '{reply}' not a valid category for URL {url}. Defaulting to Other.")
            return "Other"

        except requests.exceptions.RequestException as e:
            logger.error(f"API call failed for URL {url}: {e}")
            return "Other"
        except (KeyError, IndexError, json.JSONDecodeError) as e:
            logger.error(f"Failed to parse LLM response for URL {url}: {e}")
            return "Other"
            
    elif url and not OPENROUTER_API_KEY:
        logger.warning("OPENROUTER_API_KEY not found in api_keys.txt. Cannot classify unknown site via LLM.")
        return "Other"
         
    # Default for unknown sites without URL or if API key is missing.
    return "Other"

def get_url(website):
    """
    Returns the default URL for a given website name.
    """
    return SITE_URLS.get(website, "")