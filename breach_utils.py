# Utilities for retrieving, caching, and summarizing data breach news
# - Caches breach summaries in SQLite to limit API calls
# - Uses NewsAPI to fetch relevant articles
# - Summarizes articles via OpenRouter AI, stripping extraneous headings

import sqlite3
import datetime
import requests
import json
import logging
import os
from newsapi import NewsApiClient

logger = logging.getLogger(__name__)

# Database filename and cache settings
BREACHES_DB = "breaches.db"
CACHE_DURATION_DAYS = 7  # How long breach data remains valid before refreshing
NEWS_SEARCH_DAYS = 30    # How far back to search for breach news
MAX_BREACH_RESULTS = 5   # Limit results to avoid overwhelming the user

def load_api_keys():
    # Read API keys (NEWS_API_KEY, OPENROUTER_API_KEY) from api_keys.txt
    # This allows keys to be kept out of version control for security
    keys = {
        'NEWS_API_KEY': None,
        'OPENROUTER_API_KEY': None
    }
    
    try:
        keys_file = os.path.join(os.path.dirname(__file__), 'api_keys.txt')
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        if key in keys:
                            keys[key] = value
        else:
            logger.warning(f"Keys file not found: {keys_file}")
    except Exception as e:
        logger.error(f"Error loading API keys: {e}")
    
    return keys

API_KEYS = load_api_keys()
NEWS_API_KEY = API_KEYS.get('NEWS_API_KEY')
OPENROUTER_API_KEY = API_KEYS.get('OPENROUTER_API_KEY')

def init_breach_db():
    # Create the breach_data table and index if missing
    # This ensures the database is ready for use without manual setup
    try:
        with sqlite3.connect(BREACHES_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS breach_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                news_link TEXT UNIQUE NOT NULL,
                summary TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_site ON breach_data (site)")
            conn.commit()
            logger.info("Breaches database initialized successfully.")
    except sqlite3.Error as e:
        logger.error(f"Database error during init: {e}")

def clean_old_breaches():
    # Remove cached entries older than CACHE_DURATION_DAYS to keep data fresh
    cutoff_date = datetime.datetime.now() - datetime.timedelta(days=CACHE_DURATION_DAYS)
    try:
        with sqlite3.connect(BREACHES_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM breach_data WHERE created_at < ?", (cutoff_date,))
            conn.commit()
            logger.info(f"Cleaned {cursor.rowcount} old breach entries older than {cutoff_date.date()}.")
    except sqlite3.Error as e:
        logger.error(f"Database error during cleanup: {e}")

def get_cached_breach(site):
    # Return the latest breach summary for a site if still within cache window
    # Avoids unnecessary API calls when data is fresh enough
    try:
        with sqlite3.connect(BREACHES_DB) as conn:
            cursor = conn.cursor()
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=CACHE_DURATION_DAYS)
            cursor.execute(
                """SELECT news_link, summary, created_at FROM breach_data
                   WHERE site = ? AND created_at >= ?
                   ORDER BY created_at DESC LIMIT 1""",
                (site, cutoff_date)
            )
            result = cursor.fetchone()
        if result:
            logger.debug(f"Cache hit for site: {site}")
            return {
                "site": site,
                "news_link": result[0],
                "summary": result[1],
                "created_at": result[2]
            }
        else:
            logger.debug(f"Cache miss for site: {site}")
            return None
    except sqlite3.Error as e:
        logger.error(f"Database error getting cache for {site}: {e}")
        return None

def cache_breach(site, news_link, summary):
    # Insert or update breach summary in the local cache
    # Uses INSERT OR REPLACE to upsert data, avoiding duplicates
    try:
        with sqlite3.connect(BREACHES_DB) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO breach_data (site, news_link, summary, created_at) VALUES (?, ?, ?, ?)",
                (site, news_link, summary, datetime.datetime.now())
            )
            conn.commit()
            logger.info(f"Cached breach info for site: {site}")
            return True
    except sqlite3.Error as e:
        logger.error(f"Database error caching breach for {site}: {e}")
        return False

def fetch_breach_news(site):
    # Query NewsAPI for articles about a breach at the specified site
    # Constructs a complex query to find relevant breach articles
    if not NEWS_API_KEY:
        logger.warning("NewsAPI key not configured. Check api_keys.txt file.")
        return None
        
    try:
        newsapi = NewsApiClient(api_key=NEWS_API_KEY)
        # Build a query that looks for the site name AND breach-related terms
        # This helps filter out unrelated news about the company
        query = f'("{site}" OR "{site.lower()}") AND ("data breach" OR "hack" OR "security incident" OR "data leak" OR "compromise" OR "cyberattack" OR "exposed")'
        from_date = (datetime.datetime.now() - datetime.timedelta(days=NEWS_SEARCH_DAYS)).strftime('%Y-%m-%d')

        logger.debug(f"Fetching news for '{site}' with query: '{query}' from {from_date}")
        articles = newsapi.get_everything(
            q=query,
            language='en',
            sort_by='relevancy',
            page_size=3,
            from_param=from_date
        )

        if articles['status'] == 'ok' and articles['totalResults'] > 0:
            logger.info(f"Found {articles['totalResults']} articles for {site}")
            return articles['articles'][0]
        else:
            logger.debug(f"No relevant articles found for {site}. Status: {articles.get('status', 'N/A')}")
            return None
    except Exception as e:
        logger.error(f"NewsAPI error for site '{site}': {e}")
        return None

def fetch_breach_news_multi(site_list=None, max_results=MAX_BREACH_RESULTS):
    # Fetch breach news for multiple or general queries via NewsAPI
    # Can be used for specific sites or general breach news scanning
    if not NEWS_API_KEY:
        logger.warning("NewsAPI key not configured. Check api_keys.txt file.")
        return []
        
    try:
        newsapi = NewsApiClient(api_key=NEWS_API_KEY)
        from_date = (datetime.datetime.now() - datetime.timedelta(days=NEWS_SEARCH_DAYS)).strftime('%Y-%m-%d')
        
        if site_list and len(site_list) > 0:
            # For specific sites, build an OR query of site names combined with breach terms
            site_terms = ' OR '.join([f'"{site}"' for site in site_list])
            query = f'({site_terms}) AND ("data breach" OR "hack" OR "security incident" OR "data leak" OR "compromise" OR "cyberattack")'
        else:
            # For general news, use a broader query focused on personal data compromises
            query = '("data breach" OR "security breach" OR "hack" OR "cyber attack" OR "data leak" OR "compromised data") AND (user OR password OR account OR data OR information OR customer OR personal)'
            
        logger.debug(f"Fetching news with query: '{query}' from {from_date}")
        
        articles = newsapi.get_everything(
            q=query,
            language='en',
            sort_by='publishedAt',
            page_size=max_results,
            from_param=from_date
        )

        if articles['status'] == 'ok' and articles['totalResults'] > 0:
            logger.info(f"Found {articles['totalResults']} breach articles, returning up to {max_results}")
            return articles['articles'][:max_results]
        else:
            logger.debug(f"No relevant breach articles found. Status: {articles.get('status', 'N/A')}")
            return []
    except Exception as e:
        logger.error(f"NewsAPI error for general breaches: {e}")
        return []

def summarize_breach_article(article, site):
    # Use OpenRouter to generate a concise summary of a breach article
    # Creates a tightly focused, factual summary without generic headings/intros
    if not article or not article.get('url'):
        return None
    if not OPENROUTER_API_KEY:
        logger.warning("OpenRouter API key not configured. Check api_keys.txt file.")
        return None

    # Combine article title, description, and content for context
    # Limiting to 1500 chars to stay within token limits while providing enough context
    content_to_summarize = f"Title: {article.get('title', '')}\nDescription: {article.get('description', '')}\nContent Snippet: {article.get('content', '')}"
    prompt = f"""Create a brief summary about a security incident or data breach affecting {site}. 
DO NOT start with phrases like "Summary:" or "{site} breach:".
Start directly with the facts of what happened. Keep it concise and factual.

Article Snippet:
---
{content_to_summarize[:1500]}
---"""

    try:
        logger.debug(f"Requesting summary for '{site}' article: {article['url']}")
        response = requests.post(
            url="https://openrouter.ai/api/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5000",
                "X-Title": "Password Utility",
            },
            data=json.dumps({
                "model": "deepseek/deepseek-chat-v3-0324:free",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 100,
                "temperature": 0.5,  # Lower temperature for more factual, less creative output
            }),
            timeout=20  # Timeout after 20 seconds to prevent UI hanging
        )
        response.raise_for_status()

        result = response.json()
        if result.get('choices') and len(result['choices']) > 0:
            summary = result['choices'][0]['message']['content'].strip()
            
            # Several post-processing steps to clean up AI-generated text patterns
            # 1. Remove common header patterns with colons
            if ':' in summary and len(summary.split(':')[0].split()) < 5:
                summary = summary.split(':', 1)[1].strip()
            
            prefixes = ['summary', 'breach alert', 'data breach', 'security incident', 'breach notification']
            lower_summary = summary.lower()
            
            # 2. Remove standardized prefixes that the AI might still include
            for prefix in prefixes:
                if lower_summary.startswith(prefix):
                    summary = summary[len(prefix):].strip()
                    if summary and summary[0] in ':-—':
                        summary = summary[1:].strip()
            
            logger.debug(f"Summary received for '{site}': {summary}")
            return summary
        else:
            logger.warning(f"No summary content received from OpenRouter for '{site}'. Response: {result}")
            return "Could not generate summary."

    except requests.exceptions.RequestException as e:
        # Detailed error logging to help diagnose API connection issues
        # Especially useful for rate limits which require special handling
        logger.error(f"OpenRouter API request error for '{site}': {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"OpenRouter Response Status: {e.response.status_code}")
            logger.error(f"OpenRouter Response Body: {e.response.text}")
            if e.response.status_code == 429:
                logger.warning("OpenRouter rate limit likely exceeded.")
                return "Summary generation rate limited. Try again later."
        return "Error connecting to summarization service."
    except Exception as e:
        logger.error(f"Unexpected error summarizing article for '{site}': {e}")
        return "Unexpected error during summarization."

def process_breach_articles(articles, site_list=None):
    # Associate fetched articles with sites, clean up prefixes, cache summaries
    # Performs extensive text cleanup to provide consistent summaries
    if not articles or len(articles) == 0:
        return []
        
    results = []
    for article in articles:
        # Determine which site the article is about, either from provided list or infer from content
        if site_list:
            # Match article to a site if site_list is provided
            article_text = f"{article.get('title', '')} {article.get('description', '')}"
            matched_site = None
            for site in site_list:
                if site.lower() in article_text.lower():
                    matched_site = site
                    break
                    
            if not matched_site:
                continue
            site = matched_site
        else:
            # Try to extract a company name from the article title
            # Heuristic: first capitalized word over 3 letters that isn't a common term
            title_words = article.get('title', 'Unknown Site').split()
            site = next((word for word in title_words if word[0].isupper() and len(word) > 3 and word.lower() not in 
                        ['data', 'breach', 'hack', 'security', 'incident', 'report', 'breaking']), "Unknown Site")
        
        summary = summarize_breach_article(article, site)
        
        if summary:
            # Multiple cleanup passes to handle various formatting issues in AI output
            # Remove repeated colons and formatting artifacts
            while ':' in summary and summary.split(':')[0].strip().split() < 6:
                summary = summary.split(':', 1)[1].strip()
                
            for title_prefix in ['title:', 'headline:', 'breaking:']:
                if summary.lower().startswith(title_prefix):
                    summary = summary[len(title_prefix):].strip()
            
            summary = summary.replace('#', '').strip()
            
            # Remove bullet points sometimes added by the AI
            if summary.startswith('•') or summary.startswith('- ') or summary.startswith('* '):
                summary = summary[2:].strip()
            
            results.append({
                "site": site,
                "news_link": article['url'],
                "summary": summary,
                "created_at": article.get('publishedAt', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            })
            cache_breach(site, article['url'], summary)
            
    return results

def get_user_sites_breaches(user_sites):
    # Return cached or fresh breach info for the user's stored sites
    # Tries cache first, then fetches only what's needed to minimize API usage
    if not user_sites or len(user_sites) == 0:
        return []
        
    cached_breaches = []
    sites_to_check = []
    
    # First check cache for all sites to avoid unnecessary API calls
    for site in user_sites:
        cached = get_cached_breach(site)
        if cached:
            cached_breaches.append(cached)
        else:
            sites_to_check.append(site)
    
    # Only make API calls for sites not found in cache
    if sites_to_check:
        fresh_articles = fetch_breach_news_multi(sites_to_check)
        if fresh_articles:
            processed_fresh = process_breach_articles(fresh_articles, sites_to_check)
            cached_breaches.extend(processed_fresh)
    
    return cached_breaches

def get_general_breaches(exclude_sites=None):
    # Fetch general breach news not tied to stored sites
    # Used for general awareness of recent security incidents
    articles = fetch_breach_news_multi(None)
    if articles:
        return process_breach_articles(articles)
    return []

def get_site_breach_info(site):
    # Orchestrate cache cleanup, cache retrieval, fetch, summarize, and caching
    # Single entry point for fetching breach data about a specific site
    clean_old_breaches()

    cached_info = get_cached_breach(site)
    if cached_info:
        return cached_info

    logger.info(f"No recent cache for {site}. Fetching fresh data.")
    article = fetch_breach_news(site)

    if article and article.get('url'):
        summary = summarize_breach_article(article, site)
        if summary:
            news_link = article['url']
            cache_breach(site, news_link, summary)
            return {
                "site": site,
                "news_link": news_link,
                "summary": summary,
                "created_at": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        else:
            logger.warning(f"Failed to get summary for {site} article: {article.get('url')}")
            return None
    else:
        logger.info(f"No relevant news found for {site} in the last {NEWS_SEARCH_DAYS} days.")
        return None

