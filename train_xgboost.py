import pandas as pd
from xgboost import XGBClassifier  # Switched to XGBoost
from sklearn.model_selection import cross_val_score
from sklearn.preprocessing import PolynomialFeatures
import joblib
import random
import string
import re
import math
import zlib
from collections import Counter

# Load passwords from RockYou.txt
with open("rockyou.txt", "r", encoding="utf-8", errors="ignore") as f:
    rockyou_passwords = [line.strip() for line in f]

# 100,000 weak passwords from RockYou.txt
weak_passwords = random.sample(rockyou_passwords, 100000)

# Generate 100,000 medium passwords: 8 characters, letters and digits
medium_passwords = [
    ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    for _ in range(100000)
]

# Generate 100,000 strong passwords: 12 characters, letters, digits, and symbols
strong_passwords = [
    ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=12))
    for _ in range(100000)
]

# Combine all passwords and assign labels: 0 (weak), 1 (medium), 2 (strong)
data = weak_passwords + medium_passwords + strong_passwords
labels = [0] * 100000 + [1] * 100000 + [2] * 100000


# Define function to extract password features with complex math
def password_features(password: str) -> dict:
    """
    Extracts features from a password for strength classification, including complex math.

    Args:
        password (str): The password to analyze.

    Returns:
        dict: A dictionary with enhanced password features.
    """
    # Basic features (unchanged)
    features = {
        "length": len(password),
        "entropy": math.log2(len(set(password)) ** len(password)) if password else 0,
        "has_upper": int(bool(re.search(r"[A-Z]", password))),
        "has_symbol": int(bool(re.search(r"[^A-Za-z0-9]", password))),
        "has_leet": int(any(c in "@3!0" for c in password)),
        "repetition": int(bool(re.search(r"(.)\1{2,}", password))),
    }

    # N-gram Shannon Entropy (bigrams)
    if len(password) >= 2:
        bigrams = [password[i:i + 2] for i in range(len(password) - 1)]
        bigram_counts = Counter(bigrams)
        total_bigrams = sum(bigram_counts.values())
        bigram_entropy = -sum((count / total_bigrams) * math.log2(count / total_bigrams)
                              for count in bigram_counts.values())
    else:
        bigram_entropy = 0
    features["bigram_entropy"] = bigram_entropy

    # Compression Complexity (Kolmogorov approximation)
    compressed_len = len(zlib.compress(password.encode()))
    features["compression_ratio"] = compressed_len / len(password) if password else 1.0

    return features


# Extract features for all passwords
df = pd.DataFrame([password_features(pw) for pw in data])

# Add a feature for breached status: 1 for weak (breached), 0 for medium/strong
df["hibp_breached"] = [1 if label == 0 else 0 for label in labels]

# Add labels to the DataFrame
df["label"] = labels

# Prepare features (X) and target (y) for training
X = df.drop("label", axis=1)

# Add polynomial feature interactions
poly = PolynomialFeatures(degree=2, interaction_only=True, include_bias=False)
X_poly = poly.fit_transform(X)

# Initialize and evaluate the XGBoost Classifier
model = XGBClassifier(n_estimators=100, random_state=42, use_label_encoder=False, eval_metric='mlogloss')
scores = cross_val_score(model, X_poly, y, cv=5)
print(f"Model accuracy: {scores.mean():.2%} (+/- {scores.std() * 2:.2%})")

# Train the model on the full dataset and save it
model.fit(X_poly, y)
joblib.dump(model, "password_health_model.pkl")
print("Model saved as 'password_health_model.pkl'")