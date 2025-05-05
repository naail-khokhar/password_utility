import pandas as pd
from xgboost import XGBClassifier
from sklearn.model_selection import cross_val_score
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

# Sample 100,000 weak, medium, and strong passwords
weak_passwords = random.sample(rockyou_passwords, 100000)
medium_passwords = [
    ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    for _ in range(100000)
]
strong_passwords = [
    ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=12))
    for _ in range(100000)
]

# Combine passwords and assign labels: 0 (weak), 1 (medium), 2 (strong)
data = weak_passwords + medium_passwords + strong_passwords
labels = [0] * 100000 + [1] * 100000 + [2] * 100000

# Define function to extract password features
def password_features(password: str) -> dict:
    """
    Extracts features from a password for strength classification.

    Args:
        password (str): The password to analyze.

    Returns:
        dict: A dictionary with password features.
    """
    features = {
        "length": len(password),
        "entropy": math.log2(len(set(password)) ** len(password)) if password else 0,
        "has_upper": int(bool(re.search(r"[A-Z]", password))),
        "has_symbol": int(bool(re.search(r"[^A-Za-z0-9]", password))),
        "has_leet": int(any(c in "@3!0" for c in password)),
        "repetition": int(bool(re.search(r"(.)\1{2,}", password))),
        "digit_ratio": sum(c.isdigit() for c in password) / len(password) if password else 0,
        "unique_ratio": len(set(password)) / len(password) if password else 0
    }

    # Bigram Shannon Entropy
    if len(password) >= 2:
        bigrams = [password[i:i+2] for i in range(len(password)-1)]
        bigram_counts = Counter(bigrams)
        total_bigrams = sum(bigram_counts.values())
        features["bigram_entropy"] = -sum(
            (count / total_bigrams) * math.log2(count / total_bigrams)
            for count in bigram_counts.values()
        ) if total_bigrams > 0 else 0
    else:
        features["bigram_entropy"] = 0

    # Compression Ratio (Kolmogorov approximation)
    features["compression_ratio"] = len(zlib.compress(password.encode())) / len(password) if password else 1.0

    return features

# Extract features for all passwords
df = pd.DataFrame([password_features(pw) for pw in data])

# Add breached status: 1 for weak, 0 for medium/strong
df["hibp_breached"] = [1 if label == 0 else 0 for label in labels]
df["label"] = labels

# Prepare features (X) and target (y)
X = df.drop("label", axis=1)
y = df["label"]

# Initialize and evaluate XGBoost Classifier
model = XGBClassifier(
    n_estimators=100,
    max_depth=6,
    learning_rate=0.1,
    random_state=42,
    eval_metric='mlogloss'
)
scores = cross_val_score(model, X, y, cv=5)
print(f"Model accuracy: {scores.mean():.2%} (+/- {scores.std() * 2:.2%})")

# Train and save the model
model.fit(X, y)
joblib.dump(model, "xgboost_model.pkl")
print("Model saved as 'xgboost_model.pkl'")