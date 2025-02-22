import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
import joblib
import random
import string
import re
import math

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

# Define function to extract password features with enhanced features
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
    }

    # Proportion of digits
    num_digits = sum(1 for c in password if c.isdigit())
    features["digit_ratio"] = num_digits / len(password) if password else 0

    # Unique character ratio
    features["unique_ratio"] = len(set(password)) / len(password) if password else 0

    return features

# Extract features for all passwords
df = pd.DataFrame([password_features(pw) for pw in data])

# Breached status: 1 for weak (breached), 0 for medium/strong
df["hibp_breached"] = [1 if label == 0 else 0 for label in labels]

# Add labels to the DataFrame
df["label"] = labels

# Prepare features (X) and target (y) for training
X = df.drop("label", axis=1)
y = df["label"]

# Initialize and evaluate the Random Forest Classifier with tuned parameters
model = RandomForestClassifier(
    n_estimators=150,
    max_depth=20,              # Limit depth to prevent overfitting
    min_samples_split=5,       # Require at least 5 samples to split
    random_state=42
)
scores = cross_val_score(model, X, y, cv=5)
print(f"Model accuracy: {scores.mean():.2%} (+/- {scores.std() * 2:.2%})")

# Train the model on the dataset and save it
model.fit(X, y)
joblib.dump(model, "password_health_model.pkl")
print("Model saved as 'password_health_model.pkl'")