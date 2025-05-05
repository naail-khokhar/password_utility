# Script to train and save the password health model.
# Loads labeled password dataset, extracts features, trains a RandomForest classifier, and saves the model.

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib
import random
import string
import re
import math
import zlib
from collections import Counter

# Load the weak password list into memory for training data.
with open("weak_passwords.txt", "r", encoding="utf-8", errors="ignore") as f:
    rockyou_passwords = [line.strip() for line in f]

# Generate weak, medium, and strong password samples for training.
# Weak: real breached passwords; Medium/Strong: synthetic passwords with varying complexity.

# 100,000 weak passwords from weak_passwords.txt
weak_passwords = random.sample(rockyou_passwords, 100000)

# Generate 100,000 medium passwords: random length between 8–12, letters, digits, and occasionally symbols
# Medium passwords have 20% chance of including symbols, similar to average user-created passwords
medium_passwords = []
for _ in range(100000):
    length = random.randint(8, 12)
    if random.random() < 0.2:
        allowed_chars = string.ascii_letters + string.digits + "!@#$%"
    else:
        allowed_chars = string.ascii_letters + string.digits
    medium_passwords.append(''.join(random.choices(allowed_chars, k=length)))

# Generate 100,000 strong passwords: random length between 12–16, letters, digits, and symbols
# Strong passwords use longer lengths and always include special characters for maximum entropy
strong_passwords = [
    ''.join(random.choices(string.ascii_letters + string.digits + "!@#$%", k=random.randint(12,16)))
    for _ in range(100000)
]

# Combine all passwords and assign labels: 0 (weak), 1 (medium), 2 (strong)
data = weak_passwords + medium_passwords + strong_passwords
labels = [0] * 100000 + [1] * 100000 + [2] * 100000

# Define function to extract password features for ML classification.
def password_features(password: str) -> dict:
    """
    Extracts features from a password for strength classification.
    Returns a dictionary with password features.
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

    # Bigram entropy
    if len(password) >= 2:
        bigrams = [password[i:i+2] for i in range(len(password)-1)]
        bigram_counts = Counter(bigrams)
        total_bigrams = sum(bigram_counts.values())
        features["bigram_entropy"] = -sum(
            (count / total_bigrams) * math.log2(count / total_bigrams)
            for count in bigram_counts.values()
        ) if total_bigrams else 0
    else:
        features["bigram_entropy"] = 0

    # Compression ratio
    features["compression_ratio"] = (
        len(zlib.compress(password.encode())) / len(password)
        if password else 1.0
    )

    return features

# Extract features for all passwords and build the DataFrame.
# Creates a feature matrix of 300,000 rows × 10 columns for model training
df = pd.DataFrame([password_features(pw) for pw in data])

# Add breached status and labels to the DataFrame.
# All passwords from the weak list are compromised
df["hibp_breached"] = [1 if label == 0 else 0 for label in labels]
df["label"] = labels

# Prepare features (X) and target (y) for training.
X = df.drop("label", axis=1)
y = df["label"]

# Split into training and test sets for evaluation.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Initialize and train the Random Forest Classifier with tuned parameters.
# Parameters chosen after experimentation to balance accuracy and generalization
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,              # Limit depth to prevent overfitting
    min_samples_split=5,       # Require at least 5 samples to split
    random_state=42
)
model.fit(X_train, y_train)

# Evaluate model accuracy on the test set.
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model accuracy: {accuracy:.2%}")

# Serialize trained model for use in the application.
joblib.dump(model, "password_health_model.pkl")
print("Model saved as 'password_health_model.pkl'")