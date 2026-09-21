import pandas as pd
import numpy as np
import joblib

from ucimlrepo import fetch_ucirepo

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from feature_extractor import extract_features


print("Loading PhiUSIIL dataset...")

dataset = fetch_ucirepo(id=967)

raw_X = dataset.data.features
y = dataset.data.targets.squeeze()

print("Dataset loaded.")
print("Rows:", len(raw_X))

url_column = None
for candidate in ["URL", "url", "URLURL"]:
    if candidate in raw_X.columns:
        url_column = candidate
        break

if url_column is None:
    raise ValueError(f"Could not find a raw URL column. Columns: {list(raw_X.columns)}")

print(f"Using raw URL column: {url_column}")


# --------------------------------------------------
# BUILD FEATURES USING OUR OWN EXTRACTOR
# --------------------------------------------------

print("\nRecomputing features with our own extractor...")
print("(This may take a few minutes for 235k rows)")

FEATURE_NAMES = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "TLDLength",
    "NoOfSubDomain",
    "NoOfLettersInURL",
    "NoOfDegitsInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "IsHTTPS",
    "LetterRatioInURL",
    "DegitRatioInURL",
    "SpecialCharRatioInURL",
]

rows = []
skipped = 0

for i, raw_url in enumerate(raw_X[url_column]):
    try:
        rows.append(extract_features(raw_url))
    except Exception:
        skipped += 1
        rows.append({name: 0 for name in FEATURE_NAMES})

    if (i + 1) % 20000 == 0:
        print(f"  Processed {i + 1} / {len(raw_X)} rows...")

print(f"Done. Skipped {skipped} rows due to parsing errors.")

X = pd.DataFrame(rows)[FEATURE_NAMES]
X = X.replace([np.inf, -np.inf], np.nan).fillna(0)


# --------------------------------------------------
# TRAIN / TEST SPLIT
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# --------------------------------------------------
# RANDOM FOREST (constrained to reduce overfitting/extrapolation issues)
# --------------------------------------------------

print("\nTraining Random Forest...")

model = RandomForestClassifier(
    n_estimators=300,
    max_depth=12,
    min_samples_leaf=10,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# --------------------------------------------------
# EVALUATION
# --------------------------------------------------

predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print("\n==============================")
print("MODEL RESULTS")
print("==============================")
print(f"Accuracy: {accuracy:.4f}")
print("\nClassification Report:")
print(classification_report(y_test, predictions))

print("\nFeature Importance:")
importance = pd.Series(
    model.feature_importances_, index=FEATURE_NAMES
).sort_values(ascending=False)
print(importance)


# --------------------------------------------------
# SANITY CHECK ON REAL, WELL-KNOWN SITES
# --------------------------------------------------

print("\n==============================")
print("SANITY CHECK (real websites)")
print("==============================")

known_legit = [
    "https://google.com",
    "https://github.com",
    "https://www.wikipedia.org",
    "https://www.amazon.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.reddit.com",
    "https://www.nytimes.com",
]

known_phishing_style = [
    "http://paypal-login-verify-account.example.xyz/login",
    "http://secure-bankofamerica.account-update.tk/verify",
]

def check(url_list, expected_label):
    for test_url in url_list:
        f = extract_features(test_url)
        row = [[f[name] for name in FEATURE_NAMES]]
        proba = model.predict_proba(row)[0]
        classes = list(model.classes_)
        phishing_prob = proba[classes.index(0)] * 100
        flag = "OK" if (phishing_prob < 50) == (expected_label == "legit") else "WRONG"
        print(f"[{flag}] {test_url} -> {phishing_prob:.1f}% phishing probability")

print("\n-- Expected LEGIT --")
check(known_legit, "legit")

print("\n-- Expected PHISHING-STYLE --")
check(known_phishing_style, "phishing")


# --------------------------------------------------
# SAVE MODEL
# --------------------------------------------------

model_data = {"model": model, "features": FEATURE_NAMES}
joblib.dump(model_data, "phishing_model.pkl")

print("\nModel saved as backend/phishing_model.pkl")