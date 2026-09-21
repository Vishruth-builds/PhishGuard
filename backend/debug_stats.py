import pandas as pd
import numpy as np
from ucimlrepo import fetch_ucirepo
from feature_extractor import extract_features

print("Loading dataset...")
dataset = fetch_ucirepo(id=967)
raw_X = dataset.data.features
y = dataset.data.targets.squeeze()

FEATURE_NAMES = [
    "URLLength", "DomainLength", "IsDomainIP", "TLDLength",
    "NoOfSubDomain", "NoOfLettersInURL", "NoOfDegitsInURL",
    "NoOfEqualsInURL", "NoOfQMarkInURL", "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL", "IsHTTPS",
]

print("Recomputing features (sampling 30000 rows for speed)...")
sample = raw_X.sample(30000, random_state=1)
sample_y = y.loc[sample.index]

rows = [extract_features(u) for u in sample["URL"]]
X_sample = pd.DataFrame(rows)[FEATURE_NAMES]

print("\nMean feature values by label (1=legit, 0=phishing):")
print(X_sample.groupby(sample_y.values).mean().T)

print("\ngoogle.com features:")
print(extract_features("https://google.com"))