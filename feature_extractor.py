from urllib.parse import urlparse
import ipaddress
import tldextract


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def extract_features(url):
    """
    Converts a raw URL string into the feature format used to train
    phishing_model.pkl. Must match FEATURE_NAMES in train_model.py exactly.
    """

    normalized_url = url.strip()

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    extracted = tldextract.extract(hostname)

    url_length = len(normalized_url)

    letters = sum(c.isalpha() for c in normalized_url)
    digits = sum(c.isdigit() for c in normalized_url)

    special_chars = sum(
        not c.isalnum() and c not in ("=", "?", "&")
        for c in normalized_url
    )

    subdomain = extracted.subdomain
    subdomain_count = len(subdomain.split(".")) if subdomain else 0

    # Avoid divide-by-zero on a theoretical empty URL
    safe_length = max(url_length, 1)

    features = {
        "URLLength": url_length,
        "DomainLength": len(hostname),
        "IsDomainIP": 1 if is_ip_address(hostname) else 0,
        "TLDLength": len(extracted.suffix),
        "NoOfSubDomain": subdomain_count,
        "NoOfLettersInURL": letters,
        "NoOfDegitsInURL": digits,
        "NoOfEqualsInURL": normalized_url.count("="),
        "NoOfQMarkInURL": normalized_url.count("?"),
        "NoOfAmpersandInURL": normalized_url.count("&"),
        "NoOfOtherSpecialCharsInURL": special_chars,
        "IsHTTPS": 1 if parsed.scheme == "https" else 0,
        # Ratio features - normalize counts by URL length so short
        # URLs (like google.com) aren't treated as out-of-distribution
        "LetterRatioInURL": letters / safe_length,
        "DegitRatioInURL": digits / safe_length,
        "SpecialCharRatioInURL": special_chars / safe_length,
    }

    return features


if __name__ == "__main__":
    print("Testing: https://google.com")
    print(extract_features("https://google.com"))
    print()
    print("Testing: http://paypal-login-verify-account.example.xyz/login")
    print(extract_features("http://paypal-login-verify-account.example.xyz/login"))