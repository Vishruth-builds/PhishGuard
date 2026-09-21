from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse
import ipaddress
import tldextract
import joblib

from feature_extractor import extract_features

app = FastAPI(title="PhishGuard API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

try:
    model_data = joblib.load("phishing_model.pkl")
    ml_model = model_data["model"]
    ml_features = model_data["features"]
    print("ML model loaded successfully.")
    print("Model classes:", ml_model.classes_)
except Exception as e:
    ml_model = None
    ml_features = None
    print("Warning: could not load ML model:", e)


class URLRequest(BaseModel):
    url: str


SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "password", "confirm", "bank", "wallet",
    "payment", "recover", "authenticate", "unlock",
]

SUSPICIOUS_TLDS = ["xyz", "top", "click", "work", "zip", "tk", "ml", "ga", "cf"]

TRUSTED_DOMAINS = [
    "google.com", "github.com", "microsoft.com", "apple.com", "amazon.com",
    "wikipedia.org", "reddit.com", "nytimes.com", "youtube.com", "facebook.com",
    "linkedin.com", "cloudflare.com", "stripe.com", "twitter.com", "x.com",
    "instagram.com", "netflix.com", "spotify.com", "dropbox.com", "slack.com",
    "zoom.us", "adobe.com", "salesforce.com", "paypal.com", "ebay.com",
    "yahoo.com", "bing.com", "wordpress.com", "shopify.com", "airbnb.com",
    "uber.com", "openai.com", "anthropic.com", "notion.so", "figma.com",
    "atlassian.com", "gitlab.com", "npmjs.com", "python.org", "mozilla.org",
    "ibm.com", "oracle.com", "intel.com", "nvidia.com", "samsung.com",
    "cisco.com", "vercel.com", "digitalocean.com", "heroku.com",
    "stackoverflow.com", "medium.com", "quora.com", "twitch.tv", "discord.com",
    "whatsapp.com", "telegram.org", "wellsfargo.com", "chase.com",
    "bankofamerica.com", "americanexpress.com", "usps.com", "fedex.com",
    "ups.com",
]


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def get_ml_prediction(url):
    if ml_model is None:
        return None, None

    features_dict = extract_features(url)
    row = [[features_dict[f] for f in ml_features]]
    probabilities = ml_model.predict_proba(row)[0]

    classes = list(ml_model.classes_)
    phishing_index = classes.index(0)
    phishing_probability = probabilities[phishing_index] * 100

    if phishing_probability >= 60:
        status = "danger"
    elif phishing_probability >= 30:
        status = "warning"
    else:
        status = "good"

    indicator = {
        "name": "ML Model Prediction",
        "status": status,
        "message": f"ML model estimates {phishing_probability:.1f}% phishing probability."
    }

    return phishing_probability, indicator


def analyze_url(url):
    normalized_url = url.strip()

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = "http://" + normalized_url

    parsed = urlparse(normalized_url)
    hostname = parsed.hostname or ""
    query = parsed.query or ""
    full_url_lower = normalized_url.lower()

    # --------------------------------------------------
    # 0. TRUSTED DOMAIN OVERRIDE
    # --------------------------------------------------
    early_extract = tldextract.extract(hostname)
    registered_domain = early_extract.registered_domain.lower()

    if registered_domain in TRUSTED_DOMAINS:
        return {
            "url": normalized_url,
            "score": 0,
            "verdict": "Low Risk",
            "level": "good",
            "hostname": hostname,
            "domain": early_extract.registered_domain,
            "ml_probability": None,
            "indicators": [{
                "name": "Trusted domain",
                "status": "good",
                "message": f"{early_extract.registered_domain} is a recognized, verified domain."
            }],
        }

    score = 0
    indicators = []

    # 1. HTTPS
    if parsed.scheme == "https":
        indicators.append({"name": "HTTPS", "status": "good", "message": "The URL uses HTTPS."})
    else:
        score += 15
        indicators.append({"name": "HTTPS", "status": "danger", "message": "The URL does not use HTTPS."})

    # 2. IP address
    if is_ip_address(hostname):
        score += 25
        indicators.append({"name": "IP address", "status": "danger", "message": "The hostname is an IP address instead of a normal domain."})
    else:
        indicators.append({"name": "IP address", "status": "good", "message": "The hostname uses a domain name."})

    # 3. URL length
    url_length = len(normalized_url)
    if url_length > 100:
        score += 15
        indicators.append({"name": "URL length", "status": "danger", "message": f"The URL is unusually long ({url_length} characters)."})
    elif url_length > 75:
        score += 8
        indicators.append({"name": "URL length", "status": "warning", "message": f"The URL is relatively long ({url_length} characters)."})
    else:
        indicators.append({"name": "URL length", "status": "good", "message": f"The URL length is {url_length} characters."})

    # 4. @ symbol
    if "@" in normalized_url:
        score += 20
        indicators.append({"name": "@ symbol", "status": "danger", "message": "The URL contains an @ symbol."})
    else:
        indicators.append({"name": "@ symbol", "status": "good", "message": "No @ symbol detected."})

    # 5. Domain structure
    dot_count = hostname.count(".")
    if dot_count >= 4:
        score += 10
        indicators.append({"name": "Domain structure", "status": "danger", "message": f"The hostname contains {dot_count} dots."})
    elif dot_count >= 3:
        score += 5
        indicators.append({"name": "Domain structure", "status": "warning", "message": f"The hostname contains {dot_count} dots."})
    else:
        indicators.append({"name": "Domain structure", "status": "good", "message": "The domain structure looks relatively simple."})

    # 6. Subdomains
    extracted = tldextract.extract(hostname)
    subdomain = extracted.subdomain
    if subdomain:
        subdomain_count = len(subdomain.split("."))
        if subdomain_count >= 3:
            score += 10
            indicators.append({"name": "Subdomains", "status": "danger", "message": f"The URL contains {subdomain_count} subdomain levels."})
        elif subdomain_count >= 2:
            score += 5
            indicators.append({"name": "Subdomains", "status": "warning", "message": f"The URL contains {subdomain_count} subdomain levels."})
        else:
            indicators.append({"name": "Subdomains", "status": "good", "message": "A single subdomain level was detected."})
    else:
        indicators.append({"name": "Subdomains", "status": "good", "message": "No subdomain detected."})

    # 7. Suspicious keywords
    found_keywords = [k for k in SUSPICIOUS_KEYWORDS if k in full_url_lower]
    if found_keywords:
        score += min(len(found_keywords) * 5, 20)
        indicators.append({"name": "Suspicious keywords", "status": "danger", "message": "Detected: " + ", ".join(found_keywords)})
    else:
        indicators.append({"name": "Suspicious keywords", "status": "good", "message": "No common phishing-related keywords detected."})

    # 8. Hyphens
    hyphen_count = hostname.count("-")
    if hyphen_count >= 3:
        score += 10
        indicators.append({"name": "Hyphens", "status": "warning", "message": f"The hostname contains {hyphen_count} hyphens."})
    else:
        indicators.append({"name": "Hyphens", "status": "good", "message": f"The hostname contains {hyphen_count} hyphens."})

    # 9. Digits
    digit_count = sum(c.isdigit() for c in hostname)
    if digit_count >= 5:
        score += 8
        indicators.append({"name": "Digits", "status": "warning", "message": f"The hostname contains {digit_count} digits."})
    else:
        indicators.append({"name": "Digits", "status": "good", "message": f"The hostname contains {digit_count} digits."})

    # 10. TLD
    suffix = extracted.suffix.lower()
    if suffix in SUSPICIOUS_TLDS:
        score += 10
        indicators.append({"name": "TLD", "status": "warning", "message": f"The domain uses the .{suffix} TLD."})
    else:
        indicators.append({"name": "TLD", "status": "good", "message": f"The domain uses .{suffix or 'unknown'}."})

    # 11. Query string
    if len(query) > 150:
        score += 5
        indicators.append({"name": "Query string", "status": "warning", "message": "The URL contains a long query string."})

    # 12. ML model
    ml_probability, ml_indicator = get_ml_prediction(normalized_url)
    if ml_probability is not None:
        indicators.append(ml_indicator)
        score = (score * 0.5) + (ml_probability * 0.5)

    score = min(round(score), 100)

    if score >= 60:
        verdict = "High Risk"
        level = "danger"
    elif score >= 30:
        verdict = "Suspicious"
        level = "warning"
    else:
        verdict = "Low Risk"
        level = "good"

    return {
        "url": normalized_url,
        "score": score,
        "verdict": verdict,
        "level": level,
        "hostname": hostname,
        "domain": extracted.registered_domain,
        "ml_probability": round(ml_probability, 1) if ml_probability is not None else None,
        "indicators": indicators,
    }


@app.get("/")
def root():
    return {"message": "PhishGuard API is running"}


@app.post("/analyze")
def analyze(request: URLRequest):
    if not request.url.strip():
        return {"error": "URL cannot be empty."}

    try:
        return analyze_url(request.url)
    except Exception as error:
        return {"error": str(error)}