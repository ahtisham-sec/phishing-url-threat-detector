"""
feature_extractor.py
Extracts lexical and structural features from a URL, purely from the
string itself (no network calls, no WHOIS lookups) so it works fully
offline and instantly. These are the same category of signals used in
published phishing-detection research (URL length, IP-in-hostname,
suspicious keywords, entropy, subdomain count, etc.).

Returns a flat dict of numeric features, ready to feed into either the
rule-based heuristic scorer or the ML model.
"""

import math
import re
from urllib.parse import urlparse

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "cutt.ly", "rb.gy", "tiny.cc",
}

SUSPICIOUS_WORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "bank", "paypal", "webscr", "ebayisapi", "submit", "password",
    "wp-admin", "invoice", "billing", "suspend", "unlock", "recover",
    "security", "alert", "urgent", "click", "free", "gift", "winner",
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work", "click",
    "link", "loan", "download", "racing", "review", "bid", "gdn", "webcam",
}

COMMON_TLDS = {"com", "org", "net", "edu", "gov", "io", "co"}


def _shannon_entropy(s):
    if not s:
        return 0.0
    freq = {ch: s.count(ch) for ch in set(s)}
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _get_hostname(url):
    parsed = urlparse(url if "://" in url else "http://" + url)
    return parsed, parsed.hostname or ""


def extract_features(url):
    url = url.strip()
    parsed, hostname = _get_hostname(url)
    hostname = hostname.lower()
    path = parsed.path or ""
    query = parsed.query or ""
    full = url.lower()

    labels = hostname.split(".") if hostname else []
    tld = labels[-1] if len(labels) >= 2 else ""
    # subdomains = everything except the registrable domain + tld (rough heuristic,
    # good enough without a public-suffix-list dependency)
    num_subdomains = max(0, len(labels) - 2)

    domain_no_tld = ".".join(labels[:-1]) if len(labels) >= 2 else hostname

    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "num_dots": full.count("."),
        "num_hyphens": hostname.count("-"),
        "num_underscore": full.count("_"),
        "num_slash": full.count("/"),
        "num_question_marks": full.count("?"),
        "num_equal": full.count("="),
        "num_at": full.count("@"),
        "num_ampersand": full.count("&"),
        "num_digits": sum(c.isdigit() for c in full),
        "num_percent": full.count("%"),
        "has_ip_address": int(bool(IP_PATTERN.match(hostname))),
        "num_subdomains": num_subdomains,
        "is_https": int(parsed.scheme == "https"),
        "has_port": int(parsed.port is not None) if hostname else 0,
        "is_shortener": int(hostname in URL_SHORTENERS),
        "suspicious_word_count": sum(1 for w in SUSPICIOUS_WORDS if w in full),
        "domain_entropy": round(_shannon_entropy(domain_no_tld), 3),
        "tld_length": len(tld),
        "has_punycode": int("xn--" in hostname),
        "digit_ratio_domain": round(
            sum(c.isdigit() for c in domain_no_tld) / len(domain_no_tld), 3
        ) if domain_no_tld else 0,
        "double_slash_in_path": int("//" in path),
        "is_suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_common_tld": int(tld in COMMON_TLDS),
        "www_count": full.count("www."),
        "hyphen_in_domain": int("-" in domain_no_tld),
    }
    return features


FEATURE_ORDER = [
    "url_length", "hostname_length", "path_length", "query_length",
    "num_dots", "num_hyphens", "num_underscore", "num_slash",
    "num_question_marks", "num_equal", "num_at", "num_ampersand",
    "num_digits", "num_percent", "has_ip_address", "num_subdomains",
    "is_https", "has_port", "is_shortener", "suspicious_word_count",
    "domain_entropy", "tld_length", "has_punycode", "digit_ratio_domain",
    "double_slash_in_path", "is_suspicious_tld", "is_common_tld",
    "www_count", "hyphen_in_domain",
]


def features_to_vector(features):
    """Deterministic ordering so the ML model always sees columns in the
    same sequence, whether during training or inference."""
    return [features[name] for name in FEATURE_ORDER]
