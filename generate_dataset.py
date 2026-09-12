"""
generate_dataset.py
Builds data/urls_dataset.csv — a labeled set of legitimate vs. phishing-
style URLs used to train the classifier in train_model.py.

This is a SYNTHETIC dataset assembled from well-documented phishing
patterns (brand impersonation, IP hosts, suspicious TLDs, homograph
tricks, credential-harvesting keywords) combined with a list of
real, well-known legitimate domains. It's built this way so the repo
is fully self-contained and reproducible with no external downloads.

For a production system, swap this out for a real labeled corpus such
as the UCI "Phishing Websites" dataset or a PhishTank feed export —
the feature extractor and training pipeline don't need to change,
just the CSV this script produces.
"""

import csv
import random

random.seed(42)

LEGITIMATE_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "spotify.com", "linkedin.com", "reddit.com",
    "stackoverflow.com", "nytimes.com", "bbc.co.uk", "dropbox.com", "adobe.com",
    "cloudflare.com", "mozilla.org", "python.org", "wordpress.com", "shopify.com",
    "airbnb.com", "booking.com", "paypal.com", "ebay.com", "twitch.tv",
    "salesforce.com", "zoom.us", "slack.com", "notion.so", "figma.com",
    "gov.uk", "irs.gov", "nasa.gov", "harvard.edu", "mit.edu",
    "coursera.org", "khanacademy.org", "medium.com", "quora.com", "yelp.com",
]

LEGIT_PATHS = [
    "", "/", "/about", "/blog/2026/annual-report", "/products/overview",
    "/docs/getting-started", "/careers", "/support/contact",
    "/user/settings/profile", "/search?q=quarterly+earnings",
    "/watch?v=dQw4w9WgXcQ", "/news/technology/latest",
    "/help/account-recovery", "/pricing", "/en-us/download",
]

BRANDS_TO_IMPERSONATE = [
    "paypal", "amazon", "apple", "microsoft", "netflix", "bankofamerica",
    "chase", "wellsfargo", "google", "facebook", "instagram", "dropbox",
    "linkedin", "ebay", "irs", "hmrc", "dhl", "fedex", "usps",
]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "club", "work",
                    "click", "link", "loan", "review", "bid", "gdn"]

SUSPICIOUS_KEYWORDS = ["secure", "login", "verify", "update", "confirm",
                        "account", "signin", "billing", "suspended", "unlock",
                        "recover", "alert", "webscr"]

RANDOM_HEX_POOL = "abcdef0123456789"


def random_hex(n):
    return "".join(random.choice(RANDOM_HEX_POOL) for _ in range(n))


def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def make_legit_url():
    domain = random.choice(LEGITIMATE_DOMAINS)
    path = random.choice(LEGIT_PATHS)
    scheme = "https"
    use_www = random.random() < 0.4
    host = f"www.{domain}" if use_www else domain
    return f"{scheme}://{host}{path}"


def make_phishing_url():
    style = random.choice(["hyphen-brand", "subdomain-brand", "ip-host",
                            "keyword-stack", "suspicious-tld", "long-path"])
    brand = random.choice(BRANDS_TO_IMPERSONATE)
    keyword = random.choice(SUSPICIOUS_KEYWORDS)
    tld = random.choice(SUSPICIOUS_TLDS)

    if style == "hyphen-brand":
        host = f"{brand}-{keyword}-{random_hex(4)}.{tld}"
        return f"http://{host}/{keyword}"

    if style == "subdomain-brand":
        host = f"{brand}.{keyword}.{random_hex(5)}.{random.choice(SUSPICIOUS_TLDS)}"
        return f"http://{host}/account/{keyword}"

    if style == "ip-host":
        path = f"/{brand}/{keyword}.php?id={random_hex(6)}"
        return f"http://{random_ip()}{path}"

    if style == "keyword-stack":
        kw2 = random.choice(SUSPICIOUS_KEYWORDS)
        host = f"{brand}{kw2}{keyword}.{tld}"
        return f"http://{host}/{keyword}/{kw2}?token={random_hex(10)}"

    if style == "suspicious-tld":
        host = f"{brand}-official.{tld}"
        return f"https://{host}/{keyword}-your-account"

    # long-path: legit-looking domain but deep suspicious path with tokens
    host = f"{random_hex(6)}-{brand}.{tld}"
    return (f"http://{host}/wp-admin/{keyword}/session/"
            f"{random_hex(8)}/{keyword}.html?redirect={random_hex(12)}")


def generate(n_per_class=600, out_path="data/urls_dataset.csv"):
    rows = []
    for _ in range(n_per_class):
        rows.append((make_legit_url(), 0))
    for _ in range(n_per_class):
        rows.append((make_phishing_url(), 1))
    random.shuffle(rows)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])  # label: 0 = legitimate, 1 = phishing
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows ({n_per_class} legitimate, {n_per_class} phishing) to {out_path}")


if __name__ == "__main__":
    generate()
