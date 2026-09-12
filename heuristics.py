"""
heuristics.py
Independent, explainable rule-based layer. Even if the ML model were
unavailable or untrained, this alone gives a usable, human-readable
verdict — and its findings are what makes the final report explainable
rather than "the model said 73% phishing" with no reasoning shown.
"""

from feature_extractor import extract_features, SUSPICIOUS_WORDS


class Finding:
    def __init__(self, severity, title, detail):
        self.severity = severity  # "critical" | "warning" | "info"
        self.title = title
        self.detail = detail

    def to_dict(self):
        return {"severity": self.severity, "title": self.title, "detail": self.detail}


WEIGHTS = {"critical": 25, "warning": 12, "info": 4}


def evaluate(url):
    """Returns (findings: list[Finding], heuristic_risk_score: int 0-100)."""
    f = extract_features(url)
    findings = []

    if f["has_ip_address"]:
        findings.append(Finding("critical", "IP address used as hostname",
                                 "The domain is a raw IP address instead of a registered domain name, "
                                 "a strong phishing/malware-hosting signal."))

    if f["has_punycode"]:
        findings.append(Finding("critical", "Punycode / IDN homograph domain",
                                 "The hostname contains 'xn--', indicating an internationalized domain "
                                 "that may visually mimic a trusted brand (homograph attack)."))

    if f["num_at"] > 0:
        findings.append(Finding("critical", "'@' symbol in URL",
                                 "Browsers ignore everything before '@' when resolving the host, a "
                                 "classic trick to disguise the real destination."))

    if f["is_shortener"]:
        findings.append(Finding("warning", "URL shortener detected",
                                 "Shortened URLs hide the real destination until after the click."))

    if f["is_suspicious_tld"]:
        findings.append(Finding("warning", "Uncommon / high-abuse TLD",
                                 "This top-level domain is disproportionately used for phishing and "
                                 "spam campaigns in industry abuse reports."))

    if f["suspicious_word_count"] >= 3:
        findings.append(Finding("critical", "Multiple credential-harvesting keywords",
                                 f"Found {f['suspicious_word_count']} words associated with phishing "
                                 f"(e.g. login/verify/secure/account) in the URL."))
    elif f["suspicious_word_count"] >= 1:
        findings.append(Finding("warning", "Credential-harvesting keyword present",
                                 f"Found {f['suspicious_word_count']} suspicious keyword(s) in the URL."))

    if f["num_subdomains"] >= 3:
        findings.append(Finding("warning", "Excessive subdomains",
                                 f"{f['num_subdomains']} subdomain levels detected, often used to bury "
                                 "a brand name deep in a URL to look legitimate at a glance."))

    if f["hyphen_in_domain"] and f["num_hyphens"] >= 2:
        findings.append(Finding("warning", "Multiple hyphens in domain",
                                 "Domains impersonating a brand often insert hyphens "
                                 "(e.g. paypal-secure-login.com)."))

    if not f["is_https"]:
        findings.append(Finding("warning", "Not served over HTTPS",
                                 "No TLS encryption; credentials or data submitted here travel in "
                                 "plain text."))

    if f["url_length"] > 100:
        findings.append(Finding("info", "Unusually long URL",
                                 f"URL is {f['url_length']} characters, which can be used to bury "
                                 "the real domain or hide it off-screen."))

    if f["domain_entropy"] > 4.0:
        findings.append(Finding("warning", "High domain entropy",
                                 f"Domain entropy is {f['domain_entropy']}, suggesting a randomly "
                                 "generated string rather than a human-chosen brand name — common in "
                                 "algorithmically generated phishing/malware domains."))

    if f["double_slash_in_path"]:
        findings.append(Finding("info", "Double slash in path",
                                 "An extra '//' in the path can be used in open-redirect tricks."))

    if f["has_port"]:
        findings.append(Finding("info", "Non-standard port specified",
                                 "Legitimate consumer-facing sites rarely expose a custom port."))

    if not findings:
        findings.append(Finding("info", "No heuristic red flags found",
                                 "This URL did not trigger any of the rule-based checks."))

    penalty = sum(WEIGHTS[fi.severity] for fi in findings if fi.title != "No heuristic red flags found")
    risk_score = min(100, penalty)
    return findings, risk_score
