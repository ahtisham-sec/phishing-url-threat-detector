#!/usr/bin/env python3
"""
Phishing URL & Threat Detector — CLI entry point.

Usage:
    python main.py --url http://paypal-secure-login.tk/verify
    python main.py --file urls.txt
    python main.py --demo
"""

import argparse
import os
import sys

from detector import PhishingDetector
import report_generator

DEMO_URLS = [
    "https://www.github.com/",
    "https://www.wikipedia.org/wiki/Phishing",
    "http://paypal-secure-login-verify.tk/account/webscr",
    "http://192.168.4.21/amazon/confirm.php?id=93af12",
    "https://amazon.account.9f3a2c.xyz/signin/update",
    "https://www.google.com/search?q=weather",
    "http://bit.ly/3xample",
    "https://chase-secure-alert-suspended.club/unlock-account",
]


def load_urls_from_file(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="Phishing URL & Threat Detector")
    parser.add_argument("--url", help="Single URL to scan")
    parser.add_argument("--file", help="Path to a text file with one URL per line")
    parser.add_argument("--demo", action="store_true", help="Scan a bundled set of example URLs")
    parser.add_argument("--out-dir", default="reports", help="Directory to write reports into")
    parser.add_argument("--model", default="model/phishing_model.joblib",
                         help="Path to trained model (falls back to heuristics-only if missing)")
    args = parser.parse_args()

    if not args.url and not args.file and not args.demo:
        parser.error("provide --url, --file, or --demo")

    os.makedirs(args.out_dir, exist_ok=True)

    if args.url:
        urls = [args.url]
    elif args.file:
        urls = load_urls_from_file(args.file)
    else:
        urls = DEMO_URLS

    detector = PhishingDetector(model_path=args.model)
    if detector.model is None:
        print(f"[!] No trained model found at {args.model} — running in heuristics-only mode.")
        print("    Run `python generate_dataset.py && python train_model.py` to enable ML scoring.\n")

    print(f"Scanning {len(urls)} URL(s)...\n")
    results = detector.scan_many(urls)

    for r in results:
        print(f"{r['verdict']:<12} [{r['risk_score']:>5}/100]  {r['url']}")

    html_path = os.path.join(args.out_dir, "threat_report.html")
    json_path = os.path.join(args.out_dir, "threat_report.json")
    report_generator.generate_html(results, html_path)
    report_generator.generate_json(results, json_path)

    print(f"\nHTML report: {html_path}")
    print(f"JSON report: {json_path}")


if __name__ == "__main__":
    sys.exit(main())
