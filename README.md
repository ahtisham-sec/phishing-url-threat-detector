# Phishing URL & Threat Detector

A hybrid phishing-URL detector that combines a trained machine learning
classifier with an explainable rule-based heuristic engine. Give it a
URL, get back a risk score, a verdict (Likely Safe / Suspicious /
Dangerous), and the exact reasoning behind it — not just a black-box
number.

Built to demonstrate: feature engineering from raw text, a scikit-learn
training pipeline with proper evaluation, an explainable rules engine,
a CLI tool, a REST API, and report generation.
<img width="1920" height="3437" alt="image" src="https://github.com/user-attachments/assets/9ca547b0-dbca-4feb-8615-11205be9638b" />




## Live demo (no setup beyond installing dependencies)

```bash
pip install -r requirements.txt
python main.py --demo
```

Scans 8 bundled example URLs (mix of legitimate sites and phishing
patterns) and writes a dashboard report to `reports/threat_report.html`.

## Train the model yourself

```bash
python generate_dataset.py   # builds data/urls_dataset.csv (1,200 labeled URLs)
python train_model.py        # trains + evaluates a RandomForestClassifier
```

A pretrained model is already included in `model/phishing_model.joblib`,
so this step is optional unless you want to retrain or swap in your own
dataset.

**About the dataset:** it's synthetically generated from well-documented
phishing patterns (brand impersonation, IP-address hosts, suspicious
TLDs, credential-harvesting keywords) paired with real, well-known
legitimate domains — see `generate_dataset.py`. That's why training
accuracy on the held-out test set comes out near-perfect: the synthetic
patterns are cleanly separable by design, which is expected and worth
being upfront about. For a production-grade model, swap in a real
labeled corpus such as the UCI "Phishing Websites" dataset or a
PhishTank export — the feature extractor and training pipeline don't
need to change, only the CSV.

## Scan URLs

```bash
python main.py --url "http://paypal-secure-login.tk/verify"
python main.py --file urls.txt          # one URL per line
python main.py --demo
```

## Run it as a web API

```bash
python api.py
```

Then either open `http://127.0.0.1:5000/` for a minimal test form, or:

```bash
curl -X POST http://127.0.0.1:5000/check \
     -H "Content-Type: application/json" \
     -d '{"url": "http://paypal-secure-login.tk/verify"}'
```

## How scoring works

Two independent signals are combined:

1. **ML model** (60% weight) — a RandomForestClassifier trained on 28
   lexical/structural features (URL length, entropy, IP-as-hostname,
   subdomain count, suspicious TLD, credential-harvesting keywords,
   etc.), outputting a phishing probability.
2. **Heuristic rules engine** (40% weight) — independent, explainable
   checks that don't require a trained model at all (see
   `heuristics.py`). This is what powers the "Fix: ..." style reasoning
   in the report — the model alone can't explain *why* it flagged
   something, the rules engine can.

Combined score ≥ 70 → **Dangerous**, ≥ 35 → **Suspicious**, else →
**Likely Safe**. If no trained model is present, the tool still works,
scoring on heuristics alone.

## Architecture

```
main.py                CLI entry point
api.py                 Flask REST API + minimal test form
detector.py             Combines ML score + heuristic findings into one verdict
feature_extractor.py    Pulls 28 numeric features out of a raw URL string
heuristics.py            Explainable rule-based checks (works without ML model)
generate_dataset.py      Builds the synthetic labeled training dataset
train_model.py            Trains + evaluates the RandomForestClassifier
report_generator.py       Renders the HTML dashboard + JSON export
data/urls_dataset.csv      1,200 labeled URLs (generated, see above)
model/phishing_model.joblib  Pretrained model (included, ready to use)
templates/index.html       Minimal web UI for the Flask API
```

## Extending it

- Add a new heuristic: write a check in `heuristics.py`'s `evaluate()`,
  append a `Finding`.
- Add a new ML feature: add it to `feature_extractor.py`'s
  `extract_features()` and `FEATURE_ORDER`, then retrain.
- Swap in a real dataset: replace `data/urls_dataset.csv` with any CSV
  that has `url,label` columns (label: 0 = legitimate, 1 = phishing),
  then run `python train_model.py`.
- Plug in live threat intel: `detector.py` is the natural place to add
  a Google Safe Browsing / VirusTotal / PhishTank API lookup alongside
  the ML + heuristic scores, if you have API keys.

## Roadmap ideas

- Browser extension front-end calling the Flask API in real time
- WHOIS-based domain-age check (newly registered domains are high-risk)
- Screenshot + visual brand-logo similarity detection
- Batch CSV upload endpoint on the API

## License

MIT — use it, extend it, put it on your resume.
