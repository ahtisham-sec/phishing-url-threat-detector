"""
detector.py
The public interface of the project: give it a URL, get back a risk
score, a verdict, and the reasoning behind it. Combines the ML model's
probability estimate with the explainable rule-based findings so the
output is never a black-box number with no justification.
"""

import os

from feature_extractor import extract_features, features_to_vector
from heuristics import evaluate as run_heuristics

MODEL_PATH = "model/phishing_model.joblib"

ML_WEIGHT = 0.6
HEURISTIC_WEIGHT = 0.4


class PhishingDetector:
    def __init__(self, model_path=MODEL_PATH):
        self.model = None
        self.feature_order = None
        if os.path.exists(model_path):
            import joblib
            bundle = joblib.load(model_path)
            self.model = bundle["model"]
            self.feature_order = bundle["feature_order"]

    def _ml_score(self, features):
        if not self.model:
            return None
        vector = [features[name] for name in self.feature_order]
        proba = self.model.predict_proba([vector])[0]
        # proba[1] = probability of class "1" (phishing)
        phishing_index = list(self.model.classes_).index(1)
        return round(proba[phishing_index] * 100, 1)

    def scan(self, url):
        features = extract_features(url)
        findings, heuristic_score = run_heuristics(url)
        ml_score = self._ml_score(features)

        if ml_score is not None:
            combined = round(ML_WEIGHT * ml_score + HEURISTIC_WEIGHT * heuristic_score, 1)
        else:
            combined = heuristic_score

        if combined >= 70:
            verdict = "Dangerous"
        elif combined >= 35:
            verdict = "Suspicious"
        else:
            verdict = "Likely Safe"

        return {
            "url": url,
            "verdict": verdict,
            "risk_score": combined,
            "ml_score": ml_score,
            "heuristic_score": heuristic_score,
            "findings": [f.to_dict() for f in findings],
            "features": features,
        }

    def scan_many(self, urls):
        return [self.scan(u) for u in urls]
