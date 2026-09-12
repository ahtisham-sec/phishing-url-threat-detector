"""
api.py
Optional Flask REST API wrapping the detector, so the project can also
be demoed as a live service instead of just a CLI tool.

Run:
    python api.py
Then:
    curl -X POST http://127.0.0.1:5000/check -H "Content-Type: application/json" \\
         -d '{"url": "http://paypal-secure-login.tk/verify"}'

Or open http://127.0.0.1:5000/ in a browser for a minimal test form.
"""

from flask import Flask, jsonify, render_template, request

from detector import PhishingDetector

app = Flask(__name__)
detector = PhishingDetector()


@app.route("/")
def index():
    return render_template("index.html", model_loaded=detector.model is not None)


@app.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or request.form
    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "missing 'url' field"}), 400
    result = detector.scan(url)
    return jsonify(result)


@app.route("/health")
def health():
    return jsonify({"status": "ok", "model_loaded": detector.model is not None})


if __name__ == "__main__":
    app.run(debug=False, port=5000)
