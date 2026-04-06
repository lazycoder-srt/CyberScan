from flask import Flask, render_template, request
import hashlib
import requests

app = Flask(__name__)

# HOME PAGE
@app.route("/")
def home():
    return render_template("index.html")

# SCANNER PAGE
@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

# FILE SCAN LOGIC
@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files["file"]

    filename = file.filename
    file_bytes = file.read()
    file_size = round(len(file_bytes) / 1024, 2)

    hasher = hashlib.md5()
    hasher.update(file_bytes)
    file_hash = hasher.hexdigest()

    malicious_hashes = [
        "e99a18c428cb38d5f260853678922e03"
    ]

    if file_hash in malicious_hashes:
        result = "malicious"
        score = 90
    else:
        result = "safe"
        score = 20

    return render_template(
        "scanner.html",
        result=result,
        score=score,
        filename=filename,
        file_size=file_size,
        file_hash=file_hash
    )
@app.route("/scan-website", methods=["POST"])
def scan_website():
    url = request.form["url"]

    web_issues = []
    web_score = 0

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Check security headers
        if "Content-Security-Policy" not in headers:
            web_issues.append("⚠️ Missing Content-Security-Policy")
            web_score += 1

        if "X-Frame-Options" not in headers:
            web_issues.append("⚠️ Clickjacking protection missing")
            web_score += 1

        if "Strict-Transport-Security" not in headers:
            web_issues.append("⚠️ Missing HSTS (HTTPS protection)")
            web_score += 1

        if "X-Content-Type-Options" not in headers:
            web_issues.append("⚠️ MIME sniffing protection missing")
            web_score += 1

    except:
        web_issues.append("❌ Could not access website")

    return render_template(
        "scanner.html",
        web_issues=web_issues,
        web_score=web_score
    )

# RUN APP (ALWAYS LAST)
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)