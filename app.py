from flask import Flask, render_template, request, send_file, abort
import hashlib
import requests
import os
import time
import sqlite3
import json
from datetime import datetime
from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

app = Flask(__name__)

VT_API_KEY = os.environ.get("VT_API_KEY")  # Replace with your key

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────

def get_db():
    db = sqlite3.connect("scans.db")
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT,
                score INTEGER,
                details TEXT,
                scanned_at TEXT NOT NULL
            )
        """)
        db.commit()

init_db()

def save_scan(scan_type, target, result, score, details: dict):
    with get_db() as db:
        db.execute(
            "INSERT INTO scans (scan_type, target, result, score, details, scanned_at) VALUES (?,?,?,?,?,?)",
            (scan_type, target, result, score, json.dumps(details), datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        db.commit()

def get_all_scans():
    with get_db() as db:
        return db.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()

def get_scan_by_id(scan_id):
    with get_db() as db:
        return db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

# ─────────────────────────────────────────────
# PAGES
# ─────────────────────────────────────────────

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/scanner")
def scanner():
    return render_template("scanner.html")

@app.route("/history")
def history():
    scans = get_all_scans()
    return render_template("history.html", scans=scans)

# ─────────────────────────────────────────────
# FILE SCAN
# ─────────────────────────────────────────────

@app.route("/scan-file", methods=["POST"])
def scan_file():
    file = request.files["file"]
    filename = file.filename
    file_bytes = file.read()
    file_size = round(len(file_bytes) / 1024, 2)

    hasher = hashlib.sha256()
    hasher.update(file_bytes)
    file_hash = hasher.hexdigest()

    headers = {"x-apikey": VT_API_KEY}

    hash_check = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers
    )

    if hash_check.status_code == 200:
        vt_data = hash_check.json()
        stats = vt_data["data"]["attributes"]["last_analysis_stats"]
    else:
        upload_response = requests.post(
            "https://www.virustotal.com/api/v3/files",
            headers=headers,
            files={"file": (filename, file_bytes)}
        )
        if upload_response.status_code != 200:
            return render_template("scanner.html", error="VirusTotal upload failed. Try again.")

        analysis_id = upload_response.json()["data"]["id"]
        stats = None
        for _ in range(10):
            time.sleep(3)
            result_response = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=headers
            )
            result_data = result_response.json()
            if result_data["data"]["attributes"]["status"] == "completed":
                stats = result_data["data"]["attributes"]["stats"]
                break

        if not stats:
            return render_template("scanner.html", error="Scan timed out. Please try again.")

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless   = stats.get("harmless", 0)
    total      = malicious + suspicious + undetected + harmless
    score      = round((malicious + suspicious) / total * 100) if total > 0 else 0

    result = "malicious" if malicious > 0 else ("suspicious" if suspicious > 0 else "safe")

    details = {
        "filename": filename,
        "file_size": file_size,
        "file_hash": file_hash,
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "harmless": harmless,
        "total_engines": total
    }

    save_scan("file", filename, result, score, details)

    with get_db() as db:
        scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    return render_template(
        "scanner.html",
        result=result, score=score, filename=filename,
        file_size=file_size, file_hash=file_hash,
        malicious=malicious, suspicious=suspicious,
        undetected=undetected, harmless=harmless,
        total_engines=total, scan_id=scan_id
    )

# ─────────────────────────────────────────────
# WEBSITE SCAN
# ─────────────────────────────────────────────

@app.route("/scan-website", methods=["POST"])
def scan_website():
    url = request.form["url"]
    web_issues = []
    web_score = 0

    try:
        response = requests.get(url, timeout=5)
        hdrs = response.headers

        if "Content-Security-Policy" not in hdrs:
            web_issues.append("Missing Content-Security-Policy header")
            web_score += 25
        if "X-Frame-Options" not in hdrs:
            web_issues.append("Clickjacking protection missing (X-Frame-Options)")
            web_score += 25
        if "Strict-Transport-Security" not in hdrs:
            web_issues.append("Missing HSTS — HTTPS not enforced")
            web_score += 25
        if "X-Content-Type-Options" not in hdrs:
            web_issues.append("MIME sniffing protection missing (X-Content-Type-Options)")
            web_score += 25

    except requests.exceptions.ConnectionError:
        web_issues.append("Could not connect to website — check the URL")
    except requests.exceptions.Timeout:
        web_issues.append("Website took too long to respond")
    except Exception as e:
        web_issues.append(f"Unexpected error: {str(e)}")

    result = "vulnerable" if web_issues else "safe"
    details = {"url": url, "issues": web_issues}
    save_scan("website", url, result, web_score, details)

    with get_db() as db:
        scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

    return render_template(
        "scanner.html",
        web_issues=web_issues, web_score=web_score,
        scanned_url=url, web_scan_id=scan_id
    )

# ─────────────────────────────────────────────
# PDF REPORT
# ─────────────────────────────────────────────

@app.route("/report/<int:scan_id>")
def download_report(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        abort(404)

    details = json.loads(scan["details"])
    buffer = BytesIO()

    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        rightMargin=0.75*inch, leftMargin=0.75*inch,
        topMargin=0.75*inch, bottomMargin=0.75*inch
    )

    title_style = ParagraphStyle("T", fontSize=22, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#00a878"), alignment=TA_CENTER, spaceAfter=4)
    sub_style = ParagraphStyle("S", fontSize=10, fontName="Helvetica",
        textColor=colors.HexColor("#888888"), alignment=TA_CENTER, spaceAfter=20)
    section_style = ParagraphStyle("Sec", fontSize=12, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#00a878"), spaceBefore=18, spaceAfter=8)
    body_style = ParagraphStyle("B", fontSize=10, fontName="Helvetica",
        textColor=colors.HexColor("#333333"), spaceAfter=6, leading=16)
    mono_style = ParagraphStyle("M", fontSize=8, fontName="Courier",
        textColor=colors.HexColor("#007755"), backColor=colors.HexColor("#f0fff8"),
        borderPadding=8, spaceAfter=10, leading=14)
    warn_style = ParagraphStyle("W", fontSize=10, fontName="Helvetica",
        textColor=colors.HexColor("#b85c00"), spaceAfter=5, leading=16)
    footer_style = ParagraphStyle("F", fontSize=8, textColor=colors.HexColor("#aaaaaa"), alignment=TA_CENTER)

    story = []

    # Header
    story.append(Spacer(1, 0.2*inch))
    story.append(Paragraph("CYBERSCAN PRO", title_style))
    story.append(Paragraph("Security Scan Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#00a878")))
    story.append(Spacer(1, 0.15*inch))

    # Meta table
    result_display = scan["result"].upper()
    meta_data = [
        ["Scan ID", f"#{scan['id']}"],
        ["Scan Type", scan["scan_type"].upper()],
        ["Target", scan["target"]],
        ["Result", result_display],
        ["Risk Score", f"{scan['score']}%"],
        ["Date & Time", scan["scanned_at"]],
    ]
    meta_table = Table(meta_data, colWidths=[1.8*inch, 5.2*inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#00a878")),
        ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#222222")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f7fffe"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.2*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))

    # File scan details
    if scan["scan_type"] == "file":
        story.append(Paragraph("Engine Analysis", section_style))

        eng = [
            ["Malicious", "Suspicious", "Harmless", "Undetected", "Total Engines"],
            [str(details.get("malicious",0)), str(details.get("suspicious",0)),
             str(details.get("harmless",0)), str(details.get("undetected",0)),
             str(details.get("total_engines",0))]
        ]
        eng_table = Table(eng, colWidths=[1.4*inch]*5)
        eng_table.setStyle(TableStyle([
            ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
            ("FONTNAME", (0,1), (-1,1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 11),
            ("ALIGN", (0,0), (-1,-1), "CENTER"),
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eafff7")),
            ("TEXTCOLOR", (0,0), (0,0), colors.HexColor("#cc2222")),
            ("TEXTCOLOR", (1,0), (1,0), colors.HexColor("#cc7700")),
            ("TEXTCOLOR", (2,0), (2,0), colors.HexColor("#007733")),
            ("TEXTCOLOR", (3,0), (3,0), colors.HexColor("#555555")),
            ("TEXTCOLOR", (0,1), (0,1), colors.HexColor("#cc2222")),
            ("TEXTCOLOR", (1,1), (1,1), colors.HexColor("#cc7700")),
            ("TEXTCOLOR", (2,1), (2,1), colors.HexColor("#007733")),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ("TOPPADDING", (0,0), (-1,-1), 12),
            ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ]))
        story.append(eng_table)
        story.append(Spacer(1, 0.1*inch))

        story.append(Paragraph("File Details", section_style))
        file_data = [
            ["File Name", details.get("filename","N/A")],
            ["File Size", f"{details.get('file_size',0)} KB"],
        ]
        f_table = Table(file_data, colWidths=[1.8*inch, 5.2*inch])
        f_table.setStyle(TableStyle([
            ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE", (0,0), (-1,-1), 10),
            ("TEXTCOLOR", (0,0), (0,-1), colors.HexColor("#00a878")),
            ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#dddddd")),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f7fffe"), colors.white]),
            ("TOPPADDING", (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
            ("LEFTPADDING", (0,0), (-1,-1), 10),
        ]))
        story.append(f_table)

        story.append(Paragraph("SHA-256 Hash", section_style))
        story.append(Paragraph(details.get("file_hash","N/A"), mono_style))

    # Website scan details
    elif scan["scan_type"] == "website":
        story.append(Paragraph("Website Vulnerability Analysis", section_style))
        issues = details.get("issues", [])
        if issues:
            story.append(Paragraph(f"{len(issues)} security issue(s) detected:", body_style))
            for issue in issues:
                story.append(Paragraph(f"  \u26a0  {issue}", warn_style))
        else:
            story.append(Paragraph("\u2713  No issues found — website appears secure.", body_style))

        story.append(Paragraph("Recommendations", section_style))
        for i, rec in enumerate([
            "Add a Content-Security-Policy header to prevent XSS attacks.",
            "Enable X-Frame-Options to block clickjacking attempts.",
            "Use Strict-Transport-Security (HSTS) to enforce HTTPS.",
            "Set X-Content-Type-Options to prevent MIME type sniffing.",
        ], 1):
            story.append(Paragraph(f"{i}.  {rec}", body_style))

    # Footer
    story.append(Spacer(1, 0.4*inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph(
        f"Generated by CyberScan Pro  \u2022  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \u2022  Powered by VirusTotal",
        footer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True,
                     download_name=f"cyberscan_report_{scan_id}.pdf",
                     mimetype="application/pdf")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
