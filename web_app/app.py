import sys
import os
import io
import socket
import logging
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
import base64
import matplotlib.pyplot as plt
import seaborn as sns

from flask import (
    Flask, render_template, request, jsonify, send_file,
    session, redirect, url_for
)
from pymongo import MongoClient
from bson.objectid import ObjectId
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4

# ----------------------------------------------------------------------
# Paths & bootstrap
# ----------------------------------------------------------------------
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SRC_DIR = os.path.join(BASE_DIR, 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from feature_extraction import extract_features
from live_scan import live_scan

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'web_app', 'templates'))
app.secret_key = os.environ.get("FLASK_SECRET", "supersecretkey")

# ----------------------------------------------------------------------
# Custom JSON Provider for ObjectId / datetime serialization
# ----------------------------------------------------------------------
try:
    from flask.json.provider import DefaultJSONProvider

    class CustomJSONProvider(DefaultJSONProvider):
        def default(self, o):
            if isinstance(o, ObjectId):
                return str(o)
            if isinstance(o, datetime):
                return o.isoformat()
            return super().default(o)

    app.json = CustomJSONProvider(app)
except Exception:
    app.logger.warning("DefaultJSONProvider unavailable. Using manual conversion fallback.")


def make_serializable(obj):
    """Safely converts MongoDB and datetime types for JSON output."""
    if isinstance(obj, dict):
        return {k: make_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_serializable(v) for v in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    return obj


# ----------------------------------------------------------------------
# Model & scaler loading
# ----------------------------------------------------------------------
MODEL_DIR = os.path.join(BASE_DIR, "model")
MODEL_PATH = os.path.join(MODEL_DIR, "phiusiil_smartphish.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "phiusiil_smartphish_scaler.pkl")

model, scaler = None, None
try:
    if os.path.exists(MODEL_PATH):
        model = joblib.load(MODEL_PATH)
        app.logger.info(f"Loaded model: {MODEL_PATH}")
    else:
        app.logger.warning(f"Model not found at {MODEL_PATH}")

    if os.path.exists(SCALER_PATH):
        scaler = joblib.load(SCALER_PATH)
        app.logger.info(f"Loaded scaler: {SCALER_PATH}")
    else:
        app.logger.info("Scaler not found — skipping normalization.")
except Exception as e:
    app.logger.exception("Failed to load model/scaler: %s", e)

# ----------------------------------------------------------------------
# MongoDB setup
# ----------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)

try:
    client.server_info()
    app.logger.info("Connected to MongoDB")
except Exception as e:
    app.logger.warning(f"Could not connect to MongoDB: {e}")

db = client.url_risk_db
scans_collection = db.scans
live_scans_collection = db.live_scans

# ----------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------
def preprocess_features(feat_dict):
    """Convert feature dict to DataFrame, scale if possible."""
    df = pd.DataFrame([feat_dict])
    df = df.select_dtypes(include=[np.number]).fillna(-1)
    if scaler is not None:
        try:
            arr = scaler.transform(df)
            return pd.DataFrame(arr, columns=df.columns)
        except Exception as e:
            app.logger.warning("Scaling failed: %s", e)
    return df


def save_ml_scan_to_db(url, pred, proba, feat_dict):
    """Save ML scan results to MongoDB and return the document."""
    try:
        final_domain, ip = None, None
        try:
            if "://" in url:
                final_domain = url.split("/")[2]
            else:
                final_domain = url.split("/")[0]
            ip = socket.gethostbyname(final_domain)
        except Exception:
            pass

        scan_doc = {
            "url": url,
            "result": "risky" if int(pred) == 1 else "safe",
            "score": float(proba),
            "model_used": "phiusiil_smartphish",
            "timestamp": datetime.utcnow(),
            "details": {
                "final_url": url,
                "final_domain": final_domain,
                "ip": ip,
                "features_used": feat_dict,
            },
        }
        inserted = scans_collection.insert_one(scan_doc)
        scan_doc["_id"] = inserted.inserted_id
        return scan_doc
    except Exception as e:
        app.logger.exception("Failed to save ML scan: %s", e)
        return None


def save_live_scan_to_db(scan_result):
    """Persist live scan dict into MongoDB."""
    try:
        scan_result = dict(scan_result)
        scan_result["timestamp"] = datetime.utcnow()
        res = live_scans_collection.insert_one(scan_result)
        return bool(res.inserted_id)
    except Exception as e:
        app.logger.exception("Failed to save live scan: %s", e)
        return False


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------
@app.route("/")
def index():
    """Homepage with recent scans."""
    try:
        recent_scans = list(scans_collection.find().sort("timestamp", -1).limit(10))
    except Exception as e:
        app.logger.warning(f"Could not fetch recent scans: {e}")
        recent_scans = []
    return render_template("index.html", recent_scans=recent_scans, model_loaded=bool(model))


# ---------------- API: ML Scan ----------------
@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Perform ML-based scan."""
    data = request.get_json(force=True, silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL required"}), 400
    if model is None:
        return jsonify({"error": "Model not loaded"}), 500

    url = data["url"]
    try:
        feat_dict = extract_features(url)
        X = preprocess_features(feat_dict)
        pred = int(model.predict(X)[0])
        proba = float(model.predict_proba(X)[0][1])

        scan_doc = save_ml_scan_to_db(url, pred, proba, feat_dict)

        response = {
            "url": url,
            "result": "risky" if pred == 1 else "safe",
            "score": round(proba, 4),
            "timestamp": datetime.utcnow().isoformat(),
            "details": make_serializable(scan_doc or {}),
        }
        return jsonify(response)
    except Exception as e:
        app.logger.exception("ML scan failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ---------------- API: Live Scan ----------------
@app.route("/api/live_scan", methods=["POST"])
def api_live_scan():
    """Perform network/WHOIS scan."""
    data = request.get_json(force=True, silent=True)
    if not data or "url" not in data:
        return jsonify({"error": "URL required"}), 400

    try:
        result = live_scan(data["url"])
        save_live_scan_to_db(result)
        return jsonify({
            "url": data["url"],
            "status": "completed",
            "result": make_serializable(result)
        })
    except Exception as e:
        app.logger.exception("Live scan failed: %s", e)
        return jsonify({"error": str(e)}), 500


# ---------------- View Live Scans ----------------
@app.route("/live_scans")
def view_live_scans():
    try:
        scans = list(live_scans_collection.find().sort("timestamp", -1).limit(50))
    except Exception as e:
        app.logger.warning(f"Could not fetch live scans: {e}")
        scans = []
    return render_template("live_scans.html", scans=scans)


# ---------------- Batch Scanning ----------------
@app.route("/batch", methods=["GET", "POST"])
def batch_scan():
    if request.method == "POST":
        file = request.files.get("csv_file")
        if not file:
            return "No file uploaded", 400

        try:
            df = pd.read_csv(file)
        except Exception as e:
            return f"Failed to read uploaded CSV: {e}", 400

        scores, results = [], []
        for url in df.iloc[:, 0].astype(str):
            try:
                feat_dict = extract_features(url)
                X = preprocess_features(feat_dict)
                if model:
                    pred = int(model.predict(X)[0])
                    proba = float(model.predict_proba(X)[0][1])
                else:
                    pred, proba = 0, 0.0
                scores.append(proba)
                results.append("risky" if pred == 1 else "safe")
                save_ml_scan_to_db(url, pred, proba, feat_dict)
            except Exception as e:
                app.logger.warning(f"Batch scan error for {url}: {e}")
                scores.append(0.0)
                results.append("error")

        df["score"], df["result"] = scores, results
        session["batch_df"] = df.to_dict(orient="records")

        # Heatmap
        plt.figure(figsize=(12, 1.2))
        sns.heatmap([scores], cmap="Reds", cbar=False, xticklabels=False, yticklabels=False)
        buf = io.BytesIO()
        plt.savefig(buf, format="png", bbox_inches="tight")
        buf.seek(0)
        session["heatmap_data"] = base64.b64encode(buf.getvalue()).decode()
        plt.close()

        return redirect(url_for("batch_result"))

    return render_template("batch.html", model_loaded=bool(model))


@app.route("/batch_result")
def batch_result():
    df = session.get("batch_df")
    heatmap_data = session.get("heatmap_data")
    if not df or not heatmap_data:
        return redirect(url_for("batch_scan"))
    return render_template("batch_result.html", df=df, heatmap_data=heatmap_data)


@app.route("/download_batch/<file_format>")
def download_batch(file_format):
    records = session.get("batch_df")
    if not records:
        return "No batch available", 400

    df = pd.DataFrame(records)
    buf = io.BytesIO()
    if file_format == "csv":
        df.to_csv(buf, index=False)
        buf.seek(0)
        return send_file(buf, download_name="batch_scan.csv", mimetype="text/csv", as_attachment=True)
    elif file_format == "excel":
        df.to_excel(buf, index=False)
        buf.seek(0)
        return send_file(
            buf,
            download_name="batch_scan.xlsx",
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            as_attachment=True,
        )
    return "Invalid format", 400


# ---------------- Dashboard ----------------
@app.route("/dashboard")
def dashboard():
    try:
        total = scans_collection.count_documents({})
        safe_count = scans_collection.count_documents({"result": "safe"})
        risky_count = scans_collection.count_documents({"result": "risky"})
        recent = list(scans_collection.find().sort("timestamp", -1).limit(10))
        pipeline = [
            {"$match": {"result": "risky"}},
            {"$group": {"_id": "$details.final_domain", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ]
        top_risky_domains = list(scans_collection.aggregate(pipeline))
    except Exception as e:
        app.logger.exception("Dashboard error: %s", e)
        total = safe_count = risky_count = 0
        recent, top_risky_domains = [], []
    return render_template("dashboard.html",
                           total=total, safe_count=safe_count, risky_count=risky_count,
                           recent=recent, top_risky_domains=top_risky_domains)


# ---------------- Reports ----------------
@app.route("/report/view/<string:scan_id>")
def report_view(scan_id):
    try:
        scan = scans_collection.find_one({"_id": ObjectId(scan_id)})
        if not scan:
            return "Scan not found", 404
        return render_template("report_view.html", scan=scan, zip=zip)
    except Exception as e:
        app.logger.exception("Report view failed: %s", e)
        return "Internal server error", 500


@app.route("/report/download/<string:scan_id>")
def report_download(scan_id):
    try:
        scan = scans_collection.find_one({"_id": ObjectId(scan_id)})
        if not scan:
            return "Scan not found", 404

        buf = io.BytesIO()
        c = canvas.Canvas(buf, pagesize=A4)
        w, h = A4

        c.setFont("Helvetica-Bold", 16)
        c.drawString(40, h - 40, "URL Threat Analysis Report")

        c.setFont("Helvetica", 11)
        c.drawString(40, h - 70, f"URL: {scan.get('url', '')}")
        c.drawString(40, h - 90, f"Result: {scan.get('result', '').upper()} (Score: {scan.get('score', 0):.3f})")

        ts = scan.get("timestamp")
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ts, datetime) else str(ts)
        c.drawString(40, h - 110, f"Scanned at: {ts_str}")
        c.drawString(40, h - 130, f"Model used: {scan.get('model_used', 'N/A')}")

        y = h - 160
        c.drawString(40, y, "Details:")
        y -= 20
        for k, v in scan.get("details", {}).items():
            if y < 80:
                c.showPage()
                y = h - 40
            c.drawString(60, y, f"{k}: {v}")
            y -= 14

        c.save()
        buf.seek(0)
        return send_file(buf, as_attachment=True,
                         download_name=f"report_{scan_id}.pdf",
                         mimetype="application/pdf")
    except Exception as e:
        app.logger.exception("Report download failed: %s", e)
        return "Internal server error", 500


# ----------------------------------------------------------------------
# Run
# ----------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(debug=True, host="0.0.0.0", port=5000, use_reloader=False)
