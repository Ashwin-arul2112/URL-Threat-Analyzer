"""
predict.py
SmartPhish — PhiUSIIL-based phishing URL predictor (single-model version)
"""

import os
import joblib
import pandas as pd
import numpy as np
from feature_extraction import extract_features

# === CONFIG ===
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODEL_DIR = os.path.join(BASE_DIR, "model")

MODEL_NAME = "phiusiil_smartphish"
MODEL_PATH = os.path.join(MODEL_DIR, f"{MODEL_NAME}.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, f"{MODEL_NAME}_scaler.pkl")

# === Load model + scaler ===
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"❌ Model not found at: {MODEL_PATH}\nPlease train using model_training.py first!")

print(f"✅ Loaded model: {MODEL_PATH}")
model = joblib.load(MODEL_PATH)

scaler = None
if os.path.exists(SCALER_PATH):
    scaler = joblib.load(SCALER_PATH)
    print(f"✅ Loaded scaler: {SCALER_PATH}")
else:
    print("⚠️ No scaler found. Proceeding without scaling.")

# === Helper ===
def label_text(pred: int) -> str:
    return "🛑 PHISHING" if pred == 1 else "✅ LEGITIMATE"

# === Predict Function ===
def predict_url(url: str):
    """
    Predict phishing probability for a given URL using PhiUSIIL SmartPhish model
    """
    feats = extract_features(url)
    X = pd.DataFrame([feats])
    X_num = X.select_dtypes(include=[np.number]).fillna(-1)

    if scaler is not None:
        X_num = scaler.transform(X_num)

    prob = model.predict_proba(X_num)[0][1]
    pred = int(prob >= 0.5)

    return {
        "url": url,
        "pred": pred,
        "label": label_text(pred),
        "confidence": round(prob * 100, 2)
    }

# === CLI mode ===
if __name__ == "__main__":
    print("🧠 SmartPhish CLI — PhiUSIIL URL Detector\n(Type 'quit' to exit)\n")
    while True:
        url = input("🔗 Enter URL: ").strip()
        if url.lower() in ("quit", "exit"):
            print("👋 Goodbye!")
            break

        try:
            result = predict_url(url)
            print(f"\n🔍 Result: {result['label']}")
            print(f"🎯 Confidence: {result['confidence']}%")
        except Exception as e:
            print(f"⚠️ Error: {e}")
