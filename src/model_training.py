"""
model_training.py
Enhanced PhiUSIIL-compatible phishing URL detector.
Trains an ensemble (XGBoost + RandomForest) using 54+ extracted features.
Now fully compatible with predict.py by training only on numeric features.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, classification_report,
    roc_auc_score, confusion_matrix
)
from sklearn.preprocessing import StandardScaler
import joblib
from feature_extraction import extract_features

# --- Directories ---
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "model")

os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# --- Settings ---
N_JOBS = 6  # parallel threads
SAMPLE_URL = "http://example.com"
FEATURE_ORDER = list(extract_features(SAMPLE_URL).keys())
APPLY_SCALING = True


# ==========================================================
# 1. Prepare features
# ==========================================================
def prepare_features(data_csv: str) -> pd.DataFrame:
    """Load dataset and generate missing features if not present."""
    if not os.path.exists(data_csv):
        raise FileNotFoundError(f"Dataset not found: {data_csv}")

    df = pd.read_csv(data_csv)
    print(f"Loaded dataset: {data_csv}  ({df.shape[0]} rows)")

    # Normalize column names
    df.columns = [c.strip().capitalize() for c in df.columns]

    # Verify essential columns
    if 'Label' not in df.columns:
        raise ValueError("Dataset must contain a 'Label' column.")
    if 'Url' not in df.columns:
        raise ValueError("Dataset must contain a 'URL' column.")

    # Rename for consistency
    df.rename(columns={'Url': 'URL'}, inplace=True)

    # Remove duplicate columns if any
    df = df.loc[:, ~df.columns.duplicated()]

    # Compute missing feature columns if needed
    missing = [f for f in FEATURE_ORDER if f not in df.columns]
    if missing:
        print(f"Computing missing features for {len(missing)} fields...")
        feats = df['URL'].apply(lambda u: pd.Series(extract_features(u)))
        df = pd.concat([df.drop(columns=['URL']), feats], axis=1)
        enriched_path = os.path.join(DATA_DIR, "features_auto_generated.csv")
        df.to_csv(enriched_path, index=False)
        print(f"Saved enriched feature CSV to {enriched_path}")
    else:
        print("All required features found in dataset.")

    return df


# ==========================================================
# 2. Train Model
# ==========================================================
def train_model(data_csv: str, model_name: str = "phiusiil_smartphish"):
    """Train ensemble model (XGBoost + RandomForest) on extracted numeric features."""
    model_path = os.path.join(MODEL_DIR, f"{model_name}.pkl")
    scaler_path = os.path.join(MODEL_DIR, f"{model_name}_scaler.pkl")

    # Load and preprocess
    df = prepare_features(data_csv)

    # Features and labels
    X = df[FEATURE_ORDER].copy()
    y = df['Label'].astype(int)

    # Keep only numeric columns (drop strings like URL, TLD, Registrar, etc.)
    non_numeric_cols = X.select_dtypes(exclude=[np.number]).columns.tolist()
    if non_numeric_cols:
        print(f"Dropping non-numeric columns before training: {non_numeric_cols}")
        X.drop(columns=non_numeric_cols, inplace=True)

    # Replace missing or infinite values
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    X.fillna(-1, inplace=True)

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Feature scaling
    if APPLY_SCALING:
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X_train)
        X_test = scaler.transform(X_test)
        joblib.dump(scaler, scaler_path)
        print(f"Feature scaler saved to {scaler_path}")

    # Define ensemble models
    print(f"Training ensemble model: {model_name}")
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        eval_metric='logloss',
        use_label_encoder=False,
        random_state=42,
        n_jobs=N_JOBS
    )

    rf = RandomForestClassifier(
        n_estimators=350,
        n_jobs=N_JOBS,
        random_state=42
    )

    ensemble = VotingClassifier(
        estimators=[('xgb', xgb), ('rf', rf)],
        voting='soft',
        n_jobs=N_JOBS
    )

    # Train the ensemble
    ensemble.fit(X_train, y_train)

    # Evaluate
    y_pred = ensemble.predict(X_test)
    y_prob = ensemble.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_prob)
    cm = confusion_matrix(y_test, y_pred)

    print("\nModel Evaluation Results:")
    print(f"Accuracy:  {acc:.4f}")
    print(f"ROC-AUC:   {auc:.4f}")
    print("Confusion Matrix:\n", cm)
    print("\nClassification Report:\n", classification_report(y_test, y_pred))

    # Save model
    joblib.dump(ensemble, model_path)
    print(f"Model saved to: {model_path}")

    return ensemble


# ==========================================================
# 3. Entry Point
# ==========================================================
if __name__ == "__main__":
    csv_path = os.path.join(DATA_DIR, "phish_url.csv")
    train_model(csv_path, "phiusiil_smartphish")
