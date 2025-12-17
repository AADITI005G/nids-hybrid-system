# main.py
import os
import pickle
import numpy as np
import pandas as pd
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier

try:
    import shap
    _HAS_SHAP = True
except Exception:
    _HAS_SHAP = False

MODEL_PATH = "model.pkl"
SCALER_PATH = "scaler.pkl"
FEATURE_NAMES = ["protocol", "length", "duration", "src_bytes", "dst_bytes"]

rf_model: Optional[RandomForestClassifier] = None
scaler_full: Optional[StandardScaler] = None

class PacketFeatures(BaseModel):
    protocol: float
    length: float
    duration: float
    src_bytes: float
    dst_bytes: float

def create_mock_models():
    """Create mock model+scaler for local dev/testing if real ones are missing."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    mock_data = np.array([
        [6.0, 500.0, 1.0, 1000.0, 1000.0],
        [17.0, 100.0, 0.1, 50.0, 50.0],
        [6.0, 1200.0, 5.0, 8000.0, 2000.0],
    ])
    mock_scaler = StandardScaler()
    mock_scaler.fit(mock_data)
    with open(SCALER_PATH, "wb") as f:
        pickle.dump(mock_scaler, f)

    X_mock = mock_scaler.transform(mock_data)
    y_mock = np.array([0, 0, 1])
    mock_model = RandomForestClassifier(random_state=42)
    mock_model.fit(X_mock, y_mock)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(mock_model, f)
    print("✅ Created mock model/scaler for testing.")

def load_models():
    """Load model and scaler from disk (or create mock if missing)."""
    global rf_model, scaler_full
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        create_mock_models()

    try:
        with open(MODEL_PATH, "rb") as f:
            rf_model = pickle.load(f)
        with open(SCALER_PATH, "rb") as f:
            scaler_full = pickle.load(f)
        print("✅ Model and scaler loaded.")
    except Exception as e:
        rf_model, scaler_full = None, None
        print("❌ Error loading model/scaler:", e)

def heuristic_suggestion(top_features: List[Dict[str, Any]]) -> str:
    if not top_features:
        return "No significant features detected."
    sorted_feats = sorted(top_features, key=lambda x: abs(x.get("impact", 0)), reverse=True)
    primary = sorted_feats[0]
    feat = primary["feature"]
    value = primary.get("value", 0)

    if feat == "length":
        if value > 1000:
            return "High packet length detected — large packets may indicate potential DDoS or data exfiltration activity."
        elif value < 100:
            return "Unusually small packets detected — could indicate probing or scanning attempts."
        else:
            return "Moderate packet sizes observed — continue monitoring traffic behavior."

    elif feat == "duration":
        if value > 5:
            return "Long session durations detected — consider reviewing timeout policies and session persistence."
        else:
            return "Short bursts detected — possible scanning or bot behavior."

    elif feat in ("src_bytes", "dst_bytes"):
        if value > 5000:
            return "High byte transfer detected — large uploads/downloads may indicate data leakage."
        elif value < 50:
            return "Low byte exchange — could indicate failed or incomplete connections."
        else:
            return "Normal byte transfer activity observed."

    elif feat == "protocol":
        try:
            pv = int(value)
            if pv not in (6, 17):
                return f"Uncommon protocol ({value}) detected — verify it’s authorized in your environment."
        except Exception:
            return "Protocol value unusual — verify packets."
        return "Common protocol usage observed — continue monitoring for anomalies."

    return "Investigate the highlighted features and adjust network controls accordingly."

def compute_risk_score(probabilities, features):
    """Smart risk scoring — combines model confidence and heuristic indicators."""
    if probabilities and len(probabilities) >= 2:
        anomaly_prob = float(probabilities[1])
        anomaly_prob = min(max(anomaly_prob, 0.05), 0.95)
        risk = int(round(anomaly_prob * 100))
        # If model is extreme, fallback to heuristic boosts
        if anomaly_prob in (0.0, 1.0):
            risk = 0
            if features["length"] > 2000:
                risk += 40
            if features["duration"] > 2:
                risk += 20
            if features["src_bytes"] > 10000 or features["dst_bytes"] > 10000:
                risk += 40
            return min(100, max(10, risk))
        return max(0, min(100, risk))
    # Full fallback using features
    risk = 0
    if features["length"] > 2000:
        risk += 40
    if features["duration"] > 2:
        risk += 20
    if features["src_bytes"] > 10000 or features["dst_bytes"] > 10000:
        risk += 40
    return min(100, max(10, risk))

def fallback_explanation(scores: Dict[str, float], raw_values: Dict[str, float]) -> List[Dict[str, Any]]:
    if scores:
        items = sorted(scores.items(), key=lambda x: abs(x[1]), reverse=True)
        top = []
        for feat, imp in items[:3]:
            top.append({"feature": feat, "value": raw_values.get(feat), "impact": float(imp)})
        return top
    return [{"feature": f, "value": raw_values.get(f), "impact": 0.0} for f in FEATURE_NAMES][:3]

# FastAPI app
app = FastAPI(title="NIDS Anomaly Detection API (Explainable)")
load_models()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def read_root():
    model_status = "Loaded" if rf_model is not None else "Missing"
    return {"message": "NIDS Prediction API (Explainable)", "model_status": model_status, "shap_available": _HAS_SHAP}

@app.get("/reload")
def reload_endpoint():
    load_models()
    return {"message": "Models reloaded"}

@app.post("/predict")
def predict_anomaly(packet: PacketFeatures):
    if rf_model is None or scaler_full is None:
        raise HTTPException(status_code=503, detail="Model/scaler not loaded")

    try:
        data_dict = {k: float(v) for k, v in packet.model_dump().items()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid input: {e}")

    df = pd.DataFrame([data_dict], columns=FEATURE_NAMES)
    scaled = scaler_full.transform(df)

    pred_raw = rf_model.predict(scaled)[0]
    prediction = int(pred_raw)

    probabilities = None
    try:
        probs = rf_model.predict_proba(scaled)[0].tolist()
        probabilities = [float(p) for p in probs]
    except Exception:
        probabilities = None

    risk_score = compute_risk_score(probabilities, data_dict)

    # Explainability
    top_features = []
    if _HAS_SHAP:
        try:
            explainer = shap.TreeExplainer(rf_model)
            shap_vals = explainer.shap_values(scaled)
            if isinstance(shap_vals, list) and len(shap_vals) >= 2:
                instance_shap = np.array(shap_vals[1])[0]
            else:
                instance_shap = np.array(shap_vals)[0]
            feat_imp = {FEATURE_NAMES[i]: float(instance_shap[i]) for i in range(len(FEATURE_NAMES))}
            sorted_imp = sorted(feat_imp.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
            for feat, imp in sorted_imp:
                top_features.append({"feature": feat, "value": float(data_dict.get(feat)), "impact": float(imp)})
        except Exception as e:
            print("⚠️ SHAP failed:", e)
            if hasattr(rf_model, "feature_importances_"):
                fi = {FEATURE_NAMES[i]: float(v) for i, v in enumerate(rf_model.feature_importances_)}
                top_features = fallback_explanation(fi, data_dict)
            else:
                top_features = fallback_explanation({}, data_dict)
    else:
        if hasattr(rf_model, "feature_importances_"):
            fi = {FEATURE_NAMES[i]: float(v) for i, v in enumerate(rf_model.feature_importances_)}
            top_features = fallback_explanation(fi, data_dict)
        else:
            top_features = fallback_explanation({}, data_dict)

    suggestion = heuristic_suggestion(top_features)

    # High-risk alert
    alert = risk_score >= 70
    alert_reason = None
    if alert:
        if data_dict["length"] > 2000:
            alert_reason = "High packet length — possible flood or data leak."
        elif data_dict["duration"] > 2:
            alert_reason = "Long session — potential persistence attempt."
        elif data_dict["src_bytes"] > 10000 or data_dict["dst_bytes"] > 10000:
            alert_reason = "High byte transfer — potential data exfiltration."
        else:
            alert_reason = "Behavior deviates from normal baseline."

    return {
        "prediction": prediction,
        "probabilities": probabilities,
        "risk_score": risk_score,
        "alert": alert,
        "alert_reason": alert_reason,
        "top_features": top_features,
        "suggestion": suggestion,
        "features_used": FEATURE_NAMES,
    }

@app.post("/predict_batch")
def predict_batch(packets: List[PacketFeatures]):
    """
    Accepts a list of PacketFeatures and returns a list of responses (same structure as /predict)
    """
    if rf_model is None or scaler_full is None:
        raise HTTPException(status_code=503, detail="Model/scaler not loaded")

    responses = []
    # Build DataFrame for all records to allow vectorized scaling/predict when possible
    try:
        data_dicts = []
        for pkt in packets:
            # convert to dict with floats
            data_dicts.append({k: float(v) for k, v in pkt.model_dump().items()})
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid batch input: {e}")

    df = pd.DataFrame(data_dicts, columns=FEATURE_NAMES)
    scaled = scaler_full.transform(df)

    # Try vectorized predict/proba when supported
    try:
        preds_raw = rf_model.predict(scaled).tolist()
    except Exception:
        preds_raw = [int(rf_model.predict(scaled[[i]]))[0] for i in range(len(packets))]

    try:
        probs_all = rf_model.predict_proba(scaled).tolist()
    except Exception:
        probs_all = [None] * len(packets)

    # For SHAP explainability we can compute per-row if shap available (keep robust)
    shap_values_all = None
    if _HAS_SHAP:
        try:
            explainer = shap.TreeExplainer(rf_model)
            shap_vals = explainer.shap_values(scaled)
            shap_values_all = shap_vals
        except Exception as e:
            shap_values_all = None

    for i, data_dict in enumerate(data_dicts):
        prediction = int(preds_raw[i])
        probabilities = probs_all[i] if probs_all and isinstance(probs_all, list) else None
        risk_score = compute_risk_score(probabilities, data_dict)

        # explainability for single instance
        top_features = []
        if _HAS_SHAP and shap_values_all is not None:
            try:
                shap_vals = shap_values_all
                if isinstance(shap_vals, list) and len(shap_vals) >= 2:
                    inst_shap = np.array(shap_vals[1])[i]
                else:
                    inst_shap = np.array(shap_vals)[i]
                feat_imp = {FEATURE_NAMES[j]: float(inst_shap[j]) for j in range(len(FEATURE_NAMES))}
                sorted_imp = sorted(feat_imp.items(), key=lambda x: abs(x[1]), reverse=True)[:3]
                for feat, imp in sorted_imp:
                    top_features.append({"feature": feat, "value": float(data_dict.get(feat)), "impact": float(imp)})
            except Exception:
                top_features = fallback_explanation({}, data_dict)
        else:
            if hasattr(rf_model, "feature_importances_"):
                fi = {FEATURE_NAMES[j]: float(v) for j, v in enumerate(rf_model.feature_importances_)}
                top_features = fallback_explanation(fi, data_dict)
            else:
                top_features = fallback_explanation({}, data_dict)

        suggestion = heuristic_suggestion(top_features)

        alert = risk_score >= 70
        alert_reason = None
        if alert:
            if data_dict["length"] > 2000:
                alert_reason = "High packet length — possible flood or data leak."
            elif data_dict["duration"] > 2:
                alert_reason = "Long session — potential persistence attempt."
            elif data_dict["src_bytes"] > 10000 or data_dict["dst_bytes"] > 10000:
                alert_reason = "High byte transfer — potential data exfiltration."
            else:
                alert_reason = "Behavior deviates from normal baseline."

        resp = {
            "prediction": int(prediction),
            "probabilities": probabilities,
            "risk_score": risk_score,
            "alert": alert,
            "alert_reason": alert_reason,
            "top_features": top_features,
            "suggestion": suggestion,
            "features_used": FEATURE_NAMES,
        }
        responses.append(resp)

    return responses
