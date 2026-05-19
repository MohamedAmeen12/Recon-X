"""
ReconX - Model 4
HTTP / Traffic Anomaly Detection
Unsupervised Machine Learning Model
Algorithm: Isolation Forest
"""

import os
import joblib
import numpy as np


# Path setup
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_MODEL_PATH = os.path.join(BASE_DIR, "models", "artifacts", "model4", "model4_iforest.pkl")

class HTTPAnomalyModel:
    def __init__(self, model_path=None):
        # Lazy import to avoid slow startup
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        self.model_path = model_path or DEFAULT_MODEL_PATH

        # Feature scaler
        self.scaler = StandardScaler()

        # Isolation Forest (REAL ML)
        self.model = IsolationForest(
            n_estimators=200,
            contamination=0.1,
            random_state=42
        )

    # ==================================================
    # Feature Vector (NUMERICAL ONLY)
    # ==================================================
    def _vectorize(self, features: dict) -> np.ndarray:
        """
        Convert extracted HTTP features into ML vector
        """

        return np.array([
            features.get("missing_headers", 0),
            int(features.get("cors_wildcard", False)),
            int(features.get("server_exposed", False)),
            features.get("insecure_cookies", 0),
            features.get("response_size_kb", 0.0),
            features.get("error_rate", 0.0),
            features.get("status_entropy", 0.0),
            
            # --- Traffic Features (tcpdump) ---
            features.get("packet_count", 0),
            features.get("avg_packet_size", 0.0),
            features.get("tcp_syn_count", 0),
            features.get("udp_count", 0),
            features.get("unique_ips", 0)
        ]).reshape(1, -1)

    # ==================================================
    # TRAIN MODEL (RUN ONCE OFFLINE)
    # ==================================================
    def train(self, dataset: list):
        """
        dataset: list of feature dictionaries
        """

        X = np.vstack([self._vectorize(d) for d in dataset])
        X_scaled = self.scaler.fit_transform(X)

        self.model.fit(X_scaled)

        # Save model + scaler
        joblib.dump(
            (self.model, self.scaler),
            self.model_path
        )

        print("[OK] Model 4 trained and saved successfully")

    # ==================================================
    # LOAD TRAINED MODEL
    # ==================================================
    def load(self):
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(
                "[X] Model 4 is not trained yet. Train it first."
            )

        self.model, self.scaler = joblib.load(self.model_path)
        print("[OK] Model 4 loaded")

    # ==================================================
    # PREDICT ANOMALY
    # ==================================================
    def predict(self, features: dict) -> dict:
        """
        Input: feature dictionary from http_collector + traffic_collector.
        Output: anomaly score, status, signals, and justification.

        Two-layer detection:
          1. Rule-based signals (HTTP misconfigurations) — always evaluated.
          2. Isolation Forest ML score — evaluated when the model is loaded.
        A result is 'suspicious' if EITHER layer flags it.
        """

        # ── Layer 1: Rule-based signals (always runs) ──
        signals = self._signals(features)

        # ── Layer 2: ML score (requires trained model) ──
        ml_status = "normal"
        anomaly_score = 0.0
        ml_justification = ""

        try:
            X = self._vectorize(features)
            X_scaled = self.scaler.transform(X)
            anomaly_score = float(self.model.decision_function(X_scaled)[0])
            prediction = self.model.predict(X_scaled)[0]  # -1 = anomaly
            ml_status = "suspicious" if prediction == -1 else "normal"

            if ml_status == "suspicious":
                ml_justification = (
                    f"Isolation Forest decision score {round(anomaly_score, 4)} is below the "
                    f"anomaly threshold (0.0). Traffic features: "
                    f"packet_count={features.get('packet_count', 0)}, "
                    f"tcp_syn_count={features.get('tcp_syn_count', 0)}, "
                    f"unique_ips={features.get('unique_ips', 0)}."
                )
            else:
                ml_justification = (
                    f"Isolation Forest decision score {round(anomaly_score, 4)} is within normal "
                    f"baseline (above 0.0 threshold)."
                )
        except Exception:
            # Model not yet trained — skip ML layer, rely on rule-based signals only.
            ml_justification = "ML model not available — rule-based analysis only."

        # ── Combine both layers ──
        # Critical signals trigger suspicious regardless of ML score.
        CRITICAL_PREFIXES = (
            "CORS Policy:",
            "Missing Security Headers: 3",
            "Missing Security Headers: 4",
        )
        rule_triggered = bool(signals)
        critical_triggered = any(
            s.startswith(p) for s in signals for p in CRITICAL_PREFIXES
        )

        if ml_status == "suspicious" or critical_triggered:
            status = "suspicious"
        elif rule_triggered:
            # 2+ non-critical signals (e.g. server exposed + insecure cookies) → suspicious
            status = "suspicious" if len(signals) >= 2 else "normal"
        else:
            status = "normal"

        # ── Build justification ──
        parts = []
        if signals:
            parts.append(f"Rule-based signals detected: {'; '.join(signals)}.")
        if ml_justification:
            parts.append(ml_justification)
        if not parts:
            parts.append("No anomalies detected via rule-based or ML analysis.")

        justification = " ".join(parts)

        return {
            "model": "Model 4 - HTTP Anomaly Detection",
            "anomaly_score": round(anomaly_score, 4),
            "status": status,
            "signals": signals,
            "justification": justification,
            "traffic_data": {
                "packet_count": features.get("packet_count", 0),
                "tcp_syn_count": features.get("tcp_syn_count", 0),
                "unique_ips": features.get("unique_ips", 0)
            }
        }

    # ==================================================
    # FACTUAL FINDINGS (NO HEURISTICS)
    # ==================================================
    def _signals(self, features: dict) -> list:
        signals = []

        missing = features.get("missing_headers", 0)
        if missing >= 3:
            signals.append(f"Missing Security Headers: {missing}/4 required headers absent (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)")
        elif missing >= 1:
            signals.append(f"Missing Security Headers: {missing}/4 required security headers not set")

        if features.get("cors_wildcard", False):
            signals.append("CORS Policy: Wildcard (*) detected — allows any origin")

        if features.get("server_exposed", False):
            signals.append("Insecure Configuration: Server version header exposed")

        if features.get("insecure_cookies", 0) > 0:
            count = features.get("insecure_cookies")
            signals.append(f"Insecure Cookies: {count} cookie(s) missing Secure/HttpOnly flags")

        if features.get("error_rate", 0.0) >= 0.5:
            signals.append("Stability: High HTTP error rate (>= 50%)")

        return signals
