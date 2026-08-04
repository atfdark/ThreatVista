import os
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from typing import List, Dict, Optional

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "isolation_forest.joblib")

class AnomalyModel:
    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.feature_names = [
            "files_copied_per_hour", "files_copied_24h", "usb_inserts_24h",
            "network_upload_mb_24h", "login_hour", "weekend_activity", "night_activity",
            "folder_access_count", "delete_freq_24h", "rename_freq_24h",
            "avg_cpu_usage", "avg_ram_usage", "avg_file_size_mb",
            "process_starts_24h", "process_stops_24h", "event_count_24h"
        ]

    def train(self, feature_matrix: np.ndarray):
        self.model = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=0.05,
            random_state=42
        )
        self.model.fit(feature_matrix)
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        joblib.dump(self.model, MODEL_PATH)

    def load(self):
        if os.path.exists(MODEL_PATH):
            self.model = joblib.load(MODEL_PATH)
            return True
        return False

    def predict(self, features: Dict) -> dict:
        if not self.model:
            if not self.load():
                return {"score": 0.0, "is_anomaly": False, "raw_score": 0.0}
        vec = np.array([[features.get(k, 0) for k in self.feature_names]], dtype=float)
        raw = self.model.decision_function(vec)[0]
        pred = self.model.predict(vec)[0]
        is_anomaly = bool(pred == -1)
        score = self._map_score(raw)
        return {"score": score, "is_anomaly": is_anomaly, "raw_score": float(raw)}

    def _map_score(self, raw):
        if raw >= 0.1:
            return max(0.0, min(30.0, raw * 100))
        if raw >= -0.1:
            return max(31.0, min(60.0, 50 + raw * 100))
        return max(61.0, min(100.0, 80 + abs(raw) * 100))
