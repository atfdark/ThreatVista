from typing import List, Dict, Optional
from datetime import datetime
from ai.preprocessing import preprocess_events
from ai.features import engineer_features
from ai.dna import BehaviorDNA
from ai.model import AnomalyModel
from ai.correlation import CorrelationEngine
from ai.risk import RiskEngine
from ai.xai import ExplainableAI

class AIPipeline:
    def __init__(self, db_session=None):
        self.db = db_session
        self.dna = BehaviorDNA()
        self.model = AnomalyModel()
        self.corr = CorrelationEngine()
        self.risk = RiskEngine()
        self.xai = ExplainableAI()

    def run(self, raw_events: List[dict], employee_id: int, thresholds: Optional[Dict] = None) -> Dict:
        cleaned = preprocess_events(raw_events)
        features = engineer_features(cleaned, employee_id)
        baseline = self.dna.compute_baseline(employee_id, cleaned)
        deviations = self.dna.deviation_scores(features, baseline)
        anomalies = self.model.predict(features)
        correlations = self.corr.correlate(cleaned[-20:], features)
        risk = self.risk.calculate(features, anomalies, correlations, deviations, thresholds)
        explanation = self.xai.explain(features, baseline, anomalies, risk, correlations)
        return {
            "features": features,
            "baseline": baseline,
            "deviations": deviations,
            "anomalies": anomalies,
            "correlations": correlations,
            "risk": risk,
            "explanation": explanation,
            "timestamp": datetime.utcnow().isoformat()
        }
