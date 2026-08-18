from typing import List, Dict, Optional
from datetime import datetime
from ai.preprocessing import preprocess_events
from ai.features import engineer_features
from ai.dna import BehaviorDNA
from ai.model import AnomalyModel
from ai.correlation import CorrelationEngine
from ai.risk import RiskEngine
from ai.xai import ExplainableAI


def _correlation_event_window(cleaned: List[dict], recent_count: int = 20) -> List[dict]:
    """Recent events plus any USB insert/remove rows not in that slice.

    Keeps process/file burst rules focused on the latest activity while ensuring
    USB events from earlier in the session are still available for rules that
    scan the event list (e.g. evidence destruction).
    """
    recent = cleaned[-recent_count:]
    seen = {(e.get("timestamp"), e.get("event_type"), e.get("details")) for e in recent}
    extra = [
        e for e in cleaned
        if e.get("event_type") in ("usb_insert", "usb_remove")
        and (e.get("timestamp"), e.get("event_type"), e.get("details")) not in seen
    ]
    return recent + extra


class AIPipeline:
    def __init__(self, db_session=None):
        self.db = db_session
        self.dna = BehaviorDNA()
        self.model = AnomalyModel()
        self.corr = CorrelationEngine()
        self.risk = RiskEngine()
        self.xai = ExplainableAI()

    def run(
        self,
        raw_events: List[dict],
        employee_id: int,
        thresholds: Optional[Dict] = None,
        role_type: str = "General",
    ) -> Dict:
        cleaned = preprocess_events(raw_events)
        features = engineer_features(cleaned, employee_id, role_type=role_type)
        baseline = self.dna.compute_baseline(employee_id, cleaned)
        deviations = self.dna.deviation_scores(features, baseline)
        anomalies = self.model.predict(features)
        correlations = self.corr.correlate(_correlation_event_window(cleaned), features)
        risk = self.risk.calculate(features, anomalies, correlations, deviations, thresholds, role_type=role_type)
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
