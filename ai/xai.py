from typing import Dict, List

class ExplainableAI:
    def explain(self, features: Dict, baseline: Dict, anomalies: Dict, risk: Dict, correlations: list) -> dict:
        reasons = risk.get("reasons", [])
        recommendations = self._recommend(risk.get("status"), reasons, correlations)
        deviation = {}
        if baseline:
            try:
                from ai.dna import BehaviorDNA
                dna = BehaviorDNA()
                deviation = dna.deviation_scores(features, baseline)
            except Exception:
                pass
        return {
            "risk_score": risk.get("score"),
            "status": risk.get("status"),
            "reasons": reasons,
            "deviation": deviation,
            "recommendations": recommendations,
            "model_anomaly": anomalies.get("is_anomaly", False),
            "model_score": anomalies.get("score", 0)
        }

    def _recommend(self, status, reasons, correlations):
        recs = []
        if status == "Critical":
            recs.extend([
                "Notify Security Administrator Immediately",
                "Disable USB mass storage on endpoint",
                "Initiate forensic log collection",
                "Restrict network access to external IPs"
            ])
        elif status == "High":
            recs.extend([
                "Flag employee for security review",
                "Enable enhanced monitoring for 24 hours",
                "Restrict outbound bandwidth temporarily"
            ])
        elif status == "Medium":
            recs.extend([
                "Increase baseline recalculation frequency",
                "Alert security team for awareness"
            ])
        else:
            recs.append("Continue standard monitoring")
        return recs
