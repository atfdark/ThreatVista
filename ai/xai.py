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
            "model_score": anomalies.get("score", 0),
            "confidence": self._confidence(risk, deviations=deviation, anomalies=anomalies),
        }

    def _confidence(self, risk: Dict, deviations: Dict, anomalies: Dict) -> int:
        """Estimate how confident the engine is in its assessment (0-100).

        Rises with the strength of evidence: number of detected risk factors,
        magnitude of behavior deviations from baseline, and whether the
        Isolation Forest flagged an anomaly.
        """
        evidence = len(risk.get("reasons", [])) * 8
        if anomalies.get("is_anomaly"):
            evidence += 10
        dev_sum = sum(
            abs(v) for v in deviations.values() if isinstance(v, (int, float))
        )
        evidence += min(12, dev_sum / 100.0)
        return round(min(99, max(50, 50 + evidence)))

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
