"""
ThreatVista AI Security Copilot & Explainability Assistant.

Provides conversational, explainable AI assistance for SOC analysts:
- Instant quantitative & qualitative risk factor decomposition.
- MITRE ATT&CK technique mapping.
- Autonomous incident summarization.
- Prescriptive step-by-step remediation containment playbooks.
- Natural dialogue handling analyst inquiries and forensic exploration.
"""
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from sqlalchemy.orm import Session

from backend.models.database import Employee, Event, Alert, Incident, ActionRequest, BehavioralAnomalyLog, UserBehaviorProfile


def _upload_mb(value) -> float:
    """Parse strings like '24 MB' / '1.5' into a float, never raising."""
    import re as _re
    try:
        return float(_re.sub(r"[^0-9.]", "", str(value or "")) or 0)
    except ValueError:
        return 0.0


# MITRE ATT&CK Technique Knowledge Mapping
MITRE_MAPPING = [
    {
        "technique_id": "T1052.001",
        "technique_name": "Exfiltration over Physical Medium (USB)",
        "tactic": "Exfiltration",
        "condition": lambda events, alerts: any("usb" in (e.event_type or "").lower() or (e.usb_status == "inserted") for e in events)
    },
    {
        "technique_id": "T1070.004",
        "technique_name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "condition": lambda events, alerts: any("delete" in (e.event_type or "").lower() or (e.event_type == "file_delete") for e in events)
    },
    {
        "technique_id": "T1083",
        "technique_name": "File and Directory Discovery",
        "tactic": "Discovery",
        "condition": lambda events, alerts: len(events) >= 15
    },
    {
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud / Enterprise Accounts",
        "tactic": "Initial Access / Persistence",
        "condition": lambda events, alerts: any(a.severity == "High" for a in alerts)
    },
    {
        "technique_id": "T1567",
        "technique_name": "Exfiltration Over Web Service / Network",
        "tactic": "Exfiltration",
        "condition": lambda events, alerts: any(_upload_mb(e.network_upload) > 20 for e in events if e.network_upload)
    }
]


def explain_employee_risk(db: Session, employee_id: int) -> Dict[str, Any]:
    """Generate a comprehensive explainable AI breakdown for an employee's risk score."""
    emp = db.query(Employee).filter(Employee.id == employee_id).first()
    if not emp:
        return {
            "employee_id": employee_id,
            "error": "Employee not found",
            "summary": "No employee record found in database.",
        }

    # Fetch recent telemetry and evidence
    now = datetime.utcnow()
    recent_cutoff = now - timedelta(days=7)
    
    events = db.query(Event).filter(Event.employee_id == employee_id, Event.timestamp >= recent_cutoff).order_by(Event.timestamp.desc()).limit(50).all()
    alerts = db.query(Alert).filter(Alert.employee_id == employee_id).order_by(Alert.timestamp.desc()).limit(20).all()
    anomalies = db.query(BehavioralAnomalyLog).filter(BehavioralAnomalyLog.employee_id == employee_id).order_by(BehavioralAnomalyLog.detected_at.desc()).limit(10).all()
    requests = db.query(ActionRequest).filter(ActionRequest.employee_id == employee_id).order_by(ActionRequest.requested_at.desc()).limit(10).all()
    incidents = db.query(Incident).filter(Incident.employee_id == employee_id, Incident.active == True).all()

    # Decompose risk score factors
    factors = []
    total_score = emp.risk_score or 0

    # 1. Action requests & file sensitivity factor
    restricted_requests = [r for r in requests if (r.file_classification or "").upper() == "RESTRICTED"]
    confidential_requests = [r for r in requests if (r.file_classification or "").upper() == "CONFIDENTIAL"]
    if restricted_requests:
        factors.append({
            "factor": "Restricted Asset Access/Modification",
            "impact": "+35 pts",
            "severity": "CRITICAL",
            "detail": f"{len(restricted_requests)} restricted security/cryptographic asset operations intercepted (e.g. '{restricted_requests[0].target_file}').",
        })
    elif confidential_requests:
        factors.append({
            "factor": "Confidential Departmental Asset Movement",
            "impact": "+20 pts",
            "severity": "HIGH",
            "detail": f"{len(confidential_requests)} confidential files touched (e.g. '{confidential_requests[0].target_file}').",
        })

    # 2. USB activity factor
    usb_events = [e for e in events if "usb" in (e.event_type or "").lower() or (e.usb_status == "inserted")]
    if usb_events:
        factors.append({
            "factor": "External Physical Medium (USB Drive)",
            "impact": "+25 pts",
            "severity": "HIGH",
            "detail": f"USB insertion detected during staging activity ({len(usb_events)} events).",
        })

    # 3. Behavioral anomalies
    if anomalies:
        top_ano = anomalies[0]
        factors.append({
            "factor": f"Behavioral Deviation ({top_ano.severity})",
            "impact": f"+{top_ano.anomaly_score // 3} pts",
            "severity": top_ano.severity,
            "detail": f"UBA anomaly score {top_ano.anomaly_score}%: {top_ano.context or 'Significant deviation from daily working baseline'}.",
        })

    # 4. Deletion / Destruction attempts
    delete_events = [e for e in events if "delete" in (e.event_type or "").lower()]
    if delete_events:
        factors.append({
            "factor": "Unauthorized File Deletion Attempt",
            "impact": "+20 pts",
            "severity": "HIGH",
            "detail": f"{len(delete_events)} files marked for deletion, intercepted and protected by Shadow Vault.",
        })

    # If no specific factor matched but risk > 0
    if not factors and total_score > 0:
        factors.append({
            "factor": "Baseline Security Threshold Elevation",
            "impact": f"+{total_score} pts",
            "severity": "MEDIUM",
            "detail": "Accumulated minor security alerts and off-hours activity.",
        })

    # MITRE ATT&CK Mapping
    mitre_detected = []
    for mapping in MITRE_MAPPING:
        if mapping["condition"](events, alerts):
            mitre_detected.append({
                "technique_id": mapping["technique_id"],
                "technique_name": mapping["technique_name"],
                "tactic": mapping["tactic"],
            })

    # Containment Playbook
    playbook = []
    if total_score >= 75:
        playbook = [
            {"step": 1, "action": "Quarantine Endpoint Device", "priority": "IMMEDIATE", "reason": "High risk threshold breached (Score >= 75)"},
            {"step": 2, "action": "Revoke All Pending JIT Tokens", "priority": "IMMEDIATE", "reason": "Prevent exfiltration or unauthorized file releases"},
            {"step": 3, "action": "Trigger Zero-Knowledge Shadow Vault Verification", "priority": "HIGH", "reason": "Ensure all deleted assets are preserved with verified SHA-256 digests"},
            {"step": 4, "action": "Escalate to SOC Lead & Compliance", "priority": "MEDIUM", "reason": "Multi-tier dual quorum review for insider threat containment"},
        ]
    elif total_score >= 50:
        playbook = [
            {"step": 1, "action": "Enable Enhanced Endpoint Telemetry Logging", "priority": "HIGH", "reason": "Suspicious behavior detected (Score >= 50)"},
            {"step": 2, "action": "Inspect Recent USB File Movements", "priority": "HIGH", "reason": "Validate physical media staging"},
            {"step": 3, "action": "Notify Employee Manager", "priority": "MEDIUM", "reason": "Verify authorized business context for after-hours tasks"},
        ]
    else:
        playbook = [
            {"step": 1, "action": "Standard Autonomous Telemetry Monitoring", "priority": "LOW", "reason": "Employee operating within normal behavioral baseline"},
        ]

    # Executive Copilot Markdown Explanation
    md_summary = (
        f"### 🛡️ ARGUS Analysis: {emp.name} ({emp.department} — {emp.role_type})\n\n"
        f"**Risk Posture:** **{total_score}% ({emp.status.upper()})**\n\n"
        f"**Core Threat Vector:** "
        + (f"Attempted exfiltration and deletion of {factors[0]['factor']}." if factors else "Standard activity profile.")
        + "\n\n"
        f"#### Key Risk Drivers:\n"
        + "\n".join([f"- **{f['factor']}** ({f['impact']}): {f['detail']}" for f in factors])
        + "\n\n"
        f"#### MITRE ATT&CK Mapping:\n"
        + "\n".join([f"- `{m['technique_id']}` **{m['technique_name']}** ({m['tactic']})" for m in mitre_detected])
        + "\n\n"
        f"#### Recommended Immediate Actions:\n"
        + "\n".join([f"{p['step']}. **{p['action']}** [{p['priority']}]: {p['reason']}" for p in playbook])
    )

    return {
        "employee_id": emp.id,
        "employee_name": emp.name,
        "employee_department": emp.department,
        "employee_role": emp.role_type,
        "risk_score": total_score,
        "status": emp.status,
        "active_incidents": len(incidents),
        "factors": factors,
        "mitre_techniques": mitre_detected,
        "containment_playbook": playbook,
        "markdown_analysis": md_summary,
    }


def copilot_chat(
    db: Session,
    message: str,
    employee_id: Optional[int] = None,
    context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Process conversational questions from SOC analysts and return structured AI responses."""
    try:
        from backend.services.argus_engine import argus_chat
        return argus_chat(db, message, employee_id, context)
    except Exception as exc:  # never break the chat — fall back to legacy heuristics
        import logging
        logging.getLogger(__name__).exception("ARGUS engine failed, using legacy path: %s", exc)

    msg_lower = (message or "").lower().strip()
    
    # 1. Target employee analysis
    if employee_id:
        analysis = explain_employee_risk(db, employee_id)
        if "why" in msg_lower or "risk" in msg_lower or "score" in msg_lower or "explain" in msg_lower:
            return {
                "reply": analysis["markdown_analysis"],
                "data": analysis,
                "suggested_actions": [p["action"] for p in analysis["containment_playbook"]],
            }
        elif "contain" in msg_lower or "remediat" in msg_lower or "action" in msg_lower or "playbook" in msg_lower:
            actions_md = "### 📋 Prescriptive Containment Playbook\n\n" + "\n".join(
                [f"**Step {p['step']} [{p['priority']}]:** {p['action']}\n*{p['reason']}*\n" for p in analysis["containment_playbook"]]
            )
            return {
                "reply": actions_md,
                "data": analysis["containment_playbook"],
                "suggested_actions": [p["action"] for p in analysis["containment_playbook"]],
            }
        elif "mitre" in msg_lower or "attack" in msg_lower:
            mitre_md = "### 🎯 Detected MITRE ATT&CK Techniques\n\n" + "\n".join(
                [f"- `{m['technique_id']}` **{m['technique_name']}** (Tactic: *{m['tactic']}*)" for m in analysis["mitre_techniques"]]
            )
            return {
                "reply": mitre_md,
                "data": analysis["mitre_techniques"],
                "suggested_actions": ["Isolate Endpoint", "Revoke JIT Tokens"],
            }

    # 1.5 Dynamic Employee & Department Queries
    all_employees = db.query(Employee).all()
    
    # Check if asking about a specific employee
    for emp in all_employees:
        if emp.name and emp.name.lower() in msg_lower.split():
            analysis = explain_employee_risk(db, emp.id)
            return {
                "reply": analysis["markdown_analysis"],
                "data": analysis,
                "suggested_actions": [p["action"] for p in analysis["containment_playbook"]],
            }

    # Check if asking about a department
    dept_keywords = {
        "finance": "Finance", "financial": "Finance",
        "hr": "HR", "human resources": "HR",
        "engineering": "Engineering", "dev": "Engineering", "developer": "Engineering",
        "sales": "Sales", "it": "IT Support", "support": "IT Support",
        "marketing": "Marketing", "legal": "Legal"
    }
    
    for kw, real_dept in dept_keywords.items():
        if kw in msg_lower.split() or kw in msg_lower:
            dept_emps = [e for e in all_employees if e.department and real_dept.lower() in e.department.lower()]
            if dept_emps:
                avg_risk = sum((e.risk_score or 0) for e in dept_emps) / len(dept_emps)
                high_risk_count = sum(1 for e in dept_emps if (e.risk_score or 0) >= 50)
                
                bars = "█" * int(avg_risk // 5) + "░" * (20 - int(avg_risk // 5))
                
                reply_md = (
                    f"### 📊 Sector Analysis: {real_dept}\n\n"
                    f"**Average Risk Score:** {int(avg_risk)}%\n"
                    f"`[{bars}]`\n\n"
                    f"- **Total Employees:** {len(dept_emps)}\n"
                    f"- **High-Risk Profiles:** {high_risk_count}\n\n"
                )
                
                if avg_risk > 60:
                    reply_md += "⚠️ **Warning:** This sector is showing highly anomalous behavior. A deep audit is recommended."
                elif avg_risk > 30:
                    reply_md += "🟡 **Notice:** Moderate risk detected. Monitor file exfiltration activity."
                else:
                    reply_md += "✅ **Nominal:** Sector activity is within standard baselines."
                    
                return {
                    "reply": reply_md,
                    "data": {"avg_risk": avg_risk, "count": len(dept_emps)},
                    "suggested_actions": ["Show high-risk employees", "Analyze latest incident"]
                }

    # 2. General SOC questions
    if "high risk" in msg_lower or "who is risk" in msg_lower or "suspicious" in msg_lower:
        high_risk_emps = db.query(Employee).filter(Employee.risk_score >= 50).order_by(Employee.risk_score.desc()).all()
        if not high_risk_emps:
            return {
                "reply": "✅ **No high-risk employees detected.** All registered users are within acceptable baseline parameters.",
                "data": [],
                "suggested_actions": ["Run AI Baseline Pipeline", "View All Employees"],
            }
        lines = [f"- **{e.name}** ({e.department} - {e.role_type}): Risk **{e.risk_score}%** [{e.status}]" for e in high_risk_emps]
        reply_md = f"### ⚠️ Elevated Risk Personnel ({len(high_risk_emps)} detected)\n\n" + "\n".join(lines)
        return {
            "reply": reply_md,
            "data": [{"id": e.id, "name": e.name, "risk": e.risk_score, "dept": e.department} for e in high_risk_emps],
            "suggested_actions": [f"Investigate {high_risk_emps[0].name}", "Review Active Incidents"],
        }

    if "vault" in msg_lower or "rollback" in msg_lower or "encryption" in msg_lower:
        return {
            "reply": (
                "### 🛡️ ThreatVista Shadow Vault Status\n\n"
                "- **Encryption:** AES-256-GCM authenticated zero-knowledge vault.\n"
                "- **Instant Rollback:** Intercepted file deletions are restored in < 5 milliseconds.\n"
                "- **Ransomware Protection:** Supports 500-file atomic mass rollback with SHA-256 integrity validation.\n"
                "- **Key Management:** PBKDF2-HMAC-SHA256 (100,000 rounds) key derivation with automated key rotation."
            ),
            "data": {"cipher": "AES-256-GCM", "status": "ACTIVE_PROTECTED"},
            "suggested_actions": ["Trigger Ransomware Mass Rollback Demo", "Verify Vault Keys"],
        }

    import random

    # 3. Handle Greetings & Small Talk
    if msg_lower in ["hi", "hello", "hey", "greetings"]:
        greetings = [
            "Hello Analyst! I am **ARGUS**, your autonomous SOC assistant. How can I help you investigate today?",
            "Greetings! **ARGUS** is online and monitoring telemetry. What's our focus?",
            "Hi there! I'm **ARGUS**. Let me know if you need to pull forensic data or explain a risk score.",
            "System nominal. **ARGUS** here. Ready to map MITRE techniques or run playbooks."
        ]
        return {
            "reply": random.choice(greetings),
            "data": {},
            "suggested_actions": ["Show high-risk employees", "Analyze latest incident"]
        }

    if "what are u" in msg_lower or "what are you" in msg_lower or "who are you" in msg_lower:
        identities = [
            "I am **ARGUS**, the artificial intelligence brain behind ThreatVista. I analyze behavioral telemetry, intercept malicious file IO, and provide real-time SOC explainability.",
            "My designation is **ARGUS**. I am a specialized cybersecurity LLM agent designed to automate insider threat detection and generate containment playbooks.",
            "I am **ARGUS**, your AI Copilot. I ingest thousands of endpoint events per second and translate them into actionable, human-readable threat intelligence."
        ]
        return {
            "reply": random.choice(identities),
            "data": {},
            "suggested_actions": ["How does AES-256 Vault protect files?"]
        }

    # Default fallback answer (Dynamic)
    fallbacks = [
        "I'm continuously monitoring endpoint telemetry. I can help you dig into risk scores, map MITRE tactics, or generate containment playbooks. What do you need?",
        "**ARGUS ready.** I can explain complex risk behaviors or execute rapid ransomware rollbacks. Where should we begin?",
        "I didn't quite catch a specific query. Try asking me to 'Explain risk score for an employee' or 'Show active MITRE techniques'."
    ]
    
    return {
        "reply": random.choice(fallbacks),
        "data": {},
        "suggested_actions": ["Show high-risk employees", "Explain Shadow Vault AES-256", "Analyze latest incident"],
    }
