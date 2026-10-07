"""
ARGUS — Conversational Security Intelligence Engine for ThreatVista.

Two-tier architecture:

1. **Grounded LLM mode (optional)** — if ``GEMINI_API_KEY`` (or ``GOOGLE_API_KEY``)
   is present in the environment / ``.env``, ARGUS retrieves the relevant
   telemetry from the database (RAG) and asks Gemini to write a natural answer
   grounded strictly in that evidence. Any failure silently falls back to (2).

2. **Native reasoning engine (always available, offline)** — intent detection,
   fuzzy employee/department resolution, pronoun follow-ups ("what did *she*
   do?"), time-window parsing ("after 8 PM", "last 24 hours", "today"),
   per-employee activity dossiers, org-wide analytics and a cybersecurity
   knowledge base. Produces ChatGPT-style markdown (headings, tables, lists).
"""
from __future__ import annotations

import difflib
import json
import os
import random
import re
import urllib.request
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

try:  # make sure .env is loaded so GEMINI_API_KEY is visible
    import backend.config  # noqa: F401
except Exception:  # pragma: no cover
    pass

from backend.models.database import (
    ActionRequest,
    Alert,
    BehavioralAnomalyLog,
    Device,
    Employee,
    Event,
    ExfiltrationPredictionLog,
    Incident,
)

# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------
COMMON_WORDS = {
    "the", "and", "for", "are", "was", "who", "what", "why", "how", "show", "tell", "about",
    "her", "his", "him", "she", "they", "them", "their", "this", "that", "with", "from", "did",
    "does", "doing", "done", "any", "all", "can", "you", "your", "me", "my", "our", "list",
    "give", "explain", "risk", "score", "user", "employee", "employees", "staff", "file", "files",
    "usb", "today", "week", "month", "hours", "after", "before", "last", "recent", "latest",
    "high", "low", "top", "most", "less", "more", "actions", "action", "activity", "activities",
    "problem", "problems", "issue", "issues", "please", "info", "information", "details", "detail",
    "finance", "sales", "legal", "marketing", "engineering", "support", "security", "admin",
    "report", "summary", "compare", "versus", "between", "incident", "incidents", "alert", "alerts",
    "mitre", "attack", "playbook", "vault", "data", "network", "upload", "uploads", "device",
    "has", "have", "had", "been", "will", "would", "should", "could", "there", "here", "where",
    "when", "which", "not", "yes", "no", "hello", "hey", "thanks", "thank", "know", "doing",
    "happened", "happen", "timeline", "history", "profile", "status", "safe", "trust", "suspicious",
}

PRONOUNS = {"he", "she", "her", "his", "him", "they", "their", "them", "this employee",
            "that employee", "this user", "that user", "this person", "same person"}

DEPARTMENTS = {
    "finance": "Finance", "financial": "Finance", "accounts": "Finance", "accounting": "Finance",
    "hr": "HR", "human resources": "HR", "people team": "HR",
    "engineering": "Engineering", "engineers": "Engineering", "developers": "Engineering",
    "dev team": "Engineering", "r&d": "Engineering",
    "sales": "Sales", "it support": "IT", "it department": "IT", "it team": "IT", "helpdesk": "IT",
    "marketing": "Marketing", "legal": "Legal", "operations": "Operations",
    "security team": "Security", "executive": "Executive",
}

FACETS = {
    "usb": ["usb", "pendrive", "pen drive", "thumb drive", "flash drive", "removable", "external drive"],
    "delete": ["delete", "deleted", "deletion", "deleting", "wipe", "wiped", "destroy", "removed", "erase"],
    "upload": ["upload", "uploaded", "exfil", "exfiltration", "network", "cloud", "transfer", "sent out", "leak"],
    "files": ["file", "files", "document", "documents", "accessed", "opened", "copied", "copy", "modified", "folder"],
    "alerts": ["alert", "alerts", "warning", "warnings", "flag", "flagged"],
    "incidents": ["incident", "incidents", "case", "cases", "breach"],
    "requests": ["approval", "approvals", "request", "requests", "jit", "pending", "ticket", "permission"],
    "anomaly": ["anomaly", "anomalies", "unusual", "deviation", "baseline", "behavior", "behaviour", "abnormal"],
    "device": ["device", "laptop", "endpoint", "machine", "hostname", "computer", "online", "offline", "agent"],
    "mitre": ["mitre", "att&ck", "attack technique", "technique", "techniques", "tactic", "ttp"],
    "playbook": ["contain", "containment", "remediat", "playbook", "respond", "response", "what should",
                 "next step", "recommend", "mitigate", "what to do", "how to handle", "how do we handle"],
    "risk": ["why", "risk", "score", "explain", "dangerous", "threat level", "risky"],
    "activity": ["did", "do ", "doing", "action", "actions", "activity", "activities", "timeline",
                 "history", "happened", "up to", "behave", "what has", "events", "log", "logs"],
    "problem": ["problem", "issue", "concern", "safe", "trust", "malicious", "suspicious", "wrong",
                "threat", "insider", "guilty", "red flag", "worried", "worry", "clean"],
}


def _has(msg: str, words) -> bool:
    for w in words:
        if " " in w or not w.isalpha():
            if w in msg:
                return True
        elif re.search(rf"\b{re.escape(w)}\b", msg):
            return True
    return False


def _detect_facets(msg: str) -> List[str]:
    return [f for f, kws in FACETS.items() if _has(msg, kws)]


# ---------------------------------------------------------------------------
# Time window parsing
# ---------------------------------------------------------------------------
def _parse_time_window(msg: str) -> Dict[str, Any]:
    now = datetime.utcnow()
    win: Dict[str, Any] = {"since": None, "label": None, "hour_min": None, "hour_max": None, "off_hours": False}

    m = re.search(r"last\s+(\d+)\s*(hour|hr|day|week|month)s?", msg)
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {"hour": timedelta(hours=n), "hr": timedelta(hours=n), "day": timedelta(days=n),
                 "week": timedelta(weeks=n), "month": timedelta(days=30 * n)}[unit]
        win["since"], win["label"] = now - delta, f"last {n} {unit}{'s' if n > 1 else ''}"
    elif "today" in msg:
        win["since"], win["label"] = now.replace(hour=0, minute=0, second=0, microsecond=0), "today"
    elif "yesterday" in msg:
        win["since"], win["label"] = now - timedelta(days=1), "since yesterday"
    elif re.search(r"\b(this|past|last)\s+week\b", msg):
        win["since"], win["label"] = now - timedelta(days=7), "past 7 days"
    elif re.search(r"\b(this|past|last)\s+month\b", msg):
        win["since"], win["label"] = now - timedelta(days=30), "past 30 days"

    m = re.search(r"after\s+(\d{1,2})\s*(am|pm)?", msg)
    if m:
        h = int(m.group(1)) % 12 + (12 if (m.group(2) == "pm" or (not m.group(2) and int(m.group(1)) < 7)) else 0)
        win["hour_min"] = h
        win["label"] = (win["label"] + ", " if win["label"] else "") + f"after {m.group(1)}{(m.group(2) or 'pm').upper()}"
    m = re.search(r"before\s+(\d{1,2})\s*(am|pm)?", msg)
    if m:
        h = int(m.group(1)) % 12 + (12 if m.group(2) == "pm" else 0)
        win["hour_max"] = h
        win["label"] = (win["label"] + ", " if win["label"] else "") + f"before {m.group(1)}{(m.group(2) or 'am').upper()}"
    if _has(msg, ["after hours", "after-hours", "off hours", "off-hours", "night", "late night", "midnight", "weekend"]):
        win["off_hours"] = True
        win["label"] = (win["label"] + ", " if win["label"] else "") + "off-hours"
    return win


def _in_window(ts: Optional[datetime], win: Dict[str, Any]) -> bool:
    if ts is None:
        return False
    if win["since"] and ts < win["since"]:
        return False
    if win["hour_min"] is not None and ts.hour < win["hour_min"]:
        return False
    if win["hour_max"] is not None and ts.hour >= win["hour_max"]:
        return False
    if win["off_hours"] and 7 <= ts.hour < 20 and ts.weekday() < 5:
        return False
    return True


# ---------------------------------------------------------------------------
# Entity resolution
# ---------------------------------------------------------------------------
def _resolve_employees(msg: str, employees: List[Employee]) -> List[Employee]:
    tokens = [t for t in re.findall(r"[a-z]+", msg) if len(t) >= 3 and t not in COMMON_WORDS]
    scored: List[Tuple[float, Employee]] = []
    for emp in employees:
        if not emp.name:
            continue
        name = emp.name.lower().strip()
        parts = [p for p in re.findall(r"[a-z]+", name) if len(p) >= 2]
        score = 0.0
        if name and name in msg:
            score = 10
        elif parts and all(re.search(rf"\b{re.escape(p)}\b", msg) for p in parts):
            score = 9
        else:
            for t in tokens:
                if parts and t == parts[0]:
                    score = max(score, 6)          # first name
                elif t in parts:
                    score = max(score, 4)          # last / middle name
                elif parts and difflib.get_close_matches(t, parts, n=1, cutoff=0.84):
                    score = max(score, 2.5)        # typo tolerant
            if emp.email and emp.email.split("@")[0].lower() in tokens:
                score = max(score, 7)
        if score:
            scored.append((score, emp))
    if not scored:
        return []
    scored.sort(key=lambda x: (-x[0], -(x[1].risk_score or 0)))
    best = scored[0][0]
    # Keep everyone mentioned explicitly (score >= 6) plus ties at the top score
    return [e for s, e in scored if s >= 6 or s == best]


def _resolve_department(msg: str) -> Optional[str]:
    for kw in sorted(DEPARTMENTS, key=len, reverse=True):
        if re.search(rf"\b{re.escape(kw)}\b", msg):
            return DEPARTMENTS[kw]
    return None


def _employees_in_dept(employees: List[Employee], dept: str) -> List[Employee]:
    d = dept.lower()
    return [e for e in employees if e.department and (d in e.department.lower() or e.department.lower() in d)]


def _employee_from_history(history: List[Dict[str, str]], employees: List[Employee]) -> Optional[Employee]:
    for turn in reversed(history or []):
        text = (turn.get("text") or "").lower()
        found = _resolve_employees(text, employees)
        if found:
            return found[0]
    return None


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def _ago(ts: Optional[datetime]) -> str:
    if not ts:
        return "unknown time"
    s = (datetime.utcnow() - ts).total_seconds()
    if s < 60:
        return "just now"
    if s < 3600:
        return f"{int(s // 60)} min ago"
    if s < 86400:
        return f"{int(s // 3600)} h ago"
    return f"{int(s // 86400)} d ago"


def _fmt_ts(ts: Optional[datetime]) -> str:
    return ts.strftime("%d %b %H:%M") if ts else "—"


def _bar(value: float, width: int = 20) -> str:
    v = max(0, min(100, value))
    filled = int(round(v / 100 * width))
    return "█" * filled + "░" * (width - filled)


def _risk_label(score: int) -> str:
    if score >= 75:
        return "🔴 Critical"
    if score >= 50:
        return "🟠 Elevated"
    if score >= 25:
        return "🟡 Guarded"
    return "🟢 Low"


def _safe_mb(v: Optional[str]) -> float:
    if not v:
        return 0.0
    try:
        return float(re.sub(r"[^0-9.]", "", str(v)) or 0)
    except ValueError:
        return 0.0


def _describe_event(e: Event) -> str:
    et = (e.event_type or "event").lower()
    target = (e.filename or e.details or "").replace("|", "/").strip()
    if len(target) > 70:
        target = target[:67].rstrip() + "…"
    folder = f" in `{e.folder}`" if e.folder else ""
    if "usb" in et or e.usb_status == "inserted":
        return f"🔌 USB device activity{(' — ' + target) if target else ''}"
    if "delete" in et:
        return f"🗑️ Deleted `{target}`{folder}" if target else "🗑️ File deletion"
    if "copy" in et:
        return f"📋 Copied `{target}`{folder}" if target else "📋 File copy"
    if "upload" in et or "network" in et or e.network_upload:
        size = f" ({e.network_upload})" if e.network_upload else ""
        return f"🌐 Network upload{size}{(' — ' + target) if target else ''}"
    if "modif" in et or "write" in et:
        return f"✏️ Modified `{target}`{folder}" if target else "✏️ File modification"
    if "create" in et:
        return f"📄 Created `{target}`{folder}" if target else "📄 File created"
    if "rename" in et or "move" in et:
        return f"🔀 Moved/renamed `{target}`" if target else "🔀 File moved"
    if "login" in et or "logon" in et:
        return "🔑 Login session"
    if "process" in et:
        return f"⚙️ Process launched{(' — ' + target) if target else ''}"
    return f"• {et.replace('_', ' ').title()}{(' — `' + target + '`') if target else ''}"


def _is_usb(e: Event) -> bool:
    return "usb" in (e.event_type or "").lower() or e.usb_status == "inserted"


def _is_delete(e: Event) -> bool:
    return "delete" in (e.event_type or "").lower()


def _is_upload(e: Event) -> bool:
    et = (e.event_type or "").lower()
    return "upload" in et or "network" in et or _safe_mb(e.network_upload) > 0


# ---------------------------------------------------------------------------
# Evidence gathering
# ---------------------------------------------------------------------------
def _gather(db: Session, emp: Employee, win: Dict[str, Any]) -> Dict[str, Any]:
    q = db.query(Event).filter(Event.employee_id == emp.id)
    if win.get("since"):
        q = q.filter(Event.timestamp >= win["since"])
    events = [e for e in q.order_by(Event.timestamp.desc()).limit(400).all() if _in_window(e.timestamp, win)]
    alerts = db.query(Alert).filter(Alert.employee_id == emp.id).order_by(Alert.timestamp.desc()).limit(25).all()
    incidents = db.query(Incident).filter(Incident.employee_id == emp.id).order_by(Incident.created_at.desc()).limit(10).all()
    requests = db.query(ActionRequest).filter(ActionRequest.employee_id == emp.id).order_by(ActionRequest.requested_at.desc()).limit(15).all()
    anomalies = db.query(BehavioralAnomalyLog).filter(BehavioralAnomalyLog.employee_id == emp.id).order_by(BehavioralAnomalyLog.detected_at.desc()).limit(10).all()
    device = db.query(Device).filter(Device.employee_id == emp.id).first()
    try:
        exfil = db.query(ExfiltrationPredictionLog).filter(ExfiltrationPredictionLog.employee_id == emp.id).order_by(ExfiltrationPredictionLog.predicted_at.desc()).first()
    except Exception:
        exfil = None
    if win.get("since") or win.get("hour_min") is not None or win.get("off_hours"):
        alerts = [a for a in alerts if _in_window(a.timestamp, win)]
        requests = [r for r in requests if _in_window(r.requested_at, win)]
        anomalies = [a for a in anomalies if _in_window(a.detected_at, win)]
    return {
        "events": events, "alerts": alerts, "incidents": incidents, "requests": requests,
        "anomalies": anomalies, "device": device, "exfil": exfil,
        "usb": [e for e in events if _is_usb(e)],
        "deletes": [e for e in events if _is_delete(e)],
        "uploads": [e for e in events if _is_upload(e)],
        "off_hours": [e for e in events if e.timestamp and (e.timestamp.hour < 7 or e.timestamp.hour >= 20)],
    }


def _problem_findings(emp: Employee, ev: Dict[str, Any]) -> List[str]:
    f: List[str] = []
    score = emp.risk_score or 0
    if score >= 75:
        f.append(f"Risk score is **{score}%**, above the critical threshold (75).")
    elif score >= 50:
        f.append(f"Risk score is **{score}%**, above the suspicious threshold (50).")
    active_inc = [i for i in ev["incidents"] if i.active]
    if active_inc:
        f.append(f"**{len(active_inc)} open incident(s)** — latest: *{active_inc[0].title}* ({active_inc[0].severity}).")
    high_alerts = [a for a in ev["alerts"] if (a.severity or "").lower() in ("high", "critical")]
    if high_alerts:
        f.append(f"**{len(high_alerts)} high-severity alert(s)**, e.g. “{high_alerts[0].reason}”.")
    if ev["usb"]:
        f.append(f"**{len(ev['usb'])} USB event(s)** — physical exfiltration vector.")
    if len(ev["deletes"]) >= 3:
        f.append(f"**{len(ev['deletes'])} file deletions** — possible evidence destruction or ransomware behaviour.")
    up_mb = sum(_safe_mb(e.network_upload) for e in ev["uploads"])
    if up_mb >= 20:
        f.append(f"**{up_mb:.0f} MB uploaded** over the network.")
    if len(ev["off_hours"]) >= 3:
        f.append(f"**{len(ev['off_hours'])} off-hours actions** (before 7 AM / after 8 PM).")
    sens = [r for r in ev["requests"] if (r.file_classification or "").upper() in ("RESTRICTED", "CONFIDENTIAL")]
    if sens:
        f.append(f"Touched **{len(sens)} {sens[0].file_classification.lower()} asset(s)**, e.g. `{sens[0].target_file}`.")
    rejected = [r for r in ev["requests"] if r.status == "REJECTED"]
    if rejected:
        f.append(f"**{len(rejected)} action request(s) rejected** by SOC admins.")
    if ev["anomalies"]:
        a = ev["anomalies"][0]
        f.append(f"UBA flagged a **{a.severity} behavioural anomaly** (score {a.anomaly_score}%).")
    if ev["exfil"] and (ev["exfil"].probability or 0) >= 50:
        f.append(f"Exfiltration model predicts **{ev['exfil'].probability}%** probability via {ev['exfil'].vector}.")
    return f


# ---------------------------------------------------------------------------
# Employee responses
# ---------------------------------------------------------------------------
def _timeline_table(events: List[Event], limit: int = 10) -> str:
    if not events:
        return "_No telemetry events recorded in this window._"
    rows = ["| Time | Action | Details |", "|---|---|---|"]
    for e in events[:limit]:
        extra = []
        if e.size:
            extra.append(e.size)
        if e.usb_status:
            extra.append("USB " + (e.usb_status if len(e.usb_status) < 20 else "device"))
        if e.network_upload:
            extra.append(f"↑ {e.network_upload}")
        detail = ", ".join(extra).replace("|", "/") or "—"
        rows.append(f"| {_fmt_ts(e.timestamp)} | {_describe_event(e)} | {detail} |")
    if len(events) > limit:
        rows.append(f"\n_…and {len(events) - limit} more events._")
    return "\n".join(rows)


def _employee_answer(db: Session, emp: Employee, facets: List[str], win: Dict[str, Any], msg: str) -> Dict[str, Any]:
    from backend.services.threat_copilot import explain_employee_risk

    ev = _gather(db, emp, win)
    findings = _problem_findings(emp, ev)
    score = emp.risk_score or 0
    first = emp.name.split()[0]
    scope = f" ({win['label']})" if win.get("label") else ""
    parts: List[str] = []
    suggestions: List[str] = []

    specific = [f for f in facets if f not in ("activity", "problem", "risk", "files")]

    # --- Narrow, facet-specific questions ---------------------------------
    if "usb" in specific:
        usb = ev["usb"]
        parts.append(f"### 🔌 USB activity — {emp.name}{scope}")
        if usb:
            parts.append(f"I found **{len(usb)} USB event(s)**. Most recent was **{_ago(usb[0].timestamp)}**.\n")
            parts.append(_timeline_table(usb, 8))
            parts.append("\n> ⚠️ Removable media combined with sensitive file access is mapped to **MITRE T1052.001** (Exfiltration over Physical Medium).")
        else:
            parts.append(f"✅ No USB activity recorded for {first}{scope}.")
    if "delete" in specific:
        d = ev["deletes"]
        parts.append(f"### 🗑️ File deletions — {emp.name}{scope}")
        if d:
            parts.append(f"**{len(d)} deletion(s)** detected. Every deleted file was snapshotted into the **AES-256 Shadow Vault**, so all of them are recoverable.\n")
            parts.append(_timeline_table(d, 8))
        else:
            parts.append(f"✅ {first} hasn't deleted any monitored files{scope}.")
    if "upload" in specific:
        u = ev["uploads"]
        total = sum(_safe_mb(e.network_upload) for e in u)
        parts.append(f"### 🌐 Network uploads — {emp.name}{scope}")
        if u:
            parts.append(f"**{len(u)} upload event(s)** totalling **~{total:.1f} MB**.\n")
            parts.append(_timeline_table(u, 8))
        else:
            parts.append(f"✅ No outbound uploads recorded for {first}{scope}.")
    if "alerts" in specific:
        parts.append(f"### 🚨 Alerts — {emp.name}{scope}")
        if ev["alerts"]:
            rows = ["| Time | Severity | Reason | Status |", "|---|---|---|---|"]
            rows += [f"| {_fmt_ts(a.timestamp)} | {a.severity} | {a.reason} | {a.status} |" for a in ev["alerts"][:10]]
            parts.append("\n".join(rows))
        else:
            parts.append(f"✅ No alerts raised against {first}{scope}.")
    if "incidents" in specific:
        parts.append(f"### 📁 Incidents — {emp.name}")
        if ev["incidents"]:
            rows = ["| # | Title | Severity | Status | Score | Opened |", "|---|---|---|---|---|---|"]
            rows += [f"| {i.id} | {i.title} | {i.severity} | {i.status} | {i.risk_score}% | {_ago(i.created_at)} |" for i in ev["incidents"]]
            parts.append("\n".join(rows))
        else:
            parts.append(f"✅ {first} has no incident history.")
    if "requests" in specific:
        parts.append(f"### 🎫 Action requests (JIT approvals) — {emp.name}{scope}")
        if ev["requests"]:
            rows = ["| Requested | Action | File | Class | Status |", "|---|---|---|---|---|"]
            rows += [f"| {_fmt_ts(r.requested_at)} | {r.action_type} | `{r.target_file}` | {r.file_classification or '—'} | {r.status} |" for r in ev["requests"][:10]]
            parts.append("\n".join(rows))
        else:
            parts.append(f"✅ {first} hasn't triggered any approval requests{scope}.")
    if "anomaly" in specific:
        parts.append(f"### 🧠 Behavioural anomalies (UBA) — {emp.name}")
        if ev["anomalies"]:
            for a in ev["anomalies"][:5]:
                try:
                    inds = json.loads(a.indicators_json or "[]")
                except Exception:
                    inds = []
                parts.append(f"- **{a.severity}** · score **{a.anomaly_score}%** · {_ago(a.detected_at)} — {a.context or ', '.join(map(str, inds[:3])) or 'Deviation from baseline'}")
        else:
            parts.append(f"✅ {first}'s behaviour is within their learned baseline.")
    if "device" in specific:
        d = ev["device"]
        parts.append(f"### 💻 Endpoint — {emp.name}")
        if d:
            parts.append(
                "| Property | Value |\n|---|---|\n"
                f"| Hostname | `{d.hostname or '—'}` |\n| OS | {d.os_version or '—'} |\n| IP | `{d.ip_address or '—'}` |\n"
                f"| Agent | v{d.agent_version or '—'} |\n| Status | {'🟢 Online' if d.status == 'online' else '⚫ Offline'} |\n"
                f"| Last seen | {_ago(d.last_seen_at)} |\n| CPU / RAM | {d.last_cpu_usage or 0:.0f}% / {d.last_ram_usage or 0:.0f}% |"
            )
        else:
            parts.append(f"No endpoint agent is enrolled for {first} yet.")
    if "mitre" in specific or "playbook" in specific:
        analysis = explain_employee_risk(db, emp.id)
        if "mitre" in specific:
            parts.append(f"### 🎯 MITRE ATT&CK mapping — {emp.name}")
            if analysis.get("mitre_techniques"):
                rows = ["| Technique | Name | Tactic |", "|---|---|---|"]
                rows += [f"| `{m['technique_id']}` | {m['technique_name']} | {m['tactic']} |" for m in analysis["mitre_techniques"]]
                parts.append("\n".join(rows))
            else:
                parts.append("No ATT&CK techniques matched the current evidence.")
        if "playbook" in specific:
            parts.append(f"### 📋 Recommended response for {emp.name}")
            parts += [f"{p['step']}. **{p['action']}** `[{p['priority']}]` — {p['reason']}" for p in analysis.get("containment_playbook", [])]
            suggestions += [p["action"] for p in analysis.get("containment_playbook", [])[:2]]

    # --- Risk explanation ----------------------------------------------------
    if "risk" in facets and not specific:
        analysis = explain_employee_risk(db, emp.id)
        parts.append(f"### 🛡️ Why is {emp.name}'s risk {score}%?")
        parts.append(f"`{_bar(score)}` **{score}%** · {_risk_label(score)}\n")
        if analysis.get("factors"):
            rows = ["| Driver | Impact | Evidence |", "|---|---|---|"]
            rows += [f"| **{f['factor']}** | {f['impact']} | {f['detail']} |" for f in analysis["factors"]]
            parts.append("\n".join(rows))
        if findings:
            parts.append("\n#### 🔍 Evidence behind the score")
            parts += [f"- {x}" for x in findings]
        elif not analysis.get("factors"):
            parts.append(f"There are no significant risk drivers — {first} is operating within baseline.")
        if analysis.get("mitre_techniques"):
            parts.append("\n**Mapped ATT&CK techniques:** " + ", ".join(f"`{m['technique_id']}` {m['technique_name']}" for m in analysis["mitre_techniques"]))
        suggestions += [f"What should we do about {first}?", f"Show {first}'s timeline"]

    # --- General / "what did they do" / "is there a problem" ------------------
    if not parts:
        is_problem_q = "problem" in facets
        verdict = ""
        if findings:
            verdict = (f"**Yes — {first} needs attention.** " if is_problem_q else "") + \
                f"I found **{len(findings)} risk indicator(s)** in {first}'s recent behaviour."
        else:
            verdict = (f"**No — nothing concerning.** " if is_problem_q else "") + \
                f"{first}'s activity looks consistent with their normal baseline."

        parts.append(f"### 👤 {emp.name}")
        parts.append(f"*{emp.role_type or 'Employee'} · {emp.department} · {emp.email}*\n")
        parts.append(verdict + "\n")

        stats = (
            "| Metric | Value |\n|---|---|\n"
            f"| Risk score | `{_bar(score, 12)}` **{score}%** {_risk_label(score)} |\n"
            f"| Status | {emp.status} |\n"
            f"| Events{scope or ' (recent)'} | {len(ev['events'])} |\n"
            f"| USB / Deletions / Uploads | {len(ev['usb'])} / {len(ev['deletes'])} / {len(ev['uploads'])} |\n"
            f"| Off-hours actions | {len(ev['off_hours'])} |\n"
            f"| Alerts / Open incidents | {len(ev['alerts'])} / {len([i for i in ev['incidents'] if i.active])} |\n"
            f"| Endpoint | {('🟢 ' if ev['device'] and ev['device'].status == 'online' else '⚫ ')}{(ev['device'].hostname if ev['device'] else 'Not enrolled')} |"
        )
        parts.append(stats)

        if findings:
            parts.append("\n#### ⚠️ What's concerning")
            parts += [f"- {x}" for x in findings]

        # activity mix
        if ev["events"]:
            mix = Counter((e.event_type or "other").replace("_", " ") for e in ev["events"]).most_common(5)
            parts.append("\n#### 📊 Activity mix")
            total = sum(c for _, c in mix) or 1
            parts += [f"- `{_bar(c / total * 100, 10)}` **{t}** — {c}" for t, c in mix]

        parts.append(f"\n#### 🕒 Recent actions{scope}")
        parts.append(_timeline_table(ev["events"], 8))

        if ev["requests"]:
            r = ev["requests"][0]
            parts.append(f"\n**Latest intercepted action:** `{r.action_type}` on `{r.target_file}` ({r.file_classification or 'INTERNAL'}) → **{r.status}**")

        parts.append("\n#### ✅ My recommendation")
        if score >= 75 or len(findings) >= 4:
            parts.append(f"Treat this as a **likely insider-threat case**. Isolate {first}'s endpoint, revoke pending JIT tokens, verify Shadow Vault snapshots and escalate to the SOC lead.")
            suggestions += [f"Recommend containment playbook for {first}", f"Show MITRE techniques for {first}"]
        elif score >= 50 or findings:
            parts.append(f"**Monitor closely.** Enable enhanced telemetry on {first}'s device and confirm the business context of the flagged actions with their manager.")
            suggestions += [f"Why is {first}'s risk score {score}%?", f"Show {first}'s USB activity"]
        else:
            parts.append("No action needed — continue standard autonomous monitoring.")
            suggestions += [f"Show {first}'s file activity", "Show high-risk employees"]

    if not suggestions:
        suggestions = [f"Is there any problem with {first}?", f"What should we do about {first}?", f"Show {first}'s alerts"]

    return {
        "reply": "\n".join(parts),
        "data": {"employee_id": emp.id, "employee_name": emp.name, "risk_score": score,
                 "findings": findings, "event_count": len(ev["events"])},
        "suggested_actions": list(dict.fromkeys(suggestions))[:4],
        "focus_employee": {"id": emp.id, "name": emp.name},
    }


def _compare_employees(db: Session, emps: List[Employee], win: Dict[str, Any]) -> Dict[str, Any]:
    emps = emps[:4]
    data = [(e, _gather(db, e, win)) for e in emps]
    head = "| Metric | " + " | ".join(e.name for e in emps) + " |"
    sep = "|---|" + "---|" * len(emps)
    rows = [head, sep]

    def row(label, fn):
        rows.append(f"| {label} | " + " | ".join(str(fn(e, ev)) for e, ev in data) + " |")

    row("Department", lambda e, ev: e.department)
    row("Risk score", lambda e, ev: f"**{e.risk_score or 0}%** {_risk_label(e.risk_score or 0)}")
    row("Status", lambda e, ev: e.status)
    row("Events", lambda e, ev: len(ev["events"]))
    row("USB events", lambda e, ev: len(ev["usb"]))
    row("Deletions", lambda e, ev: len(ev["deletes"]))
    row("Uploads (MB)", lambda e, ev: f"{sum(_safe_mb(x.network_upload) for x in ev['uploads']):.0f}")
    row("Off-hours", lambda e, ev: len(ev["off_hours"]))
    row("Alerts", lambda e, ev: len(ev["alerts"]))
    row("Open incidents", lambda e, ev: len([i for i in ev["incidents"] if i.active]))
    riskiest = max(emps, key=lambda e: e.risk_score or 0)
    reply = (f"### ⚖️ Side-by-side comparison\n\n" + "\n".join(rows) +
             f"\n\n**Bottom line:** **{riskiest.name}** carries the highest exposure at **{riskiest.risk_score or 0}%**"
             + (" and should be prioritised for investigation." if (riskiest.risk_score or 0) >= 50 else ", but nobody here is above the suspicious threshold."))
    return {"reply": reply, "data": [{"id": e.id, "name": e.name, "risk": e.risk_score} for e in emps],
            "suggested_actions": [f"Tell me about {riskiest.name}", f"Why is {riskiest.name.split()[0]}'s risk high?"],
            "focus_employee": {"id": riskiest.id, "name": riskiest.name}}


# ---------------------------------------------------------------------------
# Organisation-wide answers
# ---------------------------------------------------------------------------
def _org_overview(db: Session, employees: List[Employee]) -> Dict[str, Any]:
    n = len(employees)
    if not n:
        return {"reply": "There are no employees registered yet. Once endpoints enrol, I'll start building behavioural baselines.",
                "data": {}, "suggested_actions": ["What can you do?"]}
    avg = sum(e.risk_score or 0 for e in employees) / n
    crit = [e for e in employees if (e.risk_score or 0) >= 75]
    elev = [e for e in employees if 50 <= (e.risk_score or 0) < 75]
    open_inc = db.query(Incident).filter(Incident.active == True).count()  # noqa: E712
    active_alerts = db.query(Alert).filter(Alert.status == "Active").count()
    pending = db.query(ActionRequest).filter(ActionRequest.status == "PENDING").count()
    since = datetime.utcnow() - timedelta(hours=24)
    ev24 = db.query(Event).filter(Event.timestamp >= since).count()
    top = sorted(employees, key=lambda e: -(e.risk_score or 0))[:5]
    depts: Dict[str, List[int]] = {}
    for e in employees:
        depts.setdefault(e.department or "Unassigned", []).append(e.risk_score or 0)

    posture = "🔴 **Under active threat**" if crit or open_inc else ("🟠 **Elevated**" if elev else "🟢 **Stable**")
    lines = [
        "### 🛰️ Security posture briefing",
        f"Overall posture: {posture}\n",
        "| Indicator | Value |", "|---|---|",
        f"| Monitored employees | {n} |",
        f"| Average risk | `{_bar(avg, 12)}` {avg:.0f}% |",
        f"| Critical / Elevated users | {len(crit)} / {len(elev)} |",
        f"| Open incidents | {open_inc} |",
        f"| Active alerts | {active_alerts} |",
        f"| Pending approvals | {pending} |",
        f"| Telemetry events (24 h) | {ev24} |",
        "\n#### 🔝 Highest-risk people",
    ]
    lines += [f"{i+1}. **{e.name}** — {e.department} · **{e.risk_score or 0}%** {_risk_label(e.risk_score or 0)}" for i, e in enumerate(top)]
    lines.append("\n#### 🏢 Risk by department")
    for d, scores in sorted(depts.items(), key=lambda x: -sum(x[1]) / len(x[1])):
        a = sum(scores) / len(scores)
        lines.append(f"- `{_bar(a, 12)}` **{d}** — {a:.0f}% avg ({len(scores)} people)")
    return {"reply": "\n".join(lines),
            "data": {"employees": n, "avg_risk": avg, "open_incidents": open_inc},
            "suggested_actions": [f"Tell me about {top[0].name}", "Analyze latest incident", "Show pending approvals"],
            "focus_employee": {"id": top[0].id, "name": top[0].name}}


def _ranking(employees: List[Employee], msg: str) -> Dict[str, Any]:
    m = re.search(r"\btop\s+(\d+)", msg)
    k = int(m.group(1)) if m else None
    low = _has(msg, ["lowest", "least", "safest", "low risk", "low-risk", "trusted", "clean"])
    pool = sorted(employees, key=lambda e: (e.risk_score or 0), reverse=not low)
    if not low and not k:
        pool = [e for e in pool if (e.risk_score or 0) >= 50] or pool[:5]
    pool = pool[: (k or 10)]
    if not pool:
        return {"reply": "✅ No employees match that criteria.", "data": [], "suggested_actions": ["Give me a security overview"]}
    title = "🟢 Lowest-risk employees" if low else ("⚠️ Elevated-risk personnel" if not k else f"🔝 Top {k} by risk")
    rows = ["| # | Employee | Department | Risk | Status |", "|---|---|---|---|---|"]
    rows += [f"| {i+1} | **{e.name}** | {e.department} | `{_bar(e.risk_score or 0, 8)}` {e.risk_score or 0}% | {e.status} |" for i, e in enumerate(pool)]
    reply = f"### {title}\n\n" + "\n".join(rows)
    if not low:
        reply += f"\n\n**{pool[0].name}** is the top concern. Ask me *“what did {pool[0].name.split()[0]} do?”* for the full activity breakdown."
    return {"reply": reply, "data": [{"id": e.id, "name": e.name, "risk": e.risk_score} for e in pool],
            "suggested_actions": [f"What did {pool[0].name.split()[0]} do?", f"Compare {pool[0].name.split()[0]} and {pool[1].name.split()[0]}" if len(pool) > 1 else "Give me a security overview"],
            "focus_employee": {"id": pool[0].id, "name": pool[0].name}}


def _list_employees(employees: List[Employee], dept: Optional[str]) -> Dict[str, Any]:
    pool = _employees_in_dept(employees, dept) if dept else employees
    pool = sorted(pool, key=lambda e: e.name or "")
    if not pool:
        return {"reply": f"I couldn't find any employees{(' in ' + dept) if dept else ''}.", "data": [], "suggested_actions": ["Give me a security overview"]}
    rows = ["| Employee | Role | Department | Risk |", "|---|---|---|---|"]
    rows += [f"| {e.name} | {e.role_type} | {e.department} | {e.risk_score or 0}% {_risk_label(e.risk_score or 0)} |" for e in pool[:40]]
    return {"reply": f"### 👥 {len(pool)} employee(s){(' in ' + dept) if dept else ''}\n\n" + "\n".join(rows),
            "data": [{"id": e.id, "name": e.name} for e in pool],
            "suggested_actions": ["Show high-risk employees", f"Tell me about {pool[0].name}"]}


def _department_answer(db: Session, employees: List[Employee], dept: str, win: Dict[str, Any], facets: List[str]) -> Dict[str, Any]:
    pool = _employees_in_dept(employees, dept)
    if not pool:
        return {"reply": f"There are no employees registered in **{dept}** yet.", "data": {}, "suggested_actions": ["List all employees"]}
    ids = [e.id for e in pool]
    by_id = {e.id: e for e in pool}
    q = db.query(Event).filter(Event.employee_id.in_(ids))
    if win.get("since"):
        q = q.filter(Event.timestamp >= win["since"])
    events = [e for e in q.order_by(Event.timestamp.desc()).limit(800).all() if _in_window(e.timestamp, win)]
    scope = f" · {win['label']}" if win.get("label") else ""

    for facet, pred, icon, label in (("usb", _is_usb, "🔌", "USB activity"), ("delete", _is_delete, "🗑️", "File deletions"),
                                     ("upload", _is_upload, "🌐", "Network uploads")):
        if facet in facets:
            hits = [e for e in events if pred(e)]
            if not hits:
                return {"reply": f"### {icon} {label} — {dept}{scope}\n\n✅ No matching activity found.",
                        "data": [], "suggested_actions": [f"Show {dept} risk summary", "Give me a security overview"]}
            per = Counter(by_id[e.employee_id].name for e in hits).most_common()
            rows = ["| Time | Employee | Action | Details |", "|---|---|---|---|"]
            rows += [f"| {_fmt_ts(e.timestamp)} | {by_id[e.employee_id].name} | {_describe_event(e)} | {e.network_upload or e.size or '—'} |" for e in hits[:15]]
            reply = (f"### {icon} {label} — {dept}{scope}\n\n**{len(hits)} event(s)** across **{len(per)} employee(s)**. "
                     f"Most active: **{per[0][0]}** ({per[0][1]}).\n\n" + "\n".join(rows))
            return {"reply": reply, "data": [{"employee": by_id[e.employee_id].name, "type": e.event_type} for e in hits[:50]],
                    "suggested_actions": [f"What did {per[0][0].split()[0]} do?", f"Is there any problem with {per[0][0].split()[0]}?"]}

    avg = sum(e.risk_score or 0 for e in pool) / len(pool)
    high = sorted([e for e in pool if (e.risk_score or 0) >= 50], key=lambda e: -(e.risk_score or 0))
    rows = ["| Employee | Risk | Status |", "|---|---|---|"]
    rows += [f"| {e.name} | `{_bar(e.risk_score or 0, 8)}` {e.risk_score or 0}% | {e.status} |" for e in sorted(pool, key=lambda e: -(e.risk_score or 0))[:12]]
    verdict = ("⚠️ **This department shows highly anomalous behaviour — a deep audit is recommended.**" if avg > 60
               else "🟡 **Moderate risk — keep an eye on file movement and USB usage.**" if avg > 30
               else "✅ **Activity is within normal baselines.**")
    mix = Counter(_describe_event(e).split(" ")[0] + " " + (e.event_type or "").replace("_", " ") for e in events).most_common(4)
    reply = (f"### 📊 Department analysis: {dept}{scope}\n\n"
             f"Average risk `{_bar(avg)}` **{avg:.0f}%** · {len(pool)} people · {len(high)} elevated · {len(events)} events\n\n"
             + "\n".join(rows) + "\n\n" + verdict)
    if mix:
        reply += "\n\n**Dominant activity:** " + ", ".join(f"{t.strip()} ({c})" for t, c in mix)
    sugg = [f"Show USB activity in {dept}", f"What did {high[0].name.split()[0]} do?"] if high else [f"Show USB activity in {dept}", "Show high-risk employees"]
    return {"reply": reply, "data": {"department": dept, "avg_risk": avg, "count": len(pool)}, "suggested_actions": sugg}


def _global_facet(db: Session, employees: List[Employee], facet: str, win: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    by_id = {e.id: e for e in employees}
    scope = f" · {win['label']}" if win.get("label") else ""
    if facet == "incidents":
        incs = db.query(Incident).order_by(Incident.created_at.desc()).limit(10).all()
        if not incs:
            return {"reply": "✅ No incidents on record. The environment is clean.", "data": [], "suggested_actions": ["Give me a security overview"]}
        latest = incs[0]
        emp = by_id.get(latest.employee_id)
        try:
            tl = json.loads(latest.timeline_json or "[]")
        except Exception:
            tl = []
        lines = [f"### 📁 Latest incident #{latest.id}: {latest.title}",
                 f"**{latest.severity}** · {latest.status} · score **{latest.risk_score}%** · confidence {latest.confidence}% · opened {_ago(latest.created_at)}",
                 f"**Subject:** {emp.name if emp else 'Unknown'} ({emp.department if emp else '—'})\n"]
        if tl:
            lines.append("#### Evidence timeline")
            lines += [f"- `{str(t.get('ts', ''))[:16].replace('T', ' ')}` **{t.get('title', '')}** — {t.get('detail', '')}" for t in tl[-8:]]
        if len(incs) > 1:
            lines.append("\n#### Other incidents")
            rows = ["| # | Employee | Title | Severity | Status |", "|---|---|---|---|---|"]
            rows += [f"| {i.id} | {by_id[i.employee_id].name if i.employee_id in by_id else '—'} | {i.title} | {i.severity} | {i.status} |" for i in incs[1:8]]
            lines.append("\n".join(rows))
        return {"reply": "\n".join(lines), "data": {"incident_id": latest.id},
                "suggested_actions": [f"What did {emp.name.split()[0]} do?" if emp else "Show high-risk employees",
                                      f"Recommend containment playbook for {emp.name.split()[0]}" if emp else "Give me a security overview"],
                "focus_employee": {"id": emp.id, "name": emp.name} if emp else None}
    if facet == "alerts":
        alerts = [a for a in db.query(Alert).order_by(Alert.timestamp.desc()).limit(60).all() if _in_window(a.timestamp, win) or not (win.get("since") or win.get("off_hours"))]
        if not alerts:
            return {"reply": f"✅ No alerts{scope}.", "data": [], "suggested_actions": ["Give me a security overview"]}
        sev = Counter(a.severity for a in alerts)
        rows = ["| Time | Employee | Severity | Reason | Status |", "|---|---|---|---|---|"]
        rows += [f"| {_fmt_ts(a.timestamp)} | {by_id[a.employee_id].name if a.employee_id in by_id else '—'} | {a.severity} | {a.reason} | {a.status} |" for a in alerts[:12]]
        return {"reply": f"### 🚨 Recent alerts{scope}\n\n" + " · ".join(f"**{k}**: {v}" for k, v in sev.items()) + "\n\n" + "\n".join(rows),
                "data": [], "suggested_actions": ["Analyze latest incident", "Show high-risk employees"]}
    if facet == "requests":
        reqs = db.query(ActionRequest).filter(ActionRequest.status == "PENDING").order_by(ActionRequest.requested_at.desc()).limit(15).all()
        if not reqs:
            return {"reply": "✅ The approval queue is empty — no pending JIT requests.", "data": [], "suggested_actions": ["Give me a security overview"]}
        rows = ["| Requested | Employee | Action | File | Class | Tier |", "|---|---|---|---|---|---|"]
        rows += [f"| {_ago(r.requested_at)} | {by_id[r.employee_id].name if r.employee_id in by_id else '—'} | {r.action_type} | `{r.target_file}` | {r.file_classification} | {r.policy_tier} ({r.current_approvals}/{r.required_approvals}) |" for r in reqs]
        return {"reply": f"### 🎫 {len(reqs)} pending approval(s)\n\n" + "\n".join(rows) + "\n\nRestricted assets require **dual-quorum** sign-off before release.",
                "data": [], "suggested_actions": ["Show high-risk employees"]}
    preds = {"usb": (_is_usb, "🔌", "USB activity"), "delete": (_is_delete, "🗑️", "File deletions"), "upload": (_is_upload, "🌐", "Network uploads")}
    if facet in preds:
        pred, icon, label = preds[facet]
        q = db.query(Event)
        if win.get("since"):
            q = q.filter(Event.timestamp >= win["since"])
        hits = [e for e in q.order_by(Event.timestamp.desc()).limit(1500).all() if pred(e) and _in_window(e.timestamp, win)]
        if not hits:
            return {"reply": f"### {icon} {label}{scope}\n\n✅ No matching activity across the organisation.", "data": [], "suggested_actions": ["Give me a security overview"]}
        per = Counter(by_id[e.employee_id].name for e in hits if e.employee_id in by_id).most_common(5)
        rows = ["| Time | Employee | Dept | Action |", "|---|---|---|---|"]
        rows += [f"| {_fmt_ts(e.timestamp)} | {by_id[e.employee_id].name if e.employee_id in by_id else '—'} | {by_id[e.employee_id].department if e.employee_id in by_id else '—'} | {_describe_event(e)} |" for e in hits[:15]]
        leaders = "\n".join(f"- **{n}** — {c} event(s)" for n, c in per)
        return {"reply": f"### {icon} {label} across the organisation{scope}\n\n**{len(hits)} event(s)** detected.\n\n#### Most active\n{leaders}\n\n" + "\n".join(rows),
                "data": [], "suggested_actions": [f"What did {per[0][0].split()[0]} do?" if per else "Show high-risk employees", "Give me a security overview"]}
    return None


# ---------------------------------------------------------------------------
# Knowledge base
# ---------------------------------------------------------------------------
KNOWLEDGE = [
    (["vault", "aes", "shadow vault", "encryption", "encrypt"],
     "### 🔐 Shadow Vault (AES-256-GCM)\n\nWhenever a monitored file is about to be deleted or overwritten, the endpoint agent snapshots it into an encrypted vault **before** the operation completes.\n\n"
     "| Layer | Implementation |\n|---|---|\n| Cipher | AES-256-GCM (authenticated encryption) |\n| Key derivation | PBKDF2-HMAC-SHA256, 100,000 rounds |\n| Integrity | SHA-256 digest per snapshot |\n| Restore time | < 5 ms per file |\n| Key rotation | Automated |\n\n"
     "Because GCM is authenticated, any tampering with a vaulted file is detected on restore — so an insider can't silently corrupt the evidence."),
    (["ransomware", "rollback", "mass recovery", "500-file", "500 file", "encrypted files"],
     "### 🦠 Ransomware defence & mass rollback\n\n1. **Detect** — a burst of rapid file modifications/renames with high-entropy content trips the ransomware heuristic.\n"
     "2. **Contain** — the offending process tree is flagged and the endpoint can be isolated from the dashboard.\n"
     "3. **Recover** — the Mass Recovery Engine restores up to **500 files atomically** from the Shadow Vault, verifying each SHA-256 digest.\n"
     "4. **Report** — a `RansomwareBatchLog` records files recovered, failures, data volume and recovery time.\n\n"
     "💡 Run `python scripts/simulate_ransomware.py` to see it live."),
    (["mitre", "att&ck", "attack framework"],
     "### 🎯 MITRE ATT&CK in ThreatVista\n\nARGUS maps observed telemetry to adversary techniques:\n\n| ID | Technique | Triggered by |\n|---|---|---|\n"
     "| `T1052.001` | Exfiltration over USB | Removable media insertion during sensitive access |\n| `T1567` | Exfiltration over web service | Uploads > 20 MB |\n"
     "| `T1070.004` | Indicator removal: file deletion | Deletion bursts |\n| `T1083` | File & directory discovery | High-volume enumeration |\n| `T1078` | Valid accounts | High-severity alerts on legitimate credentials |\n\n"
     "Ask *“show MITRE techniques for &lt;name&gt;”* for a per-employee mapping."),
    (["risk score", "how is risk", "how do you calculate", "scoring", "how risk"],
     "### 🧮 How the risk score works\n\nEach employee's score (0–100) blends several weighted signals:\n\n"
     "- **Asset sensitivity** — touching RESTRICTED (+35) or CONFIDENTIAL (+20) files\n- **USB staging** (+25)\n- **Deletion attempts** (+20)\n"
     "- **UBA deviation** — distance from the employee's learned baseline (login hours, file volume, directories)\n- **Network uploads** and **off-hours activity**\n\n"
     "Thresholds: **≥ 50 Suspicious**, **≥ 75 High Risk** (configurable in Settings). Incident scores are monotonic — they never silently decay."),
    (["insider threat", "insider"],
     "### 🕵️ Insider threats\n\nAn insider threat is a risk posed by someone with legitimate access — employees, contractors or partners — who misuses it, maliciously or accidentally.\n\n"
     "**Typical signals ARGUS watches for:** access outside normal hours, bulk copying, USB staging, deleting evidence, accessing data outside one's role, and resignation-period spikes.\n\n"
     "ThreatVista counters this with UBA baselines, JIT approvals, Shadow Vault and explainable risk scoring."),
    (["phishing", "spear phishing", "email attack"],
     "### 🎣 Phishing\n\nSocial-engineering emails that trick users into revealing credentials or running malware.\n\n**Defences:** MFA, link sandboxing, SPF/DKIM/DMARC, user training, and — in ThreatVista — detecting the *post-compromise* behaviour (unusual logins, bulk access) that follows a successful phish."),
    (["zero trust"],
     "### 🧱 Zero Trust\n\n“Never trust, always verify.” Every request is authenticated, authorised and continuously evaluated regardless of network location. ThreatVista applies it through **JIT action approvals**, **least-privilege tiers** and **continuous behavioural risk scoring**."),
    (["dlp", "data loss", "data leak"],
     "### 🚰 Data Loss Prevention\n\nDLP stops sensitive data leaving the organisation. ThreatVista's DLP layer combines **AI file classification** (PUBLIC → RESTRICTED), **USB blocking**, **upload monitoring** and **approval workflows** for risky exports."),
    (["uba", "ueba", "user behavior analytics", "baseline", "digital twin"],
     "### 🧠 User Behaviour Analytics\n\nARGUS learns a *digital twin* per employee — typical login/logout hours, daily file volume, deletion/copy rates, common directories and sensitivity level. Deviations produce an anomaly score and are logged as `BehavioralAnomalyLog` entries."),
    (["jit", "approval", "quorum", "dual approval"],
     "### 🎫 JIT approvals & quorum\n\nRisky actions (deleting protected files, USB exports, scripts) are paused and turned into tickets. Policy tiers decide how many admins must approve: **AUTO (0)**, **STANDARD (1)**, **ELEVATED / DUAL_QUORUM (2–3)**. Requests expire automatically if nobody acts."),
    (["ddos", "dos attack"],
     "### 🌊 DDoS\n\nA Distributed Denial-of-Service floods a service with traffic from many sources. Mitigations: CDN/anycast scrubbing, rate limiting, autoscaling and upstream filtering. (ThreatVista focuses on endpoint & insider threats rather than volumetric network attacks.)"),
    (["sql injection", "sqli", "xss", "cross site"],
     "### 💉 Injection attacks\n\nSQL injection and XSS exploit unsanitised input. Use parameterised queries (ThreatVista uses SQLAlchemy ORM), output encoding, CSP headers and a WAF."),
    (["malware", "virus", "trojan", "keylogger"],
     "### 🧬 Malware\n\nMalicious software — trojans, worms, keyloggers, ransomware. ThreatVista's endpoint agent watches process launches, file-system bursts and outbound traffic, and the Shadow Vault guarantees recovery of tampered files."),
    (["brute force", "password attack", "credential stuffing"],
     "### 🔨 Brute-force & credential attacks\n\nRepeated login attempts with guessed or leaked passwords. Defences: account lockout, MFA, rate limiting and anomaly detection on login time/location."),
    (["threatvista", "this platform", "this system", "features", "what does this app"],
     "### 🛡️ ThreatVista platform\n\n- **Endpoint agent** — file, USB, network & process telemetry\n- **UBA & risk engine** — per-employee baselines and explainable scores\n- **Shadow Vault** — AES-256 snapshots with instant rollback\n- **JIT approvals** — multi-tier quorum for risky actions\n- **Incidents & MITRE mapping** — persistent cases with evidence timelines\n- **ARGUS** — me! Conversational analysis over all of the above"),
]


def _knowledge(msg: str) -> Optional[Dict[str, Any]]:
    for keys, answer in KNOWLEDGE:
        if _has(msg, keys):
            return {"reply": answer, "data": {}, "suggested_actions": ["Give me a security overview", "Show high-risk employees"]}
    return None


# ---------------------------------------------------------------------------
# Small talk
# ---------------------------------------------------------------------------
def _small_talk(msg: str, employees: List[Employee]) -> Optional[Dict[str, Any]]:
    clean = re.sub(r"[^a-z ]", "", msg).strip()
    top = max(employees, key=lambda e: e.risk_score or 0) if employees else None
    if clean in {"hi", "hello", "hey", "hii", "yo", "greetings", "good morning", "good evening", "good afternoon", "hello argus", "hi argus", "hey argus"}:
        hint = f" Right now **{top.name}** has the highest risk score ({top.risk_score}%)." if top and (top.risk_score or 0) >= 50 else ""
        return {"reply": random.choice([
            f"Hey! 👋 I'm **ARGUS**. I'm watching {len(employees)} employees' telemetry in real time.{hint}\n\nWhat would you like to look into?",
            f"Hello, analyst. **ARGUS** online — all sensors reporting.{hint}\n\nAsk me about any employee, department or incident.",
        ]), "data": {}, "suggested_actions": ["Give me a security overview", "Show high-risk employees", "Analyze latest incident"]}
    if _has(msg, ["thank", "thanks", "thx", "great job", "nice", "awesome", "perfect"]) and len(clean.split()) <= 6:
        return {"reply": random.choice(["Anytime! 🛡️ Let me know if you want to dig deeper.", "Happy to help. I'll keep watching the telemetry.", "You're welcome — stay vigilant! 👁️"]),
                "data": {}, "suggested_actions": ["Give me a security overview"]}
    if _has(msg, ["bye", "goodbye", "see you", "good night"]) and len(clean.split()) <= 5:
        return {"reply": "Signing off the conversation — monitoring continues 24/7. 👁️", "data": {}, "suggested_actions": []}
    if _has(msg, ["how are you", "how r u", "hows it going", "how is it going"]):
        return {"reply": "All systems nominal and fully caffeinated ☕ — telemetry pipelines healthy, Shadow Vault sealed. How can I help?",
                "data": {}, "suggested_actions": ["Give me a security overview"]}
    if _has(msg, ["who are you", "what are you", "what are u", "your name", "introduce yourself", "who made you", "who built you"]):
        return {"reply": "I'm **ARGUS** — named after the hundred-eyed giant of Greek myth who never slept. 👁️\n\n"
                         "I'm ThreatVista's security intelligence assistant. I read live endpoint telemetry, behavioural baselines, alerts and incidents, then explain *in plain language* what each person did, whether it's a problem, and what to do about it.",
                "data": {}, "suggested_actions": ["What can you do?", "Give me a security overview"]}
    if _has(msg, ["what can you do", "help", "capabilities", "how to use", "commands", "what do you know"]) and len(clean.split()) <= 8:
        ex = top.name.split()[0] if top else "Nandini"
        return {"reply": "Here's what you can ask me — in plain English:\n\n"
                         "| Category | Example |\n|---|---|\n"
                         f"| 👤 Any employee | *“Tell me about {ex}”*, *“What did {ex} do today?”* |\n"
                         f"| ⚠️ Problems | *“Is there any problem with {ex}?”* |\n"
                         f"| 🔍 Specific activity | *“Show {ex}'s USB activity”*, *“Did she delete any files?”* |\n"
                         "| 🧮 Explain | *“Why is her risk score high?”* |\n"
                         "| ⚖️ Compare | *“Compare Nandini and Vaidehi”* |\n"
                         "| 🏢 Departments | *“USB activity in Finance after 8 PM”* |\n"
                         "| 🛰️ Organisation | *“Security overview”*, *“Top 5 riskiest employees”* |\n"
                         "| 📁 Incidents | *“Analyze latest incident”*, *“Pending approvals”* |\n"
                         "| 📚 Concepts | *“How does the Shadow Vault work?”*, *“What is zero trust?”* |\n\n"
                         "I remember context, so follow-ups like *“what about her alerts?”* work too.",
                "data": {}, "suggested_actions": ["Give me a security overview", f"Tell me about {ex}"]}
    return None


# ---------------------------------------------------------------------------
# Keyword evidence search (last-resort grounding)
# ---------------------------------------------------------------------------
def _evidence_search(db: Session, msg: str, employees: List[Employee]) -> Optional[Dict[str, Any]]:
    terms = [t for t in re.findall(r"[a-z0-9_.\-]{4,}", msg) if t not in COMMON_WORDS][:4]
    if not terms:
        return None
    by_id = {e.id: e for e in employees}
    hits: List[Event] = []
    for t in terms:
        like = f"%{t}%"
        hits += db.query(Event).filter((Event.filename.ilike(like)) | (Event.folder.ilike(like)) | (Event.details.ilike(like))).order_by(Event.timestamp.desc()).limit(15).all()
    if not hits:
        return None
    seen, uniq = set(), []
    for h in hits:
        if h.id not in seen:
            seen.add(h.id)
            uniq.append(h)
    rows = ["| Time | Employee | Action |", "|---|---|---|"]
    rows += [f"| {_fmt_ts(e.timestamp)} | {by_id[e.employee_id].name if e.employee_id in by_id else '—'} | {_describe_event(e)} |" for e in uniq[:12]]
    return {"reply": f"### 🔎 Telemetry search: “{', '.join(terms)}”\n\nI found **{len(uniq)}** matching event(s):\n\n" + "\n".join(rows),
            "data": [], "suggested_actions": ["Give me a security overview"]}


# ---------------------------------------------------------------------------
# Optional LLM (Gemini) grounding
# ---------------------------------------------------------------------------
ARGUS_SYSTEM_PROMPT = (
    "You are ARGUS, the AI security analyst inside ThreatVista, an insider-threat and endpoint security platform. "
    "Answer the analyst like a senior SOC expert: direct, clear, friendly, using GitHub markdown (headings, bullet lists, tables, **bold**). "
    "Ground every factual statement about employees, events, alerts and incidents ONLY in the EVIDENCE block provided. "
    "Never invent names, numbers or events. If the evidence doesn't contain the answer, say so and suggest what to ask. "
    "When asked whether someone has a problem, start with an explicit Yes/No verdict, then justify it. "
    "End with a short recommendation when relevant. Never call yourself anything other than ARGUS."
)


def _llm_key() -> Optional[str]:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")


def _llm_answer(message: str, history: List[Dict[str, str]], evidence: str) -> Optional[str]:
    key = _llm_key()
    if not key:
        return None
    model = os.environ.get("ARGUS_LLM_MODEL", "gemini-2.0-flash")
    contents = []
    for turn in (history or [])[-8:]:
        role = "user" if turn.get("role") == "user" else "model"
        txt = (turn.get("text") or "")[:3000]
        if txt:
            contents.append({"role": role, "parts": [{"text": txt}]})
    contents.append({"role": "user", "parts": [{"text": f"EVIDENCE (live ThreatVista database):\n{evidence[:24000]}\n\nANALYST QUESTION: {message}"}]})
    body = json.dumps({
        "systemInstruction": {"parts": [{"text": ARGUS_SYSTEM_PROMPT}]},
        "contents": contents,
        "generationConfig": {"temperature": 0.4, "maxOutputTokens": 1400},
    }).encode()
    req = urllib.request.Request(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={key}",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            out = json.loads(resp.read().decode())
        return "".join(p.get("text", "") for p in out["candidates"][0]["content"]["parts"]).strip() or None
    except Exception:
        return None


def _org_snapshot(employees: List[Employee]) -> str:
    rows = [f"- id={e.id} | {e.name} | {e.department} | {e.role_type} | risk={e.risk_score or 0}% | {e.status}"
            for e in sorted(employees, key=lambda e: -(e.risk_score or 0))[:80]]
    return "EMPLOYEE ROSTER:\n" + "\n".join(rows)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
def argus_chat(db: Session, message: str, employee_id: Optional[int] = None,
               context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    msg = (message or "").lower().strip()
    context = context or {}
    history: List[Dict[str, str]] = context.get("history") or []
    employees = db.query(Employee).all()
    win = _parse_time_window(msg)
    facets = _detect_facets(msg)

    result = _route(db, msg, employees, facets, win, history, employee_id, context)

    # Optional LLM polish, grounded in what the native engine retrieved
    if _llm_key() and result.get("intent") not in ("small_talk",):
        evidence = _org_snapshot(employees) + "\n\nRETRIEVED ANALYSIS:\n" + result["reply"]
        llm = _llm_answer(message, history, evidence)
        if llm:
            result["reply"] = llm
            result["engine"] = "gemini"
    result.setdefault("engine", "argus-native")
    result.pop("intent", None)
    return result


def _route(db, msg, employees, facets, win, history, employee_id, context) -> Dict[str, Any]:
    if not msg:
        return {"reply": "Ask me anything about your employees, incidents or security posture.", "data": {}, "suggested_actions": ["What can you do?"]}

    talk = _small_talk(msg, employees)
    if talk:
        talk["intent"] = "small_talk"
        return talk

    mentioned = _resolve_employees(msg, employees)

    # Comparison
    if len(mentioned) >= 2 and (_has(msg, ["compare", "versus", "vs", "difference", "between", "who is riskier", "which one"]) or " and " in msg):
        return _compare_employees(db, mentioned, win)

    # Conceptual questions ("what is zero trust?") go straight to the knowledge base
    if not mentioned and re.match(r"^(what is|what's|whats|what are|define|explain what|how does|how do|tell me about the|meaning of)\b", msg):
        kb = _knowledge(msg)
        if kb:
            return kb

    GLOBAL_WORDS = ["anyone", "anybody", "everyone", "every employee", "employees", "organisation", "organization",
                    "company", "all users", "latest", "pending", "who ", "which employee", "any employee", "overall", "team"]

    # Pronoun / follow-up resolution
    target: Optional[Employee] = mentioned[0] if mentioned else None
    if not target:
        uses_pronoun = any(re.search(rf"\b{re.escape(p)}\b", msg) for p in PRONOUNS)
        specific = [f for f in facets if f not in ("problem", "activity", "files")]
        followup = msg.startswith(("what about", "and ", "how about", "also", "same for", "now show")) or \
            (len(msg.split()) <= 3 and bool(specific))
        is_global = _has(msg, GLOBAL_WORDS)
        if uses_pronoun or (followup and not is_global and not _resolve_department(msg)):
            fid = (context.get("focus_employee") or {}).get("id") if isinstance(context.get("focus_employee"), dict) else None
            target = next((e for e in employees if e.id == fid), None) if fid else None
            target = target or _employee_from_history(history, employees)
            if not target and employee_id:
                target = next((e for e in employees if e.id == employee_id), None)
        elif employee_id and specific and not is_global and not _resolve_department(msg):
            target = next((e for e in employees if e.id == employee_id), None)

    if target:
        return _employee_answer(db, target, facets, win, msg)

    dept = _resolve_department(msg)

    # Lists & rankings
    if _has(msg, ["list employees", "all employees", "show employees", "list all", "everyone", "how many employees", "who works", "staff list", "list users", "all users"]):
        return _list_employees(employees, dept)
    if _has(msg, ["high risk", "high-risk", "riskiest", "most risky", "most dangerous", "suspicious employees", "suspicious users",
                  "who is risky", "who are risky", "top", "lowest risk", "safest", "least risky", "low risk", "rank", "ranking", "worst"]):
        if not dept:
            return _ranking(employees, msg)

    if dept:
        return _department_answer(db, employees, dept, win, facets)

    for f in ("incidents", "alerts", "requests", "usb", "delete", "upload"):
        if f in facets:
            ans = _global_facet(db, employees, f, win)
            if ans:
                return ans

    if _has(msg, ["latest incident", "recent incident", "analyze incident", "analyse incident"]):
        return _global_facet(db, employees, "incidents", win)

    if _has(msg, ["overview", "summary", "summarize", "summarise", "posture", "status", "situation", "dashboard", "brief",
                  "what's happening", "whats happening", "what is happening", "anything wrong", "any threats", "how are we", "report"]):
        return _org_overview(db, employees)

    kb = _knowledge(msg)
    if kb:
        return kb

    if win.get("off_hours"):
        q = db.query(Event).order_by(Event.timestamp.desc()).limit(1500).all()
        hits = [e for e in q if _in_window(e.timestamp, win)]
        by_id = {e.id: e for e in employees}
        per = Counter(by_id[e.employee_id].name for e in hits if e.employee_id in by_id).most_common(8)
        if per:
            return {"reply": "### 🌙 Off-hours activity\n\n" + "\n".join(f"- **{n}** — {c} action(s)" for n, c in per),
                    "data": [], "suggested_actions": [f"What did {per[0][0].split()[0]} do?"]}

    found = _evidence_search(db, msg, employees)
    if found:
        return found

    # Honest, helpful fallback with "did you mean"
    tokens = [t for t in re.findall(r"[a-z]+", msg) if len(t) >= 3 and t not in COMMON_WORDS]
    names = {p: e for e in employees for p in re.findall(r"[a-z]+", (e.name or "").lower())}
    guess = None
    for t in tokens:
        close = difflib.get_close_matches(t, list(names), n=1, cutoff=0.7)
        if close:
            guess = names[close[0]]
            break
    if guess:
        return {"reply": f"I couldn't find an exact match. Did you mean **{guess.name}** ({guess.department})?",
                "data": {}, "suggested_actions": [f"Tell me about {guess.name}", f"Is there any problem with {guess.name.split()[0]}?"]}
    return {"reply": "I don't have data that answers that directly, but here's how I can help:\n\n"
                     "- Ask about **any employee by name** — *“what did Vaidehi do?”*\n"
                     "- Ask about a **department** — *“risk in Finance”*\n"
                     "- Ask about **activity types** — USB, deletions, uploads, alerts, incidents, approvals\n"
                     "- Ask **security concepts** — ransomware, zero trust, MITRE ATT&CK, DLP\n\n"
                     "Try rephrasing, or pick a suggestion below.",
            "data": {}, "suggested_actions": ["Give me a security overview", "Show high-risk employees", "What can you do?"]}
