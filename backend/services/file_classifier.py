"""
ThreatVista AI File Sensitivity Classification Service.

Classifies target files into enterprise sensitivity tiers:
- RESTRICTED (Highest sensitivity: passwords, crypto keys, source code, database dumps, banking data)
- CONFIDENTIAL (High sensitivity: payroll, salary, HR records, financial ledgers, customer PII)
- INTERNAL (Standard corporate: project plans, presentations, meeting notes, documentation)
- PUBLIC (Low/No sensitivity: photos, marketing collateral, wallpapers, public media)

Uses multi-factor evaluation across filename tokens, extension, directory paths, and file metadata.
"""
import os
import re
from typing import Dict, Optional, Set, Tuple


# Classification Categories
RESTRICTED = "RESTRICTED"
CONFIDENTIAL = "CONFIDENTIAL"
INTERNAL = "INTERNAL"
PUBLIC = "PUBLIC"

# Rule & Keyword Dictionaries
RESTRICTED_KEYWORDS = {
    "bank", "banking", "transaction", "transactions", "secret", "secrets",
    "password", "passwords", "credential", "credentials", "token", "tokens",
    "private_key", "privkey", "id_rsa", "keystore", "wallet", "seed",
    "source_code", "source code", "source", "database", "db_dump", "db dump",
    "sql_dump", "patent", "patents", "crypto", "vault", "master", "exploit", "payload"
}

RESTRICTED_EXTENSIONS = {
    ".kdbx", ".key", ".pem", ".pfx", ".p12", ".sql", ".db", ".sqlite",
    ".env", ".id_rsa", ".ovpn", ".dump"
}

CONFIDENTIAL_KEYWORDS = {
    "salary", "salaries", "payroll", "payrolls", "compensation", "bonus",
    "employee", "employees", "performance", "appraisal", "personnel", "pii",
    "financial", "financials", "revenue", "invoice", "invoices", "tax", "taxes",
    "ledger", "balance_sheet", "budget", "budgets", "audit", "audits",
    "client", "clients", "customer", "customers", "contract", "contracts",
    "nda", "agreement", "ssn", "passport", "medical"
}

INTERNAL_KEYWORDS = {
    "presentation", "deck", "pitch", "meeting", "minutes", "agenda",
    "project", "roadmap", "strategy", "plan", "workflow", "guide",
    "sop", "notes", "memo", "spec", "specification", "draft", "architecture",
    "design", "report", "summary", "internal", "team", "onboarding"
}

INTERNAL_EXTENSIONS = {
    ".pptx", ".ppt", ".docx", ".doc", ".xlsx", ".xls", ".pdf",
    ".md", ".txt", ".json", ".yaml", ".yml", ".vsd", ".vsdx"
}

PUBLIC_KEYWORDS = {
    "holiday", "photo", "photos", "vacation", "wallpaper", "image", "images",
    "screenshot", "screenshots", "pic", "picture", "pictures", "banner",
    "logo", "icon", "public", "marketing", "brochure", "flyer", "press_release",
    "sample", "readme", "license", "template"
}

PUBLIC_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".bmp", ".webp", ".ico",
    ".mp4", ".mov", ".avi", ".mkv", ".mp3", ".wav", ".ttf", ".woff"
}


def _tokenize(text: str) -> Set[str]:
    """Tokenize filename and path components into normalized lowercase tokens and bi-grams."""
    if not text:
        return set()
    raw = text.lower().strip()
    s = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
    clean = re.sub(r"[\W_]+", " ", s).lower()
    words = clean.split()
    tokens = set(words)
    tokens.add(raw)
    for i in range(len(words) - 1):
        tokens.add(f"{words[i]}_{words[i+1]}")
        tokens.add(f"{words[i]} {words[i+1]}")
    return tokens


def classify_file(file_path: str, filename: Optional[str] = None) -> Dict:
    """Classify a file into PUBLIC, INTERNAL, CONFIDENTIAL, or RESTRICTED.

    Returns:
        {
            "classification": "CONFIDENTIAL",
            "confidence": 0.92,
            "reason": "Filename contains payroll keyword"
        }
    """
    path_str = str(file_path or "").strip()
    file_name = filename or os.path.basename(path_str) or path_str
    _, ext = os.path.splitext(file_name)
    ext = ext.lower()

    name_tokens = _tokenize(file_name)
    path_tokens = _tokenize(path_str)
    all_tokens = name_tokens.union(path_tokens)

    # 1. Check RESTRICTED criteria (Highest priority)
    matched_restricted_ext = ext in RESTRICTED_EXTENSIONS
    matched_restricted_kw = name_tokens.intersection(RESTRICTED_KEYWORDS)
    if matched_restricted_kw:
        kw = next(iter(matched_restricted_kw))
        return {
            "classification": RESTRICTED,
            "confidence": 0.96,
            "reason": f"File matches restricted asset keyword '{kw}'"
        }
    if matched_restricted_ext:
        return {
            "classification": RESTRICTED,
            "confidence": 0.94,
            "reason": f"File extension '{ext}' is classified as restricted security credential / database format"
        }
    if any(k in path_tokens for k in {"passwords", "keys", "vault", "source_code", "db_dump"}):
        return {
            "classification": RESTRICTED,
            "confidence": 0.90,
            "reason": "File is stored in a restricted system directory"
        }

    # 2. Check CONFIDENTIAL criteria
    matched_confidential_kw = name_tokens.intersection(CONFIDENTIAL_KEYWORDS)
    if matched_confidential_kw:
        kw = next(iter(matched_confidential_kw))
        return {
            "classification": CONFIDENTIAL,
            "confidence": 0.93,
            "reason": f"Filename contains sensitive company asset keyword '{kw}'"
        }
    if any(k in path_tokens for k in {"payroll", "hr", "accounting", "finance", "legal", "contracts"}):
        return {
            "classification": CONFIDENTIAL,
            "confidence": 0.88,
            "reason": "File is located within a confidential departmental repository (HR/Finance/Legal)"
        }

    # 3. Check PUBLIC criteria
    matched_public_kw = name_tokens.intersection(PUBLIC_KEYWORDS)
    matched_public_ext = ext in PUBLIC_EXTENSIONS
    if matched_public_kw and matched_public_ext:
        return {
            "classification": PUBLIC,
            "confidence": 0.95,
            "reason": f"File '{file_name}' matches public media asset profile"
        }
    if matched_public_ext and not (all_tokens.intersection(CONFIDENTIAL_KEYWORDS) or all_tokens.intersection(RESTRICTED_KEYWORDS)):
        return {
            "classification": PUBLIC,
            "confidence": 0.90,
            "reason": f"File extension '{ext}' is a standard public image/media type"
        }

    # 4. Check INTERNAL criteria
    matched_internal_kw = name_tokens.intersection(INTERNAL_KEYWORDS)
    if matched_internal_kw:
        kw = next(iter(matched_internal_kw))
        return {
            "classification": INTERNAL,
            "confidence": 0.86,
            "reason": f"File contains internal business operational keyword '{kw}'"
        }
    if ext in INTERNAL_EXTENSIONS:
        return {
            "classification": INTERNAL,
            "confidence": 0.82,
            "reason": f"Standard internal corporate document format ('{ext}')"
        }

    # Default fallback
    return {
        "classification": INTERNAL,
        "confidence": 0.75,
        "reason": "Classified as general internal corporate document by default baseline"
    }
