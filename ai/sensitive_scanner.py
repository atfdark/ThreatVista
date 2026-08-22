import re
import time
from typing import List, Dict, Set, Tuple, Optional, Any

DEFAULT_SENSITIVE_KEYWORDS = [
    {"keyword": "salary", "category": "Financial", "risk_weight": 10},
    {"keyword": "payroll", "category": "Financial", "risk_weight": 10},
    {"keyword": "budget", "category": "Financial", "risk_weight": 10},
    {"keyword": "financial", "category": "Financial", "risk_weight": 10},
    {"keyword": "invoice", "category": "Financial", "risk_weight": 10},
    {"keyword": "employee", "category": "HR", "risk_weight": 10},
    {"keyword": "performance", "category": "HR", "risk_weight": 10},
    {"keyword": "client", "category": "Strategic", "risk_weight": 10},
    {"keyword": "customer", "category": "Strategic", "risk_weight": 10},
    {"keyword": "source_code", "category": "Intellectual Property", "risk_weight": 10},
    {"keyword": "patent", "category": "Intellectual Property", "risk_weight": 10},
    {"keyword": "secret", "category": "Intellectual Property", "risk_weight": 10},
    {"keyword": "confidential", "category": "Intellectual Property", "risk_weight": 10},
    {"keyword": "project_alpha", "category": "Strategic", "risk_weight": 10},
    {"keyword": "password", "category": "Security", "risk_weight": 10},
    {"keyword": "credential", "category": "Security", "risk_weight": 10},
    {"keyword": "database", "category": "Intellectual Property", "risk_weight": 10},
    {"keyword": "private", "category": "General", "risk_weight": 10},
    {"keyword": "contract", "category": "Strategic", "risk_weight": 10},
]

ZIP_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz", ".tgz"}

class SensitiveAssetScanner:
    """Lightweight, real-time company sensitive asset detection engine.

    Performs case-insensitive, fuzzy, partial, and exact matching against
    file names, paths, and extensions without reading file contents.
    """
    _cache_time = 0
    _cached_keywords: List[Dict[str, Any]] = []
    _CACHE_TTL = 30  # seconds

    @classmethod
    def get_active_keywords(cls, db=None) -> List[Dict[str, Any]]:
        """Get active sensitive keywords with caching."""
        now = time.time()
        if cls._cached_keywords and (now - cls._cache_time < cls._CACHE_TTL) and db is None:
            return cls._cached_keywords

        if db is not None:
            try:
                from backend.models.database import SensitiveKeyword
                keywords = db.query(SensitiveKeyword).filter(SensitiveKeyword.is_active == True).all()
                if keywords:
                    cls._cached_keywords = [
                        {
                            "id": k.id,
                            "keyword": k.keyword,
                            "category": k.category,
                            "risk_weight": k.risk_weight,
                        }
                        for k in keywords
                    ]
                    cls._cache_time = now
                    return cls._cached_keywords
            except Exception:
                pass

        if not cls._cached_keywords:
            cls._cached_keywords = DEFAULT_SENSITIVE_KEYWORDS
            cls._cache_time = now
        return cls._cached_keywords

    @classmethod
    def invalidate_cache(cls):
        """Force keyword cache refresh on admin update."""
        cls._cached_keywords = []
        cls._cache_time = 0

    @classmethod
    def _clean_tokens(cls, text: str) -> Set[str]:
        """Split text into normalized tokens, including camelCase splits."""
        if not text:
            return set()
        s = re.sub(r"([a-z])([A-Z])", r"\1 \2", text)
        s = re.sub(r"[\W_]+", " ", s).lower()
        return set(s.split())

    @classmethod
    def match_file(
        cls,
        filename: Optional[str],
        folder: Optional[str] = None,
        extension: Optional[str] = None,
        details: Optional[str] = None,
        db=None,
    ) -> Dict[str, Any]:
        """Analyze a single file event and return matched sensitive keywords and risk additions.

        Matches on filename, path/folder, extension, and event details.
        """
        active_keywords = cls.get_active_keywords(db)
        
        target_name = (filename or "").strip()
        target_folder = (folder or "").strip()
        target_ext = (extension or "").lower().strip()
        target_details = (details or "").strip()
        
        full_text = f"{target_name} {target_folder} {target_details}".lower()
        unified_text = re.sub(r"[\W_]+", " ", full_text)
        tokens = cls._clean_tokens(full_text)

        matched_keywords = []
        matched_categories = set()

        for item in active_keywords:
            raw_kw = item.get("keyword", "")
            if not raw_kw:
                continue
            kw = raw_kw.lower().strip()
            if not kw:
                continue

            is_match = False

            # 1. Exact or substring match of full keyword in text or unified text
            if kw in full_text:
                is_match = True
            # 2. Token match (exact / plural / token starts with kw)
            elif any(cls._token_matches(kw, t) for t in tokens):
                is_match = True
            elif " " in kw or "_" in kw:
                kw_clean = kw.replace("_", " ").strip()
                if kw_clean in unified_text:
                    is_match = True
                else:
                    kw_tokens = kw_clean.split()
                    if len(kw_tokens) > 1:
                        kw_condensed = "".join(kw_tokens)
                        full_condensed = "".join(tokens)
                        if kw_condensed in full_condensed:
                            is_match = True

            if is_match and raw_kw not in matched_keywords:
                matched_keywords.append(raw_kw)
                matched_categories.add(item.get("category", "General"))


        match_count = len(matched_keywords)
        is_sensitive = match_count > 0

        # Check if it's a sensitive ZIP archive
        is_zip = target_ext in ZIP_EXTENSIONS or any(target_name.lower().endswith(ze) for ze in ZIP_EXTENSIONS)
        is_sensitive_zip = is_sensitive and is_zip

        # Risk scoring rules:
        # 1 match -> +10
        # 2 matches -> +20
        # 3+ matches -> +30
        # Sensitive ZIP -> +40 bonus (or 40 + keyword additions)
        risk_added = 0
        if is_sensitive_zip:
            # Sensitive ZIP base +40 plus keyword escalation
            kw_bonus = 20 if match_count >= 2 else 10
            risk_added = 40 + kw_bonus
        elif match_count == 1:
            risk_added = 10
        elif match_count == 2:
            risk_added = 20
        elif match_count >= 3:
            risk_added = 30

        # AI Explanation generation
        explanation = ""
        if is_sensitive_zip:
            kw_str = ", ".join(f"'{k}'" for k in matched_keywords)
            explanation = (
                f"Sensitive asset movement detected: company-sensitive keyword(s) {kw_str} "
                f"found in compressed archive '{target_name}'. Risk increased by {risk_added}."
            )
        elif is_sensitive:
            kw_str = ", ".join(f"'{k}'" for k in matched_keywords)
            explanation = (
                f"File name contains company-sensitive keyword(s) {kw_str}. "
                f"Risk increased by {risk_added}."
            )

        return {
            "is_sensitive": is_sensitive,
            "filename": target_name or (target_folder if target_folder else "Unknown file"),
            "matched_keywords": matched_keywords,
            "match_count": match_count,
            "categories": list(matched_categories),
            "is_sensitive_zip": is_sensitive_zip,
            "risk_added": risk_added,
            "explanation": explanation,
        }

    @staticmethod
    def _token_matches(kw: str, token: str) -> bool:
        """Fuzzy/stem token matching for singular/plural/prefixes."""
        if kw == token:
            return True
        if len(kw) >= 4 and token.startswith(kw):
            return True
        # Simple plural check: salary -> salaries, policy -> policies, employee -> employees
        if kw.endswith("y") and token == kw[:-1] + "ies":
            return True
        if token.endswith("y") and kw == token[:-1] + "ies":
            return True
        if token == kw + "s" or kw == token + "s":
            return True
        return False

    @classmethod
    def scan_events(cls, events: List[Dict[str, Any]], db=None) -> Dict[str, Any]:
        """Scan a list of events and aggregate sensitive asset findings."""
        file_events = [e for e in events if (e.get("event_type") or "").startswith("file_") or (e.get("event_type") or "").startswith("folder_")]
        
        matches_found = []
        all_matched_keywords = []
        total_risk_added = 0
        sensitive_zip_count = 0
        keyword_frequencies: Dict[str, int] = {}

        for evt in file_events:
            res = cls.match_file(
                filename=evt.get("filename"),
                folder=evt.get("folder"),
                extension=evt.get("extension"),
                details=evt.get("details"),
                db=db
            )
            if res["is_sensitive"]:
                evt_match = {
                    "event_id": evt.get("id"),
                    "event_type": evt.get("event_type"),
                    "filename": res["filename"],
                    "timestamp": evt.get("timestamp"),
                    "matched_keywords": res["matched_keywords"],
                    "risk_added": res["risk_added"],
                    "is_sensitive_zip": res["is_sensitive_zip"],
                    "explanation": res["explanation"]
                }
                matches_found.append(evt_match)
                total_risk_added = max(total_risk_added, res["risk_added"])
                if res["is_sensitive_zip"]:
                    sensitive_zip_count += 1
                for kw in res["matched_keywords"]:
                    all_matched_keywords.append(kw)
                    keyword_frequencies[kw] = keyword_frequencies.get(kw, 0) + 1

        top_keywords = sorted(
            [{"keyword": k, "count": v} for k, v in keyword_frequencies.items()],
            key=lambda x: x["count"],
            reverse=True
        )

        return {
            "total_sensitive_events": len(matches_found),
            "matches": matches_found,
            "unique_keywords_matched": list(set(all_matched_keywords)),
            "top_matched_keywords": top_keywords,
            "sensitive_zip_count": sensitive_zip_count,
            "max_risk_added": total_risk_added,
        }
