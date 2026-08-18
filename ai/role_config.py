import os
import json
from typing import Dict, Any, List, Optional

CONFIG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "role_config.json")

# Fallback default roles in case JSON is missing or corrupted
DEFAULT_ROLES = {
    "General": {
        "display_name": "General",
        "description": "Default baseline profile for general employees with standard corporate behavioral bounds.",
        "common_extensions": [".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".csv", ".txt", ".png", ".jpg"],
        "suspicious_extensions": [".kdbx", ".pem", ".key", ".sh", ".exe"],
        "max_normal_file_copies_24h": 50,
        "max_normal_file_creates_24h": 40,
        "max_normal_file_modifies_24h": 80,
        "source_code_normal": False,
        "high_process_activity_normal": False,
        "risk_modifiers": {
            "mass_file_creation_risk": 30,
            "source_code_copy_risk": 30,
            "zip_copy_risk": 25,
            "process_burst_risk": 15
        },
        "explanations": {
            "mass_files": "Mass file operations (+30) detected outside standard general baseline.",
            "source_code_transfer": "Source code file operations (+30) flagged for general corporate role.",
            "role_context": "General baseline active: standard corporate thresholds."
        }
    }
}

_cached_config: Optional[Dict[str, Any]] = None

def load_role_configs() -> Dict[str, Any]:
    """Load role configurations from JSON file with caching."""
    global _cached_config
    if _cached_config is not None:
        return _cached_config

    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                _cached_config = data.get("roles", DEFAULT_ROLES)
                return _cached_config
        except Exception as e:
            print(f"[!] Error loading role_config.json: {e}")
    
    _cached_config = DEFAULT_ROLES
    return _cached_config

def get_role_config(role_name: Optional[str]) -> Dict[str, Any]:
    """Get the baseline configuration for a specific role. Falls back to 'General'."""
    configs = load_role_configs()
    if not role_name:
        return configs.get("General", DEFAULT_ROLES["General"])
    
    # Direct lookup or case-insensitive matching
    if role_name in configs:
        return configs[role_name]
    
    norm = role_name.strip().lower()
    for key, cfg in configs.items():
        if key.lower() == norm or cfg.get("display_name", "").lower() == norm:
            return cfg
    
    # Fallback to department name mapping
    if norm in ("engineering", "dev", "tech", "r&d"):
        return configs.get("Developer", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("human resources", "hr", "people"):
        return configs.get("HR", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("finance", "accounting", "accounts"):
        return configs.get("Finance", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("sales", "business development", "marketing"):
        return configs.get("Sales", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("security", "soc", "infosec", "cybersecurity"):
        return configs.get("Security Analyst", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("it", "information technology", "support", "helpdesk"):
        return configs.get("IT Support", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("admin", "administration", "sysadmin", "devops"):
        return configs.get("Administrator", configs.get("General", DEFAULT_ROLES["General"]))
    elif norm in ("management", "executive", "leadership", "manager"):
        return configs.get("Manager", configs.get("General", DEFAULT_ROLES["General"]))

    return configs.get("General", DEFAULT_ROLES["General"])

def get_supported_roles() -> List[str]:
    """Return list of supported role names."""
    configs = load_role_configs()
    return list(configs.keys())

def get_all_role_baselines() -> Dict[str, Any]:
    """Return dictionary of all role baselines for API/UI."""
    return load_role_configs()
