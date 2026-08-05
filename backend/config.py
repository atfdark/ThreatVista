"""
ThreatVista runtime configuration.

Centralises environment-driven settings so secrets never live in source code.
All values can be overridden through a `.env` file at the project root
(see `.env.example`) or via real environment variables.

Environment variables:
    THREATVISTA_SECRET_KEY  JWT signing secret. In production this MUST be set
                            to a long random value.
    THREATVISTA_CORS_ORIGINS  Comma-separated allowed browser origins.
    THREATVISTA_AGENT_KEY   Shared secret for endpoint agents. When set,
                            POST /api/events requires an X-Agent-Key header.
"""
import os

from dotenv import load_dotenv

# Load .env from the project root (one level above this package).
_ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
load_dotenv(_ENV_PATH)


def _env_list(name: str, default: str) -> list:
    raw = os.environ.get(name, default)
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


# JWT signing secret. Dev fallback keeps the demo runnable out of the box, but
# the README warns deployments to set THREATVISTA_SECRET_KEY.
SECRET_KEY = os.environ.get(
    "THREATVISTA_SECRET_KEY", "dev-only-insecure-key-change-me"
)

# LAN demo mode. When 1 (default), the API answers browser requests from ANY
# origin so teammates can open the dashboard at http://<server-ip>:5173 without
# editing a CORS allow-list. Set THREATVISTA_LAN=0 to restrict to the origins
# below (safer for non-demo deployments).
LAN_MODE = os.environ.get("THREATVISTA_LAN", "1").lower() in ("1", "true", "yes")

# Allowed browser origins for CORS (dev defaults are the Vite dev server).
CORS_ORIGINS = (
    ["*"] if LAN_MODE
    else _env_list("THREATVISTA_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
)

# Host/port the API server binds. 0.0.0.0 exposes it on every interface so
# LAN agents and dashboards can reach it (hackathon default).
HOST = os.environ.get("THREATVISTA_HOST", "0.0.0.0")
PORT = int(os.environ.get("THREATVISTA_PORT", "8000"))

# Optional shared key for endpoint agents posting telemetry. When empty, the
# /api/events endpoint stays open (hackathon default).
AGENT_API_KEY = os.environ.get("THREATVISTA_AGENT_KEY", "")
