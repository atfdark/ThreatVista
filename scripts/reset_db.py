#!/usr/bin/env python3
"""
ThreatVista - Reset Database

Backs up the current SQLite database, drops all tables, and re-seeds.

Modes:
    python scripts/reset_db.py          # demo dataset (3 mock employees, devices,
                                        #   events, alerts) + admin/analyst/auditor
    python scripts/reset_db.py --empty  # NO mock data — only admin/analyst/auditor
                                        #   accounts + system config. The SOC then
                                        #   shows only employees that self-register
                                        #   and their real telemetry.

The backup is written to database/threatvista.backup-<timestamp>.db
"""
import sys
import shutil
import time
import os
import argparse

# Ensure project root is importable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend.database.connection import engine, Base  # noqa: E402
from backend.database.db_setup import init_db  # noqa: E402

DB_PATH = os.path.join(ROOT, "database", "threatvista.db")


def backup_db():
    if not os.path.exists(DB_PATH):
        print("[!] No database found to back up.")
        return None
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup_path = os.path.join(ROOT, "database", f"threatvista.backup-{stamp}.db")
    shutil.copy2(DB_PATH, backup_path)
    print(f"[+] Database backed up to {backup_path}")
    return backup_path


def main():
    parser = argparse.ArgumentParser(description="Reset the ThreatVista database.")
    parser.add_argument(
        "--empty",
        action="store_true",
        help="Seed with NO mock data (only admin/analyst/auditor + config).",
    )
    args = parser.parse_args()

    if args.empty:
        # init_db() reads this flag to skip the demo employees/devices/events.
        os.environ["THREATVISTA_SEED_DEMO"] = "0"

    print("=" * 60)
    print("  ThreatVista - Database Reset" + ("  (EMPTY MODE - no mock data)" if args.empty else ""))
    print("=" * 60)

    backup_db()
    print("[*] Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    print("[*] Re-creating schema and seeding...")
    init_db()
    print("\n[+] Reset complete. Login with admin / admin123")
    if args.empty:
        print("    No mock employees. Register an employee account on the login page to begin.")


if __name__ == "__main__":
    main()
