#!/usr/bin/env python3
"""
ThreatVista - Reset Database to Clean Seeded State

Backs up the current SQLite database, drops all tables, and re-seeds the
demo dataset (3 employees, behavior DNA profiles, risk history, admin +
analyst accounts, default system config).

Usage:
    python scripts/reset_db.py

The backup is written to database/threatvista.backup-<timestamp>.db
"""
import sys
import shutil
import time
import os

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
    print("=" * 60)
    print("  ThreatVista - Database Reset")
    print("=" * 60)

    backup_db()
    print("[*] Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    print("[*] Re-creating schema and seeding...")
    init_db()
    print("\n[+] Reset complete. Login with admin / admin123")


if __name__ == "__main__":
    main()
