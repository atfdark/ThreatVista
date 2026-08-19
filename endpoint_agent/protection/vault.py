"""
ThreatVista Endpoint Shadow Vault.

Maintains secure, lightweight local shadow copies of monitored files.
When an unauthorized deletion occurs, the Shadow Vault instantly restores the
file to the working directory within milliseconds, preventing data loss and
holding the operation until a Security Admin approves it.
"""
import os
import shutil
import hashlib
from typing import Optional


class ShadowVault:
    MAX_SHADOW_FILE_SIZE_MB = 50  # Cap snapshot size to keep vault lightweight

    def __init__(self, vault_dir: Optional[str] = None):
        if vault_dir:
            self.vault_dir = vault_dir
        else:
            base = os.path.expanduser("~")
            self.vault_dir = os.path.join(base, ".threatvista_vault")
        
        os.makedirs(self.vault_dir, exist_ok=True)

    def _get_shadow_path(self, original_path: str) -> str:
        """Derive safe storage path in vault based on path hash and filename."""
        norm = os.path.abspath(original_path).lower()
        path_hash = hashlib.sha256(norm.encode("utf-8")).hexdigest()[:16]
        filename = os.path.basename(original_path)
        return os.path.join(self.vault_dir, f"{path_hash}_{filename}")

    def backup_file(self, original_path: str) -> bool:
        """Create or update shadow snapshot of the given file."""
        try:
            if not os.path.isfile(original_path):
                return False
            
            size = os.path.getsize(original_path)
            if size > self.MAX_SHADOW_FILE_SIZE_MB * 1024 * 1024:
                return False  # Skip giant files to save disk/RAM

            shadow_path = self._get_shadow_path(original_path)
            shutil.copy2(original_path, shadow_path)
            return True
        except (OSError, PermissionError) as e:
            return False

    def has_backup(self, original_path: str) -> bool:
        """Check if shadow copy exists in vault."""
        shadow_path = self._get_shadow_path(original_path)
        return os.path.isfile(shadow_path)

    def restore_file(self, original_path: str) -> bool:
        """Instantly restore deleted/wiped file from shadow vault."""
        try:
            shadow_path = self._get_shadow_path(original_path)
            if not os.path.isfile(shadow_path):
                return False

            parent_dir = os.path.dirname(original_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            shutil.copy2(shadow_path, original_path)
            print(f"[🛡️ ThreatVista Protection] Instantly restored: {original_path}")
            return True
        except Exception as e:
            print(f"[-] Shadow vault restore error: {e}")
            return False

    def purge_file(self, original_path: str) -> bool:
        """Permanently delete working copy and shadow copy upon Admin approval."""
        try:
            # Delete active working copy if present
            if os.path.exists(original_path):
                if os.path.isdir(original_path):
                    shutil.rmtree(original_path, ignore_errors=True)
                else:
                    os.remove(original_path)

            # Purge shadow vault copy
            shadow_path = self._get_shadow_path(original_path)
            if os.path.isfile(shadow_path):
                os.remove(shadow_path)
            
            print(f"[+] Approved deletion executed for: {original_path}")
            return True
        except Exception as e:
            print(f"[-] Shadow vault purge error: {e}")
            return False
