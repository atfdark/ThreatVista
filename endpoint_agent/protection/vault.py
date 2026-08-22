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

    @staticmethod
    def _force_remove_file(path: str, max_retries: int = 15, retry_delay: float = 0.2) -> bool:
        """Forcefully remove a file, clearing read-only flags and handling Windows Explorer write locks with retries."""
        import time
        import stat
        if not path or not os.path.exists(path):
            return True

        for _ in range(max_retries):
            try:
                # Reset file attributes (remove read-only / hidden flags if set)
                try:
                    os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
                except Exception:
                    pass

                # Try truncating file if write handle can open it
                try:
                    with open(path, "w") as f:
                        f.truncate(0)
                except Exception:
                    pass

                os.remove(path)
                return True
            except (OSError, PermissionError):
                time.sleep(retry_delay)

        return not os.path.exists(path)

    def quarantine_file(
        self,
        original_path: str,
        source_path: Optional[str] = None,
        max_retries: int = 25,
        retry_delay: float = 0.15,
    ) -> bool:
        """Back up file to shadow vault and remove it from the destination drive (e.g. USB)."""
        import time
        # Retry loop to handle Windows Explorer file locks during copy/paste
        backed_up = False
        for _ in range(max_retries):
            if not os.path.exists(original_path):
                time.sleep(retry_delay)
                continue
            if self.backup_file(original_path):
                backed_up = True
                break
            time.sleep(retry_delay)

        if not backed_up:
            return False

        # If source_path was provided and still exists, back it up as well
        if source_path and os.path.isfile(source_path):
            self.backup_file(source_path)

        # Now remove the file from the target destination drive (e.g. USB)
        removed = self._force_remove_file(original_path, max_retries=max_retries, retry_delay=retry_delay)
        if removed:
            print(f"[🛡️ ThreatVista Protection] Quarantined file from USB to Shadow Vault: {original_path}")
        return removed

    def restore_quarantined_to_source(self, target_path: str, source_path: str) -> bool:
        """Restore quarantined file snapshot to a local source directory (e.g. Downloads)."""
        try:
            shadow_path = self._get_shadow_path(target_path)
            if not os.path.isfile(shadow_path):
                # Try source_path shadow path fallback
                shadow_path = self._get_shadow_path(source_path)
                if not os.path.isfile(shadow_path):
                    return False

            parent_dir = os.path.dirname(source_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            shutil.copy2(shadow_path, source_path)
            print(f"[🛡️ ThreatVista Protection] Restored source file safely to: {source_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to restore quarantined file to source: {e}")
            return False

    def release_quarantined_file(self, original_path: str) -> bool:
        """Release quarantined file from shadow vault back onto the destination drive."""
        try:
            shadow_path = self._get_shadow_path(original_path)
            if not os.path.isfile(shadow_path):
                return False

            parent_dir = os.path.dirname(original_path)
            if parent_dir and not os.path.exists(parent_dir):
                os.makedirs(parent_dir, exist_ok=True)

            shutil.copy2(shadow_path, original_path)
            print(f"[🛡️ ThreatVista Protection] Released approved file to USB: {original_path}")
            return True
        except Exception as e:
            print(f"[-] Shadow vault release error: {e}")
            return False

    def purge_quarantined_file(self, original_path: str, fallback_source_path: Optional[str] = None) -> bool:
        """Ensure file is deleted from target drive and purge its quarantine snapshot, preserving source file."""
        try:
            # 1. Remove from destination (USB) forcefully with retries
            removed_from_target = self._force_remove_file(original_path, max_retries=15, retry_delay=0.2)
            if not removed_from_target:
                print(f"[!] Warning: Could not remove target file from USB: {original_path}")
                return False

            shadow_path = self._get_shadow_path(original_path)

            # 2. If source path was specified (or default Downloads) and missing, restore it so user loses no data
            if fallback_source_path and not os.path.exists(fallback_source_path) and os.path.isfile(shadow_path):
                self.restore_quarantined_to_source(original_path, fallback_source_path)

            # 3. Clean up the destination quarantine snapshot
            if os.path.isfile(shadow_path):
                try:
                    os.remove(shadow_path)
                except Exception:
                    pass

            print(f"[🛡️ ThreatVista Protection] Purged rejected file from USB & Vault: {original_path}")
            return True
        except Exception as e:
            print(f"[-] Shadow vault purge error: {e}")
            return False

