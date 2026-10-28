"""Passphrase-encrypted backup and restore utility for Cryptic Nexus Vault.

Usage:
  python backup_restore.py backup path/to/backup.cnvb
  python backup_restore.py restore path/to/backup.cnvb
Stop the app before restoring. Keep the passphrase and backup separate.
"""
import getpass
import io
import os
import secrets
import shutil
import sqlite3
import sys
import tempfile
import zipfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

ROOT = Path(__file__).resolve().parent
DB = ROOT / "instance" / "cryptic_nexus.sqlite3"
KEY = ROOT / "instance" / "vault.key"
FILES = ROOT / "vault_files"
MAGIC = b"CNVBKUP1"


def derive(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 10:
        raise ValueError("Use a backup passphrase of at least 10 characters.")
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def backup(destination: Path) -> None:
    if not DB.exists() or not KEY.exists():
        raise FileNotFoundError("The app has not initialized yet. Run it once and create an account before backing up.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cnv-backup-") as temp:
        tempdir = Path(temp)
        snapshot = tempdir / "cryptic_nexus.sqlite3"
        # SQLite's backup API gives a consistent snapshot even while the app is open.
        source = sqlite3.connect(DB)
        target = sqlite3.connect(snapshot)
        try:
            source.backup(target)
        finally:
            target.close(); source.close()
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(snapshot, "instance/cryptic_nexus.sqlite3")
            archive.write(KEY, "instance/vault.key")
            if FILES.exists():
                for item in FILES.rglob("*"):
                    if item.is_file(): archive.write(item, str(Path("vault_files") / item.relative_to(FILES)))
        salt = secrets.token_bytes(16); nonce = secrets.token_bytes(12)
        passphrase = getpass.getpass("Set backup passphrase (10+ characters): ")
        confirm = getpass.getpass("Confirm backup passphrase: ")
        if passphrase != confirm: raise ValueError("Passphrases did not match; no backup was written.")
        ciphertext = AESGCM(derive(passphrase, salt)).encrypt(nonce, payload.getvalue(), MAGIC)
        temp_output = destination.with_suffix(destination.suffix + ".tmp")
        temp_output.write_bytes(MAGIC + salt + nonce + ciphertext)
        temp_output.replace(destination)
        print(f"Encrypted backup created: {destination}")
        print("Keep the passphrase safe. Without it, this backup cannot be restored.")


def restore(source: Path) -> None:
    if not source.is_file(): raise FileNotFoundError(f"Backup not found: {source}")
    blob = source.read_bytes()
    if len(blob) < len(MAGIC) + 28 or blob[:len(MAGIC)] != MAGIC:
        raise ValueError("This is not a valid CNV encrypted backup.")
    offset = len(MAGIC); salt = blob[offset:offset+16]; nonce = blob[offset+16:offset+28]; ciphertext = blob[offset+28:]
    passphrase = getpass.getpass("Backup passphrase: ")
    try: plaintext = AESGCM(derive(passphrase, salt)).decrypt(nonce, ciphertext, MAGIC)
    except Exception as exc: raise ValueError("Could not decrypt backup. Check the passphrase and file integrity.") from exc
    with tempfile.TemporaryDirectory(prefix="cnv-restore-") as temp:
        tempdir = Path(temp)
        try:
            with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
                for name in archive.namelist():
                    target = (tempdir / name).resolve()
                    if not target.is_relative_to(tempdir.resolve()): raise ValueError("Unsafe path inside backup.")
                archive.extractall(tempdir)
        except zipfile.BadZipFile as exc: raise ValueError("Backup contents are damaged.") from exc
        new_db = tempdir / "instance" / "cryptic_nexus.sqlite3"
        new_key = tempdir / "instance" / "vault.key"
        if not new_db.is_file() or not new_key.is_file(): raise ValueError("Backup is missing required database or encryption key.")
        print("WARNING: Restore replaces the current database, encryption key, and encrypted vault files.")
        if input("Type RESTORE to continue: ").strip() != "RESTORE":
            print("Restore cancelled."); return
        # App must be stopped to avoid overwriting files in active use.
        (ROOT / "instance").mkdir(exist_ok=True)
        shutil.copy2(new_db, DB); shutil.copy2(new_key, KEY)
        restored_files = tempdir / "vault_files"
        if FILES.exists(): shutil.rmtree(FILES)
        if restored_files.exists(): shutil.copytree(restored_files, FILES)
        else: FILES.mkdir(parents=True, exist_ok=True)
        print("Restore completed. Start Cryptic Nexus Vault again.")


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] not in {"backup", "restore"}:
        print("Usage: python backup_restore.py backup <file.cnvb> | restore <file.cnvb>")
        raise SystemExit(2)
    path = Path(sys.argv[2]).expanduser().resolve()
    if sys.argv[1] == "backup": backup(path)
    else: restore(path)

if __name__ == "__main__":
    try: main()
    except (OSError, ValueError, sqlite3.Error) as exc:
        print(f"Backup utility error: {exc}")
        raise SystemExit(1)
