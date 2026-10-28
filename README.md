# Cryptic Nexus Vault — Python + SQLite edition

A local-first cybersecurity major-project prototype migrated from the supplied PHP/MySQL `user-auth` archive. It runs on Windows with Python and does not require XAMPP or MySQL.

## Quick start (Windows)
1. Install Python 3.11+ from https://www.python.org/downloads/ and enable **Add Python to PATH**.
2. Extract this ZIP into a normal writable folder (not inside Program Files).
3. Double-click `run_windows.bat`. The first run creates `.venv` and installs dependencies, so internet is needed once. Later launches reuse the environment.
4. Open `http://127.0.0.1:5000` in your browser.
5. Create a user account. Login is blocked unless the email OTP is successfully delivered. Copy `.env.example` to `.env` and fill in your Gmail SMTP account plus its App Password if SMTP environment variables are not already configured on Windows.
6. To use authenticator 2FA, sign in, open **Account & 2FA**, choose **Set up authenticator 2FA**, scan the QR code in an authenticator app, and enter the six-digit code.

## Separate administrator login
- Open `http://127.0.0.1:5000/admin/login`
- Default username: `admin`. On first launch, a random initial password is generated in `instance/admin_initial_password.txt`. Open that file locally to sign in, then set `CNV_ADMIN_PASSWORD` as a Windows environment variable to choose a new password. Do not share the password file or expose this development server to the public internet.
- Administrator sessions are separate from user sessions. Admin can view user directory and audit logs, not passwords or private keys.

## Email verification setup
The app reads SMTP settings from Windows environment variables or a private `.env` file. Copy `.env.example` to `.env`, then fill `SMTP_USER`, `SMTP_PASSWORD` (Gmail App Password, not your normal account password), and `SMTP_FROM`. `SMTP_HOST=smtp.gmail.com` and `SMTP_PORT=587` are the Gmail defaults. The project archive supplied for migration had the app-password value redacted, so no working secret can be carried over from that source file. Never paste credentials into chat or commit `.env`. Login is blocked if the email OTP cannot be sent; no OTP is displayed in the browser.

## Included features
- User registration, unique username/email, password hashing using scrypt, login attempt throttling, mandatory email OTP second factor (fail-closed when delivery fails), authenticator TOTP 2FA with QR enrollment and one-time recovery codes, password reset links, session logout.
- Separate administrator login and console.
- AES-256-GCM encrypted local file vault, decrypt-on-download, SHA-256 integrity reference, expiry metadata and deletion.
- Secure messaging within the same local installation, addressed by registered username or email; AES-GCM encrypted-at-rest text and attachments up to 20 MB, expiry and read-once text handling. Attachments are encrypted at rest and access is limited to sender/recipient. This is not cross-device messaging or end-to-end encryption.
- Steganography: image LSB (PNG output), PCM WAV audio LSB, lossless FFV1 AVI video LSB (requires OpenCV/FFV1 support), and text-file zero-width Unicode embedding. Lossy conversion/editing can destroy hidden payloads.
- Security event log, login-attempt history with IP/browser agent, session-duration events at logout, RSA-2048 identity key creation, green/amber Day/Night theme, responsive layout, installable-app manifest and static-asset offline cache.
- Passphrase-encrypted backup/restore utility for the SQLite database, vault encryption key, and encrypted files.
- SQLite database created automatically at `instance/cryptic_nexus.sqlite3`.

## Important security and scope notes
- Chat messages are **encrypted at rest with a local application key**. This build is not end-to-end encrypted; the server application can decrypt them. Do not present it as E2EE in a viva.
- Email OTP is mandatory for every login. Email OTP and password-reset delivery require valid SMTP settings; if delivery fails, login is blocked and no reset link is shown.
- SMS OTP is intentionally excluded as requested.
- The vault and database are local and can be used without internet after dependencies are installed, while the local app server is running. The static shell can be cached. This is not a cross-device offline-sync system; email delivery needs internet, and messaging only reaches accounts in this same local database.
- Steganography is not encryption. Encrypt sensitive text separately before hiding it.
- Deleting an encrypted file cannot guarantee forensic erasure from SSDs or filesystem journals.
- The generated local master key is stored at `instance/vault.key`. Back up this key securely. Losing it means encrypted files and stored private keys may become unrecoverable. Keep the whole `instance` folder private.
- The app binds to `127.0.0.1` by default. `CNV_HOST=0.0.0.0` enables access from devices on a trusted LAN, but use it only on a private network: the app is not hardened for public internet exposure. Messages persist in the shared local SQLite database while recipients are away, but this is not an internet relay or cross-device sync service.

## Original project preservation
The supplied archive contained PHP registration/login, dashboard, vault UI and an OTP server script, plus a review text file. This Python edition retains the project's authentication, vault and communication intent while consolidating it into a Flask/SQLite application. The original archive is not modified.

## Original source preservation
The `original_source/user-auth/` folder contains the supplied PHP/HTML/CSS/Python source files and the original project review text for reference. The migrated app runs separately and does not require the old PHP/MySQL files.

## Encrypted backup and restore
1. Stop the app before restoring a backup.
2. Create a backup: `python backup_restore.py backup D:\CNV-Backups\my-vault.cnvb` and enter a strong passphrase when prompted. The output is encrypted with AES-GCM and a scrypt-derived key.
3. Restore: `python backup_restore.py restore D:\CNV-Backups\my-vault.cnvb`. Enter the passphrase and type `RESTORE` to confirm replacement of the current database, key, and vault files.
4. Store the backup and passphrase separately. Losing the passphrase means the backup cannot be restored.

## Run a functional smoke test
After installing dependencies, run `python smoke_test.py` from this folder. The test runs against temporary files and does not alter your real vault. It copies the app into a temporary directory, checks registration, second-factor login, encrypted vault upload/download, separate admin access, and TOTP generation, then removes the temporary test data. It does not modify your working vault database.
