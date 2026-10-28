# Feature status and demo checklist

## Implemented in this package
- [x] Registration and login with scrypt password hashing
- [x] Username/email login and basic attempt throttling
- [x] Email OTP second step with SMTP configuration or local-only development fallback
- [x] Authenticator TOTP 2FA with QR code enrollment, enable/disable verification
- [x] Password reset token with expiry and single-use marking
- [x] Separate administrator login/session and read-only user/audit console
- [x] AES-256-GCM local file encryption/decryption, file expiry metadata, SHA-256 reference
- [x] Encrypted-at-rest messages addressed by username or email, expiry and read-once flag
- [x] Image LSB steganography embed/extract
- [x] Activity logs, RSA identity key pair, responsive Day/Night UI
- [x] SQLite database initialization and Windows launch script

## Partial / not included
- [ ] True end-to-end messaging encryption and secure client-side key exchange
- [ ] SMS OTP provider integration
- [ ] Cross-device offline create/update queue and later sync (not available; local SQLite messages persist while recipient is away)
- [ ] Internet-facing cross-device/LAN/WebRTC transport and QR file-transfer workflow
- [ ] Verified email activation during registration (email OTP is used at login)

The local app shell and vault can be used offline after dependencies are installed. Messaging remains within the same local SQLite installation; it is not E2EE or an internet relay. Do not claim partial items as completed in a presentation. A clearly scoped working prototype is stronger than pretending a stub is a production security system.

- **Encrypted backup and restore:** `backup_restore.py` snapshots SQLite consistently and packages the DB, vault key, and encrypted file blobs into an AES-GCM-encrypted backup using a scrypt-derived passphrase key. Restore requires explicit confirmation and the app to be stopped.
- **Safer first-run admin credential:** a random initial password is created locally in `instance/admin_initial_password.txt` instead of shipping a known shared password.
