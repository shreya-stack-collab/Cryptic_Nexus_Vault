# Migration notes from supplied archive

The original `user-auth` archive contains `register.html`/`register.php`, `login.html`/`login.php`, `dashboard.php`, `vault.html`, `style.css`, `db.php`, `logout.php`, `email_otp_server.py`, and a text code review. The original archive remains unchanged in the conversation.

This edition consolidates the duplicate HTML/PHP login flows and local OTP server into one Flask app with SQLite persistence. Existing goals retained: account registration/login, OTP-based sign-in, dashboard, vault, and steganography. New/expanded capabilities include authenticator TOTP 2FA, separate admin access, encrypted-at-rest messaging by username/email, password recovery, security audit events, responsive theme switching, and SQLite-based local storage.

This is a migration of the supplied source's intended functionality, not a line-for-line conversion of every original PHP fragment. The `project code review.txt` was a review/transcript document, not executable application code.
