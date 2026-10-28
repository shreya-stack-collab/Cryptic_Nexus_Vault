"""Isolated functional smoke test for Cryptic Nexus Vault.

Runs against a temporary copy so it does not modify your real vault/database.
Requires dependencies from requirements.txt to be installed first.
"""
import importlib.util
import io
import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def check(condition, message):
    if not condition:
        raise RuntimeError("FAIL: " + message)
    print("PASS: " + message)


def main():
    with tempfile.TemporaryDirectory(prefix="cnv-smoke-") as temp:
        temp_path = Path(temp)
        shutil.copy2(ROOT / "app.py", temp_path / "app.py")
        shutil.copytree(ROOT / "templates", temp_path / "templates")
        shutil.copytree(ROOT / "static", temp_path / "static")
        sys.path.insert(0, str(temp_path))
        spec = importlib.util.spec_from_file_location("cnv_smoke_app", temp_path / "app.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        sent_emails = []
        def fake_send_email(to, subject, body):
            sent_emails.append((to, subject, body)); return True
        module.send_email = fake_send_email
        client = module.app.test_client()

        response = client.get('/register')
        check(response.status_code == 200, 'registration page loads')
        check(client.get('/features').status_code == 200, 'feature status page loads')
        response = client.post('/register', data={
            'username': 'smoketestuser', 'email': 'smoketest@example.test',
            'phone': '', 'password': 'SmokeTestPassword123!'
        }, follow_redirects=True)
        check(response.status_code == 200 and b'Sign in' in response.data, 'registration creates an account')

        response = client.post('/login', data={'identity': 'smoketestuser', 'password': 'SmokeTestPassword123!'})
        check(response.status_code == 302 and '/verify-login' in response.location, 'password login requires second factor')
        import re
        otp_match = re.search(r'one-time code is (\d{6})', sent_emails[-1][2])
        otp = otp_match.group(1) if otp_match else None
        check(bool(otp and len(otp) == 6), 'login sends an email containing a six-digit OTP')
        response = client.post('/verify-login', data={'otp': otp}, follow_redirects=True)
        check(response.status_code == 200 and b'Security,' in response.data, 'OTP verification opens the dashboard')

        response = client.post('/vault', data={'file': (io.BytesIO(b'CNV smoke test payload'), 'smoke.txt')}, content_type='multipart/form-data')
        check(response.status_code == 302, 'vault accepts and encrypts a file')
        with sqlite3.connect(temp_path / 'instance' / 'cryptic_nexus.sqlite3') as con:
            file_row = con.execute('SELECT id,stored_name FROM files LIMIT 1').fetchone()
        check(bool(file_row), 'encrypted file metadata is stored in SQLite')
        stored = (temp_path / 'vault_files' / file_row[1]).read_bytes()
        check(b'CNV smoke test payload' not in stored, 'vault storage does not contain plaintext payload')
        response = client.get('/vault/download/' + str(file_row[0]))
        check(response.status_code == 200 and response.data == b'CNV smoke test payload', 'vault decrypts a download correctly')

        # A second local account verifies username-addressed encrypted attachments.
        response = client.post('/register', data={
            'username': 'seconduser', 'email': 'second@example.test',
            'phone': '', 'password': 'SecondTestPassword123!'
        }, follow_redirects=True)
        check(response.status_code == 200, 'second account can be registered')
        response = client.post('/chat', data={
            'recipient': 'seconduser', 'message': 'Encrypted attachment smoke test',
            'attachment': (io.BytesIO(b'private attachment payload'), 'private.txt')
        }, content_type='multipart/form-data')
        check(response.status_code == 302, 'chat accepts a message with an attachment')
        with sqlite3.connect(temp_path / 'instance' / 'cryptic_nexus.sqlite3') as con:
            att = con.execute('SELECT a.id,a.stored_name FROM message_attachments a LIMIT 1').fetchone()
        check(bool(att), 'message attachment metadata is stored')
        encrypted_attachment = (temp_path / 'vault_files' / att[1]).read_bytes()
        check(b'private attachment payload' not in encrypted_attachment, 'message attachment is encrypted at rest')
        response = client.get('/chat/attachment/' + str(att[0]))
        check(response.status_code == 200 and response.data == b'private attachment payload', 'sender can download and decrypt the attachment')

        # Image steganography round-trip.
        from PIL import Image
        cover = io.BytesIO(); Image.new('RGB', (400, 400), (120, 130, 140)).save(cover, format='PNG'); cover.seek(0)
        hidden = module._image_hide(cover, 'hidden smoke text')
        check(module._image_extract(hidden) == 'hidden smoke text', 'image steganography embeds and extracts text')
        # Text-file steganography round-trip via the HTTP route.
        response = client.post('/steganography', data={
            'action': 'hide', 'media': 'text', 'secret': 'hidden text file',
            'media_file': (io.BytesIO(b'ordinary cover text'), 'cover.txt')
        }, content_type='multipart/form-data')
        check(response.status_code == 200 and response.data.startswith(b'ordinary cover text'), 'text steganography creates a downloadable cover file')

        with client.session_transaction() as sess:
            sess.clear()
        response = client.get('/admin')
        check(response.status_code == 403, 'administrator console blocks unauthenticated visitors')
        admin = module.app.test_client()
        admin_password = (temp_path / 'instance' / 'admin_initial_password.txt').read_text(encoding='utf-8').strip()
        response = admin.post('/admin/login', data={'username': 'admin', 'password': admin_password}, follow_redirects=True)
        check(response.status_code == 200 and b'Admin' in response.data and b'Login history' in response.data, 'separate administrator login opens console and login history')
        check(client.get('/dashboard').status_code in (302, 401), 'user session does not inherit administrator access')

        # TOTP enrollment remains available, but mandatory email OTP is used on every login.
        secret = module.new_totp_secret()
        with sqlite3.connect(temp_path / 'instance' / 'cryptic_nexus.sqlite3') as con:
            con.execute('UPDATE users SET totp_secret=?,totp_enabled=1 WHERE username=?', (secret, 'smoketestuser'))
        check(module.verify_totp(secret, module.totp_code(secret)), 'authenticator TOTP codes verify')
        wrong_code = '000000' if module.totp_code(secret) != '000000' else '000001'
        check(not module.verify_totp(secret, wrong_code), 'invalid TOTP is rejected')
        response = client.post('/login', data={'identity': 'smoketestuser', 'password': 'SmokeTestPassword123!'})
        check(response.status_code == 302 and '/verify-login' in response.location, 'TOTP-enabled account still requires email OTP at login')
        otp_match = re.search(r'one-time code is (\d{6})', sent_emails[-1][2])
        otp = otp_match.group(1) if otp_match else None
        response = client.post('/verify-login', data={'otp': otp}, follow_redirects=True)
        check(response.status_code == 200 and b'Security,' in response.data, 'email OTP completes login when authenticator is configured')

        # WAV LSB round-trip using a small PCM sample.
        wav_in = io.BytesIO()
        import wave
        with wave.open(wav_in, 'wb') as w:
            w.setnchannels(1); w.setsampwidth(2); w.setframerate(8000); w.writeframes(b'\x10\x00' * 12000)
        wav_in.seek(0); wav_out = module._wav_hide(wav_in, 'wav secret')
        check(module._wav_extract(wav_out) == 'wav secret', 'PCM WAV steganography embeds and extracts text')

        print('\nAll smoke checks passed. Temporary test data was removed.')


if __name__ == '__main__':
    main()
