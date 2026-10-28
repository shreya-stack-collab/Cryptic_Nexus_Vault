import os, sqlite3, secrets, hashlib, hmac, smtplib, json, base64, io, time, struct, urllib.parse, wave, shutil, subprocess
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort, jsonify
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from PIL import Image

ROOT=os.path.dirname(os.path.abspath(__file__))
# Load local SMTP configuration without an extra dependency. Keep .env private and never commit it.
def load_dotenv():
    path=os.path.join(ROOT,'.env')
    if os.path.isfile(path):
        try:
            for line in open(path,encoding='utf-8'):
                line=line.strip()
                if not line or line.startswith('#') or '=' not in line: continue
                k,v=line.split('=',1); k=k.strip(); v=v.strip().strip('"').strip("'")
                if k and k not in os.environ: os.environ[k]=v
        except OSError: pass
load_dotenv()
INSTANCE=os.path.join(ROOT,'instance'); UPLOADS=os.path.join(ROOT,'vault_files')
os.makedirs(INSTANCE,exist_ok=True); os.makedirs(UPLOADS,exist_ok=True)
DB=os.path.join(INSTANCE,'cryptic_nexus.sqlite3'); KEYFILE=os.path.join(INSTANCE,'vault.key')
if not os.path.exists(KEYFILE):
    with open(KEYFILE,'wb') as f: f.write(AESGCM.generate_key(bit_length=256))
    try: os.chmod(KEYFILE,0o600)
    except OSError: pass
with open(KEYFILE,'rb') as f: MASTER_KEY=f.read()
ADMIN_PASSWORD_FILE=os.path.join(INSTANCE,'admin_initial_password.txt')
if not os.path.exists(ADMIN_PASSWORD_FILE):
    with open(ADMIN_PASSWORD_FILE,'w',encoding='utf-8') as f: f.write(secrets.token_urlsafe(18)+'\n')
    try: os.chmod(ADMIN_PASSWORD_FILE,0o600)
    except OSError: pass
with open(ADMIN_PASSWORD_FILE,encoding='utf-8') as f: DEFAULT_ADMIN_PASSWORD=f.read().strip()
app=Flask(__name__); app.secret_key=os.environ.get('CNV_SESSION_SECRET') or secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH']=25*1024*1024

SCHEMA='''
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE, email TEXT UNIQUE COLLATE NOCASE, phone TEXT, password_hash TEXT, role TEXT DEFAULT 'user', public_key TEXT, private_key_enc BLOB, created_at TEXT, totp_secret TEXT, totp_enabled INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, sender_id INTEGER, recipient_id INTEGER, body_enc BLOB, nonce BLOB, created_at TEXT, expires_at TEXT, read_once INTEGER DEFAULT 0, opened INTEGER DEFAULT 0, deleted INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS message_attachments(id INTEGER PRIMARY KEY, message_id INTEGER NOT NULL, original_name TEXT NOT NULL, stored_name TEXT NOT NULL, nonce BLOB NOT NULL, sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY, user_id INTEGER, original_name TEXT, stored_name TEXT, nonce BLOB, sha256 TEXT, created_at TEXT, expires_at TEXT);
CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, user_id INTEGER, event TEXT, detail TEXT, created_at TEXT);
CREATE TABLE IF NOT EXISTS login_attempts(id INTEGER PRIMARY KEY, username TEXT, created_at REAL, success INTEGER, ip_address TEXT, user_agent TEXT);
CREATE TABLE IF NOT EXISTS reset_tokens(id INTEGER PRIMARY KEY, user_id INTEGER, token_hash TEXT, expires_at TEXT, used INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS recovery_codes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, code_hash TEXT NOT NULL, used_at TEXT);
'''
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; c.execute('PRAGMA foreign_keys=ON'); return c
with db() as c:
    c.executescript(SCHEMA)
    cols={r['name'] for r in c.execute('PRAGMA table_info(users)').fetchall()}
    if 'totp_secret' not in cols: c.execute('ALTER TABLE users ADD COLUMN totp_secret TEXT')
    if 'totp_enabled' not in cols: c.execute('ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0')
    attempt_cols={r['name'] for r in c.execute('PRAGMA table_info(login_attempts)').fetchall()}
    if 'ip_address' not in attempt_cols: c.execute('ALTER TABLE login_attempts ADD COLUMN ip_address TEXT')
    if 'user_agent' not in attempt_cols: c.execute('ALTER TABLE login_attempts ADD COLUMN user_agent TEXT')

def now(): return datetime.utcnow().replace(microsecond=0).isoformat()+'Z'
def pw_hash(p):
    salt=secrets.token_bytes(16); value=hashlib.scrypt(p.encode(),salt=salt,n=2**14,r=8,p=1)
    return base64.b64encode(salt+value).decode()
def pw_ok(p,stored):
    try:
        raw=base64.b64decode(stored); salt,expected=raw[:16],raw[16:]
        return hmac.compare_digest(hashlib.scrypt(p.encode(),salt=salt,n=2**14,r=8,p=1),expected)
    except Exception: return False
def log_event(uid,event,detail=''):
    with db() as c: c.execute('INSERT INTO activity(user_id,event,detail,created_at) VALUES(?,?,?,?)',(uid,event,detail[:300],now()))
def current_user():
    uid=session.get('uid')
    if not uid:return None
    with db() as c: return c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
def login_required(fn):
    @wraps(fn)
    def inner(*a,**kw):
        if not current_user(): flash('Please sign in first.','error'); return redirect(url_for('login'))
        return fn(*a,**kw)
    return inner
def admin_required(fn):
    @wraps(fn)
    def inner(*a,**kw):
        if not session.get('admin'): abort(403)
        return fn(*a,**kw)
    return inner
def send_email(to,subject,body):
    host=os.getenv('SMTP_HOST','smtp.gmail.com'); user=os.getenv('SMTP_USER'); password=os.getenv('SMTP_PASSWORD'); port=int(os.getenv('SMTP_PORT','587'))
    if not all([host,user,password]): return False
    msg=EmailMessage(); msg['Subject']=subject; msg['From']=os.getenv('SMTP_FROM',user); msg['To']=to; msg.set_content(body)
    try:
        with smtplib.SMTP(host,port,timeout=15) as s: s.starttls(); s.login(user,password); s.send_message(msg)
        return True
    except Exception as e: print('Email sending failed:',e); return False
def user_by_recipient(value):
    with db() as c: return c.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE',(value,value)).fetchone()
def derive_chat_key(): return hashlib.sha256(MASTER_KEY+b'cnv-message-storage-v1').digest()
CHAT_KEY=derive_chat_key()
def encrypt_message(text):
    nonce=secrets.token_bytes(12); return nonce,AESGCM(CHAT_KEY).encrypt(nonce,text.encode(),b'cnv-chat-v1')
def decrypt_message(nonce,body): return AESGCM(CHAT_KEY).decrypt(nonce,body,b'cnv-chat-v1').decode()
def create_keys():
    private=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    priv=private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    pub=private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
    nonce=secrets.token_bytes(12); encrypted=AESGCM(MASTER_KEY).encrypt(nonce,priv,b'cnv-private-key')
    return pub.decode(),nonce+encrypted
def totp_code(secret, at=None):
    """RFC 6238 TOTP using SHA-1, 30-second steps, six digits."""
    at = time.time() if at is None else at
    key = base64.b32decode(secret.upper() + '=' * ((8-len(secret)%8)%8))
    counter = int(at // 30)
    digest = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0f
    number = (struct.unpack('>I', digest[offset:offset+4])[0] & 0x7fffffff) % 1000000
    return f'{number:06d}'
def verify_totp(secret, code):
    if not secret or not code or not code.isdigit() or len(code)!=6: return False
    return any(hmac.compare_digest(totp_code(secret, time.time()+step*30), code) for step in (-1,0,1))
def new_totp_secret(): return base64.b32encode(secrets.token_bytes(20)).decode().rstrip('=')

@app.template_filter('epoch_time')
def epoch_time(value):
    try: return datetime.fromtimestamp(float(value)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError,TypeError,OSError): return str(value)

@app.context_processor
def inject(): return {'user':current_user(),'year':datetime.now().year}
@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options']='nosniff'; resp.headers['X-Frame-Options']='DENY'; resp.headers['Referrer-Policy']='strict-origin-when-cross-origin'; resp.headers['Cache-Control']='no-store'
    return resp

@app.route('/')
def index(): return redirect(url_for('dashboard') if current_user() else url_for('login'))
@app.route('/register',methods=['GET','POST'])
def register():
    if request.method=='POST':
        username=request.form.get('username','').strip(); email=request.form.get('email','').strip().lower(); phone=request.form.get('phone','').strip(); password=request.form.get('password','')
        if len(username)<3 or len(password)<8 or '@' not in email: flash('Use a username of 3+ characters, valid email, and password of at least 8 characters.','error')
        else:
            pub,priv=create_keys()
            try:
                with db() as c: c.execute('INSERT INTO users(username,email,phone,password_hash,role,public_key,private_key_enc,created_at) VALUES(?,?,?,?,?,?,?,?)',(username,email,phone,pw_hash(password),'user',pub,priv,now()))
                flash('Account created. Sign in to continue.','success'); return redirect(url_for('login'))
            except sqlite3.IntegrityError: flash('That username or email is already registered.','error')
    return render_template('register.html')
@app.route('/login',methods=['GET','POST'])
def login():
    if request.method=='POST':
        identity=request.form.get('identity','').strip().lower(); password=request.form.get('password','')
        with db() as c:
            attempts=c.execute('SELECT COUNT(*) n FROM login_attempts WHERE username=? AND created_at>? AND success=0',(identity,time.time()-900)).fetchone()['n']
            u=c.execute('SELECT * FROM users WHERE username=? COLLATE NOCASE OR email=? COLLATE NOCASE',(identity,identity)).fetchone()
            ok=bool(u and attempts<5 and pw_ok(password,u['password_hash']))
            c.execute('INSERT INTO login_attempts(username,created_at,success,ip_address,user_agent) VALUES(?,?,?,?,?)',(identity,time.time(),int(ok),request.remote_addr or 'unknown',(request.user_agent.string or '')[:300]))
        if not ok: flash('Invalid credentials or too many attempts. Try again in 15 minutes.','error')
        else:
            session.clear(); session['pending_uid']=u['id']; session['otp_tries']=0
            # Email OTP is mandatory on every login. Never expose a fallback code in the browser.
            session['login_method']='email'; otp=f'{secrets.randbelow(1000000):06d}'
            session['login_otp_hash']=hashlib.sha256(otp.encode()).hexdigest(); session['otp_exp']=time.time()+300
            sent=send_email(u['email'],'Cryptic Nexus Vault sign-in code',f'Your one-time code is {otp}. It expires in 5 minutes.')
            session['dev_otp']=None
            if not sent:
                session.clear(); flash('Email verification could not be sent. Check the private .env SMTP settings and try again. Login is blocked for your security.','error')
                return redirect(url_for('login'))
            log_event(u['id'],'login_otp_requested','email OTP sent')
            return redirect(url_for('verify_login'))
    return render_template('login.html')
@app.route('/verify-login',methods=['GET','POST'])
def verify_login():
    if not session.get('pending_uid'): return redirect(url_for('login'))
    if request.method=='POST':
        if session.get('otp_tries',0)>=5:
            session.clear(); flash('Too many verification attempts. Sign in again.','error'); return redirect(url_for('login'))
        session['otp_tries']=session.get('otp_tries',0)+1
        otp=request.form.get('otp','').strip(); uid_pending=session.get('pending_uid')
        valid=time.time()<session.get('otp_exp',0)
        if session.get('login_method')=='totp':
            within_time = valid
            with db() as c:
                pending_user=c.execute('SELECT totp_secret FROM users WHERE id=?',(uid_pending,)).fetchone()
                valid=within_time and bool(pending_user and verify_totp(pending_user['totp_secret'],otp))
                if not valid and within_time and otp:
                    digest=hashlib.sha256(otp.strip().upper().encode()).hexdigest()
                    recovery=c.execute('SELECT id FROM recovery_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL',(uid_pending,digest)).fetchone()
                    if recovery:
                        c.execute('UPDATE recovery_codes SET used_at=? WHERE id=? AND used_at IS NULL',(now(),recovery['id']))
                        valid=True
                        log_event(uid_pending,'two_factor_recovery_code_used','single-use recovery code')
        else:
            valid=valid and hmac.compare_digest(hashlib.sha256(otp.encode()).hexdigest(),session.get('login_otp_hash',''))
        if valid:
            uid=session.pop('pending_uid'); session.pop('login_otp_hash',None); session.pop('otp_exp',None); session.pop('dev_otp',None); session.pop('login_method',None); session['uid']=uid; session['login_started']=time.time()
            log_event(uid,'login_success',f'ip={request.remote_addr or "unknown"}; agent={(request.user_agent.string or "")[:160]}')
            return redirect(url_for('dashboard'))
        if session.get('otp_tries',0)>=5:
            session.clear(); flash('Too many verification attempts. Sign in again.','error'); return redirect(url_for('login'))
        flash('Invalid or expired code.','error')
    return render_template('verify.html',dev_otp=session.get('dev_otp'),method=session.get('login_method','email'))
@app.route('/logout')
def logout():
    u=current_user()
    if u:
        started=session.get('login_started'); duration=max(0,int(time.time()-started)) if started else 0
        log_event(u['id'],'logout',f'duration_seconds={duration}; ip={request.remote_addr or "unknown"}')
    session.clear(); return redirect(url_for('login'))
@app.route('/dashboard')
@login_required
def dashboard():
    u=current_user()
    with db() as c:
        files=c.execute('SELECT COUNT(*) n FROM files WHERE user_id=?',(u['id'],)).fetchone()['n']
        unread=c.execute('SELECT COUNT(*) n FROM messages WHERE recipient_id=? AND opened=0 AND deleted=0',(u['id'],)).fetchone()['n']
        activities=c.execute('SELECT * FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 6',(u['id'],)).fetchall()
    return render_template('dashboard.html',file_count=files,unread=unread,activities=activities)
@app.route('/vault',methods=['GET','POST'])
@login_required
def vault():
    u=current_user()
    if request.method=='POST':
        f=request.files.get('file')
        if not f or not f.filename: flash('Choose a file first.','error')
        else:
            raw=f.read(); nonce=secrets.token_bytes(12); encrypted=AESGCM(MASTER_KEY).encrypt(nonce,raw,('user:'+str(u['id'])).encode()); name=secrets.token_hex(16)+'.enc'
            with open(os.path.join(UPLOADS,name),'wb') as out: out.write(encrypted)
            expires=request.form.get('expiry_days','').strip(); expires_at=(datetime.utcnow()+timedelta(days=int(expires))).isoformat()+'Z' if expires.isdigit() and int(expires)>0 else None
            with db() as c: c.execute('INSERT INTO files(user_id,original_name,stored_name,nonce,sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?)',(u['id'],os.path.basename(f.filename),name,nonce,hashlib.sha256(raw).hexdigest(),now(),expires_at))
            log_event(u['id'],'vault_upload',f.filename); flash('File encrypted and stored in your local vault.','success'); return redirect(url_for('vault'))
    with db() as c: files=c.execute('SELECT * FROM files WHERE user_id=? ORDER BY id DESC',(u['id'],)).fetchall()
    return render_template('vault.html',files=files)
@app.route('/vault/download/<int:file_id>')
@login_required
def vault_download(file_id):
    u=current_user()
    with db() as c: f=c.execute('SELECT * FROM files WHERE id=? AND user_id=?',(file_id,u['id'])).fetchone()
    if not f: abort(404)
    if f['expires_at'] and f['expires_at']<now(): flash('This file has expired. Delete it from the vault.','error'); return redirect(url_for('vault'))
    try:
        with open(os.path.join(UPLOADS,f['stored_name']),'rb') as src: blob=src.read()
        raw=AESGCM(MASTER_KEY).decrypt(f['nonce'],blob,('user:'+str(u['id'])).encode())
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),f['sha256']):
            log_event(u['id'],'vault_integrity_failure',f['original_name']); abort(500,'File integrity check failed. The encrypted file may have been altered.')
    except Exception: abort(500)
    log_event(u['id'],'vault_decrypt_download',f['original_name'])
    return send_file(io.BytesIO(raw),as_attachment=True,download_name=f['original_name'])
@app.route('/vault/delete/<int:file_id>',methods=['POST'])
@login_required
def vault_delete(file_id):
    u=current_user()
    with db() as c: f=c.execute('SELECT * FROM files WHERE id=? AND user_id=?',(file_id,u['id'])).fetchone()
    if f:
        try: os.remove(os.path.join(UPLOADS,f['stored_name']))
        except FileNotFoundError: pass
        with db() as c: c.execute('DELETE FROM files WHERE id=? AND user_id=?',(file_id,u['id']))
        log_event(u['id'],'vault_delete',f['original_name']); flash('Vault entry deleted. SSD/filesystem remnants cannot be guaranteed erased.','success')
    return redirect(url_for('vault'))
@app.route('/chat',methods=['GET','POST'])
@login_required
def chat():
    u=current_user()
    if request.method=='POST':
        recipient_input=request.form.get('recipient','').strip(); body=request.form.get('message','').strip(); read_once=1 if request.form.get('read_once') else 0; expiry=request.form.get('expiry','').strip(); attachment=request.files.get('attachment')
        to=user_by_recipient(recipient_input)
        if not to: flash('Recipient not found. Enter their exact username or registered email address.','error')
        elif to['id']==u['id']: flash('Choose another account as recipient.','error')
        elif not body and not (attachment and attachment.filename): flash('Enter a message or attach a file.','error')
        elif len(body)>5000: flash('Message limit is 5,000 characters.','error')
        else:
            raw=attachment.read() if attachment and attachment.filename else None
            if raw is not None and len(raw)>20*1024*1024: flash('Message attachments are limited to 20 MB.','error')
            else:
                nonce,enc=encrypt_message(body or '[Attachment]')
                expires_at=(datetime.utcnow()+timedelta(minutes=int(expiry))).isoformat()+'Z' if expiry.isdigit() and int(expiry)>0 else None
                with db() as c:
                    cur=c.execute('INSERT INTO messages(sender_id,recipient_id,body_enc,nonce,created_at,expires_at,read_once) VALUES(?,?,?,?,?,?,?)',(u['id'],to['id'],enc,nonce,now(),expires_at,read_once)); mid=cur.lastrowid
                    if raw is not None:
                        anonce=secrets.token_bytes(12); aad=f'cnv-message-attachment:{mid}:{u["id"]}:{to["id"]}'.encode()
                        encrypted=AESGCM(MASTER_KEY).encrypt(anonce,raw,aad); stored=secrets.token_hex(20)+'.enc'
                        with open(os.path.join(UPLOADS,stored),'wb') as out: out.write(encrypted)
                        c.execute('INSERT INTO message_attachments(message_id,original_name,stored_name,nonce,sha256,size_bytes) VALUES(?,?,?,?,?,?)',(mid,os.path.basename(attachment.filename),stored,anonce,hashlib.sha256(raw).hexdigest(),len(raw)))
                log_event(u['id'],'message_sent','to '+to['username']+(' with attachment' if raw is not None else '')); flash('Encrypted message sent to '+to['username']+'.','success'); return redirect(url_for('chat'))
    with db() as c:
        rows=c.execute('SELECT m.*,s.username sender_name,r.username recipient_name,a.id attachment_id,a.original_name attachment_name,a.size_bytes attachment_size FROM messages m JOIN users s ON s.id=m.sender_id JOIN users r ON r.id=m.recipient_id LEFT JOIN message_attachments a ON a.message_id=m.id WHERE (m.sender_id=? OR m.recipient_id=?) AND m.deleted=0 ORDER BY m.id DESC LIMIT 100',(u['id'],u['id'])).fetchall()
    messages=[]
    for m in rows:
        expired=bool(m['expires_at'] and m['expires_at']<now())
        if expired:
            with db() as c: c.execute('UPDATE messages SET deleted=1 WHERE id=?',(m['id'],))
            continue
        once_view=session.get('read_once_view') or {}
        if m['read_once'] and m['opened'] and m['recipient_id']==u['id']: text=once_view.get(str(m['id']),'[Read-once message already opened]')
        else: text=decrypt_message(m['nonce'],m['body_enc'])
        messages.append(dict(id=m['id'],sender=m['sender_name'],recipient=m['recipient_name'],text=text,created=m['created_at'],incoming=m['recipient_id']==u['id'],read_once=m['read_once'],opened=m['opened'],expires=m['expires_at'],attachment_id=m['attachment_id'],attachment_name=m['attachment_name'],attachment_size=m['attachment_size']))
    if session.get('read_once_view'): session.pop('read_once_view',None)
    with db() as c: contacts=c.execute('SELECT username,email FROM users WHERE id!=? ORDER BY username',(u['id'],)).fetchall()
    return render_template('chat.html',messages=messages,contacts=contacts)

@app.route('/chat/attachment/<int:attachment_id>')
@login_required
def chat_attachment(attachment_id):
    u=current_user()
    with db() as c:
        a=c.execute('SELECT a.*,m.sender_id,m.recipient_id,m.deleted FROM message_attachments a JOIN messages m ON m.id=a.message_id WHERE a.id=?',(attachment_id,)).fetchone()
    if not a or a['deleted'] or u['id'] not in (a['sender_id'],a['recipient_id']): abort(404)
    try:
        blob=open(os.path.join(UPLOADS,a['stored_name']),'rb').read(); aad=f'cnv-message-attachment:{a["message_id"]}:{a["sender_id"]}:{a["recipient_id"]}'.encode()
        raw=AESGCM(MASTER_KEY).decrypt(a['nonce'],blob,aad)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(),a['sha256']): abort(500)
    except Exception: abort(500,'Attachment authentication failed.')
    log_event(u['id'],'message_attachment_download',a['original_name'])
    return send_file(io.BytesIO(raw),as_attachment=True,download_name=a['original_name'])

@app.route('/chat/open/<int:mid>',methods=['POST'])
@login_required
def open_message(mid):
    u=current_user()
    with db() as c:
        m=c.execute('SELECT * FROM messages WHERE id=? AND recipient_id=? AND deleted=0',(mid,u['id'])).fetchone()
        if m and m['read_once'] and not m['opened']:
            try: body=decrypt_message(m['nonce'],m['body_enc'])
            except Exception: body='[Message could not be decrypted]'
            session['read_once_view']={str(mid):body}; c.execute('UPDATE messages SET opened=1 WHERE id=?',(mid,)); log_event(u['id'],'read_once_opened',str(mid))
    return redirect(url_for('chat'))

def _bytes_to_bits(data): return ''.join(f'{b:08b}' for b in data)
def _bits_to_bytes(bits): return bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))
def _payload(text):
    data=text.encode('utf-8')
    if not data or len(data)>100000: raise ValueError('Secret text must be between 1 byte and 100 KB.')
    return len(data).to_bytes(4,'big')+data
def _extract_payload(bits):
    if len(bits)<32: raise ValueError('No valid hidden-message header found.')
    size=int(bits[:32],2)
    if size<1 or size>100000 or 32+size*8>len(bits): raise ValueError('No complete message found in this media.')
    try: return _bits_to_bytes(bits[32:32+size*8]).decode('utf-8')
    except UnicodeDecodeError: raise ValueError('Hidden payload is not valid UTF-8 text.')

def _image_hide(file_obj, text):
    image=Image.open(file_obj).convert('RGB'); payload=_payload(text); bits=_bytes_to_bits(payload); pixels=list(image.getdata())
    if len(bits)>len(pixels)*3: raise ValueError('Message is too large for this image.')
    out=[]; idx=0
    for px in pixels:
        vals=list(px)
        for j in range(3):
            if idx<len(bits): vals[j]=(vals[j]&254)|int(bits[idx]); idx+=1
        out.append(tuple(vals))
    image.putdata(out); buff=io.BytesIO(); image.save(buff,format='PNG'); buff.seek(0); return buff

def _image_extract(file_obj):
    image=Image.open(file_obj).convert('RGB'); return _extract_payload(''.join(str(v&1) for px in image.getdata() for v in px))

def _wav_hide(file_obj, text):
    with wave.open(file_obj,'rb') as src:
        params=src.getparams(); frames=bytearray(src.readframes(src.getnframes()))
    width=params.sampwidth
    if width not in (1,2,3,4): raise ValueError('Unsupported WAV sample width. Use PCM WAV audio.')
    payload=_payload(text); bits=_bytes_to_bits(payload)
    if len(bits)>len(frames): raise ValueError('Message is too large for this WAV audio.')
    for i,b in enumerate(bits): frames[i]=(frames[i]&254)|int(b)
    out=io.BytesIO()
    with wave.open(out,'wb') as dst: dst.setparams(params); dst.writeframes(frames)
    out.seek(0); return out

def _wav_extract(file_obj):
    with wave.open(file_obj,'rb') as src: frames=src.readframes(src.getnframes())
    return _extract_payload(''.join(str(v&1) for v in frames))

def _video_hide(file_obj, text):
    try: import cv2
    except ImportError: raise ValueError('Video steganography dependency is missing. Rerun run_windows.bat to install the listed packages.')
    src_path=os.path.join(INSTANCE,'stego_in_'+secrets.token_hex(6)+'.avi'); out_path=os.path.join(INSTANCE,'stego_out_'+secrets.token_hex(6)+'.avi')
    with open(src_path,'wb') as f: shutil.copyfileobj(file_obj,f)
    cap=cv2.VideoCapture(src_path)
    if not cap.isOpened(): os.remove(src_path); raise ValueError('Could not open video. Use a supported AVI/MP4 video file.')
    fps=cap.get(cv2.CAP_PROP_FPS) or 25; width=int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)); height=int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    writer=cv2.VideoWriter(out_path,cv2.VideoWriter_fourcc(*'FFV1'),fps,(width,height))
    if not writer.isOpened(): cap.release(); os.remove(src_path); raise ValueError('This OpenCV build cannot write lossless FFV1 AVI video.')
    bits=_bytes_to_bits(_payload(text)); pos=0; first=True
    while True:
        ok,frame=cap.read()
        if not ok: break
        if pos<len(bits):
            flat=frame.reshape(-1)
            n=min(len(flat),len(bits)-pos)
            for i in range(n): flat[i]=(int(flat[i])&254)|int(bits[pos+i])
            pos+=n
        writer.write(frame)
    cap.release(); writer.release(); os.remove(src_path)
    if pos<len(bits): os.remove(out_path); raise ValueError('Message is too large for this video. Use a longer/higher-resolution video.')
    out=io.BytesIO(open(out_path,'rb').read()); os.remove(out_path); out.seek(0); return out

def _video_extract(file_obj):
    try: import cv2
    except ImportError: raise ValueError('Video steganography dependency is missing. Rerun run_windows.bat to install the listed packages.')
    path=os.path.join(INSTANCE,'stego_in_'+secrets.token_hex(6)+'.avi')
    with open(path,'wb') as f: shutil.copyfileobj(file_obj,f)
    cap=cv2.VideoCapture(path); bits=[]; header=None; needed=None
    while True:
        ok,frame=cap.read()
        if not ok: break
        for v in frame.reshape(-1):
            bits.append(str(int(v)&1))
            if len(bits)==32:
                size=int(''.join(bits),2)
                if size<1 or size>100000: cap.release(); os.remove(path); raise ValueError('No valid hidden-message header found in this video.')
                needed=32+size*8
            if needed and len(bits)>=needed:
                cap.release(); os.remove(path); return _extract_payload(''.join(bits))
    cap.release(); os.remove(path); raise ValueError('No complete hidden message found in this video.')

@app.route('/steganography',methods=['GET','POST'])
@login_required
def steganography():
    result=None
    if request.method=='POST':
        action=request.form.get('action'); media=request.form.get('media','image'); f=request.files.get('media_file'); secret=request.form.get('secret','')
        try:
            if not f or not f.filename: raise ValueError('Choose a media file first.')
            if action=='hide':
                if media=='image': output=_image_hide(f.stream,secret); mime='image/png'; filename='stego_image.png'
                elif media=='audio': output=_wav_hide(f.stream,secret); mime='audio/wav'; filename='stego_audio.wav'
                elif media=='video': output=_video_hide(f.stream,secret); mime='video/x-msvideo'; filename='stego_video.avi'
                elif media=='text':
                    cover=f.read().decode('utf-8'); marker='\u200b'; binary=''.join(f'{b:08b}' for b in secret.encode('utf-8')); hidden=''.join(marker if b=='0' else '\u200c' for b in binary)
                    output=io.BytesIO((cover+'\n'+ '\u2063'+hidden+'\u2063').encode('utf-8')); mime='text/plain'; filename='stego_text.txt'
                else: raise ValueError('Choose image, audio, video, or text media.')
                log_event(current_user()['id'],'steganography_embed',media+' LSB/zero-width'); return send_file(output,mimetype=mime,as_attachment=True,download_name=filename)
            if action=='extract':
                if media=='image': result=_image_extract(f.stream)
                elif media=='audio': result=_wav_extract(f.stream)
                elif media=='video': result=_video_extract(f.stream)
                elif media=='text':
                    cover=f.read().decode('utf-8'); marker='\u2063'; parts=cover.split(marker)
                    if len(parts)<3: raise ValueError('No hidden text marker found in this text file.')
                    bits=''.join('0' if ch=='\u200b' else '1' for ch in parts[-2] if ch in ('\u200b','\u200c'))
                    if len(bits)%8: raise ValueError('Hidden text payload is incomplete.')
                    result=bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8)).decode('utf-8')
                else: raise ValueError('Choose a supported media type.')
                log_event(current_user()['id'],'steganography_extract',media)
        except Exception as e:
            flash(str(e) if isinstance(e,ValueError) else 'Could not process this media. Ensure it is a supported file and, for video, use a lossless FFV1 AVI generated by this tool.','error')
    return render_template('steganography.html',result=result)

@app.route('/security')
@login_required
def security():
    u=current_user()
    with db() as c: logs=c.execute('SELECT * FROM activity WHERE user_id=? ORDER BY id DESC LIMIT 100',(u['id'],)).fetchall()
    return render_template('security.html',logs=logs,public_key=u['public_key'])
@app.route('/settings/2fa',methods=['GET','POST'])
@login_required
def two_factor_settings():
    u=current_user(); secret=session.get('totp_setup_secret')
    if request.method=='POST':
        action=request.form.get('action')
        if action=='begin':
            secret=new_totp_secret(); session['totp_setup_secret']=secret
        elif action=='confirm':
            secret=session.get('totp_setup_secret'); code=request.form.get('code','').strip()
            if secret and verify_totp(secret,code):
                recovery_codes=[secrets.token_hex(4).upper() for _ in range(8)]
                with db() as c:
                    c.execute('UPDATE users SET totp_secret=?,totp_enabled=1 WHERE id=?',(secret,u['id']))
                    c.execute('DELETE FROM recovery_codes WHERE user_id=?',(u['id'],))
                    c.executemany('INSERT INTO recovery_codes(user_id,code_hash,used_at) VALUES(?,?,NULL)',[(u['id'],hashlib.sha256(item.encode()).hexdigest()) for item in recovery_codes])
                session['totp_recovery_codes']=recovery_codes
                session.pop('totp_setup_secret',None); log_event(u['id'],'two_factor_enabled','TOTP authenticator and recovery codes'); flash('Authenticator 2FA enabled. Save your one-time recovery codes now.','success'); return redirect(url_for('two_factor_settings'))
            flash('Code did not match. Check your authenticator time and try again.','error')
        elif action=='disable':
            if verify_totp(u['totp_secret'],request.form.get('code','').strip()):
                with db() as c:
                    c.execute('UPDATE users SET totp_secret=NULL,totp_enabled=0 WHERE id=?',(u['id'],))
                    c.execute('DELETE FROM recovery_codes WHERE user_id=?',(u['id'],))
                log_event(u['id'],'two_factor_disabled','TOTP authenticator'); flash('Authenticator 2FA disabled. Email OTP remains the login second factor.','success'); return redirect(url_for('two_factor_settings'))
            flash('Enter a valid current authenticator code to disable 2FA.','error')
    u=current_user(); uri=None; qr_data=None
    if secret:
        uri='otpauth://totp/'+urllib.parse.quote('Cryptic Nexus Vault:'+u['email'])+'?secret='+secret+'&issuer='+urllib.parse.quote('Cryptic Nexus Vault')+'&algorithm=SHA1&digits=6&period=30'
        try:
            import qrcode
            img=qrcode.make(uri); buf=io.BytesIO(); img.save(buf,format='PNG'); qr_data='data:image/png;base64,'+base64.b64encode(buf.getvalue()).decode()
        except Exception: pass
    recovery_codes=session.pop('totp_recovery_codes',None)
    return render_template('two_factor.html',setup_secret=secret,otp_uri=uri,qr_data=qr_data,recovery_codes=recovery_codes)

@app.route('/reset-password',methods=['GET','POST'])
def reset_password():
    if request.method=='POST':
        email=request.form.get('email','').strip().lower()
        with db() as c: u=c.execute('SELECT * FROM users WHERE email=? COLLATE NOCASE',(email,)).fetchone()
        if u:
            token=secrets.token_urlsafe(32); digest=hashlib.sha256(token.encode()).hexdigest(); exp=(datetime.utcnow()+timedelta(minutes=20)).isoformat()+'Z'
            with db() as c: c.execute('INSERT INTO reset_tokens(user_id,token_hash,expires_at) VALUES(?,?,?)',(u['id'],digest,exp))
            link=request.host_url.rstrip('/')+url_for('reset_finish',token=token); sent=send_email(email,'Cryptic Nexus Vault password reset',f'Reset your password within 20 minutes: {link}')
            if not sent: log_event(u['id'],'password_reset_email_failed','SMTP delivery failed')
        flash('If that email is registered, a reset link has been sent. If SMTP is unavailable, no reset link is issued.','success')
    return render_template('reset.html',dev_link=None)
@app.route('/reset-password/<token>',methods=['GET','POST'])
def reset_finish(token):
    digest=hashlib.sha256(token.encode()).hexdigest()
    with db() as c: row=c.execute('SELECT * FROM reset_tokens WHERE token_hash=? AND used=0',(digest,)).fetchone()
    if not row or row['expires_at']<now(): abort(400,'Reset link invalid or expired.')
    if request.method=='POST':
        p=request.form.get('password','')
        if len(p)<8: flash('Password must be at least 8 characters.','error')
        else:
            with db() as c: c.execute('UPDATE users SET password_hash=? WHERE id=?',(pw_hash(p),row['user_id'])); c.execute('UPDATE reset_tokens SET used=1 WHERE user_id=?',(row['user_id'],))
            flash('Password updated. Please sign in.','success'); return redirect(url_for('login'))
    return render_template('reset_finish.html')
@app.route('/admin/login',methods=['GET','POST'])
def admin_login():
    if request.method=='POST':
        name=request.form.get('username',''); password=request.form.get('password','')
        expected_user=os.getenv('CNV_ADMIN_USERNAME','admin'); expected_pass=os.getenv('CNV_ADMIN_PASSWORD') or DEFAULT_ADMIN_PASSWORD
        if hmac.compare_digest(name,expected_user) and hmac.compare_digest(password,expected_pass):
            # Admin uses its own session namespace and never impersonates a user.
            session.clear(); session['admin']=True; return redirect(url_for('admin_panel'))
        flash('Invalid administrator credentials.','error')
    return render_template('admin_login.html')
@app.route('/admin')
@admin_required
def admin_panel():
    with db() as c:
        users=c.execute('SELECT id,username,email,role,created_at FROM users ORDER BY id DESC').fetchall(); logs=c.execute('SELECT a.*,u.username FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 100').fetchall(); attempts=c.execute('SELECT username,created_at,success,ip_address,user_agent FROM login_attempts ORDER BY id DESC LIMIT 100').fetchall()
    return render_template('admin.html',users=users,logs=logs,attempts=attempts)
@app.route('/admin/logout')
def admin_logout(): session.pop('admin',None); return redirect(url_for('admin_login'))
@app.route('/features')
def features():
    implemented = [
        ('Account security', 'Registration, username/email login, scrypt password hashing, login attempt limiting, mandatory email OTP delivery, authenticator TOTP setup and one-time recovery codes, password reset tokens.'),
        ('Separate administrator access', 'Dedicated admin sign-in and session, user directory, and audit log viewer.'),
        ('Encrypted file vault', 'AES-256-GCM encryption at rest, decrypt-on-download, SHA-256 integrity reference, expiry metadata, and delete action.'),
        ('Secure messaging', 'Recipient lookup by username or email, AES-GCM encrypted-at-rest text and file attachments, expiry and read-once handling; limited to this local app database.'),
        ('Multi-media steganography', 'Hide/extract text in PNG/BMP-style images, PCM WAV audio, lossless FFV1 AVI video, and text files using zero-width characters. Format compatibility and capacity vary.'),
        ('Security visibility', 'Per-user activity history, RSA-2048 identity key pair, responsive Day/Night theme, and local PWA shell cache.'),
        ('Encrypted backups', 'Use backup_restore.py to create or restore a passphrase-encrypted backup of the SQLite database, vault files, and local encryption key.'),
    ]
    planned = [
        ('True end-to-end messaging', 'Not implemented: messages are encrypted at rest, but the server can decrypt them.'),
        ('SMS OTP and SMS recovery', 'Intentionally excluded as requested.'),
        ('Full offline sync', 'The shell can be cached; authenticated actions and message delivery require the local server.'),
        ('Cross-device/LAN/WebRTC messaging', 'Not implemented: the current app remains local to one computer and does not act as a network messaging server.'),
    ]
    return render_template('features.html', implemented=implemented, planned=planned)

@app.route('/manifest.json')
def manifest(): return jsonify({'name':'Cryptic Nexus Vault','short_name':'CN Vault','start_url':'/','display':'standalone','background_color':'#17231f','theme_color':'#b6d6a8','icons':[]})
@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')
@app.errorhandler(413)
def too_large(e): return 'File too large. Maximum upload size is 25 MB.',413
@app.errorhandler(403)
def forbidden(e): return render_template('error.html',code=403,message='Administrator access is separate from user access.'),403
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8766, debug=False, use_reloader=False)
