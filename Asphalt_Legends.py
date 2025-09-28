# Asphalt_Legends.py (updated)
import os
import sqlite3
import secrets
import time
import json
import hashlib
import hmac
import pathlib
import base64
from flask import (
    Flask, render_template_string, request, jsonify, session,
    redirect, url_for, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit

# -------- CONFIG ----------
app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
HEADING_IMG = "/static/heading.png"  # place your heading image here
MAX_MESSAGES = 80
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_VIDEO_EXT = {"mp4", "webm", "ogg"}
ALLOWED_AUDIO_EXT = {"mp3", "wav", "ogg", "m4a", "webm"}


# ensure static subfolders
pathlib.Path(os.path.join(app.static_folder, "uploads")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "stickers")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "gifs")).mkdir(parents=True, exist_ok=True)

# SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# --------- DB init & helpers ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            pass_salt BLOB,
            pass_hash BLOB,
            avatar TEXT DEFAULT NULL,
            status TEXT DEFAULT '',
            is_owner INTEGER DEFAULT 0,
            is_partner INTEGER DEFAULT 0
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            text TEXT,
            attachments TEXT DEFAULT '[]',
            reactions TEXT DEFAULT '[]',
            edited INTEGER DEFAULT 0,
            created_at INTEGER
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS calls (
            id TEXT PRIMARY KEY,
            caller TEXT,
            callee TEXT,
            is_video INTEGER,
            started_at INTEGER,
            ended_at INTEGER,
            status TEXT
        );
    """)
    conn.commit()
    conn.close()


def db_conn():
    return sqlite3.connect(DB_PATH)

init_db()

# user helpers
def save_user(name, salt_bytes, hash_bytes, avatar=None, status="", make_owner=False, make_partner=False):
    conn = db_conn(); c = conn.cursor()
    if make_owner:
        c.execute("UPDATE users SET is_owner = 0")
    c.execute("""
        INSERT INTO users (name, pass_salt, pass_hash, avatar, status, is_owner, is_partner)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          pass_salt=excluded.pass_salt, pass_hash=excluded.pass_hash,
          avatar=COALESCE(excluded.avatar, users.avatar),
          status=COALESCE(excluded.status, users.status),
          is_owner=COALESCE((SELECT is_owner FROM users WHERE name = excluded.name), excluded.is_owner),
          is_partner=COALESCE((SELECT is_partner FROM users WHERE name = excluded.name), excluded.is_partner)
    """, (name, sqlite3.Binary(salt_bytes), sqlite3.Binary(hash_bytes), avatar, status, 1 if make_owner else 0, 1 if make_partner else 0))
    conn.commit(); conn.close()


def load_user_by_name(name):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE name = ? LIMIT 1", (name,))
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1], "pass_salt": r[2], "pass_hash": r[3], "avatar": r[4], "status": r[5], "is_owner": bool(r[6]), "is_partner": bool(r[7])}
    return None


def load_first_user():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users ORDER BY id LIMIT 1")
    r = c.fetchone(); conn.close()
    if r: return {"name": r[0], "pass_salt": r[1], "pass_hash": r[2], "avatar": r[3], "status": r[4], "is_owner": bool(r[5]), "is_partner": bool(r[6])}
    return None


def set_partner_by_name(name):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE users SET is_partner = 1 WHERE name = ?", (name,))
    conn.commit(); conn.close()


def get_owner():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE is_owner = 1 LIMIT 1")
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1], "pass_salt": r[2], "pass_hash": r[3], "avatar": r[4], "status": r[5], "is_owner": bool(r[6]), "is_partner": bool(r[7])}
    return None


def get_partner():
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, name FROM users WHERE is_partner = 1 LIMIT 1")
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1]}
    return None

# message helpers
def save_message(sender, text, attachments=None):
    conn = db_conn(); c = conn.cursor()
    ts = int(time.time())
    att = json.dumps(attachments or [])
    c.execute("INSERT INTO messages (sender, text, attachments, created_at) VALUES (?, ?, ?, ?)", (sender, text, att, ts))
    conn.commit(); conn.close()
    trim_messages_limit(MAX_MESSAGES)


def fetch_messages(since_id=0):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, sender, text, attachments, reactions, edited, created_at FROM messages WHERE id > ? ORDER BY id ASC", (since_id,))
    rows = c.fetchall(); conn.close()
    out = []
    for r in rows:
        mid, sender, text, attachments_json, reactions_json, edited, created_at = r
        attachments = json.loads(attachments_json or "[]")
        reactions = json.loads(reactions_json or "[]")
        out.append({"id": mid, "sender": sender, "text": text, "attachments": attachments, "reactions": reactions, "edited": bool(edited), "created_at": created_at})
    return out


def trim_messages_limit(max_messages=80):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM messages"); total = c.fetchone()[0]
    if total <= max_messages: conn.close(); return
    to_delete = total - max_messages
    c.execute("DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY id ASC LIMIT ?)", (to_delete,))
    conn.commit(); conn.close()


def edit_message_db(msg_id, new_text, editor):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT sender FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return False, "no message"
    sender = r[0]
    user = load_user_by_name(editor)
    if editor != sender and not (user and user.get("is_owner")):
        conn.close(); return False, "not allowed"
    c.execute("UPDATE messages SET text = ?, edited = 1 WHERE id = ?", (new_text, msg_id))
    conn.commit(); conn.close(); return True, None


def delete_message_db(msg_id, requester):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT sender FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return False, "no message"
    sender = r[0]
    user = load_user_by_name(requester)
    if requester != sender and not (user and user.get("is_owner")):
        conn.close(); return False, "not allowed"
    c.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    conn.commit(); conn.close(); return True, None


def react_message_db(msg_id, reactor, emoji):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT reactions FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return False, "no message"
    reactions = json.loads(r[0] or "[]")
    found = False
    for rec in list(reactions):
        if rec.get("emoji") == emoji and rec.get("user") == reactor:
            reactions.remove(rec); found = True; break
    if not found:
        reactions.append({"emoji": emoji, "user": reactor})
    c.execute("UPDATE messages SET reactions = ? WHERE id = ?", (json.dumps(reactions), msg_id))
    conn.commit(); conn.close(); return True, None

# call logs
def save_call(call_id, caller, callee, is_video, status="ringing"):
    conn = db_conn(); c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO calls (id, caller, callee, is_video, started_at, ended_at, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
              (call_id, caller, callee, 1 if is_video else 0, int(time.time()), None, status))
    conn.commit(); conn.close()


def update_call_started(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE calls SET started_at = ?, status = ? WHERE id = ?", (int(time.time()), "active", call_id))
    conn.commit(); conn.close()


def update_call_ended(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE calls SET ended_at = ?, status = ? WHERE id = ?", (int(time.time()), "ended", call_id))
    conn.commit(); conn.close()


def fetch_call_log_by_id(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, caller, callee, is_video, started_at, ended_at, status FROM calls WHERE id = ? LIMIT 1", (call_id,))
    r = c.fetchone(); conn.close()
    if r:
        return {"id": r[0], "caller": r[1], "callee": r[2], "is_video": bool(r[3]), "started_at": r[4], "ended_at": r[5], "status": r[6]}
    return None


# --------- crypto for shared passkey ----------
PBKDF2_ITER = 200_000
SALT_BYTES = 16
HASH_LEN = 32

def hash_pass(passphrase: str, salt: bytes = None):
    if salt is None: salt = secrets.token_bytes(SALT_BYTES)
    if isinstance(passphrase, str): passphrase = passphrase.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PBKDF2_ITER, dklen=HASH_LEN)
    return salt, dk

def verify_pass(passphrase: str, salt: bytes, expected_hash: bytes) -> bool:
    if isinstance(salt, memoryview): salt = bytes(salt)
    if isinstance(expected_hash, memoryview): expected_hash = bytes(expected_hash)
    if salt is None or expected_hash is None: return False
    if isinstance(passphrase, str): passphrase = passphrase.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PBKDF2_ITER, dklen=len(expected_hash))
    return hmac.compare_digest(dk, expected_hash)

# ---------- presence & runtime state ----------
LAST_SEEN = {}
USER_SID = {}      # username -> sid
CALL_INVITES = {}  # call_id -> info

def touch_user_presence(username):
    if not username: return
    LAST_SEEN[username] = int(time.time())

# ---------- Avatar generation (WhatsApp-like initials SVG) ----------
def initials_and_color(name):
    nm = (name or "").strip()
    initials = ""
    parts = nm.split()
    if len(parts) == 0:
        initials = "?"
    elif len(parts) == 1:
        initials = parts[0][:2].upper()
    else:
        initials = (parts[0][0] + parts[-1][0]).upper()
    h = hashlib.sha256(nm.encode("utf-8")).digest()
    r,g,b = h[0], h[1], h[2]
    return initials, f"rgb({r},{g},{b})"

@app.route("/avatar/<name>")
def avatar_svg(name):
    try:
        name = name.replace("/", " ").strip()
        initials, color = initials_and_color(name)
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128">
  <rect width="100%" height="100%" fill="{color}" rx="20" />
  <text x="50%" y="54%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,Segoe UI,Roboto" font-size="52" fill="#fff">{initials}</text>
</svg>'''
        return app.response_class(svg, mimetype='image/svg+xml')
    except Exception:
        abort(404)

# ---------- Helpers for listing stickers/gifs ----------
def list_static_folder(sub):
    folder = os.path.join(app.static_folder, sub)
    if not os.path.isdir(folder): return []
    out=[]
    for fn in sorted(os.listdir(folder)):
        p = os.path.join(folder, fn)
        if os.path.isfile(p):
            ext = fn.rsplit(".",1)[-1].lower()
            if ext:
                out.append(url_for('static', filename=f"{sub}/{fn}"))
    return out

# ---------- Templates ----------
INDEX_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Asphalt Legends — Login</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;}
  .heading{display:flex;justify-content:center;gap:8px;align-items:center}
  .left{color:#3730a3;font-weight:800;font-size:1.5rem}
  .right{color:#be185d;font-weight:800;font-size:1.5rem}
  header{ text-align:center; margin:18px 0; }
</style>
</head><body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 p-4">
  <div class="max-w-3xl mx-auto">
    <header>
      <img src="{{ heading_img }}" alt="heading" class="mx-auto" style="max-height:96px"/>
      <div class="heading mt-2"><div class="left">Asphalt</div><div class="right">Legends</div></div>
      <p class="text-xs text-gray-500 mt-2">Shared single passkey login. First user creates master passkey.</p>
    </header>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
      {% if first_user_none %}
      <section class="p-4 bg-white rounded-lg shadow">
        <h3 class="text-indigo-700 font-semibold mb-2">Register (create master passkey)</h3>
        <form id="regForm">
          <input id="reg_name" class="w-full p-2 border rounded mb-2" placeholder="Display name" />
          <input id="reg_passkey" type="password" class="w-full p-2 border rounded mb-2" placeholder="Choose master passkey" />
          <div class="flex gap-2">
            <button type="submit" class="px-3 py-2 rounded bg-green-600 text-white flex-1">Register</button>
            <button id="genBtn" type="button" class="px-3 py-2 rounded bg-gray-100">Generate</button>
          </div>
          <div id="regStatus" class="text-sm mt-2 text-red-500"></div>
        </form>
      </section>
      {% endif %}

      <section class="p-4 bg-white rounded-lg shadow">
        <h3 class="text-indigo-700 font-semibold mb-2">Login</h3>
        <form id="loginForm">
          <input id="login_name" class="w-full p-2 border rounded mb-2" placeholder="Display name" />
          <input id="login_passkey" type="password" class="w-full p-2 border rounded mb-2" placeholder="Master passkey" />
          <button type="submit" class="w-full px-3 py-2 rounded bg-indigo-600 text-white">Login</button>
          <div id="loginStatus" class="text-sm mt-2 text-red-500"></div>
        </form>
      </section>
    </div>
  </div>

<script>
function show(id,msg,err){const e=document.getElementById(id); if(!e)return; e.textContent=msg; e.style.color = err? '#b91c1c':'#16a34a';}
document.getElementById('genBtn')?.addEventListener('click', ()=>{ const s = Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => (b%36).toString(36)).join(''); document.getElementById('reg_passkey').value = s; show('regStatus','Generated — copy it.'); });

async function postJson(url, body){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const text = await r.text();
  try { return {ok:r.ok, json: JSON.parse(text), text}; } catch(e){ return {ok:r.ok, text}; }
}

document.getElementById('regForm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  show('regStatus','Registering...');
  const name = document.getElementById('reg_name').value.trim();
  const passkey = document.getElementById('reg_passkey').value;
  try{
    const res = await postJson('/register', {name, passkey});
    if(!res.ok) throw new Error(res.text || 'register failed');
    show('regStatus','Registered — redirecting...');
    setTimeout(()=> location.href='/chat', 500);
  }catch(err){ show('regStatus','Register failed: '+(err.message||err), true); }
});

document.getElementById('loginForm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  show('loginStatus','Logging in...');
  const name = document.getElementById('login_name').value.trim();
  const passkey = document.getElementById('login_passkey').value;
  try{
    const res = await postJson('/login', {name, passkey});
    if(!res.ok) throw new Error(res.text || 'login failed');
    show('loginStatus','Logged in — redirecting...');
    setTimeout(()=> location.href='/chat', 300);
  }catch(err){ show('loginStatus','Login failed: '+(err.message||err), true); }
});
</script>
</body></html>
'''

CHAT_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Asphalt Legends — Chat</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{--glass-bg: rgba(255,255,255,0.5); --accent:#6366f1}
  body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; background: linear-gradient(180deg, #eef2ff 0%, #fff0f6 100%); }
  
  /* --- FIXED HEADER STYLES --- */
  .fixed-header-container { 
    position: fixed; 
    top: 0; 
    left: 0; 
    right: 0; 
    z-index: 50; 
    background: rgba(255, 255, 255, 0.55);
    backdrop-filter: blur(4px) saturate(120%);
    padding: 6px 0;
  }
  header{ 
    text-align:center; 
    margin: -6px auto 4px; 
    max-width:900px;
  }
  header img{max-height:56px; display:block; margin:0 auto;} /* Smaller heading image */
  .heading{display:flex;justify-content:center;gap:8px;align-items:center;margin-top:-6px;}
  .left{ color:#3730a3;font-weight:800;font-size:1.05rem;}
  .right{ color:#be185d;font-weight:800;font-size:1.05rem;margin-left:6px;}

  /* Top-left call buttons */
  .top-left{ 
    position: absolute; 
    left: 12px; 
    top: 50%;
    transform: translateY(-50%);
    display:flex; gap:8px; align-items:center;
  }
  
  /* Top-right profile (full name) */
  .top-right{ 
    position: absolute; 
    right: 12px; 
    top: 50%;
    transform: translateY(-50%);
    display:flex; gap:8px; align-items:center;
  }
  .profile-name { font-weight:700; background: var(--accent); color: white; padding: 6px 10px; border-radius: 12px; box-shadow: 0 6px 18px rgba(99,102,241,0.12); cursor: pointer; display:inline-flex; align-items:center; gap:8px; }

  /* --- MAIN CONTENT & CHAT BUBBLES --- */
  .bubble{ padding:10px 12px; border-radius:12px; display:inline-block; word-break:break-word; white-space:pre-wrap; background-clip:padding-box; }
  .me{ background: linear-gradient(90deg,#f7fbff,#f2f8ff); border-bottom-right-radius:6px; }
  .them{ background:#ffffff; border-bottom-left-radius:6px; }
  .meta{ font-size:.75rem; color:#6b7280; margin-bottom:6px; }
  .msg-row{ margin-bottom:10px; display:flex; gap:8px; align-items:flex-start; }

  /* responsive: smaller messages on phone */
  .bubble { max-width: min(720px, 72%); font-size: 1rem; }
  @media (max-width: 767px) {
    .bubble { max-width: calc(100% - 48px); font-size: 0.9rem; padding:8px 10px; }
    .sticker{ width:84px; }
    .preview-item { max-width:72px; }
    .image-attachment, .video-attachment { max-width: 240px; }
  }
  @media (min-width: 768px) {
    .bubble { font-size: 1rem; }
    .image-attachment, .video-attachment { max-width: 420px; }
  }

  .msg-body{ display:flex; flex-direction:column; }
  .three-dot{ background: none; border: none; cursor:pointer; font-size:1.05rem; color: #111827; padding: 1px 8px; border-radius:8px; }
  .menu{ position: absolute; background: #ffffff; color: #000000; padding:8px; border-radius:10px; box-shadow:0 12px 30px rgba(0,0,0,.25); z-index:120; min-width:140px; }
  .menu div, .menu form button{ width:100%; text-align:left; padding:8px 10px; cursor:pointer; border-radius:6px; }
  .menu div:hover, .menu form button:hover{ background: #f3f4f6; }
  .attach-menu{ position: fixed; right:20px; bottom:84px; z-index:90; display:none; flex-direction:column; gap:8px; }
  .attach-menu button, .attach-menu label{ min-width:160px; text-align:left; }
  .mic-active{ background:#10b981 !important; color:white !important; }
  .msg-meta-top{ font-size:0.75rem; color:#6b7280; display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px; }

  /* Textarea / composer tweaks */
  .textarea{ resize:none; min-height:44px; max-height:140px; overflow:auto; border-radius:10px; padding:12px; border:1px solid rgba(15,23,42,0.06); background: rgba(255,255,255,0.6); backdrop-filter: blur(6px); }

  main{ max-width:920px; margin:0 auto; padding-top: 110px; padding-bottom:140px; padding-left: 10px; padding-right: 10px; }

  /* Composer: liquid glass rectangular rounded */
  .composer { position: fixed; left:0; right:0; bottom: env(safe-area-inset-bottom, 0); display:flex; justify-content:center; padding:14px; z-index: 50; }
  .composer-inner{ width:100%; max-width:920px; display:flex; flex-direction:column; gap:8px; }
  .composer-main{ display:flex; gap:8px; align-items:center; width: 100%; background: var(--glass-bg); border-radius:18px; padding:10px; border: 1px solid rgba(255,255,255,0.4); box-shadow: 0 6px 30px rgba(2,6,23,0.06); }
  .composer-main .flex-1{ min-width:0; }

  .system-message{ text-align:center; font-size:0.8rem; color:#6b7280; background:rgba(230,230,230,0.7); padding:4px 10px; border-radius:12px; margin:10px auto; display:table; }
  #attachmentPreview { padding: 8px; border-bottom: 1px solid #e5e7eb; margin-bottom: 8px; display: none; }
  .preview-item { position: relative; display: inline-block; max-width: 90px; margin-right:8px }
  .preview-item img, .preview-item video { max-width: 100%; height: auto; border-radius: 8px; }
  .preview-item-doc { background:#f3f4f6; padding:6px; border-radius:8px; font-size:0.75rem; max-width:90px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap }
  .preview-remove-btn { position: absolute; top: -6px; right: -6px; background: #374151; color: white; border-radius: 999px; width: 20px; height: 20px; display: flex; align-items: center; justify-content: center; cursor: pointer; font-size: 1rem; line-height: 1rem; border: none; }
  .media-container { position: relative; display: inline-block; width: 100%; }
  .media-container .download-btn { position: absolute; top: 8px; right: 8px; background: rgba(0,0,0,0.6); color: white; border-radius: 999px; width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; text-decoration: none; font-size: 1rem; transition: background .2s; z-index: 10; }
  .media-container .download-btn:hover { background: rgba(0,0,0,0.8); }
  .doc-link { display: inline-flex; align-items: center; gap: 8px; background: #f3f4f6; padding: 8px 12px; border-radius: 8px; text-decoration: none; color: #1f2937; margin-top:8px; }
  .doc-link:hover { background: #e5e7eb; }
  .doc-link span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 200px; }
  .image-attachment, .video-attachment { border-radius: 10px; display: block; margin-top: 8px; width: 100%; max-width: 320px; height: auto; }
  .no-bubble-image, .no-bubble-video { display: block; border-radius: 12px; box-shadow: 0 8px 24px rgba(0,0,0,.08); width: 100%; max-width: 320px; height: auto; }

  /* Hide avatars (remove left box) */
  .avatar-sm { display:none; }

  /* uploading overlay & spinner */
  .uploading-overlay{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; background: rgba(0,0,0,0.25); border-radius:10px; }
  .spinner{ width:36px; height:36px; border-radius:50%; border:4px solid rgba(255,255,255,0.25); border-top-color: white; animation: spin 1s linear infinite; }
  @keyframes spin{ to{ transform: rotate(360deg); } }

  @media (min-width: 1024px) {
    body { font-size: 1.02rem; }
    .bubble { padding: 12px 16px; border-radius: 12px; max-width: 60%; }
    header img { max-height: 86px; }
    main { padding-top: 130px; }
    .composer { padding: 14px 12px; }
  }
</style>
</head><body>
<div class="fixed-header-container">
  <div class="top-left">
    <button id="callAudio" class="px-3 py-1 rounded bg-white shadow">📞</button>
    <button id="callVideo" class="px-3 py-1 rounded bg-white shadow">📹</button>
  </div>

  <div class="top-right">
    <div id="profileBtn" class="profile-name">{{ username }}</div>
    <div id="profileMenu" class="menu" style="display:none; right:0; top:48px;">
        <div id="viewProfileBtn">Profile</div>
        <form method="post" action="{{ url_for('logout') }}"><button type="submit">Logout</button></form>
    </div>
  </div>

  <header>
    <img src="{{ heading_img }}" alt="heading"/>
    <div class="heading">
      <div class="left">Asphalt</div>
      <div class="right">Legends</div>
    </div>
  </header>
</div>

  <main>
    <div id="messages" class="mb-3"></div>
  </main>

  <div class="composer">
    <div class="composer-inner">
      <div id="attachmentPreview"></div>
      <div class="composer-main">
        <button id="plusBtn" class="px-3 py-2 rounded bg-white shadow" style="font-size: 1rem">＋</button>
        <div id="attachMenu" class="attach-menu">
          <label class="px-3 py-2 rounded bg-white border cursor-pointer">
            <input id="fileAttach" type="file" accept="image/*,video/*,audio/*" class="hidden" multiple /> Photo/Video
          </label>
          <label class="px-3 py-2 rounded bg-white border cursor-pointer">
            <input id="cameraAttach" type="file" accept="image/*,video/*" capture="environment" class="hidden" multiple /> Camera
          </label>
          <label class="px-3 py-2 rounded bg-white border cursor-pointer">
            <input id="docAttach" type="file" class="hidden" multiple /> Document
          </label>
          <button id="stickerPickerBtn" class="px-3 py-2 rounded bg-white border">Stickers / GIFs</button>
        </div>
        <textarea id="msg" class="textarea flex-1" placeholder="Type a message..." maxlength="1200" style="width:100%"></textarea>
        <button id="mic" class="mic-btn bg-white w-11 h-11 rounded-full">🎙️</button>
        <button id="sendBtn" class="px-4 py-2 rounded bg-green-600 text-white">Send</button>
      </div>
    </div>
  </div>

  <div id="stickerModal" class="fixed inset-0 hidden items-center justify-center bg-black/40 z-50">
    <div class="bg-white rounded-lg p-4 w-11/12 max-w-2xl">
      <div class="flex justify-between items-center mb-3"><div class="font-semibold">Stickers & GIFs</div><button id="closeSticker" class="text-gray-500">✕</button></div>
      <div id="stickerGrid" class="grid grid-cols-4 gap-3"></div>
    </div>
  </div>

  <div id="profileModal" class="fixed inset-0 hidden items-center justify-center bg-black/40 z-[60]">
    <div class="bg-white rounded-lg p-4 w-96">
      <div class="flex items-center justify-between mb-3"><div><div class="text-lg font-bold">Profile</div></div><button id="closeProfile" class="text-gray-500">✕</button></div>
      <form id="profileForm" enctype="multipart/form-data">
        <div class="mb-2"><label class="text-xs">Display name</label><input id="profile_display_name" name="name" class="w-full p-2 border rounded" value="{{ username }}" /></div>
        <div class="mb-2"><label class="text-xs">Status</label><input id="profile_status" name="status" class="w-full p-2 border rounded" value="{{ user_status }}" /></div>
        <div class="mb-2"><label class="text-xs">Avatar</label><input id="profile_avatar" name="avatar" type="file" accept="image/*" class="w-full" /></div>
        <div class="flex gap-2"><button type="submit" class="px-3 py-2 rounded bg-indigo-600 text-white">Save</button><button id="profileCancel" type="button" class="px-3 py-2 rounded bg-gray-200">Cancel</button></div>
        <div id="profileMsg" class="text-sm mt-2 text-gray-500"></div>
      </form>
    </div>
  </div>

  <div id="incomingCall" style="display:none; position:fixed; left:50%; transform:translateX(-50%); top:12px; z-index:100; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,.12);">
    <div id="incomingText">Incoming call</div>
    <div class="flex gap-2 mt-2"><button id="acceptCall" class="px-3 py-1 rounded bg-green-600 text-white">Accept</button><button id="declineCall" class="px-3 py-1 rounded bg-red-500 text-white">Decline</button></div>
  </div>

<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<script>
const socket = io();
let myName = "{{ username }}";
let lastId = 0;
let micRecording = false;
let mediaRecorder = null;
let mediaChunks = [];
let stagedFiles = []; // For multiple attachment previews

const attachMenu = byId('attachMenu');
const stickerModal = byId('stickerModal');
const stickerGrid = byId('stickerGrid');
const profileMenu = byId('profileMenu');
const profileModal = byId('profileModal');

// helpers
function escapeHtml(s){ return String(s||'').replace(/[&<>\"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function byId(id){ return document.getElementById(id); }
function formatDuration(sec) { const h = Math.floor(sec / 3600).toString().padStart(2, '0'); const m = Math.floor((sec % 3600) / 60).toString().padStart(2, '0'); const s = Math.floor(sec % 60).toString().padStart(2, '0'); return h > 0 ? `${h}:${m}:${s}` : `${m}:${s}`; }

// auto-resize textarea & dynamic width
const inputEl = byId('msg');
function resizeTextarea(){ inputEl.style.height = 'auto'; inputEl.style.height = Math.min(140, inputEl.scrollHeight) + 'px'; adjustTextareaWidth(); }
function adjustTextareaWidth(){ const parent = inputEl.parentElement; if(!parent) return; const reserve = 140; const maxW = Math.max(120, parent.clientWidth - reserve); if(!inputEl.value.includes('/n')){ inputEl.style.width = Math.min(maxW, inputEl.scrollWidth + 28) + 'px'; } else { inputEl.style.width = '100%'; } }
inputEl.addEventListener('input', resizeTextarea);
window.addEventListener('resize', ()=>{ resizeTextarea(); });
resizeTextarea();

// hide menus on body click
document.addEventListener('click', (ev)=>{ const isClickInside = (el) => el && el.contains(ev.target); if (isClickInside(attachMenu) || isClickInside(byId('plusBtn'))) return; if (isClickInside(profileMenu) || isClickInside(byId('profileBtn'))) return; attachMenu.style.display = 'none'; profileMenu.style.display = 'none'; document.querySelectorAll('.menu:not(#profileMenu)').forEach(n=>n.remove()); if(stickerModal && !stickerModal.classList.contains('hidden')){ const wrap = stickerModal.querySelector('div'); if(!wrap.contains(ev.target)) { stickerModal.classList.add('hidden'); stickerModal.classList.remove('flex'); } } });

// Helper to create attachment elements for messages
function createAttachmentElement(a) {
  const container = document.createElement('div');
  if (a.type === 'image' || a.type === 'video') {
    container.className = 'media-container mt-2';
    const downloadLink = document.createElement('a');
    downloadLink.href = a.url; downloadLink.setAttribute('download', a.name || ''); downloadLink.className = 'download-btn'; downloadLink.innerHTML = '⤓'; downloadLink.title = 'Download'; container.appendChild(downloadLink);
    let mediaEl;
    if (a.type === 'image') {
      mediaEl = document.createElement('img'); mediaEl.src = a.url; mediaEl.className = 'image-attachment';
    } else { // video
      mediaEl = document.createElement('video'); mediaEl.src = a.url; mediaEl.controls = true; mediaEl.playsInline = true; mediaEl.className = 'video-attachment';
    }
    container.appendChild(mediaEl);
    return { element: container, mediaElement: mediaEl };
  } else if (a.type === 'audio') {
      const au = document.createElement('audio'); au.src = a.url; au.controls = true; au.className = 'mt-2'; container.appendChild(au); return { element: container };
  } else if (a.type === 'doc') {
      const link = document.createElement('a'); link.href = a.url; link.className = 'doc-link'; link.setAttribute('download', a.name || 'Document'); link.innerHTML = `<span>${escapeHtml(a.name || 'Document')}</span> ⤓`; container.appendChild(link); return { element: container };
  }
  return { element: null };
}

// fetch & render messages
async function poll(){
  try{
    const resp = await fetch('/poll_messages?since=' + lastId);
    if(!resp.ok) return;
    const data = await resp.json(); if(!data.length) return;
    const container = document.getElementById('messages');
    for(const m of data){
      const me = (m.sender === myName);
      const wrapper = document.createElement('div'); wrapper.className = 'msg-row' + (me ? ' justify-start' : '');
      const body = document.createElement('div'); body.className='msg-body'; if(me) body.style.alignItems = 'flex-start';
      const meta = document.createElement('div'); meta.className='msg-meta-top'; const leftMeta = document.createElement('div'); leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong> · ${new Date(m.created_at*1000).toLocaleTimeString()}`; const rightMeta = document.createElement('div'); rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : ''; meta.appendChild(leftMeta); meta.appendChild(rightMeta);
      const hasText = m.text && m.text.trim().length > 0; const attachments = (m.attachments || []);
      const menuBtn = document.createElement('button'); menuBtn.className='three-dot'; menuBtn.innerText='⋯'; menuBtn.onclick = (ev)=>{ ev.stopPropagation(); document.querySelectorAll('.menu:not(#profileMenu)').forEach(n=>n.remove()); const menu = document.createElement('div'); menu.className='menu'; const edit = document.createElement('div'); edit.innerText='Edit'; edit.onclick = async (e)=>{ e.stopPropagation(); const newText = prompt('Edit message text', m.text || ''); if(newText !== null){ await fetch('/edit_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id,text:newText})}); container.innerHTML=''; lastId=0; poll(); } }; const del = document.createElement('div'); del.innerText='Delete'; del.onclick = async (e)=>{ e.stopPropagation(); if(confirm('Delete this message?')){ await fetch('/delete_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id})}); container.innerHTML=''; lastId=0; poll(); } }; const react = document.createElement('div'); react.innerText='React ❤️'; react.onclick = async (e)=>{ e.stopPropagation(); await fetch('/react_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id,emoji:'❤️'})}); container.innerHTML=''; lastId=0; poll(); }; if(m.sender === myName) menu.appendChild(edit); menu.appendChild(del); menu.appendChild(react); document.body.appendChild(menu); const rect = menuBtn.getBoundingClientRect(); menu.style.position = 'fixed'; menu.style.top = (rect.bottom + 5) + 'px'; menu.style.left = (rect.left) + 'px'; menu.style.right = 'auto'; };
      body.appendChild(meta);

      if(attachments.length && !hasText){
        const rowInner = document.createElement('div'); rowInner.style.display='flex'; rowInner.style.gap='8px'; rowInner.style.alignItems='flex-start'; rowInner.style.flexDirection = 'row'; const attContainer = document.createElement('div'); attContainer.style.textAlign = 'left'; attachments.forEach(a=>{ if(a.type==='sticker'){ const img = document.createElement('img'); img.src = a.url; img.className = 'sticker'; attContainer.appendChild(img); } else { const { element, mediaElement } = createAttachmentElement(a); if (element) { attContainer.appendChild(element); } } }); rowInner.appendChild(attContainer); const menuContainer = document.createElement('div'); menuContainer.appendChild(menuBtn); rowInner.appendChild(menuContainer); body.appendChild(rowInner);
      } else {
        const rowInner = document.createElement('div'); rowInner.style.display='flex'; rowInner.style.gap='8px'; rowInner.style.alignItems='flex-start'; rowInner.style.flexDirection = 'row'; const msgContainer = document.createElement('div'); const topRow = document.createElement('div'); topRow.style.display='flex'; topRow.style.justifyContent='flex-start'; topRow.style.alignItems='flex-start'; topRow.style.gap = '8px'; const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me' : 'them'); bubble.innerHTML = hasText ? (escapeHtml(m.text) + (m.edited ? ' <span style="font-size:.7rem;color:#9ca3af">(edited)</span>':'') ) : '';
        if(attachments.length){ attachments.forEach(a=>{ if(a.type==='sticker'){ const el = document.createElement('img'); el.src = a.url; el.className = 'sticker'; bubble.appendChild(el); } else { const { element, mediaElement } = createAttachmentElement(a); if (element) { bubble.appendChild(element); } } }); }
        topRow.appendChild(bubble); topRow.appendChild(menuBtn); msgContainer.appendChild(topRow); rowInner.appendChild(msgContainer); body.appendChild(rowInner);
      }
      wrapper.appendChild(body); container.appendChild(wrapper); lastId = m.id;
    }
    container.scrollTop = container.scrollHeight;
  }catch(e){ console.error(e); }
}
poll(); setInterval(poll, 2000);

// send message (support multiple files) with optimistic UI for uploads
byId('sendBtn').addEventListener('click', async ()=>{
  const text = inputEl.value.trim();
  if(!text && stagedFiles.length===0) return;

  // create optimistic/pending message in UI
  const container = byId('messages');
  const tempId = 'temp-' + Date.now();
  const wrapper = document.createElement('div'); wrapper.className = 'msg-row justify-start'; wrapper.dataset.tempId = tempId;
  const body = document.createElement('div'); body.className = 'msg-body';
  const topRow = document.createElement('div'); topRow.style.display='flex'; topRow.style.gap='8px'; topRow.style.alignItems='flex-start';
  const bubble = document.createElement('div'); bubble.className = 'bubble me';
  if(text) bubble.appendChild(document.createTextNode(text));

  // attach previews (use object URLs) and overlay spinner
  const tempObjectUrls = [];
  stagedFiles.forEach((file)=>{
    if(file.type.startsWith('image/')){
      const img = document.createElement('img'); const url = URL.createObjectURL(file); tempObjectUrls.push(url); img.src = url; img.className = 'image-attachment'; bubble.appendChild(img);
    } else if(file.type.startsWith('video/')){
      const wrap = document.createElement('div'); wrap.style.position='relative'; wrap.style.display='inline-block';
      const vid = document.createElement('video'); const url = URL.createObjectURL(file); tempObjectUrls.push(url); vid.src = url; vid.muted = true; vid.controls = true; vid.className = 'video-attachment'; wrap.appendChild(vid);
      const overlay = document.createElement('div'); overlay.className = 'uploading-overlay'; overlay.innerHTML = '<div class="spinner"></div>'; wrap.appendChild(overlay);
      bubble.appendChild(wrap);
    } else if(file.type.startsWith('audio/')){
      const au = document.createElement('audio'); const url = URL.createObjectURL(file); tempObjectUrls.push(url); au.src = url; au.controls = true; bubble.appendChild(au);
    } else {
      const d = document.createElement('div'); d.className='preview-item-doc'; d.textContent = file.name; bubble.appendChild(d);
    }
  });

  topRow.appendChild(bubble); body.appendChild(topRow); wrapper.appendChild(body); container.appendChild(wrapper); container.scrollTop = container.scrollHeight;

  // prepare form data
  const fd = new FormData(); fd.append('text', text);
  stagedFiles.forEach((f)=> fd.append('file', f, f.name));

  try{
    const r = await fetch('/send_composite_message', { method: 'POST', body: fd });
    if(r.ok){
      // remove optimistic
      const el = document.querySelector('[data-temp-id="'+tempId+'"]'); if(el) el.remove();
      inputEl.value = ''; resizeTextarea(); clearAttachmentPreview(); await poll();
    } else {
      const err = await r.text(); alert('Failed to send: '+err);
      // mark as failed: remove spinner overlays
      document.querySelectorAll('[data-temp-id="'+tempId+'"] .uploading-overlay').forEach(o=>{ o.style.background='rgba(255,0,0,0.35)'; o.innerHTML='!'; });
    }
  }catch(e){ alert('Error sending: '+e.message); document.querySelectorAll('[data-temp-id="'+tempId+'"] .uploading-overlay').forEach(o=>{ o.style.background='rgba(255,0,0,0.35)'; o.innerHTML='!'; }); }
  finally{ // revoke object urls
    tempObjectUrls.forEach(u=> URL.revokeObjectURL(u));
  }
});

// send on Enter
inputEl.addEventListener('keydown', async (e)=>{ if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); byId('sendBtn').click(); } });

// Attachment Preview Logic (multiple)
function setAttachmentPreview(files) {
  stagedFiles = Array.from(files || []);
  const previewContainer = byId('attachmentPreview'); previewContainer.innerHTML = ''; previewContainer.style.display = stagedFiles.length ? 'block' : 'none';

  stagedFiles.forEach((file, idx)=>{
    const item = document.createElement('div'); item.className = 'preview-item';
    const removeBtn = document.createElement('button'); removeBtn.className = 'preview-remove-btn'; removeBtn.innerHTML = '×'; removeBtn.onclick = (e)=>{ e.stopPropagation(); stagedFiles.splice(idx,1); setAttachmentPreview(stagedFiles); };
    item.appendChild(removeBtn);

    const reader = new FileReader();
    reader.onload = (e) => {
      if (file.type.startsWith('image/')) { const img = document.createElement('img'); img.src = e.target.result; item.appendChild(img); }
      else if (file.type.startsWith('video/')) { const vid = document.createElement('video'); vid.src = e.target.result; vid.muted = true; vid.controls = true; item.appendChild(vid); }
      else if (file.type.startsWith('audio/')) { const audio = document.createElement('audio'); audio.src = e.target.result; audio.controls = true; item.appendChild(audio); }
      else { const doc = document.createElement('div'); doc.className = 'preview-item-doc'; doc.textContent = file.name; item.appendChild(doc); }
    };
    reader.readAsDataURL(file);
    previewContainer.appendChild(item);
  });
}

function clearAttachmentPreview() { stagedFiles = []; const previewContainer = byId('attachmentPreview'); previewContainer.innerHTML = ''; previewContainer.style.display = 'none'; }

function handleFileSelection(event) { const files = event.target.files; if (files && files.length) setAttachmentPreview(files); attachMenu.style.display = 'none'; event.target.value = ''; }

byId('fileAttach').addEventListener('change', handleFileSelection);
byId('cameraAttach').addEventListener('change', handleFileSelection);
byId('docAttach').addEventListener('change', handleFileSelection);

byId('plusBtn').addEventListener('click', (ev)=>{ ev.stopPropagation(); attachMenu.style.display = (attachMenu.style.display==='flex'?'none':'flex'); });

// sticker picker
byId('stickerPickerBtn').addEventListener('click', async (ev)=>{ ev.stopPropagation(); attachMenu.style.display = 'none'; const res = await fetch('/stickers_list'); const arr = await res.json(); stickerGrid.innerHTML = ''; arr.forEach(url=>{ const img = document.createElement('img'); img.src = url; img.className='sticker cursor-pointer'; img.onclick = async ()=>{ await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({text:'', attachments:[{type:'sticker', url}]})}); stickerModal.classList.add('hidden'); stickerModal.classList.remove('flex'); await poll(); }; stickerGrid.appendChild(img); }); stickerModal.classList.remove('hidden'); stickerModal.classList.add('flex'); });

// mic toggle
const micBtn = byId('mic');
micBtn.addEventListener('click', async ()=>{ if(!micRecording){ if(!navigator.mediaDevices) return alert('Media not supported'); try{ const stream = await navigator.mediaDevices.getUserMedia({ audio:true }); mediaRecorder = new MediaRecorder(stream); mediaChunks = []; mediaRecorder.ondataavailable = e => mediaChunks.push(e.data); mediaRecorder.onstop = async ()=>{ const blob = new Blob(mediaChunks, {type:'audio/webm'}); const file = new File([blob], "voice_message.webm", { type: "audio/webm" }); setAttachmentPreview([file]); stream.getTracks().forEach(t=>t.stop()); }; mediaRecorder.start(); micRecording = true; micBtn.classList.add('mic-active'); inputEl.placeholder = 'Listening... Stop to preview.'; }catch(e){ alert('Mic error: '+e.message); } } else { if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop(); micRecording = false; micBtn.classList.remove('mic-active'); inputEl.placeholder = 'Type a message...'; } });

// Profile menu & modal logic
byId('profileBtn').addEventListener('click', (e) => { e.stopPropagation(); profileMenu.style.display = profileMenu.style.display === 'block' ? 'none' : 'block'; });
byId('viewProfileBtn').addEventListener('click', async ()=>{ profileMenu.style.display = 'none'; profileModal.classList.remove('hidden'); profileModal.classList.add('flex'); document.body.classList.add('profile-modal-open'); const r = await fetch('/profile_get'); if(r.ok){ const j = await r.json(); byId('profile_display_name').value = j.name || ''; byId('profile_status').value = j.status || ''; } });
function closeProfileModal() { profileModal.classList.add('hidden'); profileModal.classList.remove('flex'); document.body.classList.remove('profile-modal-open'); }
byId('closeProfile').addEventListener('click', closeProfileModal);
byId('profileCancel').addEventListener('click', closeProfileModal);
byId('profileForm').addEventListener('submit', async (e)=>{ e.preventDefault(); const fd = new FormData(e.target); const r = await fetch('/profile_update',{method:'POST', body:fd}); const t = await r.text(); if(!r.ok){ byId('profileMsg').textContent = t; return; } byId('profileMsg').textContent='Saved'; setTimeout(()=> location.reload(), 400); });

// Call flow
let currentInvite = null;
socket.on('connect', ()=> socket.emit('identify',{name: myName}));
socket.on('incoming_call', (data)=>{ currentInvite = data.call_id; byId('incomingText').textContent = `${data.from} is calling (${data.isVideo ? 'video':'audio'})`; byId('incomingCall').style.display = 'block'; });
socket.on('call_summary', (data) => { const msgContainer = byId('messages'); const summary = document.createElement('div'); summary.className = 'system-message'; const icon = data.isVideo ? '📹' : '📞'; summary.innerHTML = `${icon} Call ended. Duration: ${formatDuration(data.duration)}`; msgContainer.appendChild(summary); msgContainer.scrollTop = msgContainer.scrollHeight; });
byId('declineCall')?.addEventListener('click', ()=>{ if(currentInvite) socket.emit('call_decline',{call_id: currentInvite}); byId('incomingCall').style.display='none'; currentInvite=null; });
byId('acceptCall')?.addEventListener('click', async ()=>{ if(!currentInvite) return; socket.emit('call_accept',{call_id: currentInvite}); byId('incomingCall').style.display='none'; currentInvite=null; window.open('/chat','_blank'); });

byId('callAudio').addEventListener('click', ()=> initiateCall(false));
byId('callVideo').addEventListener('click', ()=> initiateCall(true));
async function initiateCall(isVideo){ const resp = await fetch('/partner_info'); const p = await resp.json(); if(!p || !p.name) return alert('No partner yet'); socket.emit('call_outgoing', {to: p.name, isVideo:isVideo, from: myName}); alert('Calling ' + p.name + ' ...'); }
</script>
</body></html>
'''

# --------- Routes & API ----------
@app.context_processor
def util():
    return dict(load_user=lambda name: load_user_by_name(name))

@app.route("/")
def index():
    first = load_first_user() is None
    return render_template_string(INDEX_HTML, first_user_none=first, heading_img=HEADING_IMG)

@app.route("/stickers_list")
def stickers_list():
    return jsonify(list_static_folder("stickers") + list_static_folder("gifs"))

@app.route("/profile_get")
def profile_get():
    username = session.get('username')
    if not username: return jsonify({"error":"not signed in"}), 401
    u = load_user_by_name(username)
    return jsonify({"name": u['name'], "status": u.get('status',''), "avatar": u.get('avatar')})

@app.route("/profile_update", methods=["POST"])
def profile_update():
    username = session.get('username')
    if not username: return "not signed in", 401
    new_name = request.form.get('name', '').strip() or None
    status = request.form.get('status', None)
    avatar_file = request.files.get('avatar')
    avatar_url = None
    if avatar_file and avatar_file.filename:
        fn = secure_filename(avatar_file.filename)
        save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
        path = os.path.join(app.static_folder, save_name)
        avatar_file.save(path)
        avatar_url = url_for('static', filename=save_name)
    conn = db_conn(); c = conn.cursor()
    if new_name and new_name != username:
        c.execute("UPDATE users SET name = ? WHERE name = ?", (new_name, username))
        c.execute("UPDATE messages SET sender = ? WHERE sender = ?", (new_name, username))
        username = new_name
    if avatar_url:
        c.execute("UPDATE users SET avatar = ? WHERE name = ?", (avatar_url, username))
    if status is not None:
        c.execute("UPDATE users SET status = ? WHERE name = ?", (status, username))
    conn.commit(); conn.close()
    session['username'] = username
    return jsonify({"status":"ok"})

@app.route("/register", methods=["POST"])
def register():
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    passkey = body.get("passkey") or ""
    if not name: return "missing name", 400
    existing_master = load_first_user()
    if existing_master is None:
        if not passkey: return "passkey required for first registration", 400
        salt, h = hash_pass(passkey)
        try:
            save_user(name, salt, h, avatar=None, status="", make_owner=True)
            session['username'] = name; touch_user_presence(name)
            return jsonify({"status":"registered","username":name})
        except Exception as e: return f"db error: {e}", 500
    else:
        master = get_owner() or load_first_user()
        if not passkey: return "passkey required", 400
        if not verify_pass(passkey, master['pass_salt'], master['pass_hash']): return "invalid passkey", 403
        salt, h = hash_pass(passkey)
        try:
            save_user(name, salt, h, avatar=None, status="", make_owner=False)
            session['username'] = name; touch_user_presence(name)
            return jsonify({"status":"registered","username":name})
        except Exception as e: return f"db error: {e}", 500

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    name = (body.get("name") or "").strip()
    passkey = body.get("passkey") or ""
    if not name: return "missing name", 400
    user = load_user_by_name(name)
    if not user: return "no such user", 404
    if not passkey: return "passkey required", 400
    if not verify_pass(passkey, user['pass_salt'], user['pass_hash']):
        owner = get_owner()
        if owner and verify_pass(passkey, owner['pass_salt'], owner['pass_hash']):
            session['username'] = name; touch_user_presence(name); return jsonify({"status":"ok","username":name})
        return "invalid passkey", 403
    session['username'] = name; touch_user_presence(name)
    return jsonify({"status":"ok","username":name})

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route("/chat")
def chat():
    username = session.get('username'); 
    if not username: return redirect(url_for('index'))
    user = load_user_by_name(username); 
    if not user: return redirect(url_for('index'))
    owner = get_owner(); partner = get_partner()
    is_owner = user.get("is_owner", False); is_partner = user.get("is_partner", False)
    owner_name = owner["name"] if owner else None; partner_name = partner["name"] if partner else None
    is_member = is_owner or is_partner
    touch_user_presence(username)
    return render_template_string(CHAT_HTML, username=username, user_status=user.get('status',''), user_avatar=user.get('avatar',''), is_owner=is_owner, is_partner=is_partner, owner_name=owner_name, partner_name=partner_name, is_member=is_member, heading_img=HEADING_IMG)

# Route for sending messages that might have an attachment
@app.route("/send_composite_message", methods=["POST"])
def send_composite_message():
    username = session.get('username')
    if not username: return "not signed in", 401
    
    text = request.form.get('text', '').strip()
    files = request.files.getlist('file') or []
    attachments = []

    for file in files:
        if file and file.filename:
            fn = secure_filename(file.filename)
            save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
            path = os.path.join(app.static_folder, save_name)
            file.save(path)
            url = url_for('static', filename=save_name)
            ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
            kind = "doc"
            if ext in ALLOWED_IMAGE_EXT:
                kind = "image"
            elif ext in ALLOWED_VIDEO_EXT:
                kind = "video"
            elif ext in ALLOWED_AUDIO_EXT:
                kind = "audio"
            attachments.append({"type": kind, "url": url, "name": fn})

    if text or attachments:
        save_message(username, text, attachments=attachments)
        touch_user_presence(username)
    
    return jsonify({"status": "ok"})


# Kept for sticker sending, which is URL-based
@app.route("/send_message", methods=["POST"]) 
def send_message():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    text = (body.get("text") or "").strip()
    attachments = body.get("attachments") or []
    save_message(username, text, attachments=attachments); touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/poll_messages")
def poll_messages():
    since = int(request.args.get("since", 0))
    msgs = fetch_messages(since)
    return jsonify(msgs)

@app.route("/edit_message", methods=["POST"])
def route_edit_message():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id"); text = body.get("text","").strip()
    ok, err = edit_message_db(msg_id, text, username)
    if not ok: return err, 400
    touch_user_presence(username); return jsonify({"status":"ok"})

@app.route("/delete_message", methods=["POST"])
def route_delete_message():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id")
    ok, err = delete_message_db(msg_id, username)
    if not ok: return err, 400
    touch_user_presence(username); return jsonify({"status":"ok"})

@app.route("/react_message", methods=["POST"])
def route_react_message():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id"); emoji = body.get("emoji","❤️")
    ok, err = react_message_db(msg_id, username, emoji)
    if not ok: return err, 400
    touch_user_presence(username); return jsonify({"status":"ok"})

@app.route("/partner_info")
def partner_info():
    p = get_partner()
    return jsonify(p or {})

# socket handlers
@socketio.on('identify')
def on_identify(data):
    name = data.get('name')
    if not name: return
    USER_SID[name] = request.sid
    emit('identified', {'status':'ok'})
    emit('presence', {'user': name, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    for u, s in list(USER_SID.items()):
        if s == sid:
            del USER_SID[u]
            emit('presence', {'user': u, 'online': False}, broadcast=True)
            break

@socketio.on('call_outgoing')
def on_call_outgoing(data):
    to = data.get('to'); isVideo = data.get('isVideo', False); caller = data.get('from') or 'unknown'
    call_id = secrets.token_hex(12)
    save_call(call_id, caller, to, isVideo, status='ringing')
    CALL_INVITES[call_id] = {"caller": caller, "callee": to}
    sid = USER_SID.get(to)
    if sid:
        emit('incoming_call', {'from': caller, 'isVideo': isVideo, 'call_id': call_id}, room=sid)

@socketio.on('call_accept')
def on_call_accept(data):
    call_id = data.get('call_id')
    info = CALL_INVITES.get(call_id)
    if not info: return
    update_call_started(call_id)
    sid = USER_SID.get(info['caller'])
    if sid:
        emit('call_accepted', {'call_id': call_id, 'from': info['callee']}, room=sid)

@socketio.on('call_decline')
def on_call_decline(data):
    call_id = data.get('call_id'); info = CALL_INVITES.get(call_id)
    if not info: return
    save_call(call_id, info['caller'], info['callee'], 0, status='declined')
    sid = USER_SID.get(info['caller'])
    if sid: emit('call_declined', {'call_id': call_id}, room=sid)
    CALL_INVITES.pop(call_id, None)

@socketio.on('call_end')
def on_call_end(data):
    call_id = data.get('call_id')
    update_call_ended(call_id)
    log = fetch_call_log_by_id(call_id)
    if log and log.get('started_at') and log.get('ended_at'):
        duration = log['ended_at'] - log['started_at']
        socketio.emit('call_summary', {'duration': duration, 'isVideo': log['is_video']})

    info = CALL_INVITES.pop(call_id, None)
    if info:
        sid_caller = USER_SID.get(info.get('caller'))
        sid_callee = USER_SID.get(info.get('callee'))
        if sid_caller: emit('call_ended', {'call_id': call_id}, room=sid_caller)
        if sid_callee: emit('call_ended', {'call_id': call_id}, room=sid_callee)

# WebRTC signaling passthrough
@socketio.on('webrtc_offer')
def on_webrtc_offer(data):
    to = data.get('to'); sid = USER_SID.get(to)
    if sid: emit('webrtc_offer', data, room=sid)

@socketio.on('webrtc_answer')
def on_webrtc_answer(data):
    to = data.get('to'); sid = USER_SID.get(to)
    if sid: emit('webrtc_answer', data, room=sid)

@socketio.on('ice_candidate')
def on_ice_candidate(data):
    to = data.get('to'); sid = USER_SID.get(to)
    if sid: emit('ice_candidate', data, room=sid)

# ----- run -----
if __name__ == "__main__":
    print("DB:", DB_PATH)
    socketio.run(app, host="0.0.0.0", port=PORT, debug=True)
