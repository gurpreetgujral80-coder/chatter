# Asphalt_Legends.py
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
              (call_id, caller, callee, 1 if is_video else 0, None, None, status))
    conn.commit(); conn.close()

def update_call_started(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE calls SET started_at = ?, status = ? WHERE id = ?", (int(time.time()), "active", call_id))
    conn.commit(); conn.close()

def update_call_ended(call_id):
    conn = db_conn(); c = conn.cursor()
    c.execute("UPDATE calls SET ended_at = ?, status = ? WHERE id = ?", (int(time.time()), "ended", call_id))
    conn.commit(); conn.close()

def fetch_call_logs(limit=50):
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT id, caller, callee, is_video, started_at, ended_at, status FROM calls ORDER BY started_at DESC LIMIT ?", (limit,))
    rows = c.fetchall(); conn.close()
    out=[]
    for r in rows:
        out.append({"id": r[0], "caller": r[1], "callee": r[2], "is_video": bool(r[3]), "started_at": r[4], "ended_at": r[5], "status": r[6]})
    return out

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
      <img src="{{ heading_img }}" alt="heading" class="mx-auto" style="max-height:64px"/>
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
  body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; background: linear-gradient(180deg, #eef2ff 0%, #fff0f6 100%); }
  header{ text-align:center; margin:12px 0 6px; }
  header img{max-height:64px; display:block; margin:0 auto;}
  .heading{display:flex;justify-content:center;gap:8px;align-items:center;margin-top:6px;}
  .left{ color:#3730a3;font-weight:800;font-size:1.4rem;}
  .right{ color:#be185d;font-weight:800;font-size:1.4rem;margin-left:6px;}
  .top-right{ position: absolute; right: 12px; top: 8px; display:flex; gap:8px; align-items:center;}
  .avatar-sm{width:36px;height:36px;border-radius:999px;object-fit:cover;}
  .bubble{ padding:10px 12px; border-radius:12px; display:inline-block; max-width:72%; word-break:break-word; white-space:pre-wrap;}
  .me{ background: linear-gradient(90deg,#dcf8c6,#e6ffe6); border-bottom-right-radius:3px;}
  .them{ background:#fff; border-bottom-left-radius:3px;}
  .meta{ font-size:.75rem; color:#6b7280; margin-bottom:4px;}
  .msg-row{ margin-bottom:10px; display:flex; gap:8px; align-items:flex-start;}
  .msg-body{ display:flex; flex-direction:column;}
  .three-dot{ background: none; border: none; cursor:pointer; font-size:1.05rem; color:#f3f4f6; padding:6px 8px; border-radius:8px; background:#111827; box-shadow:0 6px 18px rgba(0,0,0,.25);}
  .menu{ position: absolute; background:#111827; color:#fff; padding:8px; border-radius:10px; box-shadow:0 12px 30px rgba(0,0,0,.25); z-index:120; min-width:140px;}
  .menu div{ padding:8px 10px; cursor:pointer; border-radius:6px;}
  .menu div:hover{ background: rgba(255,255,255,0.06); }
  .attach-menu{ position: fixed; right:20px; bottom:84px; z-index:90; display:none; flex-direction:column; gap:8px; }
  .attach-menu button, .attach-menu label{ min-width:160px; text-align:left; }
  .call-history{ position: fixed; right:20px; bottom:140px; z-index:90; display:none; background:white; border-radius:8px; padding:8px; box-shadow:0 8px 20px rgba(0,0,0,.12); max-height:50vh; overflow:auto;}
  .mic-active{ background:#10b981 !important; color:white !important; }
  .msg-meta-top{ font-size:0.75rem; color:#6b7280; display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px;}
  .image-attachment{ border-radius:10px; display:block; max-width:86vw; margin-top:8px; }
  .sticker{ width:120px; height:auto; margin-top:8px; }
  .textarea{ resize:none; min-height:44px; max-height:220px; overflow:auto; border-radius:12px; padding:8px; }
  main{ max-width:900px; margin:0 auto; padding-bottom:110px; } /* padding-bottom so messages not hidden behind composer */
  .composer { position: fixed; left:0; right:0; bottom: env(safe-area-inset-bottom, 0); display:flex; justify-content:center; padding:12px; background: linear-gradient(180deg, rgba(255,255,255,0.6), rgba(255,255,255,0.8)); backdrop-filter: blur(6px); }
  .composer-inner{ width:100%; max-width:900px; display:flex; gap:8px; align-items:flex-end; }
  .no-bubble-image{ display:block; max-width:86vw; border-radius:12px; box-shadow:0 8px 24px rgba(0,0,0,.08); }
  @media (min-width: 768px) {
    .image-attachment { max-width:400px; }
  }
</style>
</head><body>
  <div class="top-right">
    <button id="callHistoryBtn" class="px-2 py-1 rounded bg-gray-100">Call History</button>
    <button id="profileBtn" class="rounded-full bg-indigo-600 text-white w-10 h-10 flex items-center justify-center">P</button>
    <form method="post" action="{{ url_for('logout') }}" style="display:inline"><button class="px-3 py-1 rounded bg-gray-200">Logout</button></form>
  </div>

  <header>
    <img src="{{ heading_img }}" alt="heading"/>
    <div class="heading">
      <div class="left">Asphalt</div>
      <div class="right">Legends</div>
    </div>
  </header>

  <main>
    <div class="flex items-center justify-between mb-2">
      <div>
        <div class="text-lg font-semibold">{{ username }}</div>
        <div class="text-xs text-gray-500">{{ user_status }}</div>
      </div>
      <div class="flex gap-2 items-center">
        <button id="callAudio" class="px-3 py-1 rounded bg-white shadow">📞</button>
        <button id="callVideo" class="px-3 py-1 rounded bg-white shadow">📹</button>
      </div>
    </div>

    <div id="messages" class="mb-3"></div>
  </main>

  <!-- composer fixed bottom -->
  <div class="composer">
    <div class="composer-inner">
      <button id="plusBtn" class="px-3 py-2 rounded bg-white shadow">＋</button>

      <div id="attachMenu" class="attach-menu">
        <label class="px-3 py-2 rounded bg-white border cursor-pointer">
          <input id="fileAttach" type="file" accept="image/*" class="hidden" /> Photo/Video
        </label>
        <label class="px-3 py-2 rounded bg-white border cursor-pointer">
          <input id="cameraAttach" type="file" accept="image/*" capture="environment" class="hidden" /> Camera
        </label>
        <label class="px-3 py-2 rounded bg-white border cursor-pointer">
          <input id="docAttach" type="file" class="hidden" /> Document
        </label>
        <button id="stickerPickerBtn" class="px-3 py-2 rounded bg-white border">Stickers / GIFs</button>
        <button id="shareContactBtn" class="px-3 py-2 rounded bg-white border">Share Contact</button>
        <button id="shareLocationBtn" class="px-3 py-2 rounded bg-white border">Share Location</button>
      </div>

      <textarea id="msg" class="textarea flex-1" placeholder="Type a message..."></textarea>
      <button id="mic" class="mic-btn bg-white w-11 h-11 rounded-full">🎤</button>
      <button id="sendBtn" class="px-4 py-2 rounded bg-green-600 text-white">Send</button>
    </div>
  </div>

  <!-- sticker modal -->
  <div id="stickerModal" class="fixed inset-0 hidden items-center justify-center bg-black/40 z-50">
    <div class="bg-white rounded-lg p-4 w-11/12 max-w-2xl">
      <div class="flex justify-between items-center mb-3"><div class="font-semibold">Stickers & GIFs</div><button id="closeSticker" class="text-gray-500">✕</button></div>
      <div id="stickerGrid" class="grid grid-cols-4 gap-3"></div>
    </div>
  </div>

  <!-- profile modal -->
  <div id="profileModal" class="fixed inset-0 hidden items-center justify-center bg-black/40 z-60">
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

  <!-- call history -->
  <div id="callHistory" class="call-history"></div>

  <!-- incoming call popup -->
  <div id="incomingCall" style="display:none; position:fixed; left:50%; transform:translateX(-50%); top:12px; z-index:60; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,.12);">
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
const attachMenu = document.getElementById('attachMenu');
const stickerModal = document.getElementById('stickerModal');
const stickerGrid = document.getElementById('stickerGrid');

// helpers
function escapeHtml(s){ return String(s||'').replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function byId(id){ return document.getElementById(id); }

// auto-resize textarea
const inputEl = byId('msg');
function resizeTextarea(){
  inputEl.style.height = 'auto';
  inputEl.style.height = Math.min(220, inputEl.scrollHeight) + 'px';
}
inputEl.addEventListener('input', resizeTextarea);
resizeTextarea();

// hide menus on body click
document.addEventListener('click', (ev)=>{
  // if click inside attachMenu or plusBtn or stickerModal, ignore
  const attach = attachMenu;
  const plus = byId('plusBtn');
  if(attach && (attach.contains(ev.target) || plus.contains(ev.target))) {
    return;
  }
  // close attach menu
  if(attach) attach.style.display = 'none';
  // close any message menus
  document.querySelectorAll('.menu').forEach(n=>n.remove());
  // close sticker modal if clicked outside modal content
  if(stickerModal && !stickerModal.classList.contains('hidden')){
    const wrap = stickerModal.querySelector('div');
    if(!wrap.contains(ev.target)) { stickerModal.classList.add('hidden'); stickerModal.classList.remove('flex'); }
  }
});

// fetch & render messages
async function poll(){
  try{
    const resp = await fetch('/poll_messages?since=' + lastId);
    if(!resp.ok) return;
    const data = await resp.json();
    if(!data.length) return;
    const container = document.getElementById('messages');
    for(const m of data){
      const me = (m.sender === myName);
      const wrapper = document.createElement('div'); wrapper.className='msg-row';
      const body = document.createElement('div'); body.className='msg-body';

      // meta (name/time/ticks) on top
      const meta = document.createElement('div'); meta.className='msg-meta-top';
      const leftMeta = document.createElement('div'); leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong> · ${new Date(m.created_at*1000).toLocaleTimeString()}`;
      const rightMeta = document.createElement('div'); rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
      meta.appendChild(leftMeta); meta.appendChild(rightMeta);

      // attachments-only (no bubble) — show image/sticker directly when no text
      const hasText = m.text && m.text.trim().length > 0;
      const attachments = (m.attachments || []);

      // menu button (styled darker)
      const menuBtn = document.createElement('button'); menuBtn.className='three-dot'; menuBtn.innerText='⋯';
      menuBtn.onclick = (ev)=>{
        ev.stopPropagation();
        document.querySelectorAll('.menu').forEach(n=>n.remove());
        const menu = document.createElement('div'); menu.className='menu';
        const edit = document.createElement('div'); edit.innerText='Edit'; edit.onclick = async (e)=>{
          e.stopPropagation();
          const newText = prompt('Edit message text', m.text || '');
          if(newText !== null){
            await fetch('/edit_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id,text:newText})});
            container.innerHTML=''; lastId=0; poll();
          }
        };
        const del = document.createElement('div'); del.innerText='Delete'; del.onclick = async (e)=>{
          e.stopPropagation();
          if(confirm('Delete this message?')){
            await fetch('/delete_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id})});
            container.innerHTML=''; lastId=0; poll();
          }
        };
        const react = document.createElement('div'); react.innerText='React ❤️'; react.onclick = async (e)=>{
          e.stopPropagation();
          await fetch('/react_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id,emoji:'❤️'})});
          container.innerHTML=''; lastId=0; poll();
        };
        // permissions: only show Edit if sender == me
        if(m.sender === myName) menu.appendChild(edit);
        menu.appendChild(del); menu.appendChild(react);
        document.body.appendChild(menu);
        const rect = menuBtn.getBoundingClientRect();
        menu.style.left = (rect.left - 8) + 'px';
        menu.style.top = (rect.bottom + window.scrollY + 8) + 'px';
      };

      body.appendChild(meta);

      // build content
      // If attachments exist and no text: render attachments alone with no bubble
      if(attachments.length && !hasText){
        const rowInner = document.createElement('div'); rowInner.style.display='flex'; rowInner.style.gap='8px'; rowInner.style.alignItems='flex-start';
        if(!me){
          const avatar = document.createElement('div'); avatar.style.width='34px'; avatar.style.height='34px'; avatar.style.borderRadius='999px'; avatar.style.background='#e5e7eb'; avatar.innerText=m.sender[0]||'?'; avatar.style.display='flex'; avatar.style.alignItems='center'; avatar.style.justifyContent='center';
          rowInner.appendChild(avatar);
        }
        const attContainer = document.createElement('div');
        attachments.forEach(a=>{
          if(a.type==='image' || a.type==='sticker'){
            const img = document.createElement('img'); img.src = a.url;
            img.className = (a.type==='sticker' ? 'sticker' : 'no-bubble-image');
            attContainer.appendChild(img);
          } else if(a.type==='audio'){
            const au = document.createElement('audio'); au.src = a.url; au.controls=true; attContainer.appendChild(au);
          } else if(a.type==='doc'){
            const link = document.createElement('a'); link.href = a.url; link.textContent = a.name || 'Document'; attContainer.appendChild(link);
          }
        });
        rowInner.appendChild(attContainer);
        body.appendChild(rowInner);
      } else {
        // normal bubble with text and inline attachments
        const rowInner = document.createElement('div'); rowInner.style.display='flex'; rowInner.style.gap='8px'; rowInner.style.alignItems='flex-start';
        if(!me){
          const avatar = document.createElement('div'); avatar.style.width='34px'; avatar.style.height='34px'; avatar.style.borderRadius='999px'; avatar.style.background='#e5e7eb'; avatar.innerText=m.sender[0]||'?'; avatar.style.display='flex'; avatar.style.alignItems='center'; avatar.style.justifyContent='center';
          rowInner.appendChild(avatar);
        }
        const msgContainer = document.createElement('div');
        const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me' : 'them');
        bubble.innerHTML = hasText ? (escapeHtml(m.text) + (m.edited ? ' <span style="font-size:.7rem;color:#9ca3af">(edited)</span>':'') ) : '';
        // attachments inline (if both text+attachments)
        if(attachments.length){
          attachments.forEach(a=>{
            if(a.type==='image'){
              const el = document.createElement('img'); el.src = a.url; el.className = 'image-attachment'; bubble.appendChild(el);
            } else if(a.type==='sticker'){
              const el = document.createElement('img'); el.src = a.url; el.className = 'sticker'; bubble.appendChild(el);
            } else if(a.type==='audio'){
              const el = document.createElement('audio'); el.src = a.url; el.controls=true; bubble.appendChild(el);
            } else if(a.type==='doc'){
              const el = document.createElement('a'); el.href = a.url; el.textContent = a.name || 'Document'; bubble.appendChild(el);
            }
          });
        }
        const topRow = document.createElement('div'); topRow.style.display='flex'; topRow.style.justifyContent='space-between'; topRow.style.alignItems='flex-start';
        topRow.appendChild(bubble); topRow.appendChild(menuBtn);
        msgContainer.appendChild(topRow);
        rowInner.appendChild(msgContainer);
        body.appendChild(rowInner);
      }

      wrapper.appendChild(body);
      container.appendChild(wrapper);
      lastId = m.id;
    }
    container.scrollTop = container.scrollHeight;
  }catch(e){ console.error(e); }
}
poll(); setInterval(poll, 1600);

// send text
byId('sendBtn').addEventListener('click', async ()=>{
  const text = inputEl.value.trim(); if(!text) return;
  inputEl.value = ''; resizeTextarea();
  await fetch('/send_message',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text})});
  await poll();
});

// support Enter to send (Shift+Enter for newline)
inputEl.addEventListener('keydown', async (e)=>{
  if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); byId('sendBtn').click(); }
});

// plus button opens attach menu
byId('plusBtn').addEventListener('click', (ev)=>{ ev.stopPropagation(); attachMenu.style.display = (attachMenu.style.display==='flex'?'none':'flex'); });

// map camera input to file input when used on mobile
byId('cameraAttach').addEventListener('change', async (e)=> document.getElementById('fileAttach').files = e.target.files);

// file attachments
byId('fileAttach').addEventListener('change', async (e)=>{
  const f = e.target.files[0]; if(!f) return;
  const fd = new FormData(); fd.append('file', f);
  const r = await fetch('/upload_file',{method:'POST', body: fd}); const j = await r.json();
  if(r.ok){ await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({text:'', attachments:j.attachments})}); await poll(); }
  e.target.value=''; attachMenu.style.display='none';
});

// doc
byId('docAttach').addEventListener('change', async (e)=>{
  const f = e.target.files[0]; if(!f) return;
  const fd = new FormData(); fd.append('file', f);
  const r = await fetch('/upload_file',{method:'POST', body: fd}); const j = await r.json();
  if(r.ok){ await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({text:'', attachments:j.attachments})}); await poll(); }
  e.target.value=''; attachMenu.style.display='none';
});

// sticker picker: auto load stickers+gifs from server
byId('stickerPickerBtn').addEventListener('click', async (ev)=>{
  ev.stopPropagation();
  const res = await fetch('/stickers_list'); const arr = await res.json();
  stickerGrid.innerHTML = '';
  arr.forEach(url=>{
    const img = document.createElement('img'); img.src = url; img.className='sticker cursor-pointer';
    img.onclick = async (e)=>{
      await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({text:'', attachments:[{type:'sticker', url}]})});
      stickerModal.classList.add('hidden'); stickerModal.classList.remove('flex');
      await poll();
    };
    stickerGrid.appendChild(img);
  });
  stickerModal.classList.remove('hidden'); stickerModal.classList.add('flex');
});

// share contact & location
byId('shareContactBtn').addEventListener('click', async ()=>{ const name = prompt('Contact name'); const phone = prompt('Phone'); if(!name||!phone) return; await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({text:`Contact: ${name} (${phone})`})}); await poll(); attachMenu.style.display='none'; });
byId('shareLocationBtn').addEventListener('click', async ()=>{ if(!navigator.geolocation) return alert('Geolocation not supported'); navigator.geolocation.getCurrentPosition(async (pos)=>{ const lat=pos.coords.latitude, lon=pos.coords.longitude; await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({text:`Location: https://maps.google.com/?q=${lat},${lon}`})}); await poll(); }, err=> alert('Location error: '+err.message)); attachMenu.style.display='none'; });

// mic toggle
const micBtn = byId('mic');
micBtn.addEventListener('click', async ()=>{
  if(!micRecording){
    if(!navigator.mediaDevices) return alert('Media not supported');
    try{
      const stream = await navigator.mediaDevices.getUserMedia({ audio:true });
      mediaRecorder = new MediaRecorder(stream);
      mediaChunks = [];
      mediaRecorder.ondataavailable = e => mediaChunks.push(e.data);
      mediaRecorder.onstop = async ()=>{
        const blob = new Blob(mediaChunks, {type:'audio/webm'});
        const fd = new FormData(); fd.append('file', blob, 'voice.webm');
        const r = await fetch('/upload_audio', {method:'POST', body: fd}); const j = await r.json();
        if(r.ok){ await fetch('/send_message',{method:'POST',headers:{'Content-Type':'application/json'}, body: JSON.stringify({text:'', attachments:j.attachments})}); await poll(); }
        stream.getTracks().forEach(t=>t.stop());
      };
      mediaRecorder.start();
      micRecording = true; micBtn.classList.add('mic-active'); inputEl.placeholder = 'Listening...';
    }catch(e){ alert('Mic error: '+e.message); }
  } else {
    if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
    micRecording = false; micBtn.classList.remove('mic-active'); inputEl.placeholder = 'Type a message...';
  }
});

// profile modal
byId('profileBtn').addEventListener('click', async ()=>{
  const modal = byId('profileModal'); modal.classList.remove('hidden'); modal.classList.add('flex');
  const r = await fetch('/profile_get'); if(r.ok){ const j = await r.json(); byId('profile_display_name').value = j.name || ''; byId('profile_status').value = j.status || ''; }
});
byId('closeProfile').addEventListener('click', ()=>{ const m=byId('profileModal'); m.classList.add('hidden'); m.classList.remove('flex'); });
byId('profileCancel').addEventListener('click', ()=>{ const m=byId('profileModal'); m.classList.add('hidden'); m.classList.remove('flex'); });
byId('profileForm').addEventListener('submit', async (e)=>{ e.preventDefault(); const fd = new FormData(e.target); const r = await fetch('/profile_update',{method:'POST', body:fd}); const t = await r.text(); if(!r.ok){ byId('profileMsg').textContent = t; return; } byId('profileMsg').textContent='Saved'; setTimeout(()=> location.reload(), 400); });

// call flow
let currentInvite = null;
socket.on('connect', ()=> socket.emit('identify',{name: myName}));
socket.on('incoming_call', (data)=>{ currentInvite = data.call_id; byId('incomingText').textContent = `${data.from} is calling (${data.isVideo ? 'video':'audio'})`; byId('incomingCall').style.display = 'block'; });
byId('declineCall')?.addEventListener('click', ()=>{ if(currentInvite) socket.emit('call_decline',{call_id: currentInvite}); byId('incomingCall').style.display='none'; currentInvite=null; });
byId('acceptCall')?.addEventListener('click', async ()=>{ if(!currentInvite) return; socket.emit('call_accept',{call_id: currentInvite}); byId('incomingCall').style.display='none'; currentInvite=null; window.open('/chat','_blank'); });

byId('callAudio').addEventListener('click', ()=> initiateCall(false));
byId('callVideo').addEventListener('click', ()=> initiateCall(true));
async function initiateCall(isVideo){
  const resp = await fetch('/partner_info'); const p = await resp.json();
  if(!p || !p.name) return alert('No partner yet');
  socket.emit('call_outgoing', {to: p.name, isVideo:isVideo, from: myName});
  alert('Calling ' + p.name + ' ...');
}

// call history
byId('callHistoryBtn').addEventListener('click', async ()=>{
  const el = byId('callHistory'); el.style.display = el.style.display==='block'?'none':'block';
  if(el.style.display==='block'){
    const r = await fetch('/call_logs'); const j = await r.json();
    el.innerHTML = '<div class="font-semibold mb-2">Call History</div>';
    for(const c of j){
      const started = c.started_at ? new Date(c.started_at*1000).toLocaleString() : '-';
      const ended = c.ended_at ? new Date(c.ended_at*1000).toLocaleString() : '-';
      const line = document.createElement('div'); line.style.marginBottom='8px';
      line.innerHTML = `<div><strong>${c.caller}</strong> → <strong>${c.callee}</strong> ${c.is_video? '📹':'📞'}</div><div class="text-xs text-gray-500">${c.status} · ${started} - ${ended}</div>`;
      el.appendChild(line);
    }
  }
});
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

@app.route("/join_chat", methods=["POST"])
def join_chat():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    user = load_user_by_name(username); 
    if not user: return "no such user", 400
    if user.get("is_owner") or user.get("is_partner"): return "already joined", 400
    partner = get_partner()
    if partner is None:
        set_partner_by_name(username); return "joined"
    if partner and partner.get("name") == username: return "joined"
    return "chat already has a partner", 400

@app.route("/send_message", methods=["POST"])
def send_message():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    user = load_user_by_name(username); 
    if not user: return "unknown user", 400
    if not (user.get("is_owner") or user.get("is_partner")): return "not part of chat", 403
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

# uploads
@app.route("/upload_sticker", methods=["POST"])
def upload_sticker():
    if 'file' not in request.files: return jsonify({"error":"no file"}), 400
    f = request.files['file']
    if f.filename == '': return jsonify({"error":"empty filename"}), 400
    fn = secure_filename(f.filename)
    save_name = f"stickers/{secrets.token_hex(8)}_{fn}"
    path = os.path.join(app.static_folder, save_name); f.save(path)
    url = url_for('static', filename=save_name)
    attachments = [{"type":"sticker","url": url}]
    return jsonify({"status":"ok","attachments": attachments})

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if 'file' not in request.files: return jsonify({"error":"no file"}), 400
    f = request.files['file']; 
    if f.filename == '': return jsonify({"error":"empty filename"}), 400
    fn = secure_filename(f.filename)
    save_name = f"uploads/{secrets.token_hex(8)}_{fn}"; path = os.path.join(app.static_folder, save_name); f.save(path)
    url = url_for('static', filename=save_name)
    ext = fn.rsplit(".",1)[-1].lower()
    kind = "image" if ext in ALLOWED_IMAGE_EXT else "doc"
    attachments = [{"type":kind,"url": url, "name": fn}]
    return jsonify({"status":"ok","attachments": attachments})

@app.route("/upload_audio", methods=["POST"])
def upload_audio():
    if 'file' not in request.files: return jsonify({"error":"no file"}), 400
    f = request.files['file']; 
    if f.filename == '': return jsonify({"error":"empty filename"}), 400
    fn = secure_filename(f.filename)
    save_name = f"uploads/{secrets.token_hex(8)}_{fn}"; path = os.path.join(app.static_folder, save_name); f.save(path)
    url = url_for('static', filename=save_name)
    attachments = [{"type":"audio","url": url}]
    return jsonify({"status":"ok","attachments": attachments})

@app.route("/typing", methods=["POST"])
def route_typing():
    username = session.get('username'); 
    if not username: return "not signed in", 400
    touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/partner_info")
def partner_info():
    p = get_partner()
    return jsonify(p or {})

@app.route("/call_logs")
def call_logs():
    rows = fetch_call_logs(50)
    return jsonify(rows)

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
    info = CALL_INVITES.pop(call_id, None)
    if info:
        sid = USER_SID.get(info['caller'])
        if sid: emit('call_ended', {'call_id': call_id}, room=sid)

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
    pathlib.Path(os.path.join(app.static_folder,"uploads")).mkdir(parents=True, exist_ok=True)
    pathlib.Path(os.path.join(app.static_folder,"stickers")).mkdir(parents=True, exist_ok=True)
    pathlib.Path(os.path.join(app.static_folder,"gifs")).mkdir(parents=True, exist_ok=True)
    socketio.run(app, host="0.0.0.0", port=PORT, debug=True)
    
