# Asphalt_Legends.py (updated)
import os
import sqlite3
import secrets
import time
import json
import hashlib
import hmac
import pathlib
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
MAX_MESSAGES = 120
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
ALLOWED_VIDEO_EXT = {"mp4", "webm", "ogg"}
ALLOWED_AUDIO_EXT = {"mp3", "wav", "ogg", "m4a", "webm"}

# ensure static subfolders
pathlib.Path(os.path.join(app.static_folder, "uploads")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "stickers")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "gifs")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "generated")).mkdir(parents=True, exist_ok=True)

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
    # toggle: remove if same exists from same user else add
    found = False
    for rec in list(reactions):
        if rec.get("emoji") == emoji and rec.get("user") == reactor:
            reactions.remove(rec)
            found = True
            break
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

# ---------- Generated stickers (programmatic) ----------
def ensure_generated_stickers():
    """Create a handful of SVG stickers/avatars if they don't exist yet."""
    gen_dir = os.path.join(app.static_folder, "generated")
    os.makedirs(gen_dir, exist_ok=True)
    # create 12 simple SVG emoji-like stickers and some avatar variations
    for i, emoji in enumerate(["😀","😂","😍","😎","🤩","😅","😢","🤔","😴","😡","🤝","🎉"]):
        fn = f"emoji_{i}.svg"
        p = os.path.join(gen_dir, fn)
        if not os.path.exists(p):
            svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256">
  <rect width="100%" height="100%" rx="24" fill="white"/>
  <text x="50%" y="55%" font-size="120" dominant-baseline="middle" text-anchor="middle">{emoji}</text>
</svg>'''
            with open(p, "w", encoding="utf-8") as f:
                f.write(svg)
    # make some avatar SVGs (initials style) for a few example names
    sample_names = ["Ace Racer","ProGamer","Lucky Luke","Maya","Tommy"]
    for i, name in enumerate(sample_names):
        initials, color = initials_and_color(name)
        fn = f"avatar_{i}.svg"
        p = os.path.join(gen_dir, fn)
        if not os.path.exists(p):
            svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256">
  <rect width="100%" height="100%" rx="24" fill="{color}" />
  <text x="50%" y="55%" font-size="72" dominant-baseline="middle" text-anchor="middle" fill="#fff">{initials}</text>
</svg>'''
            with open(p, "w", encoding="utf-8") as f:
                f.write(svg)

ensure_generated_stickers()

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

# ---- CHAT HTML updated (contains sticker panel, emoji picker, floating plus button, reaction animation, composer shift) ----
CHAT_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Asphalt Legends — Chat</title>
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{--glass-bg: rgba(255,255,255,0.55); --accent:#6366f1; --profile-fg:#fff; --download-bg:#000;}
  html,body{height:100%; margin:0; font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; -webkit-font-smoothing:antialiased;}
  body{ background: url("/static/IMG_5939.jpeg") no-repeat center center fixed; background-size: cover; background-attachment: fixed; background-position: center; }

  /* header */
  .fixed-header-container{ position:fixed; top:0; left:0; right:0; z-index:60; background:rgba(255,255,255,0.5); backdrop-filter:blur(6px); padding:8px 0; box-shadow:0 2px 12px rgba(0,0,0,0.06);}
  header{ max-width:980px; margin:0 auto; position:relative; text-align:center; padding:2px 12px; }
  header img{ max-height:56px; display:block; margin:0 auto; object-fit:contain; }
  .heading{ display:flex; justify-content:center; gap:8px; align-items:center; font-weight:800; }
  .left{ color:#3730a3 } .right{ color:#be185d }

  /* top-left / top-right */
  .top-left{ position:absolute; left:12px; top:12px; display:flex; gap:8px; }
  .top-right{ position:absolute; right:12px; top:12px; display:flex; gap:8px; align-items:center; max-width:40vw; }
  .profile-name{ background:var(--accent); color:var(--profile-fg); padding:6px 10px; border-radius:999px; font-weight:700; display:inline-flex; align-items:center; gap:8px; max-width:40vw; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }

  /* main */
  main{ max-width:980px; margin:0 auto; padding-top:112px; padding-left:12px; padding-right:12px; padding-bottom:220px; min-height:calc(100vh - 260px); }
  #messages{ display:block; }

  /* bubble layout */
  .msg-row{ margin-bottom:12px; display:flex; gap:10px; align-items:flex-start; }
  .msg-row.justify-end{ justify-content:flex-end; }
  .msg-row.justify-start{ justify-content:flex-start; }
  .msg-body{ display:flex; flex-direction:column; min-width:0; }
  .bubble{ position:relative; padding:12px 16px; border-radius:14px; background:rgba(255,255,255,0.95); box-shadow:0 8px 24px rgba(0,0,0,0.06); max-width:72%; word-break:break-word; white-space:pre-wrap; transition:all .18s ease; }
  .me{ background:#dcfce7; align-self:flex-end; }
  .them{ background:rgba(255,255,255,0.95); align-self:flex-start; }
  .bubble .three-dot { position:absolute; top:8px; right:8px; background:transparent; color:#111827; border:none; font-size:1.1rem; padding:6px; border-radius:8px; cursor:pointer; }
  .bubble .three-dot-box{ position:absolute; top:6px; right:6px; background:white; color:#111827; border-radius:8px; padding:4px 6px; box-shadow:0 8px 20px rgba(0,0,0,0.08); cursor:pointer; }

  /* ensure three-dot doesn't overlap text: add right padding */
  .bubble { padding-right:48px; }

  /* attachments */
  .media-container{ position:relative; display:block; margin-top:8px; width:100%; max-width:420px; }
  .media-container img.thumb, .media-container img.image-attachment{ width:100%; border-radius:10px; display:block; }
  .media-container video.video-attachment{ width:100%; border-radius:10px; display:block; }
  .play-overlay{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; }
  .play-circle{ width:64px; height:64px; border-radius:999px; background:rgba(0,0,0,0.6); display:flex; align-items:center; justify-content:center; color:white; font-size:24px; }

  .download-btn{ position:absolute; top:10px; right:10px; width:36px; height:36px; border-radius:999px; display:flex; align-items:center; justify-content:center; color:white; background:var(--download-bg); box-shadow:0 8px 20px rgba(0,0,0,0.2); text-decoration:none; z-index:10; }

  .doc-link{ display:inline-flex; gap:10px; padding:8px 12px; border-radius:10px; background:white; box-shadow:0 6px 18px rgba(0,0,0,0.04); margin-top:8px; text-decoration:none; color:#111827; }

  /* reaction pills */
  .reaction-row{ margin-top:8px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .reaction-pill{ display:inline-flex; align-items:center; gap:6px; padding:6px 8px; border-radius:999px; background:rgba(0,0,0,0.06); font-size:0.9rem; transition:transform .22s cubic-bezier(.2,.9,.2,1), opacity .22s; transform-origin:center; }
  .reaction-pill.me{ background:rgba(16,185,129,0.12); border:1px solid rgba(16,185,129,0.18); }
  .reaction-pill.pop{ animation: pop .26s ease; }
  @keyframes pop{ 0%{ transform: scale(.6); opacity:0 } 60%{ transform: scale(1.08); opacity:1 } 100%{ transform: scale(1); } }

  /* composer and floating plus */
  .composer{ position:fixed; left:0; right:0; bottom:env(safe-area-inset-bottom, 12px); display:flex; justify-content:center; z-index:80; padding:12px; transition: transform .22s; }
  .composer.shift-up{ transform: translateY(-260px); } /* adjusted when sticker panel opens */
  .composer-inner{ width:100%; max-width:980px; display:flex; flex-direction:column; gap:8px; }
  .composer-main{ display:flex; gap:8px; align-items:center; width:100%; background:var(--glass-bg); border-radius:18px; padding:8px; border:1px solid rgba(255,255,255,0.6); box-shadow:0 8px 30px rgba(0,0,0,0.06); }
  .textarea{ flex:1; min-height:44px; max-height:140px; border-radius:12px; padding:12px; border:1px solid rgba(0,0,0,0.05); background:rgba(255,255,255,0.8); }
  .mic-btn{ width:44px; height:44px; border-radius:999px; display:inline-flex; align-items:center; justify-content:center; background:white; }
  .send-btn{ padding:8px 14px; border-radius:8px; background:#059669; color:white; border:none; }

  .plus-floating{ position:fixed; right:20px; bottom:90px; z-index:85; width:44px; height:44px; border-radius:12px; display:flex; align-items:center; justify-content:center; background:#fff; box-shadow:0 10px 28px rgba(0,0,0,0.12); border:none; font-size:20px; }

  /* attach menu near plus */
  .attach-menu{ position:fixed; right:20px; bottom:146px; z-index:86; display:none; background:white; border-radius:10px; box-shadow:0 22px 48px rgba(0,0,0,0.16); padding:8px; min-width:180px; }

  /* sticker panel (bottom sheet) */
  .sticker-panel{ position:fixed; left:0; right:0; bottom:0; z-index:90; background:rgba(255,255,255,0.98); box-shadow:0 -18px 40px rgba(0,0,0,0.18); border-top-left-radius:16px; border-top-right-radius:16px; padding:12px; transform: translateY(100%); transition: transform .24s ease; max-height:52vh; overflow:auto; }
  .sticker-panel.open{ transform: translateY(0); }
  .sticker-tabs{ display:flex; gap:8px; margin-bottom:8px; }
  .sticker-grid{ display:grid; grid-template-columns: repeat(auto-fill, minmax(84px, 1fr)); gap:8px; }

  /* emoji picker (used for reactions) */
  .emoji-picker{ position:fixed; z-index:9999; padding:8px; background:white; border-radius:10px; box-shadow:0 18px 44px rgba(0,0,0,0.18); display:grid; grid-template-columns: repeat(8, 1fr); gap:6px; width:auto; }

  /* small helpers */
  .menu{ position:fixed; background:white; padding:8px; border-radius:10px; box-shadow:0 18px 44px rgba(0,0,0,0.18); z-index:120; min-width:140px; }
  .menu div, .menu button{ width:100%; text-align:left; padding:8px 10px; cursor:pointer; border-radius:8px; border:none; background:transparent; }
  .menu div:hover{ background:#f3f4f6; }

  /* responsive tweaks */
  @media (max-width:640px){
    .media-container{ max-width:320px; }
    .plus-floating{ right:12px; bottom:92px; width:42px; height:42px; }
    .attach-menu{ right:12px; bottom:146px; min-width:150px; }
    .bubble{ max-width: calc(100% - 56px); padding-right:56px; }
    .composer.shift-up{ transform: translateY(-46vh); } /* taller on small screens */
    .sticker-grid{ grid-template-columns: repeat(4, 1fr); }
  }
</style>
</head><body>
<div class="fixed-header-container">
  <div class="top-left">
    <button id="callAudioBtn">📞</button>
    <button id="callVideoBtn">📹</button>
  </div>
  <div class="top-right">
    <div id="profileBtn" class="profile-name">{{ username }}</div>
    <div id="profileMenu" class="menu" style="display: block;position: absolute;right: 5px;top: 40px;background: white;border-radius: 9px;padding: 5px;">
      <div id="viewProfileBtn">Profile</div>
      <form method="post" action="{{ url_for('logout') }}"><button type="submit">Logout</button></form>
    </div>
  </div>
  <header>
    <img src="{{ heading_img }}" alt="heading"/>
    <div class="heading"><div class="left">Asphalt</div><div class="right">Legends</div></div>
  </header>
</div>

<main>
  <div id="messages"></div>
</main>

<!-- floating plus -->
<button id="plusFloating" class="plus-floating">＋</button>
<div id="attachMenu" class="attach-menu">
  <label style="display:block; padding:6px; cursor:pointer;"><input id="fileAttach" type="file" accept="image/*,video/*,audio/*" hidden multiple/> Photo/Video</label>
  <label style="display:block; padding:6px; cursor:pointer;"><input id="cameraAttach" type="file" accept="image/*,video/*" capture="environment" hidden multiple/> Camera</label>
  <label style="display:block; padding:6px; cursor:pointer;"><input id="docAttach" type="file" hidden multiple/> Document</label>
  <div id="openStickersBtn" style="padding:6px; cursor:pointer;">Stickers / GIFs</div>
</div>

<!-- sticker panel bottom sheet -->
<div id="stickerPanel" class="sticker-panel" aria-hidden="true">
  <div class="sticker-tabs">
    <button class="tab-btn" data-tab="stickers">Stickers</button>
    <button class="tab-btn" data-tab="gifs">GIFs</button>
    <button class="tab-btn" data-tab="avatars">Avatars</button>
  </div>
  <div id="stickerContent" class="sticker-grid"></div>
</div>

<!-- composer -->
<div id="composer" class="composer">
  <div class="composer-inner">
    <div id="attachmentPreview" style="display:none; padding:8px;"></div>
    <div class="composer-main">
      <textarea id="msg" class="textarea" placeholder="Type a message..." maxlength="1200"></textarea>
      <button id="mic" class="mic-btn">🎙️</button>
      <button id="sendBtn" class="send-btn">Send</button>
    </div>
  </div>
</div>

<!-- emoji picker template container -->
<div id="emojiContainer" style="display:none;"></div>

<!-- sticker modal fallback (not used as bottom sheet) -->
<div id="stickerModal" style="display:none;"></div>

<!-- incoming call -->
<div id="incomingCall" style="display:none; position:fixed; left:50%; transform:translateX(-50%); top:12px; z-index:100; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,.12);">
  <div id="incomingText">Incoming call</div>
  <div style="display:flex; gap:8px; margin-top:8px;"><button id="acceptCall" style="background:#059669;color:white;padding:6px;border-radius:6px;border:none;">Accept</button><button id="declineCall" style="background:#ef4444;color:white;padding:6px;border-radius:6px;border:none;">Decline</button></div>
</div>

<script>
const socket = io();
let myName = "{{ username }}";
let lastId = 0;
let stagedFiles = [];
let micRecording = false;
let mediaRecorder = null;
let mediaChunks = [];
const messagesEl = document.getElementById('messages');
const msgInput = document.getElementById('msg');
const composerEl = document.getElementById('composer');
const stickerPanel = document.getElementById('stickerPanel');
const stickerContent = document.getElementById('stickerContent');
const attachMenu = document.getElementById('attachMenu');
const plusFloating = document.getElementById('plusFloating');

function byId(id){ return document.getElementById(id); }
function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }

/* -- Emoji picker (lots of emojis) -- */
const EMOJI_LIST = ["👍","❤️","😂","😮","😢","👏","🔥","🎉","💯","😅","🤩","😍","🙂","🙃","😉","🤔","😴","😎","🤪","🤝","🤘","🤟","😇","😬","😱","😤","🤯","🥳","💥","🌟","✨","🎯","🍕","🍔","🍟","🍺","☕","🏁","🏎️","🛞","🏆"];

function showEmojiPickerForMessage(msgId, rect){
  // remove existing
  document.querySelectorAll('.emoji-picker').forEach(n=>n.remove());
  const picker = document.createElement('div');
  picker.className = 'emoji-picker';
  EMOJI_LIST.forEach(e=>{
    const b = document.createElement('button');
    b.style.fontSize='20px'; b.style.padding='6px'; b.style.border='none'; b.style.background='transparent'; b.style.cursor='pointer';
    b.innerText = e;
    b.onclick = async (ev) => {
      ev.stopPropagation();
      try {
        await fetch('/react_message', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id: msgId, emoji: e })});
      } catch(err) { console.error(err); }
      picker.remove();
      messagesEl.innerHTML=''; lastId = 0; poll();
    };
    picker.appendChild(b);
  });
  document.body.appendChild(picker);
  const left = Math.max(8, rect.left);
  const top = rect.bottom + 8;
  picker.style.left = left + 'px';
  picker.style.top = top + 'px';
}

/* -- Video thumbnail helpers (client side) -- */
function createVideoThumbnailFromUrl(url, seekTo = 0.5){
  return new Promise((resolve)=>{
    try{
      const video = document.createElement('video');
      video.crossOrigin = 'anonymous';
      video.src = url; video.muted = true; video.playsInline = true;
      video.addEventListener('loadeddata', ()=>{
        const t = Math.min(seekTo, Math.max(0, video.duration*0.2 || 0.5));
        function seekHandler(){
          try{
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth || 320;
            canvas.height = video.videoHeight || 180;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            const dataURL = canvas.toDataURL('image/png');
            video.remove();
            resolve(dataURL);
          }catch(e){ video.remove(); resolve(null); }
        }
        if(video.readyState >= 2){ video.currentTime = t; }
        else { video.addEventListener('canplay', ()=> video.currentTime = t, { once:true }); }
        video.addEventListener('seeked', seekHandler, { once:true });
        setTimeout(()=> resolve(null), 2500);
      }, { once:true });
      video.addEventListener('error', ()=> resolve(null));
    }catch(e){ resolve(null); }
  });
}
function createVideoThumbnailFromFile(file){ return new Promise((resolve)=>{ const url = URL.createObjectURL(file); createVideoThumbnailFromUrl(url).then((d)=>{ URL.revokeObjectURL(url); resolve(d); }).catch(()=>{ URL.revokeObjectURL(url); resolve(null); }); }); }

/* -- Attachment element factory -- */
function createAttachmentElement(a, avoidDownloadForAudio=true){
  const container = document.createElement('div');
  container.className = 'media-container';
  if(a.type === 'audio'){
    const au = document.createElement('audio'); au.src = a.url; au.controls = true; container.appendChild(au);
    return { element: container };
  }
  if(a.type === 'doc'){
    const link = document.createElement('a'); link.href = a.url; link.className = 'doc-link'; link.setAttribute('download', a.name || 'Document'); link.innerHTML = `<span>${escapeHtml(a.name||'Document')}</span>`;
    container.appendChild(link);
    const dl = document.createElement('a'); dl.className='download-btn'; dl.href = a.url; dl.setAttribute('download', a.name||''); dl.innerText = '⤓'; container.appendChild(dl);
    return { element: container };
  }
  if(a.type === 'image'){
    const img = document.createElement('img'); img.className='image-attachment'; img.src = a.url; container.appendChild(img);
    const dl = document.createElement('a'); dl.className='download-btn'; dl.href = a.url; dl.setAttribute('download', a.name||''); dl.innerText = '⤓'; container.appendChild(dl);
    return { element: container, mediaElement: img };
  }
  if(a.type === 'video'){
    const thumb = document.createElement('img'); thumb.className='thumb'; thumb.alt = a.name || 'video';
    const playOverlay = document.createElement('div'); playOverlay.className='play-overlay'; playOverlay.innerHTML = '<div class="play-circle">▶</div>';
    container.appendChild(thumb); container.appendChild(playOverlay);
    const dl = document.createElement('a'); dl.className='download-btn'; dl.href = a.url; dl.setAttribute('download', a.name||''); dl.innerText = '⤓'; container.appendChild(dl);

    createVideoThumbnailFromUrl(a.url).then(dataUrl=>{
      if(dataUrl) thumb.src = dataUrl;
      else {
        // fallback show video element directly
        container.innerHTML = '';
        const v = document.createElement('video'); v.src = a.url; v.controls = true; v.className='video-attachment';
        container.appendChild(dl); container.appendChild(v);
      }
    });

    container.addEventListener('click', ()=>{
      if(container.querySelector('video')) return;
      const v = document.createElement('video'); v.src = a.url; v.controls = true; v.autoplay=true; v.playsInline=true; v.className='video-attachment';
      const existingDl = container.querySelector('.download-btn');
      container.innerHTML = '';
      if(existingDl) container.appendChild(existingDl);
      container.appendChild(v);
    }, { once:true });

    return { element: container, mediaElement: thumb };
  }
  return { element: null };
}

/* -- Polling messages & rendering -- */
async function poll(){
  try{
    const resp = await fetch('/poll_messages?since=' + lastId);
    if(!resp.ok) return;
    const data = await resp.json();
    if(!data || !data.length) return;
    for(const m of data){
      const me = (m.sender === myName);
      const wrapper = document.createElement('div'); wrapper.className = 'msg-row ' + (me ? 'justify-end':'justify-start');
      const body = document.createElement('div'); body.className = 'msg-body';
      const meta = document.createElement('div'); meta.style.fontSize='0.78rem'; meta.style.color='#6b7280'; meta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong> · ${new Date(m.created_at*1000).toLocaleTimeString()}`;
      body.appendChild(meta);

      const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me':'them');
      // text
      if(m.text && m.text.trim().length){
        const t = document.createElement('div'); t.innerHTML = escapeHtml(m.text) + (m.edited ? ' <span style="font-size:.75rem;color:#9ca3af">(edited)</span>':'');
        bubble.appendChild(t);
      }
      // attachments
      if(m.attachments && m.attachments.length){
        for(const a of m.attachments){
          if(a.type === 'sticker'){
            const s = document.createElement('img'); s.src = a.url; s.style.maxWidth='160px'; s.style.borderRadius='12px'; s.style.display='block'; s.style.marginTop='8px';
            bubble.appendChild(s);
          } else {
            const { element } = createAttachmentElement(a);
            if(element) bubble.appendChild(element);
          }
        }
      }

      // Reaction pills (group)
      if(m.reactions && m.reactions.length){
        const counts = {};
        m.reactions.forEach(r=> counts[r.emoji] = (counts[r.emoji]||0) + 1);
        const reactionRow = document.createElement('div'); reactionRow.className = 'reaction-row';
        Object.keys(counts).forEach(emoji=>{
          const pill = document.createElement('div'); pill.className='reaction-pill';
          const foundByMe = m.reactions.some(x=> x.emoji===emoji && x.user===myName);
          if(foundByMe) pill.classList.add('me');
          pill.innerText = emoji + ' ' + counts[emoji];
          reactionRow.appendChild(pill);
        });
        bubble.appendChild(reactionRow);
      }

      // three-dot inside bubble (always present)
      const menuBtn = document.createElement('button'); menuBtn.className='three-dot'; menuBtn.innerText = '⋯';
      menuBtn.onclick = (ev) => {
        ev.stopPropagation();
        document.querySelectorAll('.menu').forEach(n=>n.remove());
        const menu = document.createElement('div'); menu.className='menu';
        // edit (only me)
        if(m.sender === myName){
          const edit = document.createElement('div'); edit.innerText='Edit'; edit.onclick = async (ev2)=>{ ev2.stopPropagation(); const txt = prompt('Edit message', m.text || ''); if(txt!==null){ await fetch('/edit_message',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id:m.id, text:txt })}); messagesEl.innerHTML=''; lastId=0; poll(); } document.querySelectorAll('.menu').forEach(n=>n.remove()); };
          menu.appendChild(edit);
        }
        const react = document.createElement('div'); react.innerText='React'; react.onclick = (ev2)=>{ ev2.stopPropagation(); const rect = menuBtn.getBoundingClientRect(); showEmojiPickerForMessage(m.id, rect); menu.remove(); };
        menu.appendChild(react);
        // download options (audio or other)
        const hasAudio = (m.attachments||[]).some(x=>x.type==='audio');
        const hasMedia = (m.attachments||[]).some(x=> x.type==='image' || x.type==='video' || x.type==='doc');
        if(hasAudio){
          const dlA = document.createElement('div'); dlA.innerText='Download audio'; dlA.onclick = ()=>{ const a = (m.attachments||[]).find(x=>x.type==='audio'); if(a){ const el = document.createElement('a'); el.href = a.url; el.setAttribute('download', a.name || 'audio'); document.body.appendChild(el); el.click(); el.remove(); } document.querySelectorAll('.menu').forEach(n=>n.remove()); };
          menu.appendChild(dlA);
        }
        if(hasMedia){
          const dlF = document.createElement('div'); dlF.innerText='Download file'; dlF.onclick = ()=>{ const f = (m.attachments||[]).find(x=>x.type!=='sticker' && x.type!=='audio'); if(f){ const el = document.createElement('a'); el.href = f.url; el.setAttribute('download', f.name || 'file'); document.body.appendChild(el); el.click(); el.remove(); } document.querySelectorAll('.menu').forEach(n=>n.remove()); };
          menu.appendChild(dlF);
        }
        const del = document.createElement('div'); del.innerText='Delete'; del.onclick = async (ev2)=>{ ev2.stopPropagation(); if(confirm('Delete message?')){ await fetch('/delete_message',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id:m.id })}); messagesEl.innerHTML=''; lastId=0; poll(); } document.querySelectorAll('.menu').forEach(n=>n.remove()); };
        menu.appendChild(del);
        document.body.appendChild(menu);
        const rect = menuBtn.getBoundingClientRect();
        menu.style.left = rect.left + 'px';
        menu.style.top = (rect.bottom + 8) + 'px';
      };
      bubble.appendChild(menuBtn);

      body.appendChild(bubble);
      wrapper.appendChild(body);
      messagesEl.appendChild(wrapper);

      lastId = m.id;
    }
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }catch(e){ console.error(e); }
}
poll(); setInterval(poll, 2000);

/* -- Sending messages (with optimistic UI, thumbnails) -- */
byId('sendBtn').addEventListener('click', async ()=>{
  const text = (msgInput.value||'').trim();
  if(!text && stagedFiles.length===0) return;
  const tempId = 'temp-'+Date.now();
  // optimistic UI
  const wrapper = document.createElement('div'); wrapper.className='msg-row justify-end';
  const body = document.createElement('div'); body.className='msg-body';
  const bubble = document.createElement('div'); bubble.className='bubble me'; bubble.dataset.tempId = tempId;
  if(text) bubble.appendChild(document.createTextNode(text));
  // previews
  const objectUrls = [];
  for(const file of stagedFiles){
    if(file.type.startsWith('image/')){
      const img = document.createElement('img'); const url = URL.createObjectURL(file); objectUrls.push(url); img.src = url; img.className='image-attachment'; bubble.appendChild(img);
    } else if(file.type.startsWith('video/')){
      const container = document.createElement('div'); container.style.position='relative';
      const placeholder = document.createElement('img'); placeholder.className='thumb';
      const overlay = document.createElement('div'); overlay.className='uploading-overlay'; overlay.innerHTML = '<div class="spinner"></div>';
      container.appendChild(placeholder); container.appendChild(overlay); bubble.appendChild(container);
      createVideoThumbnailFromFile(file).then(d=>{ if(d) placeholder.src=d; });
    } else if(file.type.startsWith('audio/')){
      const a = document.createElement('audio'); a.controls=true; const url = URL.createObjectURL(file); objectUrls.push(url); a.src=url; bubble.appendChild(a);
    } else {
      const d = document.createElement('div'); d.className='doc-link'; d.textContent = file.name; bubble.appendChild(d);
    }
  }
  body.appendChild(bubble); wrapper.appendChild(body); messagesEl.appendChild(wrapper); messagesEl.scrollTop = messagesEl.scrollHeight;

  const fd = new FormData(); fd.append('text', text);
  stagedFiles.forEach(f=> fd.append('file', f, f.name));
  try{
    const r = await fetch('/send_composite_message', { method:'POST', body: fd });
    if(r.ok){
      // remove optimistic element
      const el = document.querySelector('[data-temp-id="'+tempId+'"]'); if(el) el.parentElement.removeChild(el);
      msgInput.value=''; stagedFiles=[]; byId('attachmentPreview').innerHTML=''; byId('attachmentPreview').style.display='none';
      await poll();
    } else {
      const t = await r.text(); alert('Send failed: '+t);
    }
  }catch(e){ alert('Send error: '+e.message); }
  finally{ objectUrls.forEach(u=> URL.revokeObjectURL(u)); }
});
msgInput.addEventListener('keydown', function(e){ if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); byId('sendBtn').click(); } });

/* -- Attachment preview & handlers -- */
function setAttachmentPreview(files){
  stagedFiles = Array.from(files||[]);
  const p = byId('attachmentPreview'); p.innerHTML=''; p.style.display = stagedFiles.length ? 'block' : 'none';
  stagedFiles.forEach((file, idx)=>{
    const item = document.createElement('div'); item.style.display='inline-block'; item.style.marginRight='8px'; item.style.position='relative';
    const rem = document.createElement('button'); rem.innerText='×'; rem.style.position='absolute'; rem.style.top='-8px'; rem.style.right='-8px'; rem.style.background='#374151'; rem.style.color='#fff'; rem.style.border='none'; rem.style.borderRadius='999px'; rem.style.width='22px'; rem.style.height='22px'; rem.onclick = ()=>{ stagedFiles.splice(idx,1); setAttachmentPreview(stagedFiles); };
    item.appendChild(rem);
    if(file.type.startsWith('image/')){
      const img = document.createElement('img'); img.style.maxWidth='96px'; img.style.borderRadius='8px';
      const r = new FileReader(); r.onload = e => img.src = e.target.result; r.readAsDataURL(file);
      item.appendChild(img);
    } else if(file.type.startsWith('video/')){
      const img = document.createElement('img'); img.style.maxWidth='120px'; img.className='thumb';
      createVideoThumbnailFromFile(file).then(d=>{ if(d) img.src=d; });
      item.appendChild(img);
    } else if(file.type.startsWith('audio/')){
      const au = document.createElement('audio'); au.controls=true; const url = URL.createObjectURL(file); au.src = url; item.appendChild(au);
    } else {
      const div = document.createElement('div'); div.className='doc-link'; div.textContent = file.name; item.appendChild(div);
    }
    p.appendChild(item);
  });
}
function clearAttachmentPreview(){ stagedFiles = []; const p = byId('attachmentPreview'); p.innerHTML=''; p.style.display='none'; }

function handleFileSelection(ev){
  const files = ev.target.files;
  if(files && files.length) setAttachmentPreview(files);
  attachMenu.style.display='none';
  ev.target.value = '';
}
byId('fileAttach').addEventListener('change', handleFileSelection);
byId('cameraAttach').addEventListener('change', handleFileSelection);
byId('docAttach').addEventListener('change', handleFileSelection);

/* -- floating plus and attach menu toggling -- */
plusFloating.addEventListener('click', (ev)=>{
  ev.stopPropagation();
  attachMenu.style.display = attachMenu.style.display === 'block' ? 'none' : 'block';
});

/* close global UI on outside click */
document.addEventListener('click', (ev)=>{
  const insideAttach = attachMenu.contains(ev.target) || plusFloating.contains(ev.target);
  const insideProfile = byId('profileMenu') && byId('profileMenu').contains(ev.target);
  if(!insideAttach) attachMenu.style.display = 'none';
  if(!insideProfile) { const pm = byId('profileMenu'); if(pm) pm.style.display='none'; }
  // close emoji pickers
  document.querySelectorAll('.emoji-picker').forEach(n=>{ if(!n.contains(ev.target)) n.remove(); });
});

/* -- sticker panel logic -- */
byId('openStickersBtn').addEventListener('click', ()=> openStickerPanel());
function openStickerPanel(){
  const open = stickerPanel.classList.contains('open');
  if(open){ closeStickerPanel(); return; }
  // load lists and show
  Promise.all([fetch('/stickers_list').then(r=>r.json()).catch(()=>[]), fetch('/generated_stickers').then(r=>r.json()).catch(()=>[])]).then(([staticList, genList])=>{
    // by default show stickers (static + generated)
    renderStickerTab('stickers', (staticList || []).concat(genList||[]));
    stickerPanel.classList.add('open');
    composerEl.classList.add('shift-up');
    stickerPanel.setAttribute('aria-hidden','false');
  });
}
function closeStickerPanel(){
  stickerPanel.classList.remove('open');
  composerEl.classList.remove('shift-up');
  stickerPanel.setAttribute('aria-hidden','true');
}
document.querySelectorAll('.tab-btn').forEach(btn=>{
  btn.addEventListener('click', async (e)=>{
    const tab = btn.dataset.tab;
    if(tab === 'stickers'){
      const s = await fetch('/stickers_list').then(r=>r.json()).catch(()=>[]);
      const g = await fetch('/generated_stickers').then(r=>r.json()).catch(()=>[]);
      renderStickerTab('stickers', (s||[]).concat(g||[]));
    } else if(tab === 'gifs'){
      const g = await fetch('/gifs_list').then(r=>r.json()).catch(()=>[]);
      renderStickerTab('gifs', g || []);
    } else if(tab === 'avatars'){
      const a = await fetch('/generated_stickers').then(r=>r.json()).catch(()=>[]);
      renderStickerTab('avatars', a || []);
    }
  });
});
function renderStickerTab(kind, list){
  stickerContent.innerHTML = '';
  if(!list || list.length===0){
    stickerContent.innerHTML = '<div style="padding:12px;color:#6b7280">No items</div>';
    return;
  }
  list.forEach(url=>{
    const img = document.createElement('img'); img.src = url; img.style.width='100%'; img.style.borderRadius='8px'; img.style.cursor='pointer';
    const cell = document.createElement('div'); cell.appendChild(img);
    img.addEventListener('click', async ()=>{
      // send sticker as attachment (url)
      await fetch('/send_message', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] })});
      closeStickerPanel(); messagesEl.innerHTML=''; lastId=0; poll();
    });
    stickerContent.appendChild(cell);
  });
}

/* -- mic handling (voice) -- */
byId('mic').addEventListener('click', async ()=>{
  if(!micRecording){
    if(!navigator.mediaDevices) return alert('Media not supported');
    try{
      const stream = await navigator.mediaDevices.getUserMedia({ audio:true });
      mediaRecorder = new MediaRecorder(stream);
      mediaChunks = [];
      mediaRecorder.ondataavailable = e => mediaChunks.push(e.data);
      mediaRecorder.onstop = async ()=>{
        const blob = new Blob(mediaChunks, { type:'audio/webm' });
        const file = new File([blob], 'voice_message.webm', { type:'audio/webm' });
        setAttachmentPreview([file]);
        stream.getTracks().forEach(t=>t.stop());
      };
      mediaRecorder.start(); micRecording=true; byId('mic').style.background='#10b981';
      msgInput.placeholder = 'Recording... press mic to stop';
    }catch(e){ alert('Mic error: '+e.message); }
  } else {
    if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
    micRecording=false; byId('mic').style.background=''; msgInput.placeholder='Type a message...';
  }
});

/* profile, call & other UI wiring */
byId('profileBtn').addEventListener('click', (e)=>{ e.stopPropagation(); const m = byId('profileMenu'); m.style.display = (m.style.display==='block'?'none':'block'); });
byId('viewProfileBtn').addEventListener('click', async ()=>{ byId('profileMenu').style.display='none'; const r = await fetch('/profile_get'); if(r.ok){ const j=await r.json(); alert('Profile: '+(j.name||'')+'\\nStatus: '+(j.status||'')); } });

/* call flow */
let currentInvite = null;
socket.on('connect', ()=> socket.emit('identify',{ name: myName }));
socket.on('incoming_call', (data)=>{ currentInvite = data.call_id; byId('incomingText').textContent = `${data.from} is calling (${data.isVideo ? 'video':'audio'})`; byId('incomingCall').style.display='block'; });
byId('declineCall')?.addEventListener('click', ()=>{ if(currentInvite) socket.emit('call_decline',{ call_id: currentInvite }); byId('incomingCall').style.display='none'; currentInvite=null; });
byId('acceptCall')?.addEventListener('click', async ()=>{ if(!currentInvite) return; socket.emit('call_accept',{ call_id: currentInvite }); byId('incomingCall').style.display='none'; currentInvite=null; window.open('/chat','_blank'); });

byId('callAudioBtn').addEventListener('click', ()=> initiateCall(false));
byId('callVideoBtn').addEventListener('click', ()=> initiateCall(true));
async function initiateCall(isVideo){
  const resp = await fetch('/partner_info'); const p = await resp.json();
  if(!p || !p.name) return alert('No partner yet');
  socket.emit('call_outgoing', { to: p.name, isVideo:isVideo, from: myName });
  alert('Calling ' + p.name + ' ...');
}

/* simple helper to format duration */
function formatDuration(sec){
  const h = Math.floor(sec/3600).toString().padStart(2,'0');
  const m = Math.floor((sec%3600)/60).toString().padStart(2,'0');
  const s = Math.floor(sec%60).toString().padStart(2,'0');
  return h>'00' ? `${h}:${m}:${s}` : `${m}:${s}`;
}

/* ensure sticker endpoints exist; minimal fallback for GIF listing */
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
    # return stickers + generated
    static = list_static_folder("stickers")
    gen = list_static_folder("generated")
    return jsonify(static + gen)

@app.route("/gifs_list")
def gifs_list():
    return jsonify(list_static_folder("gifs"))

@app.route("/generated_stickers")
def generated_stickers():
    # return generated svg stickers created earlier
    return jsonify(list_static_folder("generated"))

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
    return jsonify({"status":"ok"})

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
