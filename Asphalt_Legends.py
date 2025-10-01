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
    # Toggle reactor's emoji (if same emoji exists by same user remove; otherwise add)
    removed = False
    for rec in list(reactions):
        if rec.get("emoji") == emoji and rec.get("user") == reactor:
            reactions.remove(rec); removed = True; break
    if not removed:
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
        svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240">
  <rect width="100%" height="100%" fill="{color}" rx="120" />
  <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,Segoe UI,Roboto" font-size="96" fill="#fff">{initials}</text>
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

# ---------- Generated stickers/gifs endpoints ----------
@app.route("/generated_stickers")
def generated_stickers():
    # Return a list of inline SVG data-URLs representing avatar-style stickers and a few emoji stickers.
    names = ["You","Me","AA","Pro","Gamer","Tommy","Alex","Sam"]
    outs = []
    for n in names:
        init, color = initials_and_color(n)
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240"><rect width="100%" height="100%" fill="{color}" rx="40"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="system-ui,Segoe UI,Roboto" font-size="72" fill="#fff">{init}</text></svg>'
        data = "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")
        outs.append(data)
    # A couple of emoji-based sticker placeholders
    emoji_stickers = ["😀","🔥","🏁","🚗","🎮","💥"]
    for e in emoji_stickers:
        svg = f'<svg xmlns="http://www.w3.org/2000/svg" width="240" height="240"><rect width="100%" height="100%" fill="#fff" rx="40"/><text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" font-family="Segoe UI Emoji, Noto Color Emoji, Apple Color Emoji" font-size="96" >{e}</text></svg>'
        data = "data:image/svg+xml;base64," + base64.b64encode(svg.encode("utf-8")).decode("ascii")
        outs.append(data)
    return jsonify(outs)

@app.route("/generated_gifs")
def generated_gifs():
    # Just return static/gifs plus generated placeholders if exist
    gifs = list_static_folder("gifs")
    return jsonify(gifs)

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

# ---- CHAT HTML (unchanged aside from call enhancements) ----
CHAT_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Asphalt Legends — Chat</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  :root{--glass-bg: rgba(255,255,255,0.5); --accent: #6366f1; --profile-fg: #fff; --download-bg:#000;}
  html,body{height:100%;}
  body{
    font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;
    margin:0;
    background: url("/static/IMG_5939.jpeg") no-repeat center center fixed;
    background-size: cover;
    background-attachment: fixed;
    background-position: center;
    -webkit-font-smoothing:antialiased;
    -moz-osx-font-smoothing:grayscale;
  }

  /* --- FIXED HEADER STYLES --- */
  .fixed-header-container {
    position: fixed; top: 0; left: 0; right: 0; z-index: 60;
    background: rgba(255,255,255,0.45);
    backdrop-filter: blur(6px) saturate(120%);
    padding: 6px 0;
    box-shadow: 0 2px 12px rgba(2,6,23,0.06);
  }
  header{ text-align:center; margin:-6px auto 4px; max-width:980px; position:relative; }
  header img{ max-height:56px; display:block; margin:0 auto; object-fit:contain; }
  .heading{ display:flex; justify-content:center; gap:8px; align-items:center; margin-top:-6px; }
  .left{ color:#3730a3; font-weight:800; font-size:1.05rem; }
  .right{ color:#be185d; font-weight:800; font-size:1.05rem; margin-left:6px; }

  /* Top-left call buttons */
  .top-left{
    position:absolute; left:12px; top:12px; display:flex; gap:8px; align-items:center;
  }
  .top-left button{ display:inline-flex; align-items:center; justify-content:center; min-width:36px; min-height:36px; border-radius:10px; padding:6px; box-shadow:0 6px 18px rgba(2,6,23,0.06); background:rgba(255,255,255,0.9); }

  /* Top-right profile (full name) - responsive */
  .top-right{
    position:absolute; right:12px; top:12px; display:flex; gap:8px; align-items:center;
  }
  .profile-name {
    font-weight:700; color:var(--profile-fg); background:var(--accent); padding:6px 10px; border-radius:14px;
    box-shadow:0 10px 30px rgba(99,102,241,0.12); display:inline-flex; align-items:center; gap:8px;
    max-width: calc(40vw);
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
  }
  @media (max-width:520px){
    .top-left{ left:8px; top:10px; }
    .top-right{ right:8px; top:10px; }
    .profile-name{ max-width: 46vw; padding:6px 8px; font-size:0.9rem; border-radius:12px; }
  }

  /* --- MAIN CONTENT & CHAT BUBBLES --- */
  main{ max-width:980px; margin:0 auto; padding-top: 96px; padding-bottom:170px; padding-left:12px; padding-right:12px; min-height:calc(100vh - 260px); }
  .msg-row{ margin-bottom:12px; display:flex; gap:8px; align-items:flex-start; }
  .msg-body{ display:flex; flex-direction:column; align-items:flex-start; min-width:0; }
  .bubble{ position:relative; padding:10px 14px; border-radius:12px; display:inline-block; word-break:break-word; white-space:pre-wrap; background-clip:padding-box; box-shadow: 0 6px 18px rgba(2,6,23,0.04); }
  .me{ background: linear-gradient(90deg,#e6ffed,#dcffe6); border-bottom-right-radius:6px; align-self:flex-end; margin-left:auto; }
  .them{ background: rgba(255,255,255,0.95); border-bottom-left-radius:6px; margin-right:auto; }
  .bubble .three-dot { position:absolute; top:8px; right:8px; background:transparent; border:none; font-size:1.05rem; padding:4px; cursor:pointer; color:#111827; border-radius:6px; }
  .msg-meta-top{ font-size:0.75rem; color:#6b7280; display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px; width:100%; }
  .bubble { max-width: min(780px, 72%); font-size:1rem; }
  @media (max-width:767px){ .bubble{ max-width: calc(100% - 56px); font-size:0.92rem; padding:9px 12px; } .image-attachment, .video-attachment{ max-width: 220px; } .preview-item { max-width:72px; } main{ padding-top:92px; padding-bottom:150px; } }
  @media (min-width:1024px){ main{ padding-top:120px; } .bubble{ max-width:60%; padding:12px 16px; } }

  /* attachments & previews */
  #attachmentPreview{ padding:8px; border-bottom:1px solid rgba(0,0,0,0.06); display:none; }
  .preview-item{ position:relative; display:inline-block; margin-right:8px; vertical-align:top; max-width:90px; }
  .preview-item img, .preview-item video{ max-width:100%; border-radius:8px; display:block; }
  .preview-item-doc{ background:#f3f4f6; padding:8px; border-radius:8px; font-size:0.78rem; max-width:120px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .media-container{ position:relative; display:inline-block; width:100%; max-width:420px; }
  .media-container img.thumb{ display:block; width:100%; border-radius:10px; }
  .media-container .play-overlay{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; }
  .media-container .play-overlay .play-circle{ width:56px; height:56px; background: rgba(0,0,0,0.6); border-radius:999px; display:flex; align-items:center; justify-content:center; color:white; font-size:22px; }
  .download-btn{ position:absolute; top:8px; right:8px; width:36px; height:36px; border-radius:999px; display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; background:var(--download-bg); font-size:1.05rem; z-index:10; box-shadow:0 6px 18px rgba(0,0,0,0.2); }
  .doc-link{ display:inline-flex; align-items:center; gap:10px; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 6px 18px rgba(2,6,23,0.04); margin-top:8px; text-decoration:none; color:#111827; }

  /* reaction bar under messages */
  .reaction-bar{ display:flex; gap:6px; margin-top:8px; align-items:center; }
  .reaction-pill{ display:inline-flex; align-items:center; gap:6px; padding:4px 8px; border-radius:999px; background:rgba(255,255,255,0.95); box-shadow:0 6px 18px rgba(2,6,23,0.04); font-size:0.85rem; }
  .reaction-emoji{ width:20px; height:20px; display:inline-flex; align-items:center; justify-content:center; font-size:14px; }

  /* composer */
  .composer{ position:fixed; left:0; right:0; bottom:env(safe-area-inset-bottom,0); display:flex; justify-content:center; padding:14px; z-index:70; transition:transform .22s ease; }
  .composer-inner{ width:100%; max-width:980px; display:flex; flex-direction:column; gap:8px; }
  .composer-main{ display:flex; gap:8px; align-items:center; width:100%; background:var(--glass-bg); border-radius:18px; padding:8px; border:1px solid rgba(255,255,255,0.35); box-shadow:0 6px 30px rgba(2,6,23,0.06); }
  .textarea{ resize:none; min-height:44px; max-height:140px; overflow:auto; border-radius:12px; padding:12px; border:1px solid rgba(15,23,42,0.06); background: rgba(255,255,255,0.6); backdrop-filter: blur(6px); min-width:120px; flex:1; }
  .plus-small{ width:40px; height:40px; min-width:40px; min-height:40px; border-radius:10px; display:inline-flex; align-items:center; justify-content:center; }
  .preview-remove-btn{ position:absolute; top:-8px; right:-8px; background:#374151; color:#fff; width:20px; height:20px; display:flex; align-items:center; justify-content:center; border-radius:999px; border:none; cursor:pointer; }
  .uploading-overlay{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; background: rgba(0,0,0,0.25); border-radius:10px; }
  .spinner{ width:36px; height:36px; border-radius:50%; border:4px solid rgba(255,255,255,0.2); border-top-color:#fff; animation:spin 1s linear infinite; }
  @keyframes spin{ to{ transform:rotate(360deg); } }
  #stickerPanel{ position:fixed; left:0; right:0; bottom:0; z-index:75; display:none; justify-content:center; }
  #stickerPanel .panel-inner{ max-width:980px; background:rgba(255,255,255,0.95); border-radius:12px 12px 0 0; padding:12px; box-shadow: 0 -10px 30px rgba(2,6,23,0.08); max-height:42vh; overflow:auto; }
  #stickerGrid img{ width:100%; border-radius:10px; box-shadow:0 6px 18px rgba(2,6,23,0.06); }
  .system-message{ text-align:center; font-size:0.8rem; color:#6b7280; background:rgba(230,230,230,0.7); padding:6px 12px; border-radius:12px; margin:12px auto; display:inline-block; }
  .menu{ position:fixed; background:#fff; color:#000; padding:8px; border-radius:10px; box-shadow:0 12px 30px rgba(0,0,0,.25); z-index:220; min-width:140px; }
  .menu div{ width:100%; text-align:left; padding:8px 10px; cursor:pointer; border-radius:6px; }
  .menu div:hover{ background:#f3f4f6; }

  /* call screen */
  #callScreen{ position:fixed; inset:0; z-index:300; display:none; align-items:center; justify-content:center; background: rgba(0,0,0,0.6); }
  #callScreen .call-inner{ width:100%; max-width:1080px; height:100%; max-height:680px; background: #0b1220; border-radius:12px; display:flex; flex-direction:column; gap:8px; padding:12px; box-sizing:border-box; }
  .call-videos{ flex:1; display:flex; gap:8px; align-items:stretch; justify-content:center; position:relative; }
  .call-local, .call-remote{ flex:1; border-radius:8px; overflow:hidden; position:relative; background:#000; display:flex; align-items:center; justify-content:center; }
  .call-local video, .call-remote video{ width:100%; height:100%; object-fit:cover; display:block; }
  .call-controls{ display:flex; gap:10px; justify-content:center; padding:8px; align-items:center; }
  .call-btn{ width:56px; height:56px; border-radius:999px; display:inline-flex; align-items:center; justify-content:center; font-size:20px; color:#fff; cursor:pointer; }
  .call-btn.hang { background:#ef4444; }
  .call-btn.mute { background:#374151; }
  .call-info{ color:#fff; text-align:center; font-weight:600; margin-bottom:6px; }
  .call-small-btn{ width:44px; height:44px; border-radius:999px; display:inline-flex; align-items:center; justify-content:center; font-size:18px; color:#fff; cursor:pointer; background:rgba(255,255,255,0.08); }
</style>
</head><body>
<div class="fixed-header-container">
  <div class="top-left">
    <button id="callAudio">📞</button>
    <button id="callVideo">📹</button>
  </div>

  <div class="top-right">
    <div id="profileBtn" class="profile-name">{{ username }}</div>
    <div id="profileMenu" class="menu" style="display:none; position: absolute; right:12px; top:56px;">
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
  <div id="messages" class="mb-6"></div>
</main>

<!-- Sticker panel anchored under composer -->
<div id="stickerPanel"><div class="panel-inner">
  <div style="display:flex; gap:10px; align-items:center; margin-bottom:8px;">
    <div style="font-weight:700;">Stickers & GIFs</div>
    <div style="margin-left:auto;">
      <button id="closeStickerPanel" class="px-2 py-1 rounded bg-gray-100">Close</button>
    </div>
  </div>
  <div style="display:flex; gap:8px; margin-bottom:8px;">
    <button id="tab_all" class="px-3 py-1 rounded bg-gray-100">All</button>
    <button id="tab_generated" class="px-3 py-1 rounded bg-gray-100">Avatars</button>
    <button id="tab_static" class="px-3 py-1 rounded bg-gray-100">Stickers/GIFs</button>
  </div>
  <div id="stickerList" class="grid grid-cols-5 gap-3"></div>
</div></div>

<div class="composer" id="composer">
  <div class="composer-inner">
    <div id="attachmentPreview"></div>
    <div class="composer-main" id="composerMain">
      <button id="plusBtn" class="plus-small bg-white shadow">＋</button>
      <div id="attachMenu" class="attach-menu" style="display:none;">
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

      <textarea id="msg" class="textarea" placeholder="Type a message..." maxlength="1200"></textarea>
      <button id="mic" class="mic-btn bg-white w-11 h-11 rounded-full">🎙️</button>
      <button id="sendBtn" class="px-4 py-2 rounded bg-green-600 text-white">Send</button>
    </div>
  </div>
</div>

<!-- Call screen modal -->
<div id="callScreen">
  <div class="call-inner">
    <div class="call-info" id="callInfo">Calling...</div>
    <div class="call-videos">
      <div class="call-remote" id="remoteContainer"><video id="remoteVideo" autoplay playsinline></video></div>
      <div class="call-local" id="localContainer" style="width:200px; height:140px; position:absolute; right:16px; bottom:16px; box-shadow:0 8px 24px rgba(0,0,0,0.5);">
        <video id="localVideo" autoplay muted playsinline style="width:100%; height:100%; object-fit:cover;"></video>
      </div>
    </div>
    <div class="call-controls">
      <div class="call-small-btn" id="btn_toggle_camera" title="Toggle camera">🎥</div>
      <div class="call-small-btn" id="btn_switch_camera" title="Switch camera">🔁</div>
      <div class="call-small-btn" id="btn_toggle_mic" title="Mute/unmute mic">🎙️</div>
      <div class="call-small-btn" id="btn_toggle_speaker" title="Speaker">🔊</div>
      <div class="call-small-btn" id="btn_hold" title="Hold">⏸️</div>
      <div class="call-small-btn" id="btn_add" title="Add participant">➕</div>
      <div class="call-btn hang" id="btn_hangup" title="End call">⛔</div>
    </div>
  </div>
</div>

<div id="profileModal" class="hidden fixed inset-0 items-center justify-center bg-black/40 z-[60]">
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
let pc = null;
let currentCallId = null;
let callIsVideo = false;
let localStream = null;
let remoteStream = null;
let currentCameraDeviceId = null;
let audioOutputDeviceId = null;
let callTimerInterval = null;
let callSeconds = 0;

function byId(id){ return document.getElementById(id); }
const attachMenu = byId('attachMenu');
const stickerPanel = byId('stickerPanel');
const stickerList = byId('stickerList');
const messagesEl = byId('messages');
const inputEl = byId('msg');
const composerEl = byId('composer');
const composerMain = byId('composerMain');

function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }

/* call UI helpers */
function showCallScreen(stateLabel){
  byId('callInfo').innerText = stateLabel || 'Calling...';
  byId('callScreen').style.display = 'flex';
}
function hideCallScreen(){
  byId('callScreen').style.display = 'none';
  // stop any local preview elements if needed (tracks stopped by hangup)
}

/* call timer */
function startCallTimer(){
  callSeconds = 0;
  byId('callInfo').dataset.timerRunning = '1';
  callTimerInterval = setInterval(()=>{
    callSeconds++;
    const h = Math.floor(callSeconds/3600).toString().padStart(2,'0');
    const m = Math.floor((callSeconds%3600)/60).toString().padStart(2,'0');
    const s = Math.floor(callSeconds%60).toString().padStart(2,'0');
    const str = (h>'00'? `${h}:${m}:${s}` : `${m}:${s}`);
    byId('callInfo').innerText = 'Connected — ' + str;
  }, 1000);
}
function stopCallTimer(){
  clearInterval(callTimerInterval); callTimerInterval = null;
  byId('callInfo').dataset.timerRunning = '0';
}

/* Video thumbnail helpers (unchanged) */
function createVideoThumbnailFromUrl(url, seekTo = 0.5){
  return new Promise((resolve)=>{
    try{
      const video = document.createElement('video');
      video.crossOrigin = 'anonymous';
      video.src = url;
      video.muted = true;
      video.playsInline = true;
      video.addEventListener('loadeddata', ()=>{
        const t = Math.min(seekTo, Math.max(0, (video.duration || 1)*0.2 ));
        function seekHandler(){
          const canvas = document.createElement('canvas');
          canvas.width = video.videoWidth || 320;
          canvas.height = video.videoHeight || 180;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
          const dataURL = canvas.toDataURL('image/png');
          video.remove();
          resolve(dataURL);
        }
        if(video.readyState >= 2){ video.currentTime = t; }
        else { video.addEventListener('canplay', ()=> video.currentTime = t, { once:true }); }
        video.addEventListener('seeked', seekHandler, { once:true });
        setTimeout(()=>{ try{ const canvas = document.createElement('canvas'); canvas.width=320; canvas.height=180; const ctx=canvas.getContext('2d'); ctx.fillStyle='#000'; ctx.fillRect(0,0,canvas.width,canvas.height); resolve(canvas.toDataURL()); }catch(e){ resolve(null);} }, 2500);
      }, { once:true });
      video.addEventListener('error', ()=> resolve(null));
    }catch(e){ resolve(null); }
  });
}
function createVideoThumbnailFromFile(file, seekTo=0.5){
  return new Promise((resolve)=>{
    const url = URL.createObjectURL(file);
    createVideoThumbnailFromUrl(url, seekTo).then((data)=>{
      URL.revokeObjectURL(url);
      resolve(data);
    }).catch(()=>{ URL.revokeObjectURL(url); resolve(null); });
  });
}

/* Attachment element factory (unchanged) */
function createAttachmentElement(a){
  const container = document.createElement('div');
  container.className = 'media-container mt-2';

  if(a.type === 'audio'){
    const au = document.createElement('audio'); au.src = a.url; au.controls = true; au.className = 'mt-2';
    container.appendChild(au);
    return { element: container };
  }
  if(a.type === 'doc'){
    const link = document.createElement('a');
    link.href = a.url; link.className = 'doc-link'; link.setAttribute('download', a.name || 'Document');
    link.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#111827" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h11"></path><polyline points="17 2 17 8 23 8"></polyline></svg><span style="font-size:0.92rem">${escapeHtml(a.name || 'Document')}</span>`;
    const dl = document.createElement('a'); dl.href = a.url; dl.className='download-btn'; dl.setAttribute('download', a.name || ''); dl.innerHTML = '⤓';
    container.appendChild(link);
    container.appendChild(dl);
    return { element: container };
  }

  if(a.type === 'image' || a.type === 'video'){
    const dl = document.createElement('a'); dl.href = a.url; dl.className='download-btn'; dl.setAttribute('download', a.name || ''); dl.innerHTML = '⤓';
    container.appendChild(dl);

    if(a.type === 'image'){
      const img = document.createElement('img'); img.src = a.url; img.className = 'image-attachment';
      container.appendChild(img);
      return { element: container, mediaElement: img };
    } else {
      const thumbImg = document.createElement('img'); thumbImg.className = 'thumb'; thumbImg.alt = a.name || 'video';
      const playOverlay = document.createElement('div'); playOverlay.className='play-overlay'; playOverlay.innerHTML = '<div class="play-circle">▶</div>';
      container.appendChild(thumbImg); container.appendChild(playOverlay);

      createVideoThumbnailFromUrl(a.url, 0.7).then(dataUrl=>{ if(dataUrl) thumbImg.src = dataUrl; else { const v = document.createElement('video'); v.src = a.url; v.controls = true; v.className='video-attachment'; container.innerHTML = ''; container.appendChild(dl); container.appendChild(v); } });

      container.addEventListener('click', ()=>{
        if(container.querySelector('video')) return;
        const v = document.createElement('video'); v.src = a.url; v.controls = true; v.autoplay = true; v.playsInline = true; v.className='video-attachment';
        const existingDl = container.querySelector('.download-btn');
        container.innerHTML = '';
        if(existingDl) container.appendChild(existingDl);
        container.appendChild(v);
      }, { once:true });

      return { element: container, mediaElement: thumbImg };
    }
  }
  return { element: null };
}

/* Poll & Render messages (unchanged) */
async function poll(){
  try{
    const resp = await fetch('/poll_messages?since=' + lastId);
    if(!resp.ok) return;
    const data = await resp.json();
    if(!data || !data.length) return;
    for(const m of data){
      const me = (m.sender === myName);
      const wrapper = document.createElement('div'); wrapper.className='msg-row';
      const body = document.createElement('div'); body.className='msg-body';

      const meta = document.createElement('div'); meta.className='msg-meta-top';
      const leftMeta = document.createElement('div'); leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong> · ${new Date(m.created_at*1000).toLocaleTimeString()}`;
      const rightMeta = document.createElement('div'); rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
      meta.appendChild(leftMeta); meta.appendChild(rightMeta);
      body.appendChild(meta);

      const hasText = m.text && m.text.trim().length>0;
      const attachments = (m.attachments || []);
      const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me':'them');

      if(hasText){
        const textNode = document.createElement('div');
        textNode.innerHTML = escapeHtml(m.text) + (m.edited ? ' <span style="font-size:.7rem;color:#9ca3af">(edited)</span>':'');
        bubble.appendChild(textNode);
      }

      if(attachments && attachments.length){
        for(const a of attachments){
          if(a.type === 'sticker'){
            const s = document.createElement('img'); s.src = a.url; s.className = 'sticker'; s.style.marginTop='8px';
            bubble.appendChild(s);
          } else {
            const { element, mediaElement } = createAttachmentElement(a);
            if(element) bubble.appendChild(element);
          }
        }
      }

      // reactions display under bubble
      if(m.reactions && m.reactions.length){
        const agg = {}; // emoji -> set(users)
        for(const r of m.reactions){
          agg[r.emoji] = agg[r.emoji] || new Set();
          agg[r.emoji].add(r.user);
        }
        const reactionBar = document.createElement('div'); reactionBar.className = 'reaction-bar';
        for(const emoji in agg){
          const userset = agg[emoji];
          const pill = document.createElement('div'); pill.className = 'reaction-pill';
          const em = document.createElement('div'); em.className='reaction-emoji'; em.innerText = emoji;
          const count = document.createElement('div'); count.style.fontSize='0.85rem'; count.style.color='#374151'; count.innerText = userset.size;
          pill.appendChild(em); pill.appendChild(count);
          reactionBar.appendChild(pill);
        }
        bubble.appendChild(reactionBar);
      }

      const menuBtn = document.createElement('button'); menuBtn.className='three-dot'; menuBtn.innerText='⋯';
      menuBtn.onclick = (ev)=>{
        ev.stopPropagation();
        document.querySelectorAll('.menu:not(#profileMenu)').forEach(n=>n.remove());
        const menu = document.createElement('div'); menu.className='menu';
        const edit = document.createElement('div'); edit.innerText='Edit';
        edit.onclick = async (e)=>{ e.stopPropagation(); const newText = prompt('Edit message text', m.text || ''); if(newText!==null){ await fetch('/edit_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id,text:newText})}); messagesEl.innerHTML=''; lastId=0; poll(); } };
        const del = document.createElement('div'); del.innerText='Delete'; del.onclick = async (e)=>{ e.stopPropagation(); if(confirm('Delete this message?')){ await fetch('/delete_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id})}); messagesEl.innerHTML=''; lastId=0; poll(); } };
        const react = document.createElement('div'); react.innerText='React ❤️'; react.onclick = (ev2)=>{ ev2.stopPropagation(); showEmojiPickerForMessage(m.id, menu); };

        const hasAudio = (attachments || []).some(x=>x.type==='audio');
        const hasOther = (attachments || []).some(x=>x.type==='image' || x.type==='video' || x.type==='doc');
        if(m.sender === myName) menu.appendChild(edit);
        if(hasAudio){
          const dlAudio = document.createElement('div'); dlAudio.innerText='Download audio'; dlAudio.onclick = (ev2)=>{ ev2.stopPropagation(); const audio = attachments.find(x=>x.type==='audio'); if(audio){ const a = document.createElement('a'); a.href = audio.url; a.setAttribute('download', audio.name || 'audio'); document.body.appendChild(a); a.click(); a.remove(); } menu.remove(); };
          menu.appendChild(dlAudio);
        }
        if(hasOther){
          const dlAll = document.createElement('div'); dlAll.innerText = 'Download file'; dlAll.onclick = (ev2)=>{ ev2.stopPropagation(); const f = attachments.find(x=>x.type!=='sticker' && x.type!=='audio'); if(f){ const a = document.createElement('a'); a.href = f.url; a.setAttribute('download', f.name || 'file'); document.body.appendChild(a); a.click(); a.remove(); } menu.remove(); };
          menu.appendChild(dlAll);
        }

        menu.appendChild(react);
        menu.appendChild(del);

        document.body.appendChild(menu);
        // place menu & keep inside viewport
        const rect = menuBtn.getBoundingClientRect();
        let top = rect.bottom + 8;
        let left = rect.left;
        // clamp right edge
        const maxRight = window.innerWidth - 8;
        const menuWidth = 220;
        if(left + menuWidth > maxRight) left = Math.max(8, maxRight - menuWidth);
        // clamp bottom
        const maxBottom = window.innerHeight - 8;
        if(top + 200 > maxBottom) top = rect.top - 8 - 160;
        menu.style.position = 'fixed';
        menu.style.top = (top) + 'px';
        menu.style.left = (left) + 'px';

        // hide on scroll
        const hideOnScroll = ()=>{
          if(menu && menu.parentElement) menu.remove();
          window.removeEventListener('scroll', hideOnScroll);
        };
        window.addEventListener('scroll', hideOnScroll, { once:true });

      };

      bubble.appendChild(menuBtn);
      body.appendChild(bubble);
      wrapper.appendChild(body);
      messagesEl.appendChild(wrapper);
      lastId = m.id;
    }
    messagesEl.scrollTop = messagesEl.scrollHeight;
  }catch(e){ console.error('poll error', e); }
}
poll(); setInterval(poll, 2000);

/* reaction emoji picker (small) */
function showEmojiPickerForMessage(msgId, anchorEl){
  // Create small picker
  const picker = document.createElement('div'); picker.className='menu';
  const emojis = ['😀','😁','😂','😍','😮','😢','😡','👍','👎','🎉','🔥','❤️','👏','🤝','🤯'];
  emojis.forEach(em=>{
    const el = document.createElement('div'); el.style.display='inline-flex'; el.style.padding='6px'; el.style.margin='4px'; el.style.cursor='pointer';
    el.innerText = em;
    el.onclick = async (ev)=>{ ev.stopPropagation(); await fetch('/react_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id: msgId, emoji: em }) }); picker.remove(); messagesEl.innerHTML=''; lastId=0; poll(); };
    picker.appendChild(el);
  });
  document.body.appendChild(picker);
  const rect = anchorEl.getBoundingClientRect();
  let top = rect.bottom + 8;
  let left = rect.left;
  if(left + 240 > window.innerWidth) left = Math.max(8, window.innerWidth - 248);
  picker.style.position='fixed'; picker.style.top = top + 'px'; picker.style.left = left + 'px';
  // auto-hide
  const hide = ()=>{ picker.remove(); document.removeEventListener('click', hide); };
  setTimeout(()=> document.addEventListener('click', hide), 50);
}

/* Send with optimistic UI & thumbnail generation (unchanged) */
byId('sendBtn').addEventListener('click', async ()=>{
  const text = (inputEl.value || '').trim();
  if(!text && stagedFiles.length===0) return;
  const tempId = 'temp-'+Date.now();
  const wrapper = document.createElement('div'); wrapper.className='msg-row';
  const body = document.createElement('div'); body.className='msg-body';
  const bubble = document.createElement('div'); bubble.className='bubble me'; bubble.dataset.tempId = tempId;
  if(text) bubble.appendChild(document.createTextNode(text));
  const objectUrls = [];
  const overlays = [];
  for(const file of stagedFiles){
    if(file.type.startsWith('image/')){
      const img = document.createElement('img'); const url = URL.createObjectURL(file); objectUrls.push(url); img.src = url; img.className='image-attachment'; bubble.appendChild(img);
    } else if(file.type.startsWith('video/')){
      const container = document.createElement('div'); container.style.position='relative'; container.style.display='inline-block';
      const placeholder = document.createElement('img'); placeholder.className='thumb'; placeholder.alt = file.name;
      const overlay = document.createElement('div'); overlay.className='uploading-overlay'; overlay.innerHTML='<div class="spinner"></div>';
      container.appendChild(placeholder); container.appendChild(overlay);
      bubble.appendChild(container);
      createVideoThumbnailFromFile(file, 0.7).then(dataUrl=>{ if(dataUrl) placeholder.src = dataUrl; else placeholder.src=''; });
      overlays.push(overlay);
    } else if(file.type.startsWith('audio/')){
      const au = document.createElement('audio'); const url=URL.createObjectURL(file); objectUrls.push(url); au.src = url; au.controls=true; bubble.appendChild(au);
    } else {
      const d = document.createElement('div'); d.className='preview-item-doc'; d.textContent = file.name; bubble.appendChild(d);
    }
  }
  body.appendChild(bubble); wrapper.appendChild(body); messagesEl.appendChild(wrapper); messagesEl.scrollTop = messagesEl.scrollHeight;

  const fd = new FormData(); fd.append('text', text);
  stagedFiles.forEach(f=> fd.append('file', f, f.name));
  try{
    const r = await fetch('/send_composite_message', { method:'POST', body: fd });
    if(r.ok){
      const el = document.querySelector('[data-temp-id="'+tempId+'"]'); if(el) el.parentElement.removeChild(el);
      inputEl.value=''; stagedFiles=[]; document.getElementById('attachmentPreview').innerHTML=''; document.getElementById('attachmentPreview').style.display='none';
      await poll();
    } else {
      const txt = await r.text(); alert('Send failed: '+txt);
      overlays.forEach(o=> o.innerHTML='!');
    }
  }catch(e){ alert('Send error: '+e.message); overlays.forEach(o=> o.innerHTML='!'); }
  finally{ objectUrls.forEach(u=> URL.revokeObjectURL(u)); }
});
inputEl.addEventListener('keydown', function(e){ if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); byId('sendBtn').click(); } });

/* Attachment preview (unchanged) */
function setAttachmentPreview(files){
  stagedFiles = Array.from(files || []);
  const preview = byId('attachmentPreview'); preview.innerHTML=''; preview.style.display = stagedFiles.length ? 'block' : 'none';
  stagedFiles.forEach((file, idx)=>{
    const item = document.createElement('div'); item.className='preview-item';
    const removeBtn = document.createElement('button'); removeBtn.className='preview-remove-btn'; removeBtn.innerText='×';
    removeBtn.onclick = (e)=>{ e.stopPropagation(); stagedFiles.splice(idx,1); setAttachmentPreview(stagedFiles); };
    item.appendChild(removeBtn);
    if(file.type.startsWith('image/')){
      const img = document.createElement('img');
      const reader = new FileReader();
      reader.onload = (ev)=> img.src = ev.target.result;
      reader.readAsDataURL(file);
      item.appendChild(img);
    } else if(file.type.startsWith('video/')){
      const img = document.createElement('img'); img.className='thumb'; item.appendChild(img);
      createVideoThumbnailFromFile(file).then(dataUrl=>{ if(dataUrl) img.src = dataUrl; });
    } else if(file.type.startsWith('audio/')){
      const a = document.createElement('audio'); a.controls = true;
      const url = URL.createObjectURL(file); a.src = url;
      item.appendChild(a);
    } else {
      const d = document.createElement('div'); d.className='preview-item-doc'; d.textContent = file.name; item.appendChild(d);
    }
    preview.appendChild(item);
  });
}
function clearAttachmentPreview(){ stagedFiles = []; const p = byId('attachmentPreview'); p.innerHTML=''; p.style.display='none'; }
function handleFileSelection(ev){ const files = ev.target.files; if(files && files.length) setAttachmentPreview(files); attachMenu.style.display='none'; ev.target.value = ''; }

byId('fileAttach').addEventListener('change', handleFileSelection);
byId('cameraAttach').addEventListener('change', handleFileSelection);
byId('docAttach').addEventListener('change', handleFileSelection);
byId('plusBtn').addEventListener('click', (ev)=>{ ev.stopPropagation(); attachMenu.style.display = (attachMenu.style.display === 'flex' ? 'none' : 'flex'); });

/* sticker picker (panel) */
byId('stickerPickerBtn').addEventListener('click', async (ev)=>{
  ev.stopPropagation(); attachMenu.style.display='none';
  // load stickers & generated avatars
  const arr1 = await (await fetch('/stickers_list')).json().catch(()=>[]);
  const arr2 = await (await fetch('/generated_stickers')).json().catch(()=>[]);
  const merged = (arr2 || []).concat(arr1 || []);
  showStickerPanel(merged);
});

function showStickerPanel(list){
  stickerList.innerHTML = '';
  list.forEach(url=>{
    const wrapper = document.createElement('div'); wrapper.style.cursor='pointer';
    const img = document.createElement('img'); img.src = url; img.style.width='100%'; img.style.borderRadius='8px';
    wrapper.appendChild(img);
    wrapper.onclick = async ()=>{
      await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] }) });
      hideStickerPanel();
      messagesEl.innerHTML=''; lastId=0; poll();
    };
    stickerList.appendChild(wrapper);
  });
  stickerPanel.style.display='flex';
  // shift composer up by panel height
  composerEl.style.transform = 'translateY(-40vh)';
}

function hideStickerPanel(){
  stickerPanel.style.display='none';
  composerEl.style.transform = 'translateY(0)';
}
byId('closeStickerPanel').addEventListener('click', hideStickerPanel);

/* mic (voice) - unchanged */
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
        const blob = new Blob(mediaChunks, { type:'audio/webm' });
        const file = new File([blob], 'voice_message.webm', { type:'audio/webm' });
        setAttachmentPreview([file]); stream.getTracks().forEach(t=>t.stop());
      };
      mediaRecorder.start();
      micRecording = true; micBtn.classList.add('mic-active'); inputEl.placeholder='Listening... Stop to preview.';
    }catch(e){ alert('Mic error: '+e.message); }
  } else {
    if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
    micRecording = false; micBtn.classList.remove('mic-active'); inputEl.placeholder='Type a message...';
  }
});

/* profile & other UI (unchanged) */
byId('profileBtn').addEventListener('click', (e)=>{ e.stopPropagation(); const menu = byId('profileMenu'); menu.style.display = menu.style.display === 'block' ? 'none' : 'block'; });
byId('viewProfileBtn').addEventListener('click', async ()=>{
  byId('profileMenu').style.display='none';
  const modal = byId('profileModal'); modal.classList.remove('hidden'); modal.classList.add('flex'); 
  const r = await fetch('/profile_get');
  if(r.ok){ const j = await r.json(); byId('profile_display_name').value = j.name || ''; byId('profile_status').value = j.status || ''; }
});
function closeProfileModal(){ const modal = byId('profileModal'); modal.classList.add('hidden'); modal.classList.remove('flex'); }
byId('closeProfile').addEventListener('click', closeProfileModal);
byId('profileCancel').addEventListener('click', closeProfileModal);
byId('profileForm').addEventListener('submit', async (e)=>{ e.preventDefault(); const fd = new FormData(e.target); const r = await fetch('/profile_update',{ method:'POST', body:fd }); const t = await r.text(); if(!r.ok){ byId('profileMsg').textContent = t; return; } byId('profileMsg').textContent='Saved'; setTimeout(()=> location.reload(), 400); });

/* call flow + improved WebRTC features (mute/cam/switch/speaker/hold) */
let currentInvite = null;
socket.on('connect', ()=> socket.emit('identify',{ name: myName }));

socket.on('incoming_call', (data)=>{
  currentInvite = data.call_id;
  byId('incomingText').textContent = `${data.from} is calling (${data.isVideo ? 'video':'audio'})`;
  byId('incomingCall').style.display='block';
  // store for accept path
  window._incoming_call_info = data;
});

socket.on('call_accepted', async (data)=>{
  // Caller gets notified that callee accepted; we start the WebRTC flow as caller
  const info = data;
  // Caller will already have created offer; server will forward answer via webrtc_answer event which is already handled.
  // Show UI & wait for answer
  showCallScreen('Connecting...');
});

socket.on('call_declined', (data)=>{
  alert('Call declined');
  // cleanup if we started UI
  hangupCallLocal(false);
});

socket.on('call_ended', (data)=>{
  // cleanup
  stopCallTimer();
  hangupCallLocal(false);
  alert('Call ended');
});

// WebRTC signaling events (offer/answer/ice)
socket.on('webrtc_offer', async (data)=>{
  // Received an offer from remote. As callee: create PC, add local tracks, set remote desc and answer.
  try{
    const from = data.from;
    const sdp = data.sdp;
    // create pc and local stream
    await setupLocalPeer(false, data.call_id, from);
    if(!pc) return;
    await pc.setRemoteDescription(new RTCSessionDescription(sdp));
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    socket.emit('webrtc_answer', { to: from, sdp: pc.localDescription, call_id: data.call_id });
    // show call screen connected when tracks settle
    showCallScreen('Connecting...');
  }catch(e){
    console.error('offer handling err', e);
  }
});

socket.on('webrtc_answer', async (data)=>{
  if(!pc) return;
  try{
    await pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
    // connected; UI will update when tracks arrive
  }catch(e){ console.error('answer err', e); }
});

socket.on('ice_candidate', async (data)=>{
  if(!pc) return;
  try{ await pc.addIceCandidate(data.candidate); } catch(e){ console.warn('ice add err', e); }
});

// call_control (relay) - reflect remote UI state
socket.on('call_control', (data)=>{
  // data: { type: 'mute'|'unmute'|'hold'|'unhold'|'video_on'|'video_off', from, call_id }
  if(!data) return;
  // for now we only show small info in callInfo
  if(data.type === 'mute') byId('callInfo').innerText = 'Other user muted';
  else if(data.type === 'unmute') byId('callInfo').innerText = 'Other user unmuted';
  else if(data.type === 'hold') byId('callInfo').innerText = 'Other user put call on hold';
  else if(data.type === 'unhold') byId('callInfo').innerText = 'Other user resumed call';
  else if(data.type === 'video_off') byId('callInfo').innerText = 'Other user turned video off';
  else if(data.type === 'video_on') byId('callInfo').innerText = 'Other user turned video on';
  setTimeout(()=>{ if(byId('callInfo').dataset.timerRunning === '1') startCallTimer(); }, 900);
});

// initiate outgoing call (click handlers)
byId('callAudio').addEventListener('click', ()=> initiateCall(false));
byId('callVideo').addEventListener('click', ()=> initiateCall(true));
async function initiateCall(isVideo){
  const resp = await fetch('/partner_info'); const p = await resp.json();
  if(!p || !p.name) return alert('No partner yet');
  // show calling UI immediately
  callIsVideo = isVideo;
  showCallScreen('Calling...');
  // start local peer as caller
  const call_id = Math.random().toString(36).slice(2,12);
  currentCallId = call_id;
  // create PC, local stream, then createOffer and send via socket
  await setupLocalPeer(true, call_id, p.name);
}

async function setupLocalPeer(isCaller, call_id, otherName){
  // create peer connection and local stream; if isCaller createOffer and emit
  // prepare pc
  pc = new RTCPeerConnection({ iceServers: [{ urls: 'stun:stun.l.google.com:19302' }] });
  remoteStream = new MediaStream();
  const remoteVideo = byId('remoteVideo');
  remoteVideo.srcObject = remoteStream;

  pc.ontrack = (ev)=>{
    // attach remote tracks
    ev.streams[0].getTracks().forEach(t=> remoteStream.addTrack(t));
    remoteVideo.srcObject = remoteStream;
    // when remote track arrives, update UI
    byId('callInfo').innerText = 'Connected';
    startCallTimer();
  };

  pc.onicecandidate = (ev)=>{
    if(ev.candidate){
      socket.emit('ice_candidate', { to: otherName, candidate: ev.candidate });
    }
  };

  // get local stream (audio, video if requested)
  try{
    const constraints = { audio:true, video: callIsVideo ? { facingMode: "user" } : false };
    localStream = await navigator.mediaDevices.getUserMedia(constraints);
    // set local preview
    const localVid = byId('localVideo');
    localVid.srcObject = localStream;
    // keep current camera id
    const videoTrack = localStream.getVideoTracks()[0];
    currentCameraDeviceId = videoTrack && videoTrack.getSettings ? videoTrack.getSettings().deviceId : currentCameraDeviceId;
    // add tracks to pc
    localStream.getTracks().forEach(track => pc.addTrack(track, localStream));
  }catch(e){
    console.error('media get err', e);
    alert('Could not access camera/microphone: ' + e.message);
    // if can't get media and caller, cancel call
    return;
  }

  // if caller -> create offer
  if(isCaller){
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    socket.emit('call_outgoing', { to: otherName, isVideo: callIsVideo, from: myName });
    // send the SDP via signaling
    socket.emit('webrtc_offer', { to: otherName, sdp: pc.localDescription, from: myName, call_id });
  }

  // attach control handlers
  attachCallControlHandlers();
  return pc;
}

/* Accept incoming call: on Accept click we emit call_accept and wait for offer/answer flow to continue.
   On incoming we already display incomingCall; the actual offer will be delivered as webrtc_offer event.
*/
byId('acceptCall').addEventListener('click', async ()=>{
  if(!window._incoming_call_info) return;
  const info = window._incoming_call_info;
  byId('incomingCall').style.display = 'none';
  // accept via server (this will trigger call_accepted to caller)
  socket.emit('call_accept', { call_id: info.call_id });
  // show call screen and get ready for offer -> webrtc_offer handler will create answer
  showCallScreen('Connecting...');
});

byId('declineCall').addEventListener('click', ()=>{
  if(window._incoming_call_info) socket.emit('call_decline', { call_id: window._incoming_call_info.call_id });
  byId('incomingCall').style.display = 'none';
  window._incoming_call_info = null;
});

// hang up (end call)
byId('btn_hangup').addEventListener('click', ()=>{ hangupCall(); });
function hangupCall(){
  if(currentCallId){
    socket.emit('call_end', { call_id: currentCallId });
  }
  hangupCallLocal(true);
}
function hangupCallLocal(shouldHideUI){
  try{
    if(pc){ pc.getSenders().forEach(s=>{ try{ s.track && s.track.stop(); }catch(e){} }); pc.close(); pc = null; }
    if(localStream){ localStream.getTracks().forEach(t=> t.stop()); localStream = null; }
    remoteStream = null;
    currentCallId = null;
    stopCallTimer();
  }catch(e){ console.error('hangup err', e); }
  if(shouldHideUI) hideCallScreen();
}

/* Call control buttons */
function attachCallControlHandlers(){
  // helper to emit call_control
  function emitControl(type){
    if(!currentCallId) return;
    socket.emit('call_control', { type, from: myName, call_id: currentCallId });
  }

  // toggle mic
  byId('btn_toggle_mic').onclick = ()=>{
    if(!localStream) return;
    const audioTracks = localStream.getAudioTracks();
    if(!audioTracks || !audioTracks.length) return;
    const t = audioTracks[0];
    t.enabled = !t.enabled;
    byId('btn_toggle_mic').innerText = t.enabled ? '🎙️':'🔇';
    emitControl(t.enabled ? 'unmute':'mute');
  };

  // toggle camera on/off
  byId('btn_toggle_camera').onclick = ()=>{
    if(!localStream) return;
    const vTracks = localStream.getVideoTracks();
    if(!vTracks || !vTracks.length) return;
    const vt = vTracks[0];
    vt.enabled = !vt.enabled;
    byId('btn_toggle_camera').innerText = vt.enabled ? '🎥':'🚫';
    emitControl(vt.enabled ? 'video_on':'video_off');
  };

  // switch camera (if multiple)
  byId('btn_switch_camera').onclick = async ()=>{
    try{
      const devices = await navigator.mediaDevices.enumerateDevices();
      const videoDevices = devices.filter(d=> d.kind === 'videoinput');
      if(videoDevices.length < 2) return alert('No second camera found');
      // pick next device id
      let nextIndex = 0;
      if(currentCameraDeviceId){
        const idx = videoDevices.findIndex(d=> d.deviceId === currentCameraDeviceId);
        nextIndex = (idx + 1) % videoDevices.length;
      }
      const targetDeviceId = videoDevices[nextIndex].deviceId;
      // replace track
      const newStream = await navigator.mediaDevices.getUserMedia({ video: { deviceId: { exact: targetDeviceId } }, audio: false });
      const newTrack = newStream.getVideoTracks()[0];
      const senders = pc.getSenders();
      const videoSender = senders.find(s=> s.track && s.track.kind === 'video');
      if(videoSender){
        await videoSender.replaceTrack(newTrack);
      } else {
        pc.addTrack(newTrack, newStream);
      }
      // stop old track
      const oldTracks = (localStream && localStream.getVideoTracks()) || [];
      oldTracks.forEach(t=> t.stop());
      // update localStream to include new track
      localStream.removeTrack(oldTracks[0]);
      localStream.addTrack(newTrack);
      byId('localVideo').srcObject = null;
      byId('localVideo').srcObject = localStream;
      currentCameraDeviceId = targetDeviceId;
      emitControl('camera_switched');
    }catch(e){ console.error('switch camera err', e); alert('Switch camera failed: ' + e.message); }
  };

  // toggle speaker (if setSinkId available)
  byId('btn_toggle_speaker').onclick = async ()=>{
    const remoteAudio = document.getElementById('remoteVideo'); // video element may contain audio
    if(!remoteAudio) return;
    // check setSinkId support
    if(typeof remoteAudio.setSinkId !== 'function') {
      alert('Speaker selection not available in this browser.');
      return;
    }
    try{
      // toggle between default and 'speaker' (best effort). We try to pick the first output device that is not default
      const devices = await navigator.mediaDevices.enumerateDevices();
      const outputs = devices.filter(d=> d.kind === 'audiooutput');
      if(!outputs.length) return alert('No audio outputs available');
      // find the next output
      let next = outputs[0].deviceId;
      if(audioOutputDeviceId){
        const idx = outputs.findIndex(d=> d.deviceId === audioOutputDeviceId);
        next = outputs[(idx+1) % outputs.length].deviceId;
      }
      await remoteAudio.setSinkId(next);
      audioOutputDeviceId = next;
      byId('btn_toggle_speaker').innerText = '🔊';
      emitControl('speaker_changed');
    }catch(e){ console.error('setSinkId err', e); alert('Cannot change audio output: ' + e.message); }
  };

  // hold / unhold
  byId('btn_hold').onclick = ()=>{
    if(!localStream) return;
    const tracks = localStream.getTracks();
    const isHeld = tracks[0] && tracks[0].enabled === false;
    tracks.forEach(t=> t.enabled = isHeld ? true : false);
    byId('btn_hold').innerText = isHeld ? '⏸️' : '▶️';
    emitControl(isHeld ? 'unhold':'hold');
  };

  // add participant (placeholder)
  byId('btn_add').onclick = ()=>{
    alert('Add participant / group calls require extra server-side signaling. This demo currently supports 1:1 calls. Implementing group calls requires multi-peer signaling.');
  };
}

/* Accept path: when callee sees incoming and the server sends webrtc_offer, the code above will handle offer & answer */

/* hangup UI already wired */

/* utility: send call control from other actions (exposed) */
function sendCallControl(type){
  if(!currentCallId) return;
  socket.emit('call_control', { type, from: myName, call_id: currentCallId });
}

/* close global menus on outside click */
document.addEventListener('click', (ev)=>{
  const isClickInside = el=> el && el.contains(ev.target);
  if(isClickInside(attachMenu) || isClickInside(byId('plusBtn'))) return;
  if(isClickInside(byId('profileMenu')) || isClickInside(byId('profileBtn'))) return;
  attachMenu.style.display='none'; byId('profileMenu').style.display='none';
  if(stickerPanel && stickerPanel.style.display === 'flex'){
    const wrap = stickerPanel.querySelector('.panel-inner'); if(!wrap.contains(ev.target)){ hideStickerPanel(); }
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
        # registration requires knowing master's passkey (shared)
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
    # check either user's own hash OR owner hash (owner can login to override)
    if verify_pass(passkey, user['pass_salt'], user['pass_hash']):
        session['username'] = name; touch_user_presence(name)
        return jsonify({"status":"ok","username":name})
    owner = get_owner()
    if owner and verify_pass(passkey, owner['pass_salt'], owner['pass_hash']):
        session['username'] = name; touch_user_presence(name); return jsonify({"status":"ok","username":name})
    return "invalid passkey", 403

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

# New: call control relay (mute/unmute/hold/other UI states)
@socketio.on('call_control')
def on_call_control(data):
    # data should include: type, from, call_id, optional payload
    to = None
    call_id = data.get('call_id')
    if not call_id:
        return
    info = CALL_INVITES.get(call_id)
    if not info:
        # if not found, try to find by caller/callee
        # naive scan
        for cid, val in CALL_INVITES.items():
            if cid == call_id:
                info = val; break
    if not info:
        return
    # choose recipient: if sender == caller then recipient is callee, else caller
    sender = data.get('from')
    if sender == info.get('caller'):
        to = info.get('callee')
    else:
        to = info.get('caller')
    sid = USER_SID.get(to)
    if sid:
        emit('call_control', data, room=sid)

# ----- run -----
if __name__ == "__main__":
    print("DB:", DB_PATH)
    socketio.run(app, host="0.0.0.0", port=PORT, debug=True)
