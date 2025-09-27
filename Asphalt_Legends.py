# Asphalt_Legends.py
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
    redirect, url_for, send_from_directory
)
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room

# === CONFIG ===
app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
HEADING_IMG = "/static/heading.png"

# Ensure static directories
os.makedirs(os.path.join(app.static_folder, "uploads"), exist_ok=True)
os.makedirs(os.path.join(app.static_folder, "stickers"), exist_ok=True)

# Enable SocketIO (uses eventlet/gevent in production; add to requirements)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")

# ---------- DB helpers ----------
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
            deleted INTEGER DEFAULT 0,
            delivered INTEGER DEFAULT 0,
            created_at INTEGER
        );
    """)
    conn.commit()
    conn.close()

init_db()

def db_conn():
    return sqlite3.connect(DB_PATH)

def save_user(name, salt_bytes, hash_bytes, avatar=None, status="", make_owner=False, make_partner=False):
    conn = db_conn()
    c = conn.cursor()
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
    conn.commit()
    conn.close()

def update_profile(name, new_name=None, avatar=None, status=None):
    conn = db_conn()
    c = conn.cursor()
    if new_name and new_name != name:
        # change name, but keep unique constraint checks simple
        c.execute("UPDATE users SET name = ? WHERE name = ?", (new_name, name))
        # update sender names in messages so chat displays properly
        c.execute("UPDATE messages SET sender = ? WHERE sender = ?", (new_name, name))
        name = new_name
    if avatar is not None:
        c.execute("UPDATE users SET avatar = ? WHERE name = ?", (avatar, name))
    if status is not None:
        c.execute("UPDATE users SET status = ? WHERE name = ?", (status, name))
    conn.commit()
    conn.close()
    return name

def set_partner_by_name(name):
    conn = db_conn()
    c = conn.cursor()
    c.execute("UPDATE users SET is_partner = 1 WHERE name = ?", (name,))
    conn.commit()
    conn.close()

def get_owner():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE is_owner = 1 LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "pass_salt": row[2], "pass_hash": row[3], "avatar": row[4], "status": row[5], "is_owner": bool(row[6]), "is_partner": bool(row[7])}
    return None

def get_partner():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, name FROM users WHERE is_partner = 1 LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1]}
    return None

def load_user_by_name(name):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE name = ? LIMIT 1", (name,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "pass_salt": row[2], "pass_hash": row[3], "avatar": row[4], "status": row[5], "is_owner": bool(row[6]), "is_partner": bool(row[7])}
    return None

def load_first_user():
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users ORDER BY id LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"name": row[0], "pass_salt": row[1], "pass_hash": row[2], "avatar": row[3], "status": row[4], "is_owner": bool(row[5]), "is_partner": bool(row[6])}
    return None

def save_message(sender, text, attachments=None):
    conn = db_conn()
    c = conn.cursor()
    ts = int(time.time())
    att = json.dumps(attachments or [])
    c.execute("INSERT INTO messages (sender, text, attachments, created_at) VALUES (?, ?, ?, ?)", (sender, text, att, ts))
    conn.commit()
    conn.close()
    trim_messages_limit(80)

def fetch_messages(since_id=0, viewer=None):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT id, sender, text, attachments, reactions, edited, deleted, delivered, created_at FROM messages WHERE id > ? ORDER BY id ASC", (since_id,))
    rows = c.fetchall()
    out = []
    for r in rows:
        mid, sender, text, attachments_json, reactions_json, edited, deleted, delivered, created_at = r
        attachments = json.loads(attachments_json or "[]")
        reactions = json.loads(reactions_json or "[]")
        if viewer and sender != viewer and not delivered:
            c.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (mid,))
            delivered = 1
            conn.commit()
        out.append({"id": mid, "sender": sender, "text": text, "attachments": attachments, "reactions": reactions, "edited": bool(edited), "deleted": bool(deleted), "delivered": bool(delivered), "created_at": created_at})
    conn.close()
    return out

def trim_messages_limit(max_messages=80):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM messages")
    total = c.fetchone()[0]
    if total <= max_messages:
        conn.close()
        return
    to_delete = total - max_messages
    c.execute("DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY id ASC LIMIT ?)", (to_delete,))
    conn.commit()
    conn.close()

def edit_message_db(msg_id, new_text, editor):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT sender FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close()
        return False, "no message"
    sender = r[0]
    user = load_user_by_name(editor)
    if editor != sender and not (user and user.get("is_owner")):
        conn.close()
        return False, "not allowed"
    c.execute("UPDATE messages SET text = ?, edited = 1 WHERE id = ?", (new_text, msg_id))
    conn.commit()
    conn.close()
    return True, None

def delete_message_db(msg_id, requester):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT sender FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close()
        return False, "no message"
    sender = r[0]
    user = load_user_by_name(requester)
    if requester != sender and not (user and user.get("is_owner")):
        conn.close()
        return False, "not allowed"
    c.execute("UPDATE messages SET deleted = 1 WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()
    return True, None

def react_message_db(msg_id, reactor, emoji):
    conn = db_conn()
    c = conn.cursor()
    c.execute("SELECT reactions FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close()
        return False, "no message"
    reactions = json.loads(r[0] or "[]")
    found = False
    for rec in reactions:
        if rec.get("emoji") == emoji and rec.get("user") == reactor:
            reactions.remove(rec)
            found = True
            break
    if not found:
        reactions.append({"emoji": emoji, "user": reactor})
    c.execute("UPDATE messages SET reactions = ? WHERE id = ?", (json.dumps(reactions), msg_id))
    conn.commit()
    conn.close()
    return True, None

# ---------- passkey hashing ----------
PBKDF2_ITER = 200_000
SALT_BYTES = 16
HASH_LEN = 32

def hash_pass(passphrase: str, salt: bytes = None):
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PBKDF2_ITER, dklen=HASH_LEN)
    return salt, dk

def verify_pass(passphrase: str, salt: bytes, expected_hash: bytes) -> bool:
    if isinstance(salt, memoryview):
        salt = bytes(salt)
    if isinstance(expected_hash, memoryview):
        expected_hash = bytes(expected_hash)
    if salt is None or expected_hash is None:
        return False
    if isinstance(passphrase, str):
        passphrase = passphrase.encode("utf-8")
    dk = hashlib.pbkdf2_hmac("sha256", passphrase, salt, PBKDF2_ITER, dklen=len(expected_hash))
    return hmac.compare_digest(dk, expected_hash)

# ---------- presence & typing ----------
TYPING = {}
LAST_SEEN = {}

def touch_user_presence(username):
    if not username: return
    LAST_SEEN[username] = int(time.time())

# ---------- Socket.IO / Signalling state (in-memory) ----------
# maps username -> socket sid
USER_SID = {}
# active call sessions: caller->callee mapping stored
ACTIVE_CALLS = {}

# ---------- Templates ----------
# (I reuse and adapt the earlier templates; trimmed for focus)
INDEX_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Login</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; }
  header img { height:54px; width:auto; }
  .avatar-sm { width:40px; height:40px; border-radius:999px; object-fit:cover; }
</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 flex items-start justify-center p-4">
  <div class="w-full max-w-3xl">
    <header class="flex items-center justify-between gap-4 mb-6">
      <div class="flex items-center gap-3">
        <img src="{{ heading_img }}" alt="heading" />
        <div class="text-2xl font-extrabold">
          <span class="text-indigo-700">Asphalt</span>
          <span class="text-pink-600 ml-2">Legends</span>
        </div>
      </div>
      <div class="text-sm text-gray-500">Demo chat — shared passkey & real-time calls</div>
    </header>

    {% if session.get('username') %}
      {% set user = load_user(session.get('username')) %}
      <div class="mb-6 flex items-center justify-between bg-white p-4 rounded-lg shadow">
        <div class="flex items-center gap-3">
          {% if user and user.avatar %}
            <img src="{{ user.avatar }}" class="avatar-sm" />
          {% else %}
            <div class="avatar-sm bg-gray-200 flex items-center justify-center">P</div>
          {% endif %}
          <div>
            <div class="font-semibold">{{ session['username'] }}</div>
            <div class="text-xs text-gray-500">{{ user.status if user else '' }}</div>
          </div>
        </div>
        <div class="flex items-center gap-3">
          <button id="profileBtn" class="rounded-full bg-indigo-600 text-white w-10 h-10 flex items-center justify-center">P</button>
          <form method="post" action="{{ url_for('logout') }}"><button class="px-4 py-2 rounded bg-gray-200">Logout</button></form>
        </div>
      </div>
      <div class="p-4 bg-white rounded-lg shadow">
        <a href="{{ url_for('chat') }}" class="px-4 py-2 bg-indigo-600 text-white rounded">Open Chat</a>
      </div>
    {% else %}
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        {% if first_user_none %}
        <div class="p-4 border rounded-lg bg-white">
          <h3 class="font-semibold mb-3 text-indigo-700">Register (set shared passkey)</h3>
          <form id="regForm" class="space-y-3">
            <input id="reg_name" name="name" class="w-full p-3 border rounded-lg" placeholder="Your name" value="ProGamer ♾️" />
            <input id="reg_passkey" name="passkey" type="password" class="w-full p-3 border rounded-lg" placeholder="Choose shared master passkey" />
            <div class="flex items-center gap-3">
              <button type="submit" class="px-4 py-2 rounded-lg bg-green-600 text-white flex-1">Register</button>
              <button id="genBtn" type="button" class="px-3 py-2 rounded-lg bg-gray-100">Generate</button>
            </div>
            <div id="regStatus" class="text-sm mt-2 text-center text-red-500"></div>
            <div class="text-xs text-gray-500 mt-2">First registration becomes the master passkey.</div>
          </form>
        </div>
        {% endif %}

        <div class="p-4 border rounded-lg bg-white">
          <h3 class="font-semibold mb-3 text-indigo-700">Login</h3>
          <form id="loginForm" class="space-y-3">
            <input id="login_name" name="name" class="w-full p-3 border rounded-lg" placeholder="Your name" value="ProGamer ♾️" />
            <input id="login_passkey" name="passkey" type="password" class="w-full p-3 border rounded-lg" placeholder="Enter master passkey" />
            <div class="flex justify-center">
              <button type="submit" class="px-4 py-2 rounded-lg bg-indigo-600 text-white w-full">Login</button>
            </div>
            <div id="loginStatus" class="text-sm mt-2 text-center text-red-500"></div>
            <div class="text-xs text-gray-500 mt-2">Use the same passkey both people share to register/login.</div>
          </form>
        </div>
      </div>
    {% endif %}

    <footer class="text-center text-xs text-gray-400 mt-6">Responsive — phone, tablet & desktop</footer>
  </div>

<!-- Profile modal -->
<div id="profileModal" class="fixed inset-0 hidden items-center justify-center bg-black/40">
  <div class="bg-white rounded-lg p-4 w-96">
    <div class="flex items-center justify-between mb-3">
      <div>
        <div class="text-lg font-bold">Profile</div>
        <div id="profileName" class="text-sm text-gray-600"></div>
      </div>
      <button id="closeProfile" class="text-gray-500">✕</button>
    </div>
    <form id="profileForm" enctype="multipart/form-data">
      <div class="mb-2">
        <label class="text-xs">Display name</label>
        <input id="profile_display_name" name="name" class="w-full p-2 border rounded" />
      </div>
      <div class="mb-2">
        <label class="text-xs">Status</label>
        <input id="profile_status" name="status" class="w-full p-2 border rounded" />
      </div>
      <div class="mb-2">
        <label class="text-xs">Avatar</label>
        <input id="profile_avatar" name="avatar" type="file" accept="image/*" class="w-full" />
      </div>
      <div class="flex gap-2">
        <button type="submit" class="px-3 py-2 rounded bg-indigo-600 text-white">Save</button>
        <button id="profileCancel" type="button" class="px-3 py-2 rounded bg-gray-200">Cancel</button>
      </div>
      <div id="profileMsg" class="text-sm mt-2 text-gray-500"></div>
    </form>
  </div>
</div>

<!-- socket.io client -->
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<script>
function show(el, msg, err=false){
  const node = document.getElementById(el);
  if(!node) return;
  node.textContent = msg;
  node.style.color = err ? '#b91c1c' : '#16a34a';
}
document.getElementById('genBtn')?.addEventListener('click', ()=>{
  const s = Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => (b%36).toString(36)).join('');
  document.getElementById('reg_passkey').value = s;
  show('regStatus','Generated passkey — copy it and keep it safe.');
});
async function postJson(url, body){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const text = await r.text();
  try { return { ok: r.ok, status: r.status, json: JSON.parse(text), text }; } catch(e){ return { ok: r.ok, status: r.status, json: null, text }; }
}
document.getElementById('regForm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  show('regStatus','Registering...');
  const name = document.getElementById('reg_name').value || 'ProGamer ♾️';
  const passkey = document.getElementById('reg_passkey').value || '';
  try{
    const res = await postJson('/register', {name, passkey});
    if(!res.ok) throw new Error(res.text || 'register failed');
    show('regStatus','Registered & signed in — redirecting...');
    setTimeout(()=> location.href = '/chat', 600);
  }catch(err){
    console.error(err);
    show('regStatus','Register failed: '+(err.message || err), true);
  }
});
document.getElementById('loginForm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  show('loginStatus','Logging in...');
  const name = document.getElementById('login_name').value || 'ProGamer ♾️';
  const passkey = document.getElementById('login_passkey').value || '';
  try{
    const res = await postJson('/login', {name, passkey});
    if(!res.ok) throw new Error(res.text || 'login failed');
    show('loginStatus','Login successful — redirecting...');
    setTimeout(()=> location.href = '/chat', 400);
  }catch(err){
    console.error(err);
    show('loginStatus','Login failed: '+(err.message || err), true);
  }
});

// Profile modal handling
document.getElementById('profileBtn')?.addEventListener('click', async ()=>{
  const modal = document.getElementById('profileModal');
  modal.classList.remove('hidden'); modal.classList.add('flex');
  // prefill fields
  const res = await fetch('/profile_get');
  if(res.ok){
    const j = await res.json();
    document.getElementById('profile_display_name').value = j.name || '';
    document.getElementById('profile_status').value = j.status || '';
    document.getElementById('profileName').textContent = j.name || '';
  }
});
document.getElementById('closeProfile')?.addEventListener('click', ()=> { const m=document.getElementById('profileModal'); m.classList.add('hidden'); m.classList.remove('flex'); });
document.getElementById('profileCancel')?.addEventListener('click', ()=> { const m=document.getElementById('profileModal'); m.classList.add('hidden'); m.classList.remove('flex'); });

document.getElementById('profileForm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const r = await fetch('/profile_update', {method:'POST', body: fd});
  const t = await r.text();
  if(!r.ok){
    document.getElementById('profileMsg').textContent = t;
    return;
  }
  document.getElementById('profileMsg').textContent = 'Saved';
  setTimeout(()=> location.reload(), 600);
});
</script>
</body>
</html>
"""

# CHAT (similar to earlier chat with Socket.IO signalling)
CHAT_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;}
  header img{height:48px;}
  .avatar-sm { width:36px; height:36px; border-radius:999px; object-fit:cover; }
  .bubble { max-width: 75%; padding: 10px 12px; border-radius: 12px; display:inline-block; }
  .me { background: linear-gradient(90deg,#DCF8C6,#E6FFE6); border-bottom-right-radius: 2px;}
  .them { background: #fff; border-bottom-left-radius: 2px;}
  .meta { font-size: .75rem; color:#6b7280; }
  .fab { position: fixed; right: 20px; bottom: 20px; z-index: 50; }
  .attach-menu { position: fixed; right: 20px; bottom: 84px; z-index: 50; display:none; flex-direction:column; gap:8px; }
  .mic-btn { width:44px; height:44px; border-radius:999px; display:inline-flex; align-items:center; justify-content:center; }
  .call-panel { position: fixed; left: 50%; transform: translateX(-50%); top: 12px; background:white; padding:8px 12px; border-radius:12px; box-shadow:0 8px 24px rgba(0,0,0,.12); display:none; z-index:60; }
</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 p-4">
  <div class="w-full max-w-2xl mx-auto">
    <header class="flex items-center justify-between gap-4 mb-4">
      <div class="flex items-center gap-3">
        <img src="{{ heading_img }}" alt="heading"/>
        <div class="text-2xl font-extrabold">
          <span class="text-indigo-700">Asphalt</span>
          <span class="text-pink-600 ml-2">Legends</span>
        </div>
      </div>
      <div class="flex items-center gap-2">
        <button id="callAudio" class="px-3 py-1 rounded bg-gray-100">Audio Call</button>
        <button id="callVideo" class="px-3 py-1 rounded bg-gray-100">Video Call</button>
        <button id="profileBtn" class="rounded-full bg-indigo-600 text-white w-10 h-10 flex items-center justify-center">P</button>
        <form method="post" action="{{ url_for('logout') }}"><button class="px-3 py-1 rounded bg-gray-200">Logout</button></form>
      </div>
    </header>

    <div class="bg-white rounded-lg shadow p-4 mb-4">
      <div class="flex items-center justify-between mb-3">
        <div>
          <div class="text-lg font-semibold">{{ username }}</div>
          <div class="text-xs text-gray-500">{{ user_status }}</div>
        </div>
      </div>

      {% if is_owner and not partner_name %}
        <div class="text-sm text-gray-600 mb-3">Waiting for partner to join.</div>
      {% elif is_owner and partner_name %}
        <div class="text-sm text-gray-600 mb-3">Partner: <strong>{{ partner_name }}</strong></div>
      {% elif is_partner %}
        <div class="text-sm text-gray-600 mb-3">Chatting with owner: <strong>{{ owner_name }}</strong></div>
      {% endif %}

      {% if not is_member %}
        <div class="mb-3">
          <button id="joinBtn" class="px-4 py-2 rounded bg-indigo-600 text-white">Join Chat</button>
          <div id="joinStatus" class="text-sm mt-2 text-red-500"></div>
        </div>
      {% endif %}

      <div id="messages" class="h-80 overflow-auto border rounded p-3 bg-gray-50 mb-3"></div>

      <div class="flex items-center gap-2">
        <button id="plusBtn" class="px-3 py-2 rounded bg-gray-100">+</button>
        <div class="attach-menu" id="attachMenu">
          <label class="px-3 py-2 rounded bg-white border cursor-pointer">
            <input id="fileAttach" class="attach-input" type="file" accept="image/*" />
            📷 Photo
          </label>
          <label class="px-3 py-2 rounded bg-white border cursor-pointer">
            <input id="stickerAttach" class="attach-input" type="file" accept="image/*" />
            🖼️ Sticker
          </label>
        </div>

        <input id="msg" class="flex-1 p-2 border rounded" placeholder="Type a message..." />
        <button id="mic" class="mic-btn bg-gray-100" title="Hold to record">🎤</button>
        <button id="sendBtn" class="px-4 py-2 rounded bg-green-600 text-white">Send</button>
      </div>
    </div>
  </div>

  <!-- profile modal (re-used) -->
  <div id="profileModal" class="fixed inset-0 hidden items-center justify-center bg-black/40">
    <div class="bg-white rounded-lg p-4 w-96">
      <div class="flex items-center justify-between mb-3">
        <div>
          <div class="text-lg font-bold">Profile</div>
          <div id="profileName" class="text-sm text-gray-600">{{ username }}</div>
        </div>
        <button id="closeProfile" class="text-gray-500">✕</button>
      </div>
      <form id="profileForm" enctype="multipart/form-data">
        <div class="mb-2">
          <label class="text-xs">Display name</label>
          <input id="profile_display_name" name="name" class="w-full p-2 border rounded" value="{{ username }}" />
        </div>
        <div class="mb-2">
          <label class="text-xs">Status</label>
          <input id="profile_status" name="status" class="w-full p-2 border rounded" value="{{ user_status }}" />
        </div>
        <div class="mb-2">
          <label class="text-xs">Avatar</label>
          <input id="profile_avatar" name="avatar" type="file" accept="image/*" class="w-full" />
        </div>
        <div class="flex gap-2">
          <button type="submit" class="px-3 py-2 rounded bg-indigo-600 text-white">Save</button>
          <button id="profileCancel" type="button" class="px-3 py-2 rounded bg-gray-200">Cancel</button>
        </div>
        <div id="profileMsg" class="text-sm mt-2 text-gray-500"></div>
      </form>
    </div>
  </div>

  <!-- incoming call UI -->
  <div id="incomingCall" class="call-panel">
    <div id="incomingText">Incoming call</div>
    <div class="flex gap-2 mt-2">
      <button id="acceptCall" class="px-3 py-1 rounded bg-green-600 text-white">Accept</button>
      <button id="declineCall" class="px-3 py-1 rounded bg-red-500 text-white">Decline</button>
    </div>
  </div>

<!-- socket.io client -->
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>

<script>
const socket = io();
let myName = "{{ username }}";
let userAvatar = "{{ user_avatar }}";
let callPanel = document.getElementById('incomingCall');

// mapping for UI state
let currentCall = null; // {caller, callee, pc, stream, isVideo}
let pc = null;
const cfg = {iceServers: [{urls: "stun:stun.l.google.com:19302"}]};

// Utility & chat functions (similar to previous chat code)
function escapeHtml(s){ return String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtMessage(m, me){
  const when = new Date(m.created_at * 1000).toLocaleTimeString();
  const bubbleClass = me ? 'bubble me' : 'bubble them';
  let ticks = '';
  if(me){
    if(m.delivered) ticks = '✅✅'; else ticks = '✅';
  }
  let atts = '';
  if(m.attachments && m.attachments.length){
    for(const a of m.attachments){
      if(a.type === 'image'){
        atts += `<div class="mt-2"><img src="${escapeHtml(a.url)}" style="max-width:220px;border-radius:8px" /></div>`;
      }else if(a.type === 'audio'){
        atts += `<div class="mt-2"><audio controls src="${escapeHtml(a.url)}"></audio></div>`;
      } else if(a.type === 'sticker'){
        atts += `<div class="mt-2"><img src="${escapeHtml(a.url)}" class="sticker-img" /></div>`;
      }
    }
  }
  const text = m.deleted ? '<em>message deleted</em>' : escapeHtml(m.text) + (m.edited ? ' <span class="text-xs text-gray-400">edited</span>' : '');
  const reactions = (m.reactions || []).map(r=>`<span title="${escapeHtml(r.user)}">${escapeHtml(r.emoji)}</span>`).join(' ');
  const alignmentClass = me ? 'message-row message-right' : 'message-row';
  return `<div class="${alignmentClass}">
    <div${me? ' style="margin-left:auto"' : ''}>
      <div class="${bubbleClass}">${text}${atts}<div class="meta">${escapeHtml(m.sender)} · ${when} ${me? '<span class="tick">'+ticks+'</span>':''}</div>
      <div class="mt-1">${reactions}</div>
      <div class="mt-1"><button data-id="${m.id}" class="react-btn text-xs px-2 py-1 rounded bg-gray-100">❤️</button>
          <button data-id="${m.id}" class="edit-btn text-xs px-2 py-1 rounded bg-gray-100">Edit</button>
          <button data-id="${m.id}" class="del-btn text-xs px-2 py-1 rounded bg-gray-100">Delete</button></div>
      </div>
    </div>
  </div>`;
}

let lastId = 0;
async function poll(){
  try{
    const resp = await fetch('/poll_messages?since=' + lastId);
    if(!resp.ok) return;
    const data = await resp.json();
    if(data.length){
      const container = document.getElementById('messages');
      for(const m of data){
        const me = (m.sender === "{{ username }}");
        container.insertAdjacentHTML('beforeend', fmtMessage(m, me));
        lastId = m.id;
      }
      container.scrollTop = container.scrollHeight;
    }
  }catch(e){ console.error(e); }
}

document.addEventListener('DOMContentLoaded', ()=>{
  poll();
  setInterval(poll, 1400);

  document.getElementById('sendBtn').addEventListener('click', async ()=>{
    const el = document.getElementById('msg');
    const txt = el.value.trim();
    if(!txt) return;
    el.value = '';
    await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text: txt})});
    await poll();
  });

  // profile modal
  document.getElementById('profileBtn')?.addEventListener('click', async ()=>{
    const modal = document.getElementById('profileModal');
    modal.classList.remove('hidden'); modal.classList.add('flex');
  });
  document.getElementById('closeProfile')?.addEventListener('click', ()=> { const m=document.getElementById('profileModal'); m.classList.add('hidden'); m.classList.remove('flex'); });
  document.getElementById('profileCancel')?.addEventListener('click', ()=> { const m=document.getElementById('profileModal'); m.classList.add('hidden'); m.classList.remove('flex'); });
  document.getElementById('profileForm')?.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(e.target);
    const r = await fetch('/profile_update', {method:'POST', body: fd});
    const t = await r.text();
    if(!r.ok){
      document.getElementById('profileMsg').textContent = t;
      return;
    }
    document.getElementById('profileMsg').textContent = 'Saved';
    setTimeout(()=> location.reload(), 600);
  });

  // attach menu
  const plusBtn = document.getElementById('plusBtn');
  const attachMenu = document.getElementById('attachMenu');
  plusBtn.addEventListener('click', ()=> attachMenu.style.display = attachMenu.style.display === 'flex' ? 'none' : 'flex');

  document.getElementById('fileAttach').addEventListener('change', async (e)=>{
    const file = e.target.files[0];
    if(!file) return;
    const fd = new FormData();
    fd.append('file', file);
    const r = await fetch('/upload_file', {method:'POST', body: fd});
    const t = await r.json();
    if(r.ok){
      await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text:'', attachments: t.attachments})});
      await poll();
    } else alert(t.error || 'upload failed');
    e.target.value = '';
    attachMenu.style.display = 'none';
  });

  document.getElementById('stickerAttach').addEventListener('change', async (e)=>{
    const file = e.target.files[0];
    if(!file) return;
    const fd = new FormData();
    fd.append('file', file);
    const r = await fetch('/upload_sticker', {method:'POST', body: fd});
    const t = await r.json();
    if(r.ok){
      await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text:'', attachments: t.attachments})});
      await poll();
    } else alert(t.error || 'sticker upload failed');
    e.target.value = '';
    attachMenu.style.display = 'none';
  });

  // message actions
  document.getElementById('messages').addEventListener('click', async (e)=>{
    const id = e.target.getAttribute('data-id');
    if(!id) return;
    if(e.target.classList.contains('react-btn')){
      await fetch('/react_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: parseInt(id), emoji:'❤️'})});
      document.getElementById('messages').innerHTML=''; lastId=0; await poll();
    } else if(e.target.classList.contains('edit-btn')){
      const newText = prompt('Edit message:');
      if(newText !== null){
        await fetch('/edit_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: parseInt(id), text:newText})});
        document.getElementById('messages').innerHTML=''; lastId=0; await poll();
      }
    } else if(e.target.classList.contains('del-btn')){
      if(confirm('Delete message?')){
        await fetch('/delete_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: parseInt(id)})});
        document.getElementById('messages').innerHTML=''; lastId=0; await poll();
      }
    }
  });

  // mic press-to-record
  const micBtn = document.getElementById('mic');
  let mediaRecorder, chunks=[];
  micBtn.addEventListener('pointerdown', async ()=>{
    if(!navigator.mediaDevices) return alert('No media support');
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(stream);
    chunks = [];
    mediaRecorder.ondataavailable = e => chunks.push(e.data);
    mediaRecorder.onstop = async ()=>{
      const blob = new Blob(chunks, {type:'audio/webm'});
      const fd = new FormData();
      fd.append('file', blob, 'voice.webm');
      const r = await fetch('/upload_audio', {method:'POST', body: fd});
      const t = await r.json();
      if(r.ok){
        await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text:'', attachments: t.attachments})});
        await poll();
      } else alert(t.error||'upload failed');
      stream.getTracks().forEach(s=>s.stop());
    };
    mediaRecorder.start();
  });
  micBtn.addEventListener('pointerup', ()=>{
    if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
  });

  // CALLS - Socket.IO signalling
  socket.on('connect', ()=> {
    socket.emit('identify', {name: myName});
  });

  socket.on('incoming_call', (data)=>{
    // show incoming UI
    currentCall = {caller: data.from, isVideo: data.isVideo};
    document.getElementById('incomingText').textContent = `${data.from} is calling (${data.isVideo ? 'video' : 'audio'})`;
    callPanel.style.display = 'block';
  });

  document.getElementById('acceptCall').addEventListener('click', async ()=>{
    if(!currentCall) return;
    callPanel.style.display = 'none';
    await startPeer(true, currentCall.caller, currentCall.isVideo, true);
  });
  document.getElementById('declineCall').addEventListener('click', ()=>{
    if(currentCall) socket.emit('call_decline', {to: currentCall.caller});
    currentCall = null;
    callPanel.style.display = 'none';
  });

  document.getElementById('callAudio').addEventListener('click', ()=> initiateCall(false));
  document.getElementById('callVideo').addEventListener('click', ()=> initiateCall(true));

  async function initiateCall(isVideo){
    // choose target (other user)
    const partnerResp = await fetch('/partner_info');
    const p = await partnerResp.json();
    if(!p || !p.name) return alert('No partner registered yet');
    const target = p.name;
    socket.emit('call_outgoing', {to: target, isVideo});
    // show a small "calling..." UI or just start local peer and wait for answer
    await startPeer(false, target, isVideo, false);
  }

  // create PeerConnection and handle offer/answer logic
  async function startPeer(isAnswering, remoteParty, isVideo, isAnswer){
    try{
      const localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:isVideo });
      pc = new RTCPeerConnection(cfg);
      // attach local tracks
      localStream.getTracks().forEach(t=> pc.addTrack(t, localStream));
      pc.onicecandidate = e => {
        if(e.candidate){
          socket.emit('ice_candidate', {to: remoteParty, candidate: e.candidate});
        }
      };
      pc.ontrack = e => {
        // open remote stream in new window (simple)
        const remoteStream = e.streams[0];
        const win = window.open('', '_blank');
        win.document.title = 'Call with ' + remoteParty;
        const el = win.document.createElement(isVideo ? 'video' : 'audio');
        el.autoplay = true; el.controls = true;
        el.srcObject = remoteStream;
        if(isVideo) el.style.width='100%';
        win.document.body.style.margin='0';
        win.document.body.appendChild(el);
      };

      // handle incoming offers/answers
      if(!isAnswering){
        const offer = await pc.createOffer();
        await pc.setLocalDescription(offer);
        socket.emit('webrtc_offer', {to: remoteParty, sdp: offer.sdp, type: offer.type});
      }

    }catch(err){
      console.error('startPeer error', err);
      alert('Call failed: ' + err.message);
    }
  }

  // listen for offer/answer from server
  socket.on('webrtc_offer', async (data)=>{
    // data: {from, sdp, type}
    // create pc if not exists and set remote, create answer
    try{
      const localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video: data.isVideo });
      pc = new RTCPeerConnection(cfg);
      localStream.getTracks().forEach(t=> pc.addTrack(t, localStream));
      pc.onicecandidate = e => { if(e.candidate) socket.emit('ice_candidate', {to: data.from, candidate: e.candidate}); };
      pc.ontrack = e => {
        const remoteStream = e.streams[0];
        const win = window.open();
        const el = win.document.createElement(data.isVideo ? 'video' : 'audio');
        el.autoplay=true; el.controls=true; el.srcObject = remoteStream;
        if(data.isVideo) el.style.width='100%';
        win.document.body.appendChild(el);
      };
      await pc.setRemoteDescription({type: data.type, sdp: data.sdp});
      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      socket.emit('webrtc_answer', {to: data.from, sdp: answer.sdp, type: answer.type});
    }catch(err){ console.error(err); }
  });

  socket.on('webrtc_answer', async (data)=>{
    if(!pc) return;
    try{
      await pc.setRemoteDescription({type: data.type, sdp: data.sdp});
    }catch(e){ console.error(e); }
  });

  socket.on('ice_candidate', async (data)=>{
    if(!pc) return;
    try{
      await pc.addIceCandidate(data.candidate);
    }catch(e){ console.error(e); }
  });

});
</script>
</body>
</html>
"""

# ---------- Routes ----------
@app.context_processor
def utility_processor():
    return dict(load_user=lambda name: load_user_by_name(name))

@app.route("/")
def index():
    first = load_first_user() is None
    return render_template_string(INDEX_HTML, first_user_none=first, heading_img=HEADING_IMG)

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
    updated_name = update_profile(username, new_name=new_name, avatar=avatar_url, status=status)
    # if name changed, update session
    if new_name and new_name != username:
        session['username'] = updated_name
    return jsonify({"status":"ok"})

@app.route("/register", methods=["POST"])
def register():
    body = request.get_json() or {}
    name = (body.get("name") or "ProGamer ♾️").strip()
    passkey = body.get("passkey") or ""
    if not name:
        return "missing name", 400
    existing_master = load_first_user()
    if existing_master is None:
        if not passkey:
            return "passkey required for first registration (choose a master passkey)", 400
        salt, h = hash_pass(passkey)
        try:
            save_user(name, salt, h, avatar=None, status="", make_owner=True)
            session['username'] = name
            touch_user_presence(name)
            return jsonify({"status":"registered","username":name})
        except Exception as e:
            return f"db error: {e}", 500
    else:
        master = get_owner() or load_first_user()
        if not passkey:
            return "passkey required", 400
        if not verify_pass(passkey, master['pass_salt'], master['pass_hash']):
            return "invalid passkey", 403
        salt, h = hash_pass(passkey)
        try:
            save_user(name, salt, h, avatar=None, status="", make_owner=False)
            session['username'] = name
            touch_user_presence(name)
            return jsonify({"status":"registered","username":name})
        except Exception as e:
            return f"db error: {e}", 500

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    name = (body.get("name") or "ProGamer ♾️").strip()
    passkey = body.get("passkey") or ""
    if not name:
        return "missing name", 400
    user = load_user_by_name(name)
    if not user:
        return "no such user", 404
    if not passkey:
        return "passkey required", 400
    if not verify_pass(passkey, user['pass_salt'], user['pass_hash']):
        owner = get_owner()
        if owner and verify_pass(passkey, owner['pass_salt'], owner['pass_hash']):
            session['username'] = name
            touch_user_presence(name)
            return jsonify({"status":"ok","username":name})
        return "invalid passkey", 403
    session['username'] = name
    touch_user_presence(name)
    return jsonify({"status":"ok","username":name})

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route("/chat")
def chat():
    username = session.get('username')
    if not username:
        return redirect(url_for('index'))
    user = load_user_by_name(username)
    if not user:
        return redirect(url_for('index'))
    owner = get_owner()
    partner = get_partner()
    is_owner = user.get("is_owner", False)
    is_partner = user.get("is_partner", False)
    owner_name = owner["name"] if owner else None
    partner_name = partner["name"] if partner else None
    is_member = is_owner or is_partner
    touch_user_presence(username)
    return render_template_string(
        CHAT_HTML,
        username=username,
        user_status=user.get('status',''),
        user_avatar=user.get('avatar',''),
        is_owner=is_owner,
        is_partner=is_partner,
        owner_name=owner_name,
        partner_name=partner_name,
        is_member=is_member,
        heading_img=HEADING_IMG
    )

@app.route("/join_chat", methods=["POST"])
def join_chat():
    username = session.get('username')
    if not username:
        return "not signed in", 400
    user = load_user_by_name(username)
    if not user:
        return "no such user", 400
    if user.get("is_owner") or user.get("is_partner"):
        return "already joined", 400
    partner = get_partner()
    if partner is None:
        set_partner_by_name(username)
        return "joined"
    if partner and partner.get("name") == username:
        return "joined"
    return "chat already has a partner", 400

@app.route("/send_message", methods=["POST"])
def send_message():
    username = session.get('username')
    if not username:
        return "not signed in", 400
    user = load_user_by_name(username)
    if not user:
        return "unknown user", 400
    if not (user.get("is_owner") or user.get("is_partner")):
        return "not part of chat", 403
    body = request.get_json() or {}
    text = (body.get("text") or "").strip()
    attachments = body.get("attachments") or []
    save_message(username, text, attachments=attachments)
    touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/poll_messages")
def poll_messages():
    since = int(request.args.get("since", 0))
    viewer = session.get('username')
    msgs = fetch_messages(since, viewer=viewer)
    return jsonify(msgs)

@app.route("/edit_message", methods=["POST"])
def route_edit_message():
    username = session.get('username')
    if not username:
        return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id")
    text = body.get("text","").strip()
    ok, err = edit_message_db(msg_id, text, username)
    if not ok:
        return err, 400
    touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/delete_message", methods=["POST"])
def route_delete_message():
    username = session.get('username')
    if not username:
        return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id")
    ok, err = delete_message_db(msg_id, username)
    if not ok:
        return err, 400
    touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/react_message", methods=["POST"])
def route_react_message():
    username = session.get('username')
    if not username:
        return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id")
    emoji = body.get("emoji","❤️")
    ok, err = react_message_db(msg_id, username, emoji)
    if not ok:
        return err, 400
    touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/upload_sticker", methods=["POST"])
def upload_sticker():
    if 'file' not in request.files:
        return jsonify({"error":"no file"}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({"error":"empty filename"}), 400
    fn = secure_filename(f.filename)
    save_name = f"stickers/{secrets.token_hex(8)}_{fn}"
    path = os.path.join(app.static_folder, save_name)
    f.save(path)
    url = url_for('static', filename=save_name)
    attachments = [{"type":"sticker","url": url}]
    return jsonify({"status":"ok","attachments": attachments})

@app.route("/upload_file", methods=["POST"])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error":"no file"}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({"error":"empty filename"}), 400
    fn = secure_filename(f.filename)
    save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
    path = os.path.join(app.static_folder, save_name)
    f.save(path)
    url = url_for('static', filename=save_name)
    attachments = [{"type":"image","url": url}]
    return jsonify({"status":"ok","attachments": attachments})

@app.route("/upload_audio", methods=["POST"])
def upload_audio():
    if 'file' not in request.files:
        return jsonify({"error":"no file"}), 400
    f = request.files['file']
    if f.filename == '':
        return jsonify({"error":"empty filename"}), 400
    fn = secure_filename(f.filename)
    save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
    path = os.path.join(app.static_folder, save_name)
    f.save(path)
    url = url_for('static', filename=save_name)
    attachments = [{"type":"audio","url": url}]
    return jsonify({"status":"ok","attachments": attachments})

@app.route("/typing", methods=["POST"])
def route_typing():
    username = session.get('username')
    if not username: return "not signed in", 400
    TYPING[username] = int(time.time())
    touch_user_presence(username)
    return jsonify({"status":"ok"})

@app.route("/status/<name>")
def status(name):
    last = LAST_SEEN.get(name)
    typing = False
    t = TYPING.get(name)
    if t and (int(time.time()) - t) < 4:
        typing = True
    return jsonify({"last_seen": last, "typing": typing})

@app.route("/partner_info")
def partner_info():
    p = get_partner()
    return jsonify(p or {})

# ---------- Socket.IO events ----------
@socketio.on('identify')
def on_identify(data):
    name = data.get('name')
    if not name: return
    USER_SID[name] = request.sid
    emit('identified', {'status':'ok'})
    # broadcast presence
    emit('presence', {'user': name, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    # find user and remove mapping
    for u, s in list(USER_SID.items()):
        if s == sid:
            del USER_SID[u]
            emit('presence', {'user': u, 'online': False}, broadcast=True)
            break

@socketio.on('call_outgoing')
def on_call_outgoing(data):
    to = data.get('to')
    isVideo = data.get('isVideo', False)
    from_user = data.get('from') or None
    if not to: return
    # if caller didn't supply from, try to infer from session (not always available via socket)
    caller = from_user or 'unknown'
    # look up sid for 'to'
    sid = USER_SID.get(to)
    if sid:
        emit('incoming_call', {'from': caller, 'isVideo': isVideo}, room=sid)
    else:
        emit('call_failed', {'reason':'user not online'})

@socketio.on('call_decline')
def on_call_decline(data):
    to = data.get('to')
    sid = USER_SID.get(to)
    if sid:
        emit('call_declined', {}, room=sid)

@socketio.on('webrtc_offer')
def on_webrtc_offer(data):
    to = data.get('to')
    sdp = data.get('sdp')
    typ = data.get('type')
    isVideo = data.get('isVideo', False)
    frm = data.get('from') or None
    sid = USER_SID.get(to)
    if sid:
        emit('webrtc_offer', {'from': frm, 'sdp': sdp, 'type': typ, 'isVideo': isVideo}, room=sid)

@socketio.on('webrtc_answer')
def on_webrtc_answer(data):
    to = data.get('to')
    sdp = data.get('sdp')
    typ = data.get('type')
    sid = USER_SID.get(to)
    if sid:
        emit('webrtc_answer', {'sdp': sdp, 'type': typ}, room=sid)

@socketio.on('ice_candidate')
def on_ice_candidate(data):
    to = data.get('to')
    candidate = data.get('candidate')
    sid = USER_SID.get(to)
    if sid:
        emit('ice_candidate', {'candidate': candidate}, room=sid)

# === Run ===
if __name__ == "__main__":
    print("DB:", DB_PATH)
    pathlib.Path(os.path.join(app.static_folder,"uploads")).mkdir(parents=True, exist_ok=True)
    pathlib.Path(os.path.join(app.static_folder,"stickers")).mkdir(parents=True, exist_ok=True)
    # Use socketio.run to enable Socket.IO server (with eventlet)
    socketio.run(app, host="0.0.0.0", port=PORT, debug=True)
