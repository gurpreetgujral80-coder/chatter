# Asphalt_Legends.py
import os
import sqlite3
import base64
import secrets
import time
import json
import hashlib
import hmac
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for

app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
RP_NAME = "Asphalt Legends"

# ---------- DB helpers ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # users: master passkey stored as salted hash (first user = owner)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            pass_salt BLOB,
            pass_hash BLOB,
            is_owner INTEGER DEFAULT 0,
            is_partner INTEGER DEFAULT 0
        );
    """)
    # messages: text, created timestamp, reactions (JSON text), edited flag, deleted flag
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            text TEXT,
            reactions TEXT DEFAULT '[]',
            edited INTEGER DEFAULT 0,
            deleted INTEGER DEFAULT 0,
            created_at INTEGER
        );
    """)
    conn.commit()
    conn.close()

def save_user(name, salt_bytes, hash_bytes, make_owner=False, make_partner=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if make_owner:
        c.execute("UPDATE users SET is_owner = 0")  # only one owner
    c.execute("""
        INSERT INTO users (name, pass_salt, pass_hash, is_owner, is_partner)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
          pass_salt=excluded.pass_salt, pass_hash=excluded.pass_hash,
          is_owner=COALESCE((SELECT is_owner FROM users WHERE name = excluded.name), excluded.is_owner),
          is_partner=COALESCE((SELECT is_partner FROM users WHERE name = excluded.name), excluded.is_partner)
    """, (name, sqlite3.Binary(salt_bytes), sqlite3.Binary(hash_bytes), 1 if make_owner else 0, 1 if make_partner else 0))
    conn.commit()
    conn.close()

def set_partner_by_name(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_partner = 1 WHERE name = ?", (name,))
    conn.commit()
    conn.close()

def get_owner():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, is_owner, is_partner FROM users WHERE is_owner = 1 LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "pass_salt": row[2], "pass_hash": row[3], "is_owner": bool(row[4]), "is_partner": bool(row[5])}
    return None

def get_partner():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name FROM users WHERE is_partner = 1 LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1]}
    return None

def load_user_by_name(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, pass_salt, pass_hash, is_owner, is_partner FROM users WHERE name = ? LIMIT 1", (name,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "pass_salt": row[2], "pass_hash": row[3], "is_owner": bool(row[4]), "is_partner": bool(row[5])}
    return None

def load_first_user():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, pass_salt, pass_hash, is_owner, is_partner FROM users ORDER BY id LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"name": row[0], "pass_salt": row[1], "pass_hash": row[2], "is_owner": bool(row[3]), "is_partner": bool(row[4])}
    return None

def save_message(sender, text):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    ts = int(time.time())
    c.execute("INSERT INTO messages (sender, text, created_at) VALUES (?, ?, ?)", (sender, text, ts))
    conn.commit()
    conn.close()
    trim_messages_limit(80)

def fetch_messages(since_id=0, include_deleted=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if include_deleted:
        c.execute("SELECT id, sender, text, reactions, edited, deleted, created_at FROM messages WHERE id > ? ORDER BY id ASC", (since_id,))
    else:
        c.execute("SELECT id, sender, text, reactions, edited, deleted, created_at FROM messages WHERE id > ? AND deleted = 0 ORDER BY id ASC", (since_id,))
    rows = c.fetchall()
    conn.close()
    out = []
    for r in rows:
        reactions = []
        try:
            reactions = json.loads(r[3] or "[]")
        except Exception:
            reactions = []
        out.append({"id": r[0], "sender": r[1], "text": r[2], "reactions": reactions, "edited": bool(r[4]), "deleted": bool(r[5]), "created_at": r[6]})
    return out

def trim_messages_limit(max_messages=80):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM messages")
    total = c.fetchone()[0]
    if total <= max_messages:
        conn.close()
        return
    to_delete = total - max_messages
    # delete oldest 'to_delete' rows
    c.execute("DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY id ASC LIMIT ?)", (to_delete,))
    conn.commit()
    conn.close()

def edit_message(msg_id, new_text, editor):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # only allow if editor is the sender or owner
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

def delete_message(msg_id, requester):
    conn = sqlite3.connect(DB_PATH)
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
    # soft-delete
    c.execute("UPDATE messages SET deleted = 1 WHERE id = ?", (msg_id,))
    conn.commit()
    conn.close()
    return True, None

def react_message(msg_id, reactor, emoji):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT reactions FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close()
        return False, "no message"
    reactions = []
    try:
        reactions = json.loads(r[0] or "[]")
    except Exception:
        reactions = []
    # reactions stored as list of {"emoji":"❤️","user":"name"}
    # toggle: if same user+emoji present -> remove; else add
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

init_db()

# ---------- password hashing helpers ----------
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

# ---------- typing/presence in-memory state ----------
TYPING = {}       # username -> last typing timestamp
LAST_SEEN = {}    # username -> last activity timestamp

def touch_user_presence(username):
    if not username: return
    LAST_SEEN[username] = int(time.time())

# ---------- Templates ----------
# Header uses an image at static/heading.png (you must place that file)
INDEX_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Private Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; }
  header img { height:48px; width:auto; }
</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 flex items-start justify-center p-4">
  <div class="w-full max-w-3xl">
    <header class="flex items-center justify-between gap-4 mb-4">
      <div class="flex items-center gap-3">
        <img src="/static/heading.png" alt="heading" />
        <div class="text-2xl font-extrabold">
          <span class="text-indigo-700">asphalt</span>
          <span class="text-pink-600 ml-2">legends</span>
        </div>
      </div>
      <div class="text-sm text-gray-500">Demo chat • single shared passkey</div>
    </header>

    {% if session.get('username') %}
      <div class="mb-6 flex items-center justify-between bg-white p-4 rounded-lg shadow">
        <div>Signed in as <strong>{{ session['username'] }}</strong></div>
        <div class="flex items-center gap-3">
          <button id="profileBtn" class="rounded-full bg-indigo-600 text-white w-10 h-10 flex items-center justify-center">P</button>
          <form method="post" action="{{ url_for('logout') }}"><button class="px-4 py-2 rounded bg-gray-200">Logout</button></form>
        </div>
      </div>
    {% else %}
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
        <div class="p-4 border rounded-lg bg-white">
          <h3 class="font-semibold mb-3 text-indigo-700">Register (set / use shared passkey)</h3>
          <form id="regForm" class="space-y-3">
            <input id="reg_name" name="name" class="w-full p-3 border rounded-lg" placeholder="Your name" value="ProGamer ♾️" />
            <input id="reg_passkey" name="passkey" type="password" class="w-full p-3 border rounded-lg" placeholder="Choose a shared master passkey" />
            <div class="flex items-center gap-3">
              <button type="submit" class="px-4 py-2 rounded-lg bg-green-600 text-white flex-1">Register</button>
              <button id="genBtn" type="button" class="px-3 py-2 rounded-lg bg-gray-100">Generate</button>
            </div>
            <div id="regStatus" class="text-sm mt-2 text-center text-red-500"></div>
            <div class="text-xs text-gray-500 mt-2">If you are first to register, the passkey you provide becomes the master passkey — share it with the other person.</div>
          </form>
        </div>

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

    <footer class="text-center text-xs text-gray-400 mt-6">Responsive — works on phone, tablet & desktop</footer>
  </div>

<!-- Profile modal -->
<div id="profileModal" class="fixed inset-0 hidden items-center justify-center bg-black/40">
  <div class="bg-white rounded-lg p-4 w-80">
    <div class="flex items-center justify-between mb-3">
      <div>
        <div class="text-lg font-bold">Profile</div>
        <div id="profileName" class="text-sm text-gray-600"></div>
      </div>
      <button id="closeProfile" class="text-gray-500">✕</button>
    </div>
    <div class="flex gap-2">
      <a id="openChat" class="px-3 py-2 rounded bg-indigo-600 text-white">Open Chat</a>
      <form method="post" action="{{ url_for('logout') }}"><button class="px-3 py-2 rounded bg-gray-200">Logout</button></form>
    </div>
  </div>
</div>

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

// Register
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

// Login
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

// Profile modal
document.getElementById('profileBtn')?.addEventListener('click', async ()=>{
  const modal = document.getElementById('profileModal');
  document.getElementById('profileName').textContent = '{{ session.get("username") or "" }}';
  modal.classList.remove('hidden');
  modal.classList.add('flex');
});
document.getElementById('closeProfile')?.addEventListener('click', ()=>{
  const modal = document.getElementById('profileModal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
});
document.getElementById('openChat')?.addEventListener('click', ()=> location.href = '/chat');
</script>
</body>
</html>
"""

CHAT_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 p-4 flex items-start justify-center">
  <div class="w-full max-w-2xl bg-white/95 rounded-2xl shadow-2xl p-6">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h2 class="text-xl font-bold text-indigo-700">Chat — Private (2 people)</h2>
        <div class="text-sm text-gray-600 mt-1">Signed in as <strong>{{ username }}</strong></div>
      </div>
      <div class="flex gap-2 items-center">
        <button id="profileBtn" class="rounded-full bg-indigo-600 text-white w-10 h-10 flex items-center justify-center">P</button>
        <form method="post" action="{{ url_for('logout') }}"><button class="px-3 py-1 rounded bg-gray-200">Logout</button></form>
      </div>
    </div>

    {% if is_owner and not partner_name %}
      <div class="mb-4 text-sm text-gray-600">Waiting for partner to join. Have them register on their device and click "Join Chat".</div>
    {% elif is_owner and partner_name %}
      <div class="mb-4 text-sm text-gray-600">Partner: <strong>{{ partner_name }}</strong></div>
    {% elif is_partner %}
      <div class="mb-4 text-sm text-gray-600">Chatting with owner: <strong>{{ owner_name }}</strong></div>
    {% endif %}

    {% if not is_member %}
      <div class="mb-4">
        <button id="joinBtn" class="px-4 py-2 rounded bg-indigo-600 text-white">Join Chat</button>
        <div id="joinStatus" class="text-sm mt-2 text-red-500"></div>
      </div>
    {% endif %}

    <div id="messages" class="h-64 overflow-auto border rounded p-3 mb-3 bg-gray-50"></div>

    <form id="sendForm" class="flex gap-2">
      <input id="msg" class="flex-1 p-2 border rounded" placeholder="Type a message..." />
      <button class="px-4 py-2 rounded bg-green-600 text-white">Send</button>
    </form>
  </div>

<!-- small profile modal -->
<div id="profileModal" class="fixed inset-0 hidden items-center justify-center bg-black/40">
  <div class="bg-white rounded-lg p-4 w-80">
    <div class="flex items-center justify-between mb-3">
      <div>
        <div class="text-lg font-bold">Profile</div>
        <div id="profileName" class="text-sm text-gray-600"></div>
      </div>
      <button id="closeProfile" class="text-gray-500">✕</button>
    </div>
    <div class="flex gap-2">
      <button id="profileCloseBtn" class="px-3 py-2 rounded bg-indigo-600 text-white">Close</button>
      <form method="post" action="{{ url_for('logout') }}"><button class="px-3 py-2 rounded bg-gray-200">Logout</button></form>
    </div>
  </div>
</div>

<script>
let lastId = 0;
function escapeHtml(s){ return String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtMessage(m){
  const when = new Date(m.created_at * 1000).toLocaleTimeString();
  const text = m.deleted ? '<em>message deleted</em>' : escapeHtml(m.text) + (m.edited ? ' <span class="text-xs text-gray-400">edited</span>' : '');
  const reactions = (m.reactions || []).map(r => `<span title="${escapeHtml(r.user)}">${escapeHtml(r.emoji)}</span>`).join(' ');
  return `<div class="mb-2 rounded p-2 bg-white shadow-sm">
    <div class="text-sm text-gray-500">${escapeHtml(m.sender)} · ${when}</div>
    <div class="mt-1">${text}</div>
    <div class="mt-1 text-sm">${reactions}</div>
    <div class="mt-2 flex gap-2">
      <button data-id="${m.id}" class="react-btn text-xs px-2 py-1 rounded bg-gray-100">❤️</button>
      <button data-id="${m.id}" class="edit-btn text-xs px-2 py-1 rounded bg-gray-100">Edit</button>
      <button data-id="${m.id}" class="del-btn text-xs px-2 py-1 rounded bg-gray-100">Delete</button>
    </div>
  </div>`;
}

async function poll(){
  try{
    const resp = await fetch('/poll_messages?since=' + lastId);
    if(!resp.ok) return;
    const data = await resp.json();
    if(data.length){
      const container = document.getElementById('messages');
      for(const m of data){
        container.insertAdjacentHTML('beforeend', fmtMessage(m));
        lastId = m.id;
      }
      container.scrollTop = container.scrollHeight;
    }
  }catch(e){ console.error('poll error', e); }
}

document.addEventListener('DOMContentLoaded', ()=>{
  poll();
  setInterval(poll, 1200);

  // send
  document.getElementById('sendForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const textEl = document.getElementById('msg');
    const text = textEl.value.trim();
    if(!text) return;
    textEl.value = '';
    await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text})});
    await poll();
  });

  // join
  const joinBtn = document.getElementById('joinBtn');
  if(joinBtn){
    joinBtn.addEventListener('click', async ()=>{
      const res = await fetch('/join_chat', {method:'POST'});
      const txt = await res.text();
      if(res.ok) location.reload();
      else document.getElementById('joinStatus').textContent = txt;
    });
  }

  // profile modal
  document.getElementById('profileBtn')?.addEventListener('click', ()=>{
    const modal = document.getElementById('profileModal');
    document.getElementById('profileName').textContent = '{{ username }}';
    modal.classList.remove('hidden'); modal.classList.add('flex');
  });
  document.getElementById('closeProfile')?.addEventListener('click', ()=> { const m=document.getElementById('profileModal'); m.classList.add('hidden'); m.classList.remove('flex');});
  document.getElementById('profileCloseBtn')?.addEventListener('click', ()=> { const m=document.getElementById('profileModal'); m.classList.add('hidden'); m.classList.remove('flex');});

  // delegation for react/edit/delete
  document.getElementById('messages').addEventListener('click', async (e)=>{
    const id = e.target.getAttribute('data-id');
    if(!id) return;
    if(e.target.classList.contains('react-btn')){
      // use hardcoded emoji for demo
      await fetch('/react_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: parseInt(id), emoji: '❤️'})});
      await poll();
    } else if(e.target.classList.contains('edit-btn')){
      const newText = prompt('Edit message text:');
      if(newText !== null){
        await fetch('/edit_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: parseInt(id), text: newText})});
        // refresh
        document.getElementById('messages').innerHTML = '';
        lastId = 0;
        await poll();
      }
    } else if(e.target.classList.contains('del-btn')){
      if(confirm('Delete this message?')){
        await fetch('/delete_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({id: parseInt(id)})});
        // refresh
        document.getElementById('messages').innerHTML = '';
        lastId = 0;
        await poll();
      }
    }
  });
});
</script>
</body>
</html>
"""

# ---------- Routes ----------
@app.route("/")
def index():
    return render_template_string(INDEX_HTML)

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
            save_user(name, salt, h, make_owner=True)
            session['username'] = name
            touch_user_presence(name)
            return jsonify({"status":"registered", "username": name})
        except Exception as e:
            return f"db error: {e}", 500
    else:
        master = get_owner()
        if master is None:
            master = load_first_user()
            if master is None:
                return "server error: no master", 500
        if not passkey:
            return "passkey required", 400
        if not verify_pass(passkey, master['pass_salt'], master['pass_hash']):
            return "invalid passkey", 403
        salt, h = hash_pass(passkey)
        try:
            save_user(name, salt, h, make_owner=False, make_partner=False)
            session['username'] = name
            touch_user_presence(name)
            return jsonify({"status":"registered", "username": name})
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
            return jsonify({"status":"ok", "username": name})
        return "invalid passkey", 403
    session['username'] = name
    touch_user_presence(name)
    return jsonify({"status":"ok", "username": name})

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# ---------- Chat endpoints ----------
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
    return render_template_string(CHAT_HTML, username=username, is_owner=is_owner, is_partner=is_partner, owner_name=owner_name, partner_name=partner_name, is_member=is_member)

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
    if not text:
        return "empty", 400
    save_message(username, text)
    touch_user_presence(username)
    return jsonify({"status": "ok"})

@app.route("/poll_messages")
def poll_messages():
    since = int(request.args.get("since", 0))
    msgs = fetch_messages(since)
    return jsonify(msgs)

@app.route("/edit_message", methods=["POST"])
def route_edit_message():
    username = session.get('username')
    if not username:
        return "not signed in", 400
    body = request.get_json() or {}
    msg_id = body.get("id")
    text = body.get("text", "").strip()
    ok, err = edit_message(msg_id, text, username)
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
    ok, err = delete_message(msg_id, username)
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
    emoji = body.get("emoji", "❤️")
    ok, err = react_message(msg_id, username, emoji)
    if not ok:
        return err, 400
    touch_user_presence(username)
    return jsonify({"status":"ok"})

# presence & typing endpoints (lightweight)
@app.route("/typing", methods=["POST"])
def route_typing():
    username = session.get('username')
    if not username:
        return "not signed in", 400
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

if __name__ == "__main__":
    print("DB:", DB_PATH)
    app.run(host="0.0.0.0", port=PORT, debug=True)
