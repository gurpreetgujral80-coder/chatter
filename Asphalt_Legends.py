# Asphalt_Legends.py
import os
import sqlite3
import base64
import secrets
import time
import hashlib
import hmac
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
RP_NAME = "Asphalt Legends"

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
            is_owner INTEGER DEFAULT 0,
            is_partner INTEGER DEFAULT 0
        );
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            text TEXT,
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
    # insert or replace: keep flags if existing
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
    c.execute("INSERT INTO messages (sender, text, created_at) VALUES (?, ?, ?)", (sender, text, int(time.time())))
    conn.commit()
    conn.close()

def fetch_messages(since_id=0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, sender, text, created_at FROM messages WHERE id > ? ORDER BY id ASC", (since_id,))
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "sender": r[1], "text": r[2], "created_at": r[3]} for r in rows]

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

# ---------- Responsive templates (Tailwind) ----------
INDEX_HTML = r"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Private Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body { font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; }
  .card { backdrop-filter: blur(6px); }
</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 flex items-center justify-center p-4">
  <div class="w-full max-w-3xl card bg-white/90 rounded-3xl shadow-2xl p-6">
    <div class="sm:flex sm:items-center sm:justify-between mb-4">
      <div>
        <h1 class="text-2xl sm:text-3xl font-extrabold text-indigo-700">Asphalt Legends</h1>
        <p class="text-sm text-gray-600 mt-1">Private chat for two — use the single passkey to register & login.</p>
      </div>
      <div class="mt-4 sm:mt-0 text-sm text-gray-500">Tip: First registration sets the shared passkey (owner).</div>
    </div>

    {% if session.get('username') %}
      <div class="text-center mb-6">
        <div class="text-lg">Signed in as <strong>{{ session['username'] }}</strong></div>
        <div class="mt-4 flex justify-center gap-3">
          <a href="{{ url_for('chat') }}" class="px-4 py-2 rounded-lg bg-indigo-600 text-white">Open Chat</a>
          <form method="post" action="{{ url_for('logout') }}">
            <button class="px-4 py-2 rounded-lg bg-gray-200">Logout</button>
          </form>
        </div>
      </div>
    {% else %}
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="p-4 border rounded-lg bg-white">
          <h3 class="font-semibold mb-3 text-indigo-700">Register</h3>
          <form id="regForm" class="space-y-3">
            <input id="reg_name" name="name" class="w-full p-3 border rounded-lg" placeholder="Your name" value="ProGamer ♾️" />
            <input id="reg_passkey" name="passkey" type="password" class="w-full p-3 border rounded-lg" placeholder="Enter master passkey (choose one)" />
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

<script>
function show(el, msg, err=false){
  const node = document.getElementById(el);
  if(!node) return;
  node.textContent = msg;
  node.style.color = err ? '#b91c1c' : '#16a34a';
}

// generate a secure-looking passkey for convenience
document.getElementById('genBtn')?.addEventListener('click', ()=>{
  const s = Array.from(crypto.getRandomValues(new Uint8Array(12))).map(b => (b%36).toString(36)).join('');
  document.getElementById('reg_passkey').value = s;
  show('regStatus','Generated passkey — copy it and keep it safe.');
});

// helper to POST JSON and parse
async function postJson(url, body){
  const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)});
  const text = await r.text();
  let json = null;
  try { json = JSON.parse(text); } catch(e){ json = null; }
  return { ok: r.ok, status: r.status, text, json };
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
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 p-4 flex items-center justify-center">
  <div class="w-full max-w-2xl bg-white/95 rounded-3xl shadow-2xl p-6">
    <div class="flex items-center justify-between mb-4">
      <div>
        <h2 class="text-xl font-bold text-indigo-700">Chat — Private (2 people)</h2>
        <div class="text-sm text-gray-600 mt-1">Signed in as <strong>{{ username }}</strong></div>
      </div>
      <div class="flex gap-2 items-center">
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

<script>
let lastId = 0;
function escapeHtml(s){ return String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function fmtMessage(m){
  const when = new Date(m.created_at * 1000).toLocaleTimeString();
  return `<div class="mb-2"><div class="text-sm text-gray-500">${escapeHtml(m.sender)} · ${when}</div><div class="mt-1">${escapeHtml(m.text)}</div></div>`;
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

  document.getElementById('sendForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const text = document.getElementById('msg').value.trim();
    if(!text) return;
    document.getElementById('msg').value = '';
    await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text})});
    await poll();
  });

  const joinBtn = document.getElementById('joinBtn');
  if(joinBtn){
    joinBtn.addEventListener('click', async ()=>{
      const res = await fetch('/join_chat', {method:'POST'});
      const txt = await res.text();
      if(res.ok) location.reload();
      else document.getElementById('joinStatus').textContent = txt;
    });
  }
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
    # First user: create master passkey if none exists
    existing_master = load_first_user()
    if existing_master is None:
        # owner creation; passkey required
        if not passkey:
            return "passkey required for first registration (choose a master passkey)", 400
        salt, h = hash_pass(passkey)
        try:
            save_user(name, salt, h, make_owner=True)
            session['username'] = name
            return jsonify({"status":"registered", "username": name})
        except Exception as e:
            return f"db error: {e}", 500
    else:
        # not first user: require passkey match the master's passkey
        # load master's pass salt/hash
        master = get_owner()
        if master is None:
            # fallback: pick first
            master = load_first_user()
            if master is None:
                return "server error: no master", 500
        if not passkey:
            return "passkey required", 400
        if not verify_pass(passkey, master['pass_salt'], master['pass_hash']):
            return "invalid passkey", 403
        # create user and mark as normal (not owner). If no partner exists, this user can be partner later via Join.
        salt, h = hash_pass(passkey)  # store same passhash for convenience
        try:
            save_user(name, salt, h, make_owner=False, make_partner=False)
            session['username'] = name
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
        # also allow verifying against owner master in case stored hashes differ
        owner = get_owner()
        if owner and verify_pass(passkey, owner['pass_salt'], owner['pass_hash']):
            session['username'] = name
            return jsonify({"status":"ok", "username": name})
        return "invalid passkey", 403
    session['username'] = name
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
    return jsonify({"status": "ok"})

@app.route("/poll_messages")
def poll_messages():
    since = int(request.args.get("since", 0))
    msgs = fetch_messages(since)
    return jsonify(msgs)

if __name__ == "__main__":
    print("DB:", DB_PATH)
    app.run(host="0.0.0.0", port=PORT, debug=True)
