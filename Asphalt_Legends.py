# Asphalt_Legends.py
import os
import sqlite3
import base64
import secrets
import time
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for

app = Flask(__name__)
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
RP_ID = "localhost"
RP_NAME = "Asphalt Legends"

# simple in-memory map for per-flow challenge states
FIDO2_STATES = {}

# ---------- DB ----------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE,
            cred_id BLOB,
            cred_raw BLOB,
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

def save_credential(name, cred_id_bytes, raw_blob_bytes, make_owner=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if make_owner:
        c.execute("UPDATE users SET is_owner = 0")
    # Insert or replace by name
    c.execute(
        "INSERT OR REPLACE INTO users (name, cred_id, cred_raw, is_owner, is_partner) VALUES (?, ?, ?, COALESCE((SELECT is_owner FROM users WHERE name = ?),?), COALESCE((SELECT is_partner FROM users WHERE name = ?),0))",
        (name, sqlite3.Binary(cred_id_bytes), sqlite3.Binary(raw_blob_bytes), name, 1 if make_owner else 0, name),
    )
    conn.commit()
    conn.close()

def get_owner():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, cred_id, is_owner, is_partner FROM users WHERE is_owner = 1 LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "cred_id": row[2], "is_owner": bool(row[3]), "is_partner": bool(row[4])}
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

def set_partner_by_name(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE users SET is_partner = 1 WHERE name = ?", (name,))
    conn.commit()
    conn.close()

def load_first_user():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, cred_id, cred_raw, is_owner, is_partner FROM users ORDER BY id LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"name": row[0], "cred_id": row[1], "cred_raw": row[2], "is_owner": bool(row[3]), "is_partner": bool(row[4])}
    return None

def load_user_by_name(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, cred_id, is_owner, is_partner FROM users WHERE name = ? LIMIT 1", (name,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "cred_id": row[2], "is_owner": bool(row[3]), "is_partner": bool(row[4])}
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

# ---------- helpers ----------
def b64url_encode(b: bytes) -> str:
    if b is None:
        return ""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64url_decode(s: str) -> bytes:
    if s is None:
        return None
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    s2 = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s2)

# ---------- Templates (index + chat) ----------
INDEX_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Private Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 flex items-center justify-center">
  <div class="w-full max-w-xl bg-white rounded-2xl shadow-xl p-8">
    <h1 class="text-3xl font-bold text-center text-indigo-700 mb-3">Asphalt Legends</h1>
    <p class="text-center text-sm text-gray-600 mb-6">Private chat for two — register Face/Touch ID for this device.</p>

    {% if session.get('username') %}
      <div class="text-center mb-4">Signed in as <strong>{{ session['username'] }}</strong></div>
      <div class="flex justify-center space-x-3">
        <a href="{{ url_for('chat') }}" class="px-6 py-2 rounded-lg bg-indigo-600 text-white font-semibold">Open Chat</a>
        <form method="post" action="{{ url_for('logout') }}">
          <button class="px-6 py-2 rounded-lg bg-gray-200">Logout</button>
        </form>
      </div>
    {% else %}
      <div class="grid grid-cols-1 gap-4">
        <div class="p-4 border rounded-lg">
          <h3 class="font-semibold mb-2">Register (Face/Touch ID)</h3>
          <form id="regForm" class="space-y-3">
            <input id="name" name="name" class="w-full p-3 border rounded-lg" placeholder="Enter your name" value="ProGamer ♾️" />
            <div class="flex justify-center">
              <button type="submit" class="px-6 py-2 rounded-lg bg-green-600 text-white font-semibold">Register Face/Touch ID</button>
            </div>
            <div id="regStatus" class="text-sm mt-2 text-center text-red-500"></div>
          </form>
        </div>

        <div class="p-4 border rounded-lg">
          <h3 class="font-semibold mb-2">Login (Face/Touch ID)</h3>
          <div class="flex justify-center">
            <button id="loginBtn" class="px-6 py-2 rounded-lg bg-indigo-600 text-white font-semibold">Login with Face/Touch ID</button>
          </div>
          <div id="loginStatus" class="text-sm mt-2 text-center text-red-500"></div>
        </div>
      </div>
    {% endif %}
    <div id="libStatus" class="mt-3 text-xs text-center text-gray-500"></div>
  </div>

<script>
// ----- base64url <-> ArrayBuffer helpers -----
function bufferToBase64Url(buffer){
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i=0;i<bytes.length;i++) binary += String.fromCharCode(bytes[i]);
  const b64 = btoa(binary);
  return b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function base64UrlToBuffer(base64url){
  if(!base64url) return new ArrayBuffer(0);
  let b64 = base64url.replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4;
  if(pad) b64 += '='.repeat(4 - pad);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for(let i=0;i<binary.length;i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
function utf8ToBuffer(s){
  return new TextEncoder().encode(s).buffer;
}
function decodeClientDataJSON(b64str){
  const buf = base64UrlToBuffer(b64str);
  const txt = new TextDecoder().decode(buf);
  return JSON.parse(txt);
}

// ----- helpers to talk to server and perform navigator.credentials -----
async function fetchJsonOrText(url, opts){
  const r = await fetch(url, opts);
  const text = await r.text();
  try { return { ok: r.ok, status: r.status, json: JSON.parse(text), text }; }
  catch(e){ return { ok: r.ok, status: r.status, json: null, text }; }
}

// Registration flow
document.addEventListener('DOMContentLoaded', ()=>{
  const regForm = document.getElementById('regForm');
  const loginBtn = document.getElementById('loginBtn');

  if(regForm){
    regForm.addEventListener('submit', async e=>{
      e.preventDefault();
      document.getElementById('regStatus').textContent = 'Starting registration...';
      const name = document.getElementById('name').value || 'ProGamer ♾️';
      try{
        const begin = await fetchJsonOrText('/begin_register', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name})});
        if(!begin.ok) throw new Error('begin_register failed: '+begin.text);
        const opts = begin.json;
        // convert challenge + user.id to ArrayBuffers
        opts.challenge = base64UrlToBuffer(opts.challenge);
        opts.user.id = base64UrlToBuffer(opts.user.id);
        // ensure pubKeyCredParams present:
        opts.pubKeyCredParams = opts.pubKeyCredParams || [{type:'public-key', alg:-7}];

        // call WebAuthn create
        const cred = await navigator.credentials.create({ publicKey: opts });
        if(!cred) throw new Error('No credential returned (user canceled?)');

        // build transportable object
        const clientDataJSON = bufferToBase64Url(cred.response.clientDataJSON);
        const attObj = bufferToBase64Url(cred.response.attestationObject);
        const rawId = bufferToBase64Url(cred.rawId || cred.id);

        // send to server
        const complete = await fetchJsonOrText('/complete_register', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ name, credential: { id: rawId, rawId: rawId, response: { clientDataJSON, attestationObject: attObj } } })
        });
        if(!complete.ok) throw new Error('complete_register failed: '+complete.text);
        document.getElementById('regStatus').textContent = 'Registration successful — signed in.';
        window.location = '/after_register?name=' + encodeURIComponent(name);
      }catch(err){
        console.error(err);
        document.getElementById('regStatus').textContent = 'Registration failed: ' + (err.message||err);
      }
    });
  }

  if(loginBtn){
    loginBtn.addEventListener('click', async ()=>{
      document.getElementById('loginStatus').textContent = 'Starting login...';
      try{
        const begin = await fetchJsonOrText('/begin_login', {method:'POST'});
        if(!begin.ok) throw new Error('begin_login failed: '+begin.text);
        const opts = begin.json;
        opts.challenge = base64UrlToBuffer(opts.challenge);
        if(opts.allowCredentials && Array.isArray(opts.allowCredentials)){
          opts.allowCredentials = opts.allowCredentials.map(c => ({ type: c.type, id: base64UrlToBuffer(c.id) }));
        }

        const assertion = await navigator.credentials.get({ publicKey: opts });
        if(!assertion) throw new Error('No assertion returned (user canceled?)');

        // prepare to send
        const clientDataJSON = bufferToBase64Url(assertion.response.clientDataJSON);
        const authenticatorData = bufferToBase64Url(assertion.response.authenticatorData);
        const signature = bufferToBase64Url(assertion.response.signature);
        const rawId = bufferToBase64Url(assertion.rawId || assertion.id);

        const complete = await fetchJsonOrText('/complete_login', {
          method:'POST', headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ credential: { id: rawId, rawId, response: { clientDataJSON, authenticatorData, signature } } })
        });
        if(!complete.ok) throw new Error('complete_login failed: '+complete.text);
        const body = complete.json;
        document.getElementById('loginStatus').textContent = 'Login successful.';
        // redirect to chat
        window.location = '/after_login?name=' + encodeURIComponent(body.username || '');
      }catch(err){
        console.error(err);
        document.getElementById('loginStatus').textContent = 'Login failed: ' + (err.message||err);
      }
    });
  }
});
</script>
</body>
</html>
"""

CHAT_HTML = """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Asphalt Legends — Chat</title>
<meta name="viewport" content="width=device-width,initial-scale=1" />
<script src="https://cdn.tailwindcss.com"></script>
<style>body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}</style>
</head>
<body class="min-h-screen bg-gradient-to-br from-indigo-50 via-white to-pink-50 flex items-center justify-center">
  <div class="w-full max-w-2xl bg-white rounded-2xl shadow-xl p-6">
    <div class="flex justify-between items-center mb-4">
      <h2 class="text-xl font-bold text-indigo-700">Chat — Private (2 people)</h2>
      <div>
        <form method="post" action="{{ url_for('logout') }}"><button class="px-3 py-1 rounded bg-gray-200">Logout</button></form>
      </div>
    </div>

    <div class="mb-4">
      <div>Signed in as <strong>{{ username }}</strong></div>
      {% if is_owner and not partner_name %}
        <div class="text-sm text-gray-600">Waiting for partner to join. Have them register on their device and click Join Chat.</div>
      {% elif is_owner and partner_name %}
        <div class="text-sm text-gray-600">Partner: <strong>{{ partner_name }}</strong></div>
      {% elif is_partner %}
        <div class="text-sm text-gray-600">Chatting with owner: <strong>{{ owner_name }}</strong></div>
      {% endif %}
    </div>

    {% if not is_member %}
      <div class="mb-4">
        <button id="joinBtn" class="px-4 py-2 rounded bg-indigo-600 text-white">Join Chat</button>
        <div id="joinStatus" class="text-sm mt-2 text-red-500"></div>
      </div>
    {% endif %}

    <div id="messages" class="h-64 overflow-auto border rounded p-3 mb-3 bg-gray-50"></div>

    <form id="sendForm" class="flex space-x-2">
      <input id="msg" class="flex-1 p-2 border rounded" placeholder="Type a message..." />
      <button class="px-4 py-2 rounded bg-green-600 text-white">Send</button>
    </form>
  </div>

<script>
let lastId = 0;
function fmtMessage(m){
  const when = new Date(m.created_at * 1000).toLocaleTimeString();
  return `<div class="mb-2"><div class="text-sm text-gray-500">${m.sender} · ${when}</div><div class="mt-1">${escapeHtml(m.text)}</div></div>`;
}
function escapeHtml(s){ return String(s).replace(/[&<>"]/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

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

  const sendForm = document.getElementById('sendForm');
  sendForm.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const txt = document.getElementById('msg').value.trim();
    if(!txt) return;
    document.getElementById('msg').value = '';
    await fetch('/send_message', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text: txt})});
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

@app.route("/after_register")
def after_register():
    name = request.args.get("name")
    if name:
        session['username'] = name
    return redirect(url_for('chat'))

@app.route("/after_login")
def after_login():
    name = request.args.get("name")
    if name:
        session['username'] = name
    return redirect(url_for('chat'))

@app.route("/logout", methods=["POST"])
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

# ---------- WebAuthn endpoints (simplified verification) ----------
@app.route("/begin_register", methods=["POST"])
def begin_register():
    body = request.get_json() or {}
    name = body.get("name") or "ProGamer ♾️"
    # Make user id and challenge
    user_id = secrets.token_bytes(16)
    challenge = secrets.token_bytes(32)
    # Save state key
    key = secrets.token_hex(16)
    FIDO2_STATES[key] = {"type": "register", "challenge": b64url_encode(challenge), "name": name, "user_id": b64url_encode(user_id)}
    session['fido2_state_key'] = key
    # Options returned to browser (challenge and user.id are base64url strings)
    options = {
        "challenge": b64url_encode(challenge),
        "rp": {"name": RP_NAME, "id": RP_ID},
        "user": {"id": b64url_encode(user_id), "name": name, "displayName": name},
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type":"public-key","alg": -257}],
        "timeout": 60000,
        "attestation": "direct",
        "authenticatorSelection": {"userVerification": "required"}
    }
    return jsonify(options)

@app.route("/complete_register", methods=["POST"])
def complete_register():
    body = request.get_json() or {}
    name = body.get("name") or "ProGamer ♾️"
    credential = body.get("credential")
    if not credential:
        return "missing credential", 400
    key = session.get('fido2_state_key')
    if not key or key not in FIDO2_STATES:
        return "no state", 400
    state = FIDO2_STATES.pop(key)
    # credential includes rawId (b64url), response.clientDataJSON (b64url), response.attestationObject (b64url)
    try:
        rawId_b64 = credential.get("rawId") or credential.get("id")
        clientDataJSON_b64 = credential.get("response", {}).get("clientDataJSON")
        attObj_b64 = credential.get("response", {}).get("attestationObject")
        if not rawId_b64 or not clientDataJSON_b64 or not attObj_b64:
            return "bad credential shape", 400
        # Basic check: verify clientData.challenge matches our challenge
        clientData = b64url_decode(clientDataJSON_b64)
        import json
        cd = json.loads(clientData.decode("utf-8"))
        # cd.challenge is base64url string (no padding) in most browsers
        if cd.get("challenge") != state["challenge"]:
            return "challenge mismatch", 400
        # store credential id and raw attestation
        cred_id = b64url_decode(rawId_b64)
        raw_blob = b64url_decode(attObj_b64)
        existing = load_first_user()
        make_owner = existing is None
        save_credential(name, cred_id, raw_blob, make_owner=make_owner)
        session['username'] = name
        return jsonify({"status":"registered", "username": name})
    except Exception as e:
        return f"register error: {e}", 500

@app.route("/begin_login", methods=["POST"])
def begin_login():
    user = load_first_user()
    if not user or not user.get("cred_id"):
        return "no user", 400
    challenge = secrets.token_bytes(32)
    key = secrets.token_hex(16)
    FIDO2_STATES[key] = {"type": "login", "challenge": b64url_encode(challenge)}
    session['fido2_state_key'] = key
    options = {
        "challenge": b64url_encode(challenge),
        "allowCredentials": [{"type": "public-key", "id": b64url_encode(user["cred_id"])}],
        "timeout": 60000,
        "userVerification": "required",
        "rpId": RP_ID
    }
    return jsonify(options)

@app.route("/complete_login", methods=["POST"])
def complete_login():
    body = request.get_json() or {}
    credential = body.get("credential")
    if not credential:
        return "missing credential", 400
    key = session.get('fido2_state_key')
    if not key or key not in FIDO2_STATES:
        return "no state", 400
    state = FIDO2_STATES.pop(key)
    try:
        rawId_b64 = credential.get("rawId") or credential.get("id")
        clientDataJSON_b64 = credential.get("response", {}).get("clientDataJSON")
        authenticatorData_b64 = credential.get("response", {}).get("authenticatorData")
        signature_b64 = credential.get("response", {}).get("signature")
        if not rawId_b64 or not clientDataJSON_b64 or not authenticatorData_b64 or not signature_b64:
            return "bad assertion shape", 400
        # verify clientData challenge
        clientData = b64url_decode(clientDataJSON_b64)
        import json
        cd = json.loads(clientData.decode("utf-8"))
        if cd.get("challenge") != state["challenge"]:
            return "challenge mismatch", 400
        # verify rawId matches stored cred_id
        raw_id = b64url_decode(rawId_b64)
        stored = load_first_user()
        if not stored:
            return "no stored user", 400
        if raw_id != stored["cred_id"]:
            return "credential id mismatch", 403
        # NOTE: we are NOT verifying the signature/authenticatorData cryptographically here.
        # Mark user as signed in
        username = stored["name"]
        session['username'] = username
        return jsonify({"status":"ok", "username": username})
    except Exception as e:
        return f"login error: {e}", 500

# ---------- Chat ----------
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
