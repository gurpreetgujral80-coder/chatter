# Asphalt_Legends.py
import os
import sqlite3
import base64
import secrets
import time
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity
from fido2.utils import websafe_encode

app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
RP_ID = "localhost"
RP_NAME = "Asphalt Legends"

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
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            text TEXT,
            created_at INTEGER
        )
    """)
    conn.commit()
    conn.close()

def save_credential(name, cred_id_bytes, raw_blob_bytes, make_owner=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if make_owner:
        c.execute("UPDATE users SET is_owner = 0")
    c.execute(
        "INSERT OR REPLACE INTO users (name, cred_id, cred_raw, is_owner, is_partner) VALUES (?, ?, ?, COALESCE((SELECT is_owner FROM users WHERE name = ?),?), COALESCE((SELECT is_partner FROM users WHERE name = ?),0))",
        (name, sqlite3.Binary(cred_id_bytes), sqlite3.Binary(raw_blob_bytes), name, 1 if make_owner else 0, name),
    )
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

def load_user_by_name(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, name, cred_id, is_owner, is_partner FROM users WHERE name = ? LIMIT 1", (name,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "name": row[1], "cred_id": row[2], "is_owner": bool(row[3]), "is_partner": bool(row[4])}
    return None

def load_first_user():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT name, cred_id, cred_raw, is_owner, is_partner FROM users ORDER BY id LIMIT 1")
    row = c.fetchone()
    conn.close()
    if row:
        return {"name": row[0], "cred_id": row[1], "cred_raw": row[2], "is_owner": bool(row[3]), "is_partner": bool(row[4])}
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

# ---------- FIDO2 ----------
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)

# ---------- helpers ----------
def b64u_encode_bytes(b):
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    return websafe_encode(b)

def b64u_decode_str(s):
    if s is None:
        return None
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    s2 = s + "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s2)

def make_registration_dict(registration_data):
    try:
        pk = getattr(registration_data, "public_key", registration_data)
    except Exception:
        pk = registration_data
    challenge = getattr(pk, "challenge", None) or (pk.get("challenge") if isinstance(pk, dict) else None)
    if challenge is None:
        challenge = getattr(registration_data, "challenge", None)
    user = getattr(pk, "user", None) or (pk.get("user") if isinstance(pk, dict) else None)
    rp_field = getattr(pk, "rp", None) or (pk.get("rp") if isinstance(pk, dict) else None)
    params = getattr(pk, "pub_key_cred_params", None) or getattr(pk, "pubKeyCredParams", None) or (pk.get("pubKeyCredParams") if isinstance(pk, dict) else None)
    user_id_b64, user_name, user_display = "", "", ""
    if user:
        uid = getattr(user, "id", None) if not isinstance(user, dict) else user.get("id")
        user_id_b64 = b64u_encode_bytes(uid)
        user_name = getattr(user, "name", None) if not isinstance(user, dict) else user.get("name")
        user_display = getattr(user, "display_name", None) or getattr(user, "displayName", None) if not isinstance(user, dict) else (user.get("displayName") or user.get("display_name"))
    pub_params = []
    if params:
        for p in params:
            if isinstance(p, dict):
                alg = p.get("alg") or p.get("algorithm")
                typ = p.get("type", "public-key")
            else:
                alg = getattr(p, "alg", None) or getattr(p, "algorithm", None)
                typ = getattr(p, "type", "public-key")
            if alg is None:
                continue
            pub_params.append({"type": typ, "alg": alg})
    if not pub_params:
        pub_params = [{"type": "public-key", "alg": -7}]
    return {
        "challenge": b64u_encode_bytes(challenge),
        "rp": {"name": getattr(rp_field, "name", RP_NAME) if rp_field else RP_NAME, "id": getattr(rp_field, "id", RP_ID) if rp_field else RP_ID},
        "user": {"id": user_id_b64, "name": user_name or "", "displayName": user_display or user_name or ""},
        "pubKeyCredParams": pub_params,
        "timeout": getattr(pk, "timeout", None) or (pk.get("timeout") if isinstance(pk, dict) else None),
        "attestation": getattr(pk, "attestation", None) or (pk.get("attestation") if isinstance(pk, dict) else "direct")
    }

def make_authenticate_dict(auth_data):
    try:
        pk = getattr(auth_data, "public_key", auth_data)
    except Exception:
        pk = auth_data
    challenge = getattr(pk, "challenge", None) or (pk.get("challenge") if isinstance(pk, dict) else None)
    challenge_b64 = b64u_encode_bytes(challenge)
    allow = getattr(pk, "allow_credentials", None) or getattr(pk, "allowCredentials", None) or (pk.get("allowCredentials") if isinstance(pk, dict) else None)
    allow_list = []
    if allow:
        for a in allow:
            if isinstance(a, dict):
                aid = a.get("id")
                allow_list.append({"type": a.get("type", "public-key"), "id": b64u_encode_bytes(aid)})
            else:
                aid = getattr(a, "id", None) or getattr(a, "credential_id", None)
                allow_list.append({"type": "public-key", "id": b64u_encode_bytes(aid)})
    return {"challenge": challenge_b64, "allowCredentials": allow_list, "timeout": getattr(pk, "timeout", None), "rpId": getattr(pk, "rpId", getattr(pk, "rp_id", RP_ID)), "userVerification": getattr(pk, "user_verification", None) or (pk.get("userVerification") if isinstance(pk, dict) else None)}

# ---------- Templates ----------
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

<script src="https://cdn.jsdelivr.net/npm/@github/webauthn-json@2.1.1/dist/browser-ponyfill.min.js"></script>
<script>
function show(el, msg, isError=false){
  const node = document.getElementById(el);
  if(!node) return;
  node.textContent = msg;
  node.style.color = isError ? '#b91c1c' : '#16a34a';
}

window.addEventListener('DOMContentLoaded', async ()=>{
  const WA = window.WebAuthnJSON || window.webauthnJSON;
  if(!WA){
    document.getElementById('libStatus').textContent =
      "WebAuthn library not available. Ensure the CDN is reachable.";
    console.error('WebAuthn library not available.');
    const regBtn = document.querySelector('#regForm button');
    if(regBtn) regBtn.disabled = true;
    const loginBtn = document.getElementById('loginBtn');
    if(loginBtn) loginBtn.disabled = true;
    return;
  }
  document.getElementById('libStatus').textContent = "WebAuthn library loaded ✓";

  async function fetchJsonOrText(url, opts){
    const r = await fetch(url, opts);
    const text = await r.text();
    let json = null;
    try { json = JSON.parse(text); } catch(e){ json = null; }
    return { ok: r.ok, status: r.status, text, json };
  }

  const regForm = document.getElementById('regForm');
  if(regForm){
    regForm.addEventListener('submit', async e=>{
      e.preventDefault();
      show('regStatus','Starting registration...');
      const name = document.getElementById('name').value || 'ProGamer ♾️';
      try{
        const begin = await fetchJsonOrText('/begin_register', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name})});
        if(!begin.ok) throw new Error('begin_register failed: '+begin.text);
        const options = begin.json || JSON.parse(begin.text);
        const attestation = await WA.create(options);
        const complete = await fetchJsonOrText('/complete_register', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({name, credential: attestation})});
        if(!complete.ok) throw new Error('complete_register failed: '+complete.text);
        show('regStatus','Registration successful — signed in.');
        window.location = '/after_register?name=' + encodeURIComponent(name);
      }catch(err){
        console.error('registration error', err);
        show('regStatus','Registration failed: '+err.message, true);
      }
    });
  }

  const loginBtn = document.getElementById('loginBtn');
  if(loginBtn){
    loginBtn.addEventListener('click', async ()=>{
      show('loginStatus','Starting login...');
      try{
        const begin = await fetchJsonOrText('/begin_login', {method:'POST'});
        if(!begin.ok) throw new Error('begin_login failed: '+begin.text);
        const options = begin.json || JSON.parse(begin.text);
        const assertion = await WA.get(options);
        const complete = await fetchJsonOrText('/complete_login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({credential: assertion})});
        if(!complete.ok) throw new Error('complete_login failed: '+complete.text);
        const body = complete.json || JSON.parse(complete.text);
        if(body && body.username) window.location = '/after_login?name=' + encodeURIComponent(body.username);
        else window.location = '/chat';
      }catch(err){
        console.error('login error', err);
        show('loginStatus','Login failed: '+err.message, true);
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

# -------- routes ----------
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

# ---------- WebAuthn endpoints ----------
@app.route("/begin_register", methods=["POST"])
def begin_register():
    body = request.get_json() or {}
    name = body.get("name") or "ProGamer ♾️"
    user_entity = PublicKeyCredentialUserEntity(id=os.urandom(16), name=name, display_name=name)
    try:
        registration_data, state = server.register_begin(user_entity, user_verification="required")
    except TypeError:
        registration_data, state = server.register_begin(user_entity)
    key = secrets.token_hex(16)
    FIDO2_STATES[key] = state
    session['fido2_state_key'] = key
    reg_json = make_registration_dict(registration_data)
    return jsonify(reg_json)

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
    try:
        resp = credential.get("response", {})
        clientDataJSON_b64 = resp.get("clientDataJSON") or credential.get("clientDataJSON")
        attestationObject_b64 = resp.get("attestationObject") or credential.get("attestationObject")
        client_data = b64u_decode_str(clientDataJSON_b64)
        att_obj = b64u_decode_str(attestationObject_b64)
    except Exception as e:
        return f"bad credential payload: {e}", 400
    try:
        reg_result = server.register_complete(state, client_data, att_obj)
    except TypeError:
        try:
            reg_result = server.register_complete(state, credential)
        except Exception as e:
            return f"register_complete failed: {e}", 500
    except Exception as e:
        return f"register_complete failed: {e}", 500
    cred_id = None
    try:
        if hasattr(reg_result, "credential_data") and hasattr(reg_result.credential_data, "credential_id"):
            cred_id = bytes(reg_result.credential_data.credential_id)
        elif hasattr(reg_result, "credential_id"):
            cred_id = bytes(getattr(reg_result, "credential_id"))
    except Exception:
        cred_id = None
    if cred_id is None:
        rawId = credential.get("rawId") or credential.get("id")
        if isinstance(rawId, str):
            try:
                cred_id = b64u_decode_str(rawId)
            except Exception:
                cred_id = rawId.encode("utf-8")
        elif isinstance(rawId, (bytes, bytearray)):
            cred_id = bytes(rawId)
    if cred_id is None:
        return "could not determine credential id", 500
    raw_blob = b""
    try:
        if hasattr(reg_result, "credential_data") and hasattr(reg_result.credential_data, "serialize"):
            raw_blob = reg_result.credential_data.serialize()
        else:
            raw_blob = str(credential).encode("utf-8")
    except Exception:
        raw_blob = str(credential).encode("utf-8")
    existing = load_first_user()
    make_owner = existing is None
    save_credential(name, cred_id, raw_blob, make_owner=make_owner)
    session['username'] = name
    return jsonify({"status": "registered", "username": name})

@app.route("/begin_login", methods=["POST"])
def begin_login():
    user = load_first_user()
    if not user:
        return "no user", 400
    allow = [{"type": "public-key", "id": user["cred_id"]}]
    try:
        auth_data, state = server.authenticate_begin(allow, user_verification="required")
    except TypeError:
        try:
            auth_data, state = server.authenticate_begin([{"type":"public-key","id": user["cred_id"]}], user_verification="required")
        except Exception as e:
            return f"authenticate_begin failed: {e}", 500
    except Exception as e:
        return f"authenticate_begin failed: {e}", 500
    key = secrets.token_hex(16)
    FIDO2_STATES[key] = state
    session['fido2_state_key'] = key
    return jsonify(make_authenticate_dict(auth_data))

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
        resp = credential.get("response", {})
        clientDataJSON_b64 = resp.get("clientDataJSON") or credential.get("clientDataJSON")
        authenticatorData_b64 = resp.get("authenticatorData") or resp.get("authenticator_data")
        signature_b64 = resp.get("signature")
        rawId_b64 = credential.get("rawId") or credential.get("id")
        client_data = b64u_decode_str(clientDataJSON_b64)
        auth_data = b64u_decode_str(authenticatorData_b64)
        signature = b64u_decode_str(signature_b64)
        raw_id = b64u_decode_str(rawId_b64)
    except Exception as e:
        return f"bad assertion payload: {e}", 400
    stored = load_first_user()
    if not stored:
        return "no stored user", 400
    stored_cred = stored["cred_id"]
    try:
        server.authenticate_complete(state, [stored_cred], credential.get("id"), client_data, auth_data, signature)
    except TypeError:
        try:
            server.authenticate_complete(state, [stored_cred], credential)
        except Exception as e:
            return f"authenticate_complete failed: {e}", 500
    except Exception as e:
        return f"authenticate_complete failed: {e}", 500
    username = stored["name"]
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("SELECT name FROM users WHERE cred_id = ? LIMIT 1", (raw_id,))
        r = c.fetchone()
        if r:
            username = r[0]
    except Exception:
        pass
    finally:
        conn.close()
    session['username'] = username
    return jsonify({"status":"ok", "username": username})

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
