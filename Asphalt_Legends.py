import os
import sqlite3
import secrets
import time
import json
import hashlib
import hmac
import pathlib
import base64
import requests  
from flask import (
    Flask, render_template_string, request, jsonify, session,
    redirect, url_for, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room

# -------- CONFIG ----------
app = Flask(__name__, static_folder="static")
app.secret_key = os.urandom(32)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
HEADING_IMG = "/static/heading.png"  # place your heading image here
MAX_MESSAGES = 100
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
ALLOWED_VIDEO_EXT = {"mp4", "webm", "ogg"}
ALLOWED_AUDIO_EXT = {"mp3", "wav", "ogg", "m4a", "webm"}

# ensure static subfolders
pathlib.Path(os.path.join(app.static_folder, "uploads")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "stickers")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "gifs")).mkdir(parents=True, exist_ok=True)
pathlib.Path(os.path.join(app.static_folder, "avatars")).mkdir(parents=True, exist_ok=True)

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
    # FIX: Use COLLATE NOCASE for case-insensitive username lookup
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE name = ? COLLATE NOCASE LIMIT 1", (name,))
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

def emit_to_user(username, event, data):
    sid = USER_SID.get(username)
    if sid:
        socketio.emit(event, data, to=sid)

@socketio.on('register_socket')  # call from client once on connect
def handle_register(data):
    username = data.get('username')
    if username:
        USER_SID[username] = request.sid
        # Optionally join a room for user
        join_room(username)
        touch_user_presence(username)

@socketio.on('disconnect')
def handle_disconnect():
    # remove user from USER_SID if matches
    sid = request.sid
    for u,s in list(USER_SID.items()):
        if s == sid:
            USER_SID.pop(u, None)
            break

# Caller invites callee
@socketio.on('call:invite')
def on_call_invite(data):
    # data: { to: 'otherUser', from: 'caller', is_video: true, call_id: 'uuid' }
    to = data.get('to'); caller = data.get('from'); call_id = data.get('call_id')
    if not (to and caller and call_id):
        return
    CALL_INVITES[call_id] = {'caller': caller, 'callee': to, 'is_video': bool(data.get('is_video')), 'status': 'ringing', 'created': int(time.time())}
    # notify callee
    emit_to_user(to, 'call:incoming', {'call_id': call_id, 'from': caller, 'is_video': bool(data.get('is_video'))})
    # optionally ack to caller
    emit('call:invite_ack', {'ok': True, 'call_id': call_id}, to=request.sid)
    # persist call log
    save_call(call_id, caller, to, bool(data.get('is_video')), status='ringing')

# Callee accepts -> server forwards acceptance to caller
@socketio.on('call:accept')
def on_call_accept(data):
    call_id = data.get('call_id'); callee = data.get('from')
    call = CALL_INVITES.get(call_id)
    if not call:
        emit('call:error', {'error': 'no_call'}, to=request.sid); return
    call['status'] = 'accepted'
    # inform caller
    emit_to_user(call['caller'], 'call:accepted', {'call_id': call_id, 'from': callee})
    update_call_started(call_id)

# Callee/Caller reject/hangup
@socketio.on('call:hangup')
def on_call_hangup(data):
    call_id = data.get('call_id'); who = data.get('from')
    c = CALL_INVITES.pop(call_id, None)
    if c:
        emit_to_user(c['caller'], 'call:ended', {'call_id': call_id, 'by': who})
        emit_to_user(c['callee'], 'call:ended', {'call_id': call_id, 'by': who})
        update_call_ended(call_id)

# Signaling: forward SDP offer/answer & ICE candidates
@socketio.on('call:offer')
def on_call_offer(data):
    # data: { call_id, from, to, sdp }
    to = data.get('to'); sdp = data.get('sdp'); caller = data.get('from')
    emit_to_user(to, 'call:offer', {'from': caller, 'sdp': sdp, 'call_id': data.get('call_id')})

@socketio.on('call:answer')
def on_call_answer(data):
    to = data.get('to'); sdp = data.get('sdp'); sender = data.get('from')
    emit_to_user(to, 'call:answer', {'from': sender, 'sdp': sdp, 'call_id': data.get('call_id')})

@socketio.on('call:candidate')
def on_call_candidate(data):
    to = data.get('to'); candidate = data.get('candidate'); sender = data.get('from')
    emit_to_user(to, 'call:candidate', {'from': sender, 'candidate': candidate, 'call_id': data.get('call_id')})

# Optional in-call signals: mute/unmute, hold, switch-camera
@socketio.on('call:signal')
def on_call_signal(data):
    to = data.get('to'); payload = data.get('payload'); emit_to_user(to, 'call:signal', payload)

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
TYPING_USERS = set()

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

# new endpoints for lists used by the modern UI
@app.route("/stickers_list")
def stickers_list():
    return jsonify(list_static_folder("stickers"))

@app.route("/gifs_list")
def gifs_list():
    return jsonify(list_static_folder("gifs"))

# ---------- Avatar creation & caching (DiceBear) ----------
def dicebear_avatar_url(style, seed, params):
    # style e.g. 'adventurer' ; params is dict of query params
    qs = "&".join([f"{k}={requests.utils.quote(str(v))}" for k,v in params.items() if v is not None and v != ""])
    return f"https://avatars.dicebear.com/api/{style}/{requests.utils.quote(seed)}.svg?{qs}"

@app.route("/avatar_create")
def avatar_create_page():
    # small page with controls to create and preview DiceBear avatars; will POST to /avatar_save
    username = session.get('username')
    if not username:
        return redirect(url_for('index'))
    return render_template_string(AVATAR_CREATE_HTML, username=username)

@app.route("/avatar_save", methods=["POST"])
def avatar_save():
    # Save a DiceBear avatar (server fetch and cache) and update user's avatar path
    username = session.get('username')
    if not username:
        return "not signed in", 401
    body = request.get_json() or {}
    seed = body.get("seed") or username
    style = body.get("style") or "adventurer"
    params = body.get("params") or {}
    try:
        url = dicebear_avatar_url(style, seed, params)
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            return "could not fetch avatar", 500
        svg = r.content
        fn = f"avatars/{secure_filename(username)}_{secrets.token_hex(6)}.svg"
        path = os.path.join(app.static_folder, fn)
        with open(path, "wb") as f:
            f.write(svg)
        avatar_url = url_for('static', filename=fn)
        # update user avatar in DB
        conn = db_conn(); c = conn.cursor()
        c.execute("UPDATE users SET avatar = ? WHERE name = ?", (avatar_url, username))
        conn.commit(); conn.close()
        return jsonify({"status":"ok","avatar":avatar_url})
    except Exception as e:
        return f"error: {e}", 500

# simple poll voting endpoint (updates message attachments in place)
@app.route("/vote_poll", methods=["POST"])
def vote_poll():
    username = session.get('username')
    if not username: return "not signed in", 401
    body = request.get_json() or {}
    msg_id = body.get("message_id")
    option_idx = int(body.get("option_index", -1))
    if msg_id is None or option_idx < 0:
        return "bad request", 400
    conn = db_conn(); c = conn.cursor()
    c.execute("SELECT attachments FROM messages WHERE id = ? LIMIT 1", (msg_id,))
    r = c.fetchone()
    if not r:
        conn.close(); return "no message", 404
    attachments = json.loads(r[0] or "[]")
    changed = False
    for att in attachments:
        if att.get("type") == "poll":
            poll = att
            votes = poll.setdefault("votes", {})  # user->option_index
            # toggle vote: if same vote already, remove; else set
            prev = votes.get(username)
            if prev is not None and prev == option_idx:
                votes.pop(username, None)
            else:
                votes[username] = option_idx
            changed = True
            break
    if not changed:
        conn.close(); return "no poll found", 404
    c.execute("UPDATE messages SET attachments = ? WHERE id = ?", (json.dumps(attachments), msg_id))
    conn.commit(); conn.close()
    return jsonify({"status":"ok","attachments":attachments})

# ---------- Templates ----------
# AVATAR CREATE page HTML (separate smaller page)
AVATAR_CREATE_HTML = r'''<!-- AVATAR_CREATE_HTML (updated) -->
<!doctype html>
<html>
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Create Avatar</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial; background: #f8fafc; padding:18px;}
  .preview{ width:180px; height:180px; border-radius:50%; overflow:hidden; display:inline-block; background:#fff; box-shadow:0 6px 20px rgba(2,6,23,0.06); border:6px solid rgba(255,255,255,0.8); }
  .preview img{ width:100%; height:100%; object-fit:cover; display:block; }
  .tile{ cursor:pointer; border-radius:8px; padding:6px; background:#fff; box-shadow:0 6px 18px rgba(2,6,23,0.04); display:flex; align-items:center; justify-content:center; }
  .tile.selected{ outline:3px solid #6366f1; }
  .controls{ display:flex; gap:8px; flex-wrap:wrap; }
  label.switch { display:inline-flex; align-items:center; gap:8px; cursor:pointer; user-select:none; }
</style>
</head>
<body>
  <div class="max-w-3xl mx-auto">
    <h1 class="text-2xl font-bold mb-3">Create avatar — DiceBear (WhatsApp-style approx)</h1>
    <div class="flex gap-6">
      <div>
        <div class="preview mb-3" id="avatarPreview"><img id="avatarImg" src="/avatar/{{ username }}" alt="avatar preview" /></div>
        <div style="display:flex;gap:8px;">
          <button id="saveBtn" class="px-3 py-2 rounded bg-indigo-600 text-white">Save avatar</button>
          <a href="/chat" class="px-3 py-2 rounded bg-gray-200">Back to chat</a>
        </div>
      </div>
      <div style="flex:1;">
        <div class="mb-2">
          <label class="text-sm font-semibold">Style</label>
          <select id="styleSelect" class="p-2 border rounded w-full">
            <option value="adventurer">adventurer</option>
            <option value="avataaars">avataaars</option>
            <option value="bottts">bottts</option>
            <option value="pixel-art">pixel-art</option>
          </select>
        </div>

        <div class="mb-2">
          <label class="text-sm font-semibold">Seed (name or random)</label>
          <input id="seedInput" class="p-2 border rounded w-full" placeholder="seed (e.g. your name)" />
        </div>

        <div class="mb-2">
          <label class="text-sm font-semibold">Quick presets (click)</label>
          <div class="grid grid-cols-3 gap-2 mt-2" id="presetGrid"></div>
        </div>

        <div class="mb-2">
          <label class="text-sm font-semibold">Controls</label>
          <div class="controls mt-2">
            <div><label class="text-xs">Skin tone</label>
              <select id="skinTone" class="p-2 border rounded">
                <option value="">auto</option>
                <option value="T1">light</option>
                <option value="T2">fair</option>
                <option value="T3">tan</option>
                <option value="T4">brown</option>
                <option value="T5">dark</option>
              </select>
            </div>
            <div><label class="text-xs">Hair</label>
              <select id="hair" class="p-2 border rounded">
                <option value="">auto</option><option value="short">short</option><option value="long">long</option><option value="curly">curly</option><option value="bald">bald</option>
              </select>
            </div>
            <div><label class="text-xs">Eyes</label>
              <select id="eyes" class="p-2 border rounded"><option value="">auto</option><option value="smile">smile</option><option value="round">round</option><option value="squint">squint</option></select>
            </div>
            <div><label class="text-xs">Mouth</label>
              <select id="mouth" class="p-2 border rounded"><option value="">auto</option><option value="smile">smile</option><option value="serious">serious</option><option value="laugh">laugh</option></select>
            </div>
            <div><label class="text-xs">Accessory</label>
              <select id="accessory" class="p-2 border rounded"><option value="">none</option><option value="glasses">glasses</option><option value="earrings">earrings</option><option value="cap">cap</option></select>
            </div>
            <div style="display:flex;align-items:center;">
              <label class="switch"><input id="whatsappLike" type="checkbox" /> WhatsApp-style (approx)</label>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

<script>
function el(id){ return document.getElementById(id); }
const username = "{{ username }}";

// build params; we map UI controls into query params sent to proxy.
// DiceBear will accept unknown params (they are ignored if not supported by the chosen sprite), but we use common param names.
function buildParams(){
  const p = {};
  if(el('skinTone').value) p['skin[]'] = el('skinTone').value;
  if(el('hair').value) p['hair'] = el('hair').value;
  if(el('eyes').value) p['eyes'] = el('eyes').value;
  if(el('mouth').value) p['mouth'] = el('mouth').value;
  if(el('accessory').value) p['accessories[]'] = el('accessory').value;
  // whatsapp-like toggle forwards as a flag; proxy will apply a recommended set of params for that style.
  if(el('whatsappLike').checked) p['whatsapp_like'] = '1';
  return p;
}

function updatePreview(){
  const style = el('styleSelect').value;
  const seed = (el('seedInput').value || username || 'user').trim();
  const params = buildParams();
  const qs = new URLSearchParams(params).toString();
  // proxy_dicebear will fetch and return the final SVG (CORS-safe).
  const url = `/proxy_dicebear?style=${encodeURIComponent(style)}&seed=${encodeURIComponent(seed)}${qs ? '&' + qs : ''}`;
  el('avatarImg').src = url + '&_=' + Date.now(); // cache-bust
}

// wire events
el('styleSelect').addEventListener('change', updatePreview);
el('seedInput').addEventListener('input', updatePreview);
['hair','eyes','mouth','accessory','skinTone','whatsappLike'].forEach(id => {
  el(id).addEventListener('change', updatePreview);
});

// presets (random seeds)
const presetGrid = el('presetGrid');
for(let i=0;i<9;i++){
  const seed = 'user' + Math.random().toString(36).slice(2,8);
  const d = document.createElement('div'); d.className='tile'; d.textContent = seed;
  d.onclick = ()=>{
    el('seedInput').value = seed;
    updatePreview();
    document.querySelectorAll('.tile').forEach(t=> t.classList.remove('selected'));
    d.classList.add('selected');
  };
  presetGrid.appendChild(d);
}

el('saveBtn').addEventListener('click', async ()=>{
  const style = el('styleSelect').value;
  const seed = (el('seedInput').value || username || 'user').trim();
  const params = buildParams();
  const res = await fetch('/avatar_save', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ style, seed, params })});
  if(!res.ok){ alert('Save failed: '+await res.text()); return; }
  const j=await res.json(); if(j.avatar){ alert('Saved avatar'); location.href = '/chat'; }
});

// initial preview
updatePreview();
</script>
</body>
</html>
'''

from urllib.parse import quote_plus, urlencode
import requests
from flask import request, current_app, Response

def dicebear_avatar_url(style, seed, params):
    """
    Build DiceBear API URL (SVG). When params contains 'whatsapp_like' we apply
    a recommended set of parameters to approximate WhatsApp's cartoony avatar.
    Note: this is an approximation — official WhatsApp avatars are Meta's product.
    """
    # Remove control-only params
    params = dict(params)  # copy
    whatsapp_flag = params.pop('whatsapp_like', None)

    # Basic normalization: prefer avataaars/adventurer for cartoony faces
    if whatsapp_flag:
        # prefer 'adventurer' which gives good face/body shapes; 'avataaars' is also good
        style = style if style in ('adventurer','avataaars') else 'adventurer'
        # suggested WhatsApp-like defaults (approximate)
        defaults = {
            # common, general options — DiceBear will ignore unknown names for some styles,
            # but these help push toward a round, cartoony portrait.
            'backgroundType': 'circle',    # request circular background when supported
            'backgroundColor[]': 'transparent',
            'radius': '50',                # roundedness if supported
            # character options (names vary by sprite; proxy forwards them)
            'hair': params.get('hair','short'),
            'eyes': params.get('eyes','smile'),
            'mouth': params.get('mouth','smile'),
            'accessories[]': params.get('accessories[]', params.get('accessories','')),
            # skin tone shorthands if provided
            'skin[]': params.get('skin[]', params.get('skin','')),
        }
        # merge defaults but keep explicit params the user supplied
        for k,v in defaults.items():
            if k not in params or not params[k]:
                params[k] = v

    # Build base URL: DiceBear 9.x API returns SVG for /{style}/svg
    base = f"https://api.dicebear.com/9.x/{quote_plus(style)}/svg"
    # ensure seed is included
    qs = {'seed': seed}
    # add other params (flatten lists for arrays)
    for k, v in params.items():
        if v is None or v == '':
            continue
        # DiceBear expects repeated params for array-like fields; here we accept comma or array strings too.
        qs[k] = v

    url = base + '?' + urlencode(qs, doseq=True)
    return url

@app.route("/proxy_dicebear")
def proxy_dicebear():
    style = request.args.get('style','adventurer')
    seed = request.args.get('seed','user')
    # capture all query params except style/seed (so we can forward arbitrary controls)
    params = {k: request.args.get(k) for k in request.args.keys() if k not in ('style','seed')}
    try:
        url = dicebear_avatar_url(style, seed, params)
        # fetch svg from DiceBear
        r = requests.get(url, timeout=8)
        if r.status_code != 200:
            current_app.logger.error("DiceBear returned status %s for url %s", r.status_code, url)
            return "error fetching avatar", 502
        # return SVG (CORS safe because it comes from our server)
        return Response(r.content, mimetype='image/svg+xml')
    except Exception as e:
        current_app.logger.exception("proxy_dicebear error")
        return f"error: {e}", 500

# ---------- Templates (INDEX_HTML unchanged) ----------
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
  const r = await fetch(url, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify(body),
    credentials: 'include'
  });
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
# --- AVATAR page (full-featured generator using DiceBear HTTP API) ---
AVATAR_HTML = r'''<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Create Avatar — Asphalt Legends</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{ font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial; padding:12px; background:#f8fafc; }
  .tile { display:inline-flex; gap:8px; padding:8px; border-radius:8px; background:#fff; box-shadow:0 6px 18px rgba(2,6,23,0.04); cursor:pointer; text-align:center; flex-direction:column; width:92px; align-items:center; margin:6px; }
  #avatarPreview { width:240px; height:240px; border-radius:24px; background:#fff; display:flex; align-items:center; justify-content:center; box-shadow:0 10px 30px rgba(0,0,0,0.06); overflow:hidden; }
  #cameraPreview video{ width:320px; border-radius:12px; }
</style>
</head><body>
  <h2 class="text-xl font-bold mb-3">Create Avatar</h2>
  <p class="text-sm text-gray-600">You can either capture a photo (recommended suggestions) or manually tune the avatar controls (hair, eyes, accessories). This uses DiceBear's HTTP API for generation.</p>

  <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mt-4">
    <div>
      <div id="avatarPreview" class="mb-3">Preview</div>
      <div class="flex gap-2">
        <button id="downloadAvatar" class="px-3 py-2 bg-indigo-600 text-white rounded">Download</button>
        <button id="saveAvatar" class="px-3 py-2 bg-green-600 text-white rounded">Save to profile</button>
      </div>
      <div class="mt-3">
        <label class="text-sm font-semibold">Seed (randomize to get thousands of combinations)</label>
        <div class="flex gap-2 mt-2"><input id="seedInput" class="p-2 border rounded flex-1" placeholder="seed or leave empty for random"/><button id="randomSeed" class="px-3 py-2 bg-gray-200 rounded">Random</button></div>
      </div>
    </div>

    <div>
      <div class="mb-2"><strong>Capture / Upload Photo (optional)</strong></div>
      <div id="cameraPreview" class="mb-2"></div>
      <div class="flex gap-2">
        <button id="startCamera" class="px-3 py-2 bg-gray-100 rounded">Start Camera</button>
        <button id="takePhoto" class="px-3 py-2 bg-indigo-600 text-white rounded">Capture</button>
        <button id="uploadPhoto" class="px-3 py-2 bg-gray-100 rounded">Upload Photo</button>
      </div>
      <p class="text-xs text-gray-500 mt-2">If you capture/upload a photo we'll hash it and use the hash as the DiceBear seed to create recommended avatars (simple deterministic approach).</p>
    </div>

    <div>
      <div class="mb-2"><strong>Controls</strong></div>
      <div id="controls" class="grid grid-cols-1 gap-2">
        <label class="text-xs">Style</label>
        <select id="styleSelect" class="p-2 border rounded">
          <option value="adventurer">Adventurer</option>
          <option value="avataaars">Avataaars</option>
          <option value="big-smile">Big Smile</option>
          <option value="pixel-art">Pixel Art</option>
        </select>

        <label class="text-xs mt-2">Hair</label>
        <div id="hairTiles" class="flex flex-wrap"></div>

        <label class="text-xs mt-2">Eyes</label>
        <div id="eyesTiles" class="flex flex-wrap"></div>

        <label class="text-xs mt-2">Accessories</label>
        <div id="accTiles" class="flex flex-wrap"></div>
      </div>
    </div>
  </div>

<script>
/*
  Avatar page JS:
  - Provides tile-based selectors for several parameters (hair, eyes, accessories)
  - Builds a DiceBear HTTP API URL and previews the SVG
  - Allows capture/upload of photo -> hash to seed -> preview avatars
  - Save to server via /save_avatar (expects data:image/svg+xml;base64,...)
*/

const previewEl = document.getElementById('avatarPreview');
const seedInput = document.getElementById('seedInput');
const styleSelect = document.getElementById('styleSelect');
let selectedParams = { hair: '', eyes: '', accessories: '' };

// simple tile palettes (small subset; you can expand these arrays)
const hairOptions = ['short', 'long', 'bun', 'mohawk', 'bald'];
const eyesOptions = ['normal', 'smile', 'surprised', 'wink'];
const accOptions = ['glasses', 'beanie', 'earring', 'hat', 'none'];

function buildDicebearUrl(){
  const style = styleSelect.value || 'adventurer';
  const seed = seedInput.value || Math.random().toString(36).slice(2,10);
  const params = new URLSearchParams();
  params.set('seed', seed);
  // many DiceBear styles accept different query params. We set generic ones for demonstration.
  if(selectedParams.hair) params.set('hair', selectedParams.hair);
  if(selectedParams.eyes) params.set('eyes', selectedParams.eyes);
  if(selectedParams.accessories && selectedParams.accessories !== 'none') params.set('accessories', selectedParams.accessories);
  params.set('backgroundColor', 'transparent');
  // use the 9.x DiceBear API path
  return `https://api.dicebear.com/9.x/${encodeURIComponent(style)}/svg?${params.toString()}`;
}

async function renderPreview(){
  const url = buildDicebearUrl();
  // fetch SVG (as text) then show inline; also prepare a data URL for downloading
  const r = await fetch(url);
  if(!r.ok) {
    previewEl.innerHTML = 'Could not fetch avatar';
    return;
  }
  const svgText = await r.text();
  // sanitize (basic) and show
  previewEl.innerHTML = svgText;
  // store for download
  previewEl.dataset.svg = svgText;
}

document.getElementById('randomSeed').addEventListener('click', ()=>{
  seedInput.value = Math.random().toString(36).slice(2,10);
  renderPreview();
});

styleSelect.addEventListener('change', renderPreview);
seedInput.addEventListener('change', renderPreview);

// build tiles UI
function mkTiles(containerId, options, paramKey){
  const el = document.getElementById(containerId);
  el.innerHTML = '';
  options.forEach(opt=>{
    const t = document.createElement('div'); t.className='tile';
    t.innerHTML = `<div style="font-size:28px;">${opt[0].toUpperCase()}</div><div style="font-size:12px;">${opt}</div>`;
    t.onclick = ()=>{
      selectedParams[paramKey] = opt;
      // highlight selection
      Array.from(el.children).forEach(c=> c.style.outline='');
      t.style.outline = '2px solid #4f46e5';
      renderPreview();
    };
    el.appendChild(t);
  });
}
mkTiles('hairTiles', hairOptions, 'hair');
mkTiles('eyesTiles', eyesOptions, 'eyes');
mkTiles('accTiles', accOptions, 'accessories');

// camera & upload
let stream = null;
const cameraContainer = document.getElementById('cameraPreview');
document.getElementById('startCamera').addEventListener('click', async ()=>{
  if(stream){ // stop
    stream.getTracks().forEach(t=>t.stop()); stream=null; cameraContainer.innerHTML=''; return;
  }
  try{
    stream = await navigator.mediaDevices.getUserMedia({ video:true, audio:false });
    const v = document.createElement('video'); v.autoplay = true; v.playsInline = true; v.srcObject = stream;
    cameraContainer.innerHTML=''; cameraContainer.appendChild(v);
  }catch(e){ alert('Camera error: ' + e.message); }
});

document.getElementById('takePhoto').addEventListener('click', async ()=>{
  if(!stream){ alert('Start camera first'); return; }
  const video = cameraContainer.querySelector('video');
  if(!video) return;
  const c = document.createElement('canvas'); c.width = video.videoWidth || 400; c.height = video.videoHeight || 400;
  const ctx = c.getContext('2d'); ctx.drawImage(video, 0, 0, c.width, c.height);
  const dataUrl = c.toDataURL('image/png');
  // hash the image data and use as seed
  const hashHex = await hashDataUrl(dataUrl);
  seedInput.value = 'photo-' + hashHex.slice(0,10);
  renderPreview();
});

document.getElementById('uploadPhoto').addEventListener('click', ()=>{
  const inp = document.createElement('input'); inp.type='file'; inp.accept='image/*';
  inp.onchange = async (ev)=>{
    const f = ev.target.files[0];
    const reader = new FileReader();
    reader.onload = async (e)=>{
      const dataUrl = e.target.result;
      const hh = await hashDataUrl(dataUrl);
      seedInput.value = 'upload-' + hh.slice(0,10);
      renderPreview();
    };
    reader.readAsDataURL(f);
  };
  inp.click();
});

async function hashDataUrl(dataUrl){
  const b = atob(dataUrl.split(',')[1]);
  const arr = new Uint8Array(b.length);
  for(let i=0;i<b.length;i++) arr[i]=b.charCodeAt(i);
  const digest = await crypto.subtle.digest('SHA-1', arr);
  return Array.from(new Uint8Array(digest)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

document.getElementById('downloadAvatar').addEventListener('click', ()=>{
  const svg = previewEl.dataset.svg;
  if(!svg) return alert('Generate avatar first');
  const blob = new Blob([svg], { type: 'image/svg+xml' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'avatar.svg'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
});

document.getElementById('saveAvatar').addEventListener('click', async ()=>{
  const svg = previewEl.dataset.svg;
  if(!svg) return alert('Generate avatar first');
  const b64 = btoa(unescape(encodeURIComponent(svg)));
  const dataUri = 'data:image/svg+xml;base64,' + b64;
  // send to server to save and get cached url
  const username = prompt('Save avatar for which username?', 'user');
  if(!username) return;
  const r = await fetch('/save_avatar', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username, image: dataUri })});
  const j = await r.json();
  if(j.ok){
    alert('Avatar saved: ' + j.url);
    // open profile page in parent and set preview if possible
    try{ window.opener && window.opener.postMessage({ avatarSaved: j.url }, '*'); }catch(e){}
  } else {
    alert('Save failed: ' + (j.error || 'unknown'));
  }
});

// initial render
renderPreview();
</script>
</body></html>
'''
# ---- CHAT HTML (heavily modified) ----
# --- CHAT page: updated with emoji-mart v5, sticker/gif/avatar/emoji panel, typing indicator, attach menu, poll modal, avatar flow gggggggggggggggggggggggggggggggggggggg---
CHAT_HTML = r'''<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>InfinityChatter ♾️ — Chat</title>
  <script src="https://cdn.tailwindcss.com"></script>

  <!-- emoji-mart v5 browser build (exposes global EmojiMart for vanilla JS) -->
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/emoji-mart@5.6.0/dist/browser.css">
  <script src="https://cdn.jsdelivr.net/npm/emoji-mart@5.6.0/dist/browser.js"></script>

  <style>
    :root{
      --glass-bg: rgba(255,255,255,0.8);
      --download-bg: rgba(17,24,39,0.7);
    }

    /* page background image */
    body{
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      background: url('/static/IMG_5939.jpeg') no-repeat center center fixed;
      background-size: cover;
      margin:0;
      -webkit-font-smoothing:antialiased;
      -moz-osx-font-smoothing:grayscale;
    }

    header {
      position: fixed;
      left: 0;
      right: 0;
      top: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 12px;
      background: linear-gradient(90deg, rgba(255,255,255,0.98), rgba(248,250,252,0.95));
      z-index: 40;
      padding: 10px 14px;
      border-bottom: 1px solid rgba(0,0,0,0.04);
      box-sizing: border-box;
      flex-wrap: wrap;
      text-align: center;
    }
    
    /* wrapper centers everything */
    .heading-wrapper {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 6px;
      width: 100%;
      max-width: 980px;
    }
    
    .heading-wrapper img {
      height: 56px;
      width: auto;
      border-radius: 10px;
      object-fit: cover;
    }
    
    .heading-title {
      font-weight: 800;
      font-size: 1.05rem;
      line-height: 1;
    }
    
    /* tablets */
    @media (min-width: 768px) {
      header { padding: 12px 18px; }
      .heading-wrapper { flex-direction: column; align-items: center; }
      .heading-wrapper img { height: 70px; }
      .heading-title { font-size: 1.25rem; }
    }
    
    /* laptops/desktops: slightly smaller height + keep centered */
    @media (min-width: 1024px) {
      header { padding: 10px 20px; }
      .heading-wrapper { flex-direction: column; align-items: center; text-align: center; }
      .heading-wrapper img { height: 64px; }
      .heading-title { font-size: 1.4rem; margin-left: 0; }
    }
    
    /* header action buttons */
    .header-actions {
      position: absolute;
      right: 12px;
      top: 12px;
      display: flex;
      gap: 8px;
      align-items: center;
    }
    
    .profile-name {
      cursor: pointer;
      padding: 6px 10px;
      border-radius: 10px;
      background: white;
      box-shadow: 0 6px 18px rgba(2,6,23,0.04);
    }
    
    /* give first message a bit of breathing room under header */
    .chat-messages {
      padding-top: calc(var(--header-height, 80px) + 12px);
    }

    main{ padding:120px 12px 200px; max-width:980px; margin:0 auto; min-height:calc(100vh - 260px); box-sizing:border-box; }
    .msg-row{ margin-bottom:12px; display:flex; gap:8px; align-items:flex-start; }
    .msg-body{ display:flex; flex-direction:column; align-items:flex-start; min-width:0; }
    .bubble{ position:relative; padding: 10px 36px 10px 14px; border-radius:12px; display:inline-block; word-break:break-word; white-space:pre-wrap; background-clip:padding-box; box-shadow: 0 6px 18px rgba(2,6,23,0.04); }
    .me{ background: linear-gradient(90deg,#e6ffed,#dcffe6); border-bottom-right-radius:6px; align-self:flex-end; margin-left:auto; }
    .them{ background: rgba(255,255,255,0.95); border-bottom-left-radius:6px; margin-right:auto; }
    .bubble .three-dot { position:absolute; top:8px; right:8px; background:transparent; border:none; font-size:1.05rem; padding:4px; cursor:pointer; color:#111827; border-radius:6px; }
    .msg-meta-top{ font-size:0.75rem; color:#6b7280; display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:6px; width:100%; transition: color 0.2s ease; }

    /* attachments & previews */
    #attachmentPreview{ padding:8px; border-bottom:1px solid rgba(0,0,0,0.06); display:none; }
    .preview-item{ position:relative; display:inline-block; margin-right:8px; vertical-align:top; max-width:90px; }
    .preview-item img, .preview-item video{ max-width:100%; border-radius:8px; display:block; }
    .media-container{ position:relative; display:inline-block; width:100%; max-width:420px; }
    .media-container img.thumb{ display:block; width:100%; border-radius:10px; }
    .media-container .play-overlay{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; pointer-events:none; }
    .media-container .play-overlay .play-circle{ width:56px; height:56px; background: rgba(0,0,0,0.6); border-radius:999px; display:flex; align-items:center; justify-content:center; color:white; font-size:22px; }
    .download-btn{ position:absolute; top:8px; right:8px; width:36px; height:36px; border-radius:999px; display:flex; align-items:center; justify-content:center; text-decoration:none; color:white; background:var(--download-bg); font-size:1.05rem; z-index:10; box-shadow:0 6px 18px rgba(0,0,0,0.2); }
    .doc-link{ display:inline-flex; align-items:center; gap:10px; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 6px 18px rgba(2,6,23,0.04); margin-top:8px; text-decoration:none; color:#111827; }

    .reaction-bar{ display:flex; gap:6px; margin-top:8px; align-items:center; }
    .reaction-pill{ display:inline-flex; align-items:center; gap:6px; padding:4px 8px; border-radius:999px; background:rgba(255,255,255,0.95); box-shadow:0 6px 18px rgba(2,6,23,0.04); font-size:0.85rem; }
    .reaction-emoji{ width:20px; height:20px; display:inline-flex; align-items:center; justify-content:center; font-size:14px; }

    /* ===== Liquid Glass Responsive Composer ===== */
    .composer {
      position: fixed;
      left: 0;
      right: 0;
      bottom: calc(env(safe-area-inset-bottom, 0) + 8px);
      display: flex;
      justify-content: center;
      padding: clamp(8px, 2.4vw, 18px);
      z-index: 90;
      transition: bottom 0.28s ease-in-out, transform 0.28s ease-in-out;
      pointer-events: auto;
    }
    
    .composer.up {
      transform: translateY(-60vh); /* matches drawer height */
    }
    
    .composer-main {
      display: flex;
      border-radius: 14px;
      padding: 8px 10px;
      gap: 6px;
      align-items: center;
      width: min(980px, calc(100% - 32px));
      max-width: 980px;
      margin: 0 auto;           /* <-- keeps it centered */
      position: relative;
      overflow: hidden;
      
      /* frosted translucent look */
      background: linear-gradient(
        135deg,
        rgba(255, 255, 255, 0.35) 0%,
        rgba(245, 247, 250, 0.20) 100%
      );
      backdrop-filter: blur(16px) saturate(1.35) contrast(1.05);
      -webkit-backdrop-filter: blur(16px) saturate(1.35) contrast(1.05);
    
      /* inner + outer glow */
      box-shadow: 0 8px 28px rgba(8, 15, 30, 0.12),
                  inset 0 1px 1px rgba(255, 255, 255, 0.45);
      border: 1px solid rgba(255, 255, 255, 0.25);
      transition: box-shadow .25s ease, transform .25s ease;
      flex-wrap: nowrap;
      z-index: 1;
    }
    
    /* sheen highlight */
    .composer-main::after {
      content: "";
      position: absolute;
      top: -40%;
      left: -20%;
      width: 140%;
      height: 80%;
      background: linear-gradient(
        120deg,
        rgba(255, 255, 255, 0.55) 0%,
        rgba(255, 255, 255, 0.12) 40%,
        rgba(255, 255, 255, 0) 80%
      );
      transform: rotate(-12deg);
      filter: blur(20px);
      opacity: 0.6;
      pointer-events: none;
      z-index: 0;
      transition: opacity .25s ease, transform .25s ease;
    }
    
    /* Elevated (focused/open state) */
    .composer-main.glass-elevated {
      transform: translateY(-6px);
      backdrop-filter: blur(22px) saturate(1.5) contrast(1.07);
      -webkit-backdrop-filter: blur(22px) saturate(1.5) contrast(1.07);
      box-shadow: 0 18px 40px rgba(6, 10, 25, 0.16),
                  inset 0 1px 2px rgba(255, 255, 255, 0.55);
    }
    .composer-main.glass-elevated::after {
      opacity: 0.85;
      transform: rotate(-10deg) translateY(-6px);
    }
    
    /* Buttons (plus, mic, emoji) */
    .plus-small, .mic-btn, #emojiBtn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: clamp(36px, 7vw, 48px);
      height: clamp(36px, 7vw, 48px);
      border-radius: 12px;
      border: 1px solid rgba(255,255,255,0.18);
      background: rgba(255,255,255,0.4);
      backdrop-filter: blur(6px) saturate(1.2);
      -webkit-backdrop-filter: blur(6px) saturate(1.2);
      box-shadow: 0 6px 16px rgba(2, 6, 23, 0.08);
      z-index: 5;
      flex: 0 0 auto;
      -webkit-tap-highlight-color: transparent;
      transition: background .2s ease;
    }
    .plus-small:hover, .mic-btn:hover, #emojiBtn:hover {
      background: rgba(255,255,255,0.55);
    }
    
    /* circular mic on narrow screens */
    @media (max-width:420px){
      .mic-btn {
        border-radius: 999px;
        width: clamp(40px,9vw,52px);
        height: clamp(40px,9vw,52px);
      }
    }
    
    /* Textarea */
    .textarea {
      flex: 1 1 auto;
      min-height: 40px;
      font-size: 0.9rem;
      padding: 6px 8px;
      max-height: 30vh;
      border-radius: 12px;
      border: 0;
      resize: none;
      background: rgba(255,255,255,0.75);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      color: #0b1220;
      outline: none;
      box-sizing: border-box;
      line-height: 1.4;
      transition: background .2s ease;
    }
    .textarea:focus {
      background: rgba(255,255,255,0.9);
    }
    
    /* Send button */
    #sendBtn {
      flex: 0 0 auto;
      padding: clamp(8px,1.8vw,12px) clamp(12px,2.2vw,16px);
      margin-left: 6px;
      border-radius: 12px;
      font-size: clamp(.9rem,1.6vw,1rem);
      background: linear-gradient(135deg, #6366f1, #4f46e5);
      color: white;
      box-shadow: 0 6px 20px rgba(79,70,229,0.35);
      transition: transform .15s ease, box-shadow .15s ease;
    }
    #sendBtn:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(79,70,229,0.45); }
    
    /* Extra tiny screens: hide plus */
    @media (max-width: 380px){
      .plus-small { display:none; }
      .composer-main { gap: 6px; padding: 8px; }
    }
    /* Tablet sizes (≥ 600px) → medium */
    @media (min-width: 600px) {
      .composer-main {
        border-radius: 18px;
        padding: 12px 14px;
        gap: 10px;
      }
      .textarea {
        min-height: 48px;
        font-size: 1rem;
        padding: 8px 10px;
      }
      .plus-small, .mic-btn, #emojiBtn {
        width: 42px;
        height: 42px;
      }
    }
    
    /* Laptop / Desktop (≥ 1024px) → larger and more spacious */
    @media (min-width: 1024px) {
      .composer-main {
        border-radius: 22px;
        padding: 14px 18px;
        gap: 14px;
      }
      .textarea {
        min-height: 56px;
        font-size: 1.05rem;
        padding: 10px 14px;
      }
      .plus-small, .mic-btn, #emojiBtn {
        width: 48px;
        height: 48px;
      }
      #sendBtn {
        font-size: 1rem;
        padding: 12px 18px;
        border-radius: 14px;
      }
    }
    .emoji-mart {
      position: absolute !important;
      left: 0 !important;
      right: 0 !important;
      bottom: 0 !important;
      top: auto !important;
      width: 100% !important;
      height: 100% !important;
      max-width: none !important;
      border-radius: 0 !important;
      box-shadow: none !important;
      border-top: 1px solid #e5e7eb !important;
    }
    
    .emoji-drawer.active {
      display: flex;
    }
    
    /* Header with drag handle */
    .emoji-drawer-header {
      height: 28px;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .drag-bar {
      width: 42px;
      height: 4px;
      border-radius: 4px;
      background: rgba(0,0,0,0.2);
    }
    
    /* Content scrollable */
    .emoji-drawer-content {
      flex: 1;
      overflow-y: auto;
      padding: 12px;
      display: flex;
      flex-direction: column;
      gap: 16px;
    }
    
    /* Emoji grid */
    .emoji-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(40px, 1fr));
      gap: 10px;
      font-size: 1.6rem;
      text-align: center;
    }
    
    /* GIFs */
    .gif-grid {
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
      gap: 10px;
    }
    .gif-grid img {
      width: 100%;
      border-radius: 10px;
      cursor: pointer;
      transition: transform .2s;
    }
    .gif-grid img:hover {
      transform: scale(1.05);
    }
    
    /* Push composer up when drawer open */
    .composer {
      transition: bottom 0.3s ease;
    }

    .composer.up {
      bottom: 280px;  /* match emoji panel height */
    }
    
    .attach-menu-vertical{ position:fixed; right:18px; bottom:100px; display:flex; flex-direction:column; gap:10px; border-radius:12px; z-index:80; }
    .attach-card{ background:white; padding:10px 14px; min-width:140px; box-shadow:0 10px 30px rgba(0,0,0,0.12); display:flex; gap:8px; align-items:center; cursor:pointer; }

    /* sticker panel */
    #stickerPanel{ position:fixed; left:0; right:0; bottom:76px; height:40vh; background:linear-gradient(180deg,#fff,#f9fafb); border-top-left-radius:14px; border-top-right-radius:14px; box-shadow:0 -10px 30px rgba(0,0,0,0.06); padding:12px; display:none; z-index:75; overflow:auto; }
    .panel-tabs{ display:flex; gap:8px; margin-bottom:8px; }
    .panel-tabs button{ padding:6px 10px; border-radius:999px; border:0; background:#f3f4f6; cursor:pointer; }
    .avatar-controls .tile { display:inline-flex; gap:8px; padding:8px; border-radius:8px; background:#fff; box-shadow:0 6px 18px rgba(2,6,23,0.04); cursor:pointer; text-align:center; flex-direction:column; width:92px; align-items:center; }

    /* polling modal */
    .modal { position:fixed; inset:0; display:flex; align-items:center; justify-content:center; background:rgba(0,0,0,0.4); z-index:120; }
    .modal-card { width:100%; max-width:560px; background:white; border-radius:12px; padding:16px; }

    /* small utilities */
    .hidden{ display:none; }
    /* Bottom drawer panel */
    #stickerPanel {
      position: fixed;
      left: 0;
      right: 0;
      bottom: 0;
      height: 60vh; /* adjustable */
      background: rgba(255,255,255,0.98);
      backdrop-filter: blur(12px) saturate(1.25);
      -webkit-backdrop-filter: blur(12px) saturate(1.25);
      border-top-left-radius: 18px;
      border-top-right-radius: 18px;
      box-shadow: 0 -6px 18px rgba(0,0,0,0.08);
      transform: translateY(100%);   /* hidden by default */
      transition: transform 0.28s ease-in-out;
      z-index: 120;
      overflow-y: auto;
    }
    
    /* When active, slide up */
    #stickerPanel.active {
      transform: translateY(0);
    }
    #emojiGrid .emoji-mart {
      width: 100% !important;
      height: 100% !important;
      border: none !important;
      box-shadow: none !important;
      border-radius: 0 !important;
    }
    /* Incoming call banner */
    .incoming-call-banner {
      position: fixed;
      top: calc(var(--header-height, 56px) + 8px);
      left: 0;
      right: 0;
      background: #ffffffee;
      border: 1px solid #ddd;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      z-index: 200;
      padding: 12px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .incoming-call-banner.hidden {
      display: none;
    }
    
    .incoming-call-banner .caller-info {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .incoming-call-banner .caller-info #incomingLabel {
      font-size: 0.9rem;
      color: #555;
    }
    .incoming-call-banner .caller-info #incomingCallerName {
      font-size: 1.1rem;
      font-weight: bold;
      color: #111;
    }
    
    .incoming-call-banner .banner-buttons {
      display: flex;
      gap: 12px;
    }
    .incoming-call-banner .btn-decline,
    .incoming-call-banner .btn-accept {
      padding: 8px 14px;
      border: none;
      border-radius: 8px;
      font-size: 0.9rem;
      cursor: pointer;
    }
    .btn-decline {
      background: #f87171;  /* red */
      color: white;
    }
    .btn-accept {
      background: #34d399;  /* green */
      color: white;
    }
    
    /* In-call control buttons (header area) */
    .in-call-controls {
      position: fixed;
      top: 12px;
      left: 12px;
      display: flex;
      gap: 8px;
      z-index: 210;
    }
    .in-call-controls.hidden {
      display: none;
    }
    .ic-btn {
      background: rgba(255,255,255,0.9);
      border: none;
      padding: 6px 10px;
      border-radius: 8px;
      font-size: 1.2rem;
      cursor: pointer;
      box-shadow: 0 3px 8px rgba(0,0,0,0.15);
    }
    .ic-btn:hover {
      background: rgba(255,255,255,1);
    }
    .chat-audio {
      width: 250px;
      height: 40px;
    }
  </style>
</head>
<body>

      <!-- Header -->
      <header>
        <div class="heading-wrapper" role="banner" aria-label="App header">
          <img src="{{ heading_img }}" alt="Heading image" />
          <div class="heading-title">Asphalt <span style="color:#be185d;">Legends</span></div>
        </div>
        
        <!-- Incoming Call Banner / Modal -->
        <div id="incomingCallBanner" class="incoming-call-banner hidden">
          <div class="banner-content">
            <div class="caller-info">
              <span id="incomingLabel">Incoming Call</span>
              <span id="incomingCallerName"></span>
            </div>
            <div class="banner-buttons">
              <button id="declineCallBtn" class="btn-decline">Decline</button>
              <button id="acceptCallBtn" class="btn-accept">Accept</button>
            </div>
          </div>
        </div>
        
        <!-- In-Call Controls on Header (top-left) -->
        <div id="inCallControls" class="in-call-controls hidden">
          <button id="btnHangup" class="ic-btn hangup">📞</button>
          <button id="btnMute" class="ic-btn mute">🔇</button>
          <button id="btnToggleVideo" class="ic-btn toggle-video">🎥</button>
          <button id="btnSwitchCam" class="ic-btn switch-cam">🔄</button>
        </div>
        
        <div class="header-actions" role="navigation" aria-label="Profile actions">
          <div id="profileBtn" class="profile-name">{{ username }}</div>
          <div id="profileMenu" class="menu hidden"
            style="display:none; position: absolute; right:12px; top:48px; border-radius:12px; overflow:hidden;">
            <div id="viewProfileBtn" class="attach-card">Profile</div>
            <form method="post" action="{{ url_for('logout') }}" style="margin:0;">
              <button type="submit" class="attach-card">Logout</button>
            </form>
          </div>
        </div>
      </header>
    
      <!-- Messages -->
      <main>
        <div id="messages" class="mb-6" aria-live="polite" style="padding-top:calc(80px + 1rem);"></div>
      </main>
    
      <!-- Bottom Drawer: Stickers/GIFs/Avatars/Emoji -->
      <div id="stickerPanel" aria-hidden="true" class="emoji-drawer">
          <div class="drag-bar" style="
              width:40px;
              height:5px;
              background:#ccc;
              border-radius:3px;
              margin:8px auto;
          "></div>

        <div class="emoji-drawer-header">
          <div class="drag-bar"></div>
          <button id="closeStickerPanel" class="ml-auto px-2 py-1 rounded bg-gray-100">Close</button>
        </div>
        <div class="panel-tabs">
          <button id="tab_stickers">Stickers</button>
          <button id="tab_gifs">GIFs</button>
          <button id="tab_avatars">Avatars</button>
          <button id="tab_emoji">Emoji</button>
        </div>
        <div id="panelContent" class="emoji-drawer-content">
          <div id="gifGrid" class="gif-grid hidden"></div>
          <div id="emojiGrid" class="emoji-grid hidden"></div>
        </div>
      </div>
    
      <!-- Composer -->
      <div class="composer" id="composer" aria-label="Composer area">
        <div class="composer-inner">
          <div id="attachmentPreview"></div>
    
          <div class="composer-main" id="composerMain" role="form" aria-label="Message composer">
            <button id="plusBtn" class="plus-small bg-white shadow" style="font-size:2rem;" aria-label="Attach">＋</button>
    
            <!-- vertical attachment menu -->
            <div id="attachMenuVertical" class="attach-menu-vertical" style="display:none;">
              <div class="attach-card" data-action="document">📁<div>  Documents</div></div>
              <div class="attach-card" data-action="camera">📷<div>  Camera</div></div>
              <div class="attach-card" data-action="gallery">🌇<div>  Gallery</div></div>
              <div class="attach-card" data-action="audio">🎧<div>  Audio</div></div>
              <div class="attach-card" data-action="location">🌐<div>  Location</div></div>
              <div class="attach-card" id="pollBtn">🗳️<div>  Poll</div></div>
            </div>
    
            <textarea id="msg" class="textarea" placeholder="Type a message..." maxlength="1200"
              aria-label="Message input"></textarea>
    
            <!-- emoji button opens drawer -->
            <button id="emojiBtn" title="Emoji" class="w-11 h-11 rounded-lg bg-white" aria-label="Emoji">😊</button>
    
            <!-- mic button -->
            <button id="mic" class="mic-btn" aria-label="Voice message" aria-pressed="false"
              title="Hold to record or click to toggle">🎙️</button>
    
            <button id="sendBtn" class="px-4 py-2 rounded bg-green-600 text-white" aria-label="Send">Send</button>
          </div>
        </div>
      </div>
    
      <!-- Poll modal -->
      <div id="pollModal" class="hidden" style="display:none;">
        <div class="modal">
          <div class="modal-card">
            <h3>Create Poll</h3>
            <form id="pollForm">
              <div><input id="poll_question" placeholder="Your question" class="w-full p-2 border rounded mb-2"></div>
              <div id="pollOptions">
                <input name="option" placeholder="Option 1" class="w-full p-2 border rounded mb-2">
                <input name="option" placeholder="Option 2" class="w-full p-2 border rounded mb-2">
              </div>
              <div class="flex gap-2">
                <button id="addPollOption" type="button" class="px-3 py-1 bg-gray-100 rounded">Add option</button>
                <button class="px-3 py-1 bg-indigo-600 text-white rounded">Create Poll</button>
                <button id="cancelPoll" type="button" class="px-3 py-1 bg-gray-200 rounded">Cancel</button>
              </div>
            </form>
          </div>
        </div>
      </div>
    
      <!-- Profile Modal -->
      <div id="profileModal" class="hidden fixed inset-0 items-center justify-center bg-black/40 z-[60]">
        <div class="bg-white rounded-lg p-4 w-96">
          <div class="flex items-center justify-between mb-3">
            <div>
              <div class="text-lg font-bold">Profile</div>
            </div>
            <button id="closeProfile" class="text-gray-500">✕</button>
          </div>
          <form id="profileForm" enctype="multipart/form-data">
            <div class="mb-2"><label class="text-xs">Display name</label><input id="profile_display_name" name="name"
                class="w-full p-2 border rounded" value="{{ username }}" /></div>
            <div class="mb-2"><label class="text-xs">Status</label><input id="profile_status" name="status"
                class="w-full p-2 border rounded" value="{{ user_status }}" /></div>
            <div class="mb-2">
              <label class="text-xs">Avatar</label>
              <div style="display:flex;gap:8px;">
                <button id="createAvatarBtn" type="button" class="px-3 py-2 bg-green-600 text-white rounded">Create
                  Avatar</button>
                <div id="currentAvatarPreview"
                  style="min-width:64px;min-height:64px;background:#f3f4f6;border-radius:8px;"></div>
              </div>
            </div>
            <div class="flex gap-2">
              <button type="submit" class="px-3 py-2 rounded bg-indigo-600 text-white">Save</button>
              <button id="profileCancel" type="button" class="px-3 py-2 rounded bg-gray-200">Cancel</button>
            </div>
            <div id="profileMsg" class="text-sm mt-2 text-gray-500"></div>
          </form>
        </div>
      </div>
    
      <!-- Incoming call banner -->
      <div id="incomingCall"
        style="display:none; position:fixed; left:50%; transform:translateX(-50%); top:12px; z-index:100; background:#fff; padding:8px 12px; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,.12);">
        <div id="incomingText">Incoming call</div>
        <div style="display:flex;gap:8px;margin-top:8px;">
          <button id="acceptCall" class="px-3 py-1 rounded bg-green-600 text-white">Accept</button>
          <button id="declineCall" class="px-3 py-1 rounded bg-red-500 text-white">Decline</button>
        </div>
      </div>
    <div id="emojiPanel" class="emoji-panel"></div>
</body>
<!-- include socket.io and other scripts (socket server expected) -->
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>

<script>
/* =========================
   App state & helpers
   ========================= */
const socket = io();
let myName = "{{ username }}";
let lastId = 0;
let stagedFiles = [];
let typingTimer = null;
let isTyping = false;
const messagesEl = document.getElementById('messages');
const inputEl = document.getElementById('msg');
const composerEl = document.getElementById('composer');
const composerMain = document.getElementById('composerMain');

/* simpler escape */
function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }

function showStickerPanel() {
  const panel = document.getElementById('stickerPanel');
  panel.classList.add('active'); // slide up
  document.querySelector('.composer')?.classList.add('up');
}

function hideStickerPanel() {
  const panel = document.getElementById('stickerPanel');
  panel.classList.remove('active'); // slide down
  document.querySelector('.composer')?.classList.remove('up');
}

/* =========================
   Typing indicator handling
   ========================= */
inputEl.addEventListener('input', ()=> {
  if(!isTyping){
    socket.emit('typing', { from: myName });
    isTyping = true;
  }
  clearTimeout(typingTimer);
  typingTimer = setTimeout(()=> {
    if(isTyping){ socket.emit('stop_typing', { from: myName }); isTyping=false; }
  }, 1200);
});

/* Show typing text when socket receives it */
socket.on('typing', (d)=> {
  const nodeId = 'typing-'+(d.from||'user');
  if(document.getElementById(nodeId)) return;
  const el = document.createElement('div'); el.id = nodeId; el.className='msg-row';
  el.innerHTML = `<div class="msg-body"><div class="bubble them"><em>${escapeHtml(d.from||'Someone')} is typing…</em></div></div>`;
  messagesEl.appendChild(el);
  messagesEl.scrollTop = messagesEl.scrollHeight;
});
socket.on('stop_typing', (d)=> {
  const nodeId = 'typing-'+(d.from||'user'); const el = document.getElementById(nodeId); if(el) el.remove();
});

/* =========================
   Emoji-mart picker integration (v5)
   ========================= */
let emojiPicker = null;
document.getElementById('emojiBtn').addEventListener('click', (ev)=>{
  ev.stopPropagation();
  if(!emojiPicker){
      emojiPicker = new EmojiMart.Picker({
        onEmojiSelect: (emoji) => {
          insertAtCursor(inputEl, emoji.native);
          textarea.focus();
        },
        theme: 'light',
        previewPosition: "none",
        skinTonePosition: "none"
      });
      document.getElementById('emojiGrid').appendChild(emojiPicker);
  }
  emojiDrawer.classList.toggle('active');
  composer.classList.toggle('up');
});
function closeEmojiPicker(){ if(emojiPicker) emojiPicker.style.display='none'; document.removeEventListener('click', closeEmojiPicker); }
function insertAtCursor(el, text){
  const start = el.selectionStart || 0;
  const end = el.selectionEnd || 0;
  const val = el.value || '';
  el.value = val.slice(0,start) + text + val.slice(end);
  const pos = start + text.length;
  el.selectionStart = el.selectionEnd = pos;
}

/* =========================
   + attach menu behavior (vertical rectangular buttons)
   ========================= */
const plusBtn = document.getElementById('plusBtn');
const attachMenuVertical = document.getElementById('attachMenuVertical');
plusBtn.addEventListener('click', (e)=>{
  e.stopPropagation();
  const showing = attachMenuVertical.style.display === 'flex';
  attachMenuVertical.style.display = showing ? 'none' : 'flex';
  if(!showing){
    window.addEventListener('scroll', hideAttachMenuOnce, { once:true });
  }
});
function hideAttachMenuOnce(){ attachMenuVertical.style.display='none'; }

/* Attach menu actions */
attachMenuVertical.querySelectorAll('.attach-card').forEach(c=>{
  c.addEventListener('click', (ev)=>{
    const action = c.dataset.action;
    if(action === 'camera'){
      openFileSelector(true);
    } else if(action === 'gallery'){
      openFileSelector(false);
    } else if(action === 'document'){
      openDocSelector();
    } else if(action === 'audio'){
      openAudioSelector();
    } else if(action === 'location'){
      if(!navigator.geolocation){
        alert('Geolocation not supported on this device.');
        return;
      }
      navigator.geolocation.getCurrentPosition(async (pos)=>{
        const lat = pos.coords.latitude.toFixed(6);
        const lng = pos.coords.longitude.toFixed(6);
        const url = `https://www.google.com/maps?q=${lat},${lng}`;
        const mapImg = `https://static-maps.yandex.ru/1.x/?ll=${lng},${lat}&size=600,300&z=15&l=map&pt=${lng},${lat},pm2rdm`;
        await fetch('/send_message', {
          method:'POST',
          headers:{'Content-Type':'application/json'},
          body: JSON.stringify({ text:'', attachments:[{ type:'location', lat, lng, url, map: mapImg }] })
        });
        messagesEl.innerHTML=''; lastId=0; poll();
      }, (err)=>{
        alert('Could not get location: ' + err.message);
      });
    }
    attachMenuVertical.style.display='none';
  });
});
const pcConfig = {
  iceServers: [
    { urls: ["stun:stun.l.google.com:19302"] }
    // Add TURN server here for reliable NAT traversal in production
  ]
};

// References
const incomingCallBanner = document.getElementById('incomingCallBanner');
const incomingCallerNameEl = document.getElementById('incomingCallerName');
const acceptCallBtn = document.getElementById('acceptCallBtn');
const declineCallBtn = document.getElementById('declineCallBtn');

const inCallControls = document.getElementById('inCallControls');
const btnHangup = document.getElementById('btnHangup');
const btnMute = document.getElementById('btnMute');
const btnToggleVideo = document.getElementById('btnToggleVideo');
const btnSwitchCam = document.getElementById('btnSwitchCam');

// State tracking
let activeCallId = null;

// When incoming call arrives
socket.on('call:incoming', (d) => {
  const caller = d.from;
  const callId = d.call_id;
  incomingCallerNameEl.textContent = caller;
  incomingCallBanner.classList.remove('hidden');
  activeCallId = callId;
  // store isVideo if needed for later
});

// Accept / decline buttons
acceptCallBtn.addEventListener('click', () => {
  if (!activeCallId) return;
  socket.emit('call:accept', { call_id: activeCallId, from: myName });
  incomingCallBanner.classList.add('hidden');
  // Show in-call controls
  inCallControls.classList.remove('hidden');
});

declineCallBtn.addEventListener('click', () => {
  if (!activeCallId) return;
  socket.emit('call:hangup', { call_id: activeCallId, from: myName });
  incomingCallBanner.classList.add('hidden');
  activeCallId = null;
});

// Hook in-call control buttons
btnHangup.addEventListener('click', () => {
  if (activeCallId) endCall(activeCallId);
  inCallControls.classList.add('hidden');
});

btnMute.addEventListener('click', () => {
  if (activeCallId) toggleMute(activeCallId);
  // optionally change icon or style to show mute/unmute
});

btnToggleVideo.addEventListener('click', () => {
  if (activeCallId) toggleVideo(activeCallId);
});

btnSwitchCam.addEventListener('click', () => {
  if (activeCallId) switchCamera(activeCallId);
});

// Hide controls on call end
socket.on('call:ended', (d) => {
  if (activeCallId === d.call_id) {
    activeCallId = null;
    inCallControls.classList.add('hidden');
    incomingCallBanner.classList.add('hidden');
  }
});

const localVideo = document.createElement('video'); localVideo.autoplay = true; localVideo.muted = true;
const remoteVideo = document.createElement('video'); remoteVideo.autoplay = true; remoteVideo.playsInline = true;
localVideo.id = 'localVideo'; remoteVideo.id = 'remoteVideo';
localVideo.style.display = 'none'; remoteVideo.style.maxWidth='100%';
document.body.appendChild(localVideo); document.body.appendChild(remoteVideo);

// State per call
const calls = {}; // call_id -> { pc, localStream, remoteStream, isCaller, currentCameraId }

async function startCall(toUser, isVideo = true){
  const callId = 'call-' + Date.now() + '-' + Math.random().toString(36).slice(2,8);
  // create local stream
  const constraints = { audio: true, video: isVideo ? { facingMode: 'user' } : false };
  let localStream;
  try {
    localStream = await navigator.mediaDevices.getUserMedia(constraints);
  } catch(err){
    alert('Could not access microphone/camera: ' + (err && err.message ? err.message : err));
    return;
  }
  // save
  calls[callId] = { localStream, isCaller: true, pc: null, currentCameraId: null };

  // notify callee via signaling
  socket.emit('call:invite', { to: toUser, from: myName, is_video: !!isVideo, call_id: callId });

  // create peer connection and createOffer later on 'call:accepted' event
  setupPeerConnection(callId, localStream, isVideo);

  // open local preview
  localVideo.srcObject = localStream; localVideo.style.display = isVideo ? 'block' :'none';
  showInCallUI(callId, toUser, true);
}

// Called when callee accepts — now create offer (caller)
socket.on('call:accepted', async (d) => {
  const callId = d.call_id; const call = calls[callId];
  if(!call || !call.pc) return;
  try {
    const offer = await call.pc.createOffer();
    await call.pc.setLocalDescription(offer);
    socket.emit('call:offer', { to: d.from /* caller? check flow */, from: myName, sdp: offer, call_id: callId });
  } catch(e){ console.error('offer error', e); }
});

// When receiving an offer (callee side)
socket.on('call:offer', async (d) => {
  const callId = d.call_id; const fromUser = d.from;
  // Prepare local stream
  const isVideo = d.sdp && d.sdp.type; // assume caller asked video if offer contains m=video
  const constraints = { audio:true, video: true };
  let localStream;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video: true });
  } catch(e){
    // user may choose to decline or accept audio-only
    localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:false }).catch(()=>null);
  }
  // store
  calls[callId] = { localStream, pc: null, isCaller: false, currentCameraId: getCurrentCameraId(localStream) };
  setupPeerConnection(callId, localStream, !!localStream.getVideoTracks().length);
  // set remote description
  try {
    await calls[callId].pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
    const answer = await calls[callId].pc.createAnswer();
    await calls[callId].pc.setLocalDescription(answer);
    socket.emit('call:answer', { to: fromUser, from: myName, sdp: answer, call_id: callId });
    showInCallUI(callId, fromUser, false);
  } catch(err){ console.error('handle offer error', err); }
});

// When receiving an answer (caller)
socket.on('call:answer', async (d) => {
  const callId = d.call_id; const call = calls[callId];
  if(!call || !call.pc) return;
  try {
    await call.pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
    // call is now established when ICE flows
    updateCallStateUI(callId, 'connected');
    update_call_started_on_server(callId);
  } catch(e){ console.error(e); }
});

socket.on('call:candidate', async (d) => {
  const callId = d.call_id; const call = calls[callId];
  if(!call || !call.pc || !d.candidate) return;
  try { await call.pc.addIceCandidate(new RTCIceCandidate(d.candidate)); } catch(e){ console.warn('candidate add failed', e); }
});

// Remote hangup
socket.on('call:ended', (d) => {
  const callId = d.call_id;
  endCallLocal(callId, d.by);
});

// Utility to create RTCPeerConnection and wire tracks
function setupPeerConnection(callId, localStream, hasVideo){
  const pc = new RTCPeerConnection(pcConfig);
  calls[callId].pc = pc;
  // add local tracks
  if(localStream){
    localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
  }

  const remoteStream = new MediaStream();
  pc.ontrack = (evt) => {
    evt.streams.forEach(s => {
      s.getTracks().forEach(t=> remoteStream.addTrack(t));
    });
    remoteVideo.srcObject = remoteStream;
  };

  pc.onicecandidate = (e) => {
    if(e.candidate){
      socket.emit('call:candidate', { to: getPeerForCall(callId), from: myName, candidate: e.candidate, call_id: callId });
    }
  };

  pc.onconnectionstatechange = ()=> {
    const st = pc.connectionState;
    console.log('pc state', st);
    if(st === 'connected') updateCallStateUI(callId, 'connected');
    if(st === 'disconnected' || st === 'failed' || st === 'closed') endCallLocal(callId, 'peer');
  };
  return pc;
}

function getPeerForCall(callId){
  // find other username from CALL_INVITES or local 'calls' state if you persisted when inviting
  // For simplicity assume the UI stored `calls[callId].peer`
  return calls[callId]?.peer || null;
}

// ---- UI actions ----
async function toggleMute(callId){
  const call = calls[callId]; if(!call || !call.localStream) return;
  call.localStream.getAudioTracks().forEach(t => { t.enabled = !t.enabled; });
  // notify other peer UI (optional)
  socket.emit('call:signal', { to: getPeerForCall(callId), payload: { type: 'mute', by: myName, muted: !call.localStream.getAudioTracks()[0].enabled } });
}

function toggleVideo(callId){
  const call = calls[callId]; if(!call || !call.localStream) return;
  call.localStream.getVideoTracks().forEach(t => { t.enabled = !t.enabled; });
  socket.emit('call:signal', { to: getPeerForCall(callId), payload: { type: 'video-toggled', by: myName, videoOn: !!call.localStream.getVideoTracks().find(tt=>tt.enabled) } });
}

async function switchCamera(callId){
  const call = calls[callId];
  if(!call) return;
  // enumerate devices
  const devices = await navigator.mediaDevices.enumerateDevices();
  const videoInputs = devices.filter(d => d.kind === 'videoinput');
  if(videoInputs.length <= 1) return alert('No other camera found');
  // pick another device id
  const currentId = call.currentCameraId;
  let next = videoInputs.find(d=>d.deviceId !== currentId);
  if(!next) next = videoInputs[0];
  // get new stream from device
  const newStream = await navigator.mediaDevices.getUserMedia({ video: { deviceId: { exact: next.deviceId } }, audio: false }).catch(e=>null);
  if(!newStream) return;
  // replace track
  const newTrack = newStream.getVideoTracks()[0];
  const pc = call.pc;
  const senders = pc.getSenders();
  const sender = senders.find(s => s.track && s.track.kind === 'video');
  if(sender) await sender.replaceTrack(newTrack);
  // update the stored localStream: remove old video track & add new track
  call.localStream.getVideoTracks().forEach(t => { t.stop(); call.localStream.removeTrack(t); });
  call.localStream.addTrack(newTrack);
  call.currentCameraId = next.deviceId;
  localVideo.srcObject = call.localStream;
}

async function shareScreen(callId){
  try{
    const screenStream = await navigator.mediaDevices.getDisplayMedia({ video:true });
    const call = calls[callId];
    if(!call) return;
    const screenTrack = screenStream.getVideoTracks()[0];
    const pc = call.pc;
    const senders = pc.getSenders();
    const videoSender = senders.find(s => s.track && s.track.kind === 'video');
    if(videoSender){
      await videoSender.replaceTrack(screenTrack);
      // when screen share stops, restore camera
      screenTrack.onended = async () => {
        // re-acquire camera track (best-effort)
        const camStream = await navigator.mediaDevices.getUserMedia({ video:true }).catch(()=>null);
        if(camStream){
          const camTrack = camStream.getVideoTracks()[0];
          await videoSender.replaceTrack(camTrack);
          call.localStream.getVideoTracks().forEach(t=>t.stop()); // remove old
          call.localStream.addTrack(camTrack);
          localVideo.srcObject = call.localStream;
        }
      };
    }
  }catch(e){ console.warn('screen share failed', e); }
}

function endCall(callId){
  socket.emit('call:hangup', { call_id: callId, from: myName });
  endCallLocal(callId, myName);
}

function endCallLocal(callId, by){
  const call = calls[callId];
  if(!call) return;
  try{
    if(call.pc) { call.pc.close(); call.pc = null; }
    if(call.localStream) { call.localStream.getTracks().forEach(t=>t.stop()); }
  }catch(e){}
  // cleanup UI
  localVideo.srcObject = null; remoteVideo.srcObject = null;
  // remove from map
  delete calls[callId];
  // update UI to show ended
  alert('Call ended by ' + (by || 'local'));
}

// Utility: pick camera id from stream
function getCurrentCameraId(stream){
  if(!stream) return null;
  const t = stream.getVideoTracks()[0];
  if(!t) return null;
  return t.getSettings && t.getSettings().deviceId ? t.getSettings().deviceId : null;
}

// Accept/reject UI handlers (call acceptance flow)
socket.on('call:incoming', (d) => {
  // show incoming modal with Accept/Decline
  const caller = d.from; const callId = d.call_id; const isVideo = d.is_video;
  if(confirm(`Incoming ${isVideo ? 'video':'audio'} call from ${caller}. Accept?`)){
    socket.emit('call:accept', { call_id: callId, from: myName });
    // callee will process 'call:offer' soon
  } else {
    socket.emit('call:hangup', { call_id: callId, from: myName });
  }
});

// wire up additional signals if needed
socket.on('call:signal', (payload) => {
  // e.g. show mute indicator, emoji reaction, hold etc.
  console.log('in-call signal', payload);
});

/* file selectors we inject (hidden inputs) */
function openFileSelector(camera){
  const inp = document.createElement('input'); inp.type='file'; inp.accept='image/*,video/*'; if(camera) inp.setAttribute('capture','environment');
  inp.multiple = true;
  inp.onchange = (ev)=> setAttachmentPreview(ev.target.files);
  inp.click();
}
function openDocSelector(){
  const inp = document.createElement('input'); inp.type='file'; inp.multiple=true; inp.onchange = (ev)=> setAttachmentPreview(ev.target.files); inp.click();
}
function openAudioSelector(){
  const inp = document.createElement('input'); inp.type='file'; inp.accept='audio/*'; inp.multiple=true; inp.onchange = (ev)=> setAttachmentPreview(ev.target.files); inp.click();
}

/* attachment preview (keeps same stagedFiles behavior) */
function setAttachmentPreview(files){
  stagedFiles = Array.from(files || []);
  const preview = document.getElementById('attachmentPreview'); preview.innerHTML=''; preview.style.display = stagedFiles.length ? 'block' : 'none';
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
      const au = document.createElement('audio'); const url=URL.createObjectURL(file); au.src = url; au.controls=true; item.appendChild(au);
    } else {
      const d = document.createElement('div'); d.className='preview-item-doc'; d.textContent = file.name; item.appendChild(d);
    }
    preview.appendChild(item);
  });
}

/* createVideoThumbnailFromFile helper */
function createVideoThumbnailFromFile(file, seekTo=0.5){
  return new Promise((resolve)=>{
    const url = URL.createObjectURL(file);
    createVideoThumbnailFromUrl(url, seekTo).then((data)=>{
      URL.revokeObjectURL(url);
      resolve(data);
    }).catch(()=>{ URL.revokeObjectURL(url); resolve(null); });
  });
}
function createVideoThumbnailFromUrl(url, seekTo=0.5){
  return new Promise((resolve)=>{
    try{
      const video = document.createElement('video');
      video.crossOrigin = 'anonymous';
      video.src = url;
      video.muted = true; video.playsInline = true;
      video.addEventListener('loadeddata', ()=>{
        const t = Math.min(seekTo, Math.max(0, (video.duration || 1)*0.2 ));
        function seekHandler(){
          const canvas = document.createElement('canvas');
          canvas.width = video.videoWidth || 320;
          canvas.height = video.videoHeight || 180;
          const ctx = canvas.getContext("2d", { willReadFrequently: true });
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

/* =========================
   Sticker / GIF / Avatar panel wiring
   ========================= */
const stickerPanel = document.getElementById('stickerPanel');
const panelGrid = document.getElementById('panelGrid');
document.getElementById('closeStickerPanel').addEventListener('click', hideStickerPanel);

document.getElementById('tab_stickers').addEventListener('click', async ()=>{ await loadStickers(); });
document.getElementById('tab_gifs').addEventListener('click', async ()=>{ await loadGIFs(); });
document.getElementById('tab_avatars').addEventListener('click', async ()=>{ await loadAvatars(); });
document.getElementById('tab_emoji').addEventListener('click', ()=>{ document.getElementById('emojiBtn').click(); });

document.getElementById('stickerPickerBtn')?.addEventListener('click', ()=> showStickerPanel());



/* load GIFs - Tenor trending (no API key attempt) */
async function loadGIFs(){
  panelGrid.innerHTML = '<div>Loading GIFs…</div>';
  try{
    const r = await fetch('https://g.tenor.com/v1/trending?limit=28');
    let data = await r.json();
    const results = data && data.results ? data.results : [];
    panelGrid.innerHTML = '';
    for(const it of results){
      const gifUrl = it.media && it.media[0] && it.media[0].gif && it.media[0].gif.url ? it.media[0].gif.url : (it.url || null);
      if(!gifUrl) continue;
      const w = document.createElement('div'); w.style.cursor='pointer';
      const img = document.createElement('img'); img.src = it.thumbnail || (it.media && it.media[0] && it.media[0].tinygif && it.media[0].tinygif.url) || gifUrl; img.style.width='100%'; img.style.borderRadius='8px';
      w.appendChild(img);
      w.onclick = async ()=> { await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url: gifUrl }] }) }); hideStickerPanel(); messagesEl.innerHTML=''; lastId=0; poll(); };
      panelGrid.appendChild(w);
    }
  }catch(e){
    try{
      const r2 = await fetch('/generated_gifs');
      const list = await r2.json();
      panelGrid.innerHTML = '';
      for(const url of list){
        const w = document.createElement('div'); w.style.cursor='pointer';
        const img = document.createElement('img'); img.src = url; img.style.width='100%'; img.style.borderRadius='8px';
        w.appendChild(img);
        w.onclick = async ()=> { await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] }) }); hideStickerPanel(); messagesEl.innerHTML=''; lastId=0; poll(); };
        panelGrid.appendChild(w);
      }
    }catch(e2){
      panelGrid.innerHTML = '<div>Error loading GIFs</div>';
    }
  }
}

/* load Avatars: show generated tiles via DiceBear presets & user-saved avatars */
async function loadAvatars(){
  panelGrid.innerHTML = '<div>Loading avatars…</div>';
  panelGrid.innerHTML = '';
  const presets = ['hero', 'adventurer', 'brave', 'spark', 'mystic', 'dreamer', 'alpha', 'nova', 'sol', 'luna'];
  for(const seed of presets){
    const img = document.createElement('img');
    const url = `https://api.dicebear.com/9.x/adventurer/svg?seed=${encodeURIComponent(seed)}&backgroundColor=transparent`;
    const wrapper = document.createElement('div'); wrapper.style.cursor='pointer';
    img.src = url;
    img.style.width='100%'; img.style.borderRadius='8px';
    wrapper.appendChild(img);
    wrapper.onclick = async ()=> {
      await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] }) });
      hideStickerPanel(); messagesEl.innerHTML=''; lastId=0; poll();
    };
    panelGrid.appendChild(wrapper);
  }
}

/* Avatar creation page trigger */
document.getElementById('createAvatarBtn')?.addEventListener('click', ()=>{
  window.open('/avatar_create', '_blank');
});

/* Poll modal handling */
document.getElementById('pollBtn')?.addEventListener('click', ()=>{
  document.getElementById('pollModal').style.display='block'; document.getElementById('pollModal').classList.remove('hidden');
});
document.getElementById('cancelPoll')?.addEventListener('click', ()=> { document.getElementById('pollModal').style.display='none'; document.getElementById('pollModal').classList.add('hidden'); });
document.getElementById('addPollOption')?.addEventListener('click', ()=>{
  const container = document.getElementById('pollOptions');
  if(container.querySelectorAll('input[name="option"]').length >= 12) return alert('Max 12 options');
  const inp = document.createElement('input'); inp.name='option'; inp.placeholder = 'Option ' + (container.querySelectorAll('input[name="option"]').length + 1); inp.className='w-full p-2 border rounded mb-2';
  container.appendChild(inp);
});
document.getElementById('pollForm')?.addEventListener('submit', async (e)=>{
  e.preventDefault();
  const q = document.getElementById('poll_question').value.trim();
  const opts = Array.from(document.querySelectorAll('input[name="option"]')).map(i=>i.value.trim()).filter(v=>v);
  if(!q || opts.length < 2) return alert('Question and at least 2 options required');
  await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:q, attachments:[{ type:'poll', options:opts }] }) });
  document.getElementById('pollModal').style.display='none'; document.getElementById('pollModal').classList.add('hidden');
  messagesEl.innerHTML=''; lastId=0; poll();
});

/* =========================
   Message polling/rendering
   ========================= */
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
      const leftMeta = document.createElement('div'); leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong>`;
      const rightMeta = document.createElement('div'); rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
      meta.appendChild(leftMeta); meta.appendChild(rightMeta);
      body.appendChild(meta);

      const hasText = m.text && m.text.trim().length>0;
      const attachments = (m.attachments || []);
      const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me' : 'them');

      if(hasText) {
        const textNode = document.createElement('div');
        textNode.innerHTML = escapeHtml(m.text) + (m.edited ? '<span style="font-size:.7rem;color:#9ca3af">(edited)</span>':'');
        bubble.appendChild(textNode);
      }

      if(attachments && attachments.length){
        for(const a of attachments){
          if(a.type === 'sticker'){
            const s = document.createElement('img'); s.src = a.url; s.className = 'sticker'; s.style.marginTop='8px'; s.style.maxWidth='180px'; s.style.borderRadius='8px';
            bubble.appendChild(s);
          } else if(a.type === 'poll'){
            const p = document.createElement('div'); p.className='poll'; p.style.marginTop='8px'; p.innerHTML = `<strong>Poll:</strong> ${escapeHtml(m.text || '')}`;
            bubble.appendChild(p);
            if(a.options && a.options.length){
              const ol = document.createElement('div'); ol.style.marginTop='6px';
              a.options.forEach((op, i)=>{
                const btn = document.createElement('button'); btn.textContent = op + ' 0'; btn.className='px-3 py-1 rounded bg-gray-100 mr-2'; ol.appendChild(btn);
              });
              bubble.appendChild(ol);
            }
          } else {
            const { element, mediaElement } = createAttachmentElement(a);
            if(element) bubble.appendChild(element);
          }
        }
      }

      if(m.reactions && m.reactions.length){
        const agg = {};
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
        menu.style.position='absolute'; menu.style.zIndex=200; menu.style.background='white'; menu.style.border='1px solid #e5e7eb'; menu.style.boxShadow='0 6px 18px rgba(0,0,0,0.08)'; menu.style.borderRadius='8px'; menu.style.padding='8px';
        menu.style.top = (menuBtn.getBoundingClientRect().bottom + 8) + 'px';
        menu.style.left = (menuBtn.getBoundingClientRect().left - 160) + 'px';
        const del = document.createElement('div'); del.innerText='Delete'; del.style.cursor='pointer'; del.style.padding='6px 8px';
        del.onclick = async (e)=>{ e.stopPropagation(); if(confirm('Delete this message?')){ await fetch('/delete_message',{method:'POST',headers:{'Content-Type':'application/json'},body: JSON.stringify({id:m.id})}); messagesEl.innerHTML=''; lastId=0; poll(); } };
        const forward = document.createElement('div'); forward.innerText='Forward'; forward.style.cursor='pointer'; forward.style.padding='6px 8px';
        forward.onclick = ()=>{ navigator.clipboard.writeText(m.text || ''); alert('Message copied for forwarding'); };
        const copy = document.createElement('div'); copy.innerText='Copy'; copy.style.cursor='pointer'; copy.style.padding='6px 8px';
        copy.onclick = ()=>{ navigator.clipboard.writeText(m.text || ''); alert('Copied to clipboard'); };
        const reshare = document.createElement('div'); reshare.innerText='Reshare'; reshare.style.cursor='pointer'; reshare.style.padding='6px 8px';
        reshare.onclick = ()=>{ alert('Reshare placeholder'); };
        const react = document.createElement('div'); react.innerText='React'; react.style.cursor='pointer'; react.style.padding='6px 8px';
        react.onclick = (ev2)=>{ ev2.stopPropagation(); showEmojiPickerForMessage(m.id, menuBtn); };

        menu.appendChild(copy); menu.appendChild(forward); menu.appendChild(reshare);
        if(m.sender === myName) menu.appendChild(del);
        menu.appendChild(react);
        document.body.appendChild(menu);
        const hide = ()=>{ menu.remove(); document.removeEventListener('click', hide); };
        setTimeout(()=> document.addEventListener('click', hide), 50);
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

/* small reaction picker replacement using emoji-mart quick list */
function showEmojiPickerForMessage(msgId, anchorEl){
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
  const hide = ()=>{ picker.remove(); document.removeEventListener('click', hide); };
  setTimeout(()=> document.addEventListener('click', hide), 50);
}

/* Attachment element factory (image/video/audio/doc/location) */
function createAttachmentElement(a){
  const container = document.createElement('div');
  container.className = 'media-container mt-2';

  if(a.type === 'audio' || (a.type === 'voice')) {
    html += `
    <div class="media-container">
      <audio controls src="${att.url}" class="chat-audio"></audio>
    </div>`;
    const au = document.createElement('audio'); au.src = a.url; au.controls = true; au.className = 'mt-2';
    container.appendChild(au);
    return { element: container };
  }
  if(a.type === 'doc'){
    const link = document.createElement('a');
    link.href = a.url; link.className = 'doc-link'; link.setAttribute('download', a.name || 'Document');
    link.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#111827" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h11"></path><polyline points="17 2 17 8 23 8"></polyline></svg><span style="font-size:0.92rem">${escapeHtml(a.name || 'Document')}</span>`;
    container.appendChild(link);
    return { element: container };
  }

  if(a.type === 'location'){
    const card = document.createElement('a');
    card.href = a.url || '#';
    card.target = '_blank';
    card.style.display = 'block';
    card.style.maxWidth = '320px';
    card.style.borderRadius = '10px';
    card.style.overflow = 'hidden';
    card.style.boxShadow = '0 6px 18px rgba(0,0,0,0.08)';
    card.style.textDecoration = 'none';
    card.style.color = 'inherit';
    const img = document.createElement('img'); img.src = a.map; img.alt = 'location'; img.style.width='100%'; img.style.display='block';
    const caption = document.createElement('div'); caption.style.padding='8px'; caption.style.background = '#fff'; caption.style.fontSize = '.9rem'; caption.innerText = '📍 Shared Location';
    card.appendChild(img); card.appendChild(caption);
    container.appendChild(card);
    return { element: container };
  }

  if(a.type === 'image' || a.type === 'video'){
    if(a.type === 'image'){
      const img = document.createElement('img'); img.src = a.url; img.className = 'image-attachment'; img.style.maxWidth='420px'; img.style.borderRadius='10px'; container.appendChild(img);
      return { element: container, mediaElement: img };
    } else {
      const thumbImg = document.createElement('img'); thumbImg.className = 'thumb'; thumbImg.alt = a.name || 'video';
      const playOverlay = document.createElement('div'); playOverlay.className='play-overlay'; playOverlay.innerHTML = '<div class="play-circle">▶</div>';
      container.appendChild(thumbImg); container.appendChild(playOverlay);

      createVideoThumbnailFromUrl(a.url, 0.7).then(dataUrl=>{ if(dataUrl) thumbImg.src = dataUrl; else { const v = document.createElement('video'); v.src = a.url; v.controls = true; v.className='video-attachment'; container.innerHTML = ''; container.appendChild(v); } });

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

function gatherAttachments(){
  const items = document.querySelectorAll('#previewContainer .preview-item');
  const atts = [];
  items.forEach(p=>{
    if(p.type === 'audio'){
      atts.push({ type:'audio', blob: p.blob });
    }
    // keep existing image/video handling here
  });
  return atts;
}

sendBtn.addEventListener('click', ()=>{
  const text = textarea.value.trim();
  const atts = gatherAttachments();

  if(text || atts.length){
    sendMessage(text, atts);
    textarea.value = '';
    document.getElementById('previewContainer').innerHTML = '';
  }
});

/* =========================
   Mic (voice message) implementation
   - toggles recording, provides visual state, uploads automatically on stop
   ========================= */
const micBtn = document.getElementById('mic');
let mediaRecorder = null;
let micStream = null;
let audioChunks = [];
let isRecording = false;

function updateMicUI(state){
  if(state){
    micBtn.classList.add('recording');
    micBtn.setAttribute('aria-pressed','true');
    micBtn.title = 'Recording… click to stop';
    micBtn.innerText = '⏸️';
  } else {
    micBtn.classList.remove('recording');
    micBtn.setAttribute('aria-pressed','false');
    micBtn.title = 'Record voice message';
    micBtn.innerText = '🎙️';
  }
}

async function startRecording(){
  if(isRecording) return;
  if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia){
    alert('Microphone not supported in this browser.');
    return;
  }
  try{
    micStream = await navigator.mediaDevices.getUserMedia({ audio: true });
    mediaRecorder = new MediaRecorder(micStream);
    audioChunks = [];
    mediaRecorder.addEventListener('dataavailable', e => { if(e.data && e.data.size) audioChunks.push(e.data); });
    mediaRecorder.addEventListener('stop', async ()=>{
      const blob = new Blob(audioChunks, { type: audioChunks[0]?.type || 'audio/webm' });
      const fileName = `voice_${Date.now()}.webm`;
      const file = new File([blob], fileName, { type: blob.type });

      // show preview in attachment area
      stagedFiles = [file];
      setAttachmentPreview(stagedFiles);

      // send automatically (uses same composite endpoint as normal sends)
      try{
        const fd = new FormData();
        fd.append('text', '');
        fd.append('file', file, file.name);
        const r = await fetch('/send_composite_message', { method: 'POST', body: fd });
        if(r.ok){
          // clear local preview and refresh messages
          stagedFiles = [];
          setAttachmentPreview([]);
          messagesEl.innerHTML = '';
          lastId = 0;
          await poll();
        } else {
          const txt = await r.text();
          alert('Voice send failed: ' + txt);
        }
      }catch(err){
        alert('Voice send error: ' + (err.message || err));
      }finally{
        audioChunks = [];
      }
    });
    mediaRecorder.start();
    isRecording = true;
    updateMicUI(true);
  }catch(err){
    console.error('microphone error', err);
    alert('Could not start microphone: ' + (err && err.message ? err.message : err));
    if(micStream){
      micStream.getTracks().forEach(t=>t.stop());
      micStream = null;
    }
    isRecording = false;
    updateMicUI(false);
  }
}

function stopRecording(){
  if(!isRecording) return;
  try{
    if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop();
  }catch(e){ console.warn(e); }
  if(micStream){
    micStream.getTracks().forEach(t=>t.stop());
    micStream = null;
  }
  isRecording = false;
  updateMicUI(false);
}

// toggle mic on click
recorder.onstop = () => {
  const audioBlob = new Blob(chunks, { type: 'audio/webm' });
  const url = URL.createObjectURL(audioBlob);
  chunks = [];

  // Create preview card
  const preview = document.createElement('div');
  preview.className = 'preview-item';

  preview.innerHTML = `
    <audio controls src="${url}" class="preview-audio"></audio>
    <button class="remove-btn">❌</button>
  `;

  preview.querySelector('.remove-btn').onclick = () => preview.remove();

  // Attach blob data for sending
  preview.dataset.blobUrl = url;
  preview.blob = audioBlob;
  preview.type = "audio";

  document.getElementById('previewContainer').appendChild(preview);
};


// keyboard activate (Enter / Space)
micBtn.addEventListener('keydown', (ev)=>{
  if(ev.key === 'Enter' || ev.key === ' '){
    ev.preventDefault();
    micBtn.click();
  }
});

document.getElementById('sendBtn').addEventListener('click', async ()=>{
  const text = (inputEl.value || '').trim();
  if(!text && stagedFiles.length===0) return;
  const tempId = 'temp-'+Date.now();
  const wrapper = document.createElement('div'); wrapper.className='msg-row';
  const body = document.createElement('div'); body.className='msg-body';
  const bubble = document.createElement('div'); bubble.className='bubble me'; bubble.dataset.tempId = tempId;
  if(text) bubble.appendChild(document.createTextNode(text));
  const objectUrls = [];
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
    }
  }catch(e){ alert('Send error: '+e.message); }
  finally{ objectUrls.forEach(u=> URL.revokeObjectURL(u)); }
});

/* keyboard send on Enter */
inputEl.addEventListener('keydown', function(e){ if(e.key === 'Enter' && !e.shiftKey){ e.preventDefault(); document.getElementById('sendBtn').click(); } });

/* profile toggles */
document.getElementById('profileBtn').addEventListener('click', (e)=>{ e.stopPropagation(); const menu = document.getElementById('profileMenu'); menu.classList.toggle('hidden'); menu.style.display = menu.classList.contains('hidden') ? 'none' : 'block'; });
document.getElementById('viewProfileBtn').addEventListener('click', async ()=>{ document.getElementById('profileMenu').classList.add('hidden'); document.getElementById('profileMenu').style.display='none'; const modal = document.getElementById('profileModal'); modal.classList.remove('hidden'); const r = await fetch('/profile_get'); if(r.ok){ const j = await r.json(); document.getElementById('profile_display_name').value = j.name || ''; document.getElementById('profile_status').value = j.status || ''; } });
function closeProfileModal(){ const modal = document.getElementById('profileModal'); modal.classList.add('hidden'); }
document.getElementById('closeProfile').addEventListener('click', closeProfileModal);
document.getElementById('profileCancel').addEventListener('click', closeProfileModal);

/* =========================
   Adaptive msg-meta-top color sampling
   ========================= */
let _bgImg = null;
let _bgCanvas = document.createElement('canvas');
let _bgCtx = _bgCanvas.getContext('2d');
let _bgDrawSize = { w: 0, h: 0 };
async function ensureBgLoaded(){
  if(_bgImg && _bgImg.complete) return;
  return new Promise((resolve)=> {
    if(_bgImg && _bgImg.complete){ resolve(); return; }
    _bgImg = new Image();
    _bgImg.crossOrigin = 'anonymous';
    _bgImg.src = '/static/IMG_5939.jpeg';
    _bgImg.onload = ()=> resolve();
    _bgImg.onerror = ()=> resolve();
  });
}
function drawBgToCanvasIfNeeded(){
  const w = Math.max(1, window.innerWidth);
  const h = Math.max(1, window.innerHeight);
  if(_bgDrawSize.w === w && _bgDrawSize.h === h) return;
  _bgCanvas.width = w;
  _bgCanvas.height = h;
  try{
    if(_bgImg && _bgImg.complete && _bgImg.naturalWidth){
      const iw = _bgImg.naturalWidth, ih = _bgImg.naturalHeight;
      const scale = Math.max(w/iw, h/ih);
      const dw = iw * scale, dh = ih * scale;
      const dx = (w - dw) / 2, dy = (h - dh) / 2;
      _bgCtx.clearRect(0,0,w,h);
      _bgCtx.drawImage(_bgImg, 0,0, iw, ih, dx, dy, dw, dh);
    } else {
      _bgCtx.fillStyle = '#ffffff';
      _bgCtx.fillRect(0,0,w,h);
    }
  }catch(e){
    try{ _bgCtx.fillStyle = '#ffffff'; _bgCtx.fillRect(0,0,w,h); }catch(_){}
  }
  _bgDrawSize.w = w; _bgDrawSize.h = h;
}

function samplePixelAtScreenXY(x, y){
  try{
    drawBgToCanvasIfNeeded();
    const ix = Math.max(0, Math.min(_bgCanvas.width-1, Math.round(x)));
    const iy = Math.max(0, Math.min(_bgCanvas.height-1, Math.round(y)));
    const d = _bgCtx.getImageData(ix, iy, 1, 1).data;
    return { r: d[0], g: d[1], b: d[2] };
  }catch(e){
    return { r: 255, g:255, b:255 };
  }
}

function luminance(r, g, b) {
  return 0.299*r + 0.587*g + 0.114*b;
}

async function updateMetaColors() {
  await ensureBgLoaded();
  drawBgToCanvasIfNeeded();
  const metas = document.querySelectorAll(".msg-meta-top");
  for (const el of metas) {
    const rect = el.getBoundingClientRect();
    const x = rect.left + rect.width/2;
    const y = rect.top + rect.height/2;
    const { r, g, b } = samplePixelAtScreenXY(x, y);
    const lum = luminance(r, g, b);
    el.style.color = lum > 150 ? "#111" : "#f9fafb";
  }
}

window.addEventListener("scroll", () => { updateMetaColors(); });
window.addEventListener("resize", () => { _bgDrawSize = {w:0,h:0}; updateMetaColors(); });
setInterval(updateMetaColors, 2000);

/* toggle elevated glassiness */
const composerMainEl = document.querySelector('.composer-main');
function setComposerElevated(state){
  if(!composerMainEl) return;
  composerMainEl.classList.toggle('glass-elevated', Boolean(state));
}

let lastTransform = '';
setInterval(()=>{
  if(!composerMainEl) return;
  const t = window.getComputedStyle(composerMainEl).transform || '';
  if(t !== lastTransform){
    lastTransform = t;
    const isUp = !t || t === 'none' ? false : /matrix|translate/.test(t);
    setComposerElevated(isUp);
  }
}, 250);
// Move composer up when mobile virtual keyboard opens (improves small-screen UX)
(function(){
  const composer = document.getElementById('composer');
  if(!composer) return;

  // For devices that support visualViewport (most modern mobile browsers)
  if(window.visualViewport){
    let lastBottomOffset = 0;
    function onViewportChange(){
      // visualViewport.height is reduced when keyboard appears
      const offset = Math.max(0, window.innerHeight - window.visualViewport.height);
      if(offset !== lastBottomOffset){
        // set bottom to safe-area + offset so composer sits above keyboard
        composer.style.bottom = `calc(env(safe-area-inset-bottom, 0) + ${offset}px)`;
        lastBottomOffset = offset;
      }
    }
    window.visualViewport.addEventListener('resize', onViewportChange);
    window.visualViewport.addEventListener('scroll', onViewportChange);
    // reset on focus out
    window.addEventListener('blur', ()=>{ composer.style.bottom = `calc(env(safe-area-inset-bottom, 0) + 8px)`; });
    // call once to init
    onViewportChange();
  }else{
    // fallback: slightly lift composer while input is focused
    const input = document.getElementById('msg');
    input && input.addEventListener('focus', ()=> composer.style.transform = 'translateY(-8vh)');
    input && input.addEventListener('blur', ()=> composer.style.transform = 'translateY(0)');
  }
})();
const emojiBtn = document.getElementById('emojiBtn');
const composer = document.querySelector('.composer');
const emojiDrawer = document.getElementById('stickerPanel');
const textarea = document.getElementById('msg');
const sendBtn = document.getElementById('sendBtn');

// Toggle drawer open/close
emojiBtn.addEventListener('click', () => {
  emojiDrawer.classList.toggle('active');
  composer.classList.toggle('up');
});

// Insert emoji (from drawer grid)
document.addEventListener('click', (e) => {
  if (e.target.closest('.emoji-grid span')) {
    textarea.value += e.target.textContent;
    sendBtn.click(); // auto send
  }
});

// Insert GIF (from drawer grid)
document.addEventListener('click', (e) => {
  if (e.target.closest('.gif-grid img')) {
    textarea.value = `[GIF: ${e.target.src}]`; 
    sendBtn.click(); // auto send
  }
});

// Close drawer when drag-bar clicked
emojiDrawer.addEventListener('click', (e) => {
  if (e.target.classList.contains('drag-bar')) {
    emojiDrawer.classList.remove('active');
    composer.classList.remove('up');
  }
});
</script>
</html>
''' 

# --------- Routes & API ----------
@app.context_processor
def util():
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
    # Use .strip() to remove accidental spaces from the client-side
    name = body.get("name", "").strip() 
    passkey = body.get("passkey")

    if not name or not passkey:
        return "Missing username or passkey", 400

    # This call now uses the case-insensitive lookup (Fix 1)
    user = load_user_by_name(name) 
    
    # This check returns the "Unauthorized" error
    if not user or not verify_pass(passkey, user['pass_salt'], user['pass_hash']):
        return "Unauthorized", 401 # Login fails here

    # --- FIX: Clear the existing session to prevent conflicts/redirect loops ---
    session.clear() 

    session['username'] = name # Use the name from the DB for consistent casing
    touch_user_presence(name)
    return jsonify({"status": "ok"})

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
