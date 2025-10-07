import os
import sqlite3
import secrets
import time
import json
import time
import threading
import hashlib
import hmac
import pathlib
import base64
import requests  
from datetime import datetime
from flask import (
    Flask, render_template_string, request, jsonify, session,
    redirect, url_for, send_from_directory, abort
)
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room

app = Flask(__name__, static_folder="static")
# -------- CONFIG ----------
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
# Optional cookie config
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True  # set to True in production (HTTPS)
)
PORT = int(os.environ.get("PORT", 5004))
DB_PATH = os.path.join(os.path.dirname(__file__), "Asphalt_Legends.db")
HEADING_IMG = "/static/heading.png"  # place your heading image here
MAX_MESSAGES = 100
ALLOWED_IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp", "svg"}
ALLOWED_VIDEO_EXT = {"mp4", "webm", "ogg"}
ALLOWED_AUDIO_EXT = {"mp3", "wav", "ogg", "m4a", "webm"}
messages_store = []
polls_store = {}
USER_SID = {}

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

@socketio.on('send_message')
def handle_send_message(data):
    # Save message
    new_msg = {
        "id": len(messages_store) + 1,
        "sender": data.get('sender'),
        "text": data.get('text'),
        "attachments": data.get('attachments', []),
        "reactions": []
    }
    messages_store.append(new_msg)
    # Broadcast to all connected clients
    socketio.emit('new_message', new_msg)
    
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
    # FIX: Use COLLATE NOCASE for case-insensitive lookup
    c.execute("SELECT id, name, pass_salt, pass_hash, avatar, status, is_owner, is_partner FROM users WHERE name = ? COLLATE NOCASE LIMIT 1", (name,))
    r = c.fetchone(); conn.close()
    if r: return {"id": r[0], "name": r[1], "pass_salt": r[2], "pass_hash": r[3], "avatar": r[4], "status": r[5], "is_owner": bool(r[6]), "is_partner": bool(r[7])}
    return None

def clone_user(name, pass_salt, pass_hash, avatar=None, status=""):
    """
    Create a new user row that reuses the provided salt+hash so the same
    password will work for the new username. New users are NOT owners/partners.
    Returns the newly created user dict (or None on error).
    """
    # normalize memoryview -> bytes if necessary
    if isinstance(pass_salt, memoryview): pass_salt = bytes(pass_salt)
    if isinstance(pass_hash, memoryview): pass_hash = bytes(pass_hash)

    conn = db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            """INSERT INTO users (name, pass_salt, pass_hash, avatar, status, is_owner, is_partner)
               VALUES (?, ?, ?, ?, ?, 0, 0)""",
            (name, sqlite3.Binary(pass_salt), sqlite3.Binary(pass_hash), avatar, status)
        )
        conn.commit()
    except Exception:
        # If INSERT fails (e.g. name collision), ignore/close and continue
        conn.rollback()
    finally:
        conn.close()

    return load_user_by_name(name)

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

def save_message(sender, text, attachments=None):
    """
    Save a message to the SQLite messages table and return the inserted message dict.
    attachments should be a list (will be stored as JSON string).
    """
    conn = db_conn()
    c = conn.cursor()
    ts = int(time.time())
    att = json.dumps(attachments or [])
    c.execute(
        "INSERT INTO messages (sender, text, attachments, created_at) VALUES (?, ?, ?, ?)",
        (sender, text, att, ts)
    )
    mid = c.lastrowid
    conn.commit()
    conn.close()

    # trim to configured maximum messages
    try:
        trim_messages_limit(MAX_MESSAGES)
    except Exception:
        # ignore trimming errors
        pass

    # return the same structure fetch_messages() uses
    return {
        "id": mid,
        "sender": sender,
        "text": text,
        "attachments": attachments or [],
        "reactions": [],
        "edited": False,
        "created_at": ts
    }

def fetch_messages(since=0):
    """
    Fetch all messages from SQLite whose id > since.
    Returns a list of dicts in the shape expected by your JS frontend.
    """
    conn = db_conn()
    c = conn.cursor()
    c.execute(
        "SELECT id, sender, text, attachments, reactions, edited, created_at "
        "FROM messages WHERE id > ? ORDER BY id ASC", 
        (since,)
    )
    rows = c.fetchall()
    conn.close()

    messages = []
    for r in rows:
        mid, sender, text, attachments_json, reactions_json, edited, created_at = r
        attachments = json.loads(attachments_json or "[]")
        reactions = json.loads(reactions_json or "[]")
        messages.append({
            "id": mid,
            "sender": sender,
            "text": text,
            "attachments": attachments,
            "reactions": reactions,
            "edited": bool(edited),
            "created_at": created_at
        })
    return messages

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

def next_message_id():
    return len(messages_store) + 1

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
# --- CHAT page: updated with emoji-mart v5, sticker/gif/avatar/emoji panel, typing indicator, attach menu, poll modal, avatar flow ---
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
    .call-btn{
      display:inline-flex;
      align-items:center;
      gap:6px;
      white-space:nowrap;
      padding:6px 10px;
      border-radius:8px;
      border:1px solid rgba(0,0,0,0.08);
      background: #fff;
      box-shadow: 0 1px 2px rgba(0,0,0,0.04);
      cursor:pointer;
      font-size:0.92rem;
      transition: transform .08s ease, box-shadow .08s ease;
    }
    .call-btn:active{ transform: translateY(1px); }
    .call-btn:hover{ box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
    
    /* make buttons tile/stack on very small widths */
    @media (max-width:520px){
      .header-actions { gap:6px; }
      .call-btn { padding:8px 12px; font-size:0.9rem; flex: 1 1 auto; min-width:120px; text-align:center; }
    }

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
    
    .attach-menu-vertical {
        position: fixed;
        right: 18px;
        bottom: 100px;
        display: none; /* start hidden */
        flex-direction: column;
        gap: 10px;
        border-radius: 12px;
        z-index: 80;
    }
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
      bottom: 0;               /* Stick to bottom */
      height: 40vh;            /* like phone keyboard */
      background: #fff;
      border-top-left-radius: 14px;
      border-top-right-radius: 14px;
      box-shadow: 0 -4px 16px rgba(0,0,0,0.1);
      transform: translateY(100%);
      transition: transform 0.25s ease-in-out;
      z-index: 200;
      display: flex;
      flex-direction: column;
    }
    #stickerPanel.active {
      transform: translateY(0);
    }
    .composer {
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      transition: bottom 0.25s ease-in-out;
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
        <button id="audioCallBtn" class="call-btn" title="Start audio call" aria-label="Audio call" style="position: fixed; left: 0.50rem; top: 0.50rem;">📞 Audio</button>
        <button id="videoCallBtn" class="call-btn" title="Start video call" aria-label="Video call" style="position: fixed; left: 0.50rem; top: 3.20rem">📽️ Video</button>
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
        <div id="stickerPanel" class="emoji-drawer">
          <div class="drag-bar" style="
              width:40px;
              height:5px;
              background:#ccc;
              border-radius:3px;
              margin:8px auto;
          "></div>
        
          <!-- Tabs -->
          <div class="panel-tabs">
            <button id="tab_stickers">Stickers</button>
            <button id="tab_gifs">GIFs</button>
            <button id="tab_avatars">Avatars</button>
            <button id="tab_emoji">Emoji</button>
          </div>
        
          <!-- Content area -->
          <div id="panelContent" class="emoji-drawer-content">
            <div id="stickersContainer" class="grid grid-cols-4 gap-2 hidden"></div>
            <div id="gifGrid" class="gif-grid hidden"></div>
            <div id="avatarGrid" class="emoji-grid hidden"></div>
            <div id="emojiGrid" class="emoji-grid"></div>
          </div>
        </div>
    
      <!-- Composer -->
      <div class="composer" id="composer" aria-label="Composer area">
        <div class="composer-inner">
          <div id="attachmentPreview"></div>
    
          <div class="composer-main" id="composerMain" role="form" aria-label="Message composer">
            <button id="plusBtn" class="plus-small bg-white shadow" style="font-size:2rem;" aria-label="Attach">＋</button>
    
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
      <div id="attachMenuVertical" class="attach-menu-vertical" style="display:inline-block;">
          <div class="attach-card" data-action="document">📁<div>  Documents</div></div>
          <div class="attach-card" data-action="camera">📷<div>  Camera</div></div>
          <div class="attach-card" data-action="gallery">🌇<div>  Gallery</div></div>
          <div class="attach-card" data-action="audio">🎧<div>  Audio</div></div>
          <div class="attach-card" data-action="location">🌐<div>  Location</div></div>
          <div class="attach-card" id="pollBtn">🗳️<div>  Poll</div></div>
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

<!-- include socket.io and other scripts (socket server expected) -->
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>

<script>

(function () {
  'use strict';

  // Central state container to avoid accidental globals
  const cs = {
    socket: (typeof io === 'function') ? io() : null,
    myName: "{{ username }}" || "anonymous",
    lastId: 0,
    stagedFiles: [],
    typingTimer: null,
    isTyping: false,
    calls: {},     // call_id -> call state
    pcConfig: { iceServers: [{ urls: ["stun:stun.l.google.com:19302"] }] }
  };

  // Safe DOM refs (assigned on DOMContentLoaded)
  let emojiBtn, composer, textarea, micBtn, plusBtn, attachMenuVertical;
  let sendBtn, emojiDrawer, messagesEl, inputEl, composerEl, composerMain, panel;
  let incomingCallBanner, incomingCallerNameEl, acceptCallBtn, declineCallBtn;
  let inCallControls, btnHangup, btnMute, btnToggleVideo, btnSwitchCam;
  let panelGrid;

  // Helper: safe getElement
  function $id(id){ return document.getElementById(id) || null; }

  // Simple HTML escape
  function escapeHtml(s){ return String(s||'').replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }

  // Expose escapeHtml (some other code may call it)
  window.escapeHtml = escapeHtml;

  async function sendMessage(textArg, attsArg) {
      const inputEl = document.querySelector('#msg') || document.querySelector('#textarea');
      const text = (typeof textArg === 'string') ? textArg.trim() : (inputEl ? (inputEl.value || '').trim() : '');
      const atts = Array.isArray(attsArg) ? attsArg : (cs.stagedFiles || []).slice();
    
      if (!text && (!atts || atts.length === 0)) return;
    
      try {
        let res, json;
    
        if (atts.length > 0) {
          // send files + text
          const fd = new FormData();
          fd.append('text', text);
          fd.append('sender', cs.myName);
          for (const f of atts) fd.append('file', f, f.name);
    
          res = await fetch('/send_composite_message', { method: 'POST', body: fd, credentials: 'same-origin' });
          json = await res.json().catch(() => null);
    
          if (res.ok && json && json.message) {
            appendMessage(json.message);
            cs.stagedFiles = [];
            if (inputEl) inputEl.value = '';
            const preview = document.getElementById('attachmentPreview') || document.getElementById('previewContainer');
            if (preview) { preview.innerHTML = ''; preview.style.display = 'none'; }
            cs.lastId = json.message.id || cs.lastId;
            return json.message;
          } else {
            cs.lastId = 0;
            if (typeof poll === 'function') await poll();
            return null;
          }
        } else {
          // send text only
          res = await fetch('/send_message', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, sender: cs.myName }),
            credentials: 'same-origin'
          });
    
          json = await res.json().catch(() => null);
    
          if (res.ok && json && json.message) {
            appendMessage(json.message);
            if (inputEl) inputEl.value = '';
            cs.stagedFiles = [];
            cs.lastId = json.message.id || cs.lastId;
            return json.message;
          } else {
            cs.lastId = 0;
            if (typeof poll === 'function') await poll();
            return null;
          }
        }
      } catch (err) {
        console.error('sendMessage error', err);
        alert('Send error: ' + (err && err.message ? err.message : err));
        return null;
      }
  }
    
    // expose globally
    window.sendMessage = sendMessage;

    // === Dedup & safe append helpers ===
    window._renderedMessageIds = window._renderedMessageIds || new Set();
    
    // idempotent appendMessage: will not add the same message twice
    window.appendMessage = window.appendMessage || function appendMessage(m){
      try {
        if (!m) return;
        // messages from the server should have numeric id
        const mid = (typeof m.id !== 'undefined') ? Number(m.id) : null;
    
        if (mid !== null) {
          if (window._renderedMessageIds.has(mid)) return; // already rendered
          window._renderedMessageIds.add(mid);
        }
    
        // create DOM as your code expects (keep consistent with your existing renderer)
        const me = (m.sender === (window.cs && window.cs.myName));
        const wrapper = document.createElement('div'); wrapper.className = 'msg-row';
        const body = document.createElement('div'); body.className = 'msg-body';
    
        const meta = document.createElement('div'); meta.className = 'msg-meta-top';
        const leftMeta = document.createElement('div'); leftMeta.innerHTML = `<strong>${escapeHtml(m.sender||'')}</strong>`;
        const rightMeta = document.createElement('div'); rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
        meta.appendChild(leftMeta); meta.appendChild(rightMeta);
        body.appendChild(meta);
    
        const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me' : 'them');
    
        if (m.text) {
          const textNode = document.createElement('div');
          textNode.innerHTML = escapeHtml(m.text) + (m.edited ? '<span style="font-size:.7rem;color:#9ca3af">(edited)</span>':'');
          bubble.appendChild(textNode);
        }
    
        // attachments (basic)
        (m.attachments || []).forEach(a=>{
          if (a.type === 'image') {
            const img = document.createElement('img'); img.src = a.url; img.className = 'image-attachment';
            bubble.appendChild(img);
          } else {
            const d = document.createElement('div'); d.className = 'preview-item-doc'; d.textContent = a.name || a.url || '';
            bubble.appendChild(d);
          }
        });
    
        // attach menu button (three-dot)
        const menuBtn = document.createElement('button'); menuBtn.className='three-dot'; menuBtn.innerText='⋯';
        menuBtn.onclick = function(ev){
          ev.stopPropagation();
          // your existing logic to show menu...
          // (if you already have a menu creation function, call it here)
        };
        bubble.appendChild(menuBtn);
    
        body.appendChild(bubble);
        wrapper.appendChild(body);
    
        const messagesEl = document.getElementById('messages') || document.querySelector('.messages');
        if (messagesEl) {
          messagesEl.appendChild(wrapper);
          messagesEl.scrollTop = messagesEl.scrollHeight;
        }
      } catch (err) {
        console.error('appendMessage error', err);
      }
    };
    
    // === Socket handler — only append if not already rendered ===
    if (window.socket && typeof window.socket.on === 'function') {
      window.socket.off && window.socket.off('new_message'); // remove prior if present
      window.socket.on('new_message', (m) => {
        try {
          if(!m) return;
          // If message has numeric id and already rendered, skip
          const mid = (typeof m.id !== 'undefined') ? Number(m.id) : null;
          if (mid !== null && window._renderedMessageIds.has(mid)) return;
          appendMessage(m);
          if (window.cs) window.cs.lastId = Math.max(window.cs.lastId || 0, mid || window.cs.lastId || 0);
        } catch(e){ console.error('socket new_message handler error', e); }
      });
    }

  // Attachment preview setter (exposed)
  function setAttachmentPreview(files){
    cs.stagedFiles = Array.from(files||[]);
    const preview = $id('attachmentPreview') || $id('previewContainer');
    if(!preview) return;
    preview.innerHTML = '';
    preview.style.display = cs.stagedFiles.length ? 'block' : 'none';
    cs.stagedFiles.forEach((file, idx)=>{
      const item = document.createElement('div'); item.className='preview-item';
      const removeBtn = document.createElement('button'); removeBtn.className='preview-remove-btn'; removeBtn.innerText='×';
      removeBtn.onclick = (e)=>{ e.stopPropagation(); cs.stagedFiles.splice(idx,1); setAttachmentPreview(cs.stagedFiles); };
      item.appendChild(removeBtn);
      if(file.type && file.type.startsWith('image/')){
        const img = document.createElement('img');
        const reader = new FileReader();
        reader.onload = (ev)=> img.src = ev.target.result;
        reader.readAsDataURL(file);
        item.appendChild(img);
      } else if(file.type && file.type.startsWith('video/')){
        const img = document.createElement('img'); img.className='thumb'; item.appendChild(img);
        createVideoThumbnailFromFile(file).then(dataUrl=>{ if(dataUrl) img.src = dataUrl; });
      } else if(file.type && file.type.startsWith('audio/')){
        const au = document.createElement('audio'); const url=URL.createObjectURL(file); au.src = url; au.controls=true; item.appendChild(au);
      } else {
        const d = document.createElement('div'); d.className='preview-item-doc'; d.textContent = file.name || 'file'; item.appendChild(d);
      }
      preview.appendChild(item);
    });
  }
  window.setAttachmentPreview = setAttachmentPreview;

  // Video thumbnail helpers
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
  window.createVideoThumbnailFromFile = createVideoThumbnailFromFile;

  // Recording/voice message helpers - single source of truth
  let mediaRecorder = null;
  let micStream = null;
  let audioChunks = [];
  let recording = false;

  async function startRecording(){
    if(recording) return;
    if(!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia){ alert('Microphone not supported in this browser.'); return; }
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
        cs.stagedFiles = [file];
        setAttachmentPreview(cs.stagedFiles);

        // send automatically
        try{
          const fd = new FormData();
          fd.append('text', '');
          fd.append('file', file, file.name);
          const r = await fetch('/send_composite_message', { method: 'POST', body: fd });
          if(r.ok){
            cs.stagedFiles = [];
            setAttachmentPreview([]);
            if(messagesEl){ messagesEl.innerHTML=''; }
            cs.lastId = 0;
            if(typeof window.poll === 'function') await window.poll();
          } else {
            const txt = await r.text();
            alert('Voice send failed: ' + txt);
          }
        }catch(err){
          alert('Voice send error: ' + (err && err.message ? err.message : err));
        }finally{
          audioChunks = [];
        }
      });
      mediaRecorder.start();
      recording = true;
      updateMicUI(true);
    }catch(err){
      console.error('microphone error', err);
      alert('Could not start microphone: ' + (err && err.message ? err.message : err));
      if(micStream){ micStream.getTracks().forEach(t=>t.stop()); micStream=null; }
      recording = false;
      updateMicUI(false);
    }
  }

  function stopRecording(){
    if(!recording) return;
    try{ if(mediaRecorder && mediaRecorder.state !== 'inactive') mediaRecorder.stop(); }catch(e){ console.warn(e); }
    if(micStream){ micStream.getTracks().forEach(t=>t.stop()); micStream=null; }
    recording = false;
    updateMicUI(false);
  }

  function toggleRecording(){ if(recording) stopRecording(); else startRecording(); }

  function updateMicUI(state){
    if(!micBtn) return;
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

  // Utility: gather attachments from preview container (legacy)
  function gatherAttachments(){
    const items = document.querySelectorAll('#previewContainer .preview-item');
    const atts = [];
    items.forEach(p=>{
      if(p.type === 'audio'){
        atts.push({ type:'audio', blob: p.blob });
      }
      // other handling omitted for brevity - prefer cs.stagedFiles
    });
    return atts;
  }

  // Show / hide sticker panel — fixed + accessible version
    function openStickerPanel() {
      const panel = document.getElementById('stickerPanel');
      const composer = document.querySelector('.composer');
    
      if (!panel) return;
    
      // Show panel
      panel.hidden = false;
      panel.inert = false;
      panel.classList.add('active');
      panel.setAttribute('aria-hidden', 'false');
    
      // Move composer above the panel
      if (composer) {
        const h = panel.offsetHeight || 280;
        composer.style.bottom = `${h}px`;
      }
    
      // Focus first focusable item to avoid accessibility warnings
      const firstFocusable = panel.querySelector(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (firstFocusable) firstFocusable.focus();
    }
    
    function closeStickerPanel() {
      const panel = document.getElementById('stickerPanel');
      const composer = document.querySelector('.composer');
      const input = document.getElementById('chatInput');
    
      if (!panel) return;
    
      // Hide panel visually & from accessibility tree
      panel.classList.remove('active');
      panel.hidden = true;
      panel.inert = true;
      panel.setAttribute('aria-hidden', 'true');
    
      // Reset composer position
      if (composer) composer.style.bottom = '0px';
    
      // Move focus back to chat input to prevent focus being hidden
      if (input) input.focus();
    }

  /* ---------------------------
     WebRTC / calls
     --------------------------- */

  // small in-call UI helpers
  function showInCallUI(callId, peerName, isCaller){
    let callUi = $id('inCallUI');
    if(!callUi){
      callUi = document.createElement('div');
      callUi.id = 'inCallUI';
      callUi.style.position = 'fixed';
      callUi.style.bottom = '20px';
      callUi.style.right = '20px';
      callUi.style.zIndex = '10000';
      callUi.style.padding = '12px';
      callUi.style.background = 'rgba(0,0,0,0.8)';
      callUi.style.color = 'white';
      callUi.style.borderRadius = '10px';
      callUi.style.fontSize = '0.9rem';
      document.body.appendChild(callUi);
    }
    callUi.innerHTML = `<div>In call with <strong>${escapeHtml(peerName || '')}</strong></div><div>ID: ${escapeHtml(callId)}</div><button id="btnHangupUI">Hang Up</button>`;
    const btn = $id('btnHangupUI');
    if(btn) btn.onclick = ()=>{ hideInCallUI(); endCall(callId); };
    callUi.style.display = 'block';
  }
  function hideInCallUI(){ const ui = $id('inCallUI'); if(ui){ ui.style.display='none'; ui.innerHTML=''; } }
  window.showInCallUI = showInCallUI;
  window.hideInCallUI = hideInCallUI;

  // Peer helpers
  function getPeerForCall(callId){ return cs.calls[callId]?.peer || null; }
  function getCurrentCameraId(stream){ if(!stream) return null; const t = stream.getVideoTracks()[0]; if(!t) return null; return t.getSettings && t.getSettings().deviceId ? t.getSettings().deviceId : null; }

  function setupPeerConnection(callId, localStream, hasVideo){
    const pc = new RTCPeerConnection(cs.pcConfig);
    cs.calls[callId].pc = pc;

    if(localStream){
      localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
    }

    const remoteStream = new MediaStream();
    pc.ontrack = (evt)=>{
      evt.streams.forEach(s=> s.getTracks().forEach(t=> remoteStream.addTrack(t)));
      const remoteV = $id('remoteVideo') || (function(){ const v = document.createElement('video'); v.id='remoteVideo'; v.autoplay=true; v.playsInline=true; document.body.appendChild(v); return v; })();
      remoteV.srcObject = remoteStream;
    };

    pc.onicecandidate = (e)=>{
      if(e.candidate){
        cs.socket && cs.socket.emit && cs.socket.emit('call:candidate', { to: getPeerForCall(callId), from: cs.myName, candidate: e.candidate, call_id: callId });
      }
    };

    pc.onconnectionstatechange = ()=>{
      const st = pc.connectionState;
      console.log('pc state', st);
      if(st === 'connected') updateCallStateUI(callId, 'connected');
      if(st === 'disconnected' || st === 'failed' || st === 'closed') endCallLocal(callId, 'peer');
    };

    return pc;
  }

  async function startCall(toUser, isVideo=true){
    const callId = 'call-' + Date.now() + '-' + Math.random().toString(36).slice(2,8);
    const constraints = { audio: true, video: isVideo ? { facingMode: 'user' } : false };
    let localStream;
    try {
      localStream = await navigator.mediaDevices.getUserMedia(constraints);
    } catch(err){
      alert('Could not access microphone/camera: ' + (err && err.message ? err.message : err));
      return;
    }
    cs.calls[callId] = { localStream, isCaller: true, pc: null, currentCameraId: getCurrentCameraId(localStream), peer: toUser };
    setupPeerConnection(callId, localStream, isVideo);
    // notify callee
    cs.socket && cs.socket.emit && cs.socket.emit('call:invite', { to: toUser, from: cs.myName, is_video: !!isVideo, call_id: callId });
    // local preview
    const lv = $id('localVideo') || (function(){ const v=document.createElement('video'); v.id='localVideo'; v.autoplay=true; v.muted=true; document.body.appendChild(v); return v; })();
    lv.srcObject = localStream; lv.style.display = isVideo ? 'block' : 'none';
    showInCallUI(callId, toUser, true);
  }
  window.startCall = startCall;

  async function toggleMute(callId){
    const call = cs.calls[callId]; if(!call || !call.localStream) return;
    call.localStream.getAudioTracks().forEach(t => { t.enabled = !t.enabled; });
    cs.socket && cs.socket.emit && cs.socket.emit('call:signal', { to: getPeerForCall(callId), payload: { type: 'mute', by: cs.myName, muted: !call.localStream.getAudioTracks()[0].enabled } });
  }
  async function toggleVideo(callId){
    const call = cs.calls[callId]; if(!call || !call.localStream) return;
    call.localStream.getVideoTracks().forEach(t=> t.enabled = !t.enabled);
    cs.socket && cs.socket.emit && cs.socket.emit('call:signal', { to: getPeerForCall(callId), payload: { type: 'video-toggled', by: cs.myName, videoOn: !!call.localStream.getVideoTracks().find(tt=>tt.enabled) } });
  }
  async function switchCamera(callId){
    const call = cs.calls[callId]; if(!call) return;
    const devices = await navigator.mediaDevices.enumerateDevices();
    const videoInputs = devices.filter(d=>d.kind==='videoinput');
    if(videoInputs.length<=1) return alert('No other camera found');
    const currentId = call.currentCameraId;
    let next = videoInputs.find(d=>d.deviceId !== currentId); if(!next) next = videoInputs[0];
    const newStream = await navigator.mediaDevices.getUserMedia({ video:{ deviceId:{ exact: next.deviceId } }, audio:false }).catch(()=>null);
    if(!newStream) return;
    const newTrack = newStream.getVideoTracks()[0];
    const pc = call.pc;
    const senders = pc.getSenders();
    const sender = senders.find(s => s.track && s.track.kind === 'video');
    if(sender) await sender.replaceTrack(newTrack);
    call.localStream.getVideoTracks().forEach(t=>{ t.stop(); call.localStream.removeTrack(t); });
    call.localStream.addTrack(newTrack);
    call.currentCameraId = next.deviceId;
    const lv = $id('localVideo'); if(lv) lv.srcObject = call.localStream;
  }

  async function shareScreen(callId){
    try{
      const screenStream = await navigator.mediaDevices.getDisplayMedia({ video:true });
      const call = cs.calls[callId]; if(!call) return;
      const screenTrack = screenStream.getVideoTracks()[0];
      const pc = call.pc;
      const senders = pc.getSenders();
      const videoSender = senders.find(s => s.track && s.track.kind === 'video');
      if(videoSender){
        await videoSender.replaceTrack(screenTrack);
        screenTrack.onended = async ()=>{
          const camStream = await navigator.mediaDevices.getUserMedia({ video:true }).catch(()=>null);
          if(camStream){
            const camTrack = camStream.getVideoTracks()[0];
            await videoSender.replaceTrack(camTrack);
            call.localStream.getVideoTracks().forEach(t=>t.stop());
            call.localStream.addTrack(camTrack);
            const lv = $id('localVideo'); if(lv) lv.srcObject = call.localStream;
          }
        };
      }
    }catch(e){ console.warn('screen share failed', e); }
  }

  function endCall(callId){
    cs.socket && cs.socket.emit && cs.socket.emit('call:hangup', { call_id: callId, from: cs.myName });
    endCallLocal(callId, cs.myName);
  }
  function endCallLocal(callId, by){
    const call = cs.calls[callId]; if(!call) return;
    try{
      if(call.pc){ call.pc.close(); call.pc = null; }
      if(call.localStream){ call.localStream.getTracks().forEach(t=>t.stop()); }
    }catch(e){}
    const lv = $id('localVideo'); if(lv) lv.srcObject = null;
    const rv = $id('remoteVideo'); if(rv) rv.srcObject = null;
    delete cs.calls[callId];
    hideInCallUI();
    alert('Call ended by ' + (by || 'local'));
  }

  // expose end/toggle functions for external UI
  window.toggleMute = toggleMute;
  window.toggleVideo = toggleVideo;
  window.switchCamera = switchCamera;
  window.endCall = endCall;
  window.shareScreen = shareScreen;

  /* ---------------------------
     Polling, rendering messages & reactions
     --------------------------- */

  // render and poll messages
    async function poll() {
      const me = cs.myName;
      try {
        const lastId = cs.lastId || 0;
        const endpoints = [
          `/poll_messages?since=${lastId}`
        ];
    
        const base = (typeof window.SERVER_URL === 'string' && window.SERVER_URL)
          ? window.SERVER_URL.replace(/\/$/, '')
          : '';
    
        let data = null;
    
        for (const ep of endpoints) {
          const url = base + ep;
          try {
            const resp = await fetch(url, { credentials: 'same-origin' });
            if (!resp.ok) {
              console.debug(`poll() - ${url} -> ${resp.status}`);
              continue;
            }
            data = await resp.json();
            if (!data || !data.length) return;
            console.debug('poll() succeeded with', url);
            break;
          } catch (err) {
            console.warn('poll() - fetch failed for', ep, err);
          }
        }
    
        if (!data || !data.length) return;
    
        // inside poll() after you fetch messages array `data`
        for (const m of data) {
          if (m.id && window._renderedMessageIds.has(Number(m.id))) continue;
          appendMessage(m);
          if (m.id) window._renderedMessageIds.add(Number(m.id));
          if (m.id && Number(m.id) > (cs.lastId||0)) cs.lastId = Number(m.id);
    
          // === META ===
          const meta = document.createElement('div');
          meta.className = 'msg-meta-top';
          const leftMeta = document.createElement('div');
          leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong>`;
          const rightMeta = document.createElement('div');
          rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
          meta.appendChild(leftMeta);
          meta.appendChild(rightMeta);
          body.appendChild(meta);
    
          // === BUBBLE ===
          const hasText = m.text && m.text.trim().length > 0;
          const attachments = m.attachments || [];
          const bubble = document.createElement('div');
          bubble.className = 'bubble ' + (me ? 'me' : 'them');
    
          if (hasText) {
            const textNode = document.createElement('div');
            textNode.innerHTML =
              escapeHtml(m.text) +
              (m.edited
                ? '<span style="font-size:.7rem;color:#9ca3af">(edited)</span>'
                : '');
            bubble.appendChild(textNode);
          }
    
          // === ATTACHMENTS ===
          if (attachments && attachments.length) {
            for (const a of attachments) {
              if (a.type === 'sticker') {
                const s = document.createElement('img');
                s.src = a.url;
                s.className = 'sticker';
                s.style.marginTop = '8px';
                s.style.maxWidth = '180px';
                s.style.borderRadius = '8px';
                bubble.appendChild(s);
              } else if (a.type === 'poll') {
                const p = document.createElement('div');
                p.className = 'poll';
                p.style.marginTop = '8px';
    
                if (m.text && m.text.trim()) {
                  const qEl = document.createElement('div');
                  qEl.style.fontWeight = '600';
                  qEl.style.marginBottom = '6px';
                  qEl.textContent = m.text;
                  p.appendChild(qEl);
                }
    
                if (a.options && a.options.length) {
                  const list = document.createElement('div');
                  list.style.display = 'flex';
                  list.style.flexDirection = 'column';
                  list.style.gap = '6px';
                  const counts = a.counts || new Array(a.options.length).fill(0);
                  const multi = !!a.multi;
                  a.options.forEach((op, i) => {
                    const optBtn = document.createElement('button');
                    optBtn.className =
                      'poll-option w-full px-3 py-2 rounded bg-gray-100 text-left';
                    const count = counts[i] || 0;
                    optBtn.innerHTML = `${op} <span class="poll-count" style="float:right">— ${count} vote${count !== 1 ? 's' : ''}</span>`;
                    optBtn.dataset.messageId = m.id;
                    optBtn.dataset.index = i;
                    optBtn.dataset.multi = multi ? '1' : '0';
                    optBtn.addEventListener('click', async (ev) => {
                      ev.preventDefault();
                      try {
                        await fetch('/vote_poll', {
                          method: 'POST',
                          headers: { 'Content-Type': 'application/json' },
                          body: JSON.stringify({
                            message_id: m.id,
                            option: i,
                            user: cs.myName
                          })
                        });
                        cs.lastId = 0;
                        if (typeof poll === 'function') await poll();
                      } catch (err) {
                        console.warn('vote failed', err);
                      }
                    });
                    list.appendChild(optBtn);
                  });
                  p.appendChild(list);
                }
                bubble.appendChild(p);
              } else {
                const { element } = createAttachmentElement(a);
                if (element) bubble.appendChild(element);
              }
            }
          }
    
          // === REACTIONS ===
          if (m.reactions && m.reactions.length) {
            const agg = {};
            for (const r of m.reactions) {
              agg[r.emoji] = agg[r.emoji] || new Set();
              agg[r.emoji].add(r.user);
            }
            const reactionBar = document.createElement('div');
            reactionBar.className = 'reaction-bar';
            for (const emoji in agg) {
              const userset = agg[emoji];
              const pill = document.createElement('div');
              pill.className = 'reaction-pill';
              const em = document.createElement('div');
              em.className = 'reaction-emoji';
              em.innerText = emoji;
              const count = document.createElement('div');
              count.style.fontSize = '0.85rem';
              count.style.color = '#374151';
              count.innerText = userset.size;
              pill.appendChild(em);
              pill.appendChild(count);
              reactionBar.appendChild(pill);
            }
            bubble.appendChild(reactionBar);
          }
    
          // === MESSAGE MENU ===
          const menuBtn = document.createElement('button');
          menuBtn.className = 'three-dot';
          menuBtn.innerText = '⋯';
          menuBtn.onclick = (ev) => {
            ev.stopPropagation();
            document.querySelectorAll('.menu:not(#profileMenu)').forEach(n => n.remove());
            const menu = document.createElement('div');
            menu.className = 'menu';
            menu.style.position = 'absolute';
            menu.style.zIndex = 200;
            menu.style.background = 'white';
            menu.style.border = '1px solid #e5e7eb';
            menu.style.boxShadow = '0 6px 18px rgba(0,0,0,0.08)';
            menu.style.borderRadius = '8px';
            menu.style.padding = '8px';
            menu.style.top = (menuBtn.getBoundingClientRect().bottom + 8) + 'px';
            menu.style.left = (menuBtn.getBoundingClientRect().left - 160) + 'px';
    
            const del = document.createElement('div');
            del.innerText = 'Delete';
            del.style.cursor = 'pointer';
            del.style.padding = '6px 8px';
            del.onclick = async (e) => {
              e.stopPropagation();
              if (confirm('Delete this message?')) {
                await fetch('/delete_message', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ id: m.id })
                });
                const messagesEl =
                  document.getElementById('messages') || document.querySelector('.messages');
                if (messagesEl) messagesEl.innerHTML = '';
                cs.lastId = 0;
                await poll();
              }
            };
    
            const forward = document.createElement('div');
            forward.innerText = 'Forward';
            forward.style.cursor = 'pointer';
            forward.style.padding = '6px 8px';
            forward.onclick = () => {
              navigator.clipboard.writeText(m.text || '');
              alert('Message copied for forwarding');
            };
    
            const copy = document.createElement('div');
            copy.innerText = 'Copy';
            copy.style.cursor = 'pointer';
            copy.style.padding = '6px 8px';
            copy.onclick = () => {
              navigator.clipboard.writeText(m.text || '');
              alert('Copied to clipboard');
            };
    
            const reshare = document.createElement('div');
            reshare.innerText = 'Reshare';
            reshare.style.cursor = 'pointer';
            reshare.style.padding = '6px 8px';
            reshare.onclick = () => {
              alert('Reshare placeholder');
            };
    
            const react = document.createElement('div');
            react.innerText = 'React';
            react.style.cursor = 'pointer';
            react.style.padding = '6px 8px';
            react.onclick = (ev2) => {
              ev2.stopPropagation();
              showEmojiPickerForMessage(m.id, menuBtn);
            };
    
            menu.appendChild(copy);
            menu.appendChild(forward);
            menu.appendChild(reshare);
            if (m.sender === cs.myName) menu.appendChild(del);
            menu.appendChild(react);
            document.body.appendChild(menu);
    
            const hide = () => {
              menu.remove();
              document.removeEventListener('click', hide);
            };
            setTimeout(() => document.addEventListener('click', hide), 50);
          };
    
          bubble.appendChild(menuBtn);
          body.appendChild(bubble);
          wrapper.appendChild(body);
    
          const messagesEl =
            document.getElementById('messages') || document.querySelector('.messages');
          if (messagesEl) messagesEl.appendChild(wrapper);
    
          if (m.id && Number(m.id) > (cs.lastId || 0)) cs.lastId = Number(m.id);
        }
    
        // === AUTO SCROLL ===
        const container =
          document.getElementById('messages') || document.querySelector('.messages');
        if (container) container.scrollTop = container.scrollHeight;
    
      } catch (e) {
        console.error('poll error', e);
      }
    }
    
    window.poll = poll;

  // Reaction picker
  function showEmojiPickerForMessage(msgId, anchorEl){
    const picker = document.createElement('div'); picker.className='menu';
    const emojis = ['😀','😁','😂','😍','😮','😢','😡','👍','👎','🎉','🔥','❤️','👏','🤝','🤯'];
    emojis.forEach(em=>{
      const el = document.createElement('div'); el.style.display='inline-flex'; el.style.padding='6px'; el.style.margin='4px'; el.style.cursor='pointer';
      el.innerText = em;
      el.onclick = async (ev)=>{ ev.stopPropagation(); try{ await fetch('/react_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ id: msgId, emoji: em }) }); }catch(err){console.warn('react failed',err);} picker.remove(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll(); };
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
  window.showEmojiPickerForMessage = showEmojiPickerForMessage;

  // createAttachmentElement: returns DOM element for an attachment
  function createAttachmentElement(a){
    const container = document.createElement('div');
    container.className = 'media-container mt-2';
    if(!a) return { element: null };

    if(a.type === 'audio' || a.type === 'voice'){
      const au = document.createElement('audio'); au.src = a.url; au.controls = true; au.className = 'mt-2';
      container.appendChild(au); return { element: container };
    }
    if(a.type === 'doc'){
      const link = document.createElement('a'); link.href = a.url; link.className = 'doc-link'; link.setAttribute('download', a.name || 'Document');
      link.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#111827" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h11"></path><polyline points="17 2 17 8 23 8"></polyline></svg><span style="font-size:0.92rem">${escapeHtml(a.name || 'Document')}</span>`;
      container.appendChild(link); return { element: container };
    }
    if(a.type === 'location'){
      const card = document.createElement('a'); card.href = a.url || '#'; card.target = '_blank'; card.style.display='block'; card.style.maxWidth='320px'; card.style.borderRadius='10px'; card.style.overflow='hidden'; card.style.boxShadow='0 6px 18px rgba(0,0,0,0.08)'; card.style.textDecoration='none'; card.style.color='inherit';
      const img = document.createElement('img'); img.src = a.map; img.alt = 'location'; img.style.width='100%'; img.style.display='block';
      const caption = document.createElement('div'); caption.style.padding='8px'; caption.style.background = '#fff'; caption.style.fontSize = '.9rem'; caption.innerText = '📍 Shared Location';
      card.appendChild(img); card.appendChild(caption); container.appendChild(card); return { element: container };
    }
    if(a.type === 'image'){
      const img = document.createElement('img'); img.src = a.url; img.className = 'image-attachment'; img.style.maxWidth='420px'; img.style.borderRadius='10px';
      container.appendChild(img); return { element: container, mediaElement: img };
    }
    if(a.type === 'video'){
      const thumbImg = document.createElement('img'); thumbImg.className = 'thumb'; thumbImg.alt = a.name || 'video';
      const playOverlay = document.createElement('div'); playOverlay.className='play-overlay'; playOverlay.innerHTML = '<div class="play-circle">▶</div>';
      container.appendChild(thumbImg); container.appendChild(playOverlay);
      createVideoThumbnailFromUrl(a.url, 0.7).then(dataUrl=>{ if(dataUrl) thumbImg.src = dataUrl; else { const v = document.createElement('video'); v.src = a.url; v.controls = true; v.className='video-attachment'; container.innerHTML = ''; container.appendChild(v); } });
      container.addEventListener('click', ()=>{
        if(container.querySelector('video')) return;
        const v = document.createElement('video'); v.src = a.url; v.controls = true; v.autoplay = true; v.playsInline = true; v.className='video-attachment';
        container.innerHTML = ''; container.appendChild(v);
      }, { once:true });
      return { element: container, mediaElement: thumbImg };
    }
    return { element: null };
  }
  window.createAttachmentElement = createAttachmentElement;

  /* ---------------------------
     Sticker / GIF / avatar handling & UI wiring
     --------------------------- */

  async function loadGIFs(){
    if(!panelGrid) return;
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
        w.onclick = async ()=> { await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url: gifUrl }] }) }); hideStickerPanel(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll(); };
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
          w.onclick = async ()=> { await fetch('/send_message',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ text:'', attachments:[{ type:'sticker', url }] }) }); hideStickerPanel(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll(); };
          panelGrid.appendChild(w);
        }
      }catch(e2){
        panelGrid.innerHTML = '<div>Error loading GIFs</div>';
      }
    }
  }
  window.loadGIFs = loadGIFs;

  async function loadAvatars(){
    if(!panelGrid) return;
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
        hideStickerPanel(); if(messagesEl){ messagesEl.innerHTML=''; } cs.lastId=0; await poll();
      };
      panelGrid.appendChild(wrapper);
    }
  }
  window.loadAvatars = loadAvatars;

  /* ---------------------------
     Typing indicator wiring (socket handlers)
     --------------------------- */

  // ensure socket handlers register only once
  function registerSocketHandlers(){
    if(!cs.socket) return;

    // typing
    cs.socket.on('typing', (d)=>{
      try{
        const nodeId = 'typing-'+(d && d.from ? d.from : 'user');
        if(document.getElementById(nodeId)) return;
        const el = document.createElement('div'); el.id = nodeId; el.className='msg-row';
        el.innerHTML = `<div class="msg-body"><div class="bubble them"><em>${escapeHtml((d && d.from) || 'Someone')} is typing…</em></div></div>`;
        messagesEl && messagesEl.appendChild(el);
        messagesEl && (messagesEl.scrollTop = messagesEl.scrollHeight);
      }catch(e){ console.warn('typing handler err', e); }
    });

    cs.socket.on('stop_typing', (d)=>{
      try{
        const nodeId = 'typing-'+(d && d.from ? d.from : 'user');
        const el = document.getElementById(nodeId); if(el) el.remove();
      }catch(e){ console.warn('stop_typing handler err', e); }
    });

    // call signaling
    cs.socket.on('call:incoming', (d) => {
      try{
        const caller = d.from;
        const callId = d.call_id;
        if(incomingCallerNameEl) incomingCallerNameEl.textContent = caller;
        if(incomingCallBanner) incomingCallBanner.classList.remove('hidden');
        cs.activeCallId = callId;
      }catch(e){ console.warn(e); }
    });

    cs.socket.on('call:accepted', async (d)=>{
      try{
        const callId = d.call_id; const call = cs.calls[callId];
        if(!call || !call.pc) return;
        const offer = await call.pc.createOffer();
        await call.pc.setLocalDescription(offer);
        cs.socket.emit('call:offer', { to: d.from, from: cs.myName, sdp: offer, call_id: callId });
      }catch(e){ console.error('offer error', e); }
    });

    cs.socket.on('call:offer', async (d)=>{
      try{
        const callId = d.call_id; const fromUser = d.from;
        let localStream;
        try { localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:true }); }
        catch(e){ localStream = await navigator.mediaDevices.getUserMedia({ audio:true, video:false }).catch(()=>null); }
        cs.calls[callId] = { localStream, pc: null, isCaller: false, currentCameraId: getCurrentCameraId(localStream), peer: fromUser };
        setupPeerConnection(callId, localStream, !!(localStream && localStream.getVideoTracks().length));
        try{
          await cs.calls[callId].pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
          const answer = await cs.calls[callId].pc.createAnswer();
          await cs.calls[callId].pc.setLocalDescription(answer);
          cs.socket.emit('call:answer', { to: fromUser, from: cs.myName, sdp: answer, call_id: callId });
          showInCallUI(callId, fromUser, false);
        }catch(err){ console.error('handle offer error', err); }
      }catch(e){ console.warn('call:offer handler err', e); }
    });

    cs.socket.on('call:answer', async (d)=>{
      try{
        const callId = d.call_id; const call = cs.calls[callId];
        if(!call || !call.pc) return;
        await call.pc.setRemoteDescription(new RTCSessionDescription(d.sdp));
        updateCallStateUI(callId, 'connected');
        // optionally update server call start
      }catch(e){ console.error('call answer error', e); }
    });

    cs.socket.on('call:candidate', async (d)=>{
      try{
        const callId = d.call_id; const call = cs.calls[callId];
        if(!call || !call.pc || !d.candidate) return;
        await call.pc.addIceCandidate(new RTCIceCandidate(d.candidate));
      }catch(e){ console.warn('candidate add failed', e); }
    });

    cs.socket.on('call:ended', (d)=>{
      try{ const callId = d.call_id; endCallLocal(callId, d.by); }catch(e){ console.warn(e); }
    });

    cs.socket.on('poll_update', (d)=>{
      try{
        const mid = String(d.message_id);
        const counts = d.counts || [];
        document.querySelectorAll(`.poll-option[data-message-id="${mid}"]`).forEach(btn=>{
          const idx = parseInt(btn.dataset.index, 10);
          const label = btn.dataset.label || (btn.textContent || '').split('—')[0].trim();
          const count = (counts[idx] !== undefined) ? counts[idx] : 0;
          btn.innerHTML = `${label} <span class="poll-count" style="float:right">— ${count} vote${count !== 1 ? 's' : ''}</span>`;
        });
      }catch(e){ console.warn('poll_update err', e); }
    });

    // other socket handlers (react, etc.) are handled by fetching endpoints on action
  }

  // register socket handlers once
  if(cs.socket) registerSocketHandlers();

  /* ---------------------------
     Helper: attachment selectors (file inputs)
     --------------------------- */
  function openFileSelector(camera){
    const inp = document.createElement('input'); inp.type='file'; inp.accept='image/*,video/*'; if(camera) inp.setAttribute('capture','environment');
    inp.multiple = true;
    inp.onchange = (ev)=> setAttachmentPreview(ev.target.files);
    inp.click();
  }
  function openDocSelector(){ const inp = document.createElement('input'); inp.type='file'; inp.multiple=true; inp.onchange = (ev)=> setAttachmentPreview(ev.target.files); inp.click(); }
  function openAudioSelector(){ const inp = document.createElement('input'); inp.type='file'; inp.accept='audio/*'; inp.multiple=true; inp.onchange = (ev)=> setAttachmentPreview(ev.target.files); inp.click(); }

  /* ---------------------------
     Adaptive meta color sampling (kept as in your file)
     --------------------------- */
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
    _bgCanvas.width = w; _bgCanvas.height = h;
    try{
      if(_bgImg && _bgImg.complete && _bgImg.naturalWidth){
        const iw = _bgImg.naturalWidth, ih = _bgImg.naturalHeight;
        const scale = Math.max(w/iw, h/ih);
        const dw = iw * scale, dh = ih * scale;
        const dx = (w - dw) / 2, dy = (h - dh) / 2;
        _bgCtx.clearRect(0,0,w,h);
        _bgCtx.drawImage(_bgImg, 0,0, iw, ih, dx, dy, dw, dh);
      } else {
        _bgCtx.fillStyle = '#ffffff'; _bgCtx.fillRect(0,0,w,h);
      }
    }catch(e){ try{ _bgCtx.fillStyle = '#ffffff'; _bgCtx.fillRect(0,0,w,h); }catch(_){}
    }
    _bgDrawSize.w = w; _bgDrawSize.h = h;
  }
  function samplePixelAtScreenXY(x,y){
    try{
      drawBgToCanvasIfNeeded();
      const ix = Math.max(0, Math.min(_bgCanvas.width-1, Math.round(x)));
      const iy = Math.max(0, Math.min(_bgCanvas.height-1, Math.round(y)));
      const d = _bgCtx.getImageData(ix, iy, 1, 1).data;
      return { r: d[0], g: d[1], b: d[2] };
    }catch(e){ return { r:255,g:255,b:255 }; }
  }
  function luminance(r,g,b){ return 0.299*r + 0.587*g + 0.114*b; }

  async function updateMetaColors(){
    await ensureBgLoaded();
    drawBgToCanvasIfNeeded();
    const metas = document.querySelectorAll(".msg-meta-top");
    for(const el of metas){
      const rect = el.getBoundingClientRect();
      const x = rect.left + rect.width/2;
      const y = rect.top + rect.height/2;
      const { r,g,b } = samplePixelAtScreenXY(x,y);
      const lum = luminance(r,g,b);
      el.style.color = lum > 150 ? "#111" : "#f9fafb";
    }
  }
  window.addEventListener("scroll", updateMetaColors);
  window.addEventListener("resize", ()=>{ _bgDrawSize={w:0,h:0}; updateMetaColors(); });
  setInterval(updateMetaColors, 2000);

  /* ---------------------------
     Composer elevation toggle (kept)
     --------------------------- */
  let composerMainEl = null;
  function setComposerElevated(state){ if(!composerMainEl) return; composerMainEl.classList.toggle('glass-elevated', Boolean(state)); }
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

/* ====== Minimal helper implementations to make UI work ======
   Paste this block BEFORE your DOMContentLoaded block or above sendMessage()
   These are defensive, minimal, and practical - adapt styling/markup as needed.
*/

(function(){
  // Ensure global app state container exists
  window.cs = window.cs || { stagedFiles: [], lastId: 0, isTyping: false, typingTimer: null, socket: null, myName: 'me' };

  // Append message to messages container (used both for optimistic and incoming messages)
  window.appendMessage = function appendMessage(msg) {
    try {
      const messagesEl = document.getElementById('messages') || document.querySelector('.messages') || document.querySelector('#chatContainer');
      if (!messagesEl) return console.warn('appendMessage: messages container not found');
      const wrapper = document.createElement('div');
      wrapper.className = msg.isSystem ? 'msg-row system' : (msg.from === cs.myName ? 'msg-row me' : 'msg-row them');
      const body = document.createElement('div');
      body.className = 'msg-body';
      const bubble = document.createElement('div');
      bubble.className = 'bubble';
      if (msg.text) bubble.appendChild(document.createTextNode(msg.text));
      // attachments (simple handling)
      if (Array.isArray(msg.attachments)) {
        msg.attachments.forEach(a => {
          if (!a) return;
          if (a.type === 'image' || (a.url && a.url.match(/\.(jpeg|jpg|gif|png|webp)$/i))) {
            const img = document.createElement('img');
            img.className = 'image-attachment';
            img.src = a.url || a.preview || '';
            bubble.appendChild(img);
          } else if (a.type === 'audio' || (a.url && a.url.match(/\.(mp3|wav|ogg)$/i))) {
            const au = document.createElement('audio');
            au.controls = true;
            au.src = a.url || a.preview || '';
            bubble.appendChild(au);
          } else if (a.type === 'location') {
            const link = document.createElement('a');
            link.href = a.url || '#';
            link.target = '_blank';
            link.textContent = a.url || `${a.lat},${a.lng}`;
            bubble.appendChild(link);
          } else { // generic file
            const d = document.createElement('div'); d.className = 'preview-item-doc'; d.textContent = a.name || 'file';
            bubble.appendChild(d);
          }
        });
      }
      body.appendChild(bubble);
      wrapper.appendChild(body);
      messagesEl.appendChild(wrapper);
      messagesEl.scrollTop = messagesEl.scrollHeight;
      return wrapper;
    } catch (err) {
      console.error('appendMessage error', err);
    }
  };

  // insertAtCursor: insert text into input/textarea at caret
  window.insertAtCursor = function insertAtCursor(input, text) {
    try {
      if (!input) return;
      if (input.selectionStart || input.selectionStart === 0) {
        const start = input.selectionStart, end = input.selectionEnd;
        const val = input.value;
        input.value = val.substring(0, start) + text + val.substring(end);
        const pos = start + text.length;
        input.selectionStart = input.selectionEnd = pos;
      } else {
        input.value += text;
      }
      // trigger input events
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.focus();
    } catch (err) { console.error('insertAtCursor error', err); }
  };

  // createVideoThumbnailFromFile(file, scale=0.7) => Promise<dataURL|string|null>
  window.createVideoThumbnailFromFile = async function createVideoThumbnailFromFile(file, scale) {
    scale = scale || 0.7;
    if (!file) return null;
    return new Promise((resolve) => {
      try {
        const url = URL.createObjectURL(file);
        const v = document.createElement('video');
        v.preload = 'metadata';
        v.muted = true;
        v.src = url;
        v.addEventListener('loadeddata', () => {
          try {
            // choose a frame ~0.5s or the middle
            const canvas = document.createElement('canvas');
            const w = v.videoWidth || 320;
            const h = v.videoHeight || 180;
            canvas.width = Math.max(1, Math.floor(w * scale));
            canvas.height = Math.max(1, Math.floor(h * scale));
            const ctx = canvas.getContext('2d');
            ctx.drawImage(v, 0, 0, canvas.width, canvas.height);
            const data = canvas.toDataURL('image/jpeg', 0.8);
            URL.revokeObjectURL(url);
            resolve(data);
          } catch (err) {
            URL.revokeObjectURL(url);
            resolve(null);
          }
        }, { once: true });
        // timeout fallback
        setTimeout(() => { try { URL.revokeObjectURL(url); } catch(_){}; resolve(null); }, 4000);
      } catch (err) { console.error('createVideoThumbnailFromFile', err); resolve(null); }
    });
  };

  // show/hide sticker panel
  window.showStickerPanel = function showStickerPanel() {
    const panel = document.getElementById('stickerPanel') || document.querySelector('.sticker-panel');
    if (!panel) return;
    panel.classList.add('active');
    panel.style.display = panel.style.display || 'block';
    try { panel.inert = false; } catch(_) {}
  };
  window.hideStickerPanel = function hideStickerPanel() {
    const panel = document.getElementById('stickerPanel') || document.querySelector('.sticker-panel');
    if (!panel) return;
    panel.classList.remove('active');
    panel.style.display = 'none';
    try { panel.inert = true; } catch(_) {}
  };
  window.closeDrawer = window.hideStickerPanel;

  // file pickers: adds selected files to cs.stagedFiles and visits preview
  window.setAttachmentPreview = function setAttachmentPreview() {
    const preview = document.getElementById('attachmentPreview') || document.getElementById('previewContainer');
    if (!preview) return;
    preview.innerHTML = '';
    if (!Array.isArray(cs.stagedFiles) || cs.stagedFiles.length === 0) {
      preview.style.display = 'none';
      return;
    }
    preview.style.display = 'block';
    cs.stagedFiles.forEach(f => {
      const node = document.createElement('div');
      node.className = 'attachment-preview-item';
      if (f.type && f.type.startsWith('image/')) {
        const img = document.createElement('img'); img.src = URL.createObjectURL(f); img.className='preview-img';
        node.appendChild(img);
      } else {
        node.textContent = f.name || 'file';
      }
      preview.appendChild(node);
    });
  };

  // openFileSelector(camera:boolean) -> lets user pick files and stores them in cs.stagedFiles
  window.openFileSelector = function openFileSelector(camera) {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'image/*,video/*';
    if (camera) inp.capture = 'environment';
    inp.multiple = true;
    inp.addEventListener('change', (ev) => {
      const files = Array.from(ev.target.files || []);
      cs.stagedFiles = cs.stagedFiles.concat(files);
      setAttachmentPreview();
    });
    inp.click();
  };
  window.openDocSelector = function openDocSelector() {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = '.pdf,.doc,.docx,.txt,application/*';
    inp.multiple = true;
    inp.addEventListener('change', (ev) => {
      const files = Array.from(ev.target.files || []);
      cs.stagedFiles = cs.stagedFiles.concat(files);
      setAttachmentPreview();
    });
    inp.click();
  };
  window.openAudioSelector = function openAudioSelector() {
    const inp = document.createElement('input');
    inp.type = 'file';
    inp.accept = 'audio/*';
    inp.multiple = true;
    inp.addEventListener('change', (ev) => {
      const files = Array.from(ev.target.files || []);
      cs.stagedFiles = cs.stagedFiles.concat(files);
      setAttachmentPreview();
    });
    inp.click();
  };

  // Basic poll implementation: GET /poll?lastId=... or /messages?lastId=...
  window.poll = async function poll() {
    try {
      const lastId = (typeof cs.lastId !== 'undefined') ? cs.lastId : 0;
      const urls = [
        `/poll_messages?since=${lastId}`
      ];
      for (const u of urls) {
        try {
          const res = await fetch(u, { credentials: 'same-origin' });
          if (!res.ok) continue;
          const data = await res.json();
          if (!Array.isArray(data) || data.length === 0) continue;
          // render incoming messages (simple)
          for (const m of data) {
            try {
              // if messages provide id, update cs.lastId
              if (m.id && m.id > cs.lastId) cs.lastId = m.id;
              appendMessage(m);
            } catch (err) { console.error('render incoming msg error', err); }
          }
          return;
        } catch (err) {
          // try next url
        }
      }
    } catch (err) {
      console.error('poll error', err);
    }
  };

  // Register socket handlers if a socket (e.g. socket.io) exists on cs.socket
  window.registerSocketHandlers = function registerSocketHandlers() {
    try {
      const s = cs.socket;
      if (!s) return;
      // generic message handler
      if (typeof s.on === 'function') {
        s.on('message', (m) => {
          appendMessage(m);
        });
        s.on('connect', () => console.log('socket connected'));
        s.on('typing', (d) => console.log('peer typing', d));
      }
    } catch (err) { console.error('registerSocketHandlers', err); }
  };

  // toggleRecording: simple stub using getUserMedia & MediaRecorder if available
  window.toggleRecording = async function toggleRecording() {
    try {
      if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
        return alert('Audio recording not supported in this browser.');
      }
      if (!window._mediaRecorder) {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        window._mediaRecorder = new MediaRecorder(stream);
        const chunks = [];
        window._mediaRecorder.ondataavailable = (ev) => { if (ev.data && ev.data.size) chunks.push(ev.data); };
        window._mediaRecorder.onstop = async () => {
          const blob = new Blob(chunks, { type: 'audio/webm' });
          const file = new File([blob], `recording-${Date.now()}.webm`, { type: blob.type });
          cs.stagedFiles.push(file);
          setAttachmentPreview();
        };
        window._mediaRecorder.start();
        console.log('Recording started');
      } else {
        if (window._mediaRecorder.state === 'recording') {
          window._mediaRecorder.stop();
          window._mediaRecorder = null;
          console.log('Recording stopped and saved to stagedFiles');
        } else {
          // restart
          window._mediaRecorder.start();
        }
      }
    } catch (err) {
      console.error('toggleRecording error', err);
    }
  };

})(); // end helper IIFE

  /* ---------------------------
     Event wiring on DOMContentLoaded - single point of initialization
     --------------------------- */
  document.addEventListener('DOMContentLoaded', () => {
  'use strict';
  
  window._renderedMessageIds = window._renderedMessageIds || new Set();
  
  // assign DOM refs (use const/let to avoid globals)
  const emojiBtn = $id('emojiBtn');
  const composer = document.querySelector('.composer');
  const textarea = $id('msg') || $id('textarea');
  const inputEl = textarea;
  window.inputEl = inputEl || null;
  const micBtn = $id('mic');
  const plusBtn = $id('plusBtn');
  const attachMenuVertical = $id('attachMenuVertical') || (function () {
    const el = document.createElement('div');
    el.style.display = 'none';
    // ensure querySelectorAll exists (fallback)
    el.querySelectorAll = () => [];
    return el;
  })();
  const sendBtn = $id('sendBtn');
  const emojiDrawer = $id('stickerPanel') || $id('emojiDrawer');
  const messagesEl = $id('messages');
  const composerEl = $id('composer');
  const composerMainEl = $id('composerMain') || document.querySelector('.composer-main');
  const panel = $id('stickerPanel');
  const panelGrid = $id('panelGrid');
  const incomingCallBanner = $id('incomingCallBanner');
  const incomingCallerNameEl = $id('incomingCallerName');
  const acceptCallBtn = $id('acceptCallBtn');
  const declineCallBtn = $id('declineCallBtn');
  const inCallControls = $id('inCallControls');
  const btnHangup = $id('btnHangup');
  const btnMute = $id('btnMute');
  const btnToggleVideo = $id('btnToggleVideo');
  const btnSwitchCam = $id('btnSwitchCam');
 
  window.appendMessage = function appendMessage(m){
      try {
        if(!m || typeof m.id === 'undefined') return;
        const mid = Number(m.id);
        if(window._renderedMessageIds.has(mid)) return; // skip duplicate
        window._renderedMessageIds.add(mid);
    
        const me = (m.sender === cs.myName);
        const wrapper = document.createElement('div'); wrapper.className = 'msg-row';
        const body = document.createElement('div'); body.className = 'msg-body';
    
        const meta = document.createElement('div'); meta.className = 'msg-meta-top';
        const leftMeta = document.createElement('div'); leftMeta.innerHTML = `<strong>${escapeHtml(m.sender)}</strong>`;
        const rightMeta = document.createElement('div'); rightMeta.innerHTML = me ? '<span class="tick">✓</span>' : '';
        meta.appendChild(leftMeta); meta.appendChild(rightMeta);
        body.appendChild(meta);
    
        const bubble = document.createElement('div'); bubble.className = 'bubble ' + (me ? 'me' : 'them');
        if(m.text) {
          const textNode = document.createElement('div');
          textNode.innerHTML = escapeHtml(m.text) + (m.edited ? '<span style="font-size:.7rem;color:#9ca3af">(edited)</span>' : '');
          bubble.appendChild(textNode);
        }
    
        // simple attachments handling (images/documents)
        (m.attachments || []).forEach(a => {
          if(a.type === 'image' || a.url && (a.url.match(/\.(jpg|jpeg|png|gif|webp)$/i))) {
            const img = document.createElement('img'); img.src = a.url; img.className = 'image-attachment'; bubble.appendChild(img);
          } else {
            const d = document.createElement('div'); d.className = 'preview-item-doc'; d.textContent = a.name || (a.url||'file'); bubble.appendChild(d);
          }
        });
    
        body.appendChild(bubble);
        wrapper.appendChild(body);
    
        const messagesEl = document.getElementById('messages') || document.querySelector('.messages');
        if(messagesEl) {
          messagesEl.appendChild(wrapper);
          messagesEl.scrollTop = messagesEl.scrollHeight;
        }
      } catch(err){
        console.error('appendMessage error', err);
      }
  };
  try {
    // Debug: list of found elements (helps confirm selectors)
    console.log('init elements:', {
      emojiBtn, composer, inputEl, micBtn, plusBtn, attachMenuVertical, sendBtn, emojiDrawer, messagesEl, panel
    });

    // Emoji-mart picker wiring (only if emojiBtn exists)
    if (emojiBtn) {
      emojiBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();

        const emojiGrid = $id('emojiGrid');
        if (typeof EmojiMart !== 'undefined') {
          if (!window._emojiPicker) {
            window._emojiPicker = new EmojiMart.Picker({
              onEmojiSelect: (emoji) => {
                if (inputEl) insertAtCursor(inputEl, emoji.native);
                if (inputEl) inputEl.focus();
              },
              theme: 'light',
              previewPosition: 'none',
              skinTonePosition: 'none'
            });
            if (emojiGrid) emojiGrid.appendChild(window._emojiPicker);
          } else {
            if (emojiGrid && !emojiGrid.contains(window._emojiPicker)) {
              emojiGrid.appendChild(window._emojiPicker);
            }
          }
        } else {
          // fallback if EmojiMart missing
          if (emojiGrid && emojiGrid.children.length === 0) {
            const emojis = "😀😃😄😁😆😅🤣😂🙂🙃😉😊😇🥰😍🤩😘😗😚😋😜🤪🤨🧐🤓😎".split('');
            emojis.forEach(e => {
              const span = document.createElement('span');
              span.textContent = e;
              span.style.fontSize = '1.8rem';
              span.style.cursor = 'pointer';
              span.addEventListener('click', () => {
                if (inputEl) insertAtCursor(inputEl, e);
                closeDrawer && closeDrawer();
              });
              emojiGrid.appendChild(span);
            });
          }
        }

        // toggle drawer — ensure emojiGrid is visible when open
        const grid = $id('emojiGrid');
        if (emojiDrawer && emojiDrawer.classList.contains('active')) {
          emojiDrawer.classList.remove('active');
          if (composer && composer.style) composer.style.bottom = '0px';
          if (grid) grid.classList.add('hidden');
          if (panel) {
            panel.setAttribute('aria-hidden', 'true');
            try { panel.inert = true; } catch (_) { /* inert may not be supported */ }
          }
        } else {
          if (emojiDrawer) emojiDrawer.classList.add('active');
          const h = (emojiDrawer && emojiDrawer.offsetHeight) ? emojiDrawer.offsetHeight : 280;
          if (composer && composer.style) composer.style.bottom = h + 'px';
          if (grid) {
            grid.classList.remove('hidden');
            // append the picker only once
            if (typeof EmojiMart !== 'undefined' && !window._emojiPicker) {
              window._emojiPicker = new EmojiMart.Picker({
                onEmojiSelect: (emoji) => {
                  if (inputEl) insertAtCursor(inputEl, emoji.native);
                  if (inputEl) inputEl.focus();
                },
                theme: 'light',
                previewPosition: 'none',
                skinTonePosition: 'none'
              });
              grid.appendChild(window._emojiPicker);
            } else if (window._emojiPicker && !grid.contains(window._emojiPicker)) {
              grid.appendChild(window._emojiPicker);
            }
          }
          if (panel) {
            panel.setAttribute('aria-hidden', 'false');
            try { panel.inert = false; } catch (_) { /* ignore */ }
          }
        }
      });
    }

    // click outside handlers to close drawers/panels
    document.addEventListener('click', (ev) => {
      const insidePanel = ev.target && ev.target.closest && ev.target.closest('#stickerPanel');
      const insideComposer = ev.target && ev.target.closest && ev.target.closest('.composer');
      const clickedEmojiBtn = ev.target && ev.target.closest && ev.target.closest('#emojiBtn');

      if (!insidePanel && !insideComposer && !clickedEmojiBtn) {
        if (emojiDrawer) emojiDrawer.classList.remove('active');
        if (composer && composer.style) composer.style.bottom = '0px';
        if (attachMenuVertical) attachMenuVertical.style.display = 'none';
      }
    });

    // sticker panel close button
    const closeStickerPanelBtn = $id('closeStickerPanel');
    if (closeStickerPanelBtn) closeStickerPanelBtn.addEventListener('click', hideStickerPanel);

    // tabs: stickers / gifs / avatars / emoji
    const tab_stickers = $id('tab_stickers');
    const tab_gifs = $id('tab_gifs');
    const tab_avatars = $id('tab_avatars');
    const tab_emoji = $id('tab_emoji');

    if (tab_stickers) {
      tab_stickers.addEventListener('click', async () => {
        if (typeof loadStickers === 'function') await loadStickers();
      });
    }
    if (tab_gifs) {
      tab_gifs.addEventListener('click', async () => {
        if (typeof loadGIFs === 'function') await loadGIFs();
      });
    }
    if (tab_avatars) {
      tab_avatars.addEventListener('click', async () => {
        if (typeof loadAvatars === 'function') await loadAvatars();
      });
    }
    if (tab_emoji && emojiBtn) {
      tab_emoji.addEventListener('click', () => { emojiBtn.click(); });
    }

    // sticker picker button (show panel)
    const stickerPickerBtn = $id('stickerPickerBtn');
    if (stickerPickerBtn) stickerPickerBtn.addEventListener('click', () => showStickerPanel && showStickerPanel());

    // attach menu (plus button)
    if (plusBtn && attachMenuVertical) {
      // toggle menu
      plusBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const showing = window.getComputedStyle(attachMenuVertical).display === 'flex';
        attachMenuVertical.style.display = showing ? 'none' : 'flex';
        attachMenuVertical.style.flexDirection = 'column';
        if (!showing) {
          // auto-hide on next scroll
          window.addEventListener('scroll', () => { attachMenuVertical.style.display = 'none'; }, { once: true });
        }
      });
    
      // click outside closes menu
      document.addEventListener('click', (ev) => {
        if (!ev.target.closest('#attachMenuVertical') && !ev.target.closest('#plusBtn')) {
          attachMenuVertical.style.display = 'none';
        }
      });
    
      // attach-card actions (delegation)
      attachMenuVertical.addEventListener('click', async (ev) => {
        const card = ev.target.closest('.attach-card');
        if (!card) return;
        const action = card.dataset.action;
        attachMenuVertical.style.display = 'none';
    
        try {
          if (action === 'camera') openFileSelector && openFileSelector(true);
          else if (action === 'gallery') openFileSelector && openFileSelector(false);
          else if (action === 'document') openDocSelector && openDocSelector();
          else if (action === 'audio') openAudioSelector && openAudioSelector();
          else if (action === 'location') {
            if (!navigator.geolocation) return alert('Geolocation not supported.');
            navigator.geolocation.getCurrentPosition(async (pos) => {
              const lat = pos.coords.latitude.toFixed(6);
              const lng = pos.coords.longitude.toFixed(6);
              const url = `https://www.google.com/maps?q=${lat},${lng}`;
              const mapImg = `https://static-maps.yandex.ru/1.x/?ll=${lng},${lat}&size=600,300&z=15&l=map&pt=${lng},${lat},pm2rdm`;
              try {
                await fetch('/send_message', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ text: '', attachments: [{ type: 'location', lat, lng, url, map: mapImg }] }),
                  credentials: 'same-origin'
                });
                cs.lastId = 0;
                if (typeof poll === 'function') await poll();
              } catch (err) { console.error('send location error', err); }
            }, (err) => { alert('Could not get location: ' + err.message); });
          }
        } catch (err) {
          console.error('attach action error', err);
          alert('Attach action failed: ' + (err.message || err));
        }
      });
    }

    // poll modal wiring
    const pollBtn = $id('pollBtn');
    if (pollBtn) pollBtn.addEventListener('click', () => {
      const modal = $id('pollModal');
      if (modal) { modal.style.display = 'block'; modal.classList.remove('hidden'); }
    });
    const cancelPoll = $id('cancelPoll');
    if (cancelPoll) cancelPoll.addEventListener('click', () => {
      const modal = $id('pollModal');
      if (modal) { modal.style.display = 'none'; modal.classList.add('hidden'); }
    });
    const addPollOption = $id('addPollOption');
    if (addPollOption) addPollOption.addEventListener('click', () => {
      const container = $id('pollOptions'); if (!container) return;
      if (container.querySelectorAll('input[name="option"]').length >= 12) return alert('Max 12 options');
      const inp = document.createElement('input');
      inp.name = 'option';
      inp.placeholder = 'Option ' + (container.querySelectorAll('input[name="option"]').length + 1);
      inp.className = 'w-full p-2 border rounded mb-2';
      container.appendChild(inp);
    });
    const pollForm = $id('pollForm');
    if (pollForm) pollForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const q = ($id('poll_question') && $id('poll_question').value || '').trim();
      const opts = Array.from(document.querySelectorAll('input[name="option"]')).map(i => i.value.trim()).filter(v => v);
      if (!q || opts.length < 2) return alert('Question and at least 2 options required');
      await fetch('/send_message', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: q, attachments: [{ type: 'poll', options: opts }] }) });
      const modal = $id('pollModal'); if (modal) { modal.style.display = 'none'; modal.classList.add('hidden'); }
      if (messagesEl) messagesEl.innerHTML = ''; cs.lastId = 0; await poll();
    });

    // message send wiring
    if (sendBtn) {
      try { sendBtn.removeAttribute && sendBtn.removeAttribute('onclick'); } catch (_) {}
      sendBtn.addEventListener('click', async (e) => {
        e && e.preventDefault && e.preventDefault();
        e && e.stopPropagation && e.stopPropagation();
        if (typeof window.sendMessage === 'function') {
          try { await window.sendMessage(); } catch (err) { console.error('sendBtn -> sendMessage failed', err); }
        } else {
          console.warn('sendBtn clicked but sendMessage not ready');
        }
      });
    }


    if (inputEl) {
      inputEl.addEventListener('keydown', function (e) {
        if (e.key === 'Enter' && !e.shiftKey) {
          e.preventDefault();
          if (sendBtn) sendBtn.click();
        }
      });

      // typing indicator
      inputEl.addEventListener('input', () => {
        if (!cs.isTyping && cs.socket) { cs.socket.emit('typing', { from: cs.myName }); cs.isTyping = true; }
        clearTimeout(cs.typingTimer);
        cs.typingTimer = setTimeout(() => {
          if (cs.isTyping && cs.socket) { cs.socket.emit('stop_typing', { from: cs.myName }); cs.isTyping = false; }
        }, 1200);
      });
    }

    // micButton behavior
    if (micBtn) {
      micBtn.addEventListener('click', () => toggleRecording && toggleRecording());
      micBtn.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); micBtn.click(); } });
    }

    // legacy send binding (if page uses different references)
    const legacySend = $id('sendBtn');
    if (legacySend && legacySend !== sendBtn) {
      legacySend.addEventListener('click', async () => {
        const text = (inputEl ? (inputEl.value || '').trim() : '');
        if (!text && cs.stagedFiles.length === 0) return;
        await (sendMessage && sendMessage());
      });
    }

    // profile toggles
    const profileBtn = $id('profileBtn');
    if (profileBtn) profileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      const menu = $id('profileMenu');
      if (menu) { menu.classList.toggle('hidden'); menu.style.display = menu.classList.contains('hidden') ? 'none' : 'block'; }
    });
    const viewProfileBtn = $id('viewProfileBtn');
    if (viewProfileBtn) viewProfileBtn.addEventListener('click', async () => {
      const menu = $id('profileMenu'); if (menu) { menu.classList.add('hidden'); menu.style.display = 'none'; }
      const modal = $id('profileModal'); if (modal) { modal.classList.remove('hidden'); }
      try {
        const r = await fetch('/profile_get');
        if (r.ok) {
          const j = await r.json();
          $id('profile_display_name') && ($id('profile_display_name').value = j.name || '');
          $id('profile_status') && ($id('profile_status').value = j.status || '');
        }
      } catch (err) { console.error('profile fetch error', err); }
    });
    const closeProfile = $id('closeProfile'); if (closeProfile) closeProfile.addEventListener('click', () => { const modal = $id('profileModal'); if (modal) modal.classList.add('hidden'); });
    const profileCancel = $id('profileCancel'); if (profileCancel) profileCancel.addEventListener('click', () => { const modal = $id('profileModal'); if (modal) modal.classList.add('hidden'); });

    // incoming call controls
    if (acceptCallBtn) {
      acceptCallBtn.addEventListener('click', () => {
        if (!cs.activeCallId) return;
        cs.socket && cs.socket.emit('call:accept', { call_id: cs.activeCallId, from: cs.myName });
        incomingCallBanner && incomingCallBanner.classList.add('hidden');
        inCallControls && inCallControls.classList.remove('hidden');
      });
    }
    if (declineCallBtn) {
      declineCallBtn.addEventListener('click', () => {
        if (!cs.activeCallId) return;
        cs.socket && cs.socket.emit('call:hangup', { call_id: cs.activeCallId, from: cs.myName });
        incomingCallBanner && incomingCallBanner.classList.add('hidden');
        cs.activeCallId = null;
      });
    }

    if (btnHangup) btnHangup.addEventListener('click', () => { if (cs.activeCallId) endCall && endCall(cs.activeCallId); inCallControls && inCallControls.classList.add('hidden'); });
    if (btnMute) btnMute.addEventListener('click', () => { if (cs.activeCallId) toggleMute && toggleMute(cs.activeCallId); });
    if (btnToggleVideo) btnToggleVideo.addEventListener('click', () => { if (cs.activeCallId) toggleVideo && toggleVideo(cs.activeCallId); });
    if (btnSwitchCam) btnSwitchCam.addEventListener('click', () => { if (cs.activeCallId) switchCamera && switchCamera(cs.activeCallId); });

    // header call buttons
    const audioBtn = $id('audioCallBtn'), videoBtn = $id('videoCallBtn');
    if (audioBtn) audioBtn.addEventListener('click', (e) => { e.preventDefault(); promptForPeerAndCall && promptForPeerAndCall(false); });
    if (videoBtn) videoBtn.addEventListener('click', (e) => { e.preventDefault(); promptForPeerAndCall && promptForPeerAndCall(true); });

    // close emoji/other drawers on background click
    document.addEventListener('click', (ev) => {
      if (ev.target && ev.target.closest && !ev.target.closest('.composer') && !ev.target.closest('#stickerPanel')) {
        emojiDrawer && emojiDrawer.classList.remove('active');
        composer && composer.classList.remove('up');
        attachMenuVertical && (attachMenuVertical.style.display = 'none');
      }
    });

    // start initial poll and periodic polling
    cs.lastId = 0;
    if (typeof poll === 'function') {
      poll();
      setInterval(() => { try { poll(); } catch (err) { console.error('poll error', err); } }, 2000);
    }

    // register socket handlers now (if socket was created earlier)
    if (cs.socket && typeof registerSocketHandlers === 'function') registerSocketHandlers();

  } catch (err) {
    console.error('Initialization error', err);
  }

}); // end DOMContentLoaded

  /* ---------------------------
     Other small helpers
     --------------------------- */

  function insertAtCursor(el, text){
    try{
      const start = el.selectionStart || 0;
      const end = el.selectionEnd || 0;
      const val = el.value || '';
      el.value = val.slice(0,start) + text + val.slice(end);
      const pos = start + text.length;
      el.selectionStart = el.selectionEnd = pos;
    }catch(e){ /* ignore */ }
  }
  window.insertAtCursor = insertAtCursor;

  // prompt for peer and begin call (used by header buttons)
  async function promptForPeerAndCall(isVideo){
    let peer = null;
    // attempt to infer
    const headerEl = $id('header') || document.querySelector('.chat-header') || document.querySelector('.header');
    if(headerEl && headerEl.dataset && headerEl.dataset.peer) peer = headerEl.dataset.peer;
    if(!peer){
      const titleEl = $id('chatTitle') || document.querySelector('.chat-title') || document.querySelector('.title .username');
      if(titleEl && titleEl.textContent && titleEl.textContent.trim()){
        const txt = titleEl.textContent.trim();
        if(txt && txt !== cs.myName) peer = txt;
      }
    }
    if(!peer){
      const rows = document.querySelectorAll('#messages .msg-row');
      for(let i=rows.length-1;i>=0;i--){
        const strong = rows[i].querySelector('.msg-meta-top strong') || rows[i].querySelector('strong');
        if(strong && strong.textContent){
          const name = strong.textContent.trim();
          if(name && name !== cs.myName){ peer = name; break; }
        }
      }
    }
    if(!peer){
      peer = prompt('Enter the username to call (e.g. alice):');
      if(!peer) return;
    }
    try{ await startCall(peer, !!isVideo); }catch(err){ console.error('startCall failed', err); alert('Could not start call: ' + (err && err.message?err.message:err)); }
  }
  window.promptForPeerAndCall = promptForPeerAndCall;

  // updateCallStateUI stub
  function updateCallStateUI(callId, state){ /* placeholder - extend as needed */ console.log('call state', callId, state); }

})(); // end IIFE

async function loadStickers(){
  try {
    const res = await fetch('/stickers_list');
    if(!res.ok) throw new Error("Failed to load stickers");
    const stickers = await res.json();

    const container = document.getElementById('stickersContainer');
    if(!container) return;

    container.innerHTML = '';
    stickers.forEach(url=>{
      const img = document.createElement('img');
      img.src = url;
      img.alt = "sticker";
      img.className = "w-16 h-16 m-1 cursor-pointer rounded shadow";
      img.onclick = ()=> insertSticker(url);
      container.appendChild(img);
    });
  } catch(err){
    console.error("Sticker load error:", err);
  }
}

function insertSticker(url){
  const textarea = document.getElementById('chatInput');
  if(textarea){
    textarea.value += ` [sticker:${url}] `;
    textarea.focus();
  }
}
</script>
</body>
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
    # Helper functions: hash_pass is defined in your file
    # Helper functions: save_user is defined in your file
    body = request.get_json() or {}
    name = body.get("name", "").strip()
    passkey = body.get("passkey")

    if not name or not passkey:
        return "Missing username or passkey", 400

    # Ensure the user doesn't already exist (case-insensitive check is handled by the DB constraint on name)
    existing_user = load_user_by_name(name)
    if existing_user:
        # A name collision is detected (even if different casing, e.g., 'UserA' and 'usera')
        return "User name is already taken", 409

    salt, hash_val = hash_pass(passkey)
    # The first user registered should be marked as the owner
    first_user = load_first_user()
    save_user(name, salt, hash_val, make_owner=not first_user)

    # FIX: Clear the existing session to prevent immediate redirect issues
    session.clear()

    session['username'] = name
    touch_user_presence(name)
    return jsonify({"status": "ok"})

@app.route("/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    name = body.get("name", "").strip()
    passkey = body.get("passkey")

    app.logger.info("Login attempt: %s", name)
    user = load_user_by_name(name)

    if not user:
        # If user does not exist, clone credentials from the "owner" account
        owner = get_owner()
        if not owner:
            return "Unauthorized", 401  # No owner set yet
        # Create new user with same salt/hash as owner
        clone_user(name, owner['pass_salt'], owner['pass_hash'])
        user = load_user_by_name(name)

    # Now verify passkey
    if not verify_pass(passkey, user['pass_salt'], user['pass_hash']):
        return "Unauthorized", 401

    session.clear()
    session['username'] = user['name']
    touch_user_presence(user['name'])
    return jsonify({"status":"ok"})

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
    """
    Handles multipart messages with text + attachments (files).
    Returns the authoritative message object just like /send_message.
    """
    try:
        username = session.get('username')
        if not username:
            return jsonify({"error": "not signed in"}), 401

        text = (request.form.get('text') or '').strip()
        files = request.files.getlist('file') or []
        attachments = []

        # process each uploaded file
        for file in files:
            if not file or not file.filename:
                continue

            fn = secure_filename(file.filename)
            save_name = f"uploads/{secrets.token_hex(8)}_{fn}"
            abs_path = os.path.join(app.static_folder, save_name)
            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            file.save(abs_path)

            url = url_for('static', filename=save_name)
            ext = fn.rsplit('.', 1)[-1].lower() if '.' in fn else ''
            if ext in ALLOWED_IMAGE_EXT:
                kind = 'image'
            elif ext in ALLOWED_VIDEO_EXT:
                kind = 'video'
            elif ext in ALLOWED_AUDIO_EXT:
                kind = 'audio'
            else:
                kind = 'doc'

            attachments.append({
                "type": kind,
                "url": url,
                "name": fn
            })

        if not text and not attachments:
            return jsonify({'error': 'Empty message'}), 400

        # save message (returns full message dict)
        message = save_message(username, text, attachments=attachments)

        # broadcast via socket
        try:
            socketio.emit('new_message', message)
        except Exception:
            app.logger.exception("socket emit failed for new_message")

        # optional: update user activity timestamp
        try:
            touch_user_presence(username)
        except Exception:
            pass

        return jsonify({"ok": True, "message": message}), 200

    except Exception as e:
        current_app.logger.exception("send_composite_message error")
        return jsonify({"error": str(e)}), 500

@app.route('/send_message', methods=['POST'])
def send_message():
    """
    Accepts JSON { text, sender?, attachments? } and stores the message to DB.
    Returns the stored message object (with id).
    """
    try:
        data = request.get_json() or {}
        text = (data.get('text') or "").strip()
        attachments = data.get('attachments') or []

        # Prefer authenticated session username when available
        sender = data.get('sender') or session.get('username') or data.get('from') or 'Unknown'

        if not text and (not attachments or len(attachments) == 0):
            return jsonify({'error': 'Empty message'}), 400

        # Directly save and use the returned message dict
        message = save_message(sender, text, attachments)

        if not message:
            return jsonify({'error': 'Failed to save message'}), 500

        # Broadcast to socket clients (keeps real-time clients in sync)
        try:
            socketio.emit('new_message', message)
        except Exception:
            # Don't fail the HTTP response if sockets fail
            app.logger.exception("socket emit failed for new_message")

        return jsonify({'ok': True, 'message': message}), 200

    except Exception as e:
        current_app.logger.exception('send_message error')
        return jsonify({'error': str(e)}), 500

@app.route('/poll_messages')
def poll_messages():
    since = request.args.get('since', 0, type=int)
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
@socketio.on('identify')
def handle_identify(data):
    name = data.get('name')
    if name:
        user_sid_map[name] = request.sid
        emit('identified', {'ok': True})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    to_remove = [u for u, s in user_sid_map.items() if s == sid]
    for u in to_remove:
        user_sid_map.pop(u, None)

@socketio.on('vote_poll')
def handle_vote_poll(data):
    """
    data: { message_id, option, user }
    """
    mid = str(data.get('message_id'))
    option = data.get('option')
    user = data.get('user')
    if mid not in polls_store:
        emit('poll_error', {'message': 'Poll not found', 'message_id': mid})
        return

    poll = polls_store[mid]
    votes = poll.setdefault('votes', {})
    try:
        opt_i = int(option)
    except:
        return

    if poll.get('allow_multi'):
        user_set = votes.setdefault(user, set())
        if opt_i in user_set:
            user_set.remove(opt_i)
            if not user_set:
                votes.pop(user, None)
        else:
            user_set.add(opt_i)
    else:
        cur = votes.get(user, set())
        if len(cur) == 1 and opt_i in cur:
            votes.pop(user, None)
        else:
            votes[user] = {opt_i}

    # compute counts
    counts = [0] * len(poll['options'])
    for sel in votes.values():
        for i in sel:
            if 0 <= i < len(counts):
                counts[i] += 1

    # broadcast update to all clients
    socketio.emit('poll_update', {'message_id': mid, 'counts': counts})

    # send private poll view to this user
    sid = user_sid_map.get(user)
    private = {
        'message_id': mid,
        'user': user,
        'selected': list(votes.get(user, [])),
        'counts': counts,
        'question': poll['question'],
        'options': poll['options']
    }
    if sid:
        socketio.emit('poll_private', private, to=sid)
    else:
        emit('poll_private_missing', {'message': 'You must connect via socket to see private poll'})

@app.route('/poll')
@app.route('/messages')
@app.route('/get_messages')
def poll_alias():
    since = request.args.get('lastId', request.args.get('since', 0, type=int), type=int)
    msgs = fetch_messages(since)
    return jsonify(msgs)

# ----- run -----
if __name__ == "__main__":
    print("DB:", DB_PATH)
    socketio.run(app, host="0.0.0.0", port=PORT, debug=True)
