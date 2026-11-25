"""
Triagle — sign-in.

The console stages actions like "isolate host", so nobody should reach it
without signing in. This module is deliberately small and uses only the
standard library.

Users come from the environment:

  TRIAGLE_ADMIN_PASSWORD   password for the built-in user "admin" (analyst)
  TRIAGLE_USERS            more users: "name:role:hash,name:role:hash"
                           role is "analyst" (can approve actions) or
                           "viewer" (read only). Make a hash with
                               python -m app.auth hash
  TRIAGLE_SECRET           signs session cookies. Set it, or sessions end
                           every time the app restarts.
  TRIAGLE_SESSION_HOURS    session length, default 8

A second factor (a six-digit code from an authenticator app, RFC 6238):

  TRIAGLE_ADMIN_TOTP       the authenticator key for "admin"
  TRIAGLE_USERS            a fourth field holds a user's key:
                           "name:role:hash:KEY". Make a key with
                               python -m app.auth totp
  A user with a key cannot sign in without the current code.

Single sign-on (OpenID Connect: Google, Microsoft Entra ID, Okta) is in
app/sso.py. The people allowed in, and their roles, are listed here:

  TRIAGLE_OIDC_USERS       "email:role,email:role"
  TRIAGLE_PASSWORD_LOGIN   "off" turns password sign-in off once single
                           sign-on works, so there is one way in.

If no user is configured the app does NOT run open. It creates "admin" with
a random password and prints it once in the server log.

TRIAGLE_AUTH=off turns sign-in off. Only for a laptop demo; never on a
public address.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import struct
import sys
import time

ROLES = ("viewer", "analyst")
COOKIE = "triagle_session"
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300

TOTP_STEP = 30        # seconds a code lasts
TOTP_DIGITS = 6

_state = {}
_failures = {}        # key -> [count, first_failure_time]
_totp_used = {}       # user -> the last time step a code was accepted for, so a code works once


# ---- passwords -------------------------------------------------------------

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(digest).decode()


def verify_password(password, stored):
    try:
        scheme, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


# ---- second factor: a code from an authenticator app (RFC 6238) -------------

def new_totp_key():
    """A fresh 160-bit key, in the base32 form authenticator apps take."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _totp_key_bytes(key):
    text = "".join(str(key or "").split()).upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def totp_code(key, at, step=TOTP_STEP, digits=TOTP_DIGITS):
    """The code an authenticator shows for this key at time `at`."""
    counter = struct.pack(">Q", int(at // step))
    mac = hmac.new(_totp_key_bytes(key), counter, hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10 ** digits)).zfill(digits)


def totp_step_for(key, code, now):
    """The time step a code belongs to, or None if it is wrong. The step
    before and the step after are accepted, for a clock that is a little off."""
    text = "".join(ch for ch in str(code or "") if ch.isdigit())
    if len(text) != TOTP_DIGITS:
        return None
    found = None
    try:
        for drift in (0, -1, 1):
            at = now + drift * TOTP_STEP
            if hmac.compare_digest(totp_code(key, at), text) and found is None:
                found = int(at // TOTP_STEP)
    except (ValueError, TypeError):
        return None
    return found


def totp_uri(key, name, issuer="Triagle"):
    """What an authenticator app reads from a QR code, as text."""
    from urllib.parse import quote
    return f"otpauth://totp/{quote(issuer)}:{quote(name)}?secret={key}&issuer={quote(issuer)}&digits={TOTP_DIGITS}&period={TOTP_STEP}"


def _valid_totp_key(key):
    try:
        return len(_totp_key_bytes(key)) >= 10
    except (ValueError, TypeError):
        return False


# ---- configuration ---------------------------------------------------------

def load_config(env=None):
    """(Re)reads settings. Called at import; tests call it again."""
    env = os.environ if env is None else env
    users = {}
    for part in filter(None, (p.strip() for p in env.get("TRIAGLE_USERS", "").split(","))):
        try:
            name, role, rest = part.split(":", 2)
        except ValueError:
            continue
        pw_hash, _, key = rest.partition(":")           # a hash never holds a colon
        if role in ROLES and name:
            users[name.lower()] = {"role": role, "hash": pw_hash}
            if key.strip():
                # a key that cannot be read must not leave the account without its second factor
                users[name.lower()]["totp"] = key.strip() if _valid_totp_key(key) else "unreadable"
    generated = None
    if env.get("TRIAGLE_ADMIN_PASSWORD"):
        users["admin"] = {"role": "analyst", "hash": hash_password(env["TRIAGLE_ADMIN_PASSWORD"])}
        admin_key = env.get("TRIAGLE_ADMIN_TOTP", "").strip()
        if admin_key:
            users["admin"]["totp"] = admin_key if _valid_totp_key(admin_key) else "unreadable"
    sso_users = {}
    for part in filter(None, (p.strip() for p in env.get("TRIAGLE_OIDC_USERS", "").split(","))):
        email, _, role = part.rpartition(":")
        email = email.strip().lower()
        if "@" in email and role.strip() in ROLES:
            sso_users[email] = role.strip()
    enabled = env.get("TRIAGLE_AUTH", "on").lower() != "off"
    # Password sign-in can be turned off only when people can still get in another way.
    passwords = not (env.get("TRIAGLE_PASSWORD_LOGIN", "on").strip().lower() in ("off", "false", "0", "no")
                     and sso_users and env.get("TRIAGLE_OIDC_CLIENT_ID") and env.get("TRIAGLE_OIDC_CLIENT_SECRET"))
    if enabled and not users and not sso_users:
        generated = secrets.token_urlsafe(12)
        users["admin"] = {"role": "analyst", "hash": hash_password(generated)}
        print(f"[triagle] No users configured. Sign in as  admin  with password  {generated}\n"
              f"[triagle] Set TRIAGLE_ADMIN_PASSWORD to choose your own.", file=sys.stderr, flush=True)
    secret = env.get("TRIAGLE_SECRET")
    _state.clear()
    _state.update({
        "enabled": enabled,
        "users": users,
        "sso_users": sso_users,
        "password_login": passwords,
        "secret": (secret or secrets.token_urlsafe(32)).encode(),
        "secret_is_set": bool(secret),
        "session_seconds": int(float(env.get("TRIAGLE_SESSION_HOURS", "8")) * 3600),
        "generated_password": generated,
        # a dummy hash so an unknown username costs the same time as a wrong password
        "dummy_hash": hash_password(secrets.token_urlsafe(8)),
    })
    _failures.clear()
    _totp_used.clear()
    return _state


def enabled():
    return _state["enabled"]


# ---- sign-in attempts ------------------------------------------------------

def _locked(key, now):
    count, first = _failures.get(key, (0, 0))
    if count >= MAX_FAILURES and now - first < LOCKOUT_SECONDS:
        return True
    if now - first >= LOCKOUT_SECONDS:
        _failures.pop(key, None)
    return False


def password_login():
    """Is password sign-in on? It can be turned off once single sign-on works."""
    return _state["password_login"]


def needs_code(username):
    """Does this user have a second factor? Only for the sign-in page's own
    hint: the answer to a wrong password never depends on it."""
    record = _state["users"].get((username or "").strip().lower())
    return bool(record and record.get("totp"))


def any_second_factor():
    return any(u.get("totp") for u in _state["users"].values())


def check_login(username, password, client_ip="", now=None, code=""):
    """Returns (user dict or None, reason). reason is 'ok', 'locked' or
    'invalid'. A wrong password and a wrong code give the same answer, so a
    guessed password is not confirmed to someone who lacks the code."""
    now = time.time() if now is None else now
    name = (username or "").strip().lower()
    keys = (f"user:{name}", f"ip:{client_ip}")
    if any(_locked(k, now) for k in keys):
        return None, "locked"
    record = _state["users"].get(name) if _state["password_login"] else None
    ok = verify_password(password or "", record["hash"] if record else _state["dummy_hash"])
    if record and ok and record.get("totp"):
        step = totp_step_for(record["totp"], code, now)
        # each code is good once: a code read over a shoulder cannot be used again
        ok = step is not None and step > _totp_used.get(name, -1)
        if ok:
            _totp_used[name] = step
    if record and ok:
        for k in keys:
            _failures.pop(k, None)
        return {"name": name, "role": record["role"]}, "ok"
    for k in keys:
        count, first = _failures.get(k, (0, now))
        _failures[k] = (count + 1, first)
    return None, "invalid"


def sso_user(email):
    """The user for an address that single sign-on has just proved, or None
    if that address is not on the list."""
    name = (email or "").strip().lower()
    role = _state["sso_users"].get(name)
    return {"name": name, "role": role, "sso": True} if role else None


# ---- sessions --------------------------------------------------------------

def _sign(payload_b64):
    return hmac.new(_state["secret"], payload_b64.encode(), hashlib.sha256).hexdigest()


def make_session(user, now=None):
    now = time.time() if now is None else now
    body = {"u": user["name"], "r": user["role"], "exp": int(now + _state["session_seconds"]),
            "n": secrets.token_urlsafe(8)}
    if user.get("sso"):
        body["s"] = 1
    payload = base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":")).encode()).decode()
    return payload + "." + _sign(payload)


def read_session(token, now=None):
    """Returns {"name","role"} for a valid, unexpired cookie whose user still
    exists with that role; otherwise None."""
    now = time.time() if now is None else now
    try:
        payload, sig = (token or "").rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(payload)):
            return None
        body = json.loads(base64.urlsafe_b64decode(payload.encode()))
        if body["exp"] < now:
            return None
        if body.get("s"):
            # signed in through single sign-on: still on the list, with the same role
            if _state["sso_users"].get(body["u"]) != body["r"]:
                return None
            return {"name": body["u"], "role": body["r"], "sso": True}
        record = _state["users"].get(body["u"])
        if not record or record["role"] != body["r"] or not _state["password_login"]:
            return None
        return {"name": body["u"], "role": body["r"]}
    except (ValueError, KeyError, TypeError):
        return None


def csrf_token(session_token):
    """Tied to the session, so a form posted from another site cannot carry it."""
    return hmac.new(_state["secret"], ("csrf:" + (session_token or "")).encode(), hashlib.sha256).hexdigest()


def csrf_ok(session_token, submitted):
    return bool(submitted) and hmac.compare_digest(csrf_token(session_token), submitted)


def safe_next(target):
    """Only allow redirects to a path on this site."""
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target \
            and "\n" not in target and "\r" not in target:
        return target
    return "/"


load_config()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "hash":
        import getpass
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Again: "):
            sys.exit("Passwords do not match.")
        print(hash_password(pw))
    elif len(sys.argv) > 1 and sys.argv[1] == "totp":
        who = sys.argv[2] if len(sys.argv) > 2 else "admin"
        key = new_totp_key()
        print(f"Key for {who}:  {key}")
        print("In your authenticator app choose 'Enter a setup key', type that key, and pick 'Time based'.")
        print("Or turn this line into a QR code and scan it:")
        print(totp_uri(key, who))
        print(f"Then set TRIAGLE_ADMIN_TOTP to the key (for admin), or add it as the fourth field of that "
              f"user in TRIAGLE_USERS.")
    else:
        print("usage: python -m app.auth hash | totp [name]")
