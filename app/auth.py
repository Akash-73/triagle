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
import sys
import time

ROLES = ("viewer", "analyst")
COOKIE = "triagle_session"
MAX_FAILURES = 5
LOCKOUT_SECONDS = 300

_state = {}
_failures = {}        # key -> [count, first_failure_time]


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


# ---- configuration ---------------------------------------------------------

def load_config(env=None):
    """(Re)reads settings. Called at import; tests call it again."""
    env = os.environ if env is None else env
    users = {}
    for part in filter(None, (p.strip() for p in env.get("TRIAGLE_USERS", "").split(","))):
        try:
            name, role, pw_hash = part.split(":", 2)
        except ValueError:
            continue
        if role in ROLES and name:
            users[name.lower()] = {"role": role, "hash": pw_hash}
    generated = None
    if env.get("TRIAGLE_ADMIN_PASSWORD"):
        users["admin"] = {"role": "analyst", "hash": hash_password(env["TRIAGLE_ADMIN_PASSWORD"])}
    enabled = env.get("TRIAGLE_AUTH", "on").lower() != "off"
    if enabled and not users:
        generated = secrets.token_urlsafe(12)
        users["admin"] = {"role": "analyst", "hash": hash_password(generated)}
        print(f"[triagle] No users configured. Sign in as  admin  with password  {generated}\n"
              f"[triagle] Set TRIAGLE_ADMIN_PASSWORD to choose your own.", file=sys.stderr, flush=True)
    secret = env.get("TRIAGLE_SECRET")
    _state.clear()
    _state.update({
        "enabled": enabled,
        "users": users,
        "secret": (secret or secrets.token_urlsafe(32)).encode(),
        "secret_is_set": bool(secret),
        "session_seconds": int(float(env.get("TRIAGLE_SESSION_HOURS", "8")) * 3600),
        "generated_password": generated,
        # a dummy hash so an unknown username costs the same time as a wrong password
        "dummy_hash": hash_password(secrets.token_urlsafe(8)),
    })
    _failures.clear()
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


def check_login(username, password, client_ip="", now=None):
    """Returns (user dict or None, reason). reason is 'ok', 'locked' or 'invalid'."""
    now = time.time() if now is None else now
    name = (username or "").strip().lower()
    keys = (f"user:{name}", f"ip:{client_ip}")
    if any(_locked(k, now) for k in keys):
        return None, "locked"
    record = _state["users"].get(name)
    ok = verify_password(password or "", record["hash"] if record else _state["dummy_hash"])
    if record and ok:
        for k in keys:
            _failures.pop(k, None)
        return {"name": name, "role": record["role"]}, "ok"
    for k in keys:
        count, first = _failures.get(k, (0, now))
        _failures[k] = (count + 1, first)
    return None, "invalid"


# ---- sessions --------------------------------------------------------------

def _sign(payload_b64):
    return hmac.new(_state["secret"], payload_b64.encode(), hashlib.sha256).hexdigest()


def make_session(user, now=None):
    now = time.time() if now is None else now
    body = {"u": user["name"], "r": user["role"], "exp": int(now + _state["session_seconds"]),
            "n": secrets.token_urlsafe(8)}
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
        record = _state["users"].get(body["u"])
        if not record or record["role"] != body["r"]:
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
    else:
        print("usage: python -m app.auth hash")
