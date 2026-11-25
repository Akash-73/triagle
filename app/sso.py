"""
Triagle — single sign-on (OpenID Connect).

One way in for a team that already has an identity provider: Google,
Microsoft Entra ID, Okta, or anything else that speaks OpenID Connect. The
provider proves who the person is, with its own second factor. Triagle only
decides whether that address is on its list, and with which role.

Settings
  TRIAGLE_OIDC_CLIENT_ID       from the provider's console
  TRIAGLE_OIDC_CLIENT_SECRET   from the provider's console; keep it in a secret store
  TRIAGLE_OIDC_ISSUER          default https://accounts.google.com
  TRIAGLE_OIDC_NAME            the name on the button, default "Google"
  TRIAGLE_OIDC_USERS           "email:role,email:role" (read by app/auth.py)
  TRIAGLE_PUBLIC_URL           this console's own address, e.g. https://app.example.com.
                               Unset = taken from the request.

How it works (the authorization-code flow, with PKCE):
  1. /auth/start sends the browser to the provider with a one-time state, a
     nonce and a PKCE challenge. Their secrets go in a short-lived, signed,
     HttpOnly cookie, so a reply can only be finished by the browser that
     started it.
  2. The provider sends the browser back to /auth/callback with a code.
  3. Triagle exchanges the code for an ID token, server to server over TLS,
     with the client secret. A token that comes straight from the provider's
     token endpoint over TLS is proven by that connection (OpenID Connect
     Core, section 3.1.3.7). Triagle then checks the issuer, the audience,
     the expiry, the nonce, and that the provider has verified the address.
  4. An address on the list gets a session with its role. Any other address
     is refused, and the refusal goes in the audit log.

What it does not do: create users. Nobody gets in by having an account at
the provider; they get in by being on TRIAGLE_OIDC_USERS.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from urllib.parse import urlencode

import requests

from app import auth

COOKIE = "triagle_sso"
START_SECONDS = 600                 # how long a person has to finish signing in at the provider
_DISCOVERY_SECONDS = 3600
_GOOGLE = "https://accounts.google.com"
_KNOWN = {_GOOGLE: {"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                    "token_endpoint": "https://oauth2.googleapis.com/token"}}
_cache = {}                         # issuer -> (fetched at, endpoints)


def issuer():
    return os.environ.get("TRIAGLE_OIDC_ISSUER", _GOOGLE).strip().rstrip("/") or _GOOGLE


def client_id():
    return os.environ.get("TRIAGLE_OIDC_CLIENT_ID", "").strip()


def _client_secret():
    return os.environ.get("TRIAGLE_OIDC_CLIENT_SECRET", "").strip()


def name():
    return os.environ.get("TRIAGLE_OIDC_NAME", "").strip() or ("Google" if issuer() == _GOOGLE else "single sign-on")


def configured():
    """Single sign-on is on when the provider is set up and somebody is allowed in."""
    return bool(auth.enabled() and client_id() and _client_secret() and auth._state.get("sso_users"))


def public_url(request_base):
    return (os.environ.get("TRIAGLE_PUBLIC_URL", "").strip().rstrip("/") or request_base).rstrip("/")


def _endpoints():
    """Where the provider takes sign-ins and exchanges codes."""
    iss = issuer()
    hit = _cache.get(iss)
    if hit and time.time() - hit[0] < _DISCOVERY_SECONDS:
        return hit[1]
    found = None
    try:
        r = requests.get(iss + "/.well-known/openid-configuration", timeout=10)
        doc = r.json() if r.status_code == 200 else {}
        if str(doc.get("issuer", "")).rstrip("/") == iss and str(doc.get("authorization_endpoint", "")).startswith("https://") \
                and str(doc.get("token_endpoint", "")).startswith("https://"):
            found = {"authorization_endpoint": doc["authorization_endpoint"], "token_endpoint": doc["token_endpoint"]}
    except (requests.RequestException, ValueError):
        found = None
    found = found or _KNOWN.get(iss)
    if found:
        _cache[iss] = (time.time(), found)
    return found


def _b64(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _pack(body):
    payload = _b64(json.dumps(body, separators=(",", ":")).encode())
    return payload + "." + auth._sign("sso:" + payload)


def _unpack(cookie, now):
    try:
        payload, sig = (cookie or "").rsplit(".", 1)
        if not hmac.compare_digest(sig, auth._sign("sso:" + payload)):
            return None
        body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return body if body.get("exp", 0) >= now else None
    except (ValueError, TypeError, AttributeError):
        return None


def begin(redirect_uri, next_path="/", now=None):
    """(address to send the browser to, cookie to set), or (None, None) if the
    provider cannot be reached."""
    now = time.time() if now is None else now
    ends = _endpoints()
    if not ends:
        return None, None
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64(hashlib.sha256(verifier.encode()).digest())
    query = urlencode({"response_type": "code", "client_id": client_id(), "redirect_uri": redirect_uri,
                       "scope": "openid email", "state": state, "nonce": nonce,
                       "code_challenge": challenge, "code_challenge_method": "S256", "prompt": "select_account"})
    cookie = _pack({"state": state, "nonce": nonce, "verifier": verifier, "next": auth.safe_next(next_path),
                    "redirect": redirect_uri, "exp": int(now + START_SECONDS)})
    sep = "&" if "?" in ends["authorization_endpoint"] else "?"
    return ends["authorization_endpoint"] + sep + query, cookie


def _claims(id_token):
    """The body of an ID token. Its signature is not checked here: see the
    note at the top on why the TLS connection to the token endpoint is the proof."""
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except (ValueError, IndexError, AttributeError, TypeError):
        return None


def _issuer_ok(value):
    iss = issuer()
    value = str(value or "").rstrip("/")
    return value == iss or (iss == _GOOGLE and value == "accounts.google.com")


def finish(code, state, cookie, now=None):
    """(email or None, where to go next, reason). reason is 'ok' or a short
    word for the audit log; the person is told only that sign-in did not work."""
    now = time.time() if now is None else now
    started = _unpack(cookie, now)
    if not started:
        return None, "/", "expired"
    nxt = auth.safe_next(started.get("next"))
    if not code or not state or not hmac.compare_digest(str(state), str(started.get("state", ""))):
        return None, nxt, "state"
    ends = _endpoints()
    if not ends:
        return None, nxt, "provider"
    try:
        r = requests.post(ends["token_endpoint"], timeout=10, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": started.get("redirect", ""),
            "client_id": client_id(), "client_secret": _client_secret(), "code_verifier": started.get("verifier", "")})
        token = r.json().get("id_token") if r.status_code == 200 else None
    except (requests.RequestException, ValueError, AttributeError):
        token = None
    claims = _claims(token) if token else None
    if not claims:
        return None, nxt, "exchange"
    aud = claims.get("aud")
    aud_ok = aud == client_id() or (isinstance(aud, list) and client_id() in aud and claims.get("azp") == client_id())
    if not _issuer_ok(claims.get("iss")) or not aud_ok:
        return None, nxt, "issuer"
    try:
        if float(claims.get("exp", 0)) < now - 60:
            return None, nxt, "expired"
    except (TypeError, ValueError):
        return None, nxt, "expired"
    if not hmac.compare_digest(str(claims.get("nonce", "")), str(started.get("nonce", ""))):
        return None, nxt, "nonce"
    email = str(claims.get("email") or "").strip().lower()
    if not email or claims.get("email_verified") not in (True, "true"):
        return None, nxt, "unverified"
    return email, nxt, "ok"
