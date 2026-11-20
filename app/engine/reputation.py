"""
Triagle — indicator reputation / OSINT enrichment.

During an investigation Triagle pulls the indicators out of an alert
(external IPs, file hashes, domains) and checks each one against reputation
intelligence — the same move a human analyst makes before deciding.

In production these lookups go to VirusTotal, AbuseIPDB, GreyNoise, Cisco
Talos and an internal intel platform. Here they resolve against an OFFLINE
intel pack shipped with the app, so the enrichment is real and fully
demoable with no API key and no network call — which also means it can never
rate-limit or time out in front of an audience. The pack is the seam: swap
`_PACK` lookups for live feed calls and nothing else changes.

Each indicator gets a structured reputation:
  - verdict:  malicious | suspicious | clean | internal | unknown
  - score:    0-100 (how bad), for a quick visual bar
  - sources:  the named feeds that back the verdict
  - note:     one plain-English line an analyst can read
"""
import ipaddress
import re

MALICIOUS = "malicious"
SUSPICIOUS = "suspicious"
CLEAN = "clean"
INTERNAL = "internal"
UNKNOWN = "unknown"

_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,}$", re.I)


# ---- the offline intel pack ------------------------------------------------
# key: indicator (lower-case) -> reputation record. `sources` are the feeds a
# real deployment would have queried; the notes are representative, not live.
_PACK = {
    # ransomware / C2 chain
    "185.220.101.44": {
        "type": "ip", "verdict": MALICIOUS, "score": 96,
        "category": "C2 / Tor exit",
        "sources": [("AbuseIPDB", "100% confidence of abuse, 1,400+ reports"),
                    ("GreyNoise", "classified malicious — mass scanner / C2"),
                    ("Cisco Talos", "Poor reputation — known Tor exit node")],
        "note": "Known command-and-control infrastructure and Tor exit node, flagged by multiple feeds."},
    "e3b0c44298fc1c149afbf4c8996fb924": {
        "type": "hash", "verdict": MALICIOUS, "score": 94,
        "category": "Ransomware loader",
        "sources": [("VirusTotal", "58 / 72 engines detect — Ransom:Win32/LockBit"),
                    ("Internal intel", "matches an active ransomware campaign loader")],
        "note": "File hash matches a known ransomware loader."},
    "45.146.10.22": {
        "type": "ip", "verdict": MALICIOUS, "score": 88,
        "category": "Credential stuffing / anonymising VPN",
        "sources": [("AbuseIPDB", "92% confidence — credential stuffing source"),
                    ("GreyNoise", "malicious — anonymising VPN exit")],
        "note": "Anonymising VPN exit used for credential stuffing; consistent with the impossible-travel sign-in."},
    # scan / brute source
    "203.0.113.88": {
        "type": "ip", "verdict": MALICIOUS, "score": 82,
        "category": "Scanner / brute-force",
        "sources": [("AbuseIPDB", "87% confidence — port scanning & brute force"),
                    ("GreyNoise", "malicious — opportunistic SMB scanner")],
        "note": "Reported scanning and password-spray source."},
    # web attack source
    "91.240.118.7": {
        "type": "ip", "verdict": MALICIOUS, "score": 79,
        "category": "Web application attacks",
        "sources": [("AbuseIPDB", "79% confidence — SQLi / web attacks"),
                    ("Cisco Talos", "Poor reputation")],
        "note": "Source of web-application attacks (SQL injection)."},
    # ClickFix scenario
    "cloudflare-verify.lol": {
        "type": "domain", "verdict": MALICIOUS, "score": 90,
        "category": "ClickFix lure / fake CAPTCHA",
        "sources": [("urlscan.io", "flagged — fake Cloudflare 'verify you are human' page"),
                    ("Google Safe Browsing", "social engineering")],
        "note": "Fake human-verification page used in ClickFix lures to trick users into running a pasted command."},
    "b6d91f4c2e7a8035cc1aa9f0e2d4b7619a3c5f82d0e1b4a6c7f9028d3e5a1b4c": {
        "type": "hash", "verdict": MALICIOUS, "score": 91,
        "category": "Infostealer (Lumma)",
        "sources": [("VirusTotal", "49 / 71 engines detect — Trojan:Win32/Lumma"),
                    ("Internal intel", "info-stealer dropped by ClickFix campaigns")],
        "note": "Info-stealer payload associated with ClickFix campaigns."},
    # account-compromise scenario
    "104.21.9.130": {
        "type": "ip", "verdict": MALICIOUS, "score": 85,
        "category": "AiTM phishing relay",
        "sources": [("Microsoft intel", "adversary-in-the-middle phishing relay"),
                    ("AbuseIPDB", "81% confidence — phishing infrastructure")],
        "note": "Adversary-in-the-middle phishing relay used to steal session tokens."},
    # a clean/known-good public address, to show Triagle does NOT cry wolf
    "8.8.8.8": {
        "type": "ip", "verdict": CLEAN, "score": 2,
        "category": "Public DNS resolver",
        "sources": [("GreyNoise", "benign — Google Public DNS"),
                    ("Cisco Talos", "Good reputation")],
        "note": "Google Public DNS — known-good, no adverse reports."},
}


def classify(value):
    """What kind of indicator is this string?"""
    if value is None:
        return "other"
    v = str(value).strip()
    if not v:
        return "other"
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if _HASH_RE.match(v):
        return "hash"
    if _DOMAIN_RE.match(v):
        return "domain"
    return "other"


def _is_internal_ip(v):
    try:
        ip = ipaddress.ip_address(str(v))
    except ValueError:
        return False
    # RFC 5737 documentation ranges stand in for public internet addresses in
    # the sample data, so they are NOT treated as internal.
    doc = any(ip in ipaddress.ip_network(n) for n in
              ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"))
    if doc:
        return False
    return not ip.is_global


def reputation(value):
    """Return the reputation record for one indicator. Never raises."""
    v = str(value).strip()
    key = v.lower()
    kind = classify(v)
    hit = _PACK.get(key)
    if hit:
        rec = dict(hit)
        rec["indicator"] = v
        rec.setdefault("type", kind)
        return rec
    # not in the pack: give an honest "nothing adverse on record" answer
    if kind == "ip" and _is_internal_ip(v):
        return {"indicator": v, "type": "ip", "verdict": INTERNAL, "score": 0,
                "category": "Internal asset", "sources": [],
                "note": "Internal/private address — not an external reputation subject."}
    return {"indicator": v, "type": kind, "verdict": UNKNOWN, "score": 0,
            "category": "No adverse reports", "sources": [("OSINT feeds", "no adverse reports on record")],
            "note": "No reputation hit — not known-bad, but not vouched for either."}


# Which fields of a normalized alert carry a reputation-checkable indicator.
def indicators_of(alert):
    """Pull the checkable indicators out of a normalized-alert dict, de-duped,
    in a sensible order (external IPs, hash, domain). Internal host names and
    private IPs are skipped — they are assets, not reputation subjects."""
    seen = []
    out = []

    def add(val):
        if not val:
            return
        s = str(val).strip()
        if not s or s.lower() in seen:
            return
        kind = classify(s)
        if kind == "ip" and _is_internal_ip(s):
            return
        if kind not in ("ip", "hash", "domain"):
            return
        seen.append(s.lower())
        out.append(s)

    ind = alert.get("indicators") or {}
    add(alert.get("dst_ip"))
    add(alert.get("src_ip"))
    add(ind.get("sha256"))
    add(ind.get("domain"))
    add(ind.get("url_host"))
    return out


def enrich(alert):
    """Return a list of reputation records for every checkable indicator on
    the alert. Empty list if the alert carries none."""
    return [reputation(v) for v in indicators_of(alert)]


def worst_verdict(records):
    """The most severe verdict across a set of reputation records."""
    order = [MALICIOUS, SUSPICIOUS, UNKNOWN, CLEAN, INTERNAL]
    for level in order:
        if any(r["verdict"] == level for r in records):
            return level
    return UNKNOWN


def is_confirmed_malicious(value):
    """True only when the indicator is in the intel pack AND malicious — the
    gate the auto-response policy uses before blocking an indicator."""
    return reputation(value)["verdict"] == MALICIOUS
