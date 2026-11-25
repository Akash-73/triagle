#!/usr/bin/env python3
"""
Fire a simulated attack at a running Triagle, the way a real SIEM/EDR webhook
would. Use it on stage: run this, then switch to the Triagle screen and watch
the incident get investigated and the CERT-In clock start.

    python scripts/fire_attack.py                         # localhost:8000
    python scripts/fire_attack.py --url https://triagle.example
    python scripts/fire_attack.py --key $TRIAGLE_INGEST_KEY
    python scripts/fire_attack.py --slow                  # one alert at a time

Auth: pass --key (matches TRIAGLE_INGEST_KEY on the server). Without a key the
server also accepts an analyst session, but a script has none, so use a key.
Only the standard library is required.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # run from anywhere
from app import demo_attack  # noqa: E402


def post(url, key, payload):
    if not url.lower().startswith(("https://", "http://")):
        raise SystemExit("The address must start with https:// or http://")
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url.rstrip("/") + "/ingest", data=data, method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-Triagle-Key": key or ""})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser(description="Fire a simulated attack at Triagle.")
    ap.add_argument("--url", default="http://localhost:8000", help="Triagle base URL")
    ap.add_argument("--key", default="", help="ingest key (TRIAGLE_INGEST_KEY on the server)")
    ap.add_argument("--slow", action="store_true", help="send one alert at a time, 2s apart")
    ap.add_argument("--benign", action="store_true", help="also send one benign alert")
    ap.add_argument("--scenario", default=demo_attack.DEFAULT, choices=sorted(demo_attack.SCENARIOS),
                    help="bank (default) or power, which adds a control command to an RTU")
    args = ap.parse_args()

    items = demo_attack.fresh_attack(scenario=args.scenario)
    if args.benign:
        items += demo_attack.fresh_benign(scenario=args.scenario)

    try:
        if args.slow:
            for i, it in enumerate(items, 1):
                name = (it["raw"].get("name") or it["raw"].get("attack") or it["raw"].get("riskEventType")
                        or it["raw"].get("alert"))
                res = post(args.url, args.key, it)
                print(f"  [{i}/{len(items)}] {name:42}  -> queue {res['queue']}")
                if i < len(items):
                    time.sleep(2)
        else:
            res = post(args.url, args.key, items)
            print(f"  fired {res['accepted']} alerts  -> queue {res['queue']}")
    except urllib.error.HTTPError as e:
        sys.exit(f"  server said {e.code}: {e.read().decode()[:200]}")
    except urllib.error.URLError as e:
        sys.exit(f"  could not reach {args.url}: {e.reason}")
    print("  done — switch to the Triagle screen.")


if __name__ == "__main__":
    main()
