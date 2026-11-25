#!/usr/bin/env bash
# Triagle - harden a Cloud Run deployment, in one pass.
#
# Run it in Cloud Shell, from the repository:
#     bash scripts/harden_cloud.sh            every step below
#     bash scripts/harden_cloud.sh backup     step 1 only. Safe on any version: run it before a deploy.
#
# What it does, each step safe to run again:
#   1. Backs up the saved state. A dated copy is taken now, and from now on
#      the bucket keeps every earlier version of the file for 7 days. The
#      bucket also refuses public access.
#   2. Moves the passwords and keys out of the service's plain settings and
#      into Secret Manager. Nothing secret is printed.
#   3. Ties the intake key to one customer, so the key (not the sender)
#      decides whose alerts arrive.
#   4. Mounts the bucket for the unprivileged user, so the app stops running
#      as root at its next start.
#   5. Checks that the intake key still gets in. If it does not, the revision
#      that was serving before is put back, by this script, at once.
#
# Settings (all optional):
#   PROJECT, REGION, SERVICE      which deployment        (defaults below)
#   CUSTOMER                      whose feed the existing intake key belongs to. Left unset, the
#                                 script uses the name the Wazuh feed already arrives under
#   SKIP_VOLUME=1                 leave the bucket mount as it is (the app then stays root)
#   SKIP_BACKUP=1                 go on even if the dated copy cannot be taken
#   KEEP_DAYS                     how long earlier versions of the state are kept (default 7)
set -euo pipefail

MODE="${1:-all}"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-triagle}"
CUSTOMER_GIVEN="${CUSTOMER:-}"
CUSTOMER="${CUSTOMER:-Greenvale Co-operative Bank}"
KEEP_DAYS="${KEEP_DAYS:-7}"
APP_UID=10001
STAMP="$(date -u +%Y%m%d-%H%M%S)"

WORK="$(mktemp -d)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n== %s\n' "$*"; }
got() { [ -f "$WORK/$1" ] && cat "$WORK/$1" || true; }

say "Reading the service $SERVICE in $REGION (project $PROJECT)"
gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" --format=json > "$WORK/svc.json"

# What the service looks like now: which settings are plain text, which bucket
# is mounted and where, and which revision is serving.
python3 - "$WORK" <<'PY'
import json, os, sys
work = sys.argv[1]
def put(name, text):
    with open(os.path.join(work, name), "w") as f:
        f.write(text)
svc = json.load(open(os.path.join(work, "svc.json")))
spec = svc["spec"]["template"]["spec"]
box = spec["containers"][0]
env = box.get("env", [])
plain = {e["name"]: e["value"] for e in env if e.get("value") not in (None, "")}
put("refs", "\n".join(e["name"] for e in env if e.get("valueFrom")) + "\n")
for name in ("TRIAGLE_ADMIN_PASSWORD", "TRIAGLE_SECRET", "TRIAGLE_INGEST_KEY", "TRIAGLE_USERS",
             "TRIAGLE_ADMIN_TOTP", "TRIAGLE_OIDC_CLIENT_SECRET", "TRIAGLE_INGEST_KEYS"):
    if name in plain:
        put("val." + name, plain[name])
if "TRIAGLE_INGEST_KEY" in plain:                       # for the check in step 5; sent as a header, never printed
    put("hdr", "X-Triagle-Key: " + plain["TRIAGLE_INGEST_KEY"])
vol = next((v for v in spec.get("volumes", []) if (v.get("csi") or {}).get("driver") == "gcsfuse.run.googleapis.com"), None)
if vol:
    attrs = vol["csi"].get("volumeAttributes", {})
    put("volume", vol["name"] + "\n" + attrs.get("bucketName", "") + "\n" + attrs.get("mountOptions", ""))
    mount = next((m.get("mountPath", "") for m in box.get("volumeMounts", []) if m.get("name") == vol["name"]), "")
    state = plain.get("TRIAGLE_STATE_FILE", "")
    if mount and state.startswith(mount.rstrip("/") + "/"):
        put("object", state[len(mount.rstrip("/")) + 1:])   # the state file's name inside the bucket
status = svc.get("status") or {}
put("account", spec.get("serviceAccountName", ""))
put("url", status.get("url", ""))
serving = sorted(status.get("traffic") or [], key=lambda t: -(t.get("percent") or 0))
put("previous", (serving[0].get("revisionName", "") if serving else "") or status.get("latestReadyRevisionName", ""))
follows = any(t.get("latestRevision") and (t.get("percent") or 0) == 100 for t in (svc["spec"].get("traffic") or [{"latestRevision": True, "percent": 100}]))
put("pinned", "" if follows else "1")
put("unstarted", "1" if status.get("latestCreatedRevisionName") != status.get("latestReadyRevisionName") else "")
PY

URL="$(got url)"
PREVIOUS="$(got previous)"
BUCKET=""; VOLUME_NAME=""; OPTIONS=""
if [ -f "$WORK/volume" ]; then
    VOLUME_NAME="$(sed -n 1p "$WORK/volume")"
    BUCKET="$(sed -n 2p "$WORK/volume")"
    OPTIONS="$(sed -n 3p "$WORK/volume")"
fi
OBJECT="$(got object)"

# ---- 1. back up the saved state -----------------------------------------------------
if [ -n "$BUCKET" ]; then
    say "1. Backing up the saved state on gs://$BUCKET"
    cat > "$WORK/lifecycle.json" <<JSON
{"rule": [{"action": {"type": "Delete"}, "condition": {"daysSinceNoncurrentTime": $KEEP_DAYS}}]}
JSON
    gcloud storage buckets update "gs://$BUCKET" --versioning --public-access-prevention \
        --lifecycle-file="$WORK/lifecycle.json" --project "$PROJECT" >/dev/null
    echo "   From now on every earlier version of the saved state is kept for $KEEP_DAYS days. The bucket refuses public access."
    if [ -n "$OBJECT" ] && [ "${SKIP_BACKUP:-0}" != "1" ]; then
        if gcloud storage cp "gs://$BUCKET/$OBJECT" "gs://$BUCKET/backups/$STAMP/$OBJECT" --project "$PROJECT" >/dev/null 2>"$WORK/cp.err"; then
            echo "   A copy of the state as it is now:  gs://$BUCKET/backups/$STAMP/$OBJECT"
            echo "   To put it back:  gcloud storage cp gs://$BUCKET/backups/$STAMP/$OBJECT gs://$BUCKET/$OBJECT   then restart the service."
        else
            echo "   Could not copy gs://$BUCKET/$OBJECT. gcloud said:"
            sed 's/^/      /' "$WORK/cp.err"
            echo "   Nothing on the service was changed. To go on without this copy, put SKIP_BACKUP=1 in front of the command."
            exit 1
        fi
    else
        echo "   No dated copy was taken (the state file's place in the bucket could not be worked out, or SKIP_BACKUP=1)."
    fi
else
    say "1. No Cloud Storage bucket is mounted on this service, so there is no saved state to back up"
fi
if [ "$MODE" = "backup" ]; then
    say "Backup done. Nothing on the service was changed."
    exit 0
fi

# The settings below are only understood by version 0.9 and later. Changing
# them under an older build would cut the forwarder off, so check first.
LIVE="$(curl -fs --max-time 20 "$URL/health" || true)"
VERSION="$(printf '%s' "$LIVE" | python3 -c 'import json, sys
try:
    print(json.load(sys.stdin).get("version", ""))
except Exception:
    print("")')"
case "$VERSION" in
    0.9*|0.[1-9][0-9]*|[1-9]*) echo; echo "The service answers at $URL as version $VERSION";;
    *)  echo
        echo "The service at $URL is not running version 0.9 or later (it answered: ${LIVE:-nothing})."
        echo "Deploy first, then run this script again. Nothing on the service was changed."
        exit 1;;
esac
if [ -n "$(got pinned)" ]; then
    echo "Traffic is held on the revision $PREVIOUS (somebody went back to it earlier), so a new revision would not serve."
    echo "When you are ready, let new revisions serve again, then run this script again:"
    echo "    gcloud run services update-traffic $SERVICE --region $REGION --to-latest"
    exit 1
fi

# The intake key as it answers now. The same question is asked again after the change.
key_answer() { curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H @"$WORK/hdr" "$URL/api/outbox?after=0" 2>/dev/null || true; }
settled() {   # the answer once it is clear: 200, a refusal, or whatever came last after 40 seconds
    local code="" i
    for i in 1 2 3 4 5 6 7 8; do
        code="$(key_answer)"
        case "$code" in 200|401|403) break;; esac
        sleep 5
    done
    echo "${code:-none}"
}
CHECK=0
if [ -f "$WORK/hdr" ]; then
    BEFORE="$(settled)"
    if [ "$BEFORE" != "200" ]; then
        echo "The intake key does not get in as things stand (the service answered $BEFORE), which is not what this script expects."
        echo "Nothing on the service was changed. Find out why before going on."
        exit 1
    fi
    CHECK=1
    echo "The intake key gets in now. It will be tried again after the change."
fi

ACCOUNT="$(got account)"
if [ -z "$ACCOUNT" ]; then
    ACCOUNT="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')-compute@developer.gserviceaccount.com"
fi
echo "The service runs as $ACCOUNT"

# ---- 3 (decided first, stored with the rest in step 2) --------------------------------
# The intake key belongs to one customer from now on. Left shared if the bound
# form would not be read back as exactly the same key.
BOUND=0
if [ -f "$WORK/val.TRIAGLE_INGEST_KEY" ] && [ ! -f "$WORK/val.TRIAGLE_INGEST_KEYS" ] && ! grep -qx TRIAGLE_INGEST_KEYS "$WORK/refs"; then
    # Which name does the feed arrive under today? The key must be tied to that
    # exact name, or tomorrow's alerts would land beside today's instead of with them.
    SEEN=""
    [ "$(wc -c < "$WORK/val.TRIAGLE_INGEST_KEY")" -ge 16 ] && SEEN="$(python3 - "$WORK" "$URL" <<'PY'
import json, os, sys, urllib.request
work, url = sys.argv[1], sys.argv[2]
header, _, key = open(os.path.join(work, "hdr")).read().partition(": ")
seen, after, epoch = set(), 0, ""
try:
    for _ in range(10):                                  # what people have decided, a page at a time
        ask = urllib.request.Request(f"{url}/api/outbox?after={after}&epoch={epoch}", headers={header: key})
        box = json.load(urllib.request.urlopen(ask, timeout=20))
        events = box.get("events") or []
        seen.update(e["client"] for e in events if e.get("source") == "wazuh" and e.get("client"))
        if len(events) < 100:
            break
        after, epoch = box.get("cursor", after), box.get("epoch", "")
except Exception:
    pass
print("\n".join(sorted(seen)))
PY
)"
    COUNT="$(printf '%s' "$SEEN" | grep -c . || true)"
    if [ "$(wc -c < "$WORK/val.TRIAGLE_INGEST_KEY")" -lt 16 ]; then
        :                                                # too short to tie to anyone; said below
    elif [ "$COUNT" = "0" ]; then
        echo "No decision on a Wazuh alert is on record, so the name \"$CUSTOMER\" could not be checked against the feed."
    elif printf '%s\n' "$SEEN" | grep -qxF "$CUSTOMER"; then
        echo "The Wazuh feed arrives as \"$CUSTOMER\". The key will be tied to that name."
    elif [ -z "$CUSTOMER_GIVEN" ] && [ "$COUNT" = "1" ]; then
        CUSTOMER="$SEEN"
        echo "The Wazuh feed arrives as \"$CUSTOMER\". The key will be tied to that name."
    else
        echo "The Wazuh feed on this service does not arrive as \"$CUSTOMER\". It has arrived as:"
        printf '%s\n' "$SEEN" | sed 's/^/    /'
        echo "Run again with the right name in front:  CUSTOMER=\"NAME\" bash scripts/harden_cloud.sh"
        echo "Nothing on the service was changed."
        exit 1
    fi
    WHY="$(python3 - "$WORK" "$CUSTOMER" <<'PY'
import os, re, sys
work, customer = sys.argv[1], sys.argv[2].strip()
key = open(os.path.join(work, "val.TRIAGLE_INGEST_KEY")).read()
why = ""
if len(key.strip()) < 16:
    why = "it is shorter than 16 characters. Make a longer one to tie it to a customer"
elif key != key.strip() or re.search(r"[;\s]", key):
    why = "it contains a space or a semicolon"
elif not customer or re.search(r"[=;\n]", customer):
    why = "the customer name is empty or contains = or ;"
else:
    line, back = customer + "=" + key, {}
    for part in re.split(r"[;\n]+", line):               # read it back the way the app does
        name, sep, k = part.partition("=")
        if sep and name.strip() and len(k.strip()) >= 16:
            back[k.strip()] = name.strip()
    if back != {key: customer}:
        why = "it would not be read back as the same key"
    else:
        with open(os.path.join(work, "val.TRIAGLE_INGEST_KEYS"), "w") as f:
            f.write(line)
print(why)
PY
)"
    if [ -z "$WHY" ]; then
        BOUND=1
        rm -f "$WORK/val.TRIAGLE_INGEST_KEY"
    else
        echo "The intake key stays shared: $WHY."
    fi
fi

# ---- 2. secrets -------------------------------------------------------------------
say "2. Moving secrets into Secret Manager"
gcloud services enable secretmanager.googleapis.com --project "$PROJECT" >/dev/null
for _ in 1 2 3 4 5 6; do          # a newly enabled API can take a few seconds to answer
    gcloud secrets list --limit 1 --project "$PROJECT" >/dev/null 2>&1 && break
    sleep 5
done
REMOVE=""
SECRETS=""
[ "$BOUND" = "1" ] && REMOVE=",TRIAGLE_INGEST_KEY"
store() {   # store NAME: put the plain setting NAME into a secret and plan the swap
    local name="$1" id
    id="$(printf '%s' "$name" | tr 'A-Z_' 'a-z-')"
    [ -f "$WORK/val.$name" ] || return 0
    gcloud secrets describe "$id" --project "$PROJECT" >/dev/null 2>&1 \
        || gcloud secrets create "$id" --replication-policy=automatic --project "$PROJECT" >/dev/null
    gcloud secrets versions add "$id" --data-file="$WORK/val.$name" --project "$PROJECT" >/dev/null
    gcloud secrets add-iam-policy-binding "$id" --member="serviceAccount:$ACCOUNT" \
        --role=roles/secretmanager.secretAccessor --project "$PROJECT" >/dev/null
    case ",$REMOVE," in *",$name,"*) ;; *) REMOVE="$REMOVE,$name";; esac
    SECRETS="$SECRETS,$name=$id:latest"
    echo "   $name is now the secret $id"
}
for NAME in TRIAGLE_ADMIN_PASSWORD TRIAGLE_SECRET TRIAGLE_INGEST_KEY TRIAGLE_USERS TRIAGLE_ADMIN_TOTP \
            TRIAGLE_OIDC_CLIENT_SECRET TRIAGLE_INGEST_KEYS; do
    store "$NAME"
done
[ -z "$SECRETS" ] && echo "   Nothing to move: no password or key is a plain setting."
if [ "$BOUND" = "1" ]; then
    say "3. The intake key now belongs to: $CUSTOMER"
    echo "   The forwarder needs no change. Its key now writes to that customer's queue only."
fi

# ---- 4. the bucket, mounted for the unprivileged user --------------------------------
VOLUME_FLAG=()
if [ "${SKIP_VOLUME:-0}" != "1" ] && [ -n "$BUCKET" ] && ! printf '%s' "$OPTIONS" | grep -q "uid=$APP_UID"; then
    VOLUME_FLAG=(--add-volume "name=$VOLUME_NAME,type=cloud-storage,bucket=$BUCKET,mount-options=uid=$APP_UID;gid=$APP_UID")
    say "4. The bucket will be mounted for user $APP_UID, so the app can give up root"
fi

ARGS=()
[ -n "$REMOVE" ] && ARGS+=(--remove-env-vars "${REMOVE#,}")
[ -n "$SECRETS" ] && ARGS+=(--update-secrets "${SECRETS#,}")
if [ "${#ARGS[@]}" -eq 0 ] && [ "${#VOLUME_FLAG[@]}" -eq 0 ] && [ -n "$(got unstarted)" ]; then
    # Everything is already set, but the newest revision never started: start one more.
    ARGS+=(--update-env-vars "TRIAGLE_SETTINGS_APPLIED=$STAMP")
fi
if [ "${#ARGS[@]}" -eq 0 ] && [ "${#VOLUME_FLAG[@]}" -eq 0 ]; then
    say "Nothing to change on the service: it is already set up this way"
    exit 0
fi

say "Applying the changes as one new revision (two or three minutes)"
[ -n "$SECRETS" ] && sleep 15      # a new permission on a secret takes a moment to reach Cloud Run
if ! gcloud run services update "$SERVICE" --region "$REGION" --project "$PROJECT" --quiet "${ARGS[@]}" "${VOLUME_FLAG[@]}"; then
    echo
    echo "The new revision did not start. The service is still running the revision it had ($PREVIOUS): nothing was lost."
    echo "If the lines above speak of a permission on a secret, wait two minutes and run this script again."
    echo "Otherwise keep the lines above: they say why."
    exit 1
fi

# ---- 5. does the intake key still get in? ---------------------------------------------
if [ "$CHECK" = "1" ]; then
    say "5. Trying the intake key on the new revision"
    AFTER="$(settled)"
    if [ "$AFTER" = "200" ]; then
        echo "   It gets in. The forwarder is not affected."
    else
        echo "   It does not get in (the service answered $AFTER)."
        if [ -n "$PREVIOUS" ]; then
            gcloud run services update-traffic "$SERVICE" --region "$REGION" --project "$PROJECT" \
                --to-revisions "$PREVIOUS=100" --quiet >/dev/null
            echo "   The revision that was serving before, $PREVIOUS, has been put back. It answers: $(settled)"
            echo "   Traffic now stays on that revision. When the cause is found, let new revisions serve again with:"
            echo "       gcloud run services update-traffic $SERVICE --region $REGION --to-latest"
        else
            echo "   Go back one revision now:"
            echo "       gcloud run revisions list --service $SERVICE --region $REGION --limit 3"
            echo "       gcloud run services update-traffic $SERVICE --region $REGION --to-revisions PREVIOUS_REVISION_NAME=100"
        fi
        exit 1
    fi
fi

say "Done. Check it"
echo "   Sign in, then open  $URL/health . It should say:"
[ "${#VOLUME_FLAG[@]}" -gt 0 ] && echo "     \"runs_as\": \"unprivileged user $APP_UID\""
[ "$BOUND" = "1" ] && echo "     \"customer_keys\": 1"
echo "     \"saved_state\" with \"error\": null, and the Live page with the same alerts as before."
echo "   If anything looks wrong, go back to the revision that was serving before this script ran:"
echo "       gcloud run services update-traffic $SERVICE --region $REGION --to-revisions ${PREVIOUS:-PREVIOUS_REVISION_NAME}=100"
echo "   and, once it is sorted out, let new revisions serve again:"
echo "       gcloud run services update-traffic $SERVICE --region $REGION --to-latest"
