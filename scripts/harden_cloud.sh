#!/usr/bin/env bash
# Triagle - harden a Cloud Run deployment, in one pass.
#
# Run it in Cloud Shell, from the repository:
#     bash scripts/harden_cloud.sh
#
# What it does, each step safe to run again:
#   1. Moves the passwords and keys out of the service's plain settings and
#      into Secret Manager. Nothing secret is printed.
#   2. Ties the intake key to one customer, so the key (not the sender)
#      decides whose alerts arrive. Skipped if the key is under 16 characters.
#   3. Turns on backups for the saved state: the bucket keeps every earlier
#      version of the file for 7 days. Also refuses public access to it.
#   4. Mounts the bucket for the unprivileged user, so the app stops running
#      as root at its next start.
#
# Settings (all optional):
#   PROJECT, REGION, SERVICE      which deployment        (defaults below)
#   CUSTOMER                      whose feed the existing intake key belongs to
#   SKIP_VOLUME=1                 leave the bucket mount as it is (the app then stays root)
#   KEEP_DAYS                     how long earlier versions of the state are kept (default 7)
set -euo pipefail

PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-triagle}"
CUSTOMER="${CUSTOMER:-Greenvale Co-operative Bank}"
KEEP_DAYS="${KEEP_DAYS:-7}"
APP_UID=10001

WORK="$(mktemp -d)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n== %s\n' "$*"; }

say "Reading the service $SERVICE in $REGION (project $PROJECT)"
gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" --format=json > "$WORK/svc.json"

# What the service looks like now: which settings are plain text, which bucket is mounted.
python3 - "$WORK" <<'PY'
import json, os, sys
work = sys.argv[1]
svc = json.load(open(os.path.join(work, "svc.json")))
spec = svc["spec"]["template"]["spec"]
env = spec["containers"][0].get("env", [])
plain = {e["name"]: e["value"] for e in env if e.get("value") not in (None, "")}
for name in ("TRIAGLE_ADMIN_PASSWORD", "TRIAGLE_SECRET", "TRIAGLE_INGEST_KEY", "TRIAGLE_USERS",
             "TRIAGLE_ADMIN_TOTP", "TRIAGLE_OIDC_CLIENT_SECRET", "TRIAGLE_INGEST_KEYS"):
    if name in plain:
        with open(os.path.join(work, "val." + name), "w") as f:
            f.write(plain[name])
vol = next((v for v in spec.get("volumes", []) if (v.get("csi") or {}).get("driver") == "gcsfuse.run.googleapis.com"), None)
if vol:
    attrs = vol["csi"].get("volumeAttributes", {})
    open(os.path.join(work, "volume"), "w").write(vol["name"] + "\n" + attrs.get("bucketName", "") + "\n" + attrs.get("mountOptions", ""))
open(os.path.join(work, "account"), "w").write(spec.get("serviceAccountName", ""))
open(os.path.join(work, "url"), "w").write((svc.get("status") or {}).get("url", ""))
PY

# The settings below are only understood by version 0.9 and later. Changing
# them under an older build would cut the forwarder off, so check first.
URL="$(cat "$WORK/url")"
LIVE="$(curl -fs --max-time 20 "$URL/health" || true)"
case "$LIVE" in
    *'"version":"0.8'*|*'"version":"0.7'*|"")
        echo "The service at $URL is not running version 0.9 or later (it answered: ${LIVE:-nothing})."
        echo "Deploy first, then run this script again. Nothing was changed."
        exit 1;;
esac
echo "The service answers at $URL: $LIVE"

ACCOUNT="$(cat "$WORK/account")"
if [ -z "$ACCOUNT" ]; then
    ACCOUNT="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')-compute@developer.gserviceaccount.com"
fi
echo "The service runs as $ACCOUNT"

# ---- 1. secrets -------------------------------------------------------------------
say "1. Moving secrets into Secret Manager"
gcloud services enable secretmanager.googleapis.com --project "$PROJECT" >/dev/null
REMOVE=""
SECRETS=""
store() {   # store NAME: put the plain setting NAME into a secret and plan the swap
    local name="$1" id
    id="$(printf '%s' "$name" | tr 'A-Z_' 'a-z-')"
    [ -f "$WORK/val.$name" ] || return 0
    gcloud secrets describe "$id" --project "$PROJECT" >/dev/null 2>&1 \
        || gcloud secrets create "$id" --replication-policy=automatic --project "$PROJECT" >/dev/null
    gcloud secrets versions add "$id" --data-file="$WORK/val.$name" --project "$PROJECT" >/dev/null
    gcloud secrets add-iam-policy-binding "$id" --member="serviceAccount:$ACCOUNT" \
        --role=roles/secretmanager.secretAccessor --project "$PROJECT" >/dev/null
    REMOVE="$REMOVE,$name"
    SECRETS="$SECRETS,$name=$id:latest"
    echo "   $name is now the secret $id"
}

# ---- 2. the intake key belongs to one customer -------------------------------------
if [ -f "$WORK/val.TRIAGLE_INGEST_KEY" ] && [ ! -f "$WORK/val.TRIAGLE_INGEST_KEYS" ]; then
    if [ "$(wc -c < "$WORK/val.TRIAGLE_INGEST_KEY")" -ge 16 ]; then
        printf '%s=%s' "$CUSTOMER" "$(cat "$WORK/val.TRIAGLE_INGEST_KEY")" > "$WORK/val.TRIAGLE_INGEST_KEYS"
        rm -f "$WORK/val.TRIAGLE_INGEST_KEY"
        REMOVE="$REMOVE,TRIAGLE_INGEST_KEY"
        BOUND=1
    else
        echo "   The intake key is shorter than 16 characters, so it stays shared. Make a longer one to tie it to a customer."
    fi
fi
for NAME in TRIAGLE_ADMIN_PASSWORD TRIAGLE_SECRET TRIAGLE_INGEST_KEY TRIAGLE_USERS TRIAGLE_ADMIN_TOTP \
            TRIAGLE_OIDC_CLIENT_SECRET TRIAGLE_INGEST_KEYS; do
    store "$NAME"
done
if [ "${BOUND:-0}" = "1" ]; then
    say "2. The intake key now belongs to: $CUSTOMER"
    echo "   The forwarder needs no change. Its key now writes to that customer's queue only."
fi

# ---- 4 (prepared here, applied with the secrets in one new revision) ----------------
VOLUME_FLAG=()
BUCKET=""
if [ -f "$WORK/volume" ]; then
    VOLUME_NAME="$(sed -n 1p "$WORK/volume")"
    BUCKET="$(sed -n 2p "$WORK/volume")"
    OPTIONS="$(sed -n 3p "$WORK/volume")"
    if [ "${SKIP_VOLUME:-0}" != "1" ] && [ -n "$BUCKET" ] && ! printf '%s' "$OPTIONS" | grep -q "uid=$APP_UID"; then
        VOLUME_FLAG=(--add-volume "name=$VOLUME_NAME,type=cloud-storage,bucket=$BUCKET,mount-options=uid=$APP_UID;gid=$APP_UID")
    fi
fi

if [ -n "$REMOVE" ] || [ "${#VOLUME_FLAG[@]}" -gt 0 ]; then
    say "Applying the changes as one new revision"
    ARGS=()
    [ -n "$REMOVE" ] && ARGS+=(--remove-env-vars "${REMOVE#,}")
    [ -n "$SECRETS" ] && ARGS+=(--update-secrets "${SECRETS#,}")
    gcloud run services update "$SERVICE" --region "$REGION" --project "$PROJECT" --quiet "${ARGS[@]}" "${VOLUME_FLAG[@]}"
else
    say "Nothing to change on the service: its secrets are already in Secret Manager"
fi

# ---- 3. backups for the saved state --------------------------------------------------
if [ -n "$BUCKET" ]; then
    say "3. Backups and public-access block on gs://$BUCKET"
    cat > "$WORK/lifecycle.json" <<JSON
{"rule": [{"action": {"type": "Delete"}, "condition": {"daysSinceNoncurrentTime": $KEEP_DAYS}}]}
JSON
    gcloud storage buckets update "gs://$BUCKET" --versioning --public-access-prevention \
        --uniform-bucket-level-access --lifecycle-file="$WORK/lifecycle.json" --project "$PROJECT" >/dev/null
    echo "   Every earlier version of the saved state is kept for $KEEP_DAYS days. The bucket refuses public access."
    echo "   To bring back an earlier version:  gcloud storage ls -a gs://$BUCKET/   then copy the one you want over the current file."
else
    say "3. No Cloud Storage bucket is mounted on this service, so there is nothing to back up"
fi

say "Done. Check it"
echo "   Sign in, then open  /health . It should say:"
echo "     \"runs_as\": \"unprivileged user $APP_UID\"   (after step 4)"
echo "     \"customer_keys\": 1                         (after step 2)"
echo "     and \"saved_state\" with no error."
echo "   Then open Live and wait for the next real alert: that proves the forwarder's key still works."
echo "   If anything looks wrong, go back one revision:"
echo "     gcloud run revisions list --service $SERVICE --region $REGION --limit 3"
echo "     gcloud run services update-traffic $SERVICE --region $REGION --to-revisions PREVIOUS_REVISION_NAME=100"
