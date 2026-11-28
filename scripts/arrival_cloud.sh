#!/usr/bin/env bash
# Triagle - switch on "the model on every alert" for a Cloud Run deployment.
#
# Run it in Cloud Shell, from the repository, after the deploy:
#     bash scripts/arrival_cloud.sh                 switch it on, or bring the settings up to date
#     DAILY_USD=3 bash scripts/arrival_cloud.sh     the same, with a different limit for the day
#     bash scripts/arrival_cloud.sh off             stop the work. What was read and investigated stays
#     bash scripts/arrival_cloud.sh status          what the service says about the work. Changes nothing
#
# What "on" does, each step safe to run again:
#   1. Makes a key for the work and keeps it in Secret Manager. An existing
#      key is used again. Nothing secret is printed.
#   2. Sets TRIAGLE_ARRIVAL=on, the day's limit and the key on the service,
#      as one new revision. Skipped if nothing would change.
#   3. Makes a Cloud Scheduler job that calls /api/work every minute with
#      that key. Cloud Run gives the service CPU only while it answers a
#      request, so the work is done inside this call.
#   4. Calls /api/work once itself and says what the service answered.
#
# Settings (all optional):
#   PROJECT, REGION, SERVICE      which deployment                       (defaults below)
#   DAILY_USD                     what the work may spend in a day       (default: what is set now, else 1.00)
#   JOB                           the scheduler job's name               (default triagle-work)
set -euo pipefail

MODE="${1:-on}"
PROJECT="${PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-triagle}"
JOB="${JOB:-triagle-work}"
SECRET_ID="triagle-work-key"

WORK="$(mktemp -d)"
chmod 700 "$WORK"
trap 'rm -rf "$WORK"' EXIT

say() { printf '\n== %s\n' "$*"; }
got() { [ -f "$WORK/$1" ] && cat "$WORK/$1" || true; }

case "$MODE" in on|off|status) ;; *) echo "Say on, off or status."; exit 2;; esac

say "Reading the service $SERVICE in $REGION (project $PROJECT)"
gcloud run services describe "$SERVICE" --region "$REGION" --project "$PROJECT" --format=json > "$WORK/svc.json"
python3 - "$WORK" <<'PY'
import json, os, sys
work = sys.argv[1]
def put(name, text):
    with open(os.path.join(work, name), "w") as f:
        f.write(text)
svc = json.load(open(os.path.join(work, "svc.json")))
spec = svc["spec"]["template"]["spec"]
env = spec["containers"][0].get("env", [])
plain = {e["name"]: e["value"] for e in env if e.get("value") not in (None, "")}
put("url", (svc.get("status") or {}).get("url", ""))
put("account", spec.get("serviceAccountName", ""))
put("arrival", plain.get("TRIAGLE_ARRIVAL", ""))
put("cap", plain.get("TRIAGLE_ARRIVAL_DAILY_USD", ""))
ref = next((e for e in env if e["name"] == "TRIAGLE_WORK_KEY"), None)
put("keyref", ((ref or {}).get("valueFrom") or {}).get("secretKeyRef", {}).get("name", ""))
PY
URL="$(got url)"
if [ -z "$URL" ]; then
    echo "The service has no address yet. Deploy first."
    exit 1
fi

# What the service says about the work, in a few lines. $1 is a file holding its JSON answer.
report() {
    python3 - "$1" <<'PY'
import json, sys
try:
    a = json.load(open(sys.argv[1]))
except Exception:
    print("   The answer could not be read.")
    sys.exit(0)
if not a.get("on"):
    print("   The work is switched off on the service.")
    sys.exit(0)
print("   Switched on." + ("" if a.get("model") else " No model is connected, so nothing is read yet."))
if a.get("paused"):
    print("   Paused: " + a["paused"])
if a.get("busy"):
    print("   A round of work is going on right now (the scheduler's).")
w = a.get("waiting") or {}
print(f"   Closures read again: {a.get('read', 0)}.  Alerts investigated in full: {a.get('investigated', 0)}.  Sent to a person because of it: {a.get('raised', 0)}.")
print(f"   Still to do: {w.get('read', 0)} to read, {w.get('need', 0) + w.get('look', 0)} to investigate.")
print(f"   Spent: ${a.get('usd', 0):.2f} in all, ${a.get('today_usd', 0):.2f} of ${a.get('cap_usd', 0):.2f} today.")
if a.get("per_1000_usd") is not None:
    print(f"   For 1,000 alerts of this mix: ${a['per_1000_usd']:.2f}.")
for line in (a.get("did") or [])[:6]:
    print("   Just now: " + line)
PY
}

if [ "$MODE" = "status" ]; then
    say "What the service says"
    CODE="$(curl -s -o "$WORK/arrival.json" -w '%{http_code}' --max-time 30 "$URL/api/arrival" || true)"
    if [ "$CODE" = "200" ]; then
        report "$WORK/arrival.json"
    else
        echo "   The figures need a sign-in on this service (it answered $CODE). Sign in and open the Overview."
    fi
    gcloud scheduler jobs describe "$JOB" --location "$REGION" --project "$PROJECT" --format='value(state,schedule,lastAttemptTime)' 2>/dev/null \
        | sed 's/^/   The scheduler job: /' || echo "   There is no scheduler job named $JOB."
    exit 0
fi

if [ "$MODE" = "off" ]; then
    say "Stopping the work"
    if gcloud scheduler jobs describe "$JOB" --location "$REGION" --project "$PROJECT" >/dev/null 2>&1; then
        gcloud scheduler jobs pause "$JOB" --location "$REGION" --project "$PROJECT" >/dev/null
        echo "   The scheduler job $JOB is paused."
    else
        echo "   There is no scheduler job named $JOB."
    fi
    if [ "$(got arrival)" = "on" ]; then
        gcloud run services update "$SERVICE" --region "$REGION" --project "$PROJECT" --quiet \
            --update-env-vars "TRIAGLE_ARRIVAL=off" >/dev/null
        echo "   TRIAGLE_ARRIVAL is off on the service."
    else
        echo "   TRIAGLE_ARRIVAL was not on."
    fi
    echo "   What the model read and investigated stays where it is. To start again: bash scripts/arrival_cloud.sh"
    exit 0
fi

# ---- on ------------------------------------------------------------------------------
# The work is only understood by version 0.11 and later.
LIVE="$(curl -fs --max-time 20 "$URL/health" || true)"
VERSION="$(printf '%s' "$LIVE" | python3 -c 'import json, sys
try:
    print(json.load(sys.stdin).get("version", ""))
except Exception:
    print("")')"
case "$VERSION" in
    0.1[1-9]*|0.[2-9][0-9]*|[1-9]*) echo "The service answers at $URL as version $VERSION";;
    *)  echo "The service at $URL is not running version 0.11 or later (it answered: ${LIVE:-nothing})."
        echo "Deploy first, then run this script again. Nothing was changed."
        exit 1;;
esac

CAP="${DAILY_USD:-$(got cap)}"
CAP="${CAP:-1.00}"
if ! printf '%s' "$CAP" | grep -Eq '^[0-9]+(\.[0-9]+)?$'; then
    echo "DAILY_USD must be a number of US dollars, for example 3 or 1.50. Nothing was changed."
    exit 1
fi

ACCOUNT="$(got account)"
if [ -z "$ACCOUNT" ]; then
    ACCOUNT="$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')-compute@developer.gserviceaccount.com"
fi

say "1. The key for the work"
gcloud services enable secretmanager.googleapis.com cloudscheduler.googleapis.com --project "$PROJECT" >/dev/null
for _ in 1 2 3 4 5 6; do          # a newly enabled API can take a few seconds to answer
    gcloud secrets list --limit 1 --project "$PROJECT" >/dev/null 2>&1 && break
    sleep 5
done
NEWKEY=0
if gcloud secrets versions access latest --secret "$SECRET_ID" --project "$PROJECT" > "$WORK/key" 2>/dev/null \
        && [ "$(wc -c < "$WORK/key")" -ge 16 ]; then
    echo "   The secret $SECRET_ID is already there and is used again."
else
    python3 -c 'import secrets, sys; sys.stdout.write(secrets.token_hex(24))' > "$WORK/key"
    gcloud secrets describe "$SECRET_ID" --project "$PROJECT" >/dev/null 2>&1 \
        || gcloud secrets create "$SECRET_ID" --replication-policy=automatic --project "$PROJECT" >/dev/null
    gcloud secrets versions add "$SECRET_ID" --data-file="$WORK/key" --project "$PROJECT" >/dev/null
    NEWKEY=1
    echo "   A new key was made and stored as the secret $SECRET_ID. It is not shown."
fi
gcloud secrets add-iam-policy-binding "$SECRET_ID" --member="serviceAccount:$ACCOUNT" \
    --role=roles/secretmanager.secretAccessor --project "$PROJECT" >/dev/null
printf 'X-Triagle-Key: %s' "$(cat "$WORK/key")" > "$WORK/hdr"

say "2. The settings on the service"
if [ "$(got arrival)" = "on" ] && [ "$(got cap)" = "$CAP" ] && [ "$(got keyref)" = "$SECRET_ID" ] && [ "$NEWKEY" = "0" ]; then
    echo "   Already set: on, \$$CAP a day, the key from the secret. No new revision."
else
    [ "$NEWKEY" = "1" ] && sleep 15      # a new permission on a secret takes a moment to reach Cloud Run
    if ! gcloud run services update "$SERVICE" --region "$REGION" --project "$PROJECT" --quiet \
            --update-env-vars "TRIAGLE_ARRIVAL=on,TRIAGLE_ARRIVAL_DAILY_USD=$CAP" \
            --update-secrets "TRIAGLE_WORK_KEY=$SECRET_ID:latest"; then
        echo
        echo "The new revision did not start. The service is still running the revision it had: nothing was lost."
        echo "If the lines above speak of a permission on a secret, wait two minutes and run this script again."
        exit 1
    fi
    echo "   On, with a limit of \$$CAP a day (India time)."
fi

say "3. The scheduler job that calls /api/work every minute"
if gcloud scheduler jobs describe "$JOB" --location "$REGION" --project "$PROJECT" >/dev/null 2>&1; then
    gcloud scheduler jobs update http "$JOB" --location "$REGION" --project "$PROJECT" \
        --schedule "* * * * *" --uri "$URL/api/work" --http-method POST \
        --update-headers "X-Triagle-Key=$(cat "$WORK/key")" --attempt-deadline 180s >/dev/null
    gcloud scheduler jobs resume "$JOB" --location "$REGION" --project "$PROJECT" >/dev/null 2>&1 || true
    echo "   The job $JOB was there and is up to date."
else
    gcloud scheduler jobs create http "$JOB" --location "$REGION" --project "$PROJECT" \
        --schedule "* * * * *" --uri "$URL/api/work" --http-method POST \
        --headers "X-Triagle-Key=$(cat "$WORK/key")" --attempt-deadline 180s >/dev/null
    echo "   The job $JOB was made."
fi

say "4. Asking the service to work once"
CODE="none"
for _ in 1 2 3 4 5 6; do          # the new revision can take a moment to serve
    CODE="$(curl -s -o "$WORK/work.json" -w '%{http_code}' --max-time 200 -X POST -H @"$WORK/hdr" "$URL/api/work" || true)"
    [ "$CODE" = "200" ] && break
    sleep 10
done
if [ "$CODE" = "200" ]; then
    report "$WORK/work.json"
else
    echo "   The service answered $CODE to the key. The settings are in place; the scheduler will keep trying every minute."
    echo "   If it still says so in five minutes, run:  bash scripts/arrival_cloud.sh status"
    exit 1
fi

say "Done"
echo "   The Overview shows the work under \"on every alert\": $URL/"
echo "   To see it from here:      bash scripts/arrival_cloud.sh status"
echo "   To change the day's limit: DAILY_USD=1 bash scripts/arrival_cloud.sh"
echo "   To stop it:               bash scripts/arrival_cloud.sh off"
