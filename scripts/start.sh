#!/bin/sh
# Triagle - start the app as an unprivileged user.
#
# The container starts as root for one reason: to find out whether the
# unprivileged user can write where the saved state and the audit log live.
#   - It can (the usual case): root is given up here and never used again.
#   - It cannot: the folder is a mounted bucket that belongs to root. Running
#     unprivileged would silently stop every save, so the app stays as it was
#     and says so. Mount the bucket for uid 10001 (docs/DEPLOY.md) and the
#     next start drops root by itself.
set -e
RUN_AS=triagle
PORT="${PORT:-8000}"

writable() {   # can the unprivileged user create a file in the folder of this path?
    [ -z "$1" ] && return 0
    dir=$(dirname "$1")
    [ -d "$dir" ] || mkdir -p "$dir" 2>/dev/null || true
    setpriv --reuid "$RUN_AS" --regid "$RUN_AS" --clear-groups sh -c \
        'f="$1/.triagle-write-test.$$"; : > "$f" && rm -f "$f"' sh "$dir" 2>/dev/null
}

if [ "$(id -u)" != "0" ]; then
    exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"        # already unprivileged
fi
if command -v setpriv >/dev/null 2>&1 && writable "$TRIAGLE_STATE_FILE" && writable "${TRIAGLE_AUDIT_LOG:-/app/data/audit.jsonl}"; then
    # exec, so the stop signal reaches the app and it saves its state before exiting
    exec setpriv --reuid "$RUN_AS" --regid "$RUN_AS" --clear-groups --inh-caps=-all \
        uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
fi
echo "[triagle] Running as root: user $RUN_AS cannot write to the saved-state or audit folder. Mount the bucket for uid 10001 to fix this." >&2
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
