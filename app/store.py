"""
Triagle — saved state.

The queue, the decisions people made and the reports they marked as filed are
held in memory. Without this module a restart empties them. With
TRIAGLE_STATE_FILE set, they are written to that file and read back at start.

One file, replaced whole each time. A path ending in .gz is compressed, which
matters when the file sits on a mounted bucket and every save is an upload.
On Cloud Run the file lives on a mounted Cloud Storage bucket; on a laptop or
a server it is an ordinary file.

Nothing here raises. A save that fails is reported once on stderr and the
console carries on from memory; a file that cannot be read is left alone and
the console starts empty.

Settings
  TRIAGLE_STATE_FILE      where to keep it, e.g. /data/triagle-state.json.gz. Unset = nothing is saved.
  TRIAGLE_STATE_SECONDS   least time between saves of the alert queue (default 10). A decision a
                          person makes is saved at once.
"""
import gzip
import json
import os
import sys
import time

VERSION = 1
_last = {"error": None, "saved_at": 0.0, "bytes": 0}


def path():
    return os.environ.get("TRIAGLE_STATE_FILE", "").strip()


def enabled():
    return bool(path())


def interval():
    try:
        return max(0.0, float(os.environ.get("TRIAGLE_STATE_SECONDS", "10")))
    except ValueError:
        return 10.0


def _complain(what, err):
    msg = f"{what}: {type(err).__name__}: {err}"
    if _last["error"] != msg:                        # once per distinct problem, not once per save
        print(f"[triagle] saved state: {msg}", file=sys.stderr, flush=True)
    _last["error"] = msg


def _encode(state, target):
    data = json.dumps({"version": VERSION, **state}, separators=(",", ":"), default=str).encode()
    return gzip.compress(data, compresslevel=5) if target.endswith(".gz") else data


def save(state):
    """Write the whole state. True if it was written."""
    target = path()
    if not target:
        return False
    try:
        data = _encode(state, target)
        folder = os.path.dirname(target)
        if folder:
            os.makedirs(folder, exist_ok=True)
        tmp = target + ".tmp"
        try:
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, target)                  # the old file stays whole until the new one is complete
        except OSError:
            with open(target, "wb") as f:            # a mount that cannot rename: write in place
                f.write(data)
    except (OSError, TypeError, ValueError) as e:
        _complain("could not save", e)
        return False
    _last.update(error=None, saved_at=time.time(), bytes=len(data))
    return True


def load():
    """The saved state, or None if there is none or it cannot be read."""
    target = path()
    if not target or not os.path.exists(target):
        return None
    try:
        with open(target, "rb") as f:
            data = f.read()
        if data[:2] == b"\x1f\x8b":
            data = gzip.decompress(data)
        state = json.loads(data.decode())
    except (OSError, ValueError, EOFError) as e:
        _complain("could not read, starting empty", e)
        return None
    if not isinstance(state, dict) or state.get("version") != VERSION:
        _complain("ignored", ValueError("not a state file this version wrote"))
        return None
    return state


def status():
    return {"enabled": enabled(), "path": path() or None, "error": _last["error"],
            "saved_at": _last["saved_at"] or None, "bytes": _last["bytes"]}
