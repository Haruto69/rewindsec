"""Tiny deterministic reconciler for allowlisted synthetic files only.

SIMULATION SUPPORT CODE, NOT MALWARE.  It performs no encryption, traversal,
discovery, recursion, subprocess execution, networking, persistence or command
evaluation.  It knows four fixed synthetic identifiers and a fixed workspace.
"""

import hashlib
import json
import os
import re
import signal
import sys

VERSION = "rewindsec2-target/v1"
PROJECTION_VERSION = "rewindsec2-sandbox-projection/v1"
WORKSPACE = "/workspace"
SESSION_KEY = re.compile(r"^[0-9a-f]{32}$")
FILES = {
    "f-facilities": "Facilities_Contracts_2026.xlsx",
    "f-headcount-model": "Headcount_Model.xlsx",
    "f-q3-metrics": "Q3_Metrics.xlsx",
    "f-team-rota": "Team_Rota_September.xlsx",
}
STATES = frozenset(("normal", "unavailable", "absent"))


def baseline(file_id):
    return ("REWINDSEC 2.0 SYNTHETIC FILE\nfile_id=%s\n"
            "simulation_only=true\n" % file_id).encode("utf-8")


def locked(file_id):
    return ("REWINDSEC 2.0 SYNTHETIC LOCKED MARKER\nfile_id=%s\n"
            "no_encryption=true\nsimulation_only=true\n" % file_id).encode("utf-8")


def path_for(file_id, unavailable=False):
    # ``file_id`` has already passed exact dictionary membership.  The joined
    # filename comes from this module, never input, and contains no separator.
    name = FILES[file_id] + (".demo_locked" if unavailable else "")
    return os.path.join(WORKSPACE, name)


def remove_if_present(path):
    if os.path.lexists(path):
        if os.path.islink(path):
            raise ValueError("workspace symlinks are refused")
        os.remove(path)


def replace_exact(path, data):
    if os.path.lexists(path) and os.path.islink(path):
        raise ValueError("workspace symlinks are refused")
    temporary = path + ".reconcile"
    remove_if_present(temporary)
    with open(temporary, "xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def validate(doc):
    if not isinstance(doc, dict) or set(doc) != {"version", "session_key", "files"}:
        raise ValueError("invalid projection schema")
    if doc["version"] != PROJECTION_VERSION or not SESSION_KEY.fullmatch(doc["session_key"]):
        raise ValueError("invalid projection identity or version")
    rows = doc["files"]
    if not isinstance(rows, list) or len(rows) != len(FILES):
        raise ValueError("invalid projection file set")
    parsed = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"file_id", "state"}:
            raise ValueError("invalid file-state schema")
        if row["file_id"] not in FILES or row["state"] not in STATES:
            raise ValueError("unknown file identifier or state")
        if row["file_id"] in parsed:
            raise ValueError("duplicate file identifier")
        parsed[row["file_id"]] = row["state"]
    if set(parsed) != set(FILES):
        raise ValueError("incomplete file allowlist")
    return doc["session_key"], parsed


def state_digest(session_key, states):
    doc = {
        "version": PROJECTION_VERSION,
        "session_key": session_key,
        "files": [{"file_id": key, "state": states[key]}
                  for key in sorted(FILES)],
    }
    raw = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def apply(session_key, states):
    for file_id in sorted(FILES):
        normal = path_for(file_id)
        impacted = path_for(file_id, unavailable=True)
        state = states[file_id]
        if state == "normal":
            replace_exact(normal, baseline(file_id))
            remove_if_present(impacted)
        elif state == "unavailable":
            replace_exact(impacted, locked(file_id))
            remove_if_present(normal)
        else:
            remove_if_present(normal)
            remove_if_present(impacted)
    return {"target_version": VERSION, "session_key": session_key,
            "files": [{"file_id": key, "state": states[key]}
                      for key in sorted(FILES)],
            "projection_digest": state_digest(session_key, states)}


def inspect(session_key):
    if not SESSION_KEY.fullmatch(session_key):
        raise ValueError("invalid session key")
    states = {}
    for file_id in sorted(FILES):
        normal = path_for(file_id)
        impacted = path_for(file_id, unavailable=True)
        if os.path.isfile(normal) and not os.path.lexists(impacted):
            with open(normal, "rb") as handle:
                states[file_id] = ("normal" if handle.read() == baseline(file_id)
                                   else "malformed")
        elif os.path.isfile(impacted) and not os.path.lexists(normal):
            with open(impacted, "rb") as handle:
                states[file_id] = ("unavailable" if handle.read() == locked(file_id)
                                   else "malformed")
        elif not os.path.lexists(normal) and not os.path.lexists(impacted):
            states[file_id] = "absent"
        else:
            states[file_id] = "malformed"
    if "malformed" in states.values():
        raise ValueError("malformed synthetic workspace state")
    return {"target_version": VERSION, "session_key": session_key,
            "files": [{"file_id": key, "state": states[key]}
                      for key in sorted(FILES)],
            "projection_digest": state_digest(session_key, states)}


def main(argv):
    command = argv[1] if len(argv) > 1 else ""
    if command == "idle" and len(argv) == 2:
        signal.pause()
        return 0
    if command == "reconcile" and len(argv) == 2:
        raw = sys.stdin.read(32769)
        if len(raw) > 32768:
            raise ValueError("projection exceeds fixed input bound")
        session_key, states = validate(json.loads(raw))
        print(json.dumps(apply(session_key, states), sort_keys=True,
                         separators=(",", ":")))
        return 0
    if command == "inspect" and len(argv) == 3:
        print(json.dumps(inspect(argv[2]), sort_keys=True,
                         separators=(",", ":")))
        return 0
    raise ValueError("unsupported command")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except (ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc)[:160], "target_version": VERSION}),
              file=sys.stderr)
        raise SystemExit(2)
