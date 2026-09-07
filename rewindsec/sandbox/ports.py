"""Typed, stdlib-only port for RewindSec 2.0 technical ransomware state."""

from abc import ABC, abstractmethod
import hashlib
import json
import re

SANDBOX_PORT_VERSION = "rewindsec2-sandbox-port/v1"
PROJECTION_VERSION = "rewindsec2-sandbox-projection/v1"

# These are server-owned content identifiers.  Filenames are presentation
# metadata only; callers can never supply an arbitrary path.
ALLOWED_SYNTHETIC_FILES = {
    "f-headcount-model": "Headcount_Model.xlsx",
    "f-team-rota": "Team_Rota_September.xlsx",
    "f-q3-metrics": "Q3_Metrics.xlsx",
    "f-facilities": "Facilities_Contracts_2026.xlsx",
}
ALLOWED_STATES = frozenset(("normal", "unavailable", "absent"))
_SESSION_KEY = re.compile(r"^[0-9a-f]{32}$")


class SandboxError(Exception):
    """Base class for the v2 sandbox boundary."""


class SandboxConfigurationError(SandboxError):
    """An unsafe adapter configuration was refused before Docker was called."""


class SandboxOperationalError(SandboxError):
    """A bounded sandbox operation failed or returned malformed state."""


def session_sandbox_key(session_id):
    """One-way, PII-free management key; draws no simulation randomness."""
    if not isinstance(session_id, str) or not session_id:
        raise SandboxOperationalError("a persisted session id is required")
    material = ("rewindsec2-sandbox\0" + session_id).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


class SyntheticFileState(object):
    """One validated allowlisted synthetic file projection."""

    __slots__ = ("file_id", "state")

    def __init__(self, file_id, state):
        if file_id not in ALLOWED_SYNTHETIC_FILES:
            raise SandboxOperationalError("unknown synthetic file identifier")
        if state not in ALLOWED_STATES:
            raise SandboxOperationalError("unsupported synthetic file state")
        self.file_id = file_id
        self.state = state

    def to_state(self):
        return {"file_id": self.file_id, "state": self.state}


class SandboxProjection(object):
    """Canonical desired technical state for exactly one persisted session."""

    __slots__ = ("session_key", "files")

    def __init__(self, session_key, files):
        if not isinstance(session_key, str) or not _SESSION_KEY.fullmatch(session_key):
            raise SandboxOperationalError("invalid sandbox session key")
        rows = tuple(files)
        ids = [row.file_id for row in rows]
        if ids != sorted(ALLOWED_SYNTHETIC_FILES):
            raise SandboxOperationalError(
                "projection must contain every allowlisted file exactly once")
        self.session_key = session_key
        self.files = rows

    def to_state(self):
        return {
            "version": PROJECTION_VERSION,
            "session_key": self.session_key,
            "files": [row.to_state() for row in self.files],
        }

    @property
    def digest(self):
        encoded = json.dumps(self.to_state(), sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class SandboxPort(ABC):
    """No generic exec, path, mount, network or container-handle operation."""

    @abstractmethod
    def reconcile(self, projection):
        """Create/rebuild and make technical state match ``projection``."""
        raise NotImplementedError

    @abstractmethod
    def inspect(self, session_key):
        """Return canonical technical state for one derived session key."""
        raise NotImplementedError

    @abstractmethod
    def destroy(self, session_key):
        """Destroy only the strictly labelled context for ``session_key``."""
        raise NotImplementedError
