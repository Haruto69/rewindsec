"""Post-persistence reconciliation and operational diagnostics."""

import datetime
import threading

from .ports import SandboxOperationalError, session_sandbox_key
from .projection import projection_for


class SandboxCoordinator(object):
    """Keeps Docker failure outside deterministic state while making it visible."""

    def __init__(self, port):
        self._port = port
        self._diagnostics = {}
        self._lock = threading.Lock()

    def _record(self, session_key, status, operation, detail=None, digest=None):
        row = {
            "status": status,
            "operation": operation,
            "session_key": session_key,
            "projection_digest": digest,
            # Administrative wall-clock time is diagnostic only and is never
            # persisted into, or read by, the simulation.
            "observed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        if detail:
            row["detail"] = str(detail)[:240]
        with self._lock:
            self._diagnostics[session_key] = row
        return dict(row)

    def reconcile(self, session):
        desired = projection_for(session)
        if desired is None:
            return None
        try:
            observed = self._port.reconcile(desired)
            if not isinstance(observed, dict) or observed.get("projection_digest") != desired.digest:
                raise SandboxOperationalError(
                    "sandbox returned a projection that did not match persisted state")
        except SandboxOperationalError as exc:
            return self._record(desired.session_key, "failed", "reconcile",
                                detail=exc, digest=desired.digest)
        return self._record(desired.session_key, "synchronized", "reconcile",
                            digest=desired.digest)

    def destroy(self, session_id):
        key = session_sandbox_key(session_id)
        try:
            self._port.destroy(key)
        except SandboxOperationalError as exc:
            return self._record(key, "failed", "destroy", detail=exc)
        return self._record(key, "destroyed", "destroy")

    def diagnostic(self, session_id):
        key = session_sandbox_key(session_id)
        with self._lock:
            row = self._diagnostics.get(key)
        return None if row is None else dict(row)
