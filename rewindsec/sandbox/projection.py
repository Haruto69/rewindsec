"""Pure world-to-sandbox projection.  Docker is intentionally absent."""

from rewindsec.workstation.bootstrap import NS_FILES, NS_INCIDENTS

from .ports import (ALLOWED_SYNTHETIC_FILES, SandboxProjection,
                    SyntheticFileState, session_sandbox_key)


def projection_for(session):
    """Desired state, or ``None`` until ransomware technical state is needed."""
    files = session.world.get_component(NS_FILES)
    incident = session.world.get(NS_INCIDENTS, "inc-files")
    affected = any(
        (files.get(file_id) or {}).get("state") == "unavailable"
        for file_id in ALLOWED_SYNTHETIC_FILES)
    if incident is None and not affected:
        return None

    rows = []
    for file_id in sorted(ALLOWED_SYNTHETIC_FILES):
        state = files.get(file_id)
        if state is None or state.get("deleted"):
            technical = "absent"
        elif state.get("state") == "unavailable":
            technical = "unavailable"
        else:
            technical = "normal"
        rows.append(SyntheticFileState(file_id, technical))
    return SandboxProjection(session_sandbox_key(session.session_id), rows)
