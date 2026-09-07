"""Batch 6: typed sandbox boundary, hardening, and persistence ordering."""

import ast
from dataclasses import replace
import json
import pathlib

import pytest

from rewindsec.domain.session import SimulationSession
from rewindsec.sandbox.coordinator import SandboxCoordinator
from rewindsec.sandbox.docker_adapter import DockerSandboxConfig
from rewindsec.sandbox.ports import (ALLOWED_SYNTHETIC_FILES,
                                     SandboxConfigurationError,
                                     SandboxOperationalError, SandboxPort,
                                     SandboxProjection, SyntheticFileState,
                                     session_sandbox_key)
from rewindsec.sandbox.projection import projection_for
from rewindsec.workstation import bootstrap, worldops


class RecordingPort(SandboxPort):
    def __init__(self, fail=False, mismatch=False):
        self.fail = fail
        self.mismatch = mismatch
        self.calls = []

    def reconcile(self, projection):
        self.calls.append(("reconcile", projection))
        if self.fail:
            raise SandboxOperationalError("daemon detail that stays internal")
        return {"projection_digest": ("bad" if self.mismatch else projection.digest)}

    def inspect(self, session_key):
        self.calls.append(("inspect", session_key))
        return {"session_key": session_key}

    def destroy(self, session_key):
        self.calls.append(("destroy", session_key))
        if self.fail:
            raise SandboxOperationalError("cleanup failed")
        return {"state": "absent"}


def _session(session_id="ws-batch6", learner="learner-a"):
    session = SimulationSession.create(session_id, learner, "ransomware",
                                       "simulation", 4242)
    bootstrap.seed_session(session)
    return session


def _desired(session_key="a" * 32, unavailable=()):
    return SandboxProjection(session_key, [
        SyntheticFileState(file_id,
                           "unavailable" if file_id in unavailable else "normal")
        for file_id in sorted(ALLOWED_SYNTHETIC_FILES)
    ])


def test_projection_is_absent_until_ransomware_state_is_factual():
    session = _session()
    assert projection_for(session) is None
    worldops.open_incident(session, "inc-files", "File incident", "Synthetic")
    desired = projection_for(session)
    assert desired.session_key == session_sandbox_key(session.session_id)
    assert all(row.state == "normal" for row in desired.files)


def test_projection_mirrors_impact_recovery_and_absence_from_world_truth():
    session = _session()
    worldops.open_incident(session, "inc-files", "File incident", "Synthetic")
    worldops.set_file_state(session, "f-headcount-model", "unavailable")
    state = {row.file_id: row.state for row in projection_for(session).files}
    assert state["f-headcount-model"] == "unavailable"

    worldops.set_file_state(session, "f-headcount-model", "normal")
    state = {row.file_id: row.state for row in projection_for(session).files}
    assert state["f-headcount-model"] == "normal"

    current = session.world.get("files", "f-team-rota")
    session.mutate_world("files", "f-team-rota", dict(current, deleted=True))
    state = {row.file_id: row.state for row in projection_for(session).files}
    assert state["f-team-rota"] == "absent"


@pytest.mark.parametrize("bad", [
    "../Headcount_Model.xlsx", "/etc/passwd", "f-unknown", "$(id)",
    "f-headcount-model;sh", "C:\\Users\\person\\file",
])
def test_arbitrary_paths_commands_and_unknown_identifiers_are_rejected(bad):
    with pytest.raises(SandboxOperationalError):
        SyntheticFileState(bad, "normal")


def test_projection_requires_exact_complete_allowlist():
    with pytest.raises(SandboxOperationalError):
        SandboxProjection("a" * 32, [SyntheticFileState(
            "f-headcount-model", "normal")])


def test_session_key_is_stable_non_pii_and_session_scoped():
    first = session_sandbox_key("learner-name@example.test/session/1")
    assert first == session_sandbox_key("learner-name@example.test/session/1")
    assert first != session_sandbox_key("learner-name@example.test/session/2")
    assert "learner" not in first and len(first) == 32


def test_coordinator_reports_failure_without_mutating_session():
    session = _session()
    worldops.open_incident(session, "inc-files", "File incident", "Synthetic")
    before = json.dumps(session.capture_state(), sort_keys=True)
    coordinator = SandboxCoordinator(RecordingPort(fail=True))
    diagnostic = coordinator.reconcile(session)
    assert diagnostic["status"] == "failed"
    assert diagnostic["operation"] == "reconcile"
    assert json.dumps(session.capture_state(), sort_keys=True) == before


def test_coordinator_refuses_to_call_a_mismatch_synchronized():
    session = _session()
    worldops.open_incident(session, "inc-files", "File incident", "Synthetic")
    diagnostic = SandboxCoordinator(RecordingPort(mismatch=True)).reconcile(session)
    assert diagnostic["status"] == "failed"


def test_config_has_every_required_containment_control():
    config = DockerSandboxConfig()
    assert config.network == "none"
    assert config.user == "10001:10001"
    assert config.read_only is True
    assert config.cap_drop == ("ALL",)
    assert config.no_new_privileges is True
    assert config.privileged is False
    assert config.mounts == ()
    assert all(flag in config.tmpfs for flag in ("noexec", "nosuid", "nodev", "size=8m"))
    assert config.memory == "64m" and config.pids == 32 and config.cpus == "0.50"


@pytest.mark.parametrize("changes", [
    {"network": "bridge"}, {"user": "0:0"}, {"read_only": False},
    {"cap_drop": ()}, {"no_new_privileges": False}, {"privileged": True},
    {"mounts": ("/host:/workspace",)}, {"tmpfs": "/workspace:rw"},
    {"memory": "4g"}, {"pids": 4096}, {"cpus": "8"},
])
def test_unsafe_or_unbounded_docker_configuration_is_refused(changes):
    with pytest.raises(SandboxConfigurationError):
        replace(DockerSandboxConfig(), **changes)


def test_sandbox_port_has_no_generic_execution_or_host_configuration_api():
    public = {name for name in SandboxPort.__dict__ if not name.startswith("_")}
    assert public == {"reconcile", "inspect", "destroy"}


def test_deterministic_domain_does_not_import_sandbox_or_docker():
    root = pathlib.Path(__file__).resolve().parents[1] / "rewindsec"
    for area in ("core", "domain", "training", "scoring"):
        for path in (root / area).rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imports.extend(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imports.append(node.module)
            assert not any(name.startswith("docker") or
                           name.startswith("rewindsec.sandbox")
                           for name in imports), str(path)
