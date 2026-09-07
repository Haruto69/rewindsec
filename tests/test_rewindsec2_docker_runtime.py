"""Actual-container checks for the separately versioned v2 sandbox image."""

import hashlib
import json
import subprocess

import pytest

from rewindsec.sandbox.docker_adapter import (CONTAINER_PREFIX,
                                              DockerSandboxAdapter,
                                              DockerSandboxConfig)
from rewindsec.sandbox.ports import (ALLOWED_SYNTHETIC_FILES,
                                     SandboxProjection, SyntheticFileState)


def _projection(key, unavailable=()):
    return SandboxProjection(key, [
        SyntheticFileState(file_id,
                           "unavailable" if file_id in unavailable else "normal")
        for file_id in sorted(ALLOWED_SYNTHETIC_FILES)
    ])


@pytest.fixture
def v2_docker():
    adapter = DockerSandboxAdapter(DockerSandboxConfig())
    if not adapter.is_available():
        pytest.skip("Docker daemon unavailable")
    if not adapter.image_available():
        pytest.skip("rewindsec2-ransomware-sandbox:2.0 image missing")
    keys = [hashlib.sha256(value).hexdigest()[:32]
            for value in (b"pytest-v2-a", b"pytest-v2-b")]
    try:
        yield adapter, keys
    finally:
        for key in keys:
            adapter.destroy(key)


def test_actual_container_controls_projection_recovery_and_isolation(v2_docker):
    adapter, (key_a, key_b) = v2_docker
    impacted = _projection(key_a, ("f-headcount-model",))
    normal = _projection(key_b)
    adapter.reconcile(impacted)
    adapter.reconcile(normal)

    inspect = subprocess.run(
        ["docker", "inspect", "--format", "{{json .}}", "--",
         CONTAINER_PREFIX + key_a], capture_output=True, text=True,
        timeout=30, shell=False, check=True)
    doc = json.loads(inspect.stdout)
    host, config = doc["HostConfig"], doc["Config"]
    assert config["User"] == "10001:10001"
    assert host["ReadonlyRootfs"] is True
    assert host["NetworkMode"] == "none"
    assert host["CapDrop"] == ["ALL"]
    assert host["Privileged"] is False
    assert host["Memory"] == 64 * 1024 * 1024
    assert host["PidsLimit"] == 32
    assert host["NanoCpus"] == 500000000
    assert not host.get("Binds") and not config.get("ExposedPorts")

    a = {row["file_id"]: row["state"] for row in adapter.inspect(key_a)["files"]}
    b = {row["file_id"]: row["state"] for row in adapter.inspect(key_b)["files"]}
    assert a["f-headcount-model"] == "unavailable"
    assert b["f-headcount-model"] == "normal"

    recovered = _projection(key_a)
    assert adapter.reconcile(recovered)["projection_digest"] == recovered.digest
    assert {row["file_id"]: row["state"]
            for row in adapter.inspect(key_a)["files"]}["f-headcount-model"] == "normal"

    adapter.destroy(key_a)
    assert adapter.inspect(key_a)["state"] == "absent"
    assert adapter.inspect(key_b)["projection_digest"] == normal.digest
