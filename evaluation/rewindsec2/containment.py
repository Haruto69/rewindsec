"""Actual-runtime containment verification for the RewindSec 2.0 target.

Harmless probes only.  A missing daemon/image is a blocked result, never a
pass.  Cleanup addresses only exact, doubly-labelled v2 container names.
"""

import argparse
import datetime
import hashlib
import json
import pathlib
import subprocess
import time

from evaluation.rewindsec2 import HARNESS_VERSION
from evaluation.rewindsec2.run_validation import _environment, _git_context
from rewindsec.sandbox.docker_adapter import (CONTAINER_PREFIX,
                                              DockerSandboxAdapter,
                                              DockerSandboxConfig)
from rewindsec.sandbox.ports import (ALLOWED_SYNTHETIC_FILES,
                                     SandboxOperationalError,
                                     SandboxProjection, SyntheticFileState)

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "rewindsec2-containment-result/v1"


def projection(key, unavailable=()):
    return SandboxProjection(key, [
        SyntheticFileState(file_id,
                           "unavailable" if file_id in unavailable else "normal")
        for file_id in sorted(ALLOWED_SYNTHETIC_FILES)
    ])


def _run(args, input_text=None, timeout=45):
    return subprocess.run(args, input=input_text, cwd=str(ROOT),
                          capture_output=True, text=True, shell=False,
                          timeout=timeout)


def _check(rows, name, passed=None, detail=None, unsupported=False):
    status = "unsupported" if unsupported else ("pass" if passed else "fail")
    rows.append({"check": name, "status": status, "detail": detail})


def _inspect(name):
    result = _run(["docker", "inspect", "--format", "{{json .}}", "--", name])
    if result.returncode != 0:
        raise RuntimeError("docker inspect failed")
    return json.loads(result.stdout)


def run(image="rewindsec2-ransomware-sandbox:2.0"):
    config = DockerSandboxConfig(image=image)
    adapter = DockerSandboxAdapter(config)
    rows, timings, created = [], {}, []
    result = {
        "schema_version": SCHEMA_VERSION,
        "artifact_id": "rewindsec2-docker-containment-precommit",
        "artifact_type": "docker_runtime_containment",
        "harness_version": HARNESS_VERSION,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "image_reference": image, "checks": rows, "timings_ms": timings,
        "repository": _git_context(), "environment": _environment(),
        "parameters": {"sessions": 2, "synthetic_files": 4,
                       "harmless_network_probe": "1.1.1.1:53",
                       "host_sentinel_path": "/host-sentinel-rewindsec"},
        "skips": [],
        "blocked": False, "blocker": None,
        "limitations": ["One local Docker host; no cross-host claim."],
    }
    if not adapter.is_available():
        result.update(blocked=True, blocker="Docker daemon unavailable")
        return result
    if not adapter.image_available():
        result.update(blocked=True, blocker="RewindSec 2.0 image missing")
        return result

    key_a = hashlib.sha256(b"containment-a").hexdigest()[:32]
    key_b = hashlib.sha256(b"containment-b").hexdigest()[:32]
    name_a, name_b = CONTAINER_PREFIX + key_a, CONTAINER_PREFIX + key_b
    desired_a = projection(key_a, ("f-headcount-model",))
    desired_b = projection(key_b)
    try:
        started = time.perf_counter_ns()
        observed_a = adapter.reconcile(desired_a)
        timings["startup_and_reconcile_a"] = (time.perf_counter_ns() - started) / 1e6
        created.append(key_a)
        started = time.perf_counter_ns()
        observed_b = adapter.reconcile(desired_b)
        timings["startup_and_reconcile_b"] = (time.perf_counter_ns() - started) / 1e6
        created.append(key_b)

        doc = _inspect(name_a)
        host, container = doc.get("HostConfig") or {}, doc.get("Config") or {}
        network = host.get("NetworkMode")
        _check(rows, "non_root_numeric_user", container.get("User") == "10001:10001",
               container.get("User"))
        _check(rows, "read_only_root", host.get("ReadonlyRootfs") is True)
        _check(rows, "capabilities_dropped", host.get("CapDrop") == ["ALL"],
               str(host.get("CapDrop")))
        security = host.get("SecurityOpt") or []
        _check(rows, "no_new_privileges",
               any("no-new-privileges" in value for value in security), str(security))
        _check(rows, "network_none", network == "none", str(network))
        _check(rows, "no_exposed_ports", not container.get("ExposedPorts") and
               not (host.get("PortBindings") or {}))
        _check(rows, "no_bind_mounts", not (host.get("Binds") or []) and
               not (doc.get("Mounts") or []), str(doc.get("Mounts") or []))
        _check(rows, "no_docker_socket", not any(
            "docker.sock" in json.dumps(value) for value in
            (host.get("Binds") or [], doc.get("Mounts") or [])))
        tmpfs = host.get("Tmpfs") or {}
        workspace_flags = str(tmpfs.get("/workspace", ""))
        _check(rows, "bounded_hardened_tmpfs", "/workspace" in tmpfs and all(
            flag in workspace_flags for flag in ("noexec", "nosuid", "nodev", "size=8m")),
            workspace_flags)
        _check(rows, "memory_bound", host.get("Memory") == 64 * 1024 * 1024,
               str(host.get("Memory")))
        _check(rows, "pid_bound", host.get("PidsLimit") == 32,
               str(host.get("PidsLimit")))
        _check(rows, "cpu_bound", host.get("NanoCpus") == 500000000,
               str(host.get("NanoCpus")))
        _check(rows, "not_privileged", host.get("Privileged") is False)
        _check(rows, "projection_exact", observed_a.get("projection_digest") ==
               desired_a.digest)

        write_probe = _run(["docker", "exec", "--", name_a, "python", "-c",
                            "open('/opt/rewindsec2/forbidden','w').write('x')"])
        _check(rows, "write_outside_workspace_fails", write_probe.returncode != 0)

        network_probe = _run([
            "docker", "exec", "--", name_a, "python", "-c",
            "import socket; socket.create_connection(('1.1.1.1',53),1)"])
        _check(rows, "outbound_network_fails", network_probe.returncode != 0)

        host_probe = _run(["docker", "exec", "--", name_a, "python", "-c",
                           "import os,sys;sys.exit(0 if not os.path.exists('/host-sentinel-rewindsec') else 9)"])
        _check(rows, "host_sentinel_inaccessible", host_probe.returncode == 0)

        malicious = desired_a.to_state()
        malicious["files"][0]["file_id"] = "../../host-sentinel-rewindsec"
        traversal = _run([
            "docker", "exec", "--interactive", "--", name_a, "python",
            "/opt/rewindsec2/runner.py", "reconcile"],
            input_text=json.dumps(malicious))
        _check(rows, "path_traversal_rejected", traversal.returncode != 0)

        state_a, state_b = adapter.inspect(key_a), adapter.inspect(key_b)
        files_a = {row["file_id"]: row["state"] for row in state_a["files"]}
        files_b = {row["file_id"]: row["state"] for row in state_b["files"]}
        _check(rows, "concurrent_session_isolation",
               files_a["f-headcount-model"] == "unavailable" and
               files_b["f-headcount-model"] == "normal")
        _check(rows, "distinct_contexts", key_a != key_b and name_a != name_b)

        stats = _run(["docker", "stats", "--no-stream", "--format",
                      "{{json .}}", name_a, name_b])
        if stats.returncode == 0:
            try:
                result["container_resource_snapshot"] = [
                    json.loads(line) for line in stats.stdout.splitlines() if line.strip()]
            except ValueError:
                _check(rows, "container_resource_snapshot", False,
                       "docker stats returned malformed JSON")
        else:
            _check(rows, "container_resource_snapshot", unsupported=True,
                   detail="docker stats unavailable on this host")

        recovered_a = adapter.reconcile(projection(key_a))
        recovered_files = {row["file_id"]: row["state"]
                           for row in adapter.inspect(key_a)["files"]}
        _check(rows, "recovery_reconciliation",
               recovered_a.get("projection_digest") == projection(key_a).digest
               and recovered_files["f-headcount-model"] == "normal")
        # Put A back in its impacted factual state before the restart probe.
        adapter.reconcile(desired_a)

        started = time.perf_counter_ns()
        adapter.destroy(key_a)
        timings["cleanup_a"] = (time.perf_counter_ns() - started) / 1e6
        created.remove(key_a)
        _check(rows, "one_cleanup_preserves_other",
               adapter.inspect(key_b).get("state") != "absent")

        started = time.perf_counter_ns()
        rebuilt_a = adapter.reconcile(desired_a)
        timings["restart_reconcile_a"] = (time.perf_counter_ns() - started) / 1e6
        created.append(key_a)
        _check(rows, "restart_reconciliation",
               rebuilt_a.get("projection_digest") == desired_a.digest)
        _check(rows, "restart_does_not_crosswire",
               adapter.inspect(key_b).get("projection_digest") == desired_b.digest)

        image_doc = _run(["docker", "image", "inspect", "--format", "{{json .}}",
                          "--", image])
        if image_doc.returncode == 0:
            image_state = json.loads(image_doc.stdout)
            result["image_id"] = image_state.get("Id")
            result["image_repo_digests"] = image_state.get("RepoDigests") or []
    except (SandboxOperationalError, RuntimeError, ValueError,
            subprocess.TimeoutExpired) as exc:
        _check(rows, "harness_execution", False, type(exc).__name__ + ": " + str(exc)[:160])
    finally:
        for key in list(created):
            try:
                adapter.destroy(key)
            except SandboxOperationalError as exc:
                _check(rows, "final_cleanup_" + key[:8], False, str(exc)[:160])
    result["pass_count"] = sum(row["status"] == "pass" for row in rows)
    result["fail_count"] = sum(row["status"] == "fail" for row in rows)
    result["unsupported_count"] = sum(row["status"] == "unsupported" for row in rows)
    result["passed"] = not result["blocked"] and result["fail_count"] == 0
    return result


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="rewindsec2-ransomware-sandbox:2.0")
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)
    result = run(args.image)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 2 if result["blocked"] else (0 if result["passed"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
