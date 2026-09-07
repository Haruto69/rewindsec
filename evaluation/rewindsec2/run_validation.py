"""Repeatable deterministic, resume, isolation and performance validation.

This is engineering evidence.  A dirty-tree run labels itself preliminary; a
later clean final-commit run uses the same code and parameters unchanged.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import importlib.metadata
import json
import math
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import tempfile
import time

import sqlalchemy as sa

from evaluation.rewindsec2 import HARNESS_VERSION, RESULT_SCHEMA_VERSION
from rewindsec.core.rng import SeededRandom
from rewindsec.core.scheduler import EventScheduler
from rewindsec.core.events import EventSpec
from rewindsec.persistence.sqlalchemy_adapter import SqlAlchemySessionRepository
from rewindsec.domain.session import SimulationSession
from rewindsec.sandbox.coordinator import SandboxCoordinator
from rewindsec.sandbox.ports import (ALLOWED_SYNTHETIC_FILES,
                                     SandboxOperationalError, SandboxPort,
                                     SyntheticFileState)
from rewindsec.workstation import bootstrap, worldops
from rewindsec.workstation.actions import parse_action_request
from rewindsec.workstation.errors import NoActiveSessionError
from rewindsec.workstation.seeds import FixedSeedSource
from rewindsec.workstation.service import WorkstationService
from rewindsec.workstation.projection import (MAX_RENDERED_MESSAGE_ENTRIES,
                                              MAX_RENDERED_NOTIFICATIONS)

ROOT = pathlib.Path(__file__).resolve().parents[2]
BASE_COMMIT = "e0ded68944d9e206631f5e99762dc52793a99736"
DEFAULT_SEEDS = (7, 4242, 20260907)
DEFAULT_CASES = (
    ("phishing", "practice"), ("ransomware", "simulation"),
    ("mixed", "assessment"),
)


def _command(args, timeout=30):
    try:
        result = subprocess.run(args, cwd=str(ROOT), capture_output=True,
                                text=False, timeout=timeout, shell=False)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None, ""
    raw = result.stdout or b""
    if isinstance(raw, bytes):
        # Git diffs can contain arbitrary working-tree bytes. Decode without
        # losing them, and round-trip the same bytes into the fingerprint
        # below. This also avoids Windows' locale-dependent cp1252 reader.
        output = raw.decode("utf-8", errors="surrogateescape")
    else:
        output = raw
    return result.returncode, output.strip()


def _git_context():
    _, head = _command(["git", "rev-parse", "HEAD"])
    code, status = _command(["git", "status", "--short"])
    dirty = bool(status) if code == 0 else None
    fingerprint = hashlib.sha256()
    code, diff = _command(["git", "diff", "--binary", "HEAD"], timeout=60)
    if code == 0:
        fingerprint.update(diff.encode("utf-8", errors="surrogateescape"))
    code, untracked = _command(
        ["git", "ls-files", "--others", "--exclude-standard"])
    if code == 0:
        for raw in sorted(untracked.splitlines()):
            path = raw.replace("\\", "/")
            if path == "skills-lock.json" or path.startswith(".agents/"):
                continue
            candidate = ROOT / raw
            if candidate.is_file():
                fingerprint.update(path.encode("utf-8") + b"\0")
                fingerprint.update(candidate.read_bytes())
    return {"head": head or None, "starting_base_commit": BASE_COMMIT,
            "working_tree_dirty": dirty,
            "classification": ("engineering_precommit" if dirty
                               else "clean_revision_candidate"),
            "source_tree_fingerprint_sha256": fingerprint.hexdigest()}


def _environment():
    _, docker_client = _command(["docker", "version", "--format",
                                 "{{.Client.Version}}"])
    server_code, docker_server = _command(
        ["docker", "version", "--format", "{{.Server.Version}}"])
    return {
        "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "os": platform.platform(), "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "flask": _version("Flask"), "sqlalchemy": _version("SQLAlchemy"),
        "cpu_logical_count": os.cpu_count(),
        "processor": platform.processor() or None,
        "docker_client": docker_client or None,
        "docker_daemon_available": server_code == 0,
        "docker_server": docker_server or None,
    }


def _version(name):
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _service(uri, seed, session_id):
    engine = sa.create_engine(uri)
    repository = SqlAlchemySessionRepository(engine)
    repository.create_schema()
    return (WorkstationService(repository, seed_source=FixedSeedSource(seed),
                               id_source=lambda: session_id), repository)


def _act_mark_read(service, session_id, learner):
    revision = service.revision(session_id, learner)
    action = parse_action_request({"action": "notifications.mark_read",
                                   "revision": revision})
    service.apply_action(session_id, action, learner)


def _drive(uri, seed, focus, mode, resume_at=None, suffix="a"):
    sid = "ws-validation-%s-%s-%s" % (seed, focus, suffix)
    learner = "validation-learner"
    service, repository = _service(uri, seed, sid)
    service.start_session(learner, focus, mode,
                          attempt_bound=(mode == "assessment"))
    if resume_at == "after_start":
        repository._engine.dispose()
        service, repository = _service(uri, seed, sid)
    _act_mark_read(service, sid, learner)
    if resume_at == "after_action":
        repository._engine.dispose()
        service, repository = _service(uri, seed, sid)
    service.dev_advance(sid, 4000, learner)
    if resume_at == "after_advance_4000ms":
        repository._engine.dispose()
        service, repository = _service(uri, seed, sid)
    service.dev_advance(sid, 9000, learner)
    _act_mark_read(service, sid, learner)
    state = service.require_owned(sid, learner).capture_state()
    repository._engine.dispose()
    return state


def validate_repeatability(workdir):
    cases = []
    for seed in DEFAULT_SEEDS:
        for focus, mode in DEFAULT_CASES:
            left = workdir / ("repeat-left-%s-%s.db" % (seed, focus))
            right = workdir / ("repeat-right-%s-%s.db" % (seed, focus))
            a = _drive("sqlite:///" + left.as_posix(), seed, focus, mode,
                       suffix="same")
            b = _drive("sqlite:///" + right.as_posix(), seed, focus, mode,
                       suffix="same")
            cases.append({"seed": seed, "focus": focus, "mode": mode,
                          "identical": a == b,
                          "digest": _digest(a)})
    return {"case_count": len(cases), "cases": cases,
            "failures": sum(not row["identical"] for row in cases)}


def validate_resume(workdir):
    cases = []
    for seed, (focus, mode) in zip(DEFAULT_SEEDS, DEFAULT_CASES):
        left = workdir / ("resume-control-%s.db" % seed)
        right = workdir / ("resume-rebuilt-%s.db" % seed)
        uninterrupted = _drive("sqlite:///" + left.as_posix(), seed, focus,
                               mode, suffix="same")
        for point in ("after_start", "after_action", "after_advance_4000ms"):
            resumed_path = workdir / ("resume-%s-%s.db" % (seed, point))
            rebuilt = _drive("sqlite:///" + resumed_path.as_posix(), seed,
                             focus, mode, resume_at=point, suffix="same")
            cases.append({"seed": seed, "focus": focus, "mode": mode,
                          "identical": uninterrupted == rebuilt,
                          "digest": _digest(rebuilt), "resume_point": point})
    return {"case_count": len(cases), "cases": cases,
            "failures": sum(not row["identical"] for row in cases)}


def validate_rng_streams():
    rows = []
    for seed in DEFAULT_SEEDS:
        control = SeededRandom(seed)
        changed = SeededRandom(seed)
        for _ in range(250):
            changed.stream("content_variation").random()
        names = ("threat_selection", "timing", "consequence")
        same = all([control.stream(name).random() for _ in range(20)] ==
                   [changed.stream(name).random() for _ in range(20)]
                   for name in names)
        rows.append({"seed": seed, "content_variation_draws": 250,
                     "protected_stream_draws_each": 20, "identical": same})
    return {"case_count": len(rows), "cases": rows,
            "failures": sum(not row["identical"] for row in rows)}


def validate_scheduler():
    scheduler = EventScheduler("validation-equal-time")
    expected = []
    for index in range(300):
        priority = (index % 7) - 3
        item = scheduler.schedule(EventSpec("validation.event",
                                  payload={"index": index}), 5000, priority)
        expected.append((priority, index, item.schedule_id))
    observed = [(entry.priority, entry.insertion_seq, entry.schedule_id)
                for entry in scheduler.due(5000)]
    expected.sort(key=lambda row: (row[0], row[1]))
    return {"event_count": 300, "ordering": "fire_at_ms,priority,insertion_seq",
            "identical": observed == expected,
            "failures": 0 if observed == expected else 1}


class _ProjectionPort(SandboxPort):
    def __init__(self):
        self.calls = []
    def reconcile(self, projection):
        self.calls.append(("reconcile", projection.session_key))
        return {"projection_digest": projection.digest}
    def inspect(self, session_key):
        self.calls.append(("inspect", session_key))
        return {"session_key": session_key}
    def destroy(self, session_key):
        self.calls.append(("destroy", session_key))
        return {"state": "absent"}


def validate_docker_lifecycle_independence():
    session = SimulationSession.create("ws-docker-independence", "learner",
                                       "ransomware", "simulation", 4242)
    bootstrap.seed_session(session)
    worldops.open_incident(session, "inc-files", "File incident", "Synthetic")
    worldops.set_file_state(session, "f-headcount-model", "unavailable")
    before = session.capture_state()
    port = _ProjectionPort()
    coordinator = SandboxCoordinator(port)
    first = coordinator.reconcile(session)
    second = coordinator.reconcile(session)
    coordinator.destroy(session.session_id)
    unchanged = before == session.capture_state()
    return {"reconcile_count": 2, "destroy_count": 1,
            "operational_statuses": [first["status"], second["status"]],
            "canonical_session_unchanged": unchanged,
            "failures": 0 if unchanged and len(port.calls) == 3 else 1}


def validate_security_misuse():
    probes = ("../file", "/etc/passwd", "C:\\host\\file", "$(id)",
              "f-headcount-model;rm", "unknown")
    refused = 0
    for value in probes:
        try:
            SyntheticFileState(value, "normal")
        except SandboxOperationalError:
            refused += 1
    source = "\n".join(path.read_text(encoding="utf-8")
                       for path in (ROOT / "rewindsec" / "sandbox").glob("*.py"))
    no_shell = "shell=True" not in source
    port_surface = {name for name in SandboxPort.__dict__
                    if not name.startswith("_")}
    narrow = port_surface == {"reconcile", "inspect", "destroy"}
    failures = (len(probes) - refused) + (0 if no_shell else 1) + (0 if narrow else 1)
    return {"malicious_input_probes": len(probes), "refused": refused,
            "shell_execution_absent": no_shell, "narrow_port": sorted(port_surface),
            "failures": failures,
            "scope": "defined system security/misuse validation; not a penetration test"}


def validate_session_isolation(workdir, count=8):
    uri = "sqlite:///" + (workdir / "isolation.db").as_posix()
    engine = sa.create_engine(uri)
    repo = SqlAlchemySessionRepository(engine)
    repo.create_schema()
    ids = iter("ws-isolation-%02d" % i for i in range(count))

    class Seeds(object):
        def __init__(self): self.value = 1000
        def next_seed(self):
            self.value += 1
            return self.value

    service = WorkstationService(repo, seed_source=Seeds(),
                                 id_source=lambda: next(ids))
    sessions = []
    for i in range(count):
        learner = "isolation-learner-%02d" % i
        sid = service.start_session(learner, "mixed", "simulation")
        sessions.append((sid, learner))
    before = {sid: _digest(repo.load(sid).capture_state()) for sid, _ in sessions}
    _act_mark_read(service, sessions[0][0], sessions[0][1])
    after = {sid: _digest(repo.load(sid).capture_state()) for sid, _ in sessions}
    unchanged_others = all(before[sid] == after[sid] for sid, _ in sessions[1:])
    owner_refused = False
    try:
        service.snapshot(sessions[0][0], "foreign-learner")
    except NoActiveSessionError:
        owner_refused = True
    unique = len({sid for sid, _ in sessions}) == count
    unique_rng = len({_digest(repo.load(sid).rng.capture_state())
                      for sid, _ in sessions}) == count
    result = {"session_count": count, "distinct_ids": unique,
            "distinct_rng_states": unique_rng,
            "cross_owner_read_refused": owner_refused,
            "other_sessions_unchanged": unchanged_others,
            "failures": sum(not item for item in
                            (unique, unique_rng, owner_refused, unchanged_others))}
    engine.dispose()
    return result


def _summary(values):
    ordered = sorted(values)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return {"samples": len(ordered), "min_ms": ordered[0],
            "median_ms": statistics.median(ordered),
            "p95_ms": ordered[index], "max_ms": ordered[-1]}


def measure_performance(workdir, samples=30, concurrent_sessions=8):
    uri = "sqlite:///" + (workdir / "performance.db").as_posix()
    engine = sa.create_engine(uri)
    repo = SqlAlchemySessionRepository(engine)
    repo.create_schema()
    counter = iter("ws-perf-%05d" % i for i in range(samples + concurrent_sessions + 5))
    service = WorkstationService(repo, seed_source=FixedSeedSource(20260907),
                                 id_source=lambda: next(counter))
    create_ms, read_ms, action_ms, load_ms, finish_ms = [], [], [], [], []
    failures = 0
    for i in range(samples):
        learner = "perf-learner-%05d" % i
        started = time.perf_counter_ns()
        sid = service.start_session(learner, "mixed", "simulation")
        create_ms.append((time.perf_counter_ns() - started) / 1e6)
        started = time.perf_counter_ns()
        service.snapshot(sid, learner)
        read_ms.append((time.perf_counter_ns() - started) / 1e6)
        started = time.perf_counter_ns()
        _act_mark_read(service, sid, learner)
        action_ms.append((time.perf_counter_ns() - started) / 1e6)
        started = time.perf_counter_ns()
        repo.load(sid)
        load_ms.append((time.perf_counter_ns() - started) / 1e6)
        started = time.perf_counter_ns()
        service.end_session(sid, learner)
        finish_ms.append((time.perf_counter_ns() - started) / 1e6)
    db_bytes = (workdir / "performance.db").stat().st_size

    def create_one(i):
        local_engine = sa.create_engine(uri)
        local_repo = SqlAlchemySessionRepository(local_engine)
        local_service = WorkstationService(
            local_repo, seed_source=FixedSeedSource(9000 + i),
            id_source=lambda: "ws-concurrent-%02d" % i)
        started = time.perf_counter_ns()
        try:
            local_service.start_session("concurrent-%02d" % i, "mixed", "simulation")
            return (time.perf_counter_ns() - started) / 1e6
        finally:
            local_engine.dispose()

    concurrent_values = []
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=concurrent_sessions) as pool:
            concurrent_values = list(pool.map(create_one, range(concurrent_sessions)))
    except Exception:
        failures += 1
    result = {
        "sample_count": samples, "bounded_concurrent_sessions": concurrent_sessions,
        "failures": failures,
        "latency": {"session_create": _summary(create_ms),
                    "state_projection_read": _summary(read_ms),
                    "learner_action": _summary(action_ms),
                    "persistence_load": _summary(load_ms),
                    "scoring_finalization_and_save": _summary(finish_ms),
                    "concurrent_session_create": (_summary(concurrent_values)
                                                  if concurrent_values else None)},
        "database_bytes_after_representative_sessions": db_bytes,
        "bytes_per_completed_session_observed": db_bytes / samples,
        "docker_metrics": None,
        "limitations": [
            "Local SQLite and one development machine; not production-scale load.",
            "Latency includes Python/SQLite work on this host and is descriptive only.",
            "Docker timing is emitted by the separate containment run when available.",
            "No usability, perceived responsiveness, learning, or human-effect claim.",
        ],
    }
    engine.dispose()
    return result


def static_client_audit():
    asset_root = ROOT / "static" / "prototype"
    assets = []
    for path in sorted(asset_root.iterdir()):
        if path.is_file() and path.suffix in (".js", ".css"):
            assets.append({"path": path.relative_to(ROOT).as_posix(),
                           "bytes": path.stat().st_size})
    js = "\n".join(path.read_text(encoding="utf-8")
                   for path in asset_root.glob("*.js"))
    css = "\n".join(path.read_text(encoding="utf-8")
                    for path in asset_root.glob("*.css"))
    return {
        "audit_type": "static_implementation_check",
        "browser_profile_measured": False,
        "assets": assets, "total_js_css_bytes": sum(row["bytes"] for row in assets),
        "largest_asset": max(assets, key=lambda row: row["bytes"]) if assets else None,
        "webgl_references": js.lower().count("webgl"),
        "eventsource_present": "new window.EventSource" in js,
        "set_interval_sites": js.count("setInterval("),
        "reduced_motion_present": "prefers-reduced-motion: reduce" in css,
        "render_bounds": {"notifications": MAX_RENDERED_NOTIFICATIONS,
                          "message_entries_per_conversation":
                              MAX_RENDERED_MESSAGE_ENTRIES},
        "limitations": [
            "Static source and byte-size audit only; no browser FPS, paint, or usability measurement.",
            "The 4-second POST advances authored simulation time; SSE carries revision wakeups and avoids snapshot polling.",
        ],
    }


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")).hexdigest()


def run(samples=30, concurrent_sessions=8):
    with tempfile.TemporaryDirectory(prefix="rewindsec2-validation-") as raw:
        workdir = pathlib.Path(raw)
        validations = {
            "repeatability": validate_repeatability(workdir),
            "resume": validate_resume(workdir),
            "rng_stream_independence": validate_rng_streams(),
            "equal_time_scheduler": validate_scheduler(),
            "docker_lifecycle_independence": validate_docker_lifecycle_independence(),
            "security_misuse": validate_security_misuse(),
            "session_isolation": validate_session_isolation(
                workdir, concurrent_sessions),
        }
        performance = measure_performance(workdir, samples, concurrent_sessions)
    failures = sum(item.get("failures", 0) for item in validations.values())
    failures += performance.get("failures", 0)
    environment = _environment()
    skips = []
    if not environment["docker_daemon_available"]:
        skips.append({"area": "docker_runtime_containment",
                      "reason": "Docker daemon unavailable; run containment.py when available"})
    return {
        "schema_version": RESULT_SCHEMA_VERSION,
        "artifact_id": "rewindsec2-engineering-validation-precommit",
        "artifact_type": "engineering_validation",
        "harness_version": HARNESS_VERSION,
        "architecture_version": "RewindSec_2.0_Architecture_Specification_v1.1",
        "repository": _git_context(), "environment": environment,
        "parameters": {"seeds": list(DEFAULT_SEEDS),
                       "focus_mode_cases": [list(row) for row in DEFAULT_CASES],
                       "performance_samples": samples,
                       "bounded_concurrent_sessions": concurrent_sessions},
        "validations": validations, "performance": performance,
        "low_end_client": static_client_audit(),
        "failure_count": failures, "skips": skips,
        "passed": failures == 0,
        "limitations": [
            "Engineering/pre-commit evidence when repository.working_tree_dirty is true.",
            "Not a penetration test or production-scale load test.",
            "Technical validation provides no human-effect, usability, realism, or psychometric evidence.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--concurrent-sessions", type=int, default=8)
    parser.add_argument("--output", type=pathlib.Path)
    args = parser.parse_args(argv)
    if not 1 <= args.samples <= 10000 or not 1 <= args.concurrent_sessions <= 64:
        parser.error("sample and concurrency bounds are 1..10000 and 1..64")
    result = run(args.samples, args.concurrent_sessions)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
