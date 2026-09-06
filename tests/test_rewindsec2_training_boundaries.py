"""Static guardrails on the Batch 3 training engine.

Batch 1 drew a line around the deterministic core and Batch 2 around the
workstation application layer, both by AST inspection rather than by grep,
because a guarantee about what a package cannot do is worth exactly what the
import graph makes true. Batch 3 adds a layer between them, so it gets its own
line, for the same reason and by the same method.

What is asserted here:

* the training engine imports no Flask, no SQLAlchemy, no Jinja and no
  template or request vocabulary. It is pure Python and can be driven from a
  bare interpreter;
* it imports no v1 module -- the historical study, learning, scenario and
  evaluation code stays historical;
* it cannot reach a network or a subprocess. There is no threat feed, no
  dataset fetch, no live URL and no payload, and no code path that could
  become one;
* it touches no host filesystem. Ransomware in this product is rows in a
  synthetic world; a single ``open()`` or ``os.remove`` in this package would
  make that claim false;
* it uses no ambient randomness -- no ``random``, no ``secrets``, no ``uuid``,
  no ``hash()`` of anything that decides an outcome. Every draw comes from the
  session's named seeded streams;
* it reads no wall clock. Not ``time``, not ``datetime``, not a measured
  interval. Simulation decisions are a function of the session's SimClock and
  nothing else, and there is no exemption in this package at all;
* the dependency direction holds: the engine depends on the domain and the
  core, the workstation depends on the engine, and neither the domain nor the
  core has learned anything about the engine.
"""

import ast
import io
import os
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TRAINING_ROOT = REPO_ROOT / "rewindsec" / "training"

FORBIDDEN_FRAMEWORK_IMPORTS = frozenset({
    "flask", "flask_sqlalchemy", "sqlalchemy", "werkzeug", "jinja2",
    "app", "manage", "security", "telemetry_ledger", "sandbox",
})

#: v1. Note ``training`` in this set: there is a *historical* top-level
#: ``training/`` package in this repository from v1, and the fact that the new
#: engine happens to live at ``rewindsec/training/`` must not become a way for
#: one to reach the other. Absolute imports inside this package are all
#: ``rewindsec.training.*``; a bare ``import training`` would be v1.
FORBIDDEN_V1_IMPORTS = frozenset({
    "study", "study_service", "study_routes",
    "learning", "learning_service", "learning_routes",
    "scenario_adapters", "evaluation",
    "training", "training_service", "training_routes", "training_flow",
    "sandbox_routes",
})

FORBIDDEN_IO_IMPORTS = frozenset({
    "requests", "urllib", "urllib2", "urllib3", "httpx", "http",
    "socket", "socketserver", "ftplib", "smtplib", "poplib", "imaplib",
    "telnetlib", "subprocess", "asyncio", "ssl", "docker", "webbrowser",
    "xmlrpc", "ctypes", "multiprocessing", "shutil", "pathlib", "tempfile",
    "glob", "os",
})

FORBIDDEN_NONDETERMINISM_IMPORTS = frozenset({"random", "secrets", "uuid"})

#: No exemption. The engine mints no id and no seed -- the service does both,
#: before the engine exists -- so there is nothing here that needs one.
NONDETERMINISM_EXEMPT = {}

FORBIDDEN_CLOCK_IMPORTS = frozenset({"time", "datetime", "calendar"})


def modules(root):
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


TRAINING_MODULES = modules(TRAINING_ROOT)


def _module_id(path):
    return str(pathlib.Path(path).relative_to(REPO_ROOT)).replace(os.sep, "/")


def _parse(path):
    return ast.parse(io.open(path, encoding="utf-8").read(), filename=str(path))


def _imported_top_level_names(path):
    names = set()
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def _imported_dotted_names(path):
    names = set()
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module)
    return names


# ===========================================================================
# The layer exists and is shaped as documented
# ===========================================================================

def test_the_training_layer_exists():
    assert TRAINING_ROOT.is_dir(), "rewindsec/training/ is missing"
    names = {p.name for p in TRAINING_MODULES}
    assert {"__init__.py", "candidate.py", "catalog.py", "delivery.py",
            "eligibility.py", "engine.py", "policy.py", "progression.py",
            "selection.py", "state.py"} <= names, sorted(names)


def test_every_threat_family_has_a_module():
    families = TRAINING_ROOT / "families"
    assert families.is_dir()
    names = {p.name for p in families.glob("*.py")}
    assert {"__init__.py", "background.py", "bec.py", "mfa.py", "phishing.py",
            "ransomware.py"} <= names, sorted(names)


# ===========================================================================
# What the training layer may not import
# ===========================================================================

@pytest.mark.parametrize("module_path", TRAINING_MODULES, ids=_module_id)
def test_training_module_imports_no_framework(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_FRAMEWORK_IMPORTS
    assert not forbidden, (
        "%s imports %s. The training engine is pure Python: it must be "
        "drivable from a bare interpreter with no app context, no request and "
        "no database." % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", TRAINING_MODULES, ids=_module_id)
def test_training_module_imports_no_v1_code(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_V1_IMPORTS
    assert not forbidden, (
        "%s imports v1 module(s) %s; see PROVENANCE.md. Living at "
        "rewindsec/training/ is not a licence to reach the historical "
        "training/ package." % (_module_id(module_path),
                                ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", TRAINING_MODULES, ids=_module_id)
def test_training_module_cannot_reach_the_network_a_subprocess_or_a_disk(
        module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_IO_IMPORTS
    assert not forbidden, (
        "%s imports %s. There is no threat feed, no dataset fetch, no payload "
        "and no file on this machine that the simulation may touch: ransomware "
        "here is rows in a synthetic world, and that claim has to be true at "
        "the level of the import graph."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", TRAINING_MODULES, ids=_module_id)
def test_training_module_uses_no_ambient_randomness(module_path):
    allowed = NONDETERMINISM_EXEMPT.get(pathlib.Path(module_path).name, set())
    forbidden = (_imported_top_level_names(module_path)
                 & FORBIDDEN_NONDETERMINISM_IMPORTS) - allowed
    assert not forbidden, (
        "%s imports %s. Every draw the engine makes comes from a named stream "
        "of the session's SeededRandom, and there is no exemption in this "
        "package." % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", TRAINING_MODULES, ids=_module_id)
def test_training_module_uses_no_ambient_wall_clock(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_CLOCK_IMPORTS
    assert not forbidden, (
        "%s imports %s. Whether an event happens must depend on simulation "
        "time and never on real time: waiting an hour with the tab open must "
        "do exactly nothing." % (_module_id(module_path),
                                 ", ".join(sorted(forbidden))))


def test_no_training_module_reads_a_real_clock_or_touches_a_file():
    """Structural, and stronger than the import check.

    An import test can be walked around by reaching a clock or a file through
    something already imported, so the source is read as well.
    """
    banned_calls = re.compile(
        r"\b(?:time|datetime|calendar)\.\w+"
        r"|\bopen\s*\("
        r"|\bos\.(?:remove|unlink|rename|mkdir|makedirs|listdir|walk|system)"
        r"|\bshutil\.\w+")
    for module_path in TRAINING_MODULES:
        source = io.open(module_path, encoding="utf-8").read()
        # Docstrings legitimately discuss these words; only *calls* matter, and
        # the pattern above matches call syntax rather than prose.
        uses = banned_calls.findall(source)
        assert not uses, (_module_id(module_path), uses)


def test_no_training_module_hashes_its_way_to_a_decision():
    """``hash()`` is salted per process. A decision made with it is not a decision.

    ``PYTHONHASHSEED`` differs between runs, so anything derived from
    ``hash()`` would replay differently on the next process -- exactly the
    failure the seeded streams exist to prevent.
    """
    for module_path in TRAINING_MODULES:
        for node in ast.walk(_parse(module_path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "hash", _module_id(module_path)


def test_training_module_does_not_import_dynamically():
    for module_path in TRAINING_MODULES:
        assert "importlib" not in _imported_top_level_names(module_path), \
            _module_id(module_path)
        for node in ast.walk(_parse(module_path)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "__import__", _module_id(module_path)


def test_no_training_module_contains_an_absolute_external_url():
    pattern = re.compile(r"https?://([A-Za-z0-9.\-]+)")
    allowed_suffixes = (".example", ".invalid", ".test", ".localhost")
    for path in TRAINING_MODULES:
        text = io.open(path, encoding="utf-8").read()
        for host in pattern.findall(text):
            assert host.lower().endswith(allowed_suffixes), (
                _module_id(path), host)


# ===========================================================================
# Dependency direction
# ===========================================================================

def test_the_domain_and_core_know_nothing_about_the_training_engine():
    """Dependencies point one way, and Batch 3 did not turn one around."""
    for package in ("domain", "core", "persistence"):
        for path in modules(REPO_ROOT / "rewindsec" / package):
            for name in _imported_dotted_names(path):
                assert not name.startswith("rewindsec.training"), (
                    _module_id(path), name)


def test_the_training_engine_depends_on_the_domain_not_on_a_repository():
    """It reads a session aggregate. It has never heard of storage."""
    for path in TRAINING_MODULES:
        for name in _imported_dotted_names(path):
            assert not name.startswith("rewindsec.persistence"), (
                _module_id(path), name)
            assert not name.startswith("rewindsec.prototype"), (
                _module_id(path), name)


def test_the_http_adapter_does_not_reach_past_the_service_into_the_engine():
    """A route may not select an event. It asks the service; the service asks
    the engine."""
    for path in modules(REPO_ROOT / "rewindsec" / "prototype"):
        for name in _imported_dotted_names(path):
            assert not name.startswith("rewindsec.training"), (
                _module_id(path), name)


# ===========================================================================
# The engine really is drivable on its own
# ===========================================================================

STANDALONE_SCRIPT = '''
import sys
sys.path.insert(0, {repo!r})

from rewindsec.domain.enums import Focus, Mode
from rewindsec.domain.session import SimulationSession
from rewindsec.training import engine
from rewindsec.workstation import bootstrap

session = SimulationSession.create(
    session_id="ws-standalone", learner_ref="learner-standalone",
    focus=Focus.PHISHING, mode=Mode.SIMULATION, root_seed=31337)
start = bootstrap.seed_session(session)
engine.start(session, cause_event_id=start.event_id)

# Run a hundred pulses with no repository, no service and no HTTP anywhere.
fired = 0
for _ in range(100):
    entry = engine.pending_evaluation(session)
    assert entry is not None
    for event in session.advance_time(entry.fire_at_ms - session.now_ms):
        if event.type == engine.EVALUATION_EVENT_TYPE:
            engine.evaluate(session, event)
            fired += 1
assert fired == 100, fired
assert engine.engine_summary(session)["step"] == 100
assert session.capture_state()

WATCHED = {{"flask", "werkzeug", "jinja2", "sqlalchemy", "study", "learning",
            "scenario_adapters", "evaluation", "sandbox", "requests",
            "urllib", "httpx", "socket", "subprocess", "docker", "ssl",
            "asyncio"}}
print(repr(sorted(m for m in sys.modules if m.split(".")[0] in WATCHED)))
'''


def test_the_engine_runs_a_hundred_pulses_with_nothing_else_loaded():
    """A clean subprocess drives the engine end to end.

    Two things at once. It catches a dependency that arrives through a package
    ``__init__`` rather than a direct import -- the failure the AST checks
    above cannot see -- and it is the proof that a hundred evaluation pulses
    really do terminate, really do move simulation time forward every time,
    and really do need nothing but Python.
    """
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-c", STANDALONE_SCRIPT.format(repo=str(REPO_ROOT))],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=180)
    assert completed.returncode == 0, completed.stderr
    loaded = ast.literal_eval(completed.stdout.strip())
    assert loaded == [], "driving the engine dragged in %s" % loaded
