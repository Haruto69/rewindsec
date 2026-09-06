"""Static guardrails on the Batch 2 workstation application layer.

Batch 1 established two boundaries and enforced them by AST inspection rather
than grep: the deterministic core imports no framework and no source of
ambient nondeterminism, and the domain imports no storage technology. Batch 2
adds a third layer between the domain and Flask, so it needs its own line
drawn, and for the same reason: the guarantees are only worth what the import
graph makes true.

What is asserted here:

* the workstation layer imports no Flask, no SQLAlchemy, no templates and no
  browser vocabulary. It raises typed errors; mapping them onto status codes
  is the adapter's job;
* it imports no v1 module -- ``study``, ``learning``, ``scenario_adapters``,
  the historical evaluation harnesses, the v1 training runtime or the old
  ransomware/phishing implementations;
* it imports nothing that could make a network request or run a subprocess,
  which is what "no live destination, ever" has to mean at the code level;
* the domain's own boundary is unchanged: nothing in Batch 2 reached into
  ``rewindsec/domain`` and added a Flask import to make wiring easier;
* simulation decisions draw from the session's seeded RNG and its SimClock,
  never from ``random`` or the wall clock. The one deliberate exception --
  minting a root seed for a brand-new session, which is infrastructure -- is
  confined to a single module and named here so it cannot spread quietly.

The dependency direction the whole batch depends on::

    Flask / prototype HTTP adapter
            v
    rewindsec.workstation
            v
    rewindsec.domain
            v
    rewindsec.persistence
"""

import ast
import io
import os
import pathlib
import re

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKSTATION_ROOT = REPO_ROOT / "rewindsec" / "workstation"
PROTOTYPE_ROOT = REPO_ROOT / "rewindsec" / "prototype"

#: Frameworks, storage technologies and presentation concerns. The application
#: layer talks in sessions and actions; a request object, a status code, a
#: template and a SQL statement all belong to the layer above or below it.
FORBIDDEN_FRAMEWORK_IMPORTS = frozenset({
    "flask", "flask_sqlalchemy", "sqlalchemy", "werkzeug", "jinja2",
    "app", "manage", "security", "telemetry_ledger", "sandbox",
})

#: v1. Same rule the rest of ``rewindsec/`` observes, and for the same reason:
#: a 2.0 module that depends on the architecture the v1 study measured makes
#: "is this a v1 or a 2.0 result?" unanswerable afterwards.
FORBIDDEN_V1_IMPORTS = frozenset({
    "study", "study_service", "study_routes",
    "learning", "learning_service", "learning_routes",
    "scenario_adapters", "evaluation",
    "training", "training_service", "training_routes", "training_flow",
    "sandbox_routes",
})

#: Anything that could reach outside this process. The learner's Browser and
#: Mail are synthetic and local; there is no scenario content anywhere that
#: comes from a network, and no code path that could fetch one.
FORBIDDEN_IO_IMPORTS = frozenset({
    "requests", "urllib", "urllib2", "urllib3", "httpx", "http",
    "socket", "socketserver", "ftplib", "smtplib", "poplib", "imaplib",
    "telnetlib", "subprocess", "asyncio", "ssl", "docker", "webbrowser",
    "xmlrpc", "ctypes", "multiprocessing",
})

#: Sources of values that differ between two runs of the same seed. The
#: workstation layer may not import these *except* where named below.
FORBIDDEN_NONDETERMINISM_IMPORTS = frozenset({"random", "secrets", "uuid"})

#: The two deliberate, documented exceptions, each confined to one module.
#:
#: ``seeds`` mints a root seed for a session that does not exist yet -- the one
#: value that must be unpredictable in production and fixed in a test, which is
#: exactly why it is injected rather than computed.
#: ``service`` mints a session id, which is an identifier and not a simulation
#: value; it is also injectable, and the tests inject it.
NONDETERMINISM_EXEMPT = {
    "seeds.py": {"secrets"},
    "service.py": {"secrets"},
}

#: Wall-clock modules. Simulation time is the session's SimClock and nothing
#: else, so the whole application layer is off real time -- with no exemption,
#: not even for the service that owns the tick. A step is an authored constant;
#: it is not a measurement, so there is nothing here left to measure with.
FORBIDDEN_CLOCK_IMPORTS = frozenset({"time", "datetime", "calendar"})
CLOCK_EXEMPT = {}


def modules(root):
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts)


WORKSTATION_MODULES = modules(WORKSTATION_ROOT)
PROTOTYPE_MODULES = modules(PROTOTYPE_ROOT)


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
# The layer exists and is where it says it is
# ===========================================================================

def test_the_workstation_layer_exists():
    assert WORKSTATION_ROOT.is_dir(), "rewindsec/workstation/ is missing"
    assert WORKSTATION_MODULES
    names = {p.name for p in WORKSTATION_MODULES}
    assert {"__init__.py", "actions.py", "bootstrap.py", "consequences.py",
            "projection.py", "service.py", "updates.py",
            "worldops.py"} <= names, sorted(names)


def test_the_authored_content_lives_in_the_application_layer():
    """Content a session is *seeded from* is application content, not UI.

    Keeping it under the prototype package would have made the application
    layer import the UI adapter to find out what a mail message is, which is
    the dependency direction backwards.
    """
    content = WORKSTATION_ROOT / "content"
    assert (content / "world.py").is_file()
    assert (content / "scenario.py").is_file()


# ===========================================================================
# What the workstation layer may not import
# ===========================================================================

@pytest.mark.parametrize("module_path", WORKSTATION_MODULES, ids=_module_id)
def test_workstation_module_imports_no_framework(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_FRAMEWORK_IMPORTS
    assert not forbidden, (
        "%s imports %s. The workstation application layer must be usable in a "
        "plain Python test with no Flask app context and no database: it "
        "raises WorkstationError subclasses, and mapping those onto HTTP is "
        "the adapter's job."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", WORKSTATION_MODULES, ids=_module_id)
def test_workstation_module_imports_no_v1_code(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_V1_IMPORTS
    assert not forbidden, (
        "%s imports v1 module(s) %s; see PROVENANCE.md."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", WORKSTATION_MODULES, ids=_module_id)
def test_workstation_module_cannot_reach_the_network_or_a_subprocess(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_IO_IMPORTS
    assert not forbidden, (
        "%s imports %s. Every destination in this product is synthetic and "
        "local: no scenario content is fetched, no message is delivered, no "
        "attachment is executed, and there must be no code path that could."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", WORKSTATION_MODULES, ids=_module_id)
def test_workstation_module_uses_no_ambient_randomness(module_path):
    allowed = NONDETERMINISM_EXEMPT.get(pathlib.Path(module_path).name, set())
    forbidden = (_imported_top_level_names(module_path)
                 & FORBIDDEN_NONDETERMINISM_IMPORTS) - allowed
    assert not forbidden, (
        "%s imports %s. Simulation randomness comes from the session's "
        "SeededRandom; the only exemption is minting a root seed or a session "
        "id, both of which are infrastructure and both of which are "
        "injectable." % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", WORKSTATION_MODULES, ids=_module_id)
def test_workstation_module_uses_no_ambient_wall_clock(module_path):
    allowed = CLOCK_EXEMPT.get(pathlib.Path(module_path).name, set())
    forbidden = (_imported_top_level_names(module_path)
                 & FORBIDDEN_CLOCK_IMPORTS) - allowed
    assert not forbidden, (
        "%s imports %s. Simulation time is the session's SimClock, and it is "
        "advanced only by explicit, stated amounts. Real time must not reach "
        "any simulation decision, including how far the clock moves."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", WORKSTATION_MODULES, ids=_module_id)
def test_workstation_module_does_not_import_dynamically(module_path):
    names = _imported_top_level_names(module_path)
    assert "importlib" not in names, _module_id(module_path)
    for node in ast.walk(_parse(module_path)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "__import__", _module_id(module_path)


def test_no_workstation_module_reads_a_real_clock_at_all():
    """Structural, and stronger than the import check: no clock calls either.

    An import test can be walked around by reaching a clock through something
    already imported, so the source is read as well. Wall time is allowed to
    pace a transport -- and the transport does not live in this layer.
    """
    for module_path in WORKSTATION_MODULES:
        source = io.open(module_path, encoding="utf-8").read()
        uses = re.findall(r"\b(?:time|datetime|calendar)\.\w+", source)
        assert not uses, (_module_id(module_path), uses)


def test_a_tick_cannot_be_told_how_far_to_go():
    """The size of a step is not an input, so nothing can inflate one.

    A duration parameter is all it would take for the browser's timer, or a
    crafted request, to become the thing that decides when a consequence
    lands. There is no such parameter, and this is the test that keeps it that
    way.
    """
    import inspect

    from rewindsec.workstation.service import TICK_QUANTUM_MS, WorkstationService

    signature = inspect.signature(WorkstationService.tick)
    assert list(signature.parameters) == ["self", "session_id", "learner_ref"]
    assert isinstance(TICK_QUANTUM_MS, int) and TICK_QUANTUM_MS > 0


def test_the_projection_never_reads_authored_ground_truth():
    """The wall between truth and screen is one module, and it is thin.

    ``projection.py`` may not call the predicates that answer "did the author
    mark this hostile?". If it ever needs to, the answer is that it does not.
    """
    source = io.open(WORKSTATION_ROOT / "projection.py", encoding="utf-8").read()
    tree = ast.parse(source)
    called = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            name = getattr(func, "attr", None) or getattr(func, "id", None)
            if name:
                called.add(name)
    for banned in ("is_hostile_mail", "is_hostile_prompt", "is_hostile_page"):
        assert banned not in called, banned
    # And it does not reach into an ``analysis`` block by name.
    assert '"analysis"' not in source
    assert "['analysis']" not in source


def test_the_debrief_is_not_reachable_from_the_projection():
    """The debrief may explain; the projection may not. They stay apart."""
    source = io.open(WORKSTATION_ROOT / "projection.py", encoding="utf-8").read()
    assert "debrief" not in _imported_dotted_names(
        WORKSTATION_ROOT / "projection.py")
    assert "debrief" not in source


# ===========================================================================
# The domain's boundary is unchanged
# ===========================================================================

def test_the_domain_still_knows_nothing_about_the_workstation():
    """Dependencies point one way. The domain gained no application knowledge."""
    for path in modules(REPO_ROOT / "rewindsec" / "domain"):
        names = _imported_dotted_names(path)
        for name in names:
            assert not name.startswith("rewindsec.workstation"), (
                _module_id(path), name)
            assert not name.startswith("rewindsec.prototype"), (
                _module_id(path), name)


def test_the_persistence_adapter_still_knows_nothing_about_flask():
    for path in modules(REPO_ROOT / "rewindsec" / "persistence"):
        forbidden = _imported_top_level_names(path) & {
            "flask", "flask_sqlalchemy", "app", "werkzeug"}
        assert not forbidden, (_module_id(path), sorted(forbidden))


# ===========================================================================
# The HTTP adapter
# ===========================================================================

def test_the_http_adapter_is_the_only_place_flask_appears():
    """Flask lives in the prototype package and stops there."""
    flask_users = [
        _module_id(path) for path in PROTOTYPE_MODULES
        if "flask" in _imported_top_level_names(path)]
    assert set(flask_users) == {"rewindsec/prototype/api.py",
                                "rewindsec/prototype/routes.py"}, flask_users


def test_the_http_adapter_depends_on_the_application_layer_not_the_domain():
    """The adapter talks to the service, not to the aggregate.

    A route that reached into ``SimulationSession`` directly would be a route
    that could mutate the world without going through validation, and the
    whole point of the batch is that there is no such path.
    """
    api = _imported_dotted_names(PROTOTYPE_ROOT / "api.py")
    assert any(name.startswith("rewindsec.workstation") for name in api)
    assert not any(name.startswith("rewindsec.domain") for name in api), api
    assert not any(name.startswith("rewindsec.persistence") for name in api), api


def test_the_http_adapter_cannot_reach_the_network(module_paths=None):
    for path in PROTOTYPE_MODULES:
        forbidden = _imported_top_level_names(path) & FORBIDDEN_IO_IMPORTS
        assert not forbidden, (_module_id(path), sorted(forbidden))


# ===========================================================================
# No live destination anywhere in the content
# ===========================================================================

def test_every_address_the_workstation_can_name_is_non_resolving():
    """Reserved TLDs only. Nothing here can resolve even by accident."""
    from rewindsec.prototype import fixtures

    hosts = fixtures.referenced_hosts()
    assert hosts
    for host in hosts:
        assert host.endswith(fixtures.INERT_SUFFIXES), host


def test_the_browser_serves_only_authored_pages():
    """There is no fetch, so an unknown address has no content to show.

    The projection sends a page only when the authored site map has one; the
    service records the visit either way, which is how "this address is not
    reachable" is a truthful screen rather than a failed request.
    """
    source = io.open(WORKSTATION_ROOT / "service.py", encoding="utf-8").read()
    assert "ix.PAGE_BY_URL" in source
    projection = io.open(WORKSTATION_ROOT / "projection.py",
                         encoding="utf-8").read()
    assert "ix.PAGE_BY_URL.get(url)" in projection


def test_no_workstation_module_contains_an_absolute_external_url():
    """Documentation links included: there is nothing to click through to."""
    pattern = re.compile(r"https?://([A-Za-z0-9.\-]+)")
    allowed_suffixes = (".example", ".invalid", ".test", ".localhost")
    for path in WORKSTATION_MODULES + PROTOTYPE_MODULES:
        text = io.open(path, encoding="utf-8").read()
        for host in pattern.findall(text):
            assert host.lower().endswith(allowed_suffixes), (
                _module_id(path), host)


# ===========================================================================
# The layer really is importable on its own
# ===========================================================================


#: The whole application layer, driven end to end, against a repository written
#: in eight lines. Kept as a literal script because it has to run in a *clean*
#: interpreter: importing it here would mean the modules under test were
#: already loaded by the time we looked.
STANDALONE_SCRIPT = '''
import sys
sys.path.insert(0, {repo!r})

from rewindsec.domain.session import SimulationSession
from rewindsec.persistence.ports import (SessionAlreadyExistsError,
                                         SessionNotFoundError,
                                         SessionRepository,
                                         StaleRevisionError)
from rewindsec.workstation.actions import parse_action_request
from rewindsec.workstation.seeds import FixedSeedSource
from rewindsec.workstation.service import WorkstationService


class MemoryRepository(SessionRepository):
    """Stores captured state and rebuilds from it, exactly as an adapter does."""

    def __init__(self):
        self._rows = {{}}

    def create(self, session):
        if session.session_id in self._rows:
            raise SessionAlreadyExistsError(session.session_id)
        self._rows[session.session_id] = session.capture_state()

    def load(self, session_id):
        state = self._rows.get(session_id)
        if state is None:
            raise SessionNotFoundError(session_id)
        return SimulationSession.from_state(state)

    def update(self, session, expected_revision):
        state = self._rows.get(session.session_id)
        if state is None:
            raise SessionNotFoundError(session.session_id)
        if state["revision"] != expected_revision:
            raise StaleRevisionError(session.session_id)
        self._rows[session.session_id] = session.capture_state()

    def exists(self, session_id):
        return session_id in self._rows


service = WorkstationService(MemoryRepository(),
                             seed_source=FixedSeedSource(1),
                             id_source=lambda: "ws-sub")
session_id = service.start_session("learner-sub", "mixed", "practice")
snapshot = service.snapshot(session_id, "learner-sub")
result = service.apply_action(session_id, parse_action_request(
    {{"action": "mail.open", "target": "m-payslip-aug",
      "revision": snapshot["session"]["revision"]}}), "learner-sub")
assert result.revision > snapshot["session"]["revision"]
assert result.snapshot["mail"]["messages"]

WATCHED = {{"flask", "werkzeug", "jinja2", "sqlalchemy", "study", "learning",
            "training", "scenario_adapters", "evaluation", "sandbox",
            "requests", "urllib", "httpx", "socket", "subprocess", "docker",
            "ssl", "asyncio"}}
print(repr(sorted(m for m in sys.modules if m.split(".")[0] in WATCHED)))
'''


def test_the_workstation_layer_drives_a_session_with_no_adapter_at_all():
    """A clean subprocess runs a whole session against a stub repository.

    Two things at once. It is the backstop the core and domain suites also use
    -- catching a dependency that arrives through a package ``__init__``
    rather than through a direct import -- and it is the proof that the
    repository *port* is real: the service works against any implementation of
    it, so nothing web-shaped, nothing v1 and nothing that could open a socket
    is loaded to run a session from start to action.

    The SQLAlchemy adapter legitimately pulls in ``socket`` and ``subprocess``
    on its own account, which is exactly why it is not used here: what is
    under test is the application layer, not its storage.
    """
    import subprocess
    import sys

    completed = subprocess.run(
        [sys.executable, "-c", STANDALONE_SCRIPT.format(repo=str(REPO_ROOT))],
        capture_output=True, text=True, cwd=str(REPO_ROOT), timeout=180)
    assert completed.returncode == 0, completed.stderr
    loaded = ast.literal_eval(completed.stdout.strip())
    assert loaded == [], "driving a session dragged in %s" % loaded
