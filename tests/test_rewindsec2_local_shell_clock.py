"""The publication branch's cosmetic shell clock, and the line it must not cross.

On ``paper/print-ui`` the workstation top-bar clock is a **local device
clock**: browser-only, ``new Date()``, HH:MM in the viewer's own timezone,
so a publication screenshot shows a natural wall-clock time. That is a
presentation change and nothing else.

The deterministic simulation clock is untouched and stays authoritative.
These tests hold the separation from both sides:

* the authoritative snapshot still carries server-owned simulation time, and
  a tick still advances it by the authored quantum, deterministically and
  identically for two same-seeded sessions;
* the shell no longer paints ``#pw-clock`` from that snapshot, and the
  cosmetic clock reads a device clock, sends nothing and persists nothing.

The second half is asserted statically against the shipped asset. A test that
booted a browser would prove less: what matters is that no code path writes
the simulation clock into the shell, and that the cosmetic one has no
transport.
"""

import io
import os
import re

from rewindsec.workstation.service import TICK_QUANTUM_MS
from tests.management_helpers import LEARNER, build, sqlite_uri

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKSTATION_JS = os.path.join(ROOT, "static", "prototype", "workstation.js")
WORKSTATION_HTML = os.path.join(ROOT, "templates", "prototype",
                                "workstation.html")


def _read(path):
    with io.open(path, encoding="utf-8") as handle:
        return handle.read()


# ---------------------------------------------------------------------------
# A. The authoritative simulation clock is unchanged
# ---------------------------------------------------------------------------

def test_the_snapshot_still_carries_server_owned_simulation_time(tmp_path):
    _management, workstation, _sessions = build(sqlite_uri(tmp_path))
    session_id = workstation.start_session(LEARNER, "phishing", "simulation")

    snapshot = workstation.snapshot(session_id, LEARNER)["session"]
    assert "sim_time_ms" in snapshot
    assert "clock" in snapshot
    assert "clock_rate" in snapshot
    assert isinstance(snapshot["sim_time_ms"], int)


def test_a_tick_still_advances_simulation_time_by_the_authored_quantum(
        tmp_path):
    _management, workstation, _sessions = build(sqlite_uri(tmp_path))
    session_id = workstation.start_session(LEARNER, "phishing", "simulation")

    before = workstation.snapshot(session_id, LEARNER)["session"]["sim_time_ms"]
    after = workstation.tick(session_id, LEARNER)["session"]["sim_time_ms"]

    assert after - before == TICK_QUANTUM_MS


def test_two_same_seeded_sessions_still_keep_identical_simulation_time(
        tmp_path):
    """No real clock has leaked into a simulation decision on this branch."""
    _m1, first, _s1 = build(sqlite_uri(tmp_path, "one.db"), seed=9182)
    _m2, second, _s2 = build(sqlite_uri(tmp_path, "two.db"), seed=9182)

    left = first.start_session(LEARNER, "phishing", "simulation")
    right = second.start_session(LEARNER, "phishing", "simulation")

    for _ in range(5):
        moved = first.tick(left, LEARNER)["session"]["sim_time_ms"]
        also = second.tick(right, LEARNER)["session"]["sim_time_ms"]
        assert moved == also


# ---------------------------------------------------------------------------
# B. The shell clock is cosmetic, local, and has no transport
# ---------------------------------------------------------------------------

def test_the_shell_no_longer_paints_the_clock_from_the_snapshot():
    source = _read(WORKSTATION_JS)
    # The only writer of #pw-clock is the cosmetic local clock renderer.
    writers = re.findall(r"[^\n]*#pw-clock[^\n]*", source)
    assert len(writers) == 1, writers
    assert "renderLocalClock" in source
    # The snapshot-derived display clock and its interpolation anchor are gone
    # from the shell entirely, so nothing can reintroduce the overwrite by
    # accident.
    assert "nowLabel" not in source
    assert "clockAnchor" not in source
    assert "syncClock" not in source


def test_the_cosmetic_clock_reads_the_device_and_sends_nothing():
    source = _read(WORKSTATION_JS)
    start = source.index("function localClockLabel")
    end = source.index("// =====", start)
    block = source[start:end]

    assert "new Date()" in block
    assert "getHours()" in block and "getMinutes()" in block
    # No transport, no storage, no simulation input of any kind.
    for forbidden in ("fetch", "request(", "XMLHttpRequest", "localStorage",
                      "sessionStorage", "sim_time_ms", "SNAP"):
        assert forbidden not in block, forbidden


def test_the_clock_is_labelled_as_local_device_time():
    markup = _read(WORKSTATION_HTML)
    assert 'id="pw-clock" aria-label="Local device time"' in markup
    assert "Workstation time" not in markup


def test_the_rest_of_the_top_bar_is_still_rendered_from_the_snapshot():
    """Only the clock was detached. Mode, focus and badges still come from
    authoritative session truth."""
    source = _read(WORKSTATION_JS)
    start = source.index("function renderTopBar")
    end = source.index("\n  }\n", start)
    block = source[start:end]

    assert "SNAP.session.mode" in block
    assert "SNAP.session.focus" in block
    assert "pw-assessment-chip" in block
    assert "pw-notif-badge" in block
    assert "#pw-clock" not in block
