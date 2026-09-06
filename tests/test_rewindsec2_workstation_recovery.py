"""RewindSec 2.0 Batch 4: the narrowly scoped file-recovery workflow.

Architecture Spec v1.1 S24: Recovery Quality needs a genuine recovery
opportunity, distinct from containment. This suite covers the small
``browser.support_action`` ``"restore"`` choice added for it -- prerequisite
enforcement, idempotence, that it changes only file rows and one incident
fact (never re-opening or deleting the incident, never touching the causal
graph), and that it produces the "d-ransom-recover" decision the scoring
package's Recovery Quality dimension reads.
"""

import pytest

from rewindsec.workstation.bootstrap import NS_DECISIONS, NS_FILES, NS_INCIDENTS
from tests.workstation_helpers import Driver, build_service, incident, sqlite_uri


def session_for(tmp_path, name="recover.db", focus="ransomware", mode="simulation"):
    service, _ = build_service(sqlite_uri(tmp_path, name))
    return Driver.start(service, focus=focus, mode=mode)


def open_the_attachment(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    return driver


def isolate(driver):
    return driver.act("browser.support_action", params={"choice": "isolate"})


def restore(driver):
    return driver.act("browser.support_action", params={"choice": "restore"})


def unavailable(driver):
    return {file_id for file_id, state
            in driver.session().world.get_component(NS_FILES).items()
            if state.get("state") == "unavailable"}


def decisions(driver):
    """Semantic decision classes recorded, independent of occurrence scoping.

    See the identical helper in ``test_rewindsec2_network_isolation.py``.
    """
    return {state.get("decision_class", key) for key, state
           in driver.session().world.get_component(NS_DECISIONS).items()}


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

def test_restore_with_nothing_affected_says_so(tmp_path):
    driver = session_for(tmp_path, "nothing.db")
    result = restore(driver)
    assert "nothing to restore" in result.notice["text"].lower()
    assert "d-ransom-recover" not in decisions(driver)


def test_restore_before_containment_is_refused(tmp_path):
    driver = session_for(tmp_path, "uncontained.db")
    open_the_attachment(driver)
    driver.advance(20000)  # the incident opens, uncontained
    assert incident(driver.snapshot(), "inc-files")["contained"] is False

    result = restore(driver)
    assert "contain" in result.notice["text"].lower()
    assert "d-ransom-recover" not in decisions(driver)
    # And nothing was restored.
    assert unavailable(driver)


# ---------------------------------------------------------------------------
# The successful path
# ---------------------------------------------------------------------------

def test_restore_after_containment_brings_files_back(tmp_path):
    driver = session_for(tmp_path, "recovered.db")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    assert incident(driver.snapshot(), "inc-files")["contained"] is True
    assert unavailable(driver)

    restore(driver)
    assert not unavailable(driver)
    entry = incident(driver.snapshot(), "inc-files")
    assert entry["contained"] is True  # containment fact untouched
    assert entry["recovered"] is True
    assert "d-ransom-recover" in decisions(driver)


def test_restore_does_not_close_or_delete_the_incident(tmp_path):
    """Recovery adds a fact; it is not a rewind. The incident, its
    consequences and the causal graph stay exactly as they are."""
    driver = session_for(tmp_path, "no_rewind.db")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    session = driver.session()
    before_consequences = len(session.incidents.consequences())
    before_incident_id = (session.world.get(NS_INCIDENTS, "inc-files") or {}).get(
        "incident_id")

    restore(driver)
    session = driver.session()
    assert session.world.has(NS_INCIDENTS, "inc-files")
    assert (session.world.get(NS_INCIDENTS, "inc-files") or {}).get(
        "incident_id") == before_incident_id
    assert len(session.incidents.consequences()) == before_consequences


def test_restore_is_idempotent(tmp_path):
    driver = session_for(tmp_path, "twice.db")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    restore(driver)

    result = restore(driver)
    assert "already" in result.notice["text"].lower()
    assert len(decisions(driver) & {"d-ransom-recover"}) == 1


def test_recovery_makes_recovery_quality_score_high(tmp_path):
    from rewindsec.scoring import evaluator

    driver = session_for(tmp_path, "scored.db")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    restore(driver)
    driver.service.end_session(driver.session_id, driver.learner_ref)
    result = evaluator.evaluate(driver.session())
    assert result.dimensions["recovery_quality"].applicable
    assert result.dimensions["recovery_quality"].score > 50


# ---------------------------------------------------------------------------
# No real filesystem/Docker/IT-system involvement
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Save/resume boundaries
# ---------------------------------------------------------------------------

def test_containment_survives_a_resume_before_recovery(tmp_path):
    """Resuming a session between containment and recovery must not lose the
    contained fact, invent a recovered one, or make restore unreachable."""
    uri = sqlite_uri(tmp_path, "resume_before.db")
    service, _ = build_service(uri, ids=["ws-recover-resume-before"])
    driver = Driver.start(service, focus="ransomware", mode="simulation")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    assert incident(driver.snapshot(), "inc-files")["contained"] is True
    assert unavailable(driver)

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    entry = incident(resumed.snapshot(), "inc-files")
    assert entry["contained"] is True
    assert entry.get("recovered") is not True
    assert unavailable(resumed)

    restore(resumed)
    assert not unavailable(resumed)
    assert incident(resumed.snapshot(), "inc-files")["recovered"] is True


def test_recovery_survives_a_resume_after_recovery(tmp_path):
    """Resuming after recovery must not lose the restored files or the
    recovered fact, and a repeated restore afterwards is still a no-op."""
    uri = sqlite_uri(tmp_path, "resume_after.db")
    service, _ = build_service(uri, ids=["ws-recover-resume-after"])
    driver = Driver.start(service, focus="ransomware", mode="simulation")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    restore(driver)
    assert not unavailable(driver)

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    entry = incident(resumed.snapshot(), "inc-files")
    assert entry["contained"] is True
    assert entry["recovered"] is True
    assert not unavailable(resumed)
    assert "d-ransom-recover" in decisions(resumed)

    result = restore(resumed)
    assert "already" in result.notice["text"].lower()
    assert len(decisions(resumed) & {"d-ransom-recover"}) == 1


def test_restore_touches_only_synthetic_world_rows(tmp_path):
    """A blunt check that the restore path never imports anything that would
    touch a real filesystem or container runtime."""
    import inspect

    from rewindsec.workstation import service as service_module
    source = inspect.getsource(service_module._restore)
    for banned in ("os.remove", "shutil", "docker", "subprocess", "open("):
        assert banned not in source
