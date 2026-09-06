"""RewindSec 2.0 Batch 4: scoring must stay hidden during an active attempt.

Extends the Batch 2 leakage suite's method -- walk the whole learner-facing
document and assert properties over all of it -- to the scoring fields
Architecture Spec v1.1 S30 and S72 name explicitly: rubric weights, dimension
scores, evidence valence, expected actions, opportunity classes. None of it
may ever reach ``learner_snapshot`` (active or otherwise -- that projection
never reads scoring state at all), and the debrief route itself refuses to
run before the session ends.
"""

import json

import pytest

from rewindsec.scoring import state as scoring_state
from rewindsec.workstation.debrief import debrief_document
from rewindsec.workstation.errors import ForbiddenActionError
from tests.workstation_helpers import Driver, build_service, sqlite_uri, walk

#: Field names that would leak internal scoring machinery wherever they
#: appeared in a learner-facing document.
SCORING_FORBIDDEN_KEYS = frozenset({
    "rubric", "evidence_weight", "weight", "dimension_score",
    "overall_score", "expected_action", "positive_evidence",
    "negative_evidence", "opportunity_class", "score_delta", "valence",
    "opportunity_id", "dedup_key", "explanation_code",
})


@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="mixed", mode="simulation")


def _forbidden(document):
    found = []
    for path, value in walk(document):
        if not isinstance(value, dict):
            continue
        for key in value:
            if key in SCORING_FORBIDDEN_KEYS:
                found.append("%s.%s" % (path, key))
    return found


# ---------------------------------------------------------------------------
# Active session: learner_snapshot never carries scoring at all
# ---------------------------------------------------------------------------

def test_an_active_snapshot_carries_no_scoring_field_whatsoever(driver):
    snapshot = driver.snapshot()
    assert "scoring" not in json.dumps(snapshot)
    assert _forbidden(snapshot) == []


def test_a_hostile_heavy_active_session_still_leaks_no_scoring(driver):
    """Even once real decisions and evidence exist behind the scenes, the
    active projection never surfaces any of it."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    driver.act("mail.inspect_headers", "m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    snapshot = driver.snapshot()
    assert "scoring" not in json.dumps(snapshot)
    assert _forbidden(snapshot) == []


def test_the_debrief_refuses_to_run_before_the_session_ends(driver):
    with pytest.raises(ForbiddenActionError):
        debrief_document(driver.session())


def test_assessment_also_leaks_no_scoring_mid_attempt(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path, "assess.db"))
    driver = Driver.start(service, focus="phishing", mode="assessment")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    result = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": result.notice["url"]})
    snapshot = driver.advance(120000)
    assert "scoring" not in json.dumps(snapshot)
    assert _forbidden(snapshot) == []


# ---------------------------------------------------------------------------
# Completed session: only the permitted learner projection is exposed
# ---------------------------------------------------------------------------

def test_completed_debrief_scoring_carries_no_internal_machinery(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.service.end_session(driver.session_id, driver.learner_ref)
    document = debrief_document(driver.session())
    assert _forbidden(document) == []
    # The permitted fields are still there -- this is a denylist on internals,
    # not a blanket ban on the whole block.
    scoring = document["scoring"]
    assert scoring["available"] is True
    assert isinstance(scoring["overall"], int) or scoring["overall"] is None
    for dim in scoring["dimensions"]:
        assert set(dim) == {"id", "label", "description", "applicable",
                            "score", "na_reason", "evidence"}
        for item in dim["evidence"]:
            assert set(item) == {"text", "direction"}


def test_assessment_gets_a_real_score_only_after_completion(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path, "assess2.db"))
    driver = Driver.start(service, focus="phishing", mode="assessment")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.service.end_session(driver.session_id, driver.learner_ref)
    document = debrief_document(driver.session())
    assert document["scoring"]["available"] is True
    assert document["scoring"]["dimensions"]


# ---------------------------------------------------------------------------
# Idempotence: ending twice never changes, duplicates, or regenerates
# ---------------------------------------------------------------------------

def test_ending_a_session_twice_does_not_change_the_persisted_score(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.service.end_session(driver.session_id, driver.learner_ref)
    first = scoring_state.get_result(driver.session()).to_state()

    driver.service.end_session(driver.session_id, driver.learner_ref)
    second = scoring_state.get_result(driver.session()).to_state()
    assert first == second


# ---------------------------------------------------------------------------
# Legacy sessions
# ---------------------------------------------------------------------------

def test_a_session_with_no_scoring_stamp_gets_the_explicit_legacy_projection(driver):
    """Simulates a pre-Batch-4 session: no ``scoring`` world namespace at
    all. It must never be silently treated as scored (a rubric stamp cannot
    be invented retroactively), and its projection must say so plainly."""
    session = driver.session()
    # A genuine pre-Batch-4 session simply never had ``scoring_state
    # .bootstrap`` called on it. Simulating that here directly, since every
    # session created through this suite's ``start_session`` now legitimately
    # gets the stamp.
    assert scoring_state.is_versioned_session(session)
    view = scoring_state.learner_view(_UnstampedSession(session))
    assert view["available"] is False
    assert view["legacy"] is True
    assert view["overall"] is None
    assert view["dimensions"] == []


class _UnstampedSession(object):
    """A thin proxy presenting ``world.has(...)`` as always False for the
    scoring namespace, standing in for a genuine pre-Batch-4 session without
    having to hand-construct one from a stale domain state payload."""

    def __init__(self, real_session):
        self._real = real_session

    @property
    def world(self):
        return _UnstampedWorld(self._real.world)

    def __getattr__(self, name):
        return getattr(self._real, name)


class _UnstampedWorld(object):
    def __init__(self, real_world):
        self._real = real_world

    def has(self, namespace, key):
        if namespace == "scoring":
            return False
        return self._real.has(namespace, key)

    def get(self, namespace, key, default=None):
        if namespace == "scoring":
            return default
        return self._real.get(namespace, key, default)

    def get_component(self, namespace):
        if namespace == "scoring":
            return {}
        return self._real.get_component(namespace)
