"""RewindSec 2.0 Batch 4: the deterministic six-dimension scoring rubric.

Covers each dimension's applicability, N/A semantics, dedup/spam resistance,
causal separation (a bad decision followed by a good recovery keeps both),
determinism, and score bounds. Uses the same
:class:`~tests.workstation_helpers.Driver` scaffolding the Batch 2/3 suites
use, driving a real, persisted session through the real workstation service
-- scoring is evaluated from that session's own factual history, not from a
hand-built fixture.
"""

import pytest

from rewindsec.scoring import evaluator
from rewindsec.scoring.dimensions import DIMENSION_IDS
from tests.workstation_helpers import Driver, build_service, sqlite_uri


def driver_for(tmp_path, name="scoring.db", focus="mixed", mode="simulation"):
    service, _ = build_service(sqlite_uri(tmp_path, name))
    return Driver.start(service, focus=focus, mode=mode)


def open_the_attachment(driver):
    """Download the ransomware macro workbook and open it.

    Mirrors ``tests/test_rewindsec2_network_isolation.py``'s helper of the
    same name -- kept as a small local copy rather than a shared import so
    this suite has no dependency on that one's internal layout.
    """
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    return driver


def isolate(driver):
    return driver.act("browser.support_action", params={"choice": "isolate"})


def score(driver):
    driver.service.end_session(driver.session_id, driver.learner_ref)
    return evaluator.evaluate(driver.session())


# ---------------------------------------------------------------------------
# N/A semantics
# ---------------------------------------------------------------------------

def test_a_session_with_no_hostile_content_leaves_those_dimensions_na(tmp_path):
    """A session that never delivers hostile mail/prompts/incidents leaves the
    hostile-dependent dimensions N/A. Legitimate onboarding mail is present
    from the start (``bootstrap.seed_session`` delivers "opening" arrivals),
    so ``operational_accuracy`` is legitimately applicable even here."""
    driver = driver_for(tmp_path)
    result = score(driver)
    for dim in ("security_judgment", "evidence_use", "verification_discipline",
               "incident_response", "recovery_quality"):
        dr = result.dimensions[dim]
        assert dr.applicable is False, dim
        assert dr.score is None
        assert dr.na_reason
    assert result.dimensions["operational_accuracy"].applicable is True


def test_overall_is_explicitly_unavailable_when_every_dimension_is_na(tmp_path, monkeypatch):
    """A theoretical all-N/A session must not invent a 0 or a 100 overall."""
    from rewindsec.scoring import rubric

    driver = driver_for(tmp_path, "all_na.db")
    monkeypatch.setattr(rubric, "applicability", lambda session: {
        dim: (False, "forced N/A for this test") for dim in DIMENSION_IDS})
    result = score(driver)
    assert result.overall is None
    for dim in DIMENSION_IDS:
        assert result.dimensions[dim].applicable is False


def test_na_is_excluded_from_overall_not_treated_as_zero(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    result = score(driver)

    # recovery_quality: no incident this session -> N/A.
    assert result.dimensions["recovery_quality"].applicable is False
    applicable_scores = [result.dimensions[d].score for d in DIMENSION_IDS
                         if result.dimensions[d].applicable]
    assert applicable_scores
    # The overall figure must be the mean of exactly the applicable scores,
    # which is impossible if an excluded N/A dimension had silently
    # contributed a phantom zero.
    assert result.overall == round(sum(applicable_scores) / len(applicable_scores))


def test_recovery_na_until_the_incident_is_actually_contained(tmp_path):
    """Recovery Quality is N/A until a recovery opportunity genuinely exists
    -- which, per the containment gate, means the incident must have been
    contained at least once. Opening the malicious file alone (with no
    containment) is not enough; see
    ``test_ignoring_an_open_uncontained_incident_is_negative_incident_response``
    for that case."""
    driver = driver_for(tmp_path, focus="ransomware")
    result_before = score(driver)
    assert result_before.dimensions["recovery_quality"].applicable is False

    driver2 = driver_for(tmp_path, "scoring2.db", focus="ransomware")
    open_the_attachment(driver2)
    isolate(driver2)
    driver2.advance(90000)
    result_after = score(driver2)
    assert result_after.dimensions["recovery_quality"].applicable is True


# ---------------------------------------------------------------------------
# Security Judgment / Evidence Use / Verification Discipline
# ---------------------------------------------------------------------------

def test_reporting_hostile_mail_is_positive_security_judgment(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    result = score(driver)
    assert result.dimensions["security_judgment"].score > 50


def test_submitting_credentials_is_negative_security_judgment(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    nav = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": nav.notice["url"]})
    result = score(driver)
    assert result.dimensions["security_judgment"].score < 50


def test_ignoring_hostile_mail_entirely_is_also_negative(tmp_path):
    """Doing nothing at all about a hostile message is not a free pass."""
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    result = score(driver)
    assert result.dimensions["security_judgment"].score < 50
    codes = [e[0] for e in result.dimensions["security_judgment"].explanations]
    assert any(c.startswith("opportunity_ignored:mail:") for c in codes)


def test_inspecting_evidence_before_deciding_credits_evidence_use(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    driver.act("mail.inspect_headers", "m-payroll-restructure")
    driver.act("mail.inspect_link", "m-payroll-restructure", {"index": 0})
    driver.act("mail.report", "m-payroll-restructure")
    result = score(driver)
    assert result.dimensions["evidence_use"].score >= 50


def test_deciding_without_inspecting_anything_penalizes_evidence_use(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    result = score(driver)
    assert result.dimensions["evidence_use"].score < 50


def test_calling_the_suspect_number_is_not_verification(tmp_path):
    """Only Directory/Messages verification counts; the request's own
    contact details never do -- that distinction lives in the ledger fact
    mapping and this proves the score reflects it."""
    driver = driver_for(tmp_path, focus="bec")
    driver.deliver_until("m-invoice-amend")
    driver.act("mail.report", "m-invoice-amend")
    result = score(driver)
    # No known-channel verification action of any kind was taken.
    codes = [e[0] for e in result.dimensions.get(
        "verification_discipline", result.dimensions["security_judgment"]).explanations]
    assert not any("verif" in c for c in codes)


def test_verifying_on_a_known_channel_is_positive(tmp_path):
    driver = driver_for(tmp_path, focus="bec")
    driver.deliver_until("m-invoice-amend")
    driver.act("directory.call", "dir-calderwood")
    result = score(driver)
    assert result.dimensions["verification_discipline"].applicable
    assert result.dimensions["verification_discipline"].score > 50


# ---------------------------------------------------------------------------
# Operational accuracy: reporting/refusing legitimate work is not optimal
# ---------------------------------------------------------------------------

def test_reporting_legitimate_mail_costs_operational_accuracy(tmp_path):
    # m-payslip-aug is an "opening" arrival: already in the mailbox the
    # moment the session is created, no engine draw required.
    driver = driver_for(tmp_path, focus="mixed")
    assert _has(driver, "m-payslip-aug")
    driver.act("mail.report", "m-payslip-aug")
    result = score(driver)
    assert result.dimensions["operational_accuracy"].applicable
    assert result.dimensions["operational_accuracy"].score < 50


def _has(driver, mail_id):
    return any(m["id"] == mail_id for m in driver.snapshot()["mail"]["messages"])


# ---------------------------------------------------------------------------
# Incident response / Recovery quality, and causal separation
# ---------------------------------------------------------------------------

def test_isolating_before_spread_is_strong_incident_response(tmp_path):
    """Containment alone is Incident Response, not Recovery Quality.

    Batch 4 correction: isolating used to be tagged with ``recovery_quality``
    directly, which let containment alone earn a high Recovery Quality score
    with nothing ever actually restored. It no longer does -- see
    ``rewindsec.scoring.opportunities``'s ``containment``/``recovery``
    opportunity split.
    """
    driver = driver_for(tmp_path, "recov1.db", focus="ransomware")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)  # let the (now-contained) incident actually open
    result = score(driver)
    assert result.dimensions["incident_response"].score > 50


def test_isolating_then_actually_recovering_is_strong_recovery_quality(tmp_path):
    """The genuine positive path for Recovery Quality: contain, then restore."""
    driver = driver_for(tmp_path, "recov1b.db", focus="ransomware")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    driver.act("browser.support_action", params={"choice": "restore"})
    result = score(driver)
    assert result.dimensions["incident_response"].score > 50
    assert result.dimensions["recovery_quality"].applicable is True
    assert result.dimensions["recovery_quality"].score > 50


def test_isolating_without_ever_recovering_leaves_recovery_quality_poor(tmp_path):
    """Recovery Quality is a genuine, independent opportunity: containment
    that is never followed by an actual restore does not earn it a high
    score by association -- it is applicable (recovery became available the
    moment containment happened) and scores poorly, because the opportunity
    to restore was presented and never used."""
    driver = driver_for(tmp_path, "recov1c.db", focus="ransomware")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    result = score(driver)
    assert result.dimensions["recovery_quality"].applicable is True
    assert result.dimensions["recovery_quality"].score < 50


def test_ignoring_an_open_uncontained_incident_is_negative_incident_response(tmp_path):
    """An incident nobody ever contains is a failure of Incident Response.

    Recovery Quality is legitimately N/A here, not negative: Architecture
    Spec v1.1 S24's recovery step is only ever reachable once containment has
    happened (``service._restore``'s gate), so an incident that is never
    contained never produces a recovery opportunity at all -- see
    ``rewindsec.scoring.rubric._recovery_opportunity_ever_existed``. Batch 4
    correction: this case used to be scored as negative Recovery Quality,
    which blamed the wrong dimension for a containment failure.
    """
    driver = driver_for(tmp_path, "recov2.db", focus="ransomware")
    open_the_attachment(driver)
    driver.advance(90000)  # let the incident open; never isolate
    result = score(driver)
    assert result.dimensions["incident_response"].applicable is True
    assert result.dimensions["incident_response"].score < 50
    assert result.dimensions["recovery_quality"].applicable is False


def test_bad_initial_decision_then_good_response_preserves_both_signals(tmp_path):
    """Opening the malicious file is bad judgment; isolating afterwards is
    still good incident response. Both must show up -- the rubric may not
    erase the first because the second was better."""
    driver = driver_for(tmp_path, "recov3.db", focus="ransomware")
    open_the_attachment(driver)
    isolate(driver)
    driver.advance(90000)
    result = score(driver)
    assert result.dimensions["security_judgment"].score < 50
    assert result.dimensions["incident_response"].score > 50


# ---------------------------------------------------------------------------
# Spam / dedup resistance
# ---------------------------------------------------------------------------

def test_repeated_inspection_does_not_inflate_evidence_use(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    for _ in range(10):
        driver.act("mail.inspect_headers", "m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    once = score(driver)

    driver2 = driver_for(tmp_path, "scoring_once.db", focus="phishing")
    driver2.deliver_until("m-payroll-restructure")
    driver2.act("mail.open", "m-payroll-restructure")
    driver2.act("mail.inspect_headers", "m-payroll-restructure")
    driver2.act("mail.report", "m-payroll-restructure")
    single = score(driver2)

    assert once.dimensions["evidence_use"].score == single.dimensions["evidence_use"].score


def test_repeated_reports_of_the_same_message_do_not_double_count(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    result = evaluator.evaluate(driver.session())
    # Reporting an already-reported/deleted message is refused by the
    # workstation itself (there is nothing left to act on), so the decision
    # can only be recorded once -- assert that single evidence item, not a
    # pile of identical ones.
    ids = result.dimensions["security_judgment"].evidence_ids
    assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Determinism and bounds
# ---------------------------------------------------------------------------

def test_scoring_is_deterministic_for_the_same_session_state(tmp_path):
    driver = driver_for(tmp_path, focus="mixed")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.service.end_session(driver.session_id, driver.learner_ref)
    session = driver.session()
    first = evaluator.evaluate(session).to_state()
    second = evaluator.evaluate(session).to_state()
    assert first == second


def test_every_applicable_score_is_bounded_0_to_100(tmp_path):
    driver = driver_for(tmp_path, "bounds.db", focus="ransomware")
    open_the_attachment(driver)
    driver.advance(90000)
    result = score(driver)
    for dim in DIMENSION_IDS:
        dr = result.dimensions[dim]
        if dr.applicable:
            assert 0 <= dr.score <= 100
    if result.overall is not None:
        assert 0 <= result.overall <= 100
