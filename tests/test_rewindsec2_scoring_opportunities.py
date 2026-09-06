"""RewindSec 2.0 Batch 4 correction: opportunities exist independent of
learner actions.

Covers the specific failure the architecture review found: a scoring
dimension going N/A, or defaulting to a neutral score, merely because the
learner never happened to record a decision -- even though a real
opportunity (a delivered hostile message, a raised approval request, a
contained incident, a reachable recovery step) genuinely existed. See
:mod:`rewindsec.scoring.opportunities` for the model these tests exercise.
"""

from rewindsec.scoring import evaluator
from rewindsec.scoring import opportunities as opp
from tests.workstation_helpers import Driver, build_service, sqlite_uri


def driver_for(tmp_path, name="opportunities.db", focus="mixed", mode="simulation"):
    service, _ = build_service(sqlite_uri(tmp_path, name))
    return Driver.start(service, focus=focus, mode=mode)


def score(driver):
    driver.service.end_session(driver.session_id, driver.learner_ref)
    return evaluator.evaluate(driver.session())


def open_the_attachment(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    return driver


# ---------------------------------------------------------------------------
# A. Presented-but-ignored hostile MFA stays applicable
# ---------------------------------------------------------------------------

def test_ignored_hostile_mfa_remains_applicable_not_na(tmp_path):
    driver = driver_for(tmp_path, focus="mfa")
    driver.force("cand-mfa-unsolicited")
    # No auth.approve / auth.deny action at all.
    result = score(driver)
    assert result.dimensions["security_judgment"].applicable is True
    assert result.dimensions["security_judgment"].score < 50
    # The MFA opportunity is also tagged evidence_use (d-mfa-approve-hostile
    # carries it) -- ignoring it entirely must not spare that dimension
    # either.
    assert result.dimensions["evidence_use"].applicable is True
    assert result.dimensions["evidence_use"].score < 50


def test_an_mfa_opportunity_exists_the_moment_the_prompt_is_raised(tmp_path):
    """The opportunity itself does not require any learner action to exist --
    only :mod:`rewindsec.scoring.evidence` (gated to session completion)
    treats an unresolved one as ignored."""
    driver = driver_for(tmp_path, focus="mfa")
    driver.force("cand-mfa-unsolicited")
    opportunities = opp.build_opportunities(driver.session())
    ids = [o.opportunity_id for o in opportunities]
    assert any(i.startswith("prompt:") for i in ids)
    prompt_op = next(o for o in opportunities if o.opportunity_id.startswith("prompt:"))
    assert prompt_op.source["prompt_id"] == "mfa-unexpected"
    assert "security_judgment" in prompt_op.dimensions


# ---------------------------------------------------------------------------
# B. Ignored ransomware containment stays applicable
# ---------------------------------------------------------------------------

def test_ignored_containment_remains_applicable_incident_response(tmp_path):
    driver = driver_for(tmp_path, "containment.db", focus="ransomware")
    open_the_attachment(driver)
    driver.advance(90000)  # the incident opens; never isolate
    result = score(driver)
    assert result.dimensions["incident_response"].applicable is True
    assert result.dimensions["incident_response"].score < 50


# ---------------------------------------------------------------------------
# C. Ignored recovery stays applicable
# ---------------------------------------------------------------------------

def test_ignored_recovery_remains_applicable(tmp_path):
    driver = driver_for(tmp_path, "recovery.db", focus="ransomware")
    open_the_attachment(driver)
    driver.act("browser.support_action", params={"choice": "isolate"})
    driver.advance(90000)
    result = score(driver)
    assert result.dimensions["recovery_quality"].applicable is True
    assert result.dimensions["recovery_quality"].score < 50


# ---------------------------------------------------------------------------
# D. Absent recovery opportunity is legitimately N/A
# ---------------------------------------------------------------------------

def test_no_incident_at_all_leaves_recovery_na(tmp_path):
    driver = driver_for(tmp_path, focus="mixed")
    result = score(driver)
    assert result.dimensions["recovery_quality"].applicable is False


def test_incident_never_contained_leaves_recovery_na(tmp_path):
    driver = driver_for(tmp_path, "uncontained.db", focus="ransomware")
    open_the_attachment(driver)
    driver.advance(90000)  # the incident opens; never isolate, never recover
    result = score(driver)
    assert result.dimensions["recovery_quality"].applicable is False
    opportunities = opp.build_opportunities(driver.session())
    assert not any(o.opportunity_type == "recovery" for o in opportunities)
    assert any(o.opportunity_type == "containment" for o in opportunities)


# ---------------------------------------------------------------------------
# E. Ignored relevant evidence does not become N/A
# ---------------------------------------------------------------------------

def test_ignoring_a_hostile_message_entirely_keeps_evidence_use_applicable(tmp_path):
    """A hostile message the learner never even opens still leaves Evidence
    Use applicable (there was evidence to use) and scores it poorly, rather
    than letting total inaction escape into N/A."""
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    result = score(driver)
    assert result.dimensions["evidence_use"].applicable is True
    assert result.dimensions["evidence_use"].score < 50


# ---------------------------------------------------------------------------
# F. Unrelated actions do not create opportunity credit
# ---------------------------------------------------------------------------

def test_opening_the_directory_without_calling_earns_no_verification_credit(tmp_path):
    """Viewing a Directory record is an investigation action, not the
    verification decision itself -- only ``directory.call`` records
    ``d-phish-verify``. Looking without calling must not manufacture
    Verification Discipline credit."""
    driver = driver_for(tmp_path, focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    driver.act("directory.open", "dir-priya-menon")
    result = score(driver)
    assert result.dimensions["verification_discipline"].applicable is True
    assert result.dimensions["verification_discipline"].score < 50
    codes = [e[0] for e in result.dimensions["verification_discipline"].explanations]
    assert not any("verify" in c for c in codes)


def test_random_directory_browsing_with_no_hostile_content_stays_na(tmp_path):
    """With nothing hostile ever delivered, Verification Discipline has no
    opportunity at all -- browsing the Directory for its own sake must not
    conjure one into existence."""
    driver = driver_for(tmp_path, focus="mixed")
    driver.act("directory.open", "dir-priya-menon")
    result = score(driver)
    assert result.dimensions["verification_discipline"].applicable is False


# ---------------------------------------------------------------------------
# Opportunity provenance survives mutable world state (review correction)
#
# opportunities.build_opportunities reads session.world.mutations() -- the
# world's own append-only, immutable audit log -- rather than current
# component snapshots, specifically so that an opportunity already captured
# cannot be un-captured by something that happens to it afterward. These
# tests exercise exactly the scenarios the architecture review named.
# ---------------------------------------------------------------------------

def _opportunity(session, opportunity_id):
    return next((o for o in opp.build_opportunities(session)
                if o.opportunity_id == opportunity_id), None)


def test_a_resolved_hostile_mfa_opportunity_is_still_on_record(tmp_path):
    """A. Presented, then resolved: the opportunity is not erased by being
    answered -- it is simply found to be resolved when evidence.py looks."""
    driver = driver_for(tmp_path, "mfa_resolved.db", focus="mfa")
    driver.force("cand-mfa-unsolicited")
    request_id = next(r["id"] for r in driver.snapshot()["authenticator"]["requests"]
                      if r.get("status", "pending") == "pending")
    before = _opportunity(driver.session(), "prompt:%s" % request_id)
    assert before is not None

    driver.act("auth.deny", request_id)
    after = _opportunity(driver.session(), "prompt:%s" % request_id)
    assert after is not None
    assert after.opportunity_id == before.opportunity_id
    assert after.sim_time_ms == before.sim_time_ms
    assert after.dimensions == before.dimensions
    # And it now scores as resolved (denying a hostile prompt is positive
    # Security Judgment), not as ignored.
    result = score(driver)
    assert result.dimensions["security_judgment"].score > 50


def test_a_deleted_mail_opportunity_remains_on_record(tmp_path):
    """B. The mail opportunity survives the message being moved to Deleted."""
    driver = driver_for(tmp_path, "mail_deleted.db", focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    before = _opportunity(driver.session(), "mail:m-payroll-restructure")
    assert before is not None

    driver.act("mail.delete", "m-payroll-restructure")
    after = _opportunity(driver.session(), "mail:m-payroll-restructure")
    assert after is not None
    assert after.sim_time_ms == before.sim_time_ms
    assert after.dimensions == before.dimensions
    # Deleting without reporting still resolves d-phish-delete (a real,
    # authored decision) -- the opportunity was acted on, not erased.
    result = score(driver)
    assert result.dimensions["security_judgment"].applicable is True


def test_the_containment_opportunity_survives_recovery(tmp_path):
    """C. The original containment opportunity remains on record after the
    incident later becomes contained and then recovered."""
    driver = driver_for(tmp_path, "containment_survives.db", focus="ransomware")
    open_the_attachment(driver)
    driver.advance(20000)  # the incident opens, uncontained
    containment_before = _opportunity(driver.session(),
                                      "incident:inc-files:containment")
    assert containment_before is not None
    assert _opportunity(driver.session(), "incident:inc-files:recovery") is None

    driver.act("browser.support_action", params={"choice": "isolate"})
    driver.advance(90000)
    driver.act("browser.support_action", params={"choice": "restore"})

    containment_after = _opportunity(driver.session(),
                                     "incident:inc-files:containment")
    assert containment_after is not None
    assert containment_after.sim_time_ms == containment_before.sim_time_ms
    recovery_after = _opportunity(driver.session(), "incident:inc-files:recovery")
    assert recovery_after is not None


def test_the_recovery_opportunity_is_marked_resolved_not_removed(tmp_path):
    """D. Once the learner completes recovery, the opportunity is still
    present -- it is resolved, not gone -- and scores positively."""
    driver = driver_for(tmp_path, "recovery_resolved.db", focus="ransomware")
    open_the_attachment(driver)
    driver.act("browser.support_action", params={"choice": "isolate"})
    driver.advance(90000)
    recovery_before = _opportunity(driver.session(), "incident:inc-files:recovery")
    assert recovery_before is not None

    driver.act("browser.support_action", params={"choice": "restore"})
    recovery_after = _opportunity(driver.session(), "incident:inc-files:recovery")
    assert recovery_after is not None
    assert recovery_after.sim_time_ms == recovery_before.sim_time_ms
    result = score(driver)
    assert result.dimensions["recovery_quality"].applicable is True
    assert result.dimensions["recovery_quality"].score > 50


def test_opportunity_identity_and_time_survive_a_resume(tmp_path):
    """E. Save/resume after presentation but before action: same opportunity
    id, same time, same provenance."""
    uri = sqlite_uri(tmp_path, "opp_resume.db")
    service, _ = build_service(uri, ids=["ws-opp-resume"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    before = _opportunity(driver.session(), "mail:m-payroll-restructure")
    assert before is not None

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    after = _opportunity(resumed.session(), "mail:m-payroll-restructure")
    assert after is not None
    assert after.sim_time_ms == before.sim_time_ms
    assert after.dimensions == before.dimensions
    assert after.source == before.source
    assert after.resolving_decisions == before.resolving_decisions


def test_opportunity_ordering_is_stable_across_a_fresh_process(tmp_path):
    """F. Cross-process restore: byte-equivalent opportunity ordering.

    Independent of ``PYTHONHASHSEED`` or dict/set iteration order -- ordering
    is an explicit sort by ``(sim_time_ms, opportunity_id)``, and identity is
    read from the same persisted mutation history either way."""
    uri = sqlite_uri(tmp_path, "opp_cross_process.db")
    service, _ = build_service(uri, ids=["ws-opp-cross"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    before = [o.to_state() for o in opp.build_opportunities(driver.session())]

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    after = [o.to_state() for o in opp.build_opportunities(resumed.session())]
    assert before == after
