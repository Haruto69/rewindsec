"""RewindSec 2.0 Batch 4 review correction: live, multi-family content breadth.

The first correction pass added one live background candidate and left every
threat family (phishing, BEC, MFA, ransomware) with exactly the one-shot
surface Batch 3 shipped. This suite covers the second correction: genuinely
new, independently-scored threat surfaces wired into the live training
engine, each with its own opportunity, decision quad, and evidence -- so a
session's meaningful security content no longer runs out after one hostile
mail per family.
"""

from rewindsec.core.rng import (STREAM_CONSEQUENCE, STREAM_THREAT_SELECTION,
                                STREAM_TIMING)
from rewindsec.scoring import evaluator
from rewindsec.scoring import opportunities as opp
from rewindsec.training import catalog, eligibility
from rewindsec.training import state as engine_state
from tests.workstation_helpers import Driver, build_service, sqlite_uri


def driver_for(tmp_path, name="breadth.db", focus="mixed", mode="simulation"):
    service, _ = build_service(sqlite_uri(tmp_path, name))
    return Driver.start(service, focus=focus, mode=mode)


def score(driver):
    driver.service.end_session(driver.session_id, driver.learner_ref)
    return evaluator.evaluate(driver.session())


def _has(driver, mail_id):
    return any(m["id"] == mail_id for m in driver.snapshot()["mail"]["messages"])


# ---------------------------------------------------------------------------
# Phishing: a second, independently-scored lure
# ---------------------------------------------------------------------------

def test_the_benefits_lure_is_a_live_catalogue_candidate():
    candidate = catalog.by_id("cand-phish-benefits-lure")
    assert candidate is not None
    assert candidate.family == "phishing"
    assert candidate.hostile is True
    assert candidate.content_ref == "m-benefits-verify"


def test_forcing_the_benefits_lure_delivers_a_distinct_hostile_mail(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.force("cand-phish-benefits-lure")
    assert _has(driver, "m-benefits-verify")
    opportunities = opp.build_opportunities(driver.session())
    assert any(o.opportunity_id == "mail:m-benefits-verify" for o in opportunities)


def test_reporting_the_benefits_lure_is_independently_scored(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.force("cand-phish-benefits-lure")
    driver.act("mail.report", "m-benefits-verify")
    result = score(driver)
    assert result.dimensions["security_judgment"].score > 50


def test_ignoring_the_benefits_lure_is_negative_not_na(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.force("cand-phish-benefits-lure")
    result = score(driver)
    assert result.dimensions["security_judgment"].applicable is True
    assert result.dimensions["security_judgment"].score < 50


def test_verifying_the_benefits_lure_on_a_known_channel_is_positive(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.force("cand-phish-benefits-lure")
    driver.act("directory.call", "dir-sofia-lindqvist")
    result = score(driver)
    assert result.dimensions["verification_discipline"].applicable
    assert result.dimensions["verification_discipline"].score > 50


def test_submitting_credentials_on_the_benefits_lure_is_negative(tmp_path):
    driver = driver_for(tmp_path, focus="phishing")
    driver.force("cand-phish-benefits-lure")
    driver.act("mail.open", "m-benefits-verify")
    nav = driver.act("mail.open_link", "m-benefits-verify", {"index": 0})
    driver.act("browser.sign_in", params={"url": nav.notice["url"]})
    result = score(driver)
    assert result.dimensions["security_judgment"].score < 50


def test_both_phishing_lures_can_appear_in_one_session_independently(tmp_path):
    """The two lures are genuinely independent opportunities: acting on one
    does not resolve, hide, or double-count the other."""
    driver = driver_for(tmp_path, "both_lures.db", focus="phishing")
    driver.force("cand-phish-payroll-lure")
    driver.force("cand-phish-benefits-lure")
    driver.act("mail.report", "m-payroll-restructure")
    # m-benefits-verify is left untouched.
    result = score(driver)
    opportunities = opp.build_opportunities(driver.session())
    mail_opportunity_ids = {o.opportunity_id for o in opportunities
                            if o.opportunity_type == "mail"}
    assert mail_opportunity_ids == {"mail:m-payroll-restructure",
                                    "mail:m-benefits-verify"}
    security = result.dimensions["security_judgment"]
    assert security.applicable is True
    codes = [e[0] for e in security.explanations]
    assert any(c.startswith("decision:safe:d-phish-report") for c in codes)
    assert any(c.startswith("opportunity_ignored:mail:security_judgment") for c in codes)


# ---------------------------------------------------------------------------
# BEC: a second, independently-scored vendor relationship
# ---------------------------------------------------------------------------

def test_the_meridian_bec_candidate_is_a_live_catalogue_candidate():
    candidate = catalog.by_id("cand-bec2-account-change")
    assert candidate is not None
    assert candidate.family == "bec"
    assert candidate.hostile is True
    assert candidate.content_ref == "m-meridian-amend"


def _is_eligible(session, candidate_id, focus="bec"):
    candidate = catalog.by_id(candidate_id)
    verdict = eligibility.evaluate(
        session, candidate, engine_state.family_state(session, candidate.family),
        session.now_ms, focus, None, False)
    return verdict.eligible


def test_meridian_bec_needs_the_original_thread_observed(tmp_path):
    """Same OBSERVED-gating fairness rule as the Calderwood candidate: a
    reply nobody has opened the original thread for should not be eligible."""
    driver = driver_for(tmp_path, "meridian_gate.db", focus="bec")
    assert _is_eligible(driver.session(), "cand-bec2-account-change") is False
    driver.act("mail.open", "m-meridian-invoice")
    assert _is_eligible(driver.session(), "cand-bec2-account-change") is True


def test_meridian_bec_is_independently_scored(tmp_path):
    driver = driver_for(tmp_path, "meridian_score.db", focus="bec")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force("cand-bec2-account-change")
    assert _has(driver, "m-meridian-amend")
    driver.act("directory.call", "dir-meridian")
    result = score(driver)
    assert result.dimensions["verification_discipline"].applicable
    assert result.dimensions["verification_discipline"].score > 50


def test_releasing_meridian_payment_to_the_new_account_is_negative(tmp_path):
    driver = driver_for(tmp_path, "meridian_release.db", focus="bec")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force("cand-bec2-account-change")
    driver.act("browser.navigate",
              params={"url": "intranet.northbridge.example/finance/payments-meridian"})
    driver.act("browser.release_payment",
              params={"url": "intranet.northbridge.example/finance/payments-meridian",
                      "account": "Corvane Bank · ending 3384"})
    result = score(driver)
    assert result.dimensions["security_judgment"].score < 50


def test_ignoring_the_meridian_lure_is_negative_not_na(tmp_path):
    driver = driver_for(tmp_path, "meridian_ignore.db", focus="bec")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force("cand-bec2-account-change")
    result = score(driver)
    assert result.dimensions["security_judgment"].applicable is True
    assert result.dimensions["security_judgment"].score < 50


def test_calderwood_and_meridian_bec_surfaces_score_independently(tmp_path):
    driver = driver_for(tmp_path, "both_bec.db", focus="bec")
    driver.act("mail.open", "m-vendor-invoice")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force("cand-bec-account-change")
    driver.force("cand-bec2-account-change")
    driver.act("mail.report", "m-invoice-amend")
    # m-meridian-amend left untouched.
    result = score(driver)
    opportunities = opp.build_opportunities(driver.session())
    mail_ids = {o.opportunity_id for o in opportunities if o.opportunity_type == "mail"}
    assert "mail:m-invoice-amend" in mail_ids
    assert "mail:m-meridian-amend" in mail_ids
    codes = [e[0] for e in result.dimensions["security_judgment"].explanations]
    assert any(c.startswith("decision:safe:d-bec-report") for c in codes)
    assert any(c.startswith("opportunity_ignored:mail:security_judgment") for c in codes)


# ---------------------------------------------------------------------------
# Ransomware: a second lure converging on the same consequence model
# ---------------------------------------------------------------------------

def test_the_audit_checklist_lure_is_a_live_catalogue_candidate():
    candidate = catalog.by_id("cand-ransom-audit-checklist")
    assert candidate is not None
    assert candidate.family == "ransomware"
    assert candidate.hostile is True
    assert candidate.content_ref == "m-audit-checklist"


def _open_audit_checklist(driver):
    driver.force("cand-ransom-audit-checklist")
    driver.act("mail.open", "m-audit-checklist")
    driver.act("mail.download_attachment", "m-audit-checklist", {"index": 0})
    return driver.act("files.open", "f-dl-m-audit-checklist-0")


def test_opening_the_audit_checklist_is_independently_scored(tmp_path):
    driver = driver_for(tmp_path, "audit_open.db", focus="ransomware")
    _open_audit_checklist(driver)
    result = score(driver)
    assert result.dimensions["security_judgment"].score < 50


def test_the_audit_checklist_converges_on_the_same_incident(tmp_path):
    """Both ransomware lures share the same synthetic consequence model --
    the same ``inc-files`` incident and file rows -- rather than each
    inventing a parallel one."""
    from rewindsec.workstation.bootstrap import NS_INCIDENTS

    driver = driver_for(tmp_path, "audit_incident.db", focus="ransomware")
    _open_audit_checklist(driver)
    driver.advance(90000)
    assert driver.session().world.has(NS_INCIDENTS, "inc-files")


def test_reporting_the_audit_checklist_instead_of_opening_is_positive(tmp_path):
    driver = driver_for(tmp_path, "audit_report.db", focus="ransomware")
    driver.force("cand-ransom-audit-checklist")
    driver.act("mail.report", "m-audit-checklist")
    result = score(driver)
    assert result.dimensions["security_judgment"].score > 50


def test_opening_the_original_rate_card_still_resolves_its_own_decision(tmp_path):
    """The generalised ``_files_open``/``_mail_report`` dispatch tables must
    not have changed what the original rate-card lure decides."""
    from rewindsec.workstation.bootstrap import NS_DECISIONS

    driver = driver_for(tmp_path, "rate_card_unchanged.db", focus="ransomware")
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    decisions = set(driver.session().world.get_component(NS_DECISIONS))
    assert "d-ransom-open" in decisions
    assert "d-ransom2-open" not in decisions


# ---------------------------------------------------------------------------
# RNG isolation: forcing an extra candidate does not perturb other streams
# ---------------------------------------------------------------------------

def test_forcing_the_benefits_lure_does_not_perturb_other_streams(tmp_path):
    driver = driver_for(tmp_path, "isolation2.db", focus="mixed")

    def draws():
        session = driver.session()
        return (
            session.rng.stream(STREAM_THREAT_SELECTION).draws,
            session.rng.stream(STREAM_TIMING).draws,
            session.rng.stream(STREAM_CONSEQUENCE).draws,
        )

    before = draws()
    driver.force("cand-phish-benefits-lure")
    after = draws()
    assert before == after
