"""The four threat families, end to end, plus the ordinary work around them.

One section per family. Each asserts the same four things in its own terms:

* the family's candidates become eligible for the right reasons and not before;
* the learner can act on them through the workstation actions that already
  exist, and the evidence they gather is recorded in the Context Ledger;
* unsafe and over-suspicious paths both produce factual consequences that
  persist -- nothing is rewound, and nothing is free;
* none of the family's hidden truth reaches the learner's document.

The last section covers ordinary work, which is not a threat family and is the
reason the other four mean anything: a mailbox containing only attacks makes
"report everything" correct.
"""

import io
import json

import pytest

from rewindsec.core.rng import STREAM_BACKGROUND, STREAM_CONTENT_VARIATION
from rewindsec.training import catalog, eligibility, policy
from rewindsec.training import state as engine_state
from rewindsec.workstation.bootstrap import (NS_DECISIONS, NS_SESSION,
                                             mail_body_fact, prompt_fact)
from tests.training_helpers import fresh_session, pulses, selections
from tests.workstation_helpers import (Driver, build_service, conversation,
                                       file_row, incident, message,
                                       sqlite_uri, walk)


@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path, "families.db"),
                               ids=["ws-families"])
    return Driver.start(service, focus="mixed", mode="simulation")


def practice(tmp_path, name, focus="mixed"):
    service, repository = build_service(sqlite_uri(tmp_path, name),
                                        ids=["ws-%s" % name])
    return Driver.start(service, focus=focus, mode="practice"), repository


def assessment(tmp_path, name, focus="mixed"):
    service, repository = build_service(sqlite_uri(tmp_path, name),
                                        ids=["ws-%s" % name])
    return Driver.start(service, focus=focus, mode="assessment"), repository


def decisions(driver):
    return set(driver.session().world.get_component(NS_DECISIONS))


def observed(driver, fact_id):
    ledger = driver.session().ledger
    return ledger.has(fact_id) and ledger.get(fact_id).observed


def eligible_ids(session, focus="mixed"):
    out = []
    for candidate in catalog.all_candidates():
        verdict = eligibility.evaluate(
            session, candidate,
            engine_state.family_state(session, candidate.family),
            session.now_ms, focus, None, False)
        if verdict.eligible:
            out.append(candidate.candidate_id)
    return out


def reasons_for(session, candidate_id, focus="mixed"):
    candidate = catalog.by_id(candidate_id)
    return eligibility.evaluate(
        session, candidate,
        engine_state.family_state(session, candidate.family),
        session.now_ms, focus, None, False).reasons


# ===========================================================================
# Phishing
# ===========================================================================

def test_the_phishing_lure_needs_the_genuine_payroll_domain_to_exist():
    """An AVAILABLE prerequisite, and the reason it is AVAILABLE not OBSERVED.

    ``payroll-northbridge.example`` is only recognisable as a look-alike if
    ``payroll.northbridge.example`` is somewhere in this workplace. It does not
    require the learner to have *noticed* it -- gating on attention would let
    an inattentive learner opt out of the hard events entirely.
    """
    session = fresh_session()
    fact = session.ledger.get("org.payroll_host")
    assert fact.available and not fact.observed
    assert "cand-phish-payroll-lure" in eligible_ids(session)


def test_the_phishing_lure_is_locked_when_the_genuine_domain_is_not_available():
    session = fresh_session()
    # A workplace in which the payslip notice never arrived, built by editing
    # the captured state rather than by deleting content -- the point is the
    # engine's reaction to an unavailable fact, not how it became unavailable.
    state = session.capture_state()
    for fact in state["ledger"]["facts"]:
        if fact["fact_id"] == "org.payroll_host":
            fact["available"] = False
            fact["available_at_ms"] = None
    stripped = type(session).from_state(state)
    assert "missing_fact" in reasons_for(stripped, "cand-phish-payroll-lure")
    assert "cand-phish-payroll-lure" not in eligible_ids(stripped)


def test_the_phishing_family_offers_a_legitimate_comparison_message():
    session = fresh_session()
    ids = eligible_ids(session)
    assert "cand-phish-payroll-genuine" in ids
    assert not catalog.by_id("cand-phish-payroll-genuine").hostile


def test_evidence_on_a_phishing_message_is_absent_until_it_is_gathered(driver):
    driver.deliver_until("m-payroll-restructure")
    before = message(driver.snapshot(), "m-payroll-restructure")
    # Absent, not flagged: the header block and the link's real destination are
    # simply not in the document until the learner goes and looks.
    assert before["headers"] is None
    assert before["links"][0]["href"] is None

    driver.act("mail.open", "m-payroll-restructure")
    driver.act("mail.inspect_headers", "m-payroll-restructure")
    driver.act("mail.inspect_link", "m-payroll-restructure", {"index": 0})
    after = message(driver.snapshot(), "m-payroll-restructure")
    assert after["headers"]["from_address"]
    assert after["links"][0]["href"]


def test_reporting_a_phishing_message_is_recorded_and_acted_on(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    assert "d-phish-report" in decisions(driver)
    driver.advance(60000)
    assert conversation(driver.snapshot(), "conv-lena-fischer")["entries"]


def test_verifying_on_a_known_channel_is_recorded_as_verification(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    driver.act("messages.verify", "conv-priya-menon")
    assert "d-phish-verify" in decisions(driver)


def test_a_credential_submission_produces_a_persistent_consequence_chain(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})
    assert "d-phish-credentials" in decisions(driver)

    driver.advance(200000)
    snapshot = driver.snapshot()
    assert incident(snapshot, "inc-account") is not None
    # The mailbox rule, the alert it hides, and the colleague who was written to.
    assert driver.session().world.get("mailbox", "rule")
    assert conversation(snapshot, "conv-tom-brennan")["entries"]


def test_no_credential_value_is_ever_accepted_recorded_or_stored(driver):
    """There is no parameter a credential could arrive in, so none is stored.

    Asserted structurally rather than by searching the stored state for the
    word "password" -- the mailbox legitimately contains a message *about* a
    password change, and a test that failed on that would be measuring the
    content rather than the boundary.
    """
    from rewindsec.workstation.actions import ACTION_SPECS

    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})

    # The sign-in action takes an address. That is the whole of its surface.
    assert sorted(ACTION_SPECS["browser.sign_in"].params) == ["url"]
    assert sorted(ACTION_SPECS["browser.sign_in_retry"].params) == ["url"]

    # And nothing anywhere in the allowlist accepts a secret.
    for spec in ACTION_SPECS.values():
        for name in spec.params:
            assert name not in ("password", "passphrase", "secret", "otp",
                                "token", "pin"), (spec.action_type, name)

    # The recorded action for the sign-in carries the address and nothing else.
    signin = [a for a in driver.session().action_log.actions()
              if a.action_type == "browser.sign_in"]
    assert len(signin) == 1
    assert set((signin[0].params or {})) <= {"url"}


def test_a_compromised_account_makes_a_follow_up_approval_request_eligible():
    """Cross-family causality expressed as a fact, not as a hard-coded trigger."""
    session = fresh_session()
    assert "cand-mfa-after-compromise" not in eligible_ids(session)
    assert "prerequisite_missing" in reasons_for(session, "cand-mfa-after-compromise")

    from rewindsec.workstation import worldops
    worldops.open_incident(session, "inc-account", "Account access", "note")
    assert "cand-mfa-after-compromise" in eligible_ids(session)


def test_resuming_mid_phishing_chain_keeps_the_chain(tmp_path):
    uri = sqlite_uri(tmp_path, "phish-resume.db")
    service, repository = build_service(uri, ids=["ws-phish-resume"])
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})

    rebuilt, rebuilt_repo = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    resumed.advance(200000)
    assert incident(resumed.snapshot(), "inc-account") is not None


def test_assessment_leaks_no_correctness_after_a_phishing_decision(tmp_path):
    driver, _ = assessment(tmp_path, "phish-assess.db", focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    result = driver.act("browser.sign_in", params={"url": followed.notice["url"]})
    assert result.notice is None
    driver.advance(300000)
    snapshot = driver.snapshot()
    assert snapshot["comparison"] is None
    assert snapshot["session"]["flags"]["safer_alternative"] is False
    # The consequence still happened. It is simply not commented on.
    assert incident(snapshot, "inc-account") is not None


# ===========================================================================
# MFA
# ===========================================================================

def pending_request(driver):
    requests = driver.snapshot()["authenticator"]["requests"]
    return requests[0] if requests else None


def test_an_unsolicited_approval_request_arrives_with_no_learner_action(driver):
    driver.force("cand-mfa-unsolicited")
    entry = pending_request(driver)
    assert entry is not None
    assert entry["details"] is None


def test_a_legitimate_approval_request_follows_the_learners_own_sign_in(driver):
    driver.act("browser.navigate", params={"url": "access.northbridge.example"})
    driver.act("browser.sign_in", params={"url": "access.northbridge.example"})
    entry = pending_request(driver)
    assert entry is not None
    prompt_id = driver.session().world.get("auth_requests", entry["id"])["prompt_id"]
    assert prompt_id == "mfa-vpn"


def test_inspecting_a_request_records_the_evidence_it_revealed(driver):
    driver.force("cand-mfa-unsolicited")
    entry = pending_request(driver)
    prompt_id = driver.session().world.get("auth_requests", entry["id"])["prompt_id"]
    assert not observed(driver, prompt_fact(prompt_id))
    driver.act("auth.inspect_request", entry["id"])
    assert observed(driver, prompt_fact(prompt_id))


def test_approving_an_unsolicited_request_compromises_the_account(driver):
    driver.force("cand-mfa-unsolicited")
    driver.act("auth.approve", pending_request(driver)["id"])
    assert "d-mfa-approve-hostile" in decisions(driver)
    driver.advance(200000)
    assert incident(driver.snapshot(), "inc-account") is not None


def test_denying_an_unsolicited_request_stops_it(driver):
    driver.force("cand-mfa-unsolicited")
    driver.act("auth.deny", pending_request(driver)["id"])
    assert "d-mfa-deny-hostile" in decisions(driver)
    driver.advance(200000)
    assert incident(driver.snapshot(), "inc-account") is None


def test_approving_the_learners_own_request_completes_their_work(driver):
    driver.act("browser.sign_in", params={"url": "access.northbridge.example"})
    driver.act("auth.approve", pending_request(driver)["id"])
    assert "d-mfa-approve-legit" in decisions(driver)
    snapshot = driver.snapshot()
    assert snapshot["session"]["vpn_connected"] is True
    remote = [t for t in snapshot["tasks"] if t["id"] == "task-remote-access"][0]
    assert remote["state"] == "done"


def test_denying_the_learners_own_request_costs_them_their_session(driver):
    """Over-suspicion has an operational price, and the simulation charges it."""
    driver.act("browser.sign_in", params={"url": "access.northbridge.example"})
    driver.act("auth.deny", pending_request(driver)["id"])
    assert "d-mfa-deny-legit" in decisions(driver)
    driver.advance(200000)
    snapshot = driver.snapshot()
    assert snapshot["session"]["vpn_connected"] is False
    remote = [t for t in snapshot["tasks"] if t["id"] == "task-remote-access"][0]
    assert remote["state"] == "interrupted"


def test_deny_everything_is_not_a_free_strategy(driver):
    """The two denials are not interchangeable, and the world says so."""
    driver.act("browser.sign_in", params={"url": "access.northbridge.example"})
    driver.act("auth.deny", pending_request(driver)["id"])
    driver.advance(200000)
    driver.force("cand-mfa-unsolicited")
    driver.act("auth.deny", pending_request(driver)["id"])
    driver.advance(200000)
    made = decisions(driver)
    assert {"d-mfa-deny-legit", "d-mfa-deny-hostile"} <= made
    snapshot = driver.snapshot()
    # No security incident from either denial -- and a broken piece of work
    # from one of them.
    assert incident(snapshot, "inc-account") is None
    remote = [t for t in snapshot["tasks"] if t["id"] == "task-remote-access"][0]
    assert remote["state"] == "interrupted"


def test_the_re_authentication_candidate_needs_a_live_remote_session():
    session = fresh_session()
    assert "prerequisite_missing" in reasons_for(session, "cand-mfa-reauth")
    session.mutate_world(NS_SESSION, "vpn_connected", True)
    assert "cand-mfa-reauth" in eligible_ids(session)


def test_the_projection_never_says_whether_a_request_is_legitimate(driver):
    driver.force("cand-mfa-unsolicited")
    driver.act("browser.sign_in", params={"url": "access.northbridge.example"})
    document = driver.snapshot()
    for entry in document["authenticator"]["requests"]:
        assert set(entry) == set(document["authenticator"]["requests"][0])
    text = json.dumps(document)
    for word in ("legitimate", "hostile", "unsolicited", "expected"):
        assert word not in text.lower(), word


def test_an_mfa_decision_survives_a_resume(tmp_path):
    uri = sqlite_uri(tmp_path, "mfa-resume.db")
    service, _ = build_service(uri, ids=["ws-mfa-resume"])
    driver = Driver.start(service, focus="mfa", mode="simulation")
    driver.force("cand-mfa-unsolicited")
    driver.act("auth.approve", pending_request(driver)["id"])

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    resumed.advance(200000)
    assert incident(resumed.snapshot(), "inc-account") is not None


# ===========================================================================
# BEC
# ===========================================================================

def test_the_bec_request_needs_the_learner_to_have_read_the_real_thread():
    """The OBSERVED prerequisite, and the reason it is OBSERVED not AVAILABLE.

    The hostile message is a *reply* into an existing supplier thread. A reply
    to a conversation the learner has never opened is a message from nowhere,
    and its "Re:" is a claim about something that, from where the learner is
    sitting, did not happen.
    """
    session = fresh_session()
    fact = session.ledger.get(mail_body_fact("m-vendor-invoice"))
    assert fact.available and not fact.observed
    assert "fact_not_observed" in reasons_for(session, "cand-bec-account-change")
    assert "cand-bec-account-change" not in eligible_ids(session)


def test_reading_the_invoice_thread_unlocks_the_bec_request(driver):
    session = driver.session()
    assert "cand-bec-account-change" not in eligible_ids(session)
    driver.act("mail.open", "m-vendor-invoice")
    assert "cand-bec-account-change" in eligible_ids(driver.session())


def test_the_account_of_record_is_only_required_to_be_available():
    """Looking it up is the thing being measured, so it cannot be a precondition."""
    session = fresh_session()
    fact = session.ledger.get("org.vendor_account")
    assert fact.available and not fact.observed
    prereqs = catalog.by_id("cand-bec-account-change").prerequisites
    account = [p for p in prereqs if p.ref == "org.vendor_account"][0]
    assert account.kind == eligibility.FACT_AVAILABLE


def test_releasing_a_payment_to_the_changed_account_is_consequential(driver):
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.act("mail.open", "m-invoice-amend")
    driver.act("browser.navigate",
               params={"url": "intranet.northbridge.example/finance/payments"})
    driver.act("browser.release_payment", params={
        "url": "intranet.northbridge.example/finance/payments",
        "account": "Aveley Trust Bank - 23-08-71 - ending 9032"})
    assert "d-bec-authorize" in decisions(driver)

    driver.advance(200000)
    snapshot = driver.snapshot()
    assert incident(snapshot, "inc-payment") is not None
    # Finance query it, and the real supplier is still waiting.
    assert conversation(snapshot, "conv-arjun-rao")["entries"]
    assert message(snapshot, "m-vendor-chase") is not None


def test_paying_the_account_of_record_is_ordinary_work(driver):
    driver.act("mail.open", "m-vendor-invoice")
    driver.act("browser.navigate",
               params={"url": "intranet.northbridge.example/finance/payments"})
    page = driver.snapshot()["browser"]["pages"][
        "intranet.northbridge.example/finance/payments"]
    driver.act("browser.release_payment", params={
        "url": "intranet.northbridge.example/finance/payments",
        "account": page["invoice"]["account_of_record"]})
    assert "d-bec-authorize" not in decisions(driver)
    driver.advance(200000)
    assert incident(driver.snapshot(), "inc-payment") is None


def test_known_channel_verification_uses_the_organisations_own_records(driver):
    """Not a number the suspect message supplied -- there is no such path."""
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.act("messages.verify", "conv-arjun-rao")
    assert "d-bec-verify" in decisions(driver)
    assert observed(driver, "directory.dir-arjun-rao.callback")


def test_the_directory_is_a_second_known_channel(driver):
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.act("directory.call", "dir-calderwood")
    assert "d-bec-verify" in decisions(driver)


def test_replying_to_the_requester_is_not_verification(driver):
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.act("mail.reply", "m-invoice-amend", {"text": "Can you confirm?"})
    assert "d-bec-reply" in decisions(driver)
    assert "d-bec-verify" not in decisions(driver)
    driver.advance(200000)
    # The requester confirms their own request, which proves nothing.
    assert message(driver.snapshot(), "m-invoice-confirm") is not None


def test_the_bec_family_offers_an_ordinary_supplier_message_too():
    session = fresh_session()
    assert "cand-bec-legit-po" in eligible_ids(session)
    assert not catalog.by_id("cand-bec-legit-po").hostile


def test_reporting_the_ordinary_supplier_message_has_a_cost(driver):
    """Over-suspicion applied to routine supplier correspondence."""
    driver.deliver_until("m-vendor-po-update")
    driver.act("mail.report", "m-vendor-po-update")
    assert "d-report-legitimate" in decisions(driver)


def test_a_bec_chain_survives_a_resume(tmp_path):
    uri = sqlite_uri(tmp_path, "bec-resume.db")
    service, _ = build_service(uri, ids=["ws-bec-resume"])
    driver = Driver.start(service, focus="bec", mode="simulation")
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.act("browser.release_payment", params={
        "url": "intranet.northbridge.example/finance/payments",
        "account": "Aveley Trust Bank - 23-08-71 - ending 9032"})

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    resumed.advance(200000)
    assert incident(resumed.snapshot(), "inc-payment") is not None


def test_no_bec_label_reaches_the_learner(driver):
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.deliver_until("m-vendor-po-update")
    document = driver.snapshot()
    text = json.dumps(document).lower()
    for word in ("bec", "business email compromise", "invoice fraud"):
        assert word not in text, word
    hostile = message(document, "m-invoice-amend")
    ordinary = message(document, "m-vendor-po-update")
    assert set(hostile) == set(ordinary)


# ===========================================================================
# Ordinary work
# ===========================================================================

def test_benign_workplace_activity_exists_and_is_selected():
    session = fresh_session(focus="phishing", seed=200)
    chosen = selections(pulses(session, 40))
    assert any(family == policy.BACKGROUND_FAMILY for family, _ in chosen)


def test_background_activity_draws_from_the_background_stream():
    session = fresh_session(focus="mixed", seed=201)
    pulses(session, 20)
    assert session.rng.has_stream(STREAM_BACKGROUND)
    assert session.rng.stream(STREAM_BACKGROUND).draws > 0


def test_ordinary_work_is_not_labelled_as_ordinary(driver):
    driver.deliver_until("m-facilities-notice")
    driver.deliver_until("m-payroll-restructure")
    document = driver.snapshot()
    benign = message(document, "m-facilities-notice")
    hostile = message(document, "m-payroll-restructure")
    assert set(benign) == set(hostile)
    for path, value in walk(document):
        if isinstance(value, str):
            assert value.strip().lower() not in ("benign", "legitimate", "safe"), path


def test_chatter_varies_from_the_content_stream_alone():
    """Adding a line to the chatter list must not move anything else."""
    session = fresh_session(focus="mixed", seed=202)
    pulses(session, 40)
    if not session.rng.has_stream(STREAM_CONTENT_VARIATION):
        pytest.skip("no ambient activity was selected in this run")
    assert session.rng.stream(STREAM_CONTENT_VARIATION).draws > 0


def test_a_legitimate_task_can_be_mishandled(driver):
    """Reporting a genuine request from a manager is a decision with a result."""
    driver.deliver_until("m-headcount")
    driver.act("mail.report", "m-headcount")
    assert "d-report-legitimate" in decisions(driver)
    driver.advance(200000)
    snapshot = driver.snapshot()
    headcount = [t for t in snapshot["tasks"] if t["id"] == "task-headcount"][0]
    assert headcount["state"] == "outstanding"
    assert conversation(snapshot, "conv-marcus-hale")["entries"]


def test_answering_the_legitimate_task_completes_it(driver):
    driver.deliver_until("m-headcount")
    driver.act("mail.reply", "m-headcount", {"text": "Fourteen contractors."})
    assert "d-task-headcount-done" in decisions(driver)
    driver.advance(200000)
    headcount = [t for t in driver.snapshot()["tasks"]
                 if t["id"] == "task-headcount"][0]
    assert headcount["state"] == "done"


def test_no_score_is_computed_anywhere_in_this_batch(driver):
    """Scoring is Batch 4's. Nothing here may quietly start keeping one."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.advance(200000)
    state = driver.session().capture_state()
    for path, value in walk(state):
        assert not path.endswith(".score"), path
    document = driver.snapshot()
    assert "score" not in json.dumps(document).lower().replace("scored", "")


# ===========================================================================
# Opening a file says what actually happened
# ===========================================================================

def test_opening_an_ordinary_file_does_not_claim_a_viewer_that_does_not_exist(
        driver):
    """Batch 2 answered every open with "Opened in the document viewer."

    Nothing was rendered, nothing was parsed, and no such surface existed. A
    synthetic workstation may show a learner a synthetic document; it may not
    tell them it did something it did not do, because the whole exercise
    depends on what is on screen being reliable.

    The real read-only document viewer is Batch 4's, alongside the synthetic
    content work it needs. Until then an open reports what the file is.
    """
    driver.act("files.open", "f-ops-notes")
    latest = driver.snapshot()["notifications"][0]
    assert "document viewer" not in latest["body"].lower()
    assert "no preview available" in latest["body"].lower()


def test_opening_a_file_records_that_its_metadata_was_seen(driver):
    """An open is an inspection, and the ledger says so."""
    assert not observed(driver, "file.f-ops-notes.metadata")
    driver.act("files.open", "f-ops-notes")
    assert observed(driver, "file.f-ops-notes.metadata")


def test_opening_an_unreadable_file_says_it_cannot_be_read(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    driver.advance(400000)
    unreadable = [row for row in driver.snapshot()["files"]["files"]
                  if row["state"] == "unavailable"]
    assert unreadable
    driver.act("files.open", unreadable[0]["id"])
    latest = driver.snapshot()["notifications"][0]
    assert "cannot open" in latest["title"].lower()


def test_no_module_claims_a_document_viewer_exists():
    """Belt and braces: the claim is gone from the product, not just the path.

    Comment lines are stripped first. The modules that removed the claim
    legitimately explain *why* they removed it, and a test that failed on the
    explanation would push the reasoning out of the code.
    """
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    for module in ("rewindsec/workstation/service.py",
                   "rewindsec/workstation/projection.py",
                   "static/prototype/workstation.js"):
        lines = io.open(root / module, encoding="utf-8").read().splitlines()
        code = [line for line in lines
                if not line.lstrip().startswith(("#", "//", "*", "/*"))]
        text = chr(10).join(code).lower()
        assert "opened in the document viewer" not in text, module
