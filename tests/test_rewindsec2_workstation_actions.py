"""Application-layer behaviour for all eight workstation applications.

One section per approved application -- Mail, Files, Browser, Notifications,
Notes, Authenticator, Messages, Directory -- and for each one:

* a valid read or inspection does what it says and marks the right context
  fact observed;
* an invalid target is refused, in the same way, with the same message, so a
  learner cannot probe for what exists;
* invalid parameters are refused before anything is applied;
* a consequential action leaves persisted causal state, not just a changed
  screen;
* nothing partial survives a rejected action.

These run against the service directly rather than through HTTP. The HTTP
layer has its own suite; what is under test here is the *meaning* of an
action, which has nothing to do with requests.
"""

import pytest

from rewindsec.domain.enums import ActionClass
from rewindsec.workstation.actions import ACTION_SPECS, parse_action_request
from rewindsec.workstation.bootstrap import (AUTH_HISTORY_FACT, contact_fact,
                                             conversation_fact, file_fact,
                                             mail_attachment_fact,
                                             mail_body_fact, mail_header_fact,
                                             mail_link_fact, prompt_fact)
from rewindsec.workstation.errors import (InvalidRequestError,
                                          StaleRevisionConflict,
                                          UnknownActionError,
                                          UnknownTargetError)
from tests.workstation_helpers import (Driver, build_service, contact,
                                       conversation, file_row, incident,
                                       message, sqlite_uri)


@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="mixed", mode="simulation")


@pytest.fixture
def practice(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="phishing", mode="practice")


def observed(driver, fact_id):
    ledger = driver.session().ledger
    return ledger.has(fact_id) and ledger.get(fact_id).observed


def available(driver, fact_id):
    ledger = driver.session().ledger
    return ledger.has(fact_id) and ledger.get(fact_id).available


# ===========================================================================
# The action vocabulary itself
# ===========================================================================

def test_every_allowlisted_action_has_a_handler():
    """A spec without a handler is a 500 waiting for a learner to find it."""
    from rewindsec.workstation.service import _HANDLERS
    assert set(ACTION_SPECS) == set(_HANDLERS)


def test_every_action_is_classified_as_the_domain_requires():
    for spec in ACTION_SPECS.values():
        assert spec.classification in (ActionClass.OBSERVATIONAL,
                                       ActionClass.CONSEQUENTIAL), spec.action_type


def test_an_action_outside_the_allowlist_is_refused(driver):
    with pytest.raises(UnknownActionError):
        driver.act("mail.incinerate", "m-payslip-aug")


def test_the_recorded_action_log_does_not_keep_learner_text_twice(driver):
    """A reply's text lives in the world; the action log records its length.

    Otherwise deleting a note or a message would leave a copy behind in the
    audit log, which is neither what the learner expects nor what the product
    needs.
    """
    driver.deliver_until("m-headcount")
    driver.act("mail.reply", "m-headcount", {"text": "Forty-one contractors."})
    action = [a for a in driver.session().action_log.actions()
              if a.action_type == "mail.reply"][-1]
    assert action.params["text_length"] == len("Forty-one contractors.")
    assert "Forty-one" not in str(dict(action.params))


# ===========================================================================
# Mail
# ===========================================================================

def test_mail_open_marks_the_message_read_and_observed(driver):
    driver.act("mail.open", "m-payslip-aug")
    entry = message(driver.snapshot(), "m-payslip-aug")
    assert entry["unread"] is False
    assert entry["read"] is True
    assert observed(driver, mail_body_fact("m-payslip-aug"))


def test_mail_actions_refuse_an_undelivered_message(driver):
    """Not yet delivered is not a target, however real the content is."""
    with pytest.raises(UnknownTargetError):
        driver.act("mail.open", "m-payroll-restructure")


def test_mail_actions_refuse_an_invented_message(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("mail.open", "m-does-not-exist")


def test_mail_inspect_link_refuses_an_index_that_is_not_there(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("mail.inspect_link", "m-payslip-aug", {"index": 9})


def test_mail_inspect_link_refuses_a_non_integer_index(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("mail.inspect_link", "m-payslip-aug", {"index": "0"})


def test_mail_inspect_headers_observes_the_header_fact(driver):
    assert available(driver, mail_header_fact("m-payslip-aug"))
    assert not observed(driver, mail_header_fact("m-payslip-aug"))
    driver.act("mail.inspect_headers", "m-payslip-aug")
    assert observed(driver, mail_header_fact("m-payslip-aug"))


def test_mail_report_moves_the_message_and_records_a_decision(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")

    entry = message(driver.snapshot(), "m-payroll-restructure")
    assert entry["folder"] == "reported"
    assert entry["reported"] is True

    session = driver.session()
    assert session.world.has("decisions", "d-phish-report")


def test_reporting_genuine_work_is_recorded_as_its_own_decision(driver):
    """Over-suspicion has a consequence too. It is not a free action."""
    driver.act("mail.report", "m-payslip-aug")
    assert driver.session().world.has("decisions", "d-report-legitimate")


def test_mail_delete_moves_the_message_without_destroying_it(driver):
    driver.act("mail.delete", "m-benefits")
    entry = message(driver.snapshot(), "m-benefits")
    assert entry["folder"] == "deleted"


def test_mail_reply_lands_in_sent_as_plain_text(driver):
    driver.deliver_until("m-headcount")
    result = driver.act("mail.reply", "m-headcount",
                        {"text": "Confirmed: 41 <b>contractors</b>."})
    sent = [m for m in result.snapshot["mail"]["messages"] if m["folder"] == "sent"]
    assert sent
    # Stored verbatim and rendered as text by the client. Never interpreted.
    assert sent[0]["body"] == ["Confirmed: 41 <b>contractors</b>."]
    assert message(result.snapshot, "m-headcount")["replied"] is True


def test_mail_reply_refuses_text_beyond_the_bound(driver):
    driver.deliver_until("m-headcount")
    with pytest.raises(InvalidRequestError):
        driver.act("mail.reply", "m-headcount", {"text": "x" * 5000})


#: Downloading an attachment mints a file id derived from the message and the
#: attachment index, so a test can name it without guessing.
DOWNLOADED_RATE_CARD = "f-dl-m-rate-card-0"


def test_downloading_an_attachment_creates_a_real_file(driver):
    driver.deliver_until("m-rate-card")
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD) is None

    result = driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    entry = file_row(result.snapshot, DOWNLOADED_RATE_CARD)
    assert entry is not None
    assert entry["location"] == "loc-downloads"
    assert entry["state"] == "downloaded"
    # The macro flag is visible evidence a real mail client also shows.
    assert entry["macro"] is True


def test_downloading_the_same_attachment_twice_makes_one_file(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    before = len(driver.snapshot()["files"]["files"])
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    assert len(driver.snapshot()["files"]["files"]) == before


def test_following_a_link_resolves_the_destination_server_side(driver):
    """The client says "the first link"; the server says where it goes."""
    driver.deliver_until("m-payroll-restructure")
    result = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    assert result.notice["url"] == "payroll-northbridge.example/employee/verify"
    assert result.notice["url"] in result.snapshot["browser"]["pages"]


# ===========================================================================
# Files
# ===========================================================================

def test_files_inspect_observes_the_file_metadata_fact(driver):
    driver.act("files.inspect", "f-ops-notes")
    assert observed(driver, file_fact("f-ops-notes"))


def test_files_actions_refuse_an_unknown_file(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("files.open", "f-not-a-file")


def test_files_rename_refuses_an_empty_name(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("files.rename", "f-ops-notes", {"name": "   "})


def test_files_rename_changes_the_world(driver):
    driver.act("files.rename", "f-ops-notes", {"name": "Ops_Review_v2.docx"})
    assert file_row(driver.snapshot(), "f-ops-notes")["name"] == "Ops_Review_v2.docx"


def test_files_delete_removes_it_from_the_learner_view_but_keeps_the_record(driver):
    driver.act("files.delete", "f-scratch")
    assert file_row(driver.snapshot(), "f-scratch") is None
    # The world still holds it, flagged. Deletion is a fact, not an erasure.
    assert driver.session().world.get("files", "f-scratch")["deleted"] is True


def test_opening_a_downloaded_macro_workbook_starts_the_file_incident(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", DOWNLOADED_RATE_CARD)

    snapshot = driver.advance(120000)
    assert incident(snapshot, "inc-files") is not None
    unusable = [f for f in snapshot["files"]["files"]
                if f["state"] == "unavailable"]
    assert unusable, "no file became unreadable"

    # Synthetic only. No real path is touched, now or ever.
    session = driver.session()
    assert session.incidents.consequences()


def test_a_file_incident_never_reaches_the_host_filesystem():
    """The whole ransomware effect in Batch 2 is a value in a world row.

    Matched as calls rather than as substrings, so a handler legitimately
    named ``_mail_open`` does not read as a call to :func:`open`.
    """
    import inspect
    import re

    from rewindsec.workstation import consequences, service, worldops
    banned = (r"(?<![\w.])open\(", r"os\.remove\(", r"os\.unlink\(",
              r"shutil\.", r"subprocess", r"pathlib",
              r"os\.system\(")
    for module in (worldops, consequences, service):
        source = inspect.getsource(module)
        for pattern in banned:
            assert not re.search(pattern, source), (module.__name__, pattern)


# ===========================================================================
# Browser
# ===========================================================================

def test_browser_navigate_records_the_visit_and_returns_the_page(driver):
    result = driver.act("browser.navigate",
                        params={"url": "intranet.northbridge.example"})
    assert "intranet.northbridge.example" in result.snapshot["browser"]["pages"]


def test_an_address_outside_the_synthetic_network_simply_has_no_page(driver):
    """Not an error, and certainly not a fetch. There is nothing there."""
    result = driver.act("browser.navigate", params={"url": "example.com/anything"})
    assert "example.com/anything" not in result.snapshot["browser"]["pages"]
    assert "example.com/anything" in result.snapshot["browser"]["visited"]


def test_the_browser_refuses_an_address_that_is_not_an_address(driver):
    for bad in ("http://host/../../etc/passwd", "javascript:alert(1)",
                "file:///c:/windows", "host/<script>"):
        with pytest.raises(InvalidRequestError):
            driver.act("browser.navigate", params={"url": bad})


def test_signing_in_never_carries_a_credential(driver):
    """The action has no password parameter, so there is nothing to send.

    The browser clears the field on submit and posts the address alone; what
    is recorded is the decision, not a value.
    """
    spec = ACTION_SPECS["browser.sign_in"]
    assert set(spec.params) == {"url"}

    driver.act("browser.navigate",
               params={"url": "payroll-northbridge.example/employee/verify"})
    with pytest.raises(InvalidRequestError):
        driver.act("browser.sign_in",
                   params={"url": "payroll-northbridge.example/employee/verify",
                           "password": "hunter2"})


def test_signing_in_on_the_lookalike_portal_starts_the_account_incident(driver):
    url = "payroll-northbridge.example/employee/verify"
    driver.act("browser.navigate", params={"url": url})
    driver.act("browser.sign_in", params={"url": url})

    snapshot = driver.advance(120000)
    assert incident(snapshot, "inc-account") is not None

    session = driver.session()
    consequences = session.incidents.consequences()
    assert consequences
    # The causal spine: every consequence names the action that triggered it.
    assert all(c.triggering_action_id for c in consequences)
    # And the world change it produced.
    assert any(c.mutation_ref for c in consequences)


def test_signing_in_on_the_genuine_payroll_portal_just_signs_in(driver):
    url = "payroll.northbridge.example"
    driver.act("browser.navigate", params={"url": url})
    result = driver.act("browser.sign_in", params={"url": url})
    assert result.snapshot["browser"]["pages"][url]["signed_in"] == "done"
    snapshot = driver.advance(120000)
    assert snapshot["incidents"] == []


def test_signing_in_where_there_is_no_sign_in_is_refused(driver):
    driver.act("browser.navigate", params={"url": "intranet.northbridge.example"})
    with pytest.raises(UnknownTargetError):
        driver.act("browser.sign_in", params={"url": "intranet.northbridge.example"})


def test_releasing_a_payment_to_the_account_of_record_is_not_an_incident(driver):
    url = "intranet.northbridge.example/finance/payments"
    driver.act("browser.navigate", params={"url": url})
    page = driver.snapshot()["browser"]["pages"][url]
    driver.act("browser.release_payment",
               params={"url": url, "account": page["invoice"]["account_of_record"]})
    snapshot = driver.advance(120000)
    assert incident(snapshot, "inc-payment") is None


def test_releasing_a_payment_to_a_changed_account_is(driver):
    url = "intranet.northbridge.example/finance/payments"
    driver.act("browser.navigate", params={"url": url})
    driver.act("browser.release_payment",
               params={"url": url, "account": "Aveley Trust Bank . 23-08-71"})
    snapshot = driver.advance(120000)
    assert incident(snapshot, "inc-payment") is not None


def test_the_service_desk_can_take_the_workstation_off_the_network(driver):
    result = driver.act("browser.support_action", params={"choice": "isolate"})
    assert result.snapshot["session"]["network_disconnected"] is True


def test_the_service_desk_refuses_an_action_it_does_not_offer(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("browser.support_action", params={"choice": "reformat"})


# ===========================================================================
# Notifications
# ===========================================================================

def test_opening_a_notification_marks_it_read(driver):
    first = driver.snapshot()["notifications"][0]
    driver.act("notifications.open", first["id"])
    after = [n for n in driver.snapshot()["notifications"] if n["id"] == first["id"]]
    assert after[0]["unread"] is False


def test_marking_all_read_clears_the_badge(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("notifications.mark_read")
    assert all(not n["unread"] for n in driver.snapshot()["notifications"])


def test_an_unknown_notification_is_refused(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("notifications.open", "n-9999")


def test_notifications_are_server_authored(driver):
    """An arrival's notification comes from the server, not the browser.

    Batch 2 asserted this by calling ``deliver_next`` and requiring that a
    notification appeared, which worked because the authored timeline always
    delivered something. The engine may legitimately evaluate and select
    nothing, so requiring an arrival from a pulse would now be asserting that
    a lottery was won -- a test that passes for the wrong reason today and
    flakes tomorrow.

    So the arrival is named, and the assertion is *stronger* than before: the
    notification exists, it names the sender and subject the server holds, and
    it carries the server's own routing target. None of that came from a
    browser, and none of it could have.
    """
    before = {n["id"] for n in driver.snapshot()["notifications"]}
    driver.deliver_until("m-payroll-restructure")
    after = [n for n in driver.snapshot()["notifications"]
             if n["id"] not in before]
    assert after, "the arrival raised no notification"
    raised = after[-1]
    assert raised["kind"] == "mail"
    assert raised["opens"] == {"app": "mail", "mail_id": "m-payroll-restructure"}
    assert raised["unread"] is True


# ===========================================================================
# Notes
# ===========================================================================

def test_a_note_persists_what_the_learner_wrote(driver):
    result = driver.act("notes.create")
    note_id = result.notice["note"]
    driver.act("notes.save", note_id,
               {"title": "Checks", "body": "Payroll host is payroll.northbridge.example"})
    saved = [n for n in driver.snapshot()["notes"] if n["id"] == note_id][0]
    assert saved["title"] == "Checks"
    assert "payroll.northbridge.example" in saved["body"]


def test_a_note_is_stored_as_text_and_never_as_markup(driver):
    """Injection safety starts by not interpreting anything."""
    result = driver.act("notes.create")
    note_id = result.notice["note"]
    payload = "<img src=x onerror=alert(1)><script>alert(2)</script>"
    driver.act("notes.save", note_id, {"title": payload, "body": payload})
    saved = [n for n in driver.snapshot()["notes"] if n["id"] == note_id][0]
    # Stored verbatim; the client renders it with textContent-equivalent
    # escaping, which tests/test_prototype_ui.py holds separately.
    assert saved["body"] == payload


def test_a_note_is_bounded(driver):
    result = driver.act("notes.create")
    note_id = result.notice["note"]
    with pytest.raises(InvalidRequestError):
        driver.act("notes.save", note_id, {"body": "x" * 9000})


def test_a_note_rejects_control_characters(driver):
    result = driver.act("notes.create")
    note_id = result.notice["note"]
    with pytest.raises(InvalidRequestError):
        driver.act("notes.save", note_id, {"body": "a\x00b"})


def test_deleting_a_note_removes_it_from_the_learner_view(driver):
    result = driver.act("notes.create")
    note_id = result.notice["note"]
    driver.act("notes.delete", note_id)
    assert all(n["id"] != note_id for n in driver.snapshot()["notes"])


def test_saving_an_unknown_note_is_refused(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("notes.save", "note-nope", {"body": "x"})


# ===========================================================================
# Authenticator
# ===========================================================================

def pending_request(driver):
    requests = driver.snapshot()["authenticator"]["requests"]
    return requests[0] if requests else None


def raise_a_request(driver, limit=10):
    """Get an unsolicited approval request in front of the learner.

    Named rather than waited for, for the same reason ``deliver_until`` is:
    under the training engine a phishing-focused session may never draw the
    MFA family, and a helper that waited for one would either flake or quietly
    stop testing anything.
    """
    entry = pending_request(driver)
    if entry:
        return entry
    driver.force("cand-mfa-unsolicited")
    entry = pending_request(driver)
    if entry:
        return entry
    for _ in range(limit):
        entry = pending_request(driver)
        if entry:
            return entry
        driver.deliver_next()
    raise AssertionError("no approval request arrived")


def test_inspecting_an_approval_request_observes_its_context(driver):
    entry = raise_a_request(driver)
    prompt_id = driver.session().world.get("auth_requests", entry["id"])["prompt_id"]
    assert not observed(driver, prompt_fact(prompt_id))
    driver.act("auth.inspect_request", entry["id"])
    assert observed(driver, prompt_fact(prompt_id))


def test_checking_the_approval_history_observes_it(driver):
    assert not observed(driver, AUTH_HISTORY_FACT)
    driver.act("auth.inspect_history")
    assert observed(driver, AUTH_HISTORY_FACT)
    assert driver.snapshot()["authenticator"]["history_observed"] is True


def test_approving_an_unexpected_request_starts_the_account_incident(driver):
    entry = raise_a_request(driver)
    prompt_id = driver.session().world.get("auth_requests", entry["id"])["prompt_id"]
    driver.act("auth.approve", entry["id"])
    snapshot = driver.advance(120000)
    if prompt_id == "mfa-unexpected":
        assert incident(snapshot, "inc-account") is not None
    else:
        assert snapshot["session"]["vpn_connected"] is True


def test_a_resolved_request_cannot_be_resolved_again(driver):
    entry = raise_a_request(driver)
    driver.act("auth.deny", entry["id"])
    with pytest.raises(UnknownTargetError):
        driver.act("auth.approve", entry["id"])


def test_an_invented_request_id_is_refused(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("auth.approve", "req-9999")


def test_approve_and_deny_are_the_same_shape_of_action():
    """Neither is privileged in the vocabulary, as neither is on screen."""
    assert (ACTION_SPECS["auth.approve"].classification
            == ACTION_SPECS["auth.deny"].classification)
    assert (ACTION_SPECS["auth.approve"].params
            == ACTION_SPECS["auth.deny"].params)


# ===========================================================================
# Messages
# ===========================================================================

def test_opening_a_conversation_marks_it_read_and_observed(driver):
    driver.act("messages.open", "conv-tom-brennan")
    assert observed(driver, conversation_fact("conv-tom-brennan"))
    assert conversation(driver.snapshot(), "conv-tom-brennan")["unread"] is False


def test_sending_a_message_appends_it_as_text(driver):
    result = driver.act("messages.send", "conv-tom-brennan",
                        {"text": "Back in ten <b>minutes</b>"})
    entries = conversation(result.snapshot, "conv-tom-brennan")["entries"]
    assert entries[-1]["text"] == "Back in ten <b>minutes</b>"
    assert entries[-1]["from"] == result.snapshot["learner"]["name"]


def test_a_message_cannot_be_sent_to_someone_who_is_not_there(driver):
    """No arbitrary recipient: the conversation has to already exist."""
    with pytest.raises(UnknownTargetError):
        driver.act("messages.send", "conv-attacker", {"text": "hello"})


def test_a_message_is_bounded(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("messages.send", "conv-tom-brennan", {"text": "x" * 2000})


def test_verifying_on_a_known_channel_produces_a_real_reply(driver):
    driver.deliver_until("m-payroll-restructure")
    result = driver.act("messages.verify", "conv-priya-menon")
    entries = conversation(result.snapshot, "conv-priya-menon")["entries"]
    assert len(entries) >= 2
    assert conversation(result.snapshot, "conv-priya-menon")["verify_prompt"] is None
    assert driver.session().world.has("decisions", "d-phish-verify")


def test_verification_only_counts_for_something_still_in_front_of_you(driver):
    """Checking with payroll about a message already reported is not the same act."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.act("messages.verify", "conv-priya-menon")
    assert not driver.session().world.has("decisions", "d-phish-verify")


def test_verifying_where_there_is_nothing_to_verify_is_refused(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("messages.verify", "conv-tom-brennan")


# ===========================================================================
# Directory
# ===========================================================================

def test_opening_a_contact_observes_the_directory_record(driver):
    driver.act("directory.open", "dir-marcus-hale")
    assert observed(driver, contact_fact("dir-marcus-hale"))


def test_calling_a_contact_reveals_what_they_say(driver):
    result = driver.act("directory.call", "dir-marcus-hale")
    assert contact(result.snapshot, "dir-marcus-hale")["call_result"]


def test_calling_a_contact_with_no_number_is_refused(driver):
    with_number = {c["id"] for c in driver.snapshot()["directory"] if c["can_call"]}
    without = [c["id"] for c in driver.snapshot()["directory"]
               if c["id"] not in with_number]
    if not without:
        pytest.skip("every authored contact has a callback")
    with pytest.raises(UnknownTargetError):
        driver.act("directory.call", without[0])


def test_an_unknown_contact_is_refused(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("directory.open", "dir-nobody")


def test_calling_the_supplier_about_a_live_account_change_is_verification(driver):
    driver.deliver_until("m-invoice-amend")
    driver.act("directory.call", "dir-calderwood")
    assert driver.session().world.has("decisions", "d-bec-verify")


# ===========================================================================
# Stale revisions and partial application
# ===========================================================================

def test_a_stale_revision_is_refused_and_changes_nothing(driver):
    driver.act("mail.open", "m-payslip-aug")
    stale = driver.revision - 1
    before = driver.session().capture_state()

    with pytest.raises(StaleRevisionConflict) as caught:
        driver.act("mail.report", "m-benefits", revision=stale)

    assert caught.value.detail["revision"] == driver.revision
    assert driver.session().capture_state() == before


def test_a_replayed_action_cannot_apply_its_consequence_twice(driver):
    """The lost-response case: the browser retries what already succeeded."""
    driver.deliver_until("m-payroll-restructure")
    revision = driver.revision
    driver.act("mail.report", "m-payroll-restructure", revision=revision)
    decisions_after_first = len(driver.session().world.get_component("decisions"))

    with pytest.raises(StaleRevisionConflict):
        driver.act("mail.report", "m-payroll-restructure", revision=revision)

    assert len(driver.session().world.get_component("decisions")) \
        == decisions_after_first


def test_a_rejected_action_leaves_no_persisted_trace(driver):
    """Validation failures do not half-apply, and do not consume a sequence."""
    before = driver.session().capture_state()
    with pytest.raises(UnknownTargetError):
        driver.act("files.open", "f-nope")
    assert driver.session().capture_state() == before


def test_the_same_decision_is_never_recorded_twice(driver):
    """Reporting the same message twice is one act, so one chain."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    scheduled = len(driver.session().scheduler.pending())
    driver.act("mail.report", "m-payroll-restructure")
    assert len(driver.session().scheduler.pending()) == scheduled


# ===========================================================================
# Lifecycle
# ===========================================================================

def test_a_finished_session_refuses_further_actions(driver):
    from rewindsec.workstation.errors import SessionEndedError

    driver.service.end_session(driver.session_id, driver.learner_ref)
    with pytest.raises(SessionEndedError):
        driver.act("mail.open", "m-benefits")


def test_ending_a_session_preserves_every_fact(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    before = driver.snapshot()

    driver.service.end_session(driver.session_id, driver.learner_ref)
    after = driver.snapshot()

    assert after["session"]["status"] == "completed"
    assert after["session"]["active"] is False
    assert len(after["mail"]["messages"]) == len(before["mail"]["messages"])
    assert message(after, "m-payroll-restructure")["folder"] == "reported"
    assert driver.session().action_log.actions()
    assert driver.session().event_log.events()


def test_ending_twice_is_harmless(driver):
    driver.service.end_session(driver.session_id, driver.learner_ref)
    snapshot = driver.service.end_session(driver.session_id, driver.learner_ref)
    assert snapshot["session"]["status"] == "completed"
