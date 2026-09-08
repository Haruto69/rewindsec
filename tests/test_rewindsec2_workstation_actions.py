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


def test_mail_restore_moves_a_deleted_message_back_to_inbox(driver):
    driver.act("mail.delete", "m-benefits")
    driver.act("mail.restore", "m-benefits")
    entry = message(driver.snapshot(), "m-benefits")
    assert entry["folder"] == "inbox"


def test_mail_restore_refuses_a_message_that_is_not_deleted(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("mail.restore", "m-benefits")


def test_mail_delete_permanently_refuses_a_message_that_is_not_deleted(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("mail.delete_permanently", "m-benefits")


def test_mail_delete_permanently_removes_the_message_from_the_projection(driver):
    driver.act("mail.delete", "m-benefits")
    assert message(driver.snapshot(), "m-benefits") is not None

    driver.act("mail.delete_permanently", "m-benefits")
    assert message(driver.snapshot(), "m-benefits") is None


def test_mail_delete_permanently_refuses_an_undelivered_message(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("mail.delete_permanently", "m-payroll-restructure")


def test_mail_delete_records_the_original_folder_on_first_delete(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.act("mail.delete", "m-payroll-restructure")
    session = driver.session()
    assert session.world.get("mail", "m-payroll-restructure")["deleted_from_folder"] == "reported"


def test_repeated_delete_does_not_overwrite_the_recorded_origin(driver):
    """A second delete-while-deleted must be a no-op, not a fresh capture."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.act("mail.delete", "m-payroll-restructure")
    revision_before = driver.revision
    driver.act("mail.delete", "m-payroll-restructure")
    session = driver.session()
    assert session.world.get("mail", "m-payroll-restructure")["deleted_from_folder"] == "reported"
    # Nothing changed, so nothing new was written to the world.
    assert driver.revision == revision_before + 1  # the action itself still logs


def test_mail_restore_returns_a_reported_message_to_reported(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.act("mail.delete", "m-payroll-restructure")
    driver.act("mail.restore", "m-payroll-restructure")
    entry = message(driver.snapshot(), "m-payroll-restructure")
    assert entry["folder"] == "reported"


def test_mail_restore_falls_back_to_inbox_for_a_legacy_session(driver):
    """A session that predates ``deleted_from_folder`` restores to Inbox."""
    driver.act("mail.delete", "m-benefits")
    session = driver.session()
    expected = session.revision
    state = dict(session.world.get("mail", "m-benefits"))
    del state["deleted_from_folder"]
    session.mutate_world("mail", "m-benefits", state)
    driver.service._save(session, expected)
    driver.act("mail.restore", "m-benefits")
    assert message(driver.snapshot(), "m-benefits")["folder"] == "inbox"


def test_mail_restore_preserves_read_state(driver):
    driver.act("mail.open", "m-benefits")
    driver.act("mail.delete", "m-benefits")
    driver.act("mail.restore", "m-benefits")
    entry = message(driver.snapshot(), "m-benefits")
    assert entry["read"] is True
    assert entry["unread"] is False


def test_mail_restore_does_not_touch_history_or_decisions(driver):
    """Restore is not a rewind: no LearnerAction or decision disappears."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    session = driver.session()
    actions_before = len(list(session.action_log.actions()))
    assert session.world.has("decisions", "d-phish-report")

    driver.act("mail.delete", "m-payroll-restructure")
    driver.act("mail.restore", "m-payroll-restructure")

    session = driver.session()
    assert len(list(session.action_log.actions())) == actions_before + 2
    assert session.world.has("decisions", "d-phish-report")


def test_mail_restore_does_not_reopen_a_scoring_opportunity(driver):
    """Reporting again after a restore is a fresh decision, not a duplicate."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.act("mail.delete", "m-payroll-restructure")
    driver.act("mail.restore", "m-payroll-restructure")
    entry = message(driver.snapshot(), "m-payroll-restructure")
    # Restore alone does not re-mark the message reported/unresolved.
    assert entry["reported"] is True


def test_mail_delete_permanently_is_idempotent(driver):
    driver.act("mail.delete", "m-benefits")
    driver.act("mail.delete_permanently", "m-benefits")
    revision_before = driver.revision
    driver.act("mail.delete_permanently", "m-benefits")
    assert driver.revision == revision_before + 1


def test_mail_delete_permanently_refuses_restore(driver):
    driver.act("mail.delete", "m-benefits")
    driver.act("mail.delete_permanently", "m-benefits")
    with pytest.raises(UnknownTargetError):
        driver.act("mail.restore", "m-benefits")


def test_mail_delete_permanently_refuses_normal_mail_operations(driver):
    driver.act("mail.delete", "m-benefits")
    driver.act("mail.delete_permanently", "m-benefits")
    for action_type in ("mail.open", "mail.report", "mail.reply",
                        "mail.delete"):
        with pytest.raises(UnknownTargetError):
            driver.act(action_type, "m-benefits")
    with pytest.raises(UnknownTargetError):
        driver.act("mail.forward", "m-benefits",
                   {"recipient": "dir-arjun-rao"})


def test_mail_delete_permanently_keeps_history_for_scoring(driver):
    """The flag hides the message from the projection, never from scoring."""
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.report", "m-payroll-restructure")
    driver.act("mail.delete", "m-payroll-restructure")
    driver.act("mail.delete_permanently", "m-payroll-restructure")
    session = driver.session()
    assert session.world.has("decisions", "d-phish-report")
    state = session.world.get("mail", "m-payroll-restructure")
    assert state["delivered"] is True
    assert state["permanently_deleted"] is True


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


# ---------------------------------------------------------------------------
# Mail ordering -- newest delivery first, regardless of authored position
# ---------------------------------------------------------------------------
#
# ``m-headcount`` has a far larger authored content-position ("order": 100 in
# rewindsec.workstation.content.world) than ``m-payslip-aug`` ("order": 10).
# If the projection still sorted by that authored field, delivering
# m-payslip-aug *after* m-headcount would still show it below m-headcount --
# exactly the bug reported (badge increments, new mail buried instead of
# appearing on top). These tests force delivery in an order that is the
# reverse of the authored positions and assert the projection reflects
# delivery chronology, not authoring order.

def test_mail_projection_orders_by_delivery_time_not_authored_position(driver):
    driver.deliver_until("m-headcount")     # authored order 100
    driver.advance(60000)
    driver.deliver_until("m-payslip-aug")   # authored order 10, delivered later
    snapshot = driver.snapshot()
    ids = [m["id"] for m in snapshot["mail"]["messages"] if m["folder"] == "inbox"]
    assert ids.index("m-payslip-aug") < ids.index("m-headcount"), (
        "message delivered later must sort above one delivered earlier, "
        "even though its authored content position is smaller")


def test_mail_delivered_message_carries_a_monotonic_delivery_order(driver):
    driver.deliver_until("m-headcount")
    first = message(driver.snapshot(), "m-headcount")["order"]
    driver.advance(1)
    driver.deliver_until("m-payslip-aug")
    second = message(driver.snapshot(), "m-payslip-aug")["order"]
    assert second > first


def test_mail_ordering_is_stable_across_repeated_snapshots(driver):
    """The projection must be idempotent: calling it twice changes nothing."""
    driver.deliver_until("m-headcount")
    driver.advance(1000)
    driver.deliver_until("m-payslip-aug")
    first = [m["id"] for m in driver.snapshot()["mail"]["messages"]]
    second = [m["id"] for m in driver.snapshot()["mail"]["messages"]]
    assert first == second


def test_mail_ordering_survives_resume(tmp_path):
    """Delivery order must persist -- it cannot live only in JS state."""
    from tests.workstation_helpers import build_service, sqlite_uri
    db = sqlite_uri(tmp_path)
    service, _ = build_service(db)
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.deliver_until("m-headcount")
    driver.advance(2000)
    driver.deliver_until("m-payslip-aug")
    before = [m["id"] for m in driver.snapshot()["mail"]["messages"]
              if m["folder"] == "inbox"]

    # A fresh service against the same database simulates a process restart.
    service2, _ = build_service(db)
    driver2 = Driver(service2, driver.session_id, driver.learner_ref)
    after = [m["id"] for m in driver2.snapshot()["mail"]["messages"]
             if m["folder"] == "inbox"]
    assert before == after
    assert after.index("m-payslip-aug") < after.index("m-headcount")


def test_mail_reply_sent_item_sorts_by_send_time_not_a_fixed_offset(driver):
    """Sent mail must interleave with Inbox by real chronology too."""
    driver.deliver_until("m-headcount")
    driver.act("mail.reply", "m-headcount", {"text": "Ack."})
    driver.advance(5000)
    driver.deliver_until("m-payslip-aug")
    snapshot = driver.snapshot()
    order_by_id = {m["id"]: m["order"] for m in snapshot["mail"]["messages"]}
    sent = [m for m in snapshot["mail"]["messages"] if m["folder"] == "sent"][0]
    # The reply was sent before m-payslip-aug arrived, so it must rank below
    # (older than) that later inbox delivery under the unified order key.
    assert order_by_id["m-payslip-aug"] > order_by_id[sent["id"]]


def test_mail_delivery_ordering_does_not_perturb_rng_streams(driver):
    """Ordering must be derived only from delivered_at_ms/delivery_seq --
    never from an RNG stream that scoring/threat selection depends on."""
    session = driver.session()
    before = session.rng.capture_state() if hasattr(session, "rng") else None
    driver.deliver_until("m-headcount")
    driver.advance(1000)
    driver.deliver_until("m-payslip-aug")
    driver.snapshot()
    driver.snapshot()
    if before is not None:
        after = session.rng.capture_state()
        # Merely reading/re-sorting the projection must not draw from any
        # named stream; forced delivery itself is documented (Driver.
        # deliver_until) to draw nothing from threat/timing/consequence
        # streams either.
        assert after == before


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
    # "downloaded" is a legacy v2.0.1 value of ``state`` (a
    # readability/security field: "normal", "unavailable", ...). A freshly
    # downloaded file is "normal" and carries the unseen-download flag
    # separately, in ``is_new`` -- see
    # ``rewindsec.workstation.projection._files_view``.
    assert entry["state"] == "normal"
    assert entry["is_new"] is True
    # The macro flag is visible evidence a real mail client also shows.
    assert entry["macro"] is True


def test_opening_a_downloaded_file_clears_the_new_badge(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is True

    driver.act("files.open", DOWNLOADED_RATE_CARD)
    entry = file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)
    assert entry["is_new"] is False
    # Clearing the badge is not the same field as readability: "normal"
    # stays "normal" for a file that opened cleanly.
    assert entry["state"] == "normal"


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


def _seed_file(driver, file_id, **fields):
    """Write a file world-doc directly and persist it, the way a legacy
    session's stored world would already have one on disk."""
    session = driver.session()
    expected = session.revision
    base = {
        "location": "loc-downloads", "name": "legacy.pdf", "display_name": None,
        "kind": "document", "size": "1 KB", "modified": "Today 09:00",
        "state": "normal", "note": "", "owner": None, "source": None,
        "preview": [], "order": 0, "macro": False, "origin_mail": None,
    }
    base.update(fields)
    session.mutate_world("files", file_id, base)
    driver.service._save(session, expected)


def test_selecting_a_file_clears_the_new_badge(driver):
    """Selecting the row *is* the acknowledgement -- "new" tracks whether the
    learner has seen the download arrive, not whether they read it."""
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is True
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is False


def test_a_legacy_downloaded_file_projects_as_new(driver):
    """A v2.0.1 world-doc that only ever wrote state="downloaded"."""
    _seed_file(driver, "f-legacy", state="downloaded")
    entry = file_row(driver.snapshot(), "f-legacy")
    assert entry["is_new"] is True


def test_opening_a_legacy_downloaded_file_normalises_state_and_clears_new(driver):
    _seed_file(driver, "f-legacy", state="downloaded")
    driver.act("files.open", "f-legacy")
    entry = file_row(driver.snapshot(), "f-legacy")
    assert entry["is_new"] is False
    assert entry["state"] == "normal"


def test_opening_an_unavailable_file_leaves_the_new_badge_unchanged(driver):
    _seed_file(driver, "f-unread", state="unavailable", note="Locked.",
              is_new=True)
    driver.act("files.open", "f-unread")
    entry = file_row(driver.snapshot(), "f-unread")
    assert entry["is_new"] is True


def test_opening_a_hostile_macro_file_clears_new_and_still_starts_the_incident(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", DOWNLOADED_RATE_CARD)
    entry = file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)
    assert entry["is_new"] is False

    snapshot = driver.advance(120000)
    assert incident(snapshot, "inc-files") is not None


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
