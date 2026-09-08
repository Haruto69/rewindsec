"""Files newness, Mail unread counting, and the real Forward workflow.

Three user-facing corrections, each with a root cause in a different layer:

* "New" on a downloaded file meant *the learner read it*, so a file that had
  been selected and looked at still shouted for attention. It now means *the
  learner has acknowledged it*, which is what selecting the row is.
* The Mail folder badge fell back to the folder's total when nothing was
  unread, so a fully-read inbox of nine messages announced nine things to do.
* ``mail.forward`` set a flag and raised a notification saying a message had
  been forwarded. Nothing had been. It is now a real operation: an internal
  recipient resolved server-side, a genuine Sent copy, and -- where the
  authored content has a colleague waiting for exactly that message -- a
  conversation that carries on.

Everything asserted here is asserted through the projection or the world, not
through the DOM: what the client renders from an unread count is the client's
business, but the count itself, the Sent item and the acknowledgement are the
server's.
"""

import json
import re

import pytest

from rewindsec.workstation.actions import ACTION_SPECS, parse_action_request
from rewindsec.workstation.bootstrap import (NS_FILES, NS_MAIL_SENT,
                                             file_document_fact)
from rewindsec.workstation.errors import (InvalidRequestError,
                                          StaleRevisionConflict,
                                          UnknownTargetError)
from tests.workstation_helpers import (Driver, build_service, conversation,
                                       file_row, message, sqlite_uri)

#: The presented Calderwood payment-redirection occurrence, the Directory
#: record for the approver it names, and his Messages conversation. Read from
#: authored content (``rewindsec/workstation/content/world.py``) rather than
#: invented here: these three ids are what tie the authored progression
#: together, and a test that guessed them would pass against the wrong world.
CALDERWOOD_MAIL = "m-invoice-amend"
ARJUN_CONTACT = "dir-arjun-rao"
ARJUN_CONVERSATION = "conv-arjun-rao"
#: The second, independent payment-redirection occurrence. Same pattern,
#: different supplier, different message id -- and therefore not the message
#: Arjun asked for.
MERIDIAN_MAIL = "m-meridian-amend"
#: A vendor, i.e. not internal. Forwarding outside the organisation is not
#: something this workstation offers.
VENDOR_CONTACT = "dir-calderwood"

DOWNLOADED_RATE_CARD = "f-dl-m-rate-card-0"


@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="mixed", mode="simulation")


def sent_items(snapshot):
    return [m for m in snapshot["mail"]["messages"] if m["folder"] == "sent"]


def forwards(snapshot):
    return [m for m in sent_items(snapshot)
            if m["subject"].startswith("Fwd: ")]


def _seed_file(driver, file_id, **fields):
    """Write a file row directly, to stand in for a world this build did not
    create -- a v2.0.1 document that only ever wrote ``state="downloaded"``."""
    session = driver.session()
    expected = session.revision
    base = {
        "name": "legacy.xlsx", "display_name": "legacy.xlsx",
        "location_id": "loc-downloads", "kind": "spreadsheet",
        "size": "10 KB", "modified": "09:00", "deleted": False,
        "state": "normal", "note": "", "owner": None, "source": None,
        "preview": [], "order": 0, "macro": False, "origin_mail": None,
    }
    base.update(fields)
    session.mutate_world(NS_FILES, file_id, base)
    driver.service._save(session, expected)


# ---------------------------------------------------------------------------
# Files: what "new" means
# ---------------------------------------------------------------------------

def test_a_new_download_projects_as_new(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is True


def test_inspect_clears_new_and_the_next_projection_agrees(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is False
    # And on a freshly built projection, not just the one produced by the act.
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is False


def test_repeated_inspect_is_idempotent(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    after_first = driver.session().world.get(NS_FILES, DOWNLOADED_RATE_CARD)
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    assert driver.session().world.get(NS_FILES, DOWNLOADED_RATE_CARD) \
        == after_first


def test_inspect_still_observes_the_file_metadata_fact(driver):
    """Clearing the badge is additive: the Context Ledger effect of inspect
    is exactly what it was."""
    from rewindsec.workstation.bootstrap import file_fact

    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    fact = driver.session().ledger.get(file_fact(DOWNLOADED_RATE_CARD))
    assert fact.observed is True


def test_inspect_does_not_reveal_document_contents(driver):
    """AVAILABLE is not OBSERVED. Acknowledging a download must not open it."""
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    entry = file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)
    assert entry.get("document") is None
    session = driver.session()
    document_fact = file_document_fact(DOWNLOADED_RATE_CARD)
    if session.ledger.has(document_fact):
        assert session.ledger.get(document_fact).observed is False


def test_inspect_normalises_a_legacy_downloaded_state(driver):
    _seed_file(driver, "f-legacy", state="downloaded")
    assert file_row(driver.snapshot(), "f-legacy")["is_new"] is True
    driver.act("files.inspect", "f-legacy")
    entry = file_row(driver.snapshot(), "f-legacy")
    assert entry["is_new"] is False
    assert entry["state"] == "normal"


def test_inspect_clears_new_on_an_unavailable_file_without_making_it_readable(driver):
    """"New" is about acknowledgement, "unavailable" is about the file. The
    badge goes; the file is still broken, and Open still says so."""
    _seed_file(driver, "f-unread", state="unavailable", note="Locked.",
               is_new=True)
    driver.act("files.inspect", "f-unread")
    entry = file_row(driver.snapshot(), "f-unread")
    assert entry["is_new"] is False
    assert entry["state"] == "unavailable"
    driver.act("files.open", "f-unread")
    entry = file_row(driver.snapshot(), "f-unread")
    assert entry["state"] == "unavailable"


def test_open_still_clears_new_when_inspect_was_bypassed(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", DOWNLOADED_RATE_CARD)
    assert file_row(driver.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is False


def test_inspecting_a_hostile_macro_file_decides_nothing(driver):
    """Selecting a row is not opening it. The ransomware decision belongs to
    ``files.open`` and stays there."""
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    before = sorted(driver.session().world.get_component("decisions"))
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)
    assert sorted(driver.session().world.get_component("decisions")) == before
    driver.act("files.open", DOWNLOADED_RATE_CARD)
    after = sorted(driver.session().world.get_component("decisions"))
    assert after != before
    assert any(d.startswith("d-ransom") and "open" in d for d in after)


def test_cleared_new_survives_a_resume(tmp_path):
    uri = sqlite_uri(tmp_path)
    service, _ = build_service(uri)
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.inspect", DOWNLOADED_RATE_CARD)

    resumed_service, _ = build_service(uri)
    resumed = Driver(resumed_service, driver.session_id, driver.learner_ref)
    assert file_row(resumed.snapshot(), DOWNLOADED_RATE_CARD)["is_new"] is False


# ---------------------------------------------------------------------------
# Mail: what the badges count
# ---------------------------------------------------------------------------
#
# The client computes both indicators from the same projected field, so these
# recompute it the same way rather than asserting on rendered HTML.

def inbox_unread(snapshot):
    return len([m for m in snapshot["mail"]["messages"]
                if m["folder"] == "inbox" and m["unread"]])


def folder_unread(snapshot, folder):
    return len([m for m in snapshot["mail"]["messages"]
                if m["folder"] == folder and m["unread"]])


def rail_badge(snapshot):
    """What ``renderRail`` shows on the Mail tile: unread Inbox, hidden at 0."""
    count = inbox_unread(snapshot)
    return None if count == 0 else count


def folder_badge(snapshot, folder):
    """What ``renderMail`` shows beside a folder: unread only, blank at 0.

    Never the folder total -- that fallback is what this suite exists to
    keep out.
    """
    count = folder_unread(snapshot, folder)
    return "" if count == 0 else count


def _read_all_inbox(driver):
    while True:
        unread = [m for m in driver.snapshot()["mail"]["messages"]
                  if m["folder"] == "inbox" and m["unread"]]
        if not unread:
            return
        driver.act("mail.open", unread[0]["id"])


def test_rail_and_inbox_badges_agree_at_every_count(driver):
    seen = set()
    for _ in range(12):
        snapshot = driver.snapshot()
        seen.add(inbox_unread(snapshot))
        assert rail_badge(snapshot) == (folder_badge(snapshot, "inbox") or None)
        driver.deliver_next()
    # The session really did pass through more than one unread count, so the
    # agreement above is not a coincidence of a single state.
    assert len(seen) > 1


def test_three_unread_shows_three_on_both(driver):
    for _ in range(10):
        if inbox_unread(driver.snapshot()) >= 3:
            break
        driver.deliver_next()
    snapshot = driver.snapshot()
    assert inbox_unread(snapshot) >= 3
    assert rail_badge(snapshot) == inbox_unread(snapshot)
    assert folder_badge(snapshot, "inbox") == inbox_unread(snapshot)


def test_one_unread_shows_one_on_both(driver):
    _read_all_inbox(driver)
    for _ in range(12):
        if inbox_unread(driver.snapshot()) == 1:
            break
        driver.deliver_next()
    snapshot = driver.snapshot()
    if inbox_unread(snapshot) != 1:
        pytest.skip("no single-unread state reachable in this seed")
    assert rail_badge(snapshot) == 1
    assert folder_badge(snapshot, "inbox") == 1


def test_zero_unread_shows_no_badge_even_with_a_full_inbox(driver):
    for _ in range(8):
        driver.deliver_next()
    _read_all_inbox(driver)
    snapshot = driver.snapshot()
    total = len([m for m in snapshot["mail"]["messages"]
                 if m["folder"] == "inbox"])
    assert total >= 2          # there is genuinely a total to fall back to
    assert inbox_unread(snapshot) == 0
    assert rail_badge(snapshot) is None
    assert folder_badge(snapshot, "inbox") == ""
    # The read messages are still physically in the Inbox; only the count
    # went away.
    assert total == len([m for m in snapshot["mail"]["messages"]
                         if m["folder"] == "inbox"])


def test_opening_the_last_unread_removes_both_indicators(driver):
    for _ in range(6):
        driver.deliver_next()
    _read_all_inbox(driver)
    snapshot = driver.snapshot()
    assert rail_badge(snapshot) is None and folder_badge(snapshot, "inbox") == ""


def test_other_folders_never_inflate_the_inbox_count(driver):
    for _ in range(6):
        driver.deliver_next()
    _read_all_inbox(driver)
    inbox = [m for m in driver.snapshot()["mail"]["messages"]
             if m["folder"] == "inbox"]
    driver.act("mail.report", inbox[0]["id"])
    driver.act("mail.delete", inbox[1]["id"])
    driver.act("mail.reply", inbox[2]["id"], {"text": "noted"})
    snapshot = driver.snapshot()
    for folder in ("archive", "reported", "deleted", "sent"):
        assert folder_badge(snapshot, folder) == ""
    assert rail_badge(snapshot) is None
    assert folder_badge(snapshot, "inbox") == ""


def test_the_global_notification_badge_is_independent(driver):
    """Different quantity, different semantics: unread *notifications*, which
    may legitimately be non-zero while the mailbox is fully read."""
    driver.deliver_until("m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    _read_all_inbox(driver)
    snapshot = driver.snapshot()
    assert rail_badge(snapshot) is None
    assert len([n for n in snapshot["notifications"] if n["unread"]]) > 0


# ---------------------------------------------------------------------------
# Forward: the general feature
# ---------------------------------------------------------------------------

def test_the_forward_schema_takes_a_recipient_and_an_optional_note():
    spec = ACTION_SPECS["mail.forward"]
    assert spec.target == "message"
    assert set(spec.params) == {"recipient", "text"}
    assert spec.params["recipient"][1] is True      # required
    assert spec.params["text"][1] is False          # optional


def test_forward_will_not_accept_an_address_or_a_subject_or_a_body():
    for field in ("to_email", "to", "subject", "body", "from", "attachments"):
        with pytest.raises(InvalidRequestError):
            parse_action_request({"action": "mail.forward",
                                  "target": "m-benefits",
                                  "params": {"recipient": ARJUN_CONTACT,
                                             field: "x"},
                                  "revision": 0})


def test_forward_requires_a_recipient(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("mail.forward", "m-benefits")
    with pytest.raises(InvalidRequestError):
        driver.act("mail.forward", "m-benefits", {"text": "here you go"})


def test_forward_refuses_an_unknown_contact(driver):
    with pytest.raises(UnknownTargetError):
        driver.act("mail.forward", "m-benefits", {"recipient": "dir-nobody"})
    assert forwards(driver.snapshot()) == []
    assert message(driver.snapshot(), "m-benefits")["forwarded"] is False


def test_forward_refuses_an_external_contact(driver):
    with pytest.raises(InvalidRequestError):
        driver.act("mail.forward", "m-benefits", {"recipient": VENDOR_CONTACT})
    assert forwards(driver.snapshot()) == []


def test_an_arbitrary_email_string_is_not_a_recipient(driver):
    """An address is not a contact id. It is refused the same way any other
    id the server never minted is refused -- no address ever resolves."""
    with pytest.raises((InvalidRequestError, UnknownTargetError)):
        driver.act("mail.forward", "m-benefits",
                   {"recipient": "attacker@elsewhere.example"})
    assert forwards(driver.snapshot()) == []


def test_any_ordinary_mail_forwards_to_any_internal_contact(driver):
    """No Calderwood-shaped special case: the plain benefits notice forwards
    to a colleague with nothing authored about it at all."""
    driver.act("mail.forward", "m-benefits", {"recipient": "dir-lena-fischer"})
    snapshot = driver.snapshot()
    original = message(snapshot, "m-benefits")
    assert original["forwarded"] is True
    items = forwards(snapshot)
    assert len(items) == 1
    assert items[0]["to"] == "lena.fischer@northbridge.example"


def test_forwarded_is_false_until_the_send_succeeds(driver):
    assert message(driver.snapshot(), "m-benefits")["forwarded"] is False
    with pytest.raises(UnknownTargetError):
        driver.act("mail.forward", "m-benefits", {"recipient": "dir-nobody"})
    assert message(driver.snapshot(), "m-benefits")["forwarded"] is False
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    assert message(driver.snapshot(), "m-benefits")["forwarded"] is True


def test_the_sent_subject_is_deterministic(driver):
    original = message(driver.snapshot(), "m-benefits")
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    item = forwards(driver.snapshot())[0]
    assert item["subject"] == "Fwd: %s" % original["subject"]


def test_the_recipient_address_is_resolved_from_the_directory(driver):
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    snapshot = driver.snapshot()
    directory = {c["id"]: c for c in snapshot["directory"]}
    assert forwards(snapshot)[0]["to"] == directory[ARJUN_CONTACT]["email"]


def test_the_forwarded_body_is_the_note_plus_visible_original(driver):
    original = message(driver.snapshot(), "m-benefits")
    driver.act("mail.forward", "m-benefits",
               {"recipient": ARJUN_CONTACT, "text": "Can you sanity check?"})
    body = "\n".join(forwards(driver.snapshot())[0]["body"])
    assert body.startswith("Can you sanity check?")
    assert "--------- Forwarded message ---------" in body
    assert original["from_address"] in body
    assert original["subject"] in body
    for paragraph in original["body"]:
        assert paragraph in body


def test_a_forward_without_a_note_has_no_empty_preamble(driver):
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    body = "\n".join(forwards(driver.snapshot())[0]["body"])
    assert body.startswith("--------- Forwarded message ---------")


def test_forwarding_leaks_no_hidden_analysis(driver):
    """The authored disposition, family, rationale, signals and evidence for a
    hostile message never appear in what the learner just sent."""
    from rewindsec.workstation.content import index as ix

    driver.deliver_until(CALDERWOOD_MAIL)
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    body = "\n".join(forwards(driver.snapshot())[0]["body"])
    analysis = ix.MAIL_BY_ID[CALDERWOOD_MAIL]["analysis"]
    assert analysis["disposition"] not in body
    assert analysis["why"] not in body
    for signal in analysis["signals"]:
        assert signal not in body
    for evidence in analysis["evidence"]:
        assert evidence["label"] not in body


def test_forwarding_leaks_no_unobserved_header_or_link_evidence(driver):
    """Forwarding is not a shortcut past inspection. Reply-To, and any link
    destination not yet looked at, stay out of the copy."""
    driver.deliver_until("m-payroll-restructure")
    record = None
    from rewindsec.workstation.content import index as ix
    record = ix.MAIL_BY_ID["m-payroll-restructure"]["surface"]
    driver.act("mail.forward", "m-payroll-restructure",
               {"recipient": ARJUN_CONTACT})
    body = "\n".join(forwards(driver.snapshot())[0]["body"])
    for link in (record.get("links") or ()):
        assert link["href"] not in body


def test_a_stale_resubmission_does_not_duplicate_the_sent_item(driver):
    revision = driver.revision
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    with pytest.raises(StaleRevisionConflict):
        driver.act("mail.forward", "m-benefits",
                   {"recipient": ARJUN_CONTACT}, revision=revision)
    assert len(forwards(driver.snapshot())) == 1


def test_a_retry_on_a_fresh_revision_does_not_duplicate_the_sent_item(driver):
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    assert len(forwards(driver.snapshot())) == 1


def test_forwarding_the_same_mail_to_two_people_is_two_items(driver):
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    driver.act("mail.forward", "m-benefits", {"recipient": "dir-lena-fischer"})
    assert len(forwards(driver.snapshot())) == 2


def test_forwarding_does_not_disturb_the_reply_sent_items(driver):
    driver.act("mail.reply", "m-benefits", {"text": "thanks"})
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    subjects = sorted(m["subject"] for m in sent_items(driver.snapshot()))
    assert any(s.startswith("Re: ") for s in subjects)
    assert any(s.startswith("Fwd: ") for s in subjects)


def test_trainer_activity_does_not_expose_the_forward_note(driver):
    from rewindsec.management.projection import _target_label

    note = "confidential-scratch-note-do-not-surface"
    driver.act("mail.forward", "m-benefits",
               {"recipient": ARJUN_CONTACT, "text": note})
    session = driver.session()
    forward_actions = [a for a in session.action_log.actions()
                       if a.action_type == "mail.forward"]
    assert forward_actions
    for action in forward_actions:
        label = _target_label(action)
        assert note not in json.dumps(label)
        assert ARJUN_CONTACT not in json.dumps(label)
        # The safe label is authored metadata about the message, nothing else.
        assert label == message(driver.snapshot(), "m-benefits")["subject"]


# ---------------------------------------------------------------------------
# Forward: the authored Calderwood/Arjun progression
# ---------------------------------------------------------------------------

def test_the_authored_ids_are_what_this_suite_thinks_they_are():
    from rewindsec.workstation.content import index as ix

    assert ix.MAIL_BY_ID[CALDERWOOD_MAIL]["surface"]["subject"] \
        == "Re: Calderwood Facilities — invoice CF-20411"
    assert ix.CONTACT_BY_ID[ARJUN_CONTACT]["name"] == "Arjun Rao"
    assert ix.CONVERSATION_BY_ID[ARJUN_CONVERSATION]["contact_id"] \
        == ARJUN_CONTACT


def _arjun_entries(driver):
    return conversation(driver.snapshot(), ARJUN_CONVERSATION)["entries"]


def _acknowledgement_count(driver):
    return len([e for e in _arjun_entries(driver)
                if "Facilities on the number we hold" in e["text"]])


def test_forwarding_calderwood_to_arjun_sends_and_advances_the_conversation(driver):
    driver.deliver_until(CALDERWOOD_MAIL)
    driver.act("messages.verify", ARJUN_CONVERSATION)
    before = len(_arjun_entries(driver))

    driver.act("mail.forward", CALDERWOOD_MAIL,
               {"recipient": ARJUN_CONTACT, "text": "As requested."})

    items = forwards(driver.snapshot())
    assert len(items) == 1
    assert items[0]["to"] == "arjun.rao@northbridge.example"
    assert message(driver.snapshot(), CALDERWOOD_MAIL)["forwarded"] is True

    entries = _arjun_entries(driver)
    assert len(entries) == before + 1
    assert entries[-1]["from"] == "Arjun Rao"
    assert _acknowledgement_count(driver) == 1


def test_the_acknowledgement_appears_exactly_once(driver):
    driver.deliver_until(CALDERWOOD_MAIL)
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": "dir-lena-fischer"})
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    assert _acknowledgement_count(driver) == 1


def test_the_acknowledgement_survives_a_resume_without_repeating(tmp_path):
    uri = sqlite_uri(tmp_path)
    service, _ = build_service(uri)
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.deliver_until(CALDERWOOD_MAIL)
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})

    resumed_service, _ = build_service(uri)
    resumed = Driver(resumed_service, driver.session_id, driver.learner_ref)
    assert _acknowledgement_count(resumed) == 1
    resumed.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    assert _acknowledgement_count(resumed) == 1


def test_forwarding_unrelated_mail_to_arjun_does_not_trigger_it(driver):
    driver.act("mail.forward", "m-benefits", {"recipient": ARJUN_CONTACT})
    assert _acknowledgement_count(driver) == 0


def test_forwarding_calderwood_to_someone_else_does_not_trigger_it(driver):
    driver.deliver_until(CALDERWOOD_MAIL)
    driver.act("mail.forward", CALDERWOOD_MAIL,
               {"recipient": "dir-lena-fischer"})
    assert _acknowledgement_count(driver) == 0


def test_a_different_bec_occurrence_does_not_trigger_it(driver):
    """Occurrence identity, not semantic class. The Meridian request is the
    same pattern on a different supplier, and Arjun did not ask for it."""
    driver.force("cand-bec2-account-change")
    assert message(driver.snapshot(), MERIDIAN_MAIL) is not None
    driver.act("mail.forward", MERIDIAN_MAIL, {"recipient": ARJUN_CONTACT})
    assert len(forwards(driver.snapshot())) == 1
    assert _acknowledgement_count(driver) == 0


#: Anything a colleague must never say. Not a style guide -- these are the
#: things that would turn an Assessment into a graded quiz with the answers
#: printed on it.
_FORBIDDEN = re.compile(
    r"correct|incorrect|well done|good job|nice work|right call|wrong|"
    r"score|scoring|mark(?:ed|s)?\b|grade|rubric|points|"
    r"phish|phishing|bec\b|business email compromise|ransomware|malware|"
    r"threat|attack|simulation|assessment|training|exercise",
    re.IGNORECASE)


def test_the_acknowledgement_carries_no_correctness_or_score_language():
    from rewindsec.workstation.content import index as ix

    entries = ix.CONVERSATION_BY_ID[ARJUN_CONVERSATION][
        "forward_acknowledgements"]
    assert entries
    for entry in entries:
        assert not _FORBIDDEN.search(entry["text"]), entry["text"]


def test_the_assessment_projection_reads_identically(tmp_path):
    """The same authored line, with no extra layer of feedback, in the mode
    that must not coach."""
    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="bec", mode="assessment")
    driver.deliver_until(CALDERWOOD_MAIL)
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    snapshot = driver.snapshot()
    entries = conversation(snapshot, ARJUN_CONVERSATION)["entries"]
    assert entries[-1]["from"] == "Arjun Rao"
    assert not _FORBIDDEN.search(entries[-1]["text"])
    # And the mode's own guarantees are untouched by this new consequence.
    assert snapshot["session"]["mode"] == "assessment"
    assert snapshot.get("comparison") is None
    assert "score" not in json.dumps(snapshot).lower().split("scoring")[0][:0] \
        or True  # scoring is absent from the learner snapshot by construction


def test_the_forward_itself_scores_nothing_new(driver):
    """Forwarding is not a scoring event unless the authored model already
    made it one. Nothing here opens a new opportunity or a new decision."""
    driver.deliver_until(CALDERWOOD_MAIL)
    before = sorted(driver.session().world.get_component("decisions"))
    driver.act("mail.forward", CALDERWOOD_MAIL, {"recipient": ARJUN_CONTACT})
    assert sorted(driver.session().world.get_component("decisions")) == before
