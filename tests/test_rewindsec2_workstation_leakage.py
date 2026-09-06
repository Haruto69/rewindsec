"""The learner-facing projection must not leak hidden truth.

This is the most important suite in Batch 2, and the reason it exists is that
the failure it guards against is invisible. A workstation that renders
correctly and a workstation that renders correctly *while shipping
``"disposition": "hostile"`` in the JSON behind it* look identical to a
reviewer. The second one is not a training exercise; it is a quiz with the
answers in the page source, and anyone who opens developer tools can pass it
without reading a word.

So these tests do not check the fields somebody remembered to check. They walk
the entire document -- every key and every value at every depth -- and assert
properties over all of it:

1. no key or value anywhere carries authored ground truth vocabulary;
2. structurally, a hostile record and a legitimate one are indistinguishable:
   the same keys, the same shapes, nothing present on one and absent from the
   other;
3. inspection-only facts are *absent*, not flagged, until the learner has
   performed the action that observes them;
4. an Assessment attempt carries no pedagogical material at all.

The denylist below is written to catch structure rather than prose. Learner
content is ordinary workplace English and will legitimately contain words like
"correct" in a sentence; what it must never contain is a *field* called
``correct``, or a value that is one of the authored disposition strings.
"""

import json

import pytest

from rewindsec.workstation.content import index as ix
from tests.workstation_helpers import (Driver, build_service, message,
                                       sqlite_uri, walk)

# ---------------------------------------------------------------------------
# The denylists
# ---------------------------------------------------------------------------

#: Field names that would be an answer key wherever they appeared. Checked
#: against dictionary *keys*, so a sentence containing "answer" is fine and a
#: field named ``answer`` is not.
FORBIDDEN_KEYS = frozenset({
    "analysis", "disposition", "malicious", "is_malicious", "suspicious",
    "is_suspicious", "hostile", "is_hostile", "correct", "incorrect",
    "expected_action", "answer", "answer_key", "threat_label", "family",
    "hidden_truth", "score", "scoring", "counterfactual", "safer_alternative",
    "safer_alternatives", "signals", "why", "klass", "class", "evidence_model",
    "establishes_context", "signin_id", "decisions", "chains", "seed",
    "root_seed", "learner_ref", "session_id",
})

#: Exact string values that only ever appear in authored ground truth. Matched
#: whole, case-insensitively, against every string in the document.
FORBIDDEN_VALUES = frozenset({
    "hostile", "malicious", "phishing", "ransomware", "bec", "mfa fatigue",
    "unsafe", "over_suspicious", "recovery_good", "recovery_poor",
    "portal-hostile", "vpn-legit", "payroll-legit",
})

#: The one legitimate place a threat-family word appears in a learner
#: document: the learner's own chosen training focus, which they picked
#: themselves on the entry screen and which the shell displays back to them.
FOCUS_PATHS = frozenset({"$.session.focus"})

#: The one legitimate use of a denied *name*. ``session.flags`` reflects the
#: mode the learner chose back at them so the shell can draw the right chrome,
#: and one of those flags is whether this mode has a safer-alternative screen
#: at all. It is a boolean about the mode, not material about a decision: the
#: comparison *content* is gated separately, and the tests below assert it is
#: absent from an Assessment document entirely.
ALLOWED_KEY_PATHS = frozenset({"$.session.flags.safer_alternative"})


def forbidden_keys(document):
    found = []
    for path, value in walk(document):
        if not isinstance(value, dict):
            continue
        for key in value:
            where = "%s.%s" % (path, key)
            if key in FORBIDDEN_KEYS and where not in ALLOWED_KEY_PATHS:
                found.append(where)
    return found


def forbidden_values(document):
    found = []
    for path, value in walk(document):
        if not isinstance(value, str):
            continue
        if path in FOCUS_PATHS:
            continue
        if value.strip().lower() in FORBIDDEN_VALUES:
            found.append("%s = %r" % (path, value))
    return found


# ---------------------------------------------------------------------------
# The check itself is not blind
# ---------------------------------------------------------------------------

def test_the_leak_detector_would_actually_catch_a_leak():
    """Guards the guard.

    A denylist that matches nothing is indistinguishable from a denylist that
    works, so this proves both halves fire on a document that really does leak.
    """
    leaky = {"mail": {"messages": [
        {"id": "m-1", "subject": "Fine", "analysis": {"disposition": "hostile"}},
    ]}}
    assert forbidden_keys(leaky)
    assert forbidden_values(leaky)

    clean = {"mail": {"messages": [{"id": "m-1", "subject": "Fine"}]}}
    assert forbidden_keys(clean) == []
    assert forbidden_values(clean) == []


def test_the_authored_content_really_does_contain_what_we_are_hiding():
    """If the content had no ground truth, this suite would prove nothing."""
    hostile = [m for m in ix.MAIL_BY_ID if ix.is_hostile_mail(m)]
    assert hostile, "no hostile mail in the authored content"
    record = ix.MAIL_BY_ID[hostile[0]]
    assert record["analysis"]["disposition"] == "hostile"
    assert record["analysis"]["family"]
    assert record["analysis"]["signals"]


# ---------------------------------------------------------------------------
# The projection
# ---------------------------------------------------------------------------

@pytest.fixture
def driver(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    return Driver.start(service, focus="mixed", mode="simulation")


def test_a_fresh_snapshot_leaks_nothing(driver):
    snapshot = driver.snapshot()
    assert forbidden_keys(snapshot) == []
    assert forbidden_values(snapshot) == []


def test_a_snapshot_full_of_hostile_content_still_leaks_nothing(driver):
    """The interesting case: every authored hostile record delivered at once."""
    for _ in range(10):
        driver.deliver_next()
    snapshot = driver.snapshot()

    delivered = {entry["id"] for entry in snapshot["mail"]["messages"]}
    hostile = {m for m in ix.MAIL_BY_ID if ix.is_hostile_mail(m)}
    assert delivered & hostile, "no hostile message was delivered"

    assert forbidden_keys(snapshot) == []
    assert forbidden_values(snapshot) == []


def test_a_hostile_message_is_structurally_identical_to_a_legitimate_one(driver):
    """Same keys, same shapes. Nothing distinguishes them but their content.

    A difference in *shape* is as good as a label: if hostile messages were
    the only ones carrying, say, an empty ``attachments`` list, a script could
    sort the mailbox without reading a word of it.
    """
    driver.deliver_until("m-payroll-restructure")
    snapshot = driver.snapshot()

    hostile = message(snapshot, "m-payroll-restructure")
    legitimate = message(snapshot, "m-payslip-aug")
    assert hostile is not None and legitimate is not None
    assert set(hostile) == set(legitimate)

    for key in hostile:
        assert type(hostile[key]) is type(legitimate[key]), key

    for pair in zip(hostile["links"], legitimate["links"]):
        assert set(pair[0]) == set(pair[1])


def test_both_sign_in_pages_project_the_same_shape(driver):
    """The hostile portal and the genuine payroll portal look alike on the wire.

    In particular ``signin_id`` is absent from both. One of the authored
    values for it is literally ``portal-hostile``; the client posts the
    address instead and the server resolves the handler.
    """
    driver.act("browser.navigate", params={"url": "payroll.northbridge.example"})
    driver.act("browser.navigate",
               params={"url": "payroll-northbridge.example/employee/verify"})
    pages = driver.snapshot()["browser"]["pages"]

    genuine = pages["payroll.northbridge.example"]
    lookalike = pages["payroll-northbridge.example/employee/verify"]
    assert set(genuine) == set(lookalike)
    assert "signin_id" not in genuine
    assert "analysis" not in genuine


def test_an_undelivered_message_is_absent_rather_than_hidden(driver):
    """Tomorrow's post is not in today's document with a flag on it."""
    snapshot = driver.snapshot()
    assert message(snapshot, "m-payroll-restructure") is None
    assert "m-payroll-restructure" not in json.dumps(snapshot)


# ---------------------------------------------------------------------------
# Inspection-only facts: absent until observed
# ---------------------------------------------------------------------------

def test_headers_are_absent_until_the_learner_opens_them(driver):
    driver.deliver_until("m-payroll-restructure")

    before = message(driver.snapshot(), "m-payroll-restructure")
    assert before["headers"] is None
    # The Reply-To is the giveaway on this message. It must not be on the wire.
    assert "nbsystems-secure.example" not in json.dumps(before)

    driver.act("mail.open", "m-payroll-restructure")
    driver.act("mail.inspect_headers", "m-payroll-restructure")

    after = message(driver.snapshot(), "m-payroll-restructure")
    assert after["headers"]["reply_to"] == "hr-review@nbsystems-secure.example"


def test_a_link_destination_is_absent_until_the_learner_inspects_it(driver):
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")

    before = message(driver.snapshot(), "m-payroll-restructure")
    assert before["links"][0]["text"]
    assert before["links"][0]["href"] is None

    driver.act("mail.inspect_link", "m-payroll-restructure", {"index": 0})
    after = message(driver.snapshot(), "m-payroll-restructure")
    assert after["links"][0]["href"] == (
        "https://payroll-northbridge.example/employee/verify")


def test_attachment_details_are_absent_until_inspected(driver):
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")

    before = message(driver.snapshot(), "m-rate-card")
    assert before["attachments"][0]["name"]
    assert before["attachments"][0]["detail"] is None

    driver.act("mail.inspect_attachment", "m-rate-card", {"index": 0})
    after = message(driver.snapshot(), "m-rate-card")
    assert after["attachments"][0]["detail"]["kind_label"]


def test_approval_request_context_is_absent_until_inspected(driver):
    for _ in range(10):
        driver.deliver_next()
    snapshot = driver.snapshot()
    requests = snapshot["authenticator"]["requests"]
    assert requests, "no approval request was raised"

    assert all(entry["details"] is None for entry in requests)
    # The device and the place are the evidence. Not on the wire yet.
    assert "Frankfurt" not in json.dumps(requests)

    driver.act("auth.inspect_request", requests[0]["id"])
    after = driver.snapshot()["authenticator"]["requests"][0]
    assert after["details"]["device"]
    assert after["details"]["location"]


def test_a_directory_callback_is_absent_until_the_learner_calls(driver):
    """What a colleague says on the phone is the result of ringing them."""
    before = driver.snapshot()
    priya = [c for c in before["directory"] if c["id"] == "dir-priya-menon"][0]
    assert priya["can_call"] is True
    assert priya["call_result"] is None

    driver.act("directory.call", "dir-priya-menon")
    after = driver.snapshot()
    priya = [c for c in after["directory"] if c["id"] == "dir-priya-menon"][0]
    assert "Nothing has gone out from payroll today" in priya["call_result"]


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

def test_an_assessment_snapshot_carries_no_comparison_material(tmp_path):
    """Not hidden with CSS. Absent from the document.

    The learner signs in on the lookalike portal, the whole chain runs, and
    the comparison the same run would show in Simulation is simply not there.
    """
    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="phishing", mode="assessment")
    driver.deliver_until("m-payroll-restructure")
    driver.act("mail.open", "m-payroll-restructure")
    result = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": result.notice["url"]})
    snapshot = driver.advance(120000)

    assert snapshot["incidents"], "the consequence chain did not run"
    assert snapshot["comparison"] is None

    text = json.dumps(snapshot)
    assert "Signing in on that page" not in text
    assert "safer_process" not in text
    assert "likely_outcome" not in text
    assert forbidden_keys(snapshot) == []
    assert forbidden_values(snapshot) == []


def test_assessment_suppresses_every_coaching_flag(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="mixed", mode="assessment")
    flags = driver.snapshot()["session"]["flags"]
    assert flags == {
        "coaching": False, "explicit_confirmation": False,
        "safer_alternative": False, "retry_visible": False,
        "investigation_hints": False,
    }


def test_assessment_gives_no_confirmation_for_a_good_decision(tmp_path):
    """Practice says so; Assessment says nothing at all."""
    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="phishing", mode="assessment")
    driver.deliver_until("m-payroll-restructure")
    result = driver.act("mail.report", "m-payroll-restructure")
    assert result.notice is None


def test_practice_does_confirm_a_good_decision(tmp_path):
    """The contrast that makes the previous test mean something."""
    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="phishing", mode="practice")
    driver.deliver_until("m-payroll-restructure")
    result = driver.act("mail.report", "m-payroll-restructure")
    assert result.notice["kind"] == "confirmation"
    assert result.notice["text"]


def test_simulation_gives_the_result_but_not_the_praise(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path))
    driver = Driver.start(service, focus="phishing", mode="simulation")
    driver.deliver_until("m-payroll-restructure")
    result = driver.act("mail.report", "m-payroll-restructure")
    assert result.notice is None
    assert message(result.snapshot, "m-payroll-restructure")["folder"] == "reported"


# ---------------------------------------------------------------------------
# The debrief boundary
# ---------------------------------------------------------------------------

def test_the_debrief_is_refused_while_the_session_is_running(driver):
    from rewindsec.workstation.debrief import debrief_document
    from rewindsec.workstation.errors import ForbiddenActionError

    with pytest.raises(ForbiddenActionError):
        debrief_document(driver.session())


def test_the_debrief_is_available_once_the_session_has_ended(driver):
    from rewindsec.workstation.debrief import debrief_document

    driver.service.end_session(driver.session_id, driver.learner_ref)
    document = debrief_document(driver.session())
    # It *is* allowed to explain, which is the whole point of a debrief.
    assert "timeline" in document
    assert document["scoring"]["engine"] == "none"
