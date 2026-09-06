"""Ransomware, containment, and the difference between the two.

This is the acceptance suite for the one interaction Batch 3 exists to make
real. Batch 2 had a Service Desk button that set a flag called
``network_disconnected`` and marked an incident contained. Nothing else in the
simulation read either. A learner who pressed it and a learner who did not
ended the session in the same world, which made the most important operational
decision in the product a no-op.

What the suite asserts, in the order the failures would matter:

**Timing changes the outcome.** Isolating before the local damage, between the
local damage and the network spread, after the spread, and never, must produce
four different causal histories. If any two agree, containment is decoration.

**Containment is not recovery.** Files that stopped opening stay closed. The
incident stays open. The account stays compromised. Nothing is restored, and
the word "contained" is stored separately from any notion of recovery so a
later batch cannot merge them by accident.

**Nothing is rewound.** Damage already done is untouched, and reconnecting
later does not resurrect a consequence that containment had already prevented.

**Containment has a cost when there is nothing to contain.** Otherwise
"disconnect immediately, every session" is a free universally correct move,
and the product teaches it.

**Nothing here touches a real machine.** No file on the host is read, written,
renamed or encrypted; every effect is a row in a synthetic world.
"""

import io
import json
import pathlib

import pytest

from rewindsec.training import progression
from rewindsec.training import state as engine_state
from rewindsec.workstation.bootstrap import NS_DECISIONS, NS_FILES, NS_SESSION
from tests.workstation_helpers import (Driver, build_service, conversation,
                                       file_row, incident, sqlite_uri)

SUPPORT_URL = "intranet.northbridge.example/it/support"

#: The four files the authored chain takes, in the order it takes them, and
#: whether reaching each one needs the network.
LOCAL_FILES = ("f-headcount-model", "f-team-rota")
NETWORK_FILES = ("f-q3-metrics", "f-facilities")


def session_for(tmp_path, name, mode="simulation", focus="ransomware"):
    service, repository = build_service(sqlite_uri(tmp_path, name),
                                        ids=["ws-%s" % name])
    return Driver.start(service, focus=focus, mode=mode), repository


def open_the_attachment(driver):
    """Download the macro workbook and open it. The entry vector, in two acts."""
    driver.deliver_until("m-rate-card")
    driver.act("mail.open", "m-rate-card")
    driver.act("mail.download_attachment", "m-rate-card", {"index": 0})
    driver.act("files.open", "f-dl-m-rate-card-0")
    return driver


def isolate(driver):
    return driver.act("browser.support_action", params={"choice": "isolate"})


def reconnect(driver):
    return driver.act("browser.support_action", params={"choice": "reconnect"})


def unavailable(driver):
    return {file_id for file_id, state
            in driver.session().world.get_component(NS_FILES).items()
            if state.get("state") == "unavailable"}


def decisions(driver):
    return set(driver.session().world.get_component(NS_DECISIONS))


def suppressed(driver):
    return set(engine_state.suppressed_steps(driver.session()))


# ===========================================================================
# The entry vectors
# ===========================================================================

def test_opening_the_downloaded_workbook_starts_the_incident(tmp_path):
    driver, _ = session_for(tmp_path, "entry.db")
    open_the_attachment(driver)
    assert "d-ransom-open" in decisions(driver)
    driver.advance(60000)
    assert incident(driver.snapshot(), "inc-files") is not None


def test_the_browser_download_is_a_second_entry_vector(tmp_path):
    """The same workbook, from the look-alike billing site instead of the mail.

    It has to reach the same judgement: a macro workbook from somewhere
    hostile is consequential however it arrived, or the learner learns to
    distrust attachments and trust downloads.
    """
    driver, _ = session_for(tmp_path, "webentry.db")
    driver.act("browser.navigate", params={"url": "calderwood-billing.example"})
    driver.act("browser.download", params={"url": "calderwood-billing.example",
                                           "resource": "res-rate-card"})
    downloaded = [row for row in driver.snapshot()["files"]["files"]
                  if row["location"] == "loc-downloads"
                  and row["name"].startswith("Calderwood_Rates_Q4")]
    assert len(downloaded) == 1
    driver.act("files.open", downloaded[0]["id"])
    assert "d-ransom-open" in decisions(driver)


def test_a_download_from_a_legitimate_page_is_not_consequential(tmp_path):
    driver, _ = session_for(tmp_path, "webbenign.db")
    driver.act("browser.download", params={
        "url": "intranet.northbridge.example/it/maintenance",
        "resource": "res-access-guide"})
    downloaded = [row for row in driver.snapshot()["files"]["files"]
                  if row["name"].startswith("Remote_Access_Guide")]
    assert downloaded
    driver.act("files.open", downloaded[0]["id"])
    assert "d-ransom-open" not in decisions(driver)


def test_a_download_names_a_resource_and_never_a_path(tmp_path):
    driver, _ = session_for(tmp_path, "webpath.db")
    from rewindsec.workstation.errors import UnknownTargetError
    with pytest.raises(UnknownTargetError):
        driver.act("browser.download", params={
            "url": "calderwood-billing.example", "resource": "res-nonexistent"})
    with pytest.raises(UnknownTargetError):
        driver.act("browser.download", params={
            "url": "intranet.northbridge.example", "resource": "res-rate-card"})


# ===========================================================================
# A: isolate before the network-dependent step
# ===========================================================================

def test_isolating_before_the_spread_keeps_the_local_damage_and_stops_the_rest(
        tmp_path):
    """Case A. The learner catches it after their own files start failing.

    Local damage persists -- it already happened, and nothing in this product
    un-happens it. The shared folder, which needs a network to reach, is not
    touched.
    """
    driver, _ = session_for(tmp_path, "case-a.db")
    open_the_attachment(driver)

    # Far enough for the local steps, not far enough for the network ones.
    driver.advance(20000)
    local_damage = unavailable(driver)
    assert local_damage & set(LOCAL_FILES), "the local step never fired"

    isolate(driver)
    driver.advance(400000)

    after = unavailable(driver)
    assert local_damage <= after, "isolation restored a file it must not restore"
    assert not (after & set(NETWORK_FILES)), sorted(after)
    assert suppressed(driver)


def test_the_suppressed_steps_are_the_network_ones_and_only_those(tmp_path):
    driver, _ = session_for(tmp_path, "case-a-steps.db")
    open_the_attachment(driver)
    driver.advance(20000)
    isolate(driver)

    for identity in suppressed(driver):
        chain_id, step_id = identity.split(":", 1)
        assert progression.is_network_dependent(chain_id, step_id), identity


def test_isolation_records_a_learner_action_and_a_causal_event(tmp_path):
    driver, _ = session_for(tmp_path, "case-a-causal.db")
    open_the_attachment(driver)
    driver.advance(20000)
    isolate(driver)

    session = driver.session()
    actions = [a for a in session.action_log.actions()
               if a.action_type == "browser.support_action"]
    assert actions and actions[-1].params.get("choice") == "isolate"

    suppression = [e for e in session.event_log.events()
                   if e.type == progression.SUPPRESSION_EVENT_TYPE]
    assert suppression
    for event in suppression:
        assert event.payload["reason"] == "network_isolation"
        assert event.payload["chain"] and event.payload["step"]


# ===========================================================================
# B: isolate after the spread has already happened
# ===========================================================================

def test_isolating_after_the_spread_cannot_undo_it(tmp_path):
    """Case B. Too late for the shared folder; still in time for the rest."""
    driver, _ = session_for(tmp_path, "case-b.db")
    open_the_attachment(driver)
    driver.advance(400000)

    spread = unavailable(driver)
    assert spread & set(NETWORK_FILES), "the network step never fired"

    isolate(driver)
    driver.advance(400000)
    assert spread <= unavailable(driver)


def test_isolating_after_the_spread_still_blocks_what_has_not_happened(tmp_path):
    """The uncontained continuation must not run once containment is in force."""
    driver, _ = session_for(tmp_path, "case-b2.db")
    open_the_attachment(driver)
    # Past the shared-folder step, before the uncontained continuation.
    driver.advance(35000)
    before = unavailable(driver)
    assert "f-q3-metrics" in before
    assert "f-facilities" not in before

    isolate(driver)
    driver.advance(600000)
    after = unavailable(driver)
    assert "f-facilities" not in (after - before), \
        "the uncontained chain ran after containment"


# ===========================================================================
# C: never isolate
# ===========================================================================

def test_never_isolating_lets_the_whole_authored_chain_run(tmp_path):
    """Case C. The full deterministic synthetic progression."""
    driver, _ = session_for(tmp_path, "case-c.db")
    open_the_attachment(driver)
    driver.advance(900000)

    after = unavailable(driver)
    assert set(LOCAL_FILES) <= after
    assert "f-q3-metrics" in after
    assert incident(driver.snapshot(), "inc-files")["contained"] is False
    # A colleague notices before the learner tells anyone.
    assert conversation(driver.snapshot(), "conv-tom-brennan")["entries"]


def test_the_four_timings_produce_four_different_histories(tmp_path):
    """The headline assertion. If any two agree, containment does nothing.

    The four timings are the ones that are actually different, which is not
    quite the same as four arbitrary moments. Isolating one second after
    opening the workbook and isolating twenty seconds after it produce the
    same world, and correctly so: the local step is local, it was always going
    to happen, and containment does not reach backwards. What differs is
    whether the file ever ran at all, whether the spread had already reached
    the share, and whether anything stopped it.
    """
    def run(name, open_it, isolate_after_ms):
        driver, _ = session_for(tmp_path, name)
        if open_it:
            open_the_attachment(driver)
        if isolate_after_ms is not None:
            driver.advance(isolate_after_ms)
            isolate(driver)
        driver.advance(900000)
        return frozenset(unavailable(driver))

    # Never opened it, and pulled the cable anyway.
    no_incident = run("t-none.db", False, 0)
    # Opened it, then contained before the spread reached the share.
    before_spread = run("t-before.db", True, 20000)
    # Opened it, contained only after the share had already been hit -- but
    # before the uncontained continuation took the rest of it.
    after_spread = run("t-after.db", True, 35000)
    # Never contained it at all.
    never = run("t-never.db", True, None)

    histories = {"no_incident": no_incident, "before_spread": before_spread,
                 "after_spread": after_spread, "never": never}
    assert len(set(histories.values())) == 4, {
        key: sorted(value) for key, value in histories.items()}

    # And they are ordered: the earlier the containment, the less is lost.
    assert len(no_incident) < len(before_spread) < len(after_spread) \
        <= len(never)
    assert not no_incident
    assert not (before_spread & set(NETWORK_FILES))
    assert "f-q3-metrics" in after_spread


def test_containing_before_the_first_file_fails_is_still_containment(tmp_path):
    """A learner who reacts fastest must not be told they over-reacted.

    Pulling the cable ten seconds after opening a bad workbook happens before
    any incident banner exists, and judging it by the banner would record the
    single best response in the whole scenario as an over-reaction.
    """
    driver, _ = session_for(tmp_path, "fast.db")
    open_the_attachment(driver)
    isolate(driver)

    assert "d-ransom-isolate" in decisions(driver)
    assert "d-isolate-no-incident" not in decisions(driver)

    driver.advance(900000)
    entry = incident(driver.snapshot(), "inc-files")
    # The incident is real -- their own files did fail -- and it opens already
    # contained, because the steps that would have spread it never can.
    assert entry is not None
    assert entry["contained"] is True
    assert not (unavailable(driver) & set(NETWORK_FILES))


# ===========================================================================
# Containment is not recovery
# ===========================================================================

def test_containment_and_recovery_are_stored_as_two_different_things(tmp_path):
    driver, _ = session_for(tmp_path, "contain.db")
    open_the_attachment(driver)
    driver.advance(40000)
    isolate(driver)

    entry = incident(driver.snapshot(), "inc-files")
    assert entry["contained"] is True
    # Contained is the only claim made. There is no "recovered", no "resolved"
    # and no "safe" flag for a later batch to confuse with it.
    assert "recovered" not in entry
    assert "resolved" not in entry


def test_isolation_restores_nothing_at_all(tmp_path):
    driver, _ = session_for(tmp_path, "norestore.db")
    open_the_attachment(driver)
    driver.advance(40000)

    before_files = dict(driver.session().world.get_component(NS_FILES))
    before_notifications = len(driver.snapshot()["notifications"])
    isolate(driver)
    after_files = dict(driver.session().world.get_component(NS_FILES))

    for file_id, state in before_files.items():
        if state.get("state") == "unavailable":
            assert after_files[file_id]["state"] == "unavailable", file_id
    # Isolation adds to the world. It never subtracts.
    assert len(driver.snapshot()["notifications"]) >= before_notifications


def test_isolation_does_not_undo_an_account_compromise(tmp_path):
    """Pulling the cable does not evict a session at the mail provider."""
    driver, _ = session_for(tmp_path, "account.db", focus="phishing")
    driver.deliver_until("m-payroll-restructure")
    followed = driver.act("mail.open_link", "m-payroll-restructure", {"index": 0})
    driver.act("browser.sign_in", params={"url": followed.notice["url"]})
    driver.advance(400000)
    assert incident(driver.snapshot(), "inc-account") is not None

    isolate(driver)
    driver.advance(400000)
    assert incident(driver.snapshot(), "inc-account") is not None
    assert driver.session().world.get("mailbox", "rule")


# ===========================================================================
# D: isolating with nothing to contain
# ===========================================================================

def test_isolating_with_no_incident_costs_something(tmp_path):
    """Case D. Otherwise "pull the cable first" is free and always correct."""
    driver, _ = session_for(tmp_path, "case-d.db")
    isolate(driver)
    assert "d-isolate-no-incident" in decisions(driver)
    assert driver.snapshot()["session"]["network_disconnected"] is True

    driver.advance(200000)
    snapshot = driver.snapshot()
    remote = [t for t in snapshot["tasks"] if t["id"] == "task-remote-access"][0]
    assert remote["state"] == "interrupted"
    assert conversation(snapshot, "conv-tom-brennan")["entries"]


def test_isolating_with_no_incident_fabricates_no_incident(tmp_path):
    driver, _ = session_for(tmp_path, "case-d2.db")
    isolate(driver)
    driver.advance(600000)
    assert incident(driver.snapshot(), "inc-files") is None
    assert incident(driver.snapshot(), "inc-account") is None
    assert not unavailable(driver)


def test_an_isolated_workstation_receives_no_new_mail(tmp_path):
    """The operational cost that matters most: the day stops coming to you."""
    driver, _ = session_for(tmp_path, "case-d3.db", focus="mixed")
    isolate(driver)
    before = {m["id"] for m in driver.snapshot()["mail"]["messages"]
              if m["folder"] != "deleted"}
    delivered_before = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    driver.advance(900000)
    delivered_after = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    assert delivered_after == delivered_before, sorted(
        delivered_after - delivered_before)
    assert before


def test_an_isolated_workstation_is_quiet_not_dead(tmp_path):
    """Local notices still arrive. The machine is off the network, not off."""
    driver, _ = session_for(tmp_path, "case-d4.db", focus="mixed")
    isolate(driver)
    before = len(driver.snapshot()["notifications"])
    driver.advance(900000)
    assert len(driver.snapshot()["notifications"]) > before


def test_the_learner_can_still_finish_after_isolating(tmp_path):
    """Isolation must not soft-lock a session."""
    driver, _ = session_for(tmp_path, "case-d5.db")
    isolate(driver)
    # Investigation, note-taking, reporting and ending all still work.
    driver.act("files.inspect", "f-ops-notes")
    driver.act("notes.create")
    driver.act("browser.support_action", params={"choice": "raise"})
    driver.act("directory.open", "dir-lena-fischer")
    ended = driver.service.end_session(driver.session_id, driver.learner_ref)
    assert ended["session"]["active"] is False


# ===========================================================================
# E, F: persistence around the isolation boundary
# ===========================================================================

def test_persisting_immediately_before_isolation_gives_the_same_result(tmp_path):
    """Case E. A restart at the worst possible moment changes nothing."""
    # The same session id in both runs, so the comparison is of *history*
    # rather than of identity: event ids are derived from the session id, and
    # two differently named sessions would differ for an uninteresting reason.
    def continuous(uri_name):
        service, repository = build_service(sqlite_uri(tmp_path, uri_name),
                                            ids=["ws-case-e"])
        driver = Driver.start(service, focus="ransomware", mode="simulation")
        open_the_attachment(driver)
        driver.advance(20000)
        isolate(driver)
        driver.advance(600000)
        return repository.load(driver.session_id)

    def interrupted(uri_name):
        uri = sqlite_uri(tmp_path, uri_name)
        service, _ = build_service(uri, ids=["ws-case-e"])
        driver = Driver.start(service, focus="ransomware", mode="simulation")
        open_the_attachment(driver)
        driver.advance(20000)
        # The process dies here, before the learner presses the button.
        rebuilt, rebuilt_repo = build_service(uri)
        resumed = Driver(rebuilt, driver.session_id)
        isolate(resumed)
        resumed.advance(600000)
        return rebuilt_repo.load(resumed.session_id)

    whole = continuous("case-e-whole.db")
    split = interrupted("case-e-split.db")

    assert whole.now_ms == split.now_ms
    assert {f for f, s in whole.world.get_component(NS_FILES).items()
            if s.get("state") == "unavailable"} \
        == {f for f, s in split.world.get_component(NS_FILES).items()
            if s.get("state") == "unavailable"}
    assert whole.capture_state() == split.capture_state()


def test_persisting_immediately_after_isolation_keeps_the_block(tmp_path):
    """Case F. The latch is on disk, so a restart cannot lose it."""
    uri = sqlite_uri(tmp_path, "case-f.db")
    service, _ = build_service(uri, ids=["ws-case-f"])
    driver = Driver.start(service, focus="ransomware", mode="simulation")
    open_the_attachment(driver)
    driver.advance(20000)
    isolate(driver)
    latched = suppressed(driver)
    assert latched

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    assert set(engine_state.suppressed_steps(resumed.session())) == latched
    resumed.advance(900000)
    assert not (unavailable(resumed) & set(NETWORK_FILES))


# ===========================================================================
# G: repeated and stale isolation
# ===========================================================================

def test_isolating_twice_is_one_isolation(tmp_path):
    """Case G. No doubled incident, no doubled chain, no doubled consequence."""
    driver, _ = session_for(tmp_path, "case-g.db")
    open_the_attachment(driver)
    driver.advance(20000)
    isolate(driver)

    session = driver.session()
    consequences_before = len(list(session.incidents.consequences()))
    events_before = len([e for e in session.event_log.events()
                         if e.type == progression.SUPPRESSION_EVENT_TYPE])

    second = isolate(driver)
    assert second.notice["kind"] == "notice"

    session = driver.session()
    assert len(list(session.incidents.consequences())) == consequences_before
    assert len([e for e in session.event_log.events()
                if e.type == progression.SUPPRESSION_EVENT_TYPE]) == events_before
    assert len([d for d in decisions(driver) if d == "d-ransom-isolate"]) <= 1


def test_a_repeated_isolation_records_no_second_decision(tmp_path):
    driver, _ = session_for(tmp_path, "case-g2.db")
    isolate(driver)
    isolate(driver)
    isolate(driver)
    stored = driver.session().world.get(NS_DECISIONS, "d-isolate-no-incident")
    assert stored is not None
    # One decision record, one order number. It happened once.
    assert isinstance(stored["order"], int)


# ===========================================================================
# Reconnecting
# ===========================================================================

def test_reconnecting_restores_the_network_but_not_the_past(tmp_path):
    driver, _ = session_for(tmp_path, "reconnect.db")
    open_the_attachment(driver)
    driver.advance(20000)
    damage = unavailable(driver)
    isolate(driver)
    latched = suppressed(driver)

    reconnect(driver)
    assert driver.snapshot()["session"]["network_disconnected"] is False
    assert "d-network-reconnect" in decisions(driver)
    # The latch is a record of what was true when the step would have run.
    assert suppressed(driver) == latched
    driver.advance(900000)
    assert not (unavailable(driver) & set(NETWORK_FILES))
    assert damage <= unavailable(driver)


def test_reconnecting_lets_new_work_arrive_again(tmp_path):
    driver, _ = session_for(tmp_path, "reconnect2.db", focus="mixed")
    isolate(driver)
    driver.advance(300000)
    while_offline = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    reconnect(driver)
    driver.advance(900000)
    after = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    assert after > while_offline


def test_reconnecting_when_already_connected_changes_nothing(tmp_path):
    driver, repository = session_for(tmp_path, "reconnect3.db")
    before = repository.load(driver.session_id).capture_state()
    result = reconnect(driver)
    assert result.notice["kind"] == "notice"
    after = repository.load(driver.session_id).capture_state()
    # One learner action was recorded -- the learner really did press it -- and
    # nothing else about the world moved.
    assert after["world"] == before["world"]


def test_the_isolation_moment_is_recorded_once_and_never_cleared(tmp_path):
    driver, _ = session_for(tmp_path, "moment.db")
    driver.advance(30000)
    isolate(driver)
    first = engine_state.meta(driver.session())["isolated_at_ms"]
    assert first is not None

    reconnect(driver)
    driver.advance(60000)
    isolate(driver)
    assert engine_state.meta(driver.session())["isolated_at_ms"] == first


# ===========================================================================
# Nothing here touches a real machine
# ===========================================================================

def test_the_synthetic_file_damage_touches_no_host_file(tmp_path):
    """A file here is a row. ``.demo_locked`` is a display name, not a rename."""
    driver, _ = session_for(tmp_path, "synthetic.db")
    open_the_attachment(driver)
    driver.advance(900000)

    for file_id in unavailable(driver):
        state = driver.session().world.get(NS_FILES, file_id)
        assert state["state"] == "unavailable"
        assert isinstance(state["name"], str)
        # No path, no handle, no descriptor -- just a row with a label on it.
        assert "path" not in state
    # And the temporary directory this test was given holds only the database.
    files = sorted(p.name for p in pathlib.Path(tmp_path).iterdir())
    assert all(name.endswith(".db") for name in files), files


def test_no_ransomware_code_path_opens_a_file_or_runs_anything():
    repo_root = pathlib.Path(__file__).resolve().parent.parent
    for module in ("rewindsec/training/families/ransomware.py",
                   "rewindsec/training/progression.py",
                   "rewindsec/workstation/worldops.py"):
        source = io.open(repo_root / module, encoding="utf-8").read()
        for banned in ("subprocess", "os.remove", "os.rename", "shutil.",
                       "open(", "docker", "Popen"):
            assert banned not in source, (module, banned)


def test_the_engine_state_never_reaches_the_learner(tmp_path):
    driver, _ = session_for(tmp_path, "hidden.db")
    open_the_attachment(driver)
    driver.advance(40000)
    isolate(driver)
    document = json.dumps(driver.snapshot())
    for word in ("suppressed", "network_isolation", "isolated_at_ms",
                 "cand-ransom", "chain-file-incident", "s-file-3",
                 "training_engine", "pressure", "starved", "cooldown"):
        assert word not in document, word
