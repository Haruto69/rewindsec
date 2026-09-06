"""RewindSec 2.0 Batch 4 review correction: occurrence-scoped BEC payments.

The first correction pass made the BEC family recur -- a second, generated
occurrence of ``cand-bec2-account-change`` (``m-meridian-amend-o2``) with its
own opportunity and its own reply/report decisions -- but left the *authorize*
surface shared: one payments page, one release button, one ``d-bec2-authorize``
the whole session could record exactly once. A learner who released the payment
on the first occurrence had no consequential decision left to make on the
second, which is not a recurring opportunity at all.

This suite covers the correction. A payments page is a **release queue**, and
each entry in it is a *payment context*: a stable id, its own queue reference,
and the presented BEC occurrence it belongs to. Both Meridian entries settle
the same invoice of record -- MP-7734, £612.40, Bramwell Trust ending 7729 --
because the second occurrence is a follow-up chase on the same fraud, not a
second fabricated supplier. What is occurrence-specific is the *release
request*, and it is the release request that scopes the recorded decision, its
consequence chain, and the opportunity it resolves.
"""

import pytest

from rewindsec.scoring import evaluator
from rewindsec.scoring import evidence as ev
from rewindsec.scoring import opportunities as opp
from rewindsec.workstation.bootstrap import NS_BROWSER, NS_DECISIONS
from rewindsec.workstation.consequences import NS_CONSEQUENCE_MAP
from rewindsec.workstation.content import index as ix
from rewindsec.workstation.debrief import debrief_document
from rewindsec.workstation.errors import (StaleRevisionConflict,
                                          UnknownTargetError)
from tests.workstation_helpers import Driver, build_service, sqlite_uri, walk

MERIDIAN = "intranet.northbridge.example/finance/payments-meridian"
CALDERWOOD = "intranet.northbridge.example/finance/payments"
CANDIDATE = "cand-bec2-account-change"
OCC1, OCC2 = "m-meridian-amend", "m-meridian-amend-o2"
CTX1, CTX2 = "pay-mp-7734-r1", "pay-mp-7734-r2"
#: The changed account both Meridian occurrences ask for. One fraud, chased
#: twice -- the requested account never varies between occurrences.
CHANGED = "Corvane Bank - ending 3384"
AUTHORIZE = "d-bec2-authorize"


def driver_for(tmp_path, name="bec-occurrence.db", session_id="ws-bec-occ"):
    service, _ = build_service(sqlite_uri(tmp_path, name), ids=[session_id])
    return Driver.start(service, focus="bec", mode="simulation")


def both_occurrences(driver):
    """Deliver occurrence 1 and occurrence 2 of the recurring BEC candidate."""
    driver.act("mail.open", "m-meridian-invoice")
    driver.force(CANDIDATE)
    driver.force(CANDIDATE)
    delivered = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    assert {OCC1, OCC2} <= delivered
    driver.act("browser.navigate", params={"url": MERIDIAN})


def release(driver, context_id, account=CHANGED, url=MERIDIAN):
    return driver.act("browser.release_payment",
                      params={"url": url, "account": account,
                              "context": context_id})


def decision_rows(driver):
    """``NS_DECISIONS`` rows as ``(decision_class, occurrence_key)`` pairs."""
    return {(state.get("decision_class", key), state.get("occurrence_key"))
            for key, state
            in driver.session().world.get_component(NS_DECISIONS).items()}


def page(driver, url=MERIDIAN):
    return driver.snapshot()["browser"]["pages"][url]


def contexts(driver, url=MERIDIAN):
    return {c["id"]: c for c in page(driver, url).get("payment_contexts") or []}


def browser_mutations(driver):
    return [m for m in driver.session().world.mutations()
            if m.namespace == NS_BROWSER]


def evidence_for(driver, decision_id):
    """Evidence items produced by one semantic decision class, any occurrence."""
    return [item for item in ev.build_evidence(driver.session())
            if item.source.get("decision_id") == decision_id]


def ignored_opportunities(driver):
    return {item.opportunity_id for item in ev.build_evidence(driver.session())
            if item.evidence_type == "inaction"}


def score(driver):
    driver.service.end_session(driver.session_id, driver.learner_ref)
    return evaluator.evaluate(driver.session())


# ---------------------------------------------------------------------------
# The authored model
# ---------------------------------------------------------------------------

def test_every_payment_context_id_is_unique_across_the_whole_site_map():
    """A context id travels in world state and in evidence sources without the
    page it came from, so it has to identify one queue entry globally."""
    ids = [context["id"] for context in ix.PAYMENT_CONTEXT_BY_ID.values()]
    assert len(ids) == len(set(ids))


def test_each_payment_context_names_one_occurrence_and_one_decision():
    for context in ix.PAYMENT_CONTEXT_BY_ID.values():
        assert context["occurrence_key"] in ix.MAIL_BY_ID
        assert context["authorize_decision"] in ix.DECISION_BY_ID


def test_the_recurring_bec_surface_has_one_context_per_occurrence():
    from rewindsec.training import recurrence
    occurrences = recurrence.OCCURRENCE_MAIL_IDS[CANDIDATE]
    keys = [c["occurrence_key"] for c in ix.payment_contexts_for_page(MERIDIAN)]
    assert keys == list(occurrences)


def test_both_meridian_contexts_settle_the_same_invoice_of_record():
    """Recurrence here is a second release request against one real invoice --
    never a second fabricated supplier and never a second invented invoice."""
    page_def = ix.PAGE_BY_URL[MERIDIAN]
    assert page_def["invoice"]["supplier"] == "Meridian Print Services"
    entries = page_def["payment_contexts"]
    assert len({entry["queue_ref"] for entry in entries}) == len(entries)
    assert {entry["authorize_decision"] for entry in entries} == {AUTHORIZE}


def test_the_calderwood_surface_keeps_its_single_release_request():
    entries = ix.payment_contexts_for_page(CALDERWOOD)
    assert len(entries) == 1
    assert entries[0]["occurrence_key"] == "m-invoice-amend"
    assert entries[0]["authorize_decision"] == "d-bec-authorize"


# ---------------------------------------------------------------------------
# The second queue entry only exists once its own message has arrived
# ---------------------------------------------------------------------------

def test_the_second_release_request_is_absent_until_its_message_arrives(tmp_path):
    driver = driver_for(tmp_path, "occ2_absent.db")
    driver.act("mail.open", "m-meridian-invoice")
    driver.act("browser.navigate", params={"url": MERIDIAN})
    assert set(contexts(driver)) == {CTX1}
    driver.force(CANDIDATE)
    assert set(contexts(driver)) == {CTX1}
    driver.force(CANDIDATE)
    assert set(contexts(driver)) == {CTX1, CTX2}


def test_releasing_a_request_nothing_has_raised_is_refused(tmp_path):
    driver = driver_for(tmp_path, "occ2_refused.db")
    driver.act("mail.open", "m-meridian-invoice")
    driver.act("browser.navigate", params={"url": MERIDIAN})
    with pytest.raises(UnknownTargetError):
        release(driver, CTX2)


# ---------------------------------------------------------------------------
# A. Occurrence 1 verified safely, occurrence 2 authorizes
# ---------------------------------------------------------------------------

def test_a_safe_first_occurrence_does_not_suppress_the_second(tmp_path):
    driver = driver_for(tmp_path, "a_safe_then_authorize.db")
    both_occurrences(driver)
    driver.act("directory.call", "dir-meridian")           # verify, occurrence 1
    release(driver, CTX2)                                   # authorize, occurrence 2

    rows = decision_rows(driver)
    assert ("d-bec2-verify", None) in rows
    assert (AUTHORIZE, OCC2) in rows
    assert (AUTHORIZE, OCC1) not in rows

    # Distinct outcomes on the queue itself: one entry still outstanding, one
    # settled against an account that arrived by mail.
    live = contexts(driver)
    assert live[CTX1]["released_account"] is None
    assert live[CTX2]["released_account"] == CHANGED

    # Distinct evidence, of opposite sign, one per occurrence.
    assert [item.valence for item in evidence_for(driver, "d-bec2-verify")
            if item.dimension == "verification_discipline"] == [1]
    authorized = evidence_for(driver, AUTHORIZE)
    assert authorized
    assert {item.source["occurrence_key"] for item in authorized} == {OCC2}
    assert all(item.valence == -1 for item in authorized
               if item.evidence_type == "decision")
    # Neither occurrence was ignored: both were resolved, differently.
    assert not ignored_opportunities(driver) & {
        "mail:%s" % OCC1, "mail:%s" % OCC2}


# ---------------------------------------------------------------------------
# B. Both occurrences authorize -- two independent decisions
# ---------------------------------------------------------------------------

def test_both_occurrences_can_authorize_independently(tmp_path):
    driver = driver_for(tmp_path, "b_both_authorize.db")
    both_occurrences(driver)
    release(driver, CTX1)
    release(driver, CTX2)

    rows = decision_rows(driver)
    assert (AUTHORIZE, OCC1) in rows
    assert (AUTHORIZE, OCC2) in rows

    world = driver.session().world
    assert world.has(NS_DECISIONS, "%s@%s" % (AUTHORIZE, OCC1))
    assert world.has(NS_DECISIONS, "%s@%s" % (AUTHORIZE, OCC2))

    # Two distinct payment world mutations, one per release request.
    assert world.get(NS_BROWSER, "payment_released:%s" % CTX1) == CHANGED
    assert world.get(NS_BROWSER, "payment_released:%s" % CTX2) == CHANGED


def test_both_authorizations_have_distinct_causal_roots(tmp_path):
    driver = driver_for(tmp_path, "b_causal_roots.db")
    both_occurrences(driver)
    release(driver, CTX1)
    release(driver, CTX2)
    driver.advance(400000)

    session = driver.session()
    orders = {state["order"] for state
              in session.world.get_component(NS_DECISIONS).values()
              if state.get("decision_class") == AUTHORIZE}
    assert len(orders) == 2

    # Each authorization scheduled and settled its own chain, and the
    # consequence map is keyed per occurrence rather than per semantic class.
    mapped = list(session.world.get_component(NS_CONSEQUENCE_MAP))
    first = [key for key in mapped if key.startswith("%s@%s:" % (AUTHORIZE, OCC1))]
    second = [key for key in mapped if key.startswith("%s@%s:" % (AUTHORIZE, OCC2))]
    assert first and second
    assert not set(first) & set(second)

    # Distinct consequence records, and every one of them points at a
    # consequence that actually exists in the graph.
    consequence_ids = {session.world.get(NS_CONSEQUENCE_MAP, key)
                       for key in first + second}
    assert len(consequence_ids) == len(first) + len(second)
    assert all(session.incidents.has_consequence(cid) for cid in consequence_ids)


def test_two_authorizations_score_as_two_negative_outcomes(tmp_path):
    driver = driver_for(tmp_path, "b_scored.db")
    both_occurrences(driver)
    release(driver, CTX1)
    release(driver, CTX2)

    authorized = evidence_for(driver, AUTHORIZE)
    assert {item.source["occurrence_key"] for item in authorized} == {OCC1, OCC2}
    # The two occurrences' evidence never collapses into one bucket.
    assert len({item.opportunity_id for item in authorized}) == 2
    assert len({item.evidence_id for item in authorized}) == len(authorized)
    assert score(driver).dimensions["security_judgment"].score < 50


# ---------------------------------------------------------------------------
# C. Occurrence 2's action cannot resolve occurrence 1
# ---------------------------------------------------------------------------

def test_the_second_release_never_resolves_the_first_occurrence(tmp_path):
    driver = driver_for(tmp_path, "c_no_crosstalk.db")
    both_occurrences(driver)
    release(driver, CTX2)

    assert (AUTHORIZE, OCC1) not in decision_rows(driver)
    assert driver.session().world.get(
        NS_BROWSER, "payment_released:%s" % CTX1) is None

    # Occurrence 1's opportunity is still unresolved, and scoring says so --
    # while occurrence 2's is resolved by the decision that actually resolved it.
    ignored = ignored_opportunities(driver)
    assert "mail:%s" % OCC1 in ignored
    assert "mail:%s" % OCC2 not in ignored


def test_an_unqualified_release_settles_the_outstanding_request(tmp_path):
    """A client naming no context settles the first *outstanding* entry --
    never one already settled, so it can never re-resolve occurrence 1."""
    driver = driver_for(tmp_path, "c_unqualified.db")
    both_occurrences(driver)
    driver.act("browser.release_payment",
               params={"url": MERIDIAN, "account": CHANGED})
    assert (AUTHORIZE, OCC1) in decision_rows(driver)
    driver.act("browser.release_payment",
               params={"url": MERIDIAN, "account": CHANGED})
    assert (AUTHORIZE, OCC2) in decision_rows(driver)


def test_a_context_from_another_payments_page_never_resolves(tmp_path):
    driver = driver_for(tmp_path, "c_wrong_page.db")
    both_occurrences(driver)
    driver.act("browser.navigate", params={"url": CALDERWOOD})
    with pytest.raises(UnknownTargetError):
        release(driver, CTX2, url=CALDERWOOD)
    assert (AUTHORIZE, OCC2) not in decision_rows(driver)


def test_the_calderwood_surface_stays_scoped_to_its_own_occurrence(tmp_path):
    driver = driver_for(tmp_path, "c_calderwood.db")
    driver.act("mail.open", "m-vendor-invoice")
    driver.deliver_until("m-invoice-amend")
    driver.act("browser.navigate", params={"url": CALDERWOOD})
    driver.act("browser.release_payment",
               params={"url": CALDERWOOD,
                       "account": "Aveley Trust Bank - 23-08-71 - ending 9032"})
    assert ("d-bec-authorize", "m-invoice-amend") in decision_rows(driver)
    assert "mail:m-invoice-amend" not in ignored_opportunities(driver)


# ---------------------------------------------------------------------------
# D. Idempotency
# ---------------------------------------------------------------------------

def test_retrying_the_same_release_records_one_payment(tmp_path):
    driver = driver_for(tmp_path, "d_retry.db")
    both_occurrences(driver)
    release(driver, CTX2)
    before = len(browser_mutations(driver))

    release(driver, CTX2)
    release(driver, CTX2, account="Somewhere else entirely")

    assert len(browser_mutations(driver)) == before
    assert driver.session().world.get(
        NS_BROWSER, "payment_released:%s" % CTX2) == CHANGED
    rows = [key for key in driver.session().world.get_component(NS_DECISIONS)
            if key == "%s@%s" % (AUTHORIZE, OCC2)]
    assert len(rows) == 1


def test_a_retried_release_produces_no_second_consequence(tmp_path):
    driver = driver_for(tmp_path, "d_retry_chain.db")
    both_occurrences(driver)
    release(driver, CTX2)
    release(driver, CTX2)
    driver.advance(400000)

    session = driver.session()
    steps = [key for key in session.world.get_component(NS_CONSEQUENCE_MAP)
             if key.startswith("%s@%s:" % (AUTHORIZE, OCC2))]
    chain = ix.CHAIN_BY_ID["chain-payment-meridian"]
    assert len(steps) == len(chain["steps"])


def test_a_retried_release_to_the_account_of_record_is_inert(tmp_path):
    """A settled queue entry is settled. Releasing to the account of record
    and then "changing your mind" is not a second payment either."""
    driver = driver_for(tmp_path, "d_retry_record.db")
    both_occurrences(driver)
    of_record = contexts(driver)[CTX2]["account_of_record"]
    release(driver, CTX2, account=of_record)
    release(driver, CTX2, account=CHANGED)
    assert (AUTHORIZE, OCC2) not in decision_rows(driver)
    assert driver.session().world.get(
        NS_BROWSER, "payment_released:%s" % CTX2) == of_record


def test_a_different_occurrence_is_not_a_retry(tmp_path):
    """The other half of idempotency: same semantic class, different
    occurrence, is a valid independent decision -- not a duplicate."""
    driver = driver_for(tmp_path, "d_not_a_retry.db")
    both_occurrences(driver)
    release(driver, CTX1)
    before = len(browser_mutations(driver))
    release(driver, CTX2)
    assert len(browser_mutations(driver)) > before
    assert len([state for state
                in driver.session().world.get_component(NS_DECISIONS).values()
                if state.get("decision_class") == AUTHORIZE]) == 2


def test_a_stale_revision_is_still_refused(tmp_path):
    """Occurrence scoping changes nothing about stale-revision protection."""
    driver = driver_for(tmp_path, "d_stale.db")
    both_occurrences(driver)
    stale = driver.revision - 1
    with pytest.raises(StaleRevisionConflict):
        driver.act("browser.release_payment", revision=stale,
                   params={"url": MERIDIAN, "account": CHANGED,
                           "context": CTX2})
    assert (AUTHORIZE, OCC2) not in decision_rows(driver)


# ---------------------------------------------------------------------------
# E. Save/resume between the two occurrences
# ---------------------------------------------------------------------------

def test_payment_context_identity_survives_a_resume(tmp_path):
    uri = sqlite_uri(tmp_path, "e_resume.db")
    service, _ = build_service(uri, ids=["ws-bec-resume-pay"])
    driver = Driver.start(service, focus="bec", mode="simulation")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force(CANDIDATE)
    driver.act("browser.navigate", params={"url": MERIDIAN})
    release(driver, CTX1)
    before = contexts(driver)

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)
    assert contexts(resumed) == before
    assert resumed.session().world.get(
        NS_BROWSER, "payment_released:%s" % CTX1) == CHANGED

    # The second occurrence, delivered after the resume, still gets its own
    # queue entry and its own independent decision.
    resumed.force(CANDIDATE)
    assert set(contexts(resumed)) == {CTX1, CTX2}
    release(resumed, CTX2)
    rows = decision_rows(resumed)
    assert (AUTHORIZE, OCC1) in rows
    assert (AUTHORIZE, OCC2) in rows


def test_a_resumed_second_authorization_replays_identically(tmp_path):
    def run(name, resume):
        uri = sqlite_uri(tmp_path, name)
        service, _ = build_service(uri, ids=["ws-bec-replay"])
        driver = Driver.start(service, focus="bec", mode="simulation")
        both_occurrences(driver)
        release(driver, CTX1)
        if resume:
            rebuilt, _ = build_service(uri)
            driver = Driver(rebuilt, driver.session_id)
        release(driver, CTX2)
        driver.advance(400000)
        session = driver.session()
        return (
            sorted((key, state["order"], state.get("occurrence_key"))
                   for key, state
                   in session.world.get_component(NS_DECISIONS).items()),
            sorted(session.world.get_component(NS_CONSEQUENCE_MAP)),
        )

    assert run("e_replay_a.db", False) == run("e_replay_b.db", True)


# ---------------------------------------------------------------------------
# F. The Evidence Graph maps BEC evidence to the right occurrence
# ---------------------------------------------------------------------------

def test_each_bec_opportunity_knows_its_own_occurrence(tmp_path):
    driver = driver_for(tmp_path, "f_graph.db")
    both_occurrences(driver)
    release(driver, CTX1)
    release(driver, CTX2)

    opportunities = {o.opportunity_id: o
                     for o in opp.build_opportunities(driver.session())}
    assert opportunities["mail:%s" % OCC1].occurrence_key == OCC1
    assert opportunities["mail:%s" % OCC2].occurrence_key == OCC2
    assert AUTHORIZE in opportunities["mail:%s" % OCC1].resolving_decisions
    assert AUTHORIZE in opportunities["mail:%s" % OCC2].resolving_decisions
    # Both were resolved, so neither is recorded as ignored.
    assert not ignored_opportunities(driver) & {
        "mail:%s" % OCC1, "mail:%s" % OCC2}


def test_bec_evidence_carries_the_occurrence_that_produced_it(tmp_path):
    driver = driver_for(tmp_path, "f_sources.db")
    both_occurrences(driver)
    release(driver, CTX1)
    release(driver, CTX2)

    by_occurrence = {}
    for item in evidence_for(driver, AUTHORIZE):
        by_occurrence.setdefault(item.source["occurrence_key"], set()).add(
            item.opportunity_id)
    assert set(by_occurrence) == {OCC1, OCC2}
    # Each occurrence's evidence sits in its own bucket, named after the
    # occurrence-scoped record rather than the shared semantic class.
    assert by_occurrence[OCC1] == {"decision:%s@%s" % (AUTHORIZE, OCC1)}
    assert by_occurrence[OCC2] == {"decision:%s@%s" % (AUTHORIZE, OCC2)}


def test_one_authorization_resolves_exactly_one_opportunity(tmp_path):
    driver = driver_for(tmp_path, "f_no_double.db")
    both_occurrences(driver)
    release(driver, CTX2)
    authorized = evidence_for(driver, AUTHORIZE)
    assert {item.source["occurrence_key"] for item in authorized} == {OCC2}
    assert ignored_opportunities(driver) & {"mail:%s" % OCC1}


def test_the_debrief_names_both_releases(tmp_path):
    driver = driver_for(tmp_path, "f_debrief.db")
    both_occurrences(driver)
    release(driver, CTX1)
    release(driver, CTX2)
    driver.advance(400000)
    driver.service.end_session(driver.session_id, driver.learner_ref)
    document = debrief_document(driver.session())
    released = [path for path, value in walk(document)
                if value == "Released a payment"]
    assert len(released) >= 2


# ---------------------------------------------------------------------------
# G. Nothing about the occurrence structure reaches the learner
# ---------------------------------------------------------------------------

#: Keys that would tell a learner what a queue entry *is* rather than what it
#: says: the authored decision it records, which presented occurrence it
#: belongs to, and what raised it.
PAYMENT_FORBIDDEN_KEYS = frozenset({
    "authorize_decision", "occurrence_key", "requires_mail",
    "resolving_decisions", "analysis", "disposition",
})

#: Every learner-facing field a release-queue entry is allowed to carry.
PAYMENT_CONTEXT_FIELDS = frozenset({
    "id", "queue_ref", "reference", "supplier", "amount", "approved_by",
    "account_of_record", "released_account",
})


def test_the_release_queue_exposes_no_classification(tmp_path):
    driver = driver_for(tmp_path, "g_leakage.db")
    both_occurrences(driver)
    release(driver, CTX1)
    found = []
    for path, value in walk(driver.snapshot()):
        if isinstance(value, dict):
            found.extend("%s.%s" % (path, key) for key in value
                         if key in PAYMENT_FORBIDDEN_KEYS)
    assert found == []


def test_a_queue_entry_carries_no_decision_or_occurrence_id(tmp_path):
    driver = driver_for(tmp_path, "g_entry_fields.db")
    both_occurrences(driver)
    for context in contexts(driver).values():
        assert set(context) == PAYMENT_CONTEXT_FIELDS
        for value in context.values():
            text = str(value)
            assert OCC1 not in text and OCC2 not in text
            assert AUTHORIZE not in text


def test_the_queue_does_not_announce_a_message_that_has_not_arrived(tmp_path):
    """The second entry's existence is itself a tell that a second message is
    coming, so it must not exist before that message does."""
    driver = driver_for(tmp_path, "g_no_lookahead.db")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force(CANDIDATE)
    driver.act("browser.navigate", params={"url": MERIDIAN})
    delivered = {m["id"] for m in driver.snapshot()["mail"]["messages"]}
    assert OCC2 not in delivered
    assert CTX2 not in contexts(driver)
