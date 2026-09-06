"""Occurrence-scoped decision/evidence provenance for recurring opportunities.

Batch 4's recurrence correction (see ``rewindsec.training.recurrence`` and
``tests/test_rewindsec2_content_recurrence.py``) gave phishing, BEC and
ransomware each a second, generated occurrence with its own opportunity in
:mod:`rewindsec.scoring.opportunities`. What it left unsafe -- and what this
suite covers -- is that a *decision* about one occurrence could resolve a
different occurrence's opportunity, because the underlying storage in
:data:`rewindsec.workstation.bootstrap.NS_DECISIONS` treated a decision class
as unique for the whole session:

* MFA's hostile approve/deny decisions are recorded once per session, so a
  second raised prompt (its own opportunity, its own
  :class:`~rewindsec.domain.world.WorldMutation`) could not be independently
  resolved once the first prompt had already been answered.
* The two occurrences of the benefits phishing lure share a byte-identical
  look-alike portal, so a credential submission through either one recorded
  the same global decision -- meaning the *second* occurrence's own
  opportunity could never show a genuine credential-submission outcome, only
  ever "ignored".

:mod:`rewindsec.workstation.consequences` now supports an optional
``occurrence_key`` that scopes a decision's storage key
(``consequences._record_id``) to the specific occurrence it resolves, and
:mod:`rewindsec.scoring.opportunities`/:mod:`rewindsec.scoring.evidence` match
a resolving decision against the *opportunity's own* occurrence identity
(the mail id for a mail opportunity, the request id for a raised prompt) --
never merely "was this decision class ever recorded anywhere in the
session". BEC and ransomware's report/reply/open decisions already used a
distinct id per occurrence (no shared-class problem to begin with) and are
covered here only to prove the invariant holds uniformly across families.
"""

from rewindsec.scoring import evidence, opportunities as opp
from rewindsec.workstation import consequences
from rewindsec.workstation.bootstrap import NS_DECISIONS
from rewindsec.workstation.consequences import NS_CONSEQUENCE_MAP
from tests.workstation_helpers import Driver, build_service, sqlite_uri


def driver_for(tmp_path, name="occurrence_provenance.db", focus="mixed",
              mode="simulation", ids=None):
    service, repository = build_service(sqlite_uri(tmp_path, name), ids=ids)
    return Driver.start(service, focus=focus, mode=mode), repository


def _decision_rows(driver):
    """``{record_id: state}`` -- the raw, occurrence-scoped storage."""
    return dict(driver.session().world.get_component(NS_DECISIONS))


def _semantic_classes(driver):
    return {state.get("decision_class", record_id)
           for record_id, state in _decision_rows(driver).items()}


def _mail_opportunity(session, mail_id):
    return next(o for o in opp.build_opportunities(session)
               if o.opportunity_id == "mail:%s" % mail_id)


def _explanation_codes(items):
    return [item.explanation_code for item in items]


# ---------------------------------------------------------------------------
# A. Phishing: occurrence 1 reported, occurrence 2 ignored
# ---------------------------------------------------------------------------

def test_a_phishing_occurrence_1_reported_occurrence_2_stays_unresolved(tmp_path):
    driver, _ = driver_for(tmp_path, "a.db", focus="phishing")
    driver.force("cand-phish-benefits-lure")          # occurrence 0
    driver.act("mail.report", "m-benefits-verify")
    driver.force("cand-phish-benefits-lure")          # occurrence 1 (o2 mail)

    session = driver.session()
    occ1 = _mail_opportunity(session, "m-benefits-verify")
    occ2 = _mail_opportunity(session, "m-benefits-verify-o2")
    assert occ1.occurrence_key == "m-benefits-verify"
    assert occ2.occurrence_key == "m-benefits-verify-o2"

    items = evidence.build_evidence(session)
    codes = _explanation_codes(items)
    assert any(c.startswith("decision:safe:d-phish2-report") for c in codes)
    ignored_for_occ2 = [item for item in items
                        if item.opportunity_id == occ2.opportunity_id]
    assert ignored_for_occ2, "the second occurrence must not vanish silently"
    assert all(item.evidence_type == "inaction" for item in ignored_for_occ2)
    assert all(item.valence == -1 for item in ignored_for_occ2)
    # The report made about occurrence 1 must not also resolve occurrence 2.
    assert not any(item.opportunity_id == occ2.opportunity_id
                  and item.evidence_type == "decision" for item in items)


# ---------------------------------------------------------------------------
# B. Phishing: credentials submitted on both occurrences of the shared portal
# ---------------------------------------------------------------------------

def test_b_phishing_credentials_are_independent_per_occurrence(tmp_path):
    driver, _ = driver_for(tmp_path, "b.db", focus="phishing")

    driver.force("cand-phish-benefits-lure")          # occurrence 0
    driver.act("mail.open", "m-benefits-verify")
    nav1 = driver.act("mail.open_link", "m-benefits-verify", {"index": 0})
    driver.act("browser.sign_in", params={"url": nav1.notice["url"]})

    driver.force("cand-phish-benefits-lure")          # occurrence 1
    driver.act("mail.open", "m-benefits-verify-o2")
    nav2 = driver.act("mail.open_link", "m-benefits-verify-o2", {"index": 0})
    driver.act("browser.sign_in", params={"url": nav2.notice["url"]})

    rows = _decision_rows(driver)
    credential_rows = {record_id: state for record_id, state in rows.items()
                      if state.get("decision_class") == "d-phish2-credentials"}
    assert len(credential_rows) == 2, "each occurrence needs its own record"
    assert {state["occurrence_key"] for state in credential_rows.values()} == {
        "m-benefits-verify", "m-benefits-verify-o2"}
    # Two distinct storage keys -- never collapsed into one "already decided".
    assert set(credential_rows) == {
        "d-phish2-credentials@m-benefits-verify",
        "d-phish2-credentials@m-benefits-verify-o2"}

    # Both opportunities resolve independently, with their own evidence root
    # -- keyed by ``decision:<occurrence-scoped record id>``, not by the
    # shared semantic class, so the two occurrences' Tier 1 evidence can never
    # collide into one id.
    session = driver.session()
    items = evidence.build_evidence(session)
    roots = {item.opportunity_id: item for item in items
            if item.evidence_type == "decision" and item.dimension == "security_judgment"}
    root1 = roots["decision:d-phish2-credentials@m-benefits-verify"]
    root2 = roots["decision:d-phish2-credentials@m-benefits-verify-o2"]
    assert root1.source["action_id"] != root2.source["action_id"]
    assert root1.evidence_id != root2.evidence_id

    # Each occurrence's own chain settles into its own consequence root.
    driver.advance(20000)
    consequence_map = driver.session().world.get_component(NS_CONSEQUENCE_MAP)
    keys = [key for key in consequence_map
           if key.startswith("d-phish2-credentials@") and key.endswith(":s-cred-1")]
    assert len(keys) == 2
    assert consequence_map[keys[0]] != consequence_map[keys[1]]


# ---------------------------------------------------------------------------
# C. MFA: occurrence 1 denied, occurrence 2 approved
# ---------------------------------------------------------------------------

def test_c_mfa_occurrences_are_independently_actionable_and_scored(tmp_path):
    driver, _ = driver_for(tmp_path, "c.db", focus="mixed")
    driver.force("cand-mfa-after-compromise")
    req1 = driver.snapshot()["authenticator"]["requests"][0]["id"]
    driver.act("auth.deny", req1)

    driver.force("cand-mfa-after-compromise")
    req2 = next(r["id"] for r in driver.snapshot()["authenticator"]["requests"]
               if r["id"] != req1)
    driver.act("auth.approve", req2)

    rows = _decision_rows(driver)
    assert rows["d-mfa-deny-hostile@%s" % req1]["occurrence_key"] == req1
    assert rows["d-mfa-approve-hostile@%s" % req2]["occurrence_key"] == req2
    assert "d-mfa-deny-hostile@%s" % req2 not in rows
    assert "d-mfa-approve-hostile@%s" % req1 not in rows

    session = driver.session()
    opportunities = {o.source["request_id"]: o for o in opp.build_opportunities(session)
                    if o.opportunity_type == "prompt"}
    assert set(opportunities) == {req1, req2}

    items = evidence.build_evidence(session)
    decision_items = {item.opportunity_id: item for item in items
                      if item.evidence_type == "decision"
                      and item.dimension == "security_judgment"}
    root1 = decision_items["decision:d-mfa-deny-hostile@%s" % req1]
    root2 = decision_items["decision:d-mfa-approve-hostile@%s" % req2]
    assert root1.valence == 1    # denied -- safe
    assert root2.valence == -1   # approved -- unsafe


def test_c_mfa_retry_after_resolution_is_refused_not_duplicated(tmp_path):
    """A resolved request cannot be re-resolved -- the world guard, not just
    decision uniqueness, is what makes a UI retry safe."""
    import pytest

    from rewindsec.workstation.errors import UnknownTargetError

    driver, _ = driver_for(tmp_path, "c_retry.db", focus="mixed")
    driver.force("cand-mfa-after-compromise")
    req1 = driver.snapshot()["authenticator"]["requests"][0]["id"]
    driver.act("auth.deny", req1)
    with pytest.raises(UnknownTargetError):
        driver.act("auth.deny", req1)


# ---------------------------------------------------------------------------
# D. BEC: the second occurrence is independently resolvable
# ---------------------------------------------------------------------------

def test_d_bec_second_occurrence_independently_resolved_by_its_own_reply(tmp_path):
    driver, _ = driver_for(tmp_path, "d1.db", focus="bec")
    driver.act("mail.open", "m-meridian-invoice")     # satisfy the OBSERVED gate
    driver.force("cand-bec2-account-change")          # occurrence 0
    driver.act("directory.call", "dir-meridian")      # verify occurrence 1 safely
    driver.force("cand-bec2-account-change")          # occurrence 1 (o2 mail)
    driver.act("mail.reply", "m-meridian-amend-o2", {"text": "Confirming."})

    session = driver.session()
    items = evidence.build_evidence(session)
    # Tier 1 evidence for a *resolved* decision is keyed by
    # ``decision:<record_id>`` (see evidence._decision_evidence), not by the
    # Opportunity's own id -- that pairing is what the resolution-matching
    # step above already checked. Reading these decision codes straight off
    # the graph is the direct way to confirm each occurrence's own outcome
    # actually landed.
    codes = [item.explanation_code for item in items]
    assert any(c.startswith("decision:safe:d-bec2-verify") for c in codes), (
        "occurrence 1's verification must be recorded")
    assert any(c.startswith("decision:unsafe:d-bec3-reply") for c in codes), (
        "occurrence 2's own reply must be recorded independently")


def test_d_bec_ignoring_occurrence_2_does_not_borrow_occurrence_1s_outcome(tmp_path):
    driver, _ = driver_for(tmp_path, "d2.db", focus="bec")
    driver.act("mail.open", "m-meridian-invoice")
    driver.force("cand-bec2-account-change")
    driver.act("mail.report", "m-meridian-amend")     # occurrence 1: reported
    driver.force("cand-bec2-account-change")          # occurrence 2: left alone

    session = driver.session()
    occ2 = _mail_opportunity(session, "m-meridian-amend-o2")
    items = evidence.build_evidence(session)
    # Occurrence 1 was resolved (a report decision was recorded for it).
    assert any(item.explanation_code.startswith("decision:safe:d-bec2-report")
              for item in items)
    # Occurrence 2, left alone, produces its own negative "ignored" evidence,
    # under its own opportunity id -- never occurrence 1's report standing in
    # for it.
    occ2_items = [i for i in items if i.opportunity_id == occ2.opportunity_id]
    assert occ2_items and all(i.evidence_type == "inaction" for i in occ2_items)


# ---------------------------------------------------------------------------
# E. Ransomware: occurrence 1 handled safely, occurrence 2 opened unsafely
# ---------------------------------------------------------------------------

def test_e_ransomware_second_occurrence_still_produces_its_own_consequence(tmp_path):
    driver, _ = driver_for(tmp_path, "e.db", focus="ransomware")
    driver.force("cand-ransom-audit-checklist")       # occurrence 0
    driver.act("mail.report", "m-audit-checklist")    # handled safely

    driver.force("cand-ransom-audit-checklist")       # occurrence 1 (o2 mail)
    driver.act("mail.open", "m-audit-checklist-o2")
    driver.act("mail.download_attachment", "m-audit-checklist-o2", {"index": 0})
    driver.act("files.open", "f-dl-m-audit-checklist-o2-0")

    classes = _semantic_classes(driver)
    assert "d-ransom2-report" in classes
    assert "d-ransom3-open" in classes
    assert "d-ransom2-open" not in classes  # occurrence 1 was never opened

    driver.advance(200000)
    session = driver.session()
    # The second occurrence's own chain fired and settled into the shared
    # synthetic file-incident model, independent of the first occurrence
    # having been handled safely.
    incidents = session.incidents.consequences()
    assert len(incidents) > 0
    items = evidence.build_evidence(session)
    codes = [item.explanation_code for item in items]
    assert any(c.startswith("decision:safe:d-ransom2-report") for c in codes)
    assert any(c.startswith("decision:unsafe:d-ransom3-open") for c in codes)


# ---------------------------------------------------------------------------
# F. Idempotency: the same occurrence/action retried records nothing extra
# ---------------------------------------------------------------------------

def test_f_recording_the_same_occurrence_twice_is_a_no_op(tmp_path):
    driver, _ = driver_for(tmp_path, "f.db", focus="mixed")
    session = driver.session()
    first = consequences.record_decision(
        session, "d-mfa-approve-hostile", "act-1", "Authenticator", {},
        occurrence_key="req-fixed")
    assert first is not None
    before = dict(session.world.get_component(NS_DECISIONS))

    second = consequences.record_decision(
        session, "d-mfa-approve-hostile", "act-1", "Authenticator", {},
        occurrence_key="req-fixed")
    assert second is None
    after = dict(session.world.get_component(NS_DECISIONS))
    assert before == after, "a retried occurrence must record nothing new"

    # A *different* occurrence with the same semantic class is still valid.
    third = consequences.record_decision(
        session, "d-mfa-approve-hostile", "act-2", "Authenticator", {},
        occurrence_key="req-other")
    assert third is not None
    assert len(session.world.get_component(NS_DECISIONS)) == 2


# ---------------------------------------------------------------------------
# G. Save/resume preserves occurrence identity
# ---------------------------------------------------------------------------

def test_g_occurrence_identity_survives_a_save_and_resume(tmp_path):
    uri = sqlite_uri(tmp_path, "g.db")
    service, _ = build_service(uri, ids=["ws-occurrence-resume"])
    driver = Driver.start(service, focus="mixed", mode="simulation")

    driver.force("cand-mfa-after-compromise")
    req1 = driver.snapshot()["authenticator"]["requests"][0]["id"]
    driver.act("auth.deny", req1)

    before_rows = _decision_rows(driver)

    rebuilt, _ = build_service(uri)
    resumed = Driver(rebuilt, driver.session_id)

    resumed.force("cand-mfa-after-compromise")
    req2 = next(r["id"] for r in resumed.snapshot()["authenticator"]["requests"]
               if r["id"] != req1)
    resumed.act("auth.approve", req2)

    after_rows = _decision_rows(resumed)
    # Occurrence 1's record, written before the resume, is byte-identical.
    key1 = "d-mfa-deny-hostile@%s" % req1
    assert after_rows[key1] == before_rows[key1]
    # Occurrence 2, resolved only after the resume, is its own new record.
    key2 = "d-mfa-approve-hostile@%s" % req2
    assert key2 in after_rows and key2 not in before_rows


# ---------------------------------------------------------------------------
# H. The Evidence Graph maps every item to the correct occurrence
# ---------------------------------------------------------------------------

def test_h_evidence_graph_maps_each_item_to_its_own_occurrence(tmp_path):
    driver, _ = driver_for(tmp_path, "h.db", focus="mixed")

    driver.force("cand-mfa-after-compromise")
    req1 = driver.snapshot()["authenticator"]["requests"][0]["id"]
    driver.act("auth.deny", req1)
    driver.force("cand-mfa-after-compromise")
    req2 = next(r["id"] for r in driver.snapshot()["authenticator"]["requests"]
               if r["id"] != req1)
    driver.act("auth.approve", req2)

    session = driver.session()
    # Every opportunity this session presented -- resolved or not -- so we
    # can confirm both raised prompts are tracked as genuinely separate
    # occurrences, independent of how their evidence happens to resolve.
    opportunities = opp.build_opportunities(session)
    prompt_ids = {o.opportunity_id for o in opportunities if o.opportunity_type == "prompt"}
    assert prompt_ids == {"prompt:%s" % req1, "prompt:%s" % req2}

    items = evidence.build_evidence(session)
    by_opportunity = {}
    for item in items:
        by_opportunity.setdefault(item.opportunity_id, []).append(item)

    # A resolved occurrence's Tier 1 evidence is filed under
    # ``decision:<occurrence-scoped record id>``, one bucket per occurrence --
    # the mapping this whole suite exists to guarantee.
    key1 = "decision:d-mfa-deny-hostile@%s" % req1
    key2 = "decision:d-mfa-approve-hostile@%s" % req2
    assert key1 in by_opportunity and key2 in by_opportunity
    req1_sources = {i.source.get("action_id") for i in by_opportunity[key1]}
    req2_sources = {i.source.get("action_id") for i in by_opportunity[key2]}
    assert req1_sources and req2_sources
    assert req1_sources.isdisjoint(req2_sources)
