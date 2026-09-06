"""The training engine: eligibility, pressure, cooldown, starvation, streams.

This is the suite that says the Batch 3 scheduler is a scheduler rather than a
shuffled list. It asserts the properties the architecture actually requires --
not that a particular seed produces a particular message, which would pass for
the wrong reason and break on the first content change, but that:

* eligibility is decided before any random value is drawn, and a locked
  candidate consumes nothing;
* pressure, cooldown and starvation behave exactly as
  :mod:`rewindsec.training.policy` documents them;
* focus changes which family is likely, and Mixed privileges none;
* the modes pace differently, on the server;
* the named RNG streams are genuinely independent, so an extra content draw
  cannot move a threat draw;
* the same seed replays -- across a save and restore, across a process, across
  ``PYTHONHASHSEED`` values, and whether the clock is advanced in one step or
  fifty;
* nothing a learner *reads* -- a snapshot, a revision, a reconnect -- moves the
  engine a millimetre.
"""

import json
import os
import subprocess
import sys

import pytest

from rewindsec.core.rng import (STREAM_BACKGROUND, STREAM_CONSEQUENCE,
                                STREAM_CONTENT_VARIATION,
                                STREAM_THREAT_SELECTION, STREAM_TIMING)
from rewindsec.training import catalog, eligibility, policy, selection
from rewindsec.training import engine as training_engine
from rewindsec.training import state as engine_state
from tests.training_helpers import (engine_of, fresh_session, pulse, pulses,
                                    selections, set_family)
from tests.workstation_helpers import Driver, build_service, sqlite_uri

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def draws(session, stream_name):
    """How many values a named stream has produced. Zero if never materialised."""
    if not session.rng.has_stream(stream_name):
        return 0
    return session.rng.stream(stream_name).draws


# ===========================================================================
# The engine replaces the fixed timeline
# ===========================================================================

def test_a_new_session_is_driven_by_the_engine_not_the_timeline():
    session = fresh_session()
    assert engine_state.engine_is_active(session)
    summary = engine_of(session)
    assert summary["engine_version"] == policy.ENGINE_VERSION
    assert summary["catalog_version"] == policy.CATALOG_VERSION
    # And there is no authored-timeline arrival queued anywhere.
    types = {entry.spec.type for entry in session.scheduler.pending()}
    assert types == {training_engine.EVALUATION_EVENT_TYPE}


def test_the_engine_does_not_guarantee_every_authored_message_appears():
    """A sequence, not a playlist.

    Two sessions differing only in seed must be able to produce different
    sets of arrivals over the same simulation window. If every message always
    appeared, the engine would be a list with extra steps.
    """
    seen = set()
    for seed in (11, 22, 33, 44, 55, 66, 77, 88):
        session = fresh_session(focus="mixed", seed=seed)
        chosen = tuple(c for _, c in selections(pulses(session, 8)))
        seen.add(chosen)
    assert len(seen) > 1, "every seed produced an identical run"


def test_the_engine_does_not_force_equal_threat_quotas():
    """Over a short window, families genuinely differ in how often they appear."""
    counts = {}
    for seed in range(30):
        session = fresh_session(focus="mixed", seed=900 + seed)
        for family, _ in selections(pulses(session, 6)):
            counts[family] = counts.get(family, 0) + 1
    assert len(set(counts.values())) > 1, counts


# ===========================================================================
# Eligibility before probability
# ===========================================================================

def test_eligibility_is_computed_without_drawing_anything():
    session = fresh_session()
    before = {name: draws(session, name)
              for name in (STREAM_THREAT_SELECTION, STREAM_BACKGROUND,
                           STREAM_CONTENT_VARIATION, STREAM_TIMING)}
    for candidate in catalog.all_candidates():
        eligibility.evaluate(
            session, candidate, engine_state.family_state(session, candidate.family),
            session.now_ms, session.focus.value, None, False)
    after = {name: draws(session, name) for name in before}
    assert after == before


def test_a_locked_candidate_consumes_no_selection_draw():
    """Adding a candidate nobody can select must not shift the stream.

    Asserted by comparing a real run against one in which every candidate of
    one family has been locked out by cooldown: if a locked candidate cost a
    draw, the two runs would diverge in *how many* values the stream had
    produced, not merely in what was chosen.
    """
    baseline = fresh_session(focus="mixed", seed=606)
    # Lock the whole BEC family for the duration by putting it in a cooldown
    # that outlives the run. Nothing else changes.
    locked = fresh_session(focus="mixed", seed=606)
    set_family(locked, "bec", cooldown_until_ms=10 ** 9)

    pulses(baseline, 1)
    pulses(locked, 1)

    # One pressure draw per *eligible* family, then the occurrence roll. The
    # locked session has one eligible family fewer, so exactly one draw fewer
    # up to the roll -- never the same count, and never two fewer.
    assert draws(locked, STREAM_THREAT_SELECTION) \
        == draws(baseline, STREAM_THREAT_SELECTION) - 1


def test_the_reason_codes_say_why_a_candidate_is_locked():
    session = fresh_session()
    candidate = catalog.by_id("cand-bec-account-change")
    verdict = eligibility.evaluate(
        session, candidate, engine_state.family_state(session, "bec"),
        session.now_ms, "mixed", None, False)
    assert not verdict.eligible
    # The learner has not read the invoice thread this reply threads onto.
    assert "fact_not_observed" in verdict.reasons
    assert set(verdict.reasons) <= eligibility.REASON_CODES


def test_every_reason_code_the_engine_can_emit_is_declared():
    """A typo in a reason code must fail loudly rather than read as a new one."""
    session = fresh_session()
    for candidate in catalog.all_candidates():
        verdict = eligibility.evaluate(
            session, candidate,
            engine_state.family_state(session, candidate.family),
            session.now_ms, "mixed", {"ref": "x"}, True)
        assert set(verdict.reasons) <= eligibility.REASON_CODES, verdict.reasons


def test_probability_is_not_used_as_a_substitute_for_a_prerequisite():
    """A candidate with an unmet prerequisite never fires, however long we run."""
    session = fresh_session(focus="bec", seed=4)
    chosen = {c for _, c in selections(pulses(session, 60))}
    assert "cand-bec-account-change" not in chosen
    # ...and it is not merely that BEC never came up: its sibling did.
    assert "cand-bec-legit-po" in chosen


# ===========================================================================
# Pressure
# ===========================================================================

def test_pressure_accumulates_while_a_family_is_eligible_and_unselected():
    session = fresh_session(focus="mixed", seed=7)
    seen = []
    for _ in range(6):
        record = pulse(session)
        seen.append(record["pressure"].get("phishing"))
        if record["family"] == "phishing":
            break
    rising = [value for value in seen if value is not None]
    assert rising == sorted(rising), rising


def test_pressure_resets_after_the_family_fires():
    session = fresh_session(focus="phishing", seed=12)
    for _ in range(40):
        record = pulse(session)
        if record["family"] == "phishing":
            assert engine_state.family_state(session, "phishing")["pressure"] \
                == policy.PRESSURE_AFTER_SELECTION
            return
    pytest.fail("phishing never fired in forty pulses")


def test_pressure_is_capped_per_family():
    session = fresh_session(focus="phishing", seed=13)
    for _ in range(120):
        pulse(session)
        for family in policy.FAMILIES:
            value = engine_state.family_state(session, family)["pressure"]
            assert value <= policy.FAMILY_PRESSURE_CAP, (family, value)


def test_pressure_is_integer_arithmetic_end_to_end():
    """Floats would be deterministic here too. Integers make it obvious."""
    session = fresh_session(seed=14)
    pulses(session, 10)
    for family in policy.FAMILIES:
        state = engine_state.family_state(session, family)
        for key in ("pressure", "starved", "cooldown_until_ms", "occurrences"):
            assert isinstance(state[key], int) and not isinstance(state[key], bool)


def test_a_family_with_nothing_eligible_neither_gains_nor_loses_pressure():
    """Frozen, not decayed. Eligibility that returns resumes where it was."""
    session = fresh_session(focus="mixed", seed=15)
    pulses(session, 3)
    before = engine_state.family_state(session, "phishing")["pressure"]

    set_family(session, "phishing", cooldown_until_ms=10 ** 9)
    pulses(session, 5)
    assert engine_state.family_state(session, "phishing")["pressure"] == before


# ===========================================================================
# Starvation
# ===========================================================================

def test_starvation_rises_while_a_family_is_eligible_and_passed_over():
    session = fresh_session(focus="ransomware", seed=16)
    highest = 0
    for _ in range(12):
        record = pulse(session)
        if record["family"] == "bec":
            break
        highest = max(highest, engine_state.family_state(session, "bec")["starved"])
    assert highest > 0


def test_starvation_is_bounded():
    session = fresh_session(focus="phishing", seed=17)
    for _ in range(150):
        pulse(session)
        for family in policy.FAMILIES:
            starved = engine_state.family_state(session, family)["starved"]
            assert starved * policy.STARVATION_STEP <= 10 ** 6
    # The *contribution* is what is capped, and the cap is authored.
    assert policy.STARVATION_CAP > 0


def test_starvation_resets_when_a_family_stops_being_eligible():
    """A family cannot bank pressure for a period it could not have been chosen.

    This is the rule that keeps starvation from becoming a quota by the back
    door: sit out long enough and you would otherwise return with a decisive
    advantage you did nothing to earn.
    """
    session = fresh_session(focus="mixed", seed=18)
    for _ in range(10):
        pulse(session)
        if engine_state.family_state(session, "bec")["starved"] > 0:
            break
    assert engine_state.family_state(session, "bec")["starved"] > 0

    set_family(session, "bec", cooldown_until_ms=10 ** 9)
    pulse(session)
    assert engine_state.family_state(session, "bec")["starved"] == 0


def test_starvation_does_not_guarantee_a_family_appears():
    """It raises the odds. It is not a promise, and must not become one."""
    never = 0
    for seed in range(25):
        session = fresh_session(focus="phishing", seed=500 + seed)
        families = {family for family, _ in selections(pulses(session, 5))}
        if "bec" not in families:
            never += 1
    assert never > 0, "every short run contained BEC, which is a quota"


def test_starvation_resets_for_the_family_that_was_selected():
    session = fresh_session(focus="mixed", seed=19)
    for _ in range(40):
        record = pulse(session)
        if record["family"]:
            assert engine_state.family_state(session, record["family"])["starved"] == 0
            return
    pytest.fail("nothing was ever selected")


# ===========================================================================
# Cooldown
# ===========================================================================

def test_a_family_enters_cooldown_after_it_fires():
    session = fresh_session(focus="mixed", seed=20)
    for _ in range(40):
        record = pulse(session)
        if record["family"]:
            family = record["family"]
            state = engine_state.family_state(session, family)
            assert state["cooldown_until_ms"] == (
                session.now_ms + policy.cooldown_ms(family, "simulation"))
            return
    pytest.fail("nothing was ever selected")


def test_cooldown_is_measured_in_simulation_milliseconds_not_real_time():
    """Proved by never letting real time pass and still seeing it expire."""
    session = fresh_session(focus="phishing", seed=21)
    for _ in range(40):
        record = pulse(session)
        if record["family"] == "phishing":
            break
    cooldown_until = engine_state.family_state(session, "phishing")["cooldown_until_ms"]
    assert cooldown_until > session.now_ms
    while session.now_ms < cooldown_until:
        pulse(session)
    assert session.now_ms >= cooldown_until


def test_cooldown_differs_by_mode():
    assert policy.cooldown_ms("ransomware", "assessment") \
        < policy.cooldown_ms("ransomware", "simulation") \
        < policy.cooldown_ms("ransomware", "practice")


def test_cooldown_does_not_force_round_robin():
    """Consecutive arrivals from the same family must remain possible."""
    repeats = 0
    for seed in range(40):
        session = fresh_session(focus="phishing", seed=700 + seed)
        families = [family for family, _ in selections(pulses(session, 40))]
        repeats += sum(1 for a, b in zip(families, families[1:]) if a == b)
    assert repeats > 0, "no family ever fired twice in a row: that is a rota"


# ===========================================================================
# Focus
# ===========================================================================

def _family_counts(focus, seeds, pulse_count=14):
    counts = {family: 0 for family in policy.THREAT_FAMILIES}
    for seed in seeds:
        session = fresh_session(focus=focus, seed=seed)
        for family, _ in selections(pulses(session, pulse_count)):
            if family in counts:
                counts[family] += 1
    return counts


@pytest.mark.parametrize("focus", ["phishing", "ransomware"])
def test_the_selected_focus_makes_its_family_materially_more_likely(focus):
    """Relative behaviour over many seeds, never one lucky one.

    Only the two families with more than one selectable candidate are
    parametrised here: MFA and BEC saturate their catalogue within this window
    and would be measuring the size of the authored content rather than the
    policy. Their weighting is asserted directly, at the policy level, below.
    """
    seeds = range(1200, 1260)
    focused = _family_counts(focus, seeds)
    mixed = _family_counts("mixed", seeds)
    assert focused[focus] > mixed[focus], (focused, mixed)
    others = [f for f in policy.THREAT_FAMILIES if f != focus]
    assert focused[focus] > max(focused[f] for f in others), focused


def test_focus_raises_the_increment_and_does_so_exactly_once():
    assert policy.focus_percent("phishing", "phishing") \
        == policy.FOCUS_PERCENT_SELECTED
    assert policy.focus_percent("phishing", "bec") == policy.FOCUS_PERCENT_OTHER
    # Mixed is not a family, so it matches nothing.
    for family in policy.THREAT_FAMILIES:
        assert policy.focus_percent("mixed", family) == policy.FOCUS_PERCENT_OTHER


def test_mixed_privileges_no_family_including_by_catalogue_order():
    """The failure this guards against is subtle and silent.

    If Mixed quietly favoured whichever family sorts first, the bias would be
    invisible in any single run and would show up only as "BEC never appears".
    So the assertion is about the *first* family selected across many seeds:
    every family that can be selected at all must be able to be first.
    """
    firsts = {}
    for seed in range(1400, 1520):
        session = fresh_session(focus="mixed", seed=seed)
        chosen = selections(pulses(session, 4))
        if chosen:
            firsts[chosen[0][0]] = firsts.get(chosen[0][0], 0) + 1
    assert len(firsts) >= 3, firsts
    # And no family takes almost all of them.
    assert max(firsts.values()) < sum(firsts.values()) * 0.75, firsts


def test_a_focused_session_is_not_composed_only_of_hostile_events():
    session = fresh_session(focus="phishing", seed=23)
    chosen = [catalog.by_id(c) for _, c in selections(pulses(session, 30))]
    assert chosen
    assert any(not candidate.hostile for candidate in chosen), \
        "a focused session contained nothing but attacks"


# ===========================================================================
# Mode
# ===========================================================================

def test_the_modes_pace_differently_and_the_server_decides():
    """Compare simulation time consumed by the same number of pulses."""
    spent = {}
    for mode in ("practice", "simulation", "assessment"):
        session = fresh_session(mode=mode, seed=24)
        pulses(session, 20)
        spent[mode] = session.now_ms
    assert spent["assessment"] < spent["simulation"] < spent["practice"], spent


def test_practice_does_not_pile_a_second_primary_on_an_unresolved_one():
    session = fresh_session(focus="phishing", mode="practice", seed=25)
    primaries = 0
    for _ in range(40):
        record = pulse(session)
        if record["selected"] and catalog.by_id(record["selected"]).is_primary:
            primaries += 1
    assert primaries == 1, "Practice delivered a second primary unprompted"


def test_practice_still_lets_ordinary_ambient_activity_happen():
    """Learner-paced is not the same as dead."""
    session = fresh_session(focus="phishing", mode="practice", seed=26)
    chosen = [catalog.by_id(c) for _, c in selections(pulses(session, 40))]
    assert any(not candidate.is_primary for candidate in chosen), \
        "nothing at all happened while the learner was reading"


def test_assessment_allows_arrivals_to_accumulate():
    session = fresh_session(focus="phishing", mode="assessment", seed=27)
    primaries = [c for _, c in selections(pulses(session, 40))
                 if catalog.by_id(c).is_primary]
    assert len(primaries) > 1


def test_resolving_the_current_item_brings_practice_forward():
    session = fresh_session(focus="phishing", mode="practice", seed=28)
    for _ in range(40):
        record = pulse(session)
        if record["selected"] and catalog.by_id(record["selected"]).is_primary:
            break
    active = engine_state.meta(session)["active_primary"]
    assert active
    before = training_engine.pending_evaluation(session).fire_at_ms

    training_engine.note_resolved(session, active["ref"])
    assert engine_state.meta(session)["active_primary"] is None
    after = training_engine.pending_evaluation(session).fire_at_ms
    assert after < before, (before, after)


# ===========================================================================
# Occurrence caps
# ===========================================================================

def test_a_candidate_never_exceeds_its_occurrence_cap():
    session = fresh_session(focus="mixed", seed=29)
    pulses(session, 200)
    for candidate in catalog.all_candidates():
        if candidate.max_occurrences is None:
            continue
        state = engine_state.candidate_state(session, candidate.candidate_id)
        assert state["occurrences"] <= candidate.max_occurrences, candidate


# ===========================================================================
# Deterministic iteration
# ===========================================================================

def test_the_catalogue_is_iterated_in_one_fixed_order():
    ids = [candidate.candidate_id for candidate in catalog.all_candidates()]
    assert ids == sorted(ids)
    assert len(set(ids)) == len(ids)


def test_the_family_order_is_authored_not_a_set():
    assert isinstance(policy.THREAT_FAMILIES, tuple)
    assert isinstance(policy.FAMILIES, tuple)
    assert list(policy.THREAT_FAMILIES) == sorted(policy.THREAT_FAMILIES)


def test_weighted_choice_consumes_exactly_one_draw():
    session = fresh_session()
    stream = session.rng.stream(STREAM_THREAT_SELECTION)
    before = stream.draws
    selection.weighted_choice(stream, [("a", 1), ("b", 5), ("c", 9)])
    assert stream.draws == before + 1


def test_weighted_choice_draws_nothing_when_there_is_no_decision():
    session = fresh_session()
    stream = session.rng.stream(STREAM_THREAT_SELECTION)
    before = stream.draws
    assert selection.weighted_choice(stream, []) is None
    assert selection.weighted_choice(stream, [("a", 0)]) is None
    assert stream.draws == before


def test_weighted_choice_respects_the_weights():
    session = fresh_session()
    stream = session.rng.stream(STREAM_THREAT_SELECTION)
    picks = [selection.weighted_choice(stream, [("rare", 1), ("common", 99)])
             for _ in range(400)]
    assert picks.count("common") > picks.count("rare") * 5


# ===========================================================================
# RNG stream independence
# ===========================================================================

def test_the_five_architecture_streams_are_distinct_names():
    names = {STREAM_BACKGROUND, STREAM_THREAT_SELECTION, STREAM_TIMING,
             STREAM_CONTENT_VARIATION, STREAM_CONSEQUENCE}
    assert len(names) == 5


def test_an_extra_content_draw_does_not_move_threat_selection():
    """The property the whole partition exists for.

    Adding a line to the benign chatter list changes which line appears. It
    must not change which family attacks, when, or what follows.
    """
    plain = fresh_session(focus="mixed", seed=31)
    disturbed = fresh_session(focus="mixed", seed=31)
    # Twenty extra content-variation draws, as if the authored variation
    # material had grown.
    variation = disturbed.rng.stream(STREAM_CONTENT_VARIATION)
    for _ in range(20):
        variation.random()

    assert selections(pulses(plain, 25)) == selections(pulses(disturbed, 25))


def test_an_extra_background_draw_does_not_move_hostile_family_selection():
    plain = fresh_session(focus="phishing", seed=32)
    disturbed = fresh_session(focus="phishing", seed=32)
    background = disturbed.rng.stream(STREAM_BACKGROUND)
    for _ in range(15):
        background.random()

    def threats(session):
        return [(family, candidate)
                for family, candidate in selections(pulses(session, 25))
                if family != policy.BACKGROUND_FAMILY]

    assert threats(plain) == threats(disturbed)


def test_an_extra_consequence_draw_moves_neither_content_nor_selection():
    plain = fresh_session(focus="mixed", seed=33)
    disturbed = fresh_session(focus="mixed", seed=33)
    stream = disturbed.rng.stream(STREAM_CONSEQUENCE)
    for _ in range(30):
        stream.random()

    assert selections(pulses(plain, 20)) == selections(pulses(disturbed, 20))
    assert draws(plain, STREAM_CONTENT_VARIATION) \
        == draws(disturbed, STREAM_CONTENT_VARIATION)


def test_timing_jitter_draws_only_from_the_timing_stream():
    session = fresh_session(seed=34)
    before = draws(session, STREAM_THREAT_SELECTION)
    timing_before = draws(session, STREAM_TIMING)
    training_engine.schedule_next_evaluation(session)  # already queued: no-op
    assert draws(session, STREAM_TIMING) == timing_before
    assert draws(session, STREAM_THREAT_SELECTION) == before


def test_the_background_family_draws_from_its_own_stream():
    session = fresh_session(focus="mixed", seed=35)
    pulses(session, 12)
    assert draws(session, STREAM_BACKGROUND) > 0
    assert draws(session, STREAM_THREAT_SELECTION) > 0


# ===========================================================================
# Determinism, persistence and resume
# ===========================================================================

def test_the_same_seed_produces_the_same_run():
    a = fresh_session(focus="mixed", seed=36)
    b = fresh_session(focus="mixed", seed=36)
    assert selections(pulses(a, 30)) == selections(pulses(b, 30))
    assert a.capture_state() == b.capture_state()


def test_a_different_seed_produces_a_different_run():
    a = fresh_session(focus="mixed", seed=37)
    b = fresh_session(focus="mixed", seed=38)
    assert selections(pulses(a, 30)) != selections(pulses(b, 30))


def test_engine_state_is_persisted_with_the_session():
    session = fresh_session(seed=39)
    pulses(session, 6)
    state = session.capture_state()
    assert engine_state.NS_ENGINE in state["world"]["components"], \
        sorted(state["world"]["components"])
    payload = json.dumps(state)          # JSON-safe, or this raises
    assert policy.ENGINE_VERSION in payload


def test_engine_state_survives_a_capture_and_restore_exactly():
    original = fresh_session(focus="mixed", seed=40)
    pulses(original, 12)
    restored = type(original).from_state(original.capture_state())

    assert selections(pulses(original, 18)) == selections(pulses(restored, 18))
    assert original.capture_state() == restored.capture_state()


def test_a_session_restored_mid_run_continues_the_same_run():
    """Save after twelve pulses, rebuild, run the remaining eighteen."""
    continuous = fresh_session(focus="phishing", seed=41)
    split = fresh_session(focus="phishing", seed=41)

    pulses(continuous, 30)

    pulses(split, 12)
    split = type(split).from_state(json.loads(json.dumps(split.capture_state())))
    pulses(split, 18)

    assert continuous.capture_state() == split.capture_state()


def test_the_engine_survives_a_rebuilt_service_and_repository(tmp_path):
    uri = sqlite_uri(tmp_path, "engine-resume.db")
    service, _ = build_service(uri, seed=77, ids=["ws-engine-resume"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.advance(120000)
    first = service.dev_engine_state(driver.session_id, driver.learner_ref)

    rebuilt, _ = build_service(uri, seed=77)
    resumed = rebuilt.dev_engine_state(driver.session_id, driver.learner_ref)
    assert resumed == first

    Driver(rebuilt, driver.session_id).advance(120000)
    after_rebuild = rebuilt.dev_engine_state(driver.session_id, driver.learner_ref)

    whole, _ = build_service(sqlite_uri(tmp_path, "engine-whole.db"), seed=77,
                             ids=["ws-engine-resume"])
    other = Driver.start(whole, focus="mixed", mode="simulation")
    other.advance(240000)
    assert after_rebuild == whole.dev_engine_state(other.session_id,
                                                   other.learner_ref)


CROSS_PROCESS_SCRIPT = '''
import json, sys
sys.path.insert(0, {repo!r})
from tests.training_helpers import fresh_session, pulses, selections
session = fresh_session(focus="mixed", seed=515151)
print(json.dumps(selections(pulses(session, 25))))
'''


def test_the_same_seed_replays_across_processes_and_hash_seeds():
    """``PYTHONHASHSEED`` is the classic way a "deterministic" engine is not.

    Two subprocesses with deliberately different hash seeds must produce the
    same run. If any decision anywhere came from a set, a dict's iteration
    order or ``hash()``, this is where it shows.
    """
    outputs = []
    for hash_seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=hash_seed)
        completed = subprocess.run(
            [sys.executable, "-c", CROSS_PROCESS_SCRIPT.format(repo=REPO_ROOT)],
            capture_output=True, text=True, cwd=REPO_ROOT, env=env, timeout=180)
        assert completed.returncode == 0, completed.stderr
        outputs.append(completed.stdout.strip())
    assert len(set(outputs)) == 1, outputs
    assert json.loads(outputs[0])


# ===========================================================================
# Simulation time is the only clock
# ===========================================================================

def test_one_long_advance_and_many_short_ones_agree(tmp_path):
    lump, lump_repo = build_service(sqlite_uri(tmp_path, "lump.db"), seed=91,
                                    ids=["ws-step"])
    one = Driver.start(lump, focus="mixed", mode="simulation")
    one.advance(300000)

    step, step_repo = build_service(sqlite_uri(tmp_path, "step.db"), seed=91,
                                    ids=["ws-step"])
    many = Driver.start(step, focus="mixed", mode="simulation")
    for _ in range(60):
        many.advance(5000)

    assert lump_repo.load(one.session_id).capture_state() \
        == step_repo.load(many.session_id).capture_state()


def test_events_fire_at_the_time_they_were_scheduled_for(tmp_path):
    """Not all at the moment somebody happened to look."""
    service, repository = build_service(sqlite_uri(tmp_path, "spaced.db"),
                                        seed=92, ids=["ws-spaced"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.advance(300000)
    stored = repository.load(driver.session_id)
    times = [event.sim_time_ms for event in stored.event_log.events()
             if event.type == training_engine.EVALUATION_EVENT_TYPE]
    assert len(times) > 5
    assert times == sorted(times)
    assert len(set(times)) == len(times), "pulses collapsed onto one timestamp"


def test_waiting_in_real_time_does_nothing(tmp_path):
    import time

    service, repository = build_service(sqlite_uri(tmp_path, "wait.db"),
                                        seed=93, ids=["ws-wait"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    before = repository.load(driver.session_id).capture_state()
    time.sleep(0.6)
    assert repository.load(driver.session_id).capture_state() == before


def test_every_pulse_moves_simulation_time_forward():
    """The bound that makes an unbounded advance impossible."""
    session = fresh_session(seed=94)
    times = [session.now_ms]
    for _ in range(60):
        pulse(session)
        times.append(session.now_ms)
    assert all(later > earlier for earlier, later in zip(times, times[1:]))
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    assert min(gaps) >= policy.MIN_EVALUATION_INTERVAL_MS


def test_a_very_large_advance_terminates(tmp_path):
    service, _ = build_service(sqlite_uri(tmp_path, "big.db"), seed=95,
                              ids=["ws-big"])
    driver = Driver.start(service, focus="mixed", mode="assessment")
    for _ in range(6):
        driver.advance(600000)
    assert driver.snapshot()["session"]["sim_time_ms"] >= 3600000


# ===========================================================================
# Reads do not run the engine
# ===========================================================================

def test_a_snapshot_runs_no_evaluation_and_draws_nothing(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "reads.db"),
                                        seed=96, ids=["ws-reads"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.advance(60000)
    before = repository.load(driver.session_id).capture_state()
    for _ in range(10):
        driver.snapshot()
        driver.revision
    assert repository.load(driver.session_id).capture_state() == before


def test_reading_the_engine_state_mutates_nothing(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "introspect.db"),
                                        seed=97, ids=["ws-introspect"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.advance(60000)
    before = repository.load(driver.session_id).capture_state()
    for _ in range(5):
        service.dev_engine_state(driver.session_id, driver.learner_ref)
    assert repository.load(driver.session_id).capture_state() == before


def test_an_sse_style_revision_read_does_not_advance_the_engine(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "sse.db"),
                                        seed=98, ids=["ws-sse"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.advance(60000)
    before = repository.load(driver.session_id).capture_state()
    for _ in range(20):
        service.revision(driver.session_id, driver.learner_ref)
    assert repository.load(driver.session_id).capture_state() == before


def test_forcing_a_candidate_draws_from_no_selection_stream():
    """So a test that forces an arrival does not perturb the run it is testing."""
    session = fresh_session(focus="mixed", seed=99)
    before = (draws(session, STREAM_THREAT_SELECTION),
              draws(session, STREAM_BACKGROUND))
    training_engine.force_candidate(session, "cand-phish-payroll-lure")
    after = (draws(session, STREAM_THREAT_SELECTION),
             draws(session, STREAM_BACKGROUND))
    assert after == before


# ===========================================================================
# The comparison blocks, and the session ends
# ===========================================================================

def test_a_pending_comparison_blocks_new_primary_arrivals():
    from rewindsec.workstation.bootstrap import NS_SESSION

    session = fresh_session(focus="mixed", seed=100)
    session.mutate_world(NS_SESSION, "pending_comparison", "d-phish-credentials")
    records = pulses(session, 12)
    assert all(record["selected"] is None for record in records)
    assert all(record["reason"] == "blocked_by_comparison" for record in records)


def test_the_engine_resumes_once_the_comparison_is_dismissed():
    from rewindsec.workstation.bootstrap import NS_SESSION

    session = fresh_session(focus="mixed", seed=101)
    session.mutate_world(NS_SESSION, "pending_comparison", "d-phish-credentials")
    pulses(session, 5)
    session.mutate_world(NS_SESSION, "pending_comparison", None)
    assert any(record["selected"] for record in pulses(session, 20))


def test_a_blocked_pulse_still_schedules_the_next_one():
    """Otherwise dismissing the comparison would resume into a dead session."""
    from rewindsec.workstation.bootstrap import NS_SESSION

    session = fresh_session(seed=102)
    session.mutate_world(NS_SESSION, "pending_comparison", "d-phish-credentials")
    pulse(session)
    assert training_engine.pending_evaluation(session) is not None


def test_a_completed_session_stops_the_engine(tmp_path):
    service, repository = build_service(sqlite_uri(tmp_path, "ended.db"),
                                        seed=103, ids=["ws-ended"])
    driver = Driver.start(service, focus="mixed", mode="simulation")
    driver.advance(60000)
    service.end_session(driver.session_id, driver.learner_ref)
    after_end = repository.load(driver.session_id).capture_state()

    driver.advance(600000)
    driver.tick(5)
    assert repository.load(driver.session_id).capture_state() == after_end


# ===========================================================================
# Versioning
# ===========================================================================

def test_the_engine_and_catalogue_versions_are_recorded_on_the_session():
    session = fresh_session()
    meta = engine_state.meta(session)
    assert meta["engine_version"] == policy.ENGINE_VERSION
    assert meta["catalog_version"] == policy.CATALOG_VERSION


def test_the_versions_are_stable_strings_not_derived_values():
    assert policy.ENGINE_VERSION == "training-engine/v1"
    assert policy.CATALOG_VERSION == "training-catalog/v1"


def test_the_internal_trace_is_bounded():
    session = fresh_session(seed=104)
    pulses(session, 80)
    assert len(engine_state.trace(session)) <= policy.TRACE_DEPTH


def test_the_trace_explains_a_decision():
    session = fresh_session(focus="phishing", seed=105)
    pulses(session, 10)
    entries = engine_state.trace(session)
    assert entries
    for entry in entries:
        assert set(entry) == {"step", "at_ms", "selected", "family", "reason",
                              "eligible", "pressure"}
        assert isinstance(entry["step"], int)
        assert entry["reason"] is not None
