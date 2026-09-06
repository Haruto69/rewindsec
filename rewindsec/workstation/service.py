"""The workstation application service: the only thing that changes a session.

Everything a learner can do arrives here as a validated
:class:`~rewindsec.workstation.actions.SemanticAction` and leaves as a
learner-safe projection. Between those two points this module decides, on the
server, what the action means:

    validate lifecycle and mode
        -> validate that the target exists and may be touched
        -> record a LearnerAction
        -> mark the context facts that action observed
        -> mutate the world
        -> record events and consequences
        -> persist atomically
        -> project

No route mutates a world dictionary, and no client submits one. A request can
choose an allowlisted verb and a narrow set of parameters; every consequence of
choosing it is computed here.

Concurrency
-----------
Each mutating call loads the session, checks that the caller's revision is the
one currently stored, applies, and saves with that revision as
``expected_revision``. A submission built on a stale view is refused with
:class:`~rewindsec.workstation.errors.StaleRevisionConflict` and changes
nothing -- which is also what stops a retried request, whose response was lost
on the way back, from applying the same consequence a second time. Every
action records a :class:`~rewindsec.domain.actions.LearnerAction` and therefore
bumps the revision, so a genuine duplicate can never match.

Time
----
Simulation time is owned by the session's ``SimClock`` and is the only clock
any simulation decision reads. **No real clock advances it.** There is no
``time`` import in this module, no datetime, no measured interval and no
client-supplied duration: nothing about how long a request took, how fast the
machine is, how long the browser was closed, or how often a timer fired can
change a single millisecond of simulation time.

Simulation time moves only when an explicit application operation says so, and
every such operation advances it by a value that is *stated*, never measured:

``tick``
    advances exactly :data:`TICK_QUANTUM_MS`, an authored constant. The
    browser's heartbeat decides only *whether* a step is asked for, never how
    big it is; two sessions given the same number of ticks reach the same
    simulation time on any machine, at any speed, under any load.
``dev_advance`` / ``dev_deliver_next``
    advance by an amount named by the caller. Prototype tooling.

A session's state is therefore a pure function of its seed and the recorded
sequence of application inputs. Replay them and you get the same clock, the
same scheduler, the same events, the same world.

What decides *what arrives*
---------------------------
Not this module. Since Batch 3 the sequence of workplace activity comes from
:mod:`rewindsec.training.engine`, which evaluates on its own pulse in
simulation time, reads the world and the Context Ledger, and draws from named
seeded streams. This service owns actions, persistence and projection; it
calls the engine when an engine pulse fires and tells it when the learner has
finished with something, and it makes no selection decision of its own.

Reads never mutate. :meth:`snapshot` and :meth:`comparison` load, project and
return. They advance no clock, fire no event, consume no sequence number and
observe no fact, so a refresh -- or ten -- leaves ``capture_state()`` identical.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.core.rng import STREAM_TIMING
from rewindsec.domain.enums import Focus, Mode, SessionStatus, coerce_enum
from rewindsec.domain.errors import DomainError
from rewindsec.domain.session import SimulationSession
from rewindsec.persistence.ports import (SessionNotFoundError,
                                         StaleRevisionError)
from rewindsec.workstation import bootstrap, clock, consequences, worldops
from rewindsec.workstation.bootstrap import (NS_AUTH_REQUESTS, NS_BROWSER,
                                             NS_DIRECTORY, NS_FILES,
                                             NS_INCIDENTS, NS_MAIL, NS_MESSAGES,
                                             NS_NOTES, NS_NOTIFICATIONS,
                                             NS_SESSION, NS_TASKS,
                                             AUTH_HISTORY_FACT,
                                             contact_callback_fact,
                                             contact_fact, conversation_fact,
                                             file_fact, mail_attachment_fact,
                                             mail_body_fact, mail_header_fact,
                                             mail_link_fact, page_fact,
                                             prompt_fact)
from rewindsec.workstation.content import index as ix
from rewindsec.workstation.content import scenario
from rewindsec.workstation.errors import (ForbiddenActionError,
                                          InternalWorkstationError,
                                          InvalidRequestError,
                                          NoActiveSessionError,
                                          SessionEndedError,
                                          StaleRevisionConflict,
                                          UnknownTargetError)
from rewindsec.training import engine as training_engine
from rewindsec.training import progression
from rewindsec.training import state as engine_state
from rewindsec.workstation.projection import learner_snapshot
from rewindsec.workstation.seeds import SystemSeedSource

__all__ = ["WorkstationService", "ActionResult", "DELIVERY_EVENT_TYPE",
           "TICK_QUANTUM_MS"]

#: The event type an arrival fires as. Behavioural, and deliberately
#: uninformative: nothing in the name tells a learner what kind of thing has
#: just arrived. The training engine emits the same type, so a session driven
#: by the engine and a legacy session driven by the authored timeline are
#: indistinguishable in the event stream.
DELIVERY_EVENT_TYPE = "world.activity"

#: Practice releases the next item a short while after the learner finishes
#: with the current one; it does not run to a clock of its own.
PRACTICE_FOLLOW_MS = 7000
PRACTICE_MAX_WAIT_MS = 90000

#: How far one :meth:`WorkstationService.tick` moves simulation time.
#:
#: An authored constant, and the whole point of it is that it is a constant.
#: A tick used to advance by however much real time the server had measured
#: since the last one, which made the arrival time of a consequence a function
#: of machine speed, request latency and how long a tab had been in the
#: background -- and made a restarted process lose the measurement entirely.
#: Now a tick is a *step*, not a *duration*: the client's timer chooses when to
#: ask for one, and the size of every step is fixed here, on the server, in
#: simulation milliseconds.
TICK_QUANTUM_MS = 4000


class ActionResult(object):
    """What an accepted action produced: the new truth, plus a transient notice.

    The notice is presentation -- a Practice confirmation, a download
    acknowledgement -- and is deliberately *not* stored in the world. It
    belongs to the moment the button was pressed; a refresh should not replay
    it, and a debrief should not treat it as a fact.
    """

    __slots__ = ("snapshot", "notice", "revision")

    def __init__(self, snapshot, notice=None):
        self.snapshot = snapshot
        self.notice = notice
        self.revision = snapshot["session"]["revision"]


class WorkstationService(object):
    """Server-authoritative operations on one learner's simulation session."""

    def __init__(self, repository, seed_source=None, id_source=None,
                 updates=None):
        self._repository = repository
        self._seeds = seed_source or SystemSeedSource()
        self._id_source = id_source
        self._updates = updates

    # -- lifecycle ---------------------------------------------------------

    def start_session(self, learner_ref, focus, mode):
        """Create, seed and persist a brand-new session; return its id.

        The id and the root seed are both minted here, on the server. Neither
        is ever accepted from a request: an id chosen by a client is an
        invitation to open somebody else's session, and a seed chosen by a
        client is an invitation to pick a scenario.
        """
        focus = _coerce(focus, Focus, "focus")
        mode = _coerce(mode, Mode, "mode")
        session_id = self._new_session_id()
        session = SimulationSession.create(
            session_id=session_id, learner_ref=learner_ref, focus=focus,
            mode=mode, root_seed=self._seeds.next_seed())
        start_event = bootstrap.seed_session(session)
        # Every session created from here on is driven by the training engine.
        # The authored timeline is not consulted, not scheduled and not
        # advanced; it survives only for sessions that were already half-played
        # when this batch landed. See ``training.state.engine_is_active``.
        training_engine.start(session, cause_event_id=start_event.event_id)
        self._repository.create(session)
        return session_id

    def _new_session_id(self):
        if self._id_source is not None:
            return self._id_source()
        # Not part of the simulation, so ``secrets`` rather than the session
        # RNG -- which does not exist yet at this point anyway.
        import secrets
        return "ws-%s" % secrets.token_hex(12)

    def load(self, session_id):
        """The session, or :class:`NoActiveSessionError` if there is none."""
        if not session_id:
            raise NoActiveSessionError("There is no training session open.")
        try:
            return self._repository.load(session_id)
        except SessionNotFoundError:
            raise NoActiveSessionError("There is no training session open.")

    def owns(self, session, learner_ref):
        return session.learner_ref == learner_ref

    def require_owned(self, session_id, learner_ref):
        """Load a session and refuse it unless it belongs to this learner.

        Answering "not found" rather than "forbidden" is deliberate: a learner
        who guesses another learner's session id learns nothing from the
        response about whether the guess was right.
        """
        session = self.load(session_id)
        if learner_ref is not None and session.learner_ref != learner_ref:
            raise NoActiveSessionError("There is no training session open.")
        return session

    def end_session(self, session_id, learner_ref=None):
        """Complete the session. Preserves everything; resets nothing."""
        session = self.require_owned(session_id, learner_ref)
        if session.status is not SessionStatus.ACTIVE:
            return self._project(session)
        expected = session.revision
        session.record_immediate_event(
            "session.ended", source=EventSource.SYSTEM,
            visibility=EventVisibility.INTERNAL)
        session.complete()
        self._save(session, expected)
        return self._project(session)

    # -- reads (no mutation, ever) -----------------------------------------

    def snapshot(self, session_id, learner_ref=None):
        """The learner-safe projection. Reads only."""
        session = self.require_owned(session_id, learner_ref)
        return self._project(session)

    def revision(self, session_id, learner_ref=None):
        """The authoritative revision, for the update transport to compare."""
        return self.require_owned(session_id, learner_ref).revision

    def _project(self, session):
        return learner_snapshot(session, ix.mode_flags(session.mode.value))

    # -- time --------------------------------------------------------------

    def tick(self, session_id, learner_ref=None):
        """Advance simulation time by one authored quantum; apply what is due.

        A state-changing operation, and only ever reached through a POST. It
        is what lets an authored delayed consequence arrive while the learner
        is reading rather than only when they next click.

        The step is :data:`TICK_QUANTUM_MS` every time. Nothing here reads a
        real clock, and the caller cannot name a duration -- there is no
        parameter through which one could arrive -- so no client, timer or
        machine can buy itself a longer step than any other. Ten ticks are ten
        quanta whether they arrive in a second or over an afternoon.
        """
        session = self.require_owned(session_id, learner_ref)
        if session.status is not SessionStatus.ACTIVE:
            return self._project(session)
        expected = session.revision
        before_ms = session.now_ms
        self._advance(session, TICK_QUANTUM_MS)
        self._save_if_moved(session, expected, before_ms)
        return self._project(session)

    #: A single advance is applied in at most this many slices.
    #:
    #: The engine schedules its own next evaluation, so a long ``dev_advance``
    #: legitimately walks through many pulses -- at the Assessment floor of one
    #: second, the 600-second ceiling on a single advance is 600 of them, plus
    #: whatever consequence steps they cause. The bound is sized above that and
    #: is a backstop, not a budget: it exists so that a future bug in which
    #: something schedules itself at the same simulation time cannot spin here
    #: forever. Every recurring engine pulse is floored at
    #: ``policy.MIN_EVALUATION_INTERVAL_MS``, so simulation time always moves.
    _MAX_ADVANCE_SLICES = 2000

    def _advance(self, session, elapsed_ms):
        """Move the clock to ``now + elapsed_ms``, stopping at each due time.

        Advancing straight to the target and then firing everything that had
        become due would stamp every one of those events with the *arrival*
        time rather than the time it was scheduled for -- so a chain whose
        steps are six, fourteen, twenty-two and thirty seconds apart would
        show up in the debrief as four things that happened simultaneously.
        They did not; the learner simply was not watching.

        So the clock is walked forward one due time at a time. Each event
        fires at exactly the simulation time it was scheduled for, whatever
        size of step brought us here, which is also what makes a long step and
        a sequence of short ones produce identical history.
        """
        mode_flags = ix.mode_flags(session.mode.value)
        target_ms = session.now_ms + max(0, int(elapsed_ms))

        for _ in range(self._MAX_ADVANCE_SLICES):
            next_due = self._next_due_at(session, target_ms)
            if next_due is None:
                break
            for event in session.advance_time(next_due - session.now_ms):
                self._handle_fired(session, event, mode_flags)

        if session.now_ms < target_ms:
            # Nothing left to fire in the window; close the remaining gap so
            # the clock ends where the caller asked for it.
            for event in session.advance_time(target_ms - session.now_ms):
                self._handle_fired(session, event, mode_flags)

    @staticmethod
    def _next_due_at(session, target_ms):
        """The earliest pending fire time at or before *target_ms*, if any."""
        earliest = None
        for entry in session.scheduler.pending():
            if entry.cancelled or entry.fire_at_ms > target_ms:
                continue
            if earliest is None or entry.fire_at_ms < earliest:
                earliest = entry.fire_at_ms
        return earliest

    def _handle_fired(self, session, event, mode_flags):
        if event.type == consequences.CONSEQUENCE_EVENT_TYPE:
            outcome = consequences.apply_step_event(session, event, mode_flags)
            if outcome.get("settled"):
                self._on_chain_settled(session, outcome, mode_flags)
        elif event.type == training_engine.EVALUATION_EVENT_TYPE:
            # One engine pulse. Everything it does -- eligibility, pressure,
            # the draws, the arrival, the next pulse -- happens here, inside an
            # explicit advance of simulation time, and nowhere else.
            training_engine.evaluate(session, event)
        elif event.type == DELIVERY_EVENT_TYPE:
            # Legacy only: a pre-Batch-3 session still walking its authored
            # timeline. New sessions never schedule this.
            self._deliver_from_timeline(session, event)

    # -- the authored timeline (legacy sessions only) ----------------------
    #
    # Everything from here to ``_mark_resolved`` served Batch 2 and now serves
    # exactly one purpose: a session created before Batch 3 has a half-played
    # timeline and pending arrivals in its scheduler, and moving it into a
    # different event universe mid-attempt would change what the learner was
    # being asked to do without telling them. Those sessions finish the way
    # they started. Nothing created since reaches any of it.

    def _schedule_next_delivery(self, session, delay_ms=None):
        """Queue the next authored arrival, if the timeline has one left.

        One at a time rather than the whole list: Practice has to be able to
        bring the next item forward once the learner finishes with the current
        one, and a queue that is already fully scheduled cannot be nudged
        without cancelling a pile of entries.

        The interval comes from the mode's authored cadence plus a jitter draw
        from the session's ``timing`` RNG stream, so arrival is irregular,
        reproducible from the seed, and identical after a resume.
        """
        index = session.world.get(NS_SESSION, "queue_index", 0)
        timeline = ix.timeline_for(session.focus.value)
        if index >= len(timeline):
            return
        if self._pending_delivery(session) is not None:
            return
        if delay_ms is None:
            delay_ms = self._delivery_delay(session)
        session.schedule_event(
            DELIVERY_EVENT_TYPE, delay_ms=delay_ms,
            payload={"index": index},
            source=EventSource.SCHEDULER,
            visibility=EventVisibility.LEARNER_VISIBLE)

    def _delivery_delay(self, session):
        cadence = scenario.CADENCE.get(session.mode.value) \
            or scenario.CADENCE["simulation"]
        stream = session.rng.stream(STREAM_TIMING)
        if cadence.get("style") == "paced":
            # Practice is learner-paced. The long interval is a backstop for a
            # learner who has stopped, not a cadence.
            return PRACTICE_MAX_WAIT_MS
        base = int(cadence.get("base_ms", 30000))
        jitter = int(cadence.get("jitter_ms", 0))
        if jitter:
            base += stream.randint(-jitter, jitter)
        return max(4000, base)

    def _pending_delivery(self, session):
        # ``pending()`` includes entries that have been cancelled but not yet
        # swept past their fire time. Those can never fire again, so treating
        # one as "a delivery is already queued" would stall the timeline.
        for entry in session.scheduler.pending():
            if entry.cancelled:
                continue
            if entry.spec.type == DELIVERY_EVENT_TYPE:
                return entry
        return None

    def _deliver_from_timeline(self, session, event):
        timeline = ix.timeline_for(session.focus.value)
        index = event.payload.get("index", 0)
        if not isinstance(index, int) or index < 0 or index >= len(timeline):
            return
        entry = timeline[index]
        session.mutate_world(NS_SESSION, "queue_index", index + 1,
                             cause_event_id=event.event_id)
        if entry.get("type") == "mail":
            worldops.deliver_mail(session, entry.get("ref"),
                                  cause_event_id=event.event_id)
            session.mutate_world(NS_SESSION, "awaiting", entry.get("ref"),
                                 cause_event_id=event.event_id)
        elif entry.get("type") == "mfa":
            worldops.create_auth_request(session, entry.get("ref"),
                                         cause_event_id=event.event_id)
            session.mutate_world(NS_SESSION, "awaiting", entry.get("ref"),
                                 cause_event_id=event.event_id)
        self._schedule_next_delivery(session)

    def _mark_resolved(self, session, ref):
        """The learner has finished with the arrival that was waiting on them.

        In Practice this brings the next one forward, which is what makes the
        mode learner-paced rather than merely slow. The pending schedule entry
        is cancelled and replaced, so the audit log records both the
        cancellation and its reason.

        Two implementations behind one call: the engine's for a Batch 3
        session, the authored timeline's for a legacy one. Every handler calls
        this and none of them knows which.
        """
        if engine_state.engine_is_active(session):
            training_engine.note_resolved(session, ref)
            return
        if session.world.get(NS_SESSION, "awaiting") != ref:
            return
        session.mutate_world(NS_SESSION, "awaiting", None)
        cadence = scenario.CADENCE.get(session.mode.value) or {}
        if cadence.get("style") != "paced":
            return
        pending = self._pending_delivery(session)
        if pending is not None:
            session.cancel_scheduled(pending.schedule_id,
                                     reason="learner resolved the current item")
        self._schedule_next_delivery(session, delay_ms=PRACTICE_FOLLOW_MS)

    # -- actions -----------------------------------------------------------

    def apply_action(self, session_id, action, learner_ref=None):
        """Validate, apply and persist one semantic learner action."""
        session = self.require_owned(session_id, learner_ref)

        if session.status is not SessionStatus.ACTIVE:
            raise SessionEndedError(
                "This training session has finished. Its record is still "
                "available in your results.")

        if action.expected_revision != session.revision:
            raise StaleRevisionConflict(
                "The workstation has moved on since that was on screen.",
                detail={"revision": session.revision})

        loaded_revision = session.revision
        mode_flags = ix.mode_flags(session.mode.value)

        handler = _HANDLERS.get(action.action_type)
        if handler is None:
            raise InternalWorkstationError()

        learner_action = session.record_action(
            action_type=action.action_type,
            classification=action.classification,
            target=action.target,
            params=_recordable_params(action))

        try:
            notice = handler(self, session, action, learner_action, mode_flags)
        except (UnknownTargetError, ForbiddenActionError, InvalidRequestError):
            # Nothing is persisted, so the rejected attempt leaves no trace in
            # the stored world -- the in-memory session is discarded with it.
            raise
        except DomainError as exc:
            raise InvalidRequestError(
                "That action could not be applied.") from exc

        self._save(session, loaded_revision)
        return ActionResult(self._project(session), notice)

    def _save_if_moved(self, session, expected_revision, before_ms):
        """Persist when anything changed -- including when only the clock did.

        Advancing the clock without firing anything does not bump the
        revision, because nothing about the world changed. It still has to be
        stored: if it were not, every tick that happened to fire nothing would
        be thrown away on the next load, the clock would only ever move in the
        ticks that *did* fire something, and a consequence scheduled further
        out than a single tick could never come due at all.
        """
        if session.revision != expected_revision or session.now_ms != before_ms:
            self._save(session, expected_revision)

    def _save(self, session, expected_revision):
        try:
            self._repository.update(session, expected_revision=expected_revision)
        except StaleRevisionError as exc:
            raise StaleRevisionConflict(
                "The workstation has moved on since that was on screen.",
                detail={"revision": session.revision}) from exc
        except SessionNotFoundError as exc:
            raise NoActiveSessionError(
                "There is no training session open.") from exc
        if self._updates is not None:
            self._updates.publish(session.session_id, session.revision)

    # -- shared helpers used by the handlers ------------------------------

    def _observe(self, session, fact_id, learner_action):
        """Mark one context fact observed by this action, if it is available.

        Observation is recorded against the action that caused it, which is
        what the Context Ledger is for. An unavailable fact is skipped rather
        than forced: the learner cannot have inspected something the workplace
        has not surfaced.
        """
        if not session.ledger.has(fact_id):
            return False
        if not session.ledger.get(fact_id).available:
            return False
        session.observe_fact(fact_id, learner_action.action_id)
        return True

    def _decide(self, session, decision_id, learner_action, where, mode_flags):
        """Record a decision, schedule its chain, and return any confirmation.

        The Practice-only confirmation is computed here, on the server, and
        travels back as a transient notice. In Simulation and Assessment the
        same decision produces the same world change and no commentary at all.
        """
        event_id = consequences.record_decision(
            session, decision_id, learner_action.action_id, where, mode_flags)
        if event_id is None:
            return None
        if not mode_flags.get("explicit_confirmation"):
            return None
        definition = ix.DECISION_BY_ID.get(decision_id) or {}
        if definition.get("class") not in ("safe", "recovery_good"):
            return None
        return {"kind": "confirmation",
                "text": _CONFIRMATION_TEXT.get(
                    decision_id, "That was a reasonable way to handle it.")}

    def _on_chain_settled(self, session, outcome, mode_flags):
        """A consequence chain has reached its authored resting point.

        Two things can follow, and neither of them is a rewind. The world may
        pose its *second* question -- once files have been failing for a while,
        carrying on working is itself a decision -- and, outside an Assessment
        attempt, the comparison may become eligible to be shown.
        """
        decision_id = outcome.get("decision")
        if outcome.get("chain") == "chain-file-incident":
            incident = session.world.get(NS_INCIDENTS, "inc-files") or {}
            if not incident.get("contained") \
                    and not consequences.already_decided(session, "d-ransom-continue"):
                consequences.record_decision(
                    session, "d-ransom-continue", None, "Files", mode_flags)
        if session.mode is Mode.ASSESSMENT:
            return
        if not mode_flags.get("safer_alternative"):
            return
        if consequences.safer_alternative_for(decision_id) is None:
            return
        session.mutate_world(NS_SESSION, "pending_comparison", decision_id)

    # -- development-only operations --------------------------------------

    def dev_advance(self, session_id, milliseconds, learner_ref=None):
        """Advance simulation time by an explicit amount. Prototype tooling.

        Exposed only through the development endpoint, never as a learner
        action, and it takes the same path as an ordinary tick: it persists,
        it fires the same events in the same order, and it cannot skip a
        consequence. It compresses waiting, not causality.
        """
        session = self.require_owned(session_id, learner_ref)
        if session.status is not SessionStatus.ACTIVE:
            return self._project(session)
        expected = session.revision
        before_ms = session.now_ms
        step = max(0, min(int(milliseconds), 600000))
        if step:
            self._advance(session, step)
        self._save_if_moved(session, expected, before_ms)
        return self._project(session)

    def dev_deliver_next(self, session_id, learner_ref=None):
        """Run the next engine evaluation immediately. Prototype tooling.

        Compresses waiting, not causality: it advances simulation time to the
        moment the next pulse was already due and lets it fire through the
        ordinary path. The engine still evaluates eligibility, still draws from
        the same streams at the same positions, and may still select nothing --
        this is a fast-forward button, not a "make something happen" button.
        """
        session = self.require_owned(session_id, learner_ref)
        if session.status is not SessionStatus.ACTIVE:
            return self._project(session)
        expected = session.revision
        before_ms = session.now_ms
        if engine_state.engine_is_active(session):
            pending = training_engine.pending_evaluation(session)
        else:
            pending = self._pending_delivery(session)
            if pending is None:
                self._schedule_next_delivery(session, delay_ms=1)
                pending = self._pending_delivery(session)
        if pending is not None:
            remaining = max(1, pending.fire_at_ms - session.now_ms)
            self._advance(session, remaining)
        self._save_if_moved(session, expected, before_ms)
        return self._project(session)

    def dev_force_candidate(self, session_id, candidate_id, learner_ref=None):
        """Deliver one named engine candidate now. Prototype/test tooling.

        The one thing ``dev_deliver_next`` cannot do: put a *specific* piece of
        activity in front of the learner. It bypasses the lottery -- and draws
        nothing from the threat or background streams while doing so, so using
        it does not perturb any selection the engine makes afterwards -- but it
        goes through the same delivery adapters, the same world operations and
        the same causal event as a selected arrival. There is no learner route
        to it, and it cannot produce a world the engine could not.
        """
        session = self.require_owned(session_id, learner_ref)
        if session.status is not SessionStatus.ACTIVE:
            return self._project(session)
        if not engine_state.engine_is_active(session):
            raise InvalidRequestError(
                "That session predates the training engine.")
        expected = session.revision
        before_ms = session.now_ms
        training_engine.force_candidate(session, candidate_id)
        self._save_if_moved(session, expected, before_ms)
        return self._project(session)

    def dev_engine_state(self, session_id, learner_ref=None):
        """The engine's internal state. Development boundary only.

        Deliberately not part of the projection and deliberately not reachable
        from any learner route: eligibility reasons, pressure values and the
        selection trace are, between them, a description of what is about to
        happen. This exists so a developer or a test can explain a decision the
        engine made; a learner has no path to it.
        """
        session = self.require_owned(session_id, learner_ref)
        if not engine_state.engine_is_active(session):
            return {"engine_version": None, "legacy_session": True}
        return training_engine.engine_summary(session)


# ---------------------------------------------------------------------------
# Action handlers
# ---------------------------------------------------------------------------
#
# One function per allowlisted action. Each receives the service, the session,
# the validated request, the LearnerAction already recorded for it, and the
# mode's authored flags; each returns an optional transient notice.
#
# Every one of them starts by resolving the target against the *world*, not
# against the authored content: a message the learner cannot see is not a
# target, whatever the content module knows about it.


def _require_delivered_mail(session, mail_id):
    state = session.world.get(NS_MAIL, mail_id)
    if state is None or not state.get("delivered"):
        raise UnknownTargetError("No such message.")
    record = ix.MAIL_BY_ID.get(mail_id)
    if record is None:
        raise UnknownTargetError("No such message.")
    return state, record


def _mail_open(service, session, action, learner_action, mode_flags):
    state, record = _require_delivered_mail(session, action.target)
    service._observe(session, mail_body_fact(action.target), learner_action)
    if state.get("unread"):
        worldops.set_mail_field(session, action.target, unread=False, read=True)
    service._mark_resolved(session, action.target)
    return None


def _mail_inspect_headers(service, session, action, learner_action, mode_flags):
    _require_delivered_mail(session, action.target)
    service._observe(session, mail_header_fact(action.target), learner_action)
    return None


def _mail_inspect_link(service, session, action, learner_action, mode_flags):
    _, record = _require_delivered_mail(session, action.target)
    index = action.params["index"]
    if index >= len(record["surface"].get("links") or []):
        raise UnknownTargetError("No such link.")
    service._observe(session, mail_link_fact(action.target, index), learner_action)
    return None


def _mail_inspect_attachment(service, session, action, learner_action, mode_flags):
    _, record = _require_delivered_mail(session, action.target)
    index = action.params["index"]
    if index >= len(record["surface"].get("attachments") or []):
        raise UnknownTargetError("No such attachment.")
    service._observe(session, mail_attachment_fact(action.target, index),
                     learner_action)
    return None


def _mail_open_link(service, session, action, learner_action, mode_flags):
    """Follow a link from a message.

    The client never holds the destination unless it inspected it, so the
    address is resolved here from the authored message. Nothing is fetched:
    "navigating" means recording that this synthetic page is now part of the
    learner's browsing history.
    """
    _, record = _require_delivered_mail(session, action.target)
    index = action.params["index"]
    links = record["surface"].get("links") or []
    if index >= len(links):
        raise UnknownTargetError("No such link.")
    href = links[index].get("href", "")
    url = _normalise_url(href)
    _visit(session, url, learner_action, service)
    return {"kind": "navigate", "url": url}


def _mail_report(service, session, action, learner_action, mode_flags):
    state, record = _require_delivered_mail(session, action.target)
    worldops.set_mail_field(session, action.target, folder="reported",
                            reported=True, unread=False)
    service._mark_resolved(session, action.target)
    decision_id = (_REPORT_DECISION.get(action.target, "d-phish-report")
                   if ix.is_hostile_mail(action.target)
                   else "d-report-legitimate")
    return service._decide(session, decision_id, learner_action, "Mail",
                           mode_flags)


def _mail_delete(service, session, action, learner_action, mode_flags):
    _require_delivered_mail(session, action.target)
    worldops.set_mail_field(session, action.target, folder="deleted",
                            unread=False)
    service._mark_resolved(session, action.target)
    if action.target == "m-payroll-restructure" and ix.is_hostile_mail(action.target):
        return service._decide(session, "d-phish-delete", learner_action,
                               "Mail", mode_flags)
    return None


def _mail_forward(service, session, action, learner_action, mode_flags):
    _, record = _require_delivered_mail(session, action.target)
    worldops.set_mail_field(session, action.target, forwarded=True)
    worldops.raise_notification(
        session, kind="mail", title="Message forwarded",
        body=record["surface"].get("subject", ""), opens=None)
    return None


def _mail_reply(service, session, action, learner_action, mode_flags):
    _, record = _require_delivered_mail(session, action.target)
    text = action.params.get("text", "")
    worldops.set_mail_field(session, action.target, replied=True)
    worldops.add_sent_mail(
        session, subject="Re: %s" % record["surface"].get("subject", ""),
        to=record["surface"].get("from_address", ""),
        body=text or "(no text)")
    service._mark_resolved(session, action.target)
    decision_id = _REPLY_DECISION.get(action.target)
    if decision_id:
        return service._decide(session, decision_id, learner_action, "Mail",
                               mode_flags)
    return None


def _mail_download(service, session, action, learner_action, mode_flags):
    _, record = _require_delivered_mail(session, action.target)
    index = action.params["index"]
    attachments = record["surface"].get("attachments") or []
    if index >= len(attachments):
        raise UnknownTargetError("No such attachment.")
    attachment = attachments[index]
    file_id = "f-dl-%s-%d" % (action.target, index)
    kind = attachment.get("kind")
    worldops.add_downloaded_file(
        session, file_id=file_id, location_id="loc-downloads",
        name=attachment.get("name", ""),
        kind="spreadsheet" if kind == "spreadsheet-macro" else kind,
        size=attachment.get("size", ""),
        source=record["surface"].get("from_address", ""),
        macro=(kind == "spreadsheet-macro"), origin_mail=action.target)
    # What the file is actually called, which is not always what the message
    # called it: a download that would have landed on an existing file is
    # kept alongside it under a numbered name. Everything downstream -- the
    # Context Ledger fact, the notification, the Files app -- uses the name
    # the learner will actually see in the folder.
    saved_name = (session.world.get(NS_FILES, file_id) or {}).get(
        "name") or attachment.get("name", "")
    if not session.ledger.has(file_fact(file_id)):
        session.introduce_fact(
            file_fact(file_id), category="file_metadata",
            value={"name": saved_name,
                   "source": record["surface"].get("from_address", "")},
            source="filesystem", available=True)
    worldops.raise_notification(
        session, kind="system", title="Download complete",
        body="%s is in your Downloads folder." % saved_name,
        opens={"app": "files", "location_id": "loc-downloads"})
    service._mark_resolved(session, action.target)
    if action.target == "m-rate-card":
        return service._decide(session, "d-ransom-download", learner_action,
                               "Mail", mode_flags)
    return None


# -- browser ----------------------------------------------------------------

def _normalise_url(raw):
    text = str(raw or "").strip()
    for prefix in ("https://", "http://"):
        if text.lower().startswith(prefix):
            text = text[len(prefix):]
            break
    return text.rstrip("/").lower()


def _visit(session, url, learner_action, service):
    """Record a synthetic page visit. No request of any kind is made.

    An address that is not an authored page is still recorded -- the learner
    genuinely typed it, and the browser genuinely showed them "not reachable"
    -- but it resolves to no content, because there is no content outside the
    authored site map and no mechanism here that could fetch any.
    """
    visited = list(session.world.get(NS_BROWSER, "visited") or [])
    if url not in visited:
        visited.append(url)
        # Bounded: a learner typing addresses cannot grow the session snapshot
        # without limit.
        session.mutate_world(NS_BROWSER, "visited", visited[-60:])
    if url in ix.PAGE_BY_URL:
        service._observe(session, page_fact(url), learner_action)


def _browser_navigate(service, session, action, learner_action, mode_flags):
    url = action.params["url"]
    _visit(session, url, learner_action, service)
    return None


def _browser_sign_in(service, session, action, learner_action, mode_flags):
    """A synthetic sign-in.

    No credential of any kind reaches this function. The client sends the
    address and nothing else: the password field is cleared in the browser, is
    never serialised, never appears in the action parameters, is never
    persisted and is never logged. What is recorded is the decision to sign in
    on that page, which is the only part that has any training meaning.
    """
    url = action.params["url"]
    page = ix.PAGE_BY_URL.get(url)
    if page is None or page.get("kind") != "signin":
        raise UnknownTargetError("That page has no sign-in.")
    _visit(session, url, learner_action, service)
    signin_id = page.get("signin_id")

    if signin_id == "vpn-legit":
        worldops.set_browser_state(session, "signin:%s" % url, "pending")
        worldops.create_auth_request(session, "mfa-vpn")
        worldops.set_task(session, "task-remote-access", "outstanding",
                          note="Remote access waiting for approval.")
        return None

    if signin_id == "payroll-legit":
        worldops.set_browser_state(session, "signin:%s" % url, "done")
        return None

    worldops.set_browser_state(session, "signin:%s" % url, "submitted")
    return service._decide(session, "d-phish-credentials", learner_action,
                           "Browser", mode_flags)


def _browser_sign_in_retry(service, session, action, learner_action, mode_flags):
    url = action.params["url"]
    if url not in ix.PAGE_BY_URL:
        raise UnknownTargetError("No such page.")
    worldops.set_browser_state(session, "signin:%s" % url, None)
    return None


def _browser_release_payment(service, session, action, learner_action, mode_flags):
    url = action.params["url"]
    page = ix.PAGE_BY_URL.get(url)
    if page is None or page.get("kind") != "payments":
        raise UnknownTargetError("No such page.")
    invoice = page.get("invoice") or {}
    account = action.params["account"]
    worldops.set_browser_state(session, "payment_released", account)
    worldops.set_browser_state(session, "payment_account", account)
    if account.strip() != str(invoice.get("account_of_record", "")).strip():
        return service._decide(session, "d-bec-authorize", learner_action,
                               "Browser", mode_flags)
    worldops.raise_notification(
        session, kind="system", title="Payment released",
        body="%s . account of record" % invoice.get("reference", ""), opens=None)
    return None


def _browser_download(service, session, action, learner_action, mode_flags):
    """Download a file a synthetic page offers.

    No fetch of any kind occurs. The client sends the page address and the
    *resource id* the projection gave it -- never a filename, never a path,
    never a URL to retrieve -- and the server resolves that pair against the
    authored site map, decides what the file is, and materialises it as a row
    in the synthetic Downloads folder.

    The name it lands under comes from
    :func:`rewindsec.workstation.worldops.resolve_download_name`, which is the
    same single server-side resolver a mail attachment uses. There is exactly
    one collision algorithm in this product: ``report.pdf``, then
    ``report (1).pdf``, then ``report (2).pdf``, compared case-insensitively
    within the folder, and nothing is ever silently overwritten. A file
    downloaded from the Browser and the same file downloaded from Mail
    therefore behave identically, because they are the same code.
    """
    url = action.params["url"]
    if url not in ix.PAGE_BY_URL:
        raise UnknownTargetError("No such page.")
    resource = ix.resource_on_page(url, action.params["resource"])
    if resource is None:
        raise UnknownTargetError("There is nothing to download on that page.")

    _visit(session, url, learner_action, service)
    kind = resource.get("kind")
    file_id = "f-web-%s-%s" % (ix.url_slug(url), resource["id"])
    worldops.add_downloaded_file(
        session, file_id=file_id, location_id="loc-downloads",
        name=resource.get("name", ""),
        kind="spreadsheet" if kind == "spreadsheet-macro" else kind,
        size=resource.get("size", ""), source=url,
        macro=(kind == "spreadsheet-macro"),
        # ``web:`` marks a browser origin. The judgement about whether it came
        # from somewhere hostile is made in one place, ``_from_hostile_origin``,
        # so a workbook is equally consequential however it arrived.
        origin_mail="web:%s" % url)
    saved_name = (session.world.get(NS_FILES, file_id) or {}).get(
        "name") or resource.get("name", "")
    if not session.ledger.has(file_fact(file_id)):
        session.introduce_fact(
            file_fact(file_id), category="file_metadata",
            value={"name": saved_name, "source": url},
            source="filesystem", available=True)
    worldops.raise_notification(
        session, kind="system", title="Download complete",
        body="%s is in your Downloads folder." % saved_name,
        opens={"app": "files", "location_id": "loc-downloads"})
    if ix.is_hostile_page(url):
        return service._decide(session, "d-ransom-web-download", learner_action,
                               "Browser", mode_flags)
    return None


def _browser_support(service, session, action, learner_action, mode_flags):
    choice = action.params["choice"]
    if choice == "isolate":
        return _isolate(service, session, learner_action, mode_flags)
    if choice == "reconnect":
        return _reconnect(service, session, learner_action, mode_flags)

    worldops.raise_notification(
        session, kind="system", title="Incident raised",
        body="The Service Desk has your case reference.", opens=None)
    worldops.append_message(
        session, "conv-lena-fischer", "Lena Fischer",
        "Thanks - I can see your ticket. Someone is picking it up now.")
    return None


def _isolate(service, session, learner_action, mode_flags):
    """Take this workstation off the network.

    Six things happen, in this order, and the order is the design:

    1. a :class:`LearnerAction` is already recorded -- the caller did that;
    2. the authoritative network flag flips, and the simulation time of the
       *first* isolation is recorded and never cleared;
    3. every network-dependent consequence that had not yet happened is
       latched as contained, with an internal event naming chain, step and
       reason;
    4. an open file incident is marked **contained** -- and not recovered:
       nothing is restored, no incident is closed, no file comes back, and no
       account is un-compromised;
    5. with an incident, this is the recovery decision it always was. Without
       one, it is an operational decision with an operational cost, and the
       simulation charges it;
    6. nothing that has already happened is touched. Files that stopped
       opening stay closed. That asymmetry is the entire point.

    Isolating twice is one isolation. The second attempt is refused before any
    of this runs, so no incident is opened twice, no chain is scheduled twice
    and no consequence is duplicated.
    """
    if engine_state.is_isolated(session):
        return {"kind": "notice",
                "text": "This workstation is already off the network."}

    if not engine_state.engine_is_active(session):
        # A session created before Batch 3. It gets the behaviour it started
        # with, exactly: the flag, the containment mark, the recovery decision
        # if an incident is open, and nothing else. Introducing containment
        # semantics or an operational cost into an attempt already in progress
        # would change what its learner was being asked to do.
        return _isolate_legacy(service, session, learner_action, mode_flags)

    engine_state.set_isolated(session, True)
    contained_steps = progression.on_isolation(session)
    has_incident = session.world.has(NS_INCIDENTS, "inc-files")

    # "Was there anything to contain?" is answered by the world, not by
    # whether an incident banner happens to be on screen yet. A learner who
    # opens a bad workbook and pulls the cable ten seconds later, before the
    # first file has failed, has contained something real: the chain is in
    # flight and its network steps have just been stopped. Judging that by the
    # banner would call the fastest correct response an over-reaction.
    if has_incident or contained_steps:
        if has_incident:
            # Contained, not recovered. The two are stored as separate facts
            # precisely so a later batch cannot collapse them by accident. An
            # incident that opens *after* this point opens contained -- see
            # ``consequences._chain_is_contained``.
            worldops.set_incident_contained(session, "inc-files", True)
        if not consequences.already_decided(session, "d-ransom-isolate"):
            return service._decide(session, "d-ransom-isolate", learner_action,
                                   "Service Desk", mode_flags)
        worldops.raise_notification(
            session, kind="system", title="Network disconnected",
            body="This workstation is off the network.", opens=None)
        return None

    # Nothing to contain. Disconnecting is not free, and a training
    # environment in which it were would teach that pulling the cable is
    # always the right first move.
    worldops.raise_notification(
        session, kind="system", title="Network disconnected",
        body="This workstation is off the network. Mail, shared folders and "
             "remote access are unavailable until it is reconnected.",
        opens=None)
    worldops.set_session_flag(session, "vpn_connected", False)
    return service._decide(session, "d-isolate-no-incident", learner_action,
                           "Service Desk", mode_flags)


def _isolate_legacy(service, session, learner_action, mode_flags):
    """Batch 2's isolation, preserved verbatim for Batch 2's sessions."""
    worldops.set_session_flag(session, "network_disconnected", True)
    worldops.set_incident_contained(session, "inc-files", True)
    if session.world.has(NS_INCIDENTS, "inc-files") \
            and not consequences.already_decided(session, "d-ransom-isolate"):
        return service._decide(session, "d-ransom-isolate", learner_action,
                               "Service Desk", mode_flags)
    worldops.raise_notification(
        session, kind="system", title="Network disconnected",
        body="This workstation is off the network.", opens=None)
    return None


def _reconnect(service, session, learner_action, mode_flags):
    """Put the workstation back on the network.

    Narrow on purpose: one action, one flag, no network-management UI. It
    exists so isolation cannot soft-lock a session -- a learner who
    disconnected early must still be able to finish, report, investigate and
    reach the debrief.

    It is consequential, and it is not an undo. Consequences that isolation
    already contained stay contained: the latch in
    :mod:`rewindsec.training.progression` is a record of what was true when
    the step would have run, and reconnecting does not change the past. What
    reconnecting restores is the learner's ability to receive new work.
    """
    if not engine_state.is_isolated(session):
        return {"kind": "notice",
                "text": "This workstation is already on the network."}
    engine_state.set_isolated(session, False)
    worldops.raise_notification(
        session, kind="system", title="Network reconnected",
        body="This workstation is back on the network.", opens=None)
    return service._decide(session, "d-network-reconnect", learner_action,
                           "Service Desk", mode_flags)


# -- files ------------------------------------------------------------------

def _require_file(session, file_id):
    state = session.world.get(NS_FILES, file_id)
    if state is None or state.get("deleted"):
        raise UnknownTargetError("No such file.")
    return state


def _files_inspect(service, session, action, learner_action, mode_flags):
    _require_file(session, action.target)
    service._observe(session, file_fact(action.target), learner_action)
    return None


def _files_open(service, session, action, learner_action, mode_flags):
    state = _require_file(session, action.target)
    if state.get("state") == "unavailable":
        worldops.raise_notification(
            session, kind="file",
            title="Cannot open %s" % state.get("name", ""),
            body=state.get("note") or "The file could not be read.", opens=None)
        return None
    origin = state.get("origin_mail")
    if state.get("macro") and _from_hostile_origin(origin):
        return service._decide(session, "d-ransom-open", learner_action,
                               "Files", mode_flags)
    # There is no document viewer, so the workstation does not claim one.
    #
    # Batch 2 answered every open with "Opened in the document viewer.", which
    # was untrue: nothing was rendered, nothing was parsed, and no such surface
    # exists. A synthetic workstation may show a learner a synthetic document,
    # but it may not tell them it did something it did not do -- the whole
    # exercise depends on what is on screen being reliable. The safe
    # read-only document viewer is Batch 4's, alongside the synthetic content
    # work it needs; until then an open reports what the file *is*.
    service._observe(session, file_fact(action.target), learner_action)
    detail = " . ".join(part for part in (
        state.get("size") or "", state.get("modified") or "") if part)
    worldops.raise_notification(
        session, kind="file", title=state.get("name", ""),
        body=("No preview available on this workstation. %s" % detail).strip(),
        opens=None)
    return None


def _from_hostile_origin(origin):
    """Whether a downloaded file came from somewhere the author marked hostile.

    A file can now arrive from a message *or* from a page in the Browser, and
    both have to reach the same judgement -- otherwise the same workbook would
    be consequential when mailed and inert when downloaded.
    """
    if not origin:
        return False
    if origin.startswith("web:"):
        return ix.is_hostile_page(origin[4:])
    return ix.is_hostile_mail(origin)


def _files_delete(service, session, action, learner_action, mode_flags):
    state = _require_file(session, action.target)
    session.mutate_world(NS_FILES, action.target, dict(state, deleted=True))
    return None


def _files_rename(service, session, action, learner_action, mode_flags):
    state = _require_file(session, action.target)
    name = action.params["name"].strip()
    if not name:
        raise InvalidRequestError("A file needs a name.")
    display = name
    if state.get("state") == "unavailable":
        display = "%s.demo_locked" % name
    session.mutate_world(NS_FILES, action.target,
                         dict(state, name=name, display_name=display))
    return None


# -- notifications ----------------------------------------------------------

def _notifications_open(service, session, action, learner_action, mode_flags):
    state = session.world.get(NS_NOTIFICATIONS, action.target)
    if state is None:
        raise UnknownTargetError("No such notification.")
    session.mutate_world(NS_NOTIFICATIONS, action.target,
                         dict(state, unread=False))
    return None


def _notifications_mark_read(service, session, action, learner_action, mode_flags):
    for key, state in session.world.get_component(NS_NOTIFICATIONS).items():
        if state.get("unread"):
            session.mutate_world(NS_NOTIFICATIONS, key, dict(state, unread=False))
    return None


# -- notes ------------------------------------------------------------------

def _notes_create(service, session, action, learner_action, mode_flags):
    seq = worldops.next_seq(session, "note_seq")
    note_id = "note-run-%d" % seq
    worldops.set_note(session, note_id, "New note", "", order=1000 + seq)
    return {"kind": "note_created", "note": note_id}


def _require_note(session, note_id):
    state = session.world.get(NS_NOTES, note_id)
    if state is None or state.get("deleted"):
        raise UnknownTargetError("No such note.")
    return state


def _notes_open(service, session, action, learner_action, mode_flags):
    _require_note(session, action.target)
    return None


def _notes_save(service, session, action, learner_action, mode_flags):
    """Persist what the learner deliberately typed into Notes.

    Stored because it is explicit product data: the learner opened a notebook
    and wrote in it. Nothing else about the clipboard is recorded -- not what
    was copied, not what was pasted, not that a paste happened. Bounded, plain
    text, and rendered as text.
    """
    state = _require_note(session, action.target)
    title = action.params.get("title", state.get("title", ""))
    body = action.params.get("body", state.get("body", ""))
    worldops.set_note(session, action.target, title, body,
                      order=state.get("order", 0))
    return None


def _notes_delete(service, session, action, learner_action, mode_flags):
    state = _require_note(session, action.target)
    session.mutate_world(NS_NOTES, action.target, dict(state, deleted=True))
    return None


# -- authenticator ----------------------------------------------------------

def _require_request(session, request_id):
    state = session.world.get(NS_AUTH_REQUESTS, request_id)
    if state is None or state.get("status") != "pending":
        raise UnknownTargetError("No such approval request.")
    return state


def _auth_inspect(service, session, action, learner_action, mode_flags):
    state = _require_request(session, action.target)
    service._observe(session, prompt_fact(state["prompt_id"]), learner_action)
    return None


def _auth_inspect_history(service, session, action, learner_action, mode_flags):
    service._observe(session, AUTH_HISTORY_FACT, learner_action)
    return None


def _auth_resolve(service, session, action, learner_action, mode_flags, approved):
    state = _require_request(session, action.target)
    prompt_id = state["prompt_id"]
    prompt = ix.PROMPT_BY_ID[prompt_id]
    surface = prompt["surface"]
    session.mutate_world(NS_AUTH_REQUESTS, action.target,
                         dict(state, status="approved" if approved else "denied"))
    service._mark_resolved(session, prompt_id)

    if ix.is_hostile_prompt(prompt_id):
        decision_id = ("d-mfa-approve-hostile" if approved
                       else "d-mfa-deny-hostile")
        return service._decide(session, decision_id, learner_action,
                               "Authenticator", mode_flags)

    # The learner's own remote-access sign-in. Resolving it settles the
    # browser page and belongs in their own approval history.
    for key, value in session.world.get_component(NS_BROWSER).items():
        if key.startswith("signin:") and value == "pending":
            worldops.set_browser_state(session, key,
                                       "done" if approved else "denied")
    worldops.record_auth_activity(
        session, app=surface.get("app", ""),
        result="Approved by you" if approved else "Denied by you",
        device=surface.get("device", ""), location=surface.get("location", ""))
    worldops.set_session_flag(session, "vpn_connected", bool(approved))
    if approved:
        worldops.set_task(session, "task-remote-access", "done",
                          note="Remote access session started.")
    decision_id = "d-mfa-approve-legit" if approved else "d-mfa-deny-legit"
    return service._decide(session, decision_id, learner_action,
                           "Authenticator", mode_flags)


def _auth_approve(service, session, action, learner_action, mode_flags):
    return _auth_resolve(service, session, action, learner_action, mode_flags, True)


def _auth_deny(service, session, action, learner_action, mode_flags):
    return _auth_resolve(service, session, action, learner_action, mode_flags, False)


# -- messages ---------------------------------------------------------------

def _require_conversation(session, conversation_id):
    state = session.world.get(NS_MESSAGES, conversation_id)
    if state is None:
        raise UnknownTargetError("No such conversation.")
    record = ix.CONVERSATION_BY_ID.get(conversation_id)
    if record is None:
        raise UnknownTargetError("No such conversation.")
    return state, record


def _messages_open(service, session, action, learner_action, mode_flags):
    state, _ = _require_conversation(session, action.target)
    if state.get("unread"):
        session.mutate_world(NS_MESSAGES, action.target, dict(state, unread=False))
    service._observe(session, conversation_fact(action.target), learner_action)
    return None


def _messages_send(service, session, action, learner_action, mode_flags):
    """Send a message the learner typed, to a colleague who already exists.

    No arbitrary recipient: the conversation must already be in the world, so
    there is no path from here to an address the learner chose. Bounded plain
    text, stored and rendered as text.
    """
    _require_conversation(session, action.target)
    from rewindsec.workstation.content import world as content_world
    worldops.append_message(session, action.target,
                            content_world.LEARNER["name"],
                            action.params["text"], unread=False)
    return None


def _messages_verify(service, session, action, learner_action, mode_flags):
    """Ask a colleague, on a channel the suspect message did not supply."""
    state, record = _require_conversation(session, action.target)
    script = record.get("verification_reply")
    if not script:
        raise UnknownTargetError("There is nothing to check with this contact.")
    from rewindsec.workstation.content import world as content_world
    worldops.append_message(session, action.target,
                            content_world.LEARNER["name"],
                            script.get("sent", ""), unread=False)
    reply = script.get("reply") or {}
    worldops.append_message(session, action.target, reply.get("from", ""),
                            reply.get("text", ""), unread=True)
    worldops.raise_notification(
        session, kind="message", title=reply.get("from", ""),
        body=reply.get("text", "")[:72],
        opens={"app": "messages", "conversation_id": action.target})
    session.mutate_world(NS_MESSAGES, action.target,
                         dict(session.world.get(NS_MESSAGES, action.target),
                              verified=True))
    contact_id = record.get("contact_id")
    if contact_id:
        service._observe(session, contact_callback_fact(contact_id), learner_action)
    decision_id = _verification_decision(session, action.target)
    if decision_id:
        return service._decide(session, decision_id, learner_action, "Messages",
                               mode_flags)
    return None


# -- directory --------------------------------------------------------------

def _directory_open(service, session, action, learner_action, mode_flags):
    if action.target not in ix.CONTACT_BY_ID:
        raise UnknownTargetError("No such contact.")
    service._observe(session, contact_fact(action.target), learner_action)
    return None


def _directory_call(service, session, action, learner_action, mode_flags):
    """Ring the number the *directory* holds, not the one the message offered."""
    contact = ix.CONTACT_BY_ID.get(action.target)
    if contact is None or not contact.get("callback"):
        raise UnknownTargetError("There is no number on that record.")
    session.mutate_world(NS_DIRECTORY, action.target, {"called": True})
    service._observe(session, contact_callback_fact(action.target), learner_action)
    decision_id = _verification_decision_for_contact(session, action.target)
    if decision_id:
        return service._decide(session, decision_id, learner_action, "Directory",
                               mode_flags)
    return None


# -- session ----------------------------------------------------------------

def _session_acknowledge(service, session, action, learner_action, mode_flags):
    """Continue past the safer-alternative comparison.

    This dismisses an explanation. It restores nothing, rewinds nothing and
    reverses nothing: the world the learner returns to is the one their
    decision produced, which is the whole point of the architecture's refusal
    of automatic rewind.
    """
    if session.world.get(NS_SESSION, "pending_comparison"):
        session.mutate_world(NS_SESSION, "pending_comparison", None)
    return None


# ---------------------------------------------------------------------------
# Decision routing tables
# ---------------------------------------------------------------------------

#: Which authored decision a report maps to. Data rather than branches, so the
#: mapping is inspectable in one place.
_REPORT_DECISION = {
    "m-payroll-restructure": "d-phish-report",
    "m-rate-card": "d-ransom-report",
    "m-invoice-amend": "d-bec-report",
    "m-invoice-confirm": "d-bec-report",
}

_REPLY_DECISION = {
    "m-headcount": "d-task-headcount-done",
    "m-invoice-amend": "d-bec-reply",
}

#: Verification only counts as verification of something actually in front of
#: the learner. Checking with payroll about a message that was deleted an hour
#: ago is not the same act.
_VERIFY_BY_CONVERSATION = {
    "conv-arjun-rao": ("m-invoice-amend", "d-bec-verify"),
    "conv-priya-menon": ("m-payroll-restructure", "d-phish-verify"),
}

_VERIFY_BY_CONTACT = {
    "dir-calderwood": ("m-invoice-amend", "d-bec-verify"),
    "dir-priya-menon": ("m-payroll-restructure", "d-phish-verify"),
}


def _is_live(session, mail_id):
    state = session.world.get(NS_MAIL, mail_id)
    return bool(state and state.get("delivered") and not state.get("reported")
                and state.get("folder") != "deleted")


def _verification_decision(session, conversation_id):
    pair = _VERIFY_BY_CONVERSATION.get(conversation_id)
    if pair and _is_live(session, pair[0]):
        return pair[1]
    return None


def _verification_decision_for_contact(session, contact_id):
    pair = _VERIFY_BY_CONTACT.get(contact_id)
    if pair and _is_live(session, pair[0]):
        return pair[1]
    return None


#: Practice, and only Practice, says so when a decision was a good one. The
#: text lives on the server because whether it is said at all is a mode
#: decision, not a rendering decision.
_CONFIRMATION_TEXT = {
    "d-phish-report": "That was the right call. Reporting it means the same "
                      "batch can be stopped for everyone else who received it.",
    "d-ransom-report": "Good. The attachment stayed unopened and the sender is "
                       "now on record.",
    "d-bec-report": "Good. An account change that arrives by mail is exactly "
                    "the thing to stop and check.",
    "d-phish-verify": "That is the check that works - you asked on a channel "
                      "the message did not supply.",
    "d-bec-verify": "That is the check that works. The number came from your "
                    "own records, not from the request.",
    "d-mfa-deny-hostile": "Right call. An approval belongs to something you "
                          "started.",
    "d-mfa-approve-legit": "That one was yours - same workstation, same "
                           "location, seconds after you signed in.",
    "d-ransom-isolate": "Taking it off the network first is the part most "
                        "people skip.",
    "d-task-headcount-done": "Done - and it was a genuine request, which is "
                             "the other half of the job.",
}


_HANDLERS = {
    "mail.open": _mail_open,
    "mail.inspect_headers": _mail_inspect_headers,
    "mail.inspect_link": _mail_inspect_link,
    "mail.inspect_attachment": _mail_inspect_attachment,
    "mail.open_link": _mail_open_link,
    "mail.report": _mail_report,
    "mail.delete": _mail_delete,
    "mail.forward": _mail_forward,
    "mail.reply": _mail_reply,
    "mail.download_attachment": _mail_download,

    "browser.navigate": _browser_navigate,
    "browser.sign_in": _browser_sign_in,
    "browser.sign_in_retry": _browser_sign_in_retry,
    "browser.release_payment": _browser_release_payment,
    "browser.support_action": _browser_support,
    "browser.download": _browser_download,

    "files.inspect": _files_inspect,
    "files.open": _files_open,
    "files.delete": _files_delete,
    "files.rename": _files_rename,

    "notifications.open": _notifications_open,
    "notifications.mark_read": _notifications_mark_read,

    "notes.create": _notes_create,
    "notes.open": _notes_open,
    "notes.save": _notes_save,
    "notes.delete": _notes_delete,

    "auth.inspect_request": _auth_inspect,
    "auth.inspect_history": _auth_inspect_history,
    "auth.approve": _auth_approve,
    "auth.deny": _auth_deny,

    "messages.open": _messages_open,
    "messages.send": _messages_send,
    "messages.verify": _messages_verify,

    "directory.open": _directory_open,
    "directory.call": _directory_call,

    "session.acknowledge": _session_acknowledge,
}


def _recordable_params(action):
    """What of an action's parameters goes into the durable action log.

    Learner-authored content the product exists to keep -- a note, a reply, a
    message -- is recorded as its length, not its text: the text itself is
    already in the world, where it belongs, and duplicating it into the action
    log would mean deleting a note left a copy behind. Nothing resembling a
    credential is accepted by any action in the first place.
    """
    out = {}
    for name, value in sorted(action.params.items()):
        if name in ("text", "body", "title", "name", "account"):
            out["%s_length" % name] = len(value)
        else:
            out[name] = value
    return out or None


def _coerce(value, enum_cls, what):
    try:
        return coerce_enum(value, enum_cls, what)
    except DomainError as exc:
        raise InvalidRequestError("That %s is not one of the options." % what) from exc
