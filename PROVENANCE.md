# Provenance: RewindSec v1 vs RewindSec 2.0

This is an engineering document, not a research narrative. It records which
parts of this repository belong to the **pre-2.0 (v1) system** and which belong
to the **RewindSec 2.0 rebuild**, so that no later change can silently present
v1 artifacts as 2.0 evidence.

It exists because the two systems will live side by side in one repository for
a while, and because the most damaging possible defect here is not a crash. It
is a table, a results file or a figure that is quietly attributed to the wrong
architecture.

**Baseline of record:** tag `v1.0.0` = commit `0421c8a`
(*Polish RewindSec frontend experience*), on branch `rewindsec-redesign`.
That tag is the complete, working v1 system. Anything described below as "v1"
can be recovered from it exactly.

---

## 1. The rules

1. **v1 study and evaluation data must never be pooled with, relabelled as, or
   presented as RewindSec 2.0 evidence.** Not by re-running a v1 harness against
   2.0 code, not by adding 2.0 rows to a v1 table, not by merging result
   directories.
2. **Every historical evaluation result stays attributable to the architecture
   it actually measured.** The files under `evaluation/results/**` measured v1.
   They do not become 2.0 measurements because 2.0 later exists in the same
   repository.
3. **RewindSec 2.0 uses separately named packages, models, tables, harnesses and
   results directories.** Separation is structural, not a matter of discipline:
   if the names are disjoint, no query, join or glob can accidentally mix the
   two populations.
4. **No module under `rewindsec/` may import v1 study, learning, scenario or
   historical evaluation code.** Enforced statically by
   `tests/test_provenance.py`.
5. **Historical v1 code is not deleted or rewritten during the 2.0 rebuild.**
   It is the provenance of published and in-progress claims.

---

## 2. Reusable technical ideas and infrastructure

These are **not** v1-specific claims. They are engineering assets, and 2.0 is
expected to reuse or port them. Reusing them creates no provenance problem,
because they carry no experimental result.

| Component | What is reusable |
|---|---|
| `training/snapshots.py` | Canonical JSON (`canonical_json`) + SHA-256 state fingerprinting (`fingerprint`), with rejection of secret-shaped keys, non-finite floats and non-string keys. Explicitly avoids process-salted `hash()`. |
| `training/runtime.py` | The **verify-before-continue** invariant: after a rewind, re-capture and re-hash, and fail closed on mismatch (`CounterfactualRuntime.rewind_and_verify`, `BaselineVerificationError`). |
| `training/adapters/base.py` | The `prepare` / `capture_state` / `apply` / `rewind` contract, the closed symbolic action vocabulary, and the rule that capturing state must never change it. |
| `sandbox/` (all of it) | Container containment flags, ownership by label + name prefix, content-verified readiness seeding, the two-gate synthetic file impact (`sandbox/impact_core.py`), path policy (`sandbox/paths.py`), derived sandbox ids (`sandbox/session_scope.py`), age-based reaping. |
| `sandbox/sanitize.py`, `sandbox/pseudonym.py` | Error sanitisation and pseudonymisation for instructor-facing views. |
| `telemetry_ledger.py` | The SAVEPOINT + unique-constraint idempotency claim pattern. |
| `security.py` | CSRF, login throttling, session rotation, instructor auth. |
| `manage.py` | Explicit, confirmation-gated database commands. |

Reuse of these is a code decision. It is never, on its own, evidence about
2.0's behaviour: 2.0 must be measured by its own harness.

---

## 3. v1 learner architecture

The v1 learner experience: one labelled threat-family module per URL, one
decision per attempt, attempt state in the signed Flask cookie, a full page
render per step, and a rewind that reconstructs a single authored baseline.

| Path | Role |
|---|---|
| `training/` | Framework-free paired-counterfactual runtime, scenario definitions, comparison and observation types. |
| `training_routes.py` | The `/training` blueprint: phishing and ransomware flows (`brief`, `start`, `inbox`/`workstation`, `decision`, `outcome`, `rewind`, `result`). |
| `training_flow.py` | `SyntheticModule` / `register_synthetic_module`, the shared MFA and BEC flow. |
| `training_service.py` | The Flask/SQLAlchemy seam: identity, persistence, staged-preview integrity, telemetry translation. |
| `scenario_adapters/` | `phishing.py`, `ransomware.py`, `mfa.py`, `bec.py`, `presentation.py` — the four v1 scenario keys. |
| `TrainingExecution` (`app.py`) | One paired-execution result row: digests, both branch states, the difference, failure type. |
| `learning/`, `learning_service.py`, `learning_routes.py` | The v1 pedagogy layer: reflection quality, concept evidence, transfer probes. |
| `LearningReflection`, `ConceptEvidence`, `TransferAttempt` (`app.py`) | The v1 pedagogy tables. |
| v1 learner templates | `templates/training_*.html`, `templates/_training_*.html`, `templates/index.html`, `templates/resources.html`, and `templates/training_base.html`. |
| v1 scenario docs | `docs/phishing-scenario.md`, `docs/ransomware-scenario.md`, `docs/mfa-scenario.md`, `docs/bec-scenario.md`, `docs/learning-layer.md`, `docs/training-runtime.md`. |

**Status:** frozen for reference. 2.0 will replace this learner architecture,
but the v1 code stays until 2.0 covers its function, and its behaviour is not
edited to suit 2.0.

**Provenance note:** these modules define what the v1 study and the v1 formal
evaluation actually measured. Changing them retroactively changes the meaning of
every stored result, which is why they are not refactored during the rebuild.

---

## 4. v1 study and protocol artifacts

A randomised pilot **of the v1 phishing module**. Disabled by default
(`REWINDSEC_STUDY_ENABLED`), fail-closed without its three secrets.

| Path | Role |
|---|---|
| `study/` | Framework-free protocol code: `assignment.py` (HMAC arm allocation), `protocol.py` (phase machine), `continuity.py` (return codes), `assessment.py`, `errors.py`. |
| `study_service.py` | Enrollment, phase advance, the three arms, retention windows, `export_rows()`, `dashboard()`. |
| `study_routes.py` | The `/study` blueprint. |
| `StudyEnrollment`, `StudyIntervention`, `StudyAssessmentAttempt` (`app.py`) | The three v1 study tables. |
| `templates/study_*.html` | The participant-facing study screens. |
| `docs/study-protocol.md` | The protocol as executed. |
| `tests/test_study_*.py` | Eight test modules, including the privacy assertions. |

**Status:** **frozen**. Do not repoint, extend or reuse for 2.0.

**Why frozen:** the arms, the assessment items and the retention windows are all
defined against v1's single-decision phishing module. A participant row in
`StudyEnrollment` means "took part in the v1 pilot" and can mean nothing else.
Recruiting 2.0 participants into these tables would make the two populations
indistinguishable after the fact.

**For 2.0:** a new protocol, new tables with new names, and a new document. Not
an extra column on these.

---

## 5. v1 evaluation artifacts and results

Two harnesses exist, measuring two different v1 architectures. Both are
historical.

| Harness | Measures | Results |
|---|---|---|
| `evaluation/formal_run.py` + `evaluation/specifications.py` | The earlier Milestone-4 simulator (scenario keys `credential_reuse_phishing`, `file_impact`, `ransomware_awareness`). | `evaluation/results/formal/` |
| `evaluation/rewindsec_formal_run.py` + `evaluation/rewindsec_specifications.py` | The v1 paired-counterfactual architecture (scenario keys `phishing_credential_compromise`, `ransomware_incident_response`, `mfa_fatigue_response`, `business_email_compromise`). | `evaluation/results/rewindsec-formal/` |

Supporting modules: `evaluation/containment.py`, `evaluation/environment.py`,
`evaluation/metrics.py`, `evaluation/run_experiments.py`. Documentation:
`docs/rewindsec-formal-evaluation.md`.

**Status:** **frozen.** Do not edit either harness's semantics, and do not edit
any file under `evaluation/results/**`.

### Standing caveat on the stored `rewindsec-formal` results

`evaluation/results/rewindsec-formal/smoke/metadata.json` records
`"admissible": false`, `"development_run": true`, `"smoke": true`,
`"git_tree_dirty": true`, at commit `7a72743` — which is **not** the `v1.0.0`
baseline. These are development numbers produced by a reduced-configuration
smoke run against a dirty tree. They are not admissible results for any claim
about anything, and the `admissible: false` flag must never be dropped when
these files are summarised, copied or quoted.

### How the results are protected

`evaluation/results/` is listed in `.gitignore` (line 38), so **git does not
track these files and cannot detect a change to them**. That makes an explicit
integrity record necessary rather than optional.

`evaluation/results_manifest.json` records the relative path, SHA-256 and byte
size of each of the 32 artifacts present at commit `0421c8a`.
`tests/test_provenance.py` verifies every entry when the results tree exists,
and skips when it does not — a fresh clone or a CI machine legitimately has no
results tree, and failing there would be noise rather than signal. Files present
on disk but absent from the manifest are allowed, so a **new** run can be added
without editing the manifest; what the manifest forbids is a listed artifact
being modified or deleted.

**For 2.0:** a third harness, named separately (e.g.
`evaluation/rewindsec2_*`), writing to a separate directory (e.g.
`evaluation/results/rewindsec2/`), with its own independent oracle. Never
re-run a v1 harness against 2.0 code and report the numbers as a continuation.

---

## 6. RewindSec 2.0 artifacts

Everything 2.0 owns lives under `rewindsec/`.

| Path | Role |
|---|---|
| `rewindsec/core/rng.py` | `SeededRandom`: the single randomness owner, with independently derived named streams and full state capture/restore. |
| `rewindsec/core/simtime.py` | `SimClock`: integer-millisecond simulation time, independent of the wall clock. |
| `rewindsec/core/events.py` | `Event` and `EventSpec`: the canonical event model, with SHA-256-derived event identity and behavioural (never threat-family) type names. |
| `rewindsec/core/scheduler.py` | `EventScheduler`: the deterministic delayed-event queue, ordered by `(fire_at_ms, priority, insertion_seq)`. |

Rules for anything added here:

* **Framework-free core.** Nothing under `rewindsec/core/` may import Flask,
  SQLAlchemy, `sandbox`, or any v1 module.
* **No hidden nondeterminism.** Nothing under `rewindsec/core/` may import
  `secrets`, `uuid`, `time` or `datetime`. `random` may be imported only by
  `rewindsec/core/rng.py`, where it is wrapped behind explicitly seeded
  `random.Random` instances that the session owns.
* **Separate names.** 2.0 models, tables, harnesses and results directories get
  their own names; they never extend a v1 one.

Both rules are enforced by
`tests/test_rewindsec2_core_boundaries.py` and `tests/test_provenance.py`.

Wall-clock timestamps are not banned from the project — only from deterministic
state. They belong in diagnostic and telemetry layers outside `rewindsec/core/`.

### Batch 1: simulation domain and persistence

`rewindsec/domain/` and `rewindsec/persistence/` add the storage-independent
session aggregate on top of the core above, and the port/adapter pair that
persists it.

| Path | Role |
|---|---|
| `rewindsec/domain/session.py` | `SimulationSession`: the aggregate root composing the core (`SeededRandom`, `SimClock`, `EventScheduler`) with the domain objects below, and the only object responsible for cross-object referential integrity. |
| `rewindsec/domain/world.py` | `WorldState`: versioned, generic, auditable workplace state (no Mail/Files/Browser backends yet — later batches). |
| `rewindsec/domain/context_ledger.py` | `ContextLedger`: the available-vs-observed distinction as first-class state. |
| `rewindsec/domain/actions.py` | `LearnerAction`/`ActionLog`: observational vs. consequential learner actions, with their own SHA-256-derived id scheme, distinct from event ids. |
| `rewindsec/domain/session_events.py` | `SessionEventLog` (reuses `core.events.derive_event_id` directly) and `ScheduleAuditLog`, the durable record of what was scheduled/fired/cancelled and why, independent of the live scheduler's own swept state. |
| `rewindsec/domain/incidents.py` | `IncidentGraph`: the generic, threat-agnostic causal consequence graph. |
| `rewindsec/persistence/ports.py` | `SessionRepository`: the storage-independent repository contract, with an optimistic-concurrency (`expected_revision`) update contract. |
| `rewindsec/persistence/sqlalchemy_adapter.py` | The one adapter Batch 1 ships: reuses the app's existing SQLAlchemy dependency, isolated from Flask, no pickle, versioned JSON snapshots. |

Rules for anything added here:

* **Storage- and framework-independent domain.** Nothing under
  `rewindsec/domain/` may import Flask, Flask-SQLAlchemy, SQLAlchemy, `random`,
  or any v1 module; it must be usable in a pure Python test with no app context
  and no database.
* **SQLAlchemy stays in the adapter.** Only `rewindsec/persistence/
  sqlalchemy_adapter.py` may import SQLAlchemy; `ports.py` (the contract) does
  not, and neither module imports Flask.
* **One event-id scheme.** `SessionEventLog` uses `core.events.derive_event_id`
  directly; it does not invent a second one. `LearnerAction` ids use their own,
  distinct, SHA-256 label so the two schemes can never collide.

Enforced by `tests/test_rewindsec2_domain_boundaries.py`, alongside the
adversarial unit and resume-determinism suites
(`tests/test_rewindsec2_domain_*.py`, `tests/test_rewindsec2_persistence_*.py`,
`tests/test_rewindsec2_resume_determinism.py`,
`tests/test_rewindsec2_cross_process_determinism.py`).

No application content, threat-family engine, scoring, or UI wiring is part of
this batch — see the batch's own completion report for the full boundary.


### Batch 2: workstation backend integration

`rewindsec/workstation/` is the application layer between the domain and the
HTTP adapter. It is the batch in which the learner-facing product stopped
being a presentation prototype: the workstation now runs on a persisted
`SimulationSession`, and the browser is no longer authoritative for any
factual simulation state.

| Path | Role |
|---|---|
| `rewindsec/workstation/content/` | The authored bootstrap workplace (`world.py`, `scenario.py`, moved here from `rewindsec/prototype/`, plus `index.py`). One fixed authored scenario a session is *seeded from* — explicitly **not** the Batch 3 generator. |
| `rewindsec/workstation/bootstrap.py` | Seeds one session's `WorldState` and `ContextLedger` from that content, including every inspection-only fact in its unobserved state. |
| `rewindsec/workstation/actions.py` | The closed, allowlisted learner-action vocabulary and its strict request parser. Unknown keys, unknown actions, bool-as-int, NaN/infinity and over-long payloads are rejected rather than ignored. |
| `rewindsec/workstation/service.py` | `WorkstationService`: the only thing that changes a session. Validates lifecycle and target, records the `LearnerAction`, marks observed facts, mutates the world, records events and consequences, persists under optimistic concurrency, projects. It reads no real clock: simulation time advances only by explicitly stated amounts (`TICK_QUANTUM_MS` per heartbeat, or a caller-named amount from the development tooling). |
| `rewindsec/workstation/worldops.py` | The primitive world verbs shared by the action handlers and the consequence engine. |
| `rewindsec/workstation/consequences.py` | The authored consequence chains, scheduled on the session's own `EventScheduler` at mode-scaled simulation delays and applied when their events fire. |
| `rewindsec/workstation/projection.py` | The learner-safe view model. An allowlist, not a filter: the wall between authored ground truth and the browser. |
| `rewindsec/workstation/debrief.py` | The post-session factual debrief, refused while a session is active. |
| `rewindsec/workstation/updates.py` | `UpdateBroker`: a bounded, in-process revision broker behind SSE. Carries revision numbers, never content. |
| `rewindsec/workstation/seeds.py`, `clock.py`, `errors.py` | Root-seed sources (injectable), the display clock, and the typed error vocabulary the HTTP adapter maps onto status codes. |
| `rewindsec/prototype/api.py` | The Flask adapter. The only module that knows what a request or a status code is. |

Rules for anything added here:

* **Framework-free application layer.** Nothing under `rewindsec/workstation/`
  may import Flask, SQLAlchemy, Werkzeug, Jinja, `app`, `security`, `sandbox`
  or any v1 module; nor anything that could open a socket or start a
  subprocess. It raises `WorkstationError` subclasses and the adapter maps
  them onto status codes.
* **One dependency direction.** Flask adapter → workstation → domain →
  persistence. The adapter may not import `rewindsec.domain` or
  `rewindsec.persistence` directly, because a route that reached the aggregate
  could mutate the world without passing validation.
* **No ambient nondeterminism in simulation decisions.** Randomness comes from
  the session's `SeededRandom`; simulation time from its `SimClock`. The two
  documented exceptions are minting a root seed and minting a session id, both
  infrastructure and both injectable.
* **No wall clock at all, with no exemption.** No module in
  `rewindsec/workstation/` imports `time`, `datetime` or `calendar` or calls
  into one. Simulation time moves only when an explicit application operation
  says so, by an amount that is stated rather than measured, so a session's
  state is a pure function of its seed and its recorded inputs — identical
  across machine speed, request latency, sleeps, process restarts and browser
  timer cadence.
* **A session is replaced only on purpose.** Rendering a page or reading a
  session never ends, creates, or re-focuses one, and query parameters carry
  no authority over a session that already exists; `POST /api/session/start`
  is refused while one is live, and `POST /api/session/new` completes the
  outgoing attempt on the record before opening another.
* **The projection may not read authored ground truth.** It never calls the
  `is_hostile_*` predicates and never names an `analysis` block.
* **A download never replaces a synthetic file.** The name a downloaded file
  is saved under is resolved on the server from world state alone -- the
  client cannot name it -- and a name already in that folder (compared
  case-insensitively) yields the first free `name (n).ext` instead of an
  overwrite. Nothing on the host filesystem is read or written.

Enforced by `tests/test_rewindsec2_workstation_boundaries.py`, alongside the
leakage, action, HTTP, resume, SSE, determinism-under-real-time,
session-lifecycle and download-collision suites
(`tests/test_rewindsec2_workstation_*.py`).

**What was still fixture-backed at the time of Batch 2, and is not any more:**
the numeric scores on the results screen (made real by Batch 4) and the
trainer console (made real by Batch 5). Both statements are preserved here as
the record of what Batch 2 shipped, not as a description of the current
system.

**Persistence:** the three Batch 1 tables (`rewindsec2_*`) are created
alongside the application's own in `init_db()` with `checkfirst`, so they are
added to an existing database without touching a single historical table. No
v1 table is read, written or migrated.

### Batch 3: training engine and threat families

**Base commit:** `e69448d` (*Wire workstation to server-authoritative sessions*).
**Engine version:** `training-engine/v1`. **Catalogue version:**
`training-catalog/v1`.

`rewindsec/training/` is the layer that decides what the simulated workplace
does next. It is the batch in which the fixed authored timeline stopped being
the runtime truth: a session created from here on selects its own workplace
activity from world state, the Context Ledger, per-family pressure and named
seeded RNG streams, and the authored `TIMELINES` table is consulted only for
sessions that predate this batch.

| Path | Role |
|---|---|
| `rewindsec/training/policy.py` | Every authored constant, and the occurrence rule written out in full: pressure increment, focus and mode multipliers, starvation, cooldown, hazard cap, evaluation cadence. Authored system logic, not a published algorithm and not derived from human-learning research. |
| `rewindsec/training/state.py` | The persisted engine state and the only vocabulary for reading or writing it. Lives in one dedicated `WorldState` namespace (`training_engine`), so it is persisted, restored and audited with the session and is invisible to the projection's namespace allowlist. |
| `rewindsec/training/eligibility.py` | LOCKED or ELIGIBLE, with machine-readable reason codes, computed before any random value is drawn. Declares `fact_available` and `fact_observed` as separate prerequisite kinds. |
| `rewindsec/training/candidate.py`, `catalog.py` | The candidate value object and the single sorted catalogue of every activity the engine may select. |
| `rewindsec/training/families/` | Per-family candidates and network-dependence declarations: `phishing.py`, `ransomware.py`, `mfa.py`, `bec.py`, `background.py`. |
| `rewindsec/training/selection.py` | Weighted choice over an explicitly ordered sequence, consuming exactly one draw per decision. |
| `rewindsec/training/delivery.py` | The adapters that turn a selected candidate into world state, through `worldops` and nothing else. |
| `rewindsec/training/progression.py` | Whether a scheduled consequence step may still happen. Holds the network-dependent step registry and the isolation latch. |
| `rewindsec/training/engine.py` | The evaluation pulse: eligibility, pressure, occurrence, family, candidate, delivery, reschedule. |

**Threat families implemented:** phishing, ransomware, MFA and BEC, each with
at least one hostile candidate and at least one structurally identical
legitimate counterpart, plus a separate benign background family for ordinary
workplace activity.

**Deterministic selection semantics.** Simulation time is divided into
evaluation pulses scheduled on the session's own `EventScheduler`. At each
pulse the engine resolves every candidate to LOCKED or ELIGIBLE with no RNG
involvement, raises pressure for eligible families by a seeded `+3..+10`
percentage points scaled by integer focus and mode multipliers plus a bounded
starvation term, rolls once against the capped sum, then picks a family by
pressure and a candidate by authored weight. Selection resets that family's
pressure and starts its cooldown; every other eligible family's starvation
counter increments; a family with nothing eligible is frozen and its
starvation reset. Background activity runs the same rule on its own state and
its own stream, only when no threat fired.

RNG is partitioned into the five named streams architecture §16.1 requires:
`background`, `threat_selection`, `timing`, `content_variation` and
`consequence`. The four Batch 1 stream names are unchanged — a stream's seed
is derived from its name, so renaming one would silently alter every stored
session — and the new names were added alongside them.

**Network isolation.** The Service Desk disconnect action became meaningful
containment. It records a `LearnerAction`, flips the authoritative network
flag, records the simulation time of the first isolation, and latches every
pending network-dependent consequence step as suppressed with an internal
event naming chain, step and reason. Suppressed steps still come due and still
settle their chain; they simply apply no effect, open no incident and record no
consequence, so the causal graph never points at something that did not
happen. Containment is stored separately from any notion of recovery: nothing
is restored, no incident is closed, no file returns and no account is
un-compromised. Damage already incurred is untouched, and reconnecting — a
narrow, consequential action added so isolation cannot soft-lock a session —
does not resurrect a contained consequence. Isolating with nothing to contain
has an operational cost rather than being free.

**Synthetic content only.** Four new messages and two downloadable page
resources were authored for this repository. No external corpus, dataset or
threat feed is ingested, nothing is derived from a real message, every address
is under a reserved TLD, and no credential, payment detail or employee record
is real. The dataset provenance and sanitisation pipeline architecture §28
specifies is Batch 4's.

**Explicitly out of scope, and still fixture-backed or absent:** six-dimension
scoring, the Evidence Graph and the overall score (Batch 4); the safe
read-only synthetic document viewer (Batch 4 — the file-open path no longer
claims one exists); trainer attempt records, students, groups and assessments
(Batch 5); Docker-backed technical ransomware state (Batch 6 — every effect
here is a row in a synthetic world, and the training boundary suite asserts
that the layer imports no `os`, `shutil`, `subprocess`, `socket` or HTTP
client and calls no `open()`).

**Compatibility with Batch 2 sessions.** A session carries the engine state
that created it or it does not, and `training.state.engine_is_active` is the
single predicate that decides. Sessions created before this batch keep the
authored timeline, never schedule an evaluation pulse, never receive an engine
candidate, and keep Batch 2's isolation behaviour verbatim. There is
deliberately no migration and no third case: half an authored queue and half a
stochastic engine would give a learner two overlapping simulations.

Rules for anything added here:

* **Pure Python engine.** Nothing under `rewindsec/training/` may import
  Flask, SQLAlchemy, Jinja, `app`, `security`, `sandbox`, any v1 module,
  anything that could reach a network or a subprocess, or anything that
  touches the host filesystem.
* **No ambient nondeterminism, with no exemption.** No `random`, no `secrets`,
  no `uuid`, no `hash()` in a decision, and no `time`, `datetime` or
  `calendar` anywhere in the package. Every draw comes from a named stream of
  the session's `SeededRandom`; every decision reads the session's `SimClock`.
* **Eligibility before probability.** A LOCKED candidate consumes no draw, so
  adding a candidate nobody can select cannot shift a stored session's replay.
* **One dependency direction.** HTTP adapter → workstation → training →
  domain/core. The domain, the core and the HTTP adapter import nothing from
  `rewindsec.training`.
* **Engine state is versioned and namespaced.** It is never written to ad-hoc
  world keys; changing the selection rule or the catalogue in a way that
  alters replay requires an intentional version change.
* **The projection never sees any of it.** Family, candidate id, hostility,
  pressure, starvation, cooldown, eligibility reasons, suppression latches and
  the selection trace are all learner-hidden; internal engine introspection is
  a development-only endpoint, never a field on a learner snapshot.

Tests added: `tests/test_rewindsec2_training_boundaries.py`,
`test_rewindsec2_training_engine.py`, `test_rewindsec2_training_families.py`,
`test_rewindsec2_network_isolation.py`, `test_rewindsec2_training_legacy.py`,
plus `tests/training_helpers.py`. Existing Batch 2 suites that asserted
fixed-timeline behaviour were replaced with stronger assertions of the new
architecture rather than relaxed.

### Batch 4: scoring, evidence, synthetic content pipeline, document viewer

**Base commit:** `f38b9c5` (*Add deterministic training engine and threat
families*). **Versions:** `rewindsec-scoring/v1`, `rewindsec-rubric/v1`,
`rewindsec-evidence-model/v1` (`rewindsec/scoring/versions.py`).

`rewindsec/scoring/` turns a completed session's own factual history into the
real six-dimension result; `rewindsec/content/` is the safe synthetic content
pipeline; the document viewer is a small addition to
`rewindsec/workstation/` and `rewindsec/workstation/content/`.

| Path | Role |
|---|---|
| `rewindsec/scoring/dimensions.py` | The six authoritative dimension ids, matching the `dimensions` vocabulary already authored on every decision in `workstation/content/scenario.py` since Batch 2/3. |
| `rewindsec/scoring/opportunities.py` | The Opportunity model (review correction): every chance a session presented to demonstrate something, materialized from factual world state (a delivered message, a raised approval request, a contained incident) — never from a recorded decision. |
| `rewindsec/scoring/evidence.py` | The Evidence Graph: deterministic, SHA-256-derived evidence ids. Walks every `Opportunity`; a resolved one contributes its decision's authored evidence, an ignored one contributes explicit negative evidence for every dimension it was relevant to — not only `security_judgment`. |
| `rewindsec/scoring/rubric.py` | The authored policy: decision-class → valence, evidence weights, and one applicability predicate per dimension (the N/A rule; Recovery Quality's now keyed to a genuine recovery opportunity, not merely "an incident occurred"). |
| `rewindsec/scoring/evaluator.py` | Pure aggregation: evidence → per-dimension score (deterministic integer rounding, no floating-point ambiguity) → overall. |
| `rewindsec/scoring/result.py` | `ScoringResult`/`DimensionResult`: the internal artifact (`to_state`) and the permitted learner/debrief projection (`to_learner_view`), plus the human-competence disclaimer every result carries. |
| `rewindsec/scoring/state.py` | Versioning at session creation (`bootstrap`), finalize-once persistence (`finalize`), and the legacy/versioned/unavailable three-way `learner_view`. |
| `rewindsec/content/provenance.py` | Machine-readable source records. All `origin="internally_authored_synthetic"` — **no external phishing/security corpus is used by runtime content.** |
| `rewindsec/content/sanitize.py` | The fail-closed sanitizer: rejects real-looking domains/emails/phone numbers, any HTML tag, `javascript:`, event-handler attributes, path traversal, credential-shaped strings, and control characters. |
| `rewindsec/content/normalize.py`, `archetypes.py` | Reviewed-and-sanitized source → normalized feature → safe high-level archetype (document, mail, MFA), never a copy of anything real. |
| `rewindsec/content/generate.py` | Deterministic id derivation (`derive_content_id`, SHA-256, never `hash()`) and variant choice from a caller-owned RNG stream — session-stream-shaped and tested as such, even though the shipped catalogue is static (see below). |
| `rewindsec/content/bind.py` | Binds generated content to the one existing fictional organisation in `workstation/content/world.py` rather than inventing a second one. |
| `rewindsec/content/catalog.py`, `schema.py` | The eight-document runtime catalogue and the closed `SyntheticDocument` block schema (`paragraph`/`heading`/`key_value`/`table`/`list`), sanitized at construction. |
| `rewindsec/workstation/content/documents.py` | The workstation-side binding of file ids / mail-attachment origins / browser-download origins to a catalogue document id. |
| `rewindsec/training/families/background.py::cand-bg-facilities-followup`, `rewindsec/training/delivery.py::_SUBJECT_VARIANTS` (review correction) | The first live training candidate wired to the content pipeline: a real, selectable mail whose subject is a deterministic `content_variation` draw and whose attachment resolves to a pipeline-generated document, reaching the mailbox and the document viewer through the same paths every other candidate and document use. |
| `rewindsec/workstation/bootstrap.file_document_fact` | The Context Ledger fact carrying one file's document content — available when the file exists, observed only once opened. |
| `rewindsec/workstation/service._restore` | The narrowly scoped recovery action (`browser.support_action` choice `"restore"`): only reachable once an incident is contained, restores affected file rows, and records the `d-ransom-recover` decision, without touching the incident's identity or causal history. |

**Why the scoring dimensions and rubric are not a new invention.** The
authored `class`/`dimensions` fields on every entry in
`workstation/content/scenario.py::DECISIONS` were already present since
Batch 2/3 and already used exactly the six dimension names this batch makes
authoritative. The Evidence Graph is built primarily by reading those
existing fields plus the existing `evidence_source`/`evidence_model`
translation (moved from `workstation/projection.py` into
`workstation/content/index.py` so both the projection and the scoring package
read one shared vocabulary, never two that could drift).

**Versioning and legacy sessions.** `scoring_state.bootstrap` stamps every
session with its three versions at creation (`WorkstationService
.start_session`), mirroring how `training.state` stamps the engine version.
A session with no stamp — every session created before this batch — is
unambiguously legacy for scoring for its entire lifetime, independent of when
it happens to complete: `debrief_document`'s `scoring` block returns
`{"available": false, "legacy": true, ...}` for it, never a retroactively
invented rubric result and never the old `{"engine": "none"}` placeholder.
A versioned session's result is computed once — at `end_session`, before the
session transitions to `COMPLETED` (state mutation requires an active
session) — and persisted under a dedicated `scoring` `WorldState` namespace;
ending an already-completed session is a no-op that returns the stored
result unchanged.

**No external dataset.** Every archetype's provenance record is marked
`internally_authored_synthetic`; none references or was derived from a real
corpus, a real message, or a real organisation.

**Opportunities are independent of learner actions (review correction).**
The first cut of scoring derived the Evidence Graph directly from recorded
decisions, which meant a hostile message, approval request or recovery step
the learner never touched could silently produce no evidence at all —
scoring it as a neutral 50, or in some cases leaving the dimension N/A, when
a real, presented opportunity had in fact been ignored. `rewindsec/scoring
/opportunities.py` corrects this: an `Opportunity` is now materialized from a
fixed, hand-authored map of which decisions would resolve it — never from
whether one actually was recorded. `evidence.py` walks every opportunity a
session presented; an unresolved one now contributes explicit negative
evidence for *every* dimension it was relevant to, derived from the union of
its resolving decisions' own authored `dimensions`. This is what makes "the
learner never touched it" and "there was nothing to touch" two
distinguishable outcomes instead of both quietly producing no evidence.

**Opportunity provenance survives mutable world state (second review
correction).** The first cut of `build_opportunities` read *current*
`WorldState` component snapshots (`get_component`) — sufficient for "what is
available right now", but not, by itself, a defensible scoring record, since
nothing stops the world changing after an opportunity was presented (a
message deleted, an approval request resolved, an incident later recovered).
It now walks `session.world.mutations()` — the world's own append-only,
immutable audit log, already persisted and already restored byte-for-byte on
every resume — and captures each opportunity at the *first* mutation that
establishes it, using that mutation's own `sim_time_ms` (stamped when it
actually happened). Every later mutation to the same mail/request/incident
row (deleted, resolved, recovered) is never consulted again for that
opportunity. No new namespace, no separate log to keep in sync, and no risk
to the existing "one big time-step and many small ones reach the same world"
determinism guarantee — an earlier version of this fix that persisted a
parallel log via `mutate_world` on every save broke exactly that guarantee
(`tests/test_rewindsec2_training_engine.py
::test_one_long_advance_and_many_short_ones_agree`) and was replaced with
this design instead. `tests/test_rewindsec2_scoring_opportunities.py`'s
"opportunity provenance survives mutable state" section proves this directly:
a resolved MFA prompt, a deleted phishing mail, a recovered incident, and a
resume all leave the opportunity's id, time, dimensions and source
byte-identical to what they were the moment it was first presented.

**Containment and recovery are separate opportunities, not one decision's two
tags.** `d-ransom-isolate`/`d-ransom-continue` were originally tagged with
both `incident_response` and `recovery_quality` — meaning isolating alone
could earn a high Recovery Quality score with nothing ever actually
restored. Both decisions are now tagged `incident_response` only; a
`recovery` opportunity is a separate `Opportunity` that exists only once
containment has genuinely happened (mirroring `service._restore`'s own gate)
and is resolved only by the distinct `d-ransom-recover` decision. Recovery
Quality's applicability predicate (`rubric._recovery_opportunity_ever_existed`)
now reads the incident's `contained` flag directly, not merely whether an
incident occurred — an incident that is opened but never contained leaves
Recovery Quality legitimately N/A (no recovery opportunity ever existed) and
blames the correct dimension, Incident Response, instead.

**Content breadth: live, multi-family, and no longer exhausted in ~5 minutes
(second review correction).** The first correction pass added exactly one
live background candidate and left every threat family at its original
one-shot surface — the review correctly rejected this as "not Batch 5's job
deferred, Batch 4's job undone." This pass adds a genuinely new, independently
scored, live training candidate to **every** named family:

* **Phishing** — `cand-phish-benefits-lure` delivers `m-benefits-verify`, a
  benefits/HR-themed credential-harvest lure with its own decision quad
  (`d-phish2-credentials/-report/-verify/-delete`), own hostile sign-in page
  (`benefits-northbridge.example/portal/verify`), and own verification
  contact (`dir-sofia-lindqvist`, an existing but previously
  verification-inert Directory entry). Converges on the same generic
  `chain-credentials`/`chain-reported-hostile` consequence model the payroll
  lure already uses — one safe synthetic account-compromise outcome, not two.
* **BEC** — `cand-bec2-account-change` delivers `m-meridian-amend`, a second
  vendor relationship (Meridian Print Services, previously an unused
  Directory entry) with its own decision quad (`d-bec2-*`), own payments page
  (`.../finance/payments-meridian`), and own consequence chain
  (`chain-payment-meridian`, cloned from `chain-payment` with Meridian's own
  invoice/amount/account text so a released Meridian payment is never
  described using Calderwood's numbers).
* **Ransomware** — `cand-ransom-audit-checklist` delivers `m-audit-checklist`,
  a compliance-audit pretext with its own decision pair (`d-ransom2-open/
  -report`) that converges on the *same* `chain-file-incident`/
  `chain-uncontained`/`inc-files` incident the rate-card lure uses — per the
  review's own instruction, "all still converge on the same safe synthetic
  consequence model," not a second parallel incident economy.
* **MFA** — no new candidate was needed: Batch 3 already ships
  `cand-mfa-after-compromise` (`max_occurrences=2`, its own cooldown), and
  since each raised approval request is its own `NS_AUTH_REQUESTS` row, the
  Batch 4 opportunity model (above) already tracks each occurrence as an
  independent `prompt:<request_id>` opportunity. **Correction (occurrence-
  scoped decisions, below): the earlier limitation that `d-mfa-approve-
  hostile`/`d-mfa-deny-hostile` were recorded globally-once no longer holds.**
  A second raised prompt now records its own, independently classified
  decision, scoped by the request id that already distinguishes it as its own
  opportunity.
* **Background** — `cand-bg-standup-notes` delivers `m-standup-notes`, the
  second previously-unwired archetype (`arche-mail-ordinary-team-update`),
  alongside the first correction's `cand-bg-facilities-followup`.

Generalized, not redesigned: the decision-dispatch tables `_REPORT_DECISION`,
`_REPLY_DECISION`, `_VERIFY_BY_CONTACT`, `_DELETE_DECISION`, and two
previously-hardcoded single-id checks in `_browser_sign_in` and `_files_open`
(now `_CREDENTIAL_DECISION_BY_SIGNIN`/`_RANSOM_OPEN_DECISION`) were widened
from one hardcoded id to a small lookup table with the original id as the
only entry that mattered before — provably byte-identical behavior for the
original three lures (`tests/test_rewindsec2_content_breadth.py
::test_opening_the_original_rate_card_still_resolves_its_own_decision`), and
now a second entry for the new one. No existing eligibility, weighting or RNG
stream logic in `rewindsec/training/` changed.

`tests/test_rewindsec2_content_long_horizon.py` is the acceptance test the
review specified directly: over a 30-minute simulated horizon (with no
forcing), a Mixed session sees at least 8 distinct delivered messages
spanning at least two hostile families and at least one background surface;
a Phishing-focused session sees both phishing lures; a BEC-focused session
reaches the second vendor once its thread is read; a Ransomware-focused
session sees both lures; and an MFA-focused session's raised-request count
stays bounded by the authored occurrence caps (≤ 3), never unbounded.

The remaining six mail/MFA archetypes in `rewindsec/content/archetypes.py`
stay implemented, provenance-backed and unit-tested for deterministic
generation but not yet wired into further live candidates — turning every
one of them into its own independently-scored candidate (new decision ids,
new evidence-source entries, new eligibility/cooldown tuning, in some cases a
new consequence chain) is real, ongoing content-authoring work, not an
architectural gap; see Known Limitations for what is explicitly left.

**Document viewer.** A `SyntheticDocument` is plain server-owned structured
data (title, kind, ordered blocks from a five-member closed vocabulary) with
every leaf string already rejected by the sanitizer if it looked like markup.
Its content fact follows the same available/observed discipline as every
other inspection-only fact: introduced (available) when the file is seeded or
downloaded, observed only once `files.open` succeeds and the file is not
`unavailable`. The ransomware lure attachment (`m-rate-card`) is deliberately
left unbound — opening it is still the consequential trigger for
`d-ransom-open`, and the viewer never fabricates a document body standing in
for it. Mail attachment downloads and Browser resource downloads both
materialise through the one shared `worldops.add_downloaded_file`, so both
share the same document binding and the same locked filename-collision
resolver from Batch 2 (`report.pdf`, `report (1).pdf`, …) unchanged. The
front end (`static/prototype/workstation.js`) renders every block with the
same `esc()`-escaping string-building style the Files panel already used for
its metadata and preview text — no `innerHTML` of raw document text, no
iframe/object/embed, no external resource, no parser.

**Recovery vs. containment, and the exact factual mutation.**
`d-ransom-isolate` (Batch 3) remains containment, and — as of the review
correction above — contributes only `incident_response` evidence, never
`recovery_quality`. This batch's `d-ransom-recover` is a distinct, later,
optional decision. `service._restore` refuses to run (returns a notice, no
mutation, no decision) unless `world.get(NS_INCIDENTS, "inc-files")
["contained"]` is true, and is idempotent (a second call, once
`["recovered"]` is already true, is also a no-op notice). On success it:

1. Walks every `NS_FILES` row; for each with `state == "unavailable"` and not
   `deleted`, calls `worldops.set_file_state(session, file_id, "normal",
   note="")`. That function's own mutation sets, on the row: `state`:
   `"unavailable"` → `"normal"`; `note`: whatever the ransomware chain step
   wrote → `""`; `display_name`: recomputed from the row's own immutable
   `name` field (never from the locked `display_name`), which is what
   silently drops the `.demo_locked` suffix the same function added when the
   file first became unavailable — nothing strips a suffix by string
   surgery, the display name is simply rederived from the untouched original
   each time. Each such write is one `WorldMutation`, causally linked
   (`cause_event_id`) to a `"file.state_changed"` event.
2. Calls `worldops.set_incident_recovered(session, "inc-files")`, which
   merges `recovered: True` into the incident row *alongside* — the merge is
   `dict(current, recovered=True)` — its existing `contained`, `incident_id`,
   `title` and `note` fields, none of which are touched.
3. Records the `LearnerAction` (already recorded by the caller before
   dispatch, per every action) and calls `service._decide(session,
   "d-ransom-recover", learner_action, "Service Desk", mode_flags)`, which
   writes one `NS_DECISIONS` row (`decision_id`, `action_id`, `at_ms`) —
   the association between the recovery `LearnerAction` and the incident is
   this decision row's own `action_id` field, not a separate link.

Nothing here touches `session.incidents.consequences()`, the incident's
`incident_id`, or any earlier chain step's record —
`tests/test_rewindsec2_workstation_recovery
::test_restore_does_not_close_or_delete_the_incident` asserts the
consequence count and incident id are byte-identical before and after.
Recovery Quality evidence comes only from this factual opportunity/decision
pair, never from the `recovered` flag being read directly by the rubric.

**Active-session secrecy.** Nothing under this batch's code is reachable from
`learner_snapshot`: `rewindsec/scoring/` is never imported by
`workstation/projection.py`, and the `scoring` `WorldState` namespace is not
named in its allowlist. `tests/test_rewindsec2_scoring_leakage.py` walks the
whole active-session document (including an Assessment attempt mid-chain) and
asserts no scoring field of any kind is present, then separately asserts the
completed-session debrief projection carries only the six permitted fields
per dimension.

Rules for anything added here:

* **Pure scoring.** Nothing under `rewindsec/scoring/` may import Flask,
  SQLAlchemy, or any UI-facing module. It depends on domain types and on the
  authored decision/evidence vocabulary in `workstation/content/`
  (deliberately treated as stable "training metadata" for this purpose);
  nothing under `rewindsec/training/` depends on it.
* **Offline, deterministic content pipeline.** Nothing under
  `rewindsec/content/` makes a network call, calls an LLM, or reads a real
  external dataset. Every id is SHA-256-derived from stable material, never
  `hash()`. `rewindsec/content/` never imports `rewindsec/workstation/`; the
  binding direction is one-way (`workstation/content/documents.py` imports
  from `rewindsec/content/`, not the reverse).
* **Fail-closed sanitization.** An unreviewed or unsanitized source can never
  reach generation (`ProvenanceRecord.may_generate`); an unsafe string is
  rejected outright by `rewindsec/content/sanitize.py`, never silently
  cleaned.
* **Scoring never leaks mid-attempt.** No dimension score, evidence weight,
  opportunity class, or expected action reaches `learner_snapshot`, in any
  mode, at any point before the session completes.
* **Finalize once.** A completed session's persisted result never changes
  because the rubric code on disk later changes, and ending an
  already-completed session never recomputes or duplicates it.

Tests added: `tests/test_rewindsec2_scoring_evaluator.py` (all six dimensions,
N/A semantics, spam/dedup resistance, causal separation of a bad decision from
a good recovery, determinism, score bounds — updated for the opportunity-model
correction: containment alone no longer earns Recovery Quality, an
uncontained incident is negative Incident Response and N/A Recovery Quality,
not the reverse), `tests/test_rewindsec2_scoring_opportunities.py` (review
correction: ignored-but-presented hostile MFA/containment/recovery stay
applicable and score poorly rather than going N/A or neutral; an absent
recovery opportunity is legitimately N/A; unrelated actions — viewing, not
calling, a Directory record — earn no credit),
`tests/test_rewindsec2_scoring_leakage.py` (active-session and Assessment
secrecy, the permitted debrief projection, finalize idempotency, the legacy
projection), `tests/test_rewindsec2_content_pipeline.py` (adversarial
sanitizer inputs, provenance/review gating, deterministic id derivation
independent of `hash()`, stream-independence, catalogue safety),
`tests/test_rewindsec2_content_runtime_wiring.py` (review correction: the new
live candidate delivers real mail with a deterministic subject variant, its
attachment resolves to a pipeline-generated document, the subject variant is
stable across a resume, and content-variation draws never perturb
threat-selection/timing/consequence streams),
`tests/test_rewindsec2_workstation_documents.py` (available-vs-observed for
document content, safe rendering, Mail/Browser download integration, filename
collisions, the ransomware-unavailable state),
`tests/test_rewindsec2_workstation_recovery.py` (prerequisites, idempotency,
no rewind of the incident/causal graph, the resulting Recovery Quality score,
and — added for the review correction — containment/recovery each surviving
an independent save/resume boundary), `tests/test_rewindsec2_content_breadth
.py` (second review correction: each new phishing/BEC/ransomware surface is
live in the training catalogue, independently scored, cannot be resolved by
acting on a different surface, and the generalized decision-dispatch tables
leave the three original lures' own decisions byte-identical), and
`tests/test_rewindsec2_content_long_horizon.py` (the review's own long-horizon
acceptance test: meaningfully varied delivered content over 30 simulated
minutes, at least two hostile families in one Mixed session, both lures
reachable in a family-focused session, and MFA request counts staying
bounded by the authored occurrence caps). Existing suites that asserted the
pre-Batch-4 contract (`"recovered" not in entry`, the placeholder
`{"engine": "none"}` debrief block, the Batch 2 "no document viewer" behaviour
on a file this batch now binds one to, and an exact-equality world-state
comparison across `end_session`) were replaced with stronger assertions of
the Batch 4 contract, not relaxed.

**Explicitly out of scope, and still fixture-backed or absent:** trainer
attempt records, students, groups, assessments and assignment provenance
(Batch 5); Docker-backed technical ransomware state (Batch 6). Scoring
integration with Trainer records is deliberately not implemented — a
completed session's persisted `ScoringResult` is the artifact Batch 5 will
associate with a Student/Assessment/Attempt, not something this batch reaches
into the (still fixture-backed) trainer console to display. **Content
breadth remains Batch 4's responsibility, not Batch 5's**, and is left
genuinely incomplete in two specific, narrow ways rather than deferred
wholesale: (1) six of the nine authored mail/MFA archetypes are not yet
wired into their own live candidate — each remaining one is a real
content-authoring task (decision quad, evidence-source entries, eligibility
tuning, in some cases a new consequence chain), not an architecture gap, and
the pattern this batch established for the three it did wire is the template
for finishing the rest. (2) is resolved — see "Occurrence-scoped decision and
evidence provenance for recurring opportunities" below: MFA's second-
occurrence decisions are no longer recorded globally-once, neither is a
credential submission through a lure's second, generated occurrence, and —
see "Occurrence-scoped BEC payment authorization" below — neither is a
payment released against a recurring BEC occurrence's own release request.
Every recurring family's consequential outcome is occurrence-scoped; none of
it is deferred to Batch 5 or Batch 6.

**Live threat content now uses the deterministic runtime content pipeline for
bounded recurring variation (third review correction).** The second
correction (above) gave every threat family a genuinely new live candidate,
but each one was still a single authored, one-shot surface — the pipeline
built in this batch (`rewindsec.content.generate.choose_variant`/
`derive_content_id`) had exactly one production consumer
(`cand-bg-facilities-followup`'s subject-line variant) and the mail/MFA
archetype tables remained reserved, unconsumed surface area. This correction
wires the pipeline into an actual *recurring* runtime surface for one live
candidate in each of phishing, BEC and ransomware, plus the MFA family's
already-recurring candidate, via the new
`rewindsec.training.recurrence` module:

* **Recurring candidates and caps** — `cand-phish-benefits-lure`,
  `cand-bec2-account-change` and `cand-ransom-audit-checklist` each gained
  `max_occurrences=2` (from 1) and a `cooldown_ms`; `cand-mfa-after-compromise`
  already had `max_occurrences=2`. Candidate selection is unchanged: the
  Batch 3 engine still draws which candidate fires, and when, from
  `threat_selection`/`background` alone: `rewindsec.training.recurrence` runs
  only *after* a candidate is selected, and only reads the candidate's own
  persisted occurrence count (never randomness) to decide which physical mail
  id or notification wording to use.
* **Occurrence 0 unchanged, occurrence 1 generated** — a recurring
  candidate's first occurrence is exactly its original authored message
  (unchanged decision quad, unchanged opportunity). Its second occurrence
  targets a second, distinct, pre-seeded mail row (`m-benefits-verify-o2`,
  `m-meridian-amend-o2`, `m-audit-checklist-o2`) with its own small decision
  pair/triple (`d-phish3-*`, `d-bec3-*`, `d-ransom3-*`) and its own
  opportunity in `rewindsec.scoring.opportunities`, whose subject, sender
  persona and opening line are chosen deterministically at delivery time from
  `session.rng.stream(STREAM_CONTENT_VARIATION)` via
  `generate.choose_variant`, with a stable id from `generate.derive_content_id
  (session.session_id, candidate_id, occurrence)` — never `hash()`. MFA has no
  second physical mail id — the same authored prompt is legitimately raised
  twice — so its recurrence instead varies the arrival notification's wording
  and the authenticator's displayed application label
  (`worldops.create_auth_request`'s new `app_override`/`notification_body`
  parameters); the inspectable device/location/network detail behind
  "Details" is untouched, exactly as authored.
* **Underlying facts never vary** — the BEC second occurrence keeps the exact
  vendor, bank, sort code and account number the first occurrence already
  established (this is a second message about the same fraud, not a second
  fabricated vendor); the ransomware second occurrence converges on the same
  synthetic file-availability consequence model (`chain-file-incident`,
  reused, not a second incident); the phishing second occurrence's link
  targets the byte-identical look-alike portal the first occurrence already
  uses, and a credential submission through either one still records the
  original `d-phish2-credentials` — there is one lure identity here, followed
  up on, not two.
* **Persistence and RNG isolation** — the generated overrides
  (`subject_override`, `from_name_override`, `opening_line_override`,
  `content_variation_id`, and MFA's `app_override`/`content_variation_id`) are
  written through the existing `worldops.set_mail_field`/
  `worldops.create_auth_request` world mutations, so they are part of the
  session's ordinary persisted snapshot: nothing is regenerated from the
  current RNG position on a GET, a resume replays the exact same stored
  override values, and the one extra `content_variation` draw a second
  occurrence makes cannot perturb `threat_selection`, `timing`, `background`
  or `consequence` — each is its own named stream, exactly as the first
  correction's subject-variant mechanism already proved.
* **Scoped narrower than a full decision quad, deliberately** — each
  generated second occurrence carries report/delete (phishing), report/reply
  (BEC) or report/open (ransomware) as its own tracked opportunity, not the
  full four-decision shape the first occurrence has. **Correction (occurrence-
  scoped decisions, below): phishing's "credentials" outcome, reached through
  the same reused portal both occurrences link to, is now tracked as part of
  the second occurrence's own opportunity too** — `d-phish2-credentials` is
  the same semantic decision class either occurrence resolves (there is one
  lure identity here, not two), but which occurrence a submission counts
  against is now resolved from provenance (which mail's link the learner
  actually followed), not left untracked. **Correction (occurrence-scoped BEC
  payment authorization, below): BEC's `authorize` outcome is now
  occurrence-scoped too.** The earlier limitation — that `d-bec2-authorize`
  remained a single shared decision point because there was only one Meridian
  payments page — no longer holds: recurring BEC payment decisions are
  occurrence-scoped exactly like the other recurring families, and a second
  presented BEC occurrence produces its own consequential payment decision,
  its own world mutation and its own consequence provenance.

New file: `rewindsec/training/recurrence.py`. Changed: the three families'
own candidate modules (recurrence gating), `rewindsec/training/delivery.py`
(occurrence resolution), `rewindsec/workstation/worldops.py`
(`create_auth_request`'s new optional parameters), `rewindsec/workstation
/projection.py` (`_message_view`/`_authenticator_view` prefer the new
overrides, mirroring the existing `subject_override` pattern),
`rewindsec/workstation/content/world.py` (the three new mail rows),
`rewindsec/workstation/content/scenario.py` (the six new decisions),
`rewindsec/workstation/content/index.py` (`_EVIDENCE_SOURCE` entries),
`rewindsec/workstation/service.py` (report/delete/reply/ransom-open decision
tables), and `rewindsec/scoring/opportunities.py` (`_MAIL_RESOLUTIONS`
entries — new, non-overlapping decision ids, so no opportunity can ever be
double-resolved by the same recorded decision). New tests:
`tests/test_rewindsec2_content_recurrence.py`.

**Occurrence-scoped decision and evidence provenance for recurring
opportunities (fourth review correction).** The third correction (above) gave
phishing, BEC and ransomware a second, generated occurrence each with its own
opportunity, but two specific decision classes stayed unsafe against it: MFA's
hostile approve/deny decisions were recorded globally-once per session
(`consequences.already_decided` keyed purely by decision id), so a second
raised prompt could never be independently resolved once the first had been
answered; and the two occurrences of the benefits phishing lure share a
byte-identical look-alike portal, so a credential submission through *either*
one recorded the same global decision, meaning the second occurrence's own
opportunity could only ever show "ignored", never a genuine credential
outcome. A decision from occurrence 1 could therefore, in effect, be read as
resolving occurrence 2.

`rewindsec.workstation.consequences.record_decision`/`already_decided` now
take an optional `occurrence_key`. Storage is unchanged for every decision
this architecture has always treated as one-shot for the whole session
(`occurrence_key=None` keeps the bare decision id as the `NS_DECISIONS` row
key, byte-identical to before); a caller that passes an `occurrence_key` gets
a distinct row per occurrence (`"<decision_id>@<occurrence_key>"`), with the
row itself carrying both the semantic `decision_class` and the
`occurrence_key` so every reader can recover "what kind of decision" and
"which occurrence" independent of how the row happens to be keyed. Two call
sites now pass one: `service._auth_resolve` scopes every MFA
approve/deny decision by the resolved request's own id (already the
opportunity's own `request_id`); `service._browser_sign_in` scopes a
credential decision by whichever mail's link the learner actually followed to
reach the sign-in page (tracked by `_mail_open_link` as that page's current
referrer). A page reached with no recorded referrer — typed directly, or an
in-flight session predating this correction — falls back to the original
unscoped, one-shot-per-session behaviour, so no existing one-shot decision's
semantics changed. Consequence-chain bookkeeping
(`NS_CONSEQUENCE_MAP`, causal-parent lookups) is keyed by the same
occurrence-scoped record id, so two occurrences of the same recurring chain
(both open the same `inc-account` incident, reused rather than reopened)
can never have their steps' causal-parent links cross-contaminate.

`rewindsec.scoring.opportunities.Opportunity` gained an `occurrence_key`
field — the mail id for a mail opportunity, the request id for a prompt,
`None` for the two opportunity types that never recur in a session
(containment, recovery). `rewindsec.scoring.evidence.build_evidence` matches
a resolving decision against the *specific* `(decision_id, occurrence_key)`
pair an opportunity presents, falling back to the legacy unscoped pair only
when no occurrence-scoped record exists (and consuming that fallback match at
most once, so one unscoped record can never "resolve" more than one
occurrence). `_decision_evidence`'s emitted evidence is now keyed by the same
occurrence-scoped record id too (`decision:<record_id>`, not
`decision:<decision_id>`) — the fix that closes the last gap: without it, two
occurrences resolving the same decision *class* would still merge their
Tier 1 evidence into one colliding id and one colliding `opportunity_id`,
even after the resolution-matching step above told them apart correctly.
`m-benefits-verify-o2`'s `_MAIL_RESOLUTIONS` entry now includes
`d-phish2-credentials`, since a credential submission through the second
occurrence is now independently trackable.

`rewindsec/workstation/debrief.py`'s decision rows changed shape to match:
`id` is now the row's own (occurrence-scoped) storage key, and a new
`decisionId` field carries the semantic class every occurrence of a decision
shares — everything that reads a decision's authored meaning (label, class,
family, dimensions, evidence model, its causal chain) keys off `decisionId`,
never `id`. `static/prototype/results.js`'s browser-side demonstration
scoring (explicitly not real RewindSec 2.0 scoring; see the Batch 2 note
above) was updated to match on `decisionId` where it falls back to `id` for
fixture data that carries no `decisionId` at all, so its exact-match checks
(`d-mfa-deny-legit`, `-report` suffix matching) do not silently stop firing
for a real, occurrence-scoped session.

Changed: `rewindsec/workstation/consequences.py` (`_record_id`, the
`occurrence_key` parameter, occurrence-scoped `NS_CONSEQUENCE_MAP` keys),
`rewindsec/workstation/service.py` (`_decide`'s `occurrence_key` parameter,
`_auth_resolve`, `_browser_sign_in`, `_mail_open_link`'s new referrer
tracking), `rewindsec/scoring/opportunities.py` (`Opportunity.occurrence_key`,
the `m-benefits-verify-o2` resolution entry), `rewindsec/scoring/evidence.py`
(`_decision_records`, `_decision_evidence`, the occurrence-aware resolution
match in `build_evidence`), `rewindsec/workstation/debrief.py` (`_decisions`,
`_chains`), `static/prototype/results.js`. New tests:
`tests/test_rewindsec2_scoring_occurrence_provenance.py`. Updated:
`tests/test_rewindsec2_network_isolation.py`,
`tests/test_rewindsec2_training_families.py`,
`tests/test_rewindsec2_workstation_recovery.py` (their shared `decisions()`
helper now reads a row's `decision_class` rather than assuming the storage
key is the semantic class), `tests/test_rewindsec2_workstation_resume.py`
(one assertion now reads `decisionId`).

---

**Occurrence-scoped BEC payment authorization (fifth review correction).**
The fourth correction (above) scoped MFA approvals and phishing credential
submissions to the occurrence that produced them, but left BEC's most
consequential outcome — releasing a supplier payment to an account that
arrived by mail — as a single shared decision point per surface. The Meridian
relationship is the one BEC surface that recurs
(`cand-bec2-account-change`, `max_occurrences=2`), and its second occurrence
had report and reply decisions of its own but no authorize path at all: one
payments page, one release button, one `d-bec2-authorize` the whole session
could record exactly once. A learner who released the payment on the first
occurrence had no consequential payment decision left to make on the second,
which is not a recurring opportunity.

A payments page is now modelled as a **release queue**, and each entry in it
is a *payment context*: a stable id (`pay-mp-7734-r1`/`-r2`), its own queue
reference (`RQ-4482`/`RQ-4519`), the presented BEC occurrence it belongs to,
and the authored decision it records. Both Meridian entries settle the *same*
invoice of record — MP-7734, Meridian Print Services, £612.40, Bramwell Trust
ending 7729 — and both authorize through the *same* semantic decision class,
`d-bec2-authorize`: releasing a supplier payment to an account that arrived by
mail is the same mistake the second time, and the second occurrence is a
follow-up chase on one fraud, not a second fabricated supplier or a second
invented invoice (the same rule the recurrence correction already applies to
`rewindsec/training/recurrence.py`'s variant tables). What is
occurrence-specific is the *release request*, and it is the release request
that scopes everything downstream. There is no second Browser application and
no second payments subsystem: one authored table, one generic handler.

* **Decision scoping** — `browser.release_payment` takes an optional
  `context` parameter naming the queue entry being settled (the id the
  projection handed the client — never an invoice, an occurrence or a decision
  id). `service._resolve_payment_context` resolves the `(url, context_id)`
  pair against the authored site map, refusing a context that belongs to a
  different payments page, and passes the context's `occurrence_key` to
  `_decide`, so the recorded row is
  `d-bec2-authorize@m-meridian-amend-o2` rather than the bare class. A client
  naming no context settles the page's first *outstanding* entry — what every
  single-entry payments page has always done, and never an entry already
  settled, so an unqualified action about the second occurrence can never fall
  back onto the first occurrence's resolved one.
* **Only what has actually been raised** — the second entry carries
  `requires_mail: m-meridian-amend-o2` and does not exist, in the projection
  or in the handler, until that occurrence's message has actually been
  delivered. A learner cannot settle a payment nothing in their day raised,
  and the queue never announces a message the mailbox has not.
* **World mutations and causal provenance** — release state moved from a
  single page-wide `payment_released` flag to one `payment_released:<context>`
  row per queue entry (`worldops.payment_release_key`), so two occurrences
  produce two distinct payment mutations. Each authorization records its own
  decision event, schedules its own `chain-payment-meridian` run, and writes
  its own occurrence-scoped `NS_CONSEQUENCE_MAP` rows — the causal chain is
  candidate/archetype → occurrence id → mail and payment context → scoring
  opportunity → learner action → semantic decision class → occurrence key →
  payment world mutation → consequence. Both runs open the same
  `inc-payment-meridian` incident (reused, not reopened: one supplier, one
  invoice, one fraud) with distinct consequence records under it, exactly as
  the fourth correction already established for recurring chains.
* **Idempotency** — a retried release of the same context mutates nothing and
  records nothing a second time, checked against that entry's own world row
  before any mutation, so a retry to the account of record is as inert as a
  retry to a changed one. A release of a *different* context is a valid
  independent decision even though it is the same semantic class about the
  same invoice. Stale-revision protection is untouched.
* **Scoring and evidence** — `m-meridian-amend-o2`'s `_MAIL_RESOLUTIONS` entry
  now includes `d-bec2-authorize`, so authorizing while resolving the second
  occurrence resolves the second occurrence's opportunity. The fourth
  correction's exact `(decision_id, occurrence_key)` matching is what keeps
  the two apart: `d-bec2-authorize@m-meridian-amend` can never resolve the
  second occurrence's opportunity, or vice versa, and each occurrence's
  evidence lands in its own `decision:<record_id>` bucket. The Calderwood
  surface is scoped the same way (`occurrence_key: m-invoice-amend`) even
  though it never recurs, so there is one code path rather than two.
* **No leakage** — a projected queue entry carries only `id`, `queue_ref`,
  `reference`, `supplier`, `amount`, `approved_by`, `account_of_record` and
  `released_account`. `authorize_decision`, `occurrence_key` and
  `requires_mail` stay server-side; the client sends back the context id and
  the server recovers the rest.

Changed: `rewindsec/workstation/content/world.py` (`payment_contexts` on both
payments pages), `rewindsec/workstation/content/index.py`
(`PAYMENT_CONTEXT_BY_ID`, `payment_contexts_for_page`,
`payment_context_on_page`), `rewindsec/workstation/actions.py` (the optional
`context` parameter), `rewindsec/workstation/worldops.py`
(`payment_release_key`, `available_payment_contexts`),
`rewindsec/workstation/service.py` (`_resolve_payment_context`, a rewritten
`_browser_release_payment`), `rewindsec/workstation/projection.py` (the
release-queue view), `rewindsec/scoring/opportunities.py` (the
`m-meridian-amend-o2` resolution entry), `static/prototype/workstation.js`
(per-entry rendering and per-entry account drafts). New tests:
`tests/test_rewindsec2_bec_occurrence_payments.py`.

---

### Batch 5: students, groups, assessments, assignments, attempts, trainer console

**Base commit:** `6f9919f` (*Add deterministic scoring, content pipeline, and
document viewer*). **Versions:** `rewindsec-assessment-definition/v1`,
`bounded-attempts/v1` (retry policy), `rewindsec-attempt-stamp/v1`,
`rewindsec-assessment-boundary/v2`,
`rewindsec-assessment-runtime-policy/v1`,
`rewindsec-self-directed-assessment-definition/v1`,
`rewindsec-scored-interaction/v1`, `rewindsec-trainer-metrics/v2`.

`rewindsec/management/` is the administrative half of RewindSec 2.0: who a
learner is, which groups they belong to, which assessments they hold and by
what route, and which attempts they have made. It **consumes** the simulation
and the Batch 4 scoring system and reimplements neither.

| Path | Role |
|---|---|
| `rewindsec/management/records.py` | The storage-independent records: `Student`, `StudentGroup`, `GroupMembership`, `Assessment`, `Assignment`, `Attempt`, `SessionOwnership`, `EnrollmentCode`. Identity is minimal - display name, optional organisational reference, optional cohort label, status - and `cohort` is presentational only, never a substitute for membership. |
| `rewindsec/management/ports.py` | The repository contract, in the same *port* style `rewindsec/persistence/ports.py` established for the session aggregate. |
| `rewindsec/persistence/management_adapter.py` | The one adapter: eight `rewindsec2_*` tables on their own MetaData, created with `checkfirst`. Additive - no Batch 1-4 table is altered and no stored session is rewritten. |
| `rewindsec/management/ids.py` | Identifier minting. `secrets` or SHA-256 derivation; **never** a simulation RNG stream and **never** `hash()`. |
| `rewindsec/management/assignments.py` | Effective-assignment resolution and duplicate-source lookup, as pure functions. An assignment is a *route*, and routes are never merged. |
| `rewindsec/management/progress.py` | Assessment progress, counted in **scored interactions** - resolved opportunities from `rewindsec.scoring.evidence.resolve_opportunities`. Never events, messages, elapsed time or scheduler ticks. |
| `rewindsec/management/assessment_policy.py` | The versioned feasibility rule derived from the live candidate catalogue and scoring opportunity registry, plus stable system-owned self-directed definition ids/defaults. |
| `rewindsec/management/session_link.py` | The attempt stamp a TrainingSession carries, and the assessment completion boundary, both in its own world namespace - the same pattern `training/state.py` and `scoring/state.py` already use, so no session state version is bumped and neither can reach a learner projection. |
| `rewindsec/management/analytics.py` | Versioned, extensible trainer metrics derived from stored sessions, each stating its own denominator and each capable of an explicit *unavailable* state. |
| `rewindsec/management/service.py` | The application service: the only thing that changes a record. |
| `rewindsec/management/projection.py` | Trainer view models. Reached only through an authorized route. |
| `rewindsec/prototype/trainer_api.py` | The trainer HTTP adapter. Every route is wrapped in the application's real instructor authentication by the registration helper - never by a URL prefix - and the blueprint fails closed when no guard is supplied. |

**Scored interactions, and the interpretation chosen.** An assessment's
`required_interactions` is compared against the number of Batch 4
`Opportunity` records that a recorded decision actually *resolved*, matched by
the exact `(decision_id, occurrence_key)` rule Batch 4 already implements.
Where Batch 4 left room, the **narrow** reading was taken: an ignored
opportunity is presented but not completed. The wider reading - counting an
ignored opportunity as "interacted with, badly" - was rejected, because an
assessment a learner completes by ignoring everything is not an assessment.
Ignoring still costs the learner their score, exactly as Batch 4 already
scores it; it does not buy them progress. Benign and context traffic produces
no opportunity at all and therefore cannot move progress; investigation
records no decision and therefore completes nothing; an idempotent repeat of
a decision resolves the same occurrence and cannot inflate the count; and two
occurrences of a recurring surface remain two independently countable
interactions, which is the behaviour Batch 4 already models.

**Batch 4 is consumed, not replaced.** A completed attempt's result *is* the
session's own immutable, finalized `ScoringResult`, copied verbatim onto the
attempt row under the `scoring`/`rubric`/`evidence-model` versions that
produced it. There is no second "trainer score" anywhere, and nothing in this
batch recomputes a dimension. `resolve_opportunities` is the one implementation
of "did a decision that resolves this occurrence get recorded" for progress
and evidence. For an Assessment with a v2 completion boundary it also reads
the boundary's exact admitted pairs as the complete scoreable opportunity
set; an unadmitted opportunity contributes neither a later decision nor an
ignored-opportunity penalty. Its delivery and any later action remain in
immutable history. The existing evaluator, dimensions, rubric and weights are
unchanged and finalize the bounded session once through the existing
`scoring.state.finalize` path.

**Determinism.** The attempt stamp is a single world value written through
`mutate_world`. It draws nothing from any RNG stream, schedules nothing and
advances no clock, and `build_opportunities` never looks at its namespace.
The same seed and the same learner inputs produce a byte-identical RNG state,
clock, scheduler and event log with or without it. Administrative timestamps
use ordinary application time; no simulation decision reads a clock of any
kind, and `rewindsec/management/` imports `datetime` in exactly one module
(`service.py`) and `random` in none.


#### Batch 5 corrections

Five defects in the first cut of this batch, and what replaced each.

**1. Assessment mode without an Attempt.** Self-directed Assessment is one of
the three learner-selectable modes. The generic start route delegates that
choice to `ManagementService.start_self_directed_attempt`; it never calls the
bare session constructor for Assessment. The service resolves/persists one
stable system-owned definition per focus, versioned
`rewindsec-self-directed-assessment-definition/v1`, writes an Attempt with
`assignment_source = "self_directed"` and null assignment/group ids, and only
then creates and stamps its TrainingSession. These system definitions do not
appear in the trainer-created assessment list and cannot be assigned or edited
through trainer operations. Trainer-assigned starts continue through
`ManagementService.start_attempt` and retain their real direct/group snapshot.
`WorkstationService.start_session` still refuses Assessment mode without the
server-side Attempt assertion. The invariant remains `Assessment mode =>
Assessment Attempt => TrainingSession`, including the self-directed path.

**2. `required_interactions` was only a progress bar.** A learner could start
an assessment, resolve one interaction, press End Training and be recorded as
having *completed* it. Completion is now a rule: an attempt is `completed`
only if the bound session ended `completed` **and** its resolved
scored-interaction count met the definition's requirement. Ending early is
recorded as `abandoned` with `termination_reason = "requirement_unmet"`,
distinct from `session_abandoned` and `session_missing`, and it still counts
against the retry limit. The session's own finalized Batch 4 `ScoringResult`
is stored verbatim either way: the learner's decisions keep their
consequences and their score, and what ending early costs them is a *valid
assessment*, not the factual record.

The upper bound is exact. Once the requirement is satisfied, the server writes
`rewindsec-assessment-boundary/v2` with exactly N admitted
`(opportunity_id, decision_record_id)` rows plus the simulation time, revision
and closing learner action. `resolve_opportunities` admits only those pairs to
Assessment progress, and `build_evidence` treats them as the complete
scoreable opportunity set. An already-visible N+1 opportunity therefore
contributes neither a later decision nor an ignored-opportunity penalty to the
result. `training.engine.evaluate` also declines new primary activity. The
session does not end at the cutoff: the clock keeps running,
already-scheduled factual consequences still fire, and later actions remain
in immutable history. Batch 4 finalizes once against that persisted boundary
and its result is still the one authoritative score.

**Feasibility.** `rewindsec-assessment-runtime-policy/v1` derives the maximum
required count from finite, directly scoreable primary candidates in the
training catalogue and opportunity registry. Current capacities are Phishing
3, Ransomware 3, MFA 5, BEC 3 and Mixed 14. Conditional containment/recovery
opportunities are not relied upon for completion. The trainer API rejects a
larger value and the UI publishes/enforces the focus-specific maximum; it
never silently clamps. The self-directed definition uses the feasible default
of 3.

**3. No learner-to-Student binding.** A trainer-created `Student` was given a
minted `learner_ref` no browser would ever present, so trainer-created
students, memberships and assignments were not reachable end-to-end and the
smoke tests seeded the learner cookie by hand. A trainer-created student is
now created **unbound** (`learner_ref is None`, which means exactly one
checkable thing: nobody has claimed them), and a trainer mints an
`EnrollmentCode` - a bounded, single-use, purpose-specific secret, separate
from the learner reference and shown once. A browser spends it at
`/api/enroll`, whose entire request is the code: no student id, no learner
reference, no attempt id and no session id, so there is no parameter through
which a learner could ask to be somebody else. The claim is one conditional
`UPDATE` matching only an unclaimed row, so of two browsers presenting the
same material the database picks one winner; the winner may re-present it
idempotently, and a second browser is refused. Unknown, spent and revoked
codes are refused identically, so the endpoint is not an oracle for which
codes or students exist. A browser already bound to a roster student cannot
swap onto another. An anonymous auto-provisioned record is *released* rather
than merged - ownership is established once and never moved, so earlier
anonymous history stays where it happened instead of being reattributed to a
named person. The persistent `learner_ref` is never rendered on any screen or
returned by any API.

**4. `scheduled` was treated as `open`.** The start rule accepted
`{open, scheduled}` on the grounds that this batch implements no scheduling
engine - an argument about what the server does *not* do, used to widen what a
learner *may* do. The approved trainer UI shows the two as different states.
Only `open` starts an attempt; `scheduled` is visible and assignable and
refuses; `draft` and `closed` refuse. Releasing a scheduled assessment is the
explicit act of setting it `open`. **No scheduling automation was invented.**

**5. A misleading false-positive metric.** `false_positive_reports` counted
"reported something genuine **or** disconnected with nothing to contain" over
every session analysed - two different operational behaviours under one label
that described only the first, so no reading of the percentage was true. It is
now two metrics with two denominators: `false_positive_reports` (sessions that
reported a genuine work request, over sessions that actually delivered a
genuine message the learner could have reported) and `unnecessary_isolation`
(sessions that disconnected the workstation with no incident open, over
sessions analysed - disconnecting is available in every session from the
moment it starts). Neither is inferred from the other, neither denominator is
fabricated, a zero denominator stays `available: false` with a stated reason,
and the metric set version moved to `rewindsec-trainer-metrics/v2` so a figure
recorded under the blended definition can never be silently compared with one
recorded under these. Neither metric is evidence about learning.

**Authorization.** The whole trainer surface - six pages and every API route -
is behind `security.require_instructor`, injected into the blueprint rather
than imported by it, and applied by the route-registration helper so an
unguarded route cannot be added by forgetting a decorator. A learner cookie
carries no instructor flag and reaches none of it. On the learner side,
ownership stays exactly what it was: the active session id lives only in the
signed cookie, no route accepts a session, student, learner or attempt
identifier, and every read goes through the server-side ownership check.

**Analytics discipline.** Every figure is computed from stored 2.0 sessions.
Each metric carries `rewindsec-trainer-metrics/v2`, its own definition, its
own explicit denominator, and - where the stored data cannot support it - an
`available: false` state that the console renders as a dash with a stated
reason. **No trainer figure in this batch is authored, illustrative, or
carried over from `trainer_fixtures.py`.** Those fixtures survive only for
standalone visual development; no production trainer route, template or
module reads them, and `tests/test_rewindsec2_trainer_data.py` holds that
statically. Every metric also carries an interpretation limit that travels
with the number: these are technical telemetry about authored simulations
under an authored rubric, and they are **not** measures of competence,
learning, retention or transfer.

**Legacy and unowned sessions.** A session stored before this batch has no
`rewindsec2_session_owners` row. It is reported as unowned rather than
attributed to anybody, its lifecycle columns are still listed, and a stored
snapshot this build cannot parse is shown as unreadable rather than as absent
or as somebody's result. No ownership is ever invented.

**Persistence:** eight new `rewindsec2_*` tables, created alongside the
application's own in `init_db()` with `checkfirst`. Verified additive: the
Batch 1-4 session, event and action tables keep every column and every row.
No v1 table is read, written or migrated. The correction added
`rewindsec2_enrollment_codes` and two nullable columns on
`rewindsec2_attempts` (`completed_interactions`, `termination_reason`);
nullable, so a row written before the completion rule existed reads back as
"never recorded" rather than as "the learner resolved none of them".

New tests: `tests/test_rewindsec2_management_persistence.py`,
`test_rewindsec2_management_assignments.py`,
`test_rewindsec2_management_attempts.py`,
`test_rewindsec2_management_authorization.py`,
`test_rewindsec2_trainer_data.py`, `test_rewindsec2_assessment_boundary.py`,
`test_rewindsec2_enrollment.py`, plus `tests/management_helpers.py`.
Updated: `tests/test_prototype_ui.py` - its trainer-route and
assignment-provenance tests now exercise the authorization gate and real
persisted records instead of fixture rows, and the minimal-identity property
it held of the fixture people is now also held of the `Student` record.

**Explicitly out of scope, and not started:** Docker-backed RewindSec 2.0
ransomware state (Batch 6). Nothing in this batch touches `docker/`, the
sandbox backends, or the v1 ransomware demo.

---

## 7. Quick reference

| Category | Verdict |
|---|---|
| Reusable infrastructure (§2) | Port or reuse freely. Carries no experimental claim. |
| v1 learner architecture (§3) | Frozen for reference. Replaced by 2.0, not edited to suit it. |
| v1 study artifacts (§4) | Frozen. Never extended or repointed for 2.0. |
| v1 evaluation harnesses and results (§5) | Frozen. Never re-run against 2.0 and reported as continuous. |
| RewindSec 2.0 (§6) | New names, new tables, new harness, framework-free deterministic core. |
| RewindSec 2.0 results screen | Timeline, decisions, consequence chains, evidence, and (Batch 4) the six dimension scores are all real, server-derived session facts for any session created since Batch 4. A session created before it gets an explicit legacy/unscored projection, never a retroactive score. |
| RewindSec 2.0 event selection (§6, Batch 3) | Deterministic authored scheduling policy, versioned `training-engine/v1`. No claim is made that it improves learning, retention, realism or difficulty calibration; those require human evidence. |
| RewindSec 2.0 scoring (§6, Batch 4) | Deterministic, versioned, authored rubric (`rewindsec-scoring/v1`). It is implementation policy, not a validated measure of competence, retention or transfer; those require human research data this system does not collect. |
| RewindSec 2.0 trainer records (§6, Batch 5) | Real persisted students, groups, many-to-many membership, assessments, assignment provenance and attempts. A completed attempt's result is the session's own finalized `ScoringResult`, stored under the versions that produced it - never a second, recomputed trainer score. |
| RewindSec 2.0 trainer analytics (§6, Batch 5) | Derived from stored 2.0 sessions, versioned `rewindsec-trainer-metrics/v2`, each with an explicit denominator and an honest unavailable state. Technical telemetry about authored simulations; **not** evidence about competence, learning, retention or transfer. Fixture numbers in `trainer_fixtures.py` are demonstration data only and are never presented as measurements. |

---

## 8. RewindSec 2.0 Batch 6 boundary (additive chronology)

Batch 6 starts from `e0ded68944d9e206631f5e99762dc52793a99736`. It does
not rewrite the v1 chronology, manifests or formal results described above.

The v2 technical ransomware boundary is `rewindsec/sandbox/` with target
`docker/rewindsec2-target/`. It takes a canonical projection of the four
server-owned ransomware file IDs only after the authoritative session write.
Its management key is a one-way digest of the opaque session ID and consumes no
simulation RNG. Docker failure is recorded in operational diagnostics, never in
the world, scheduler, Context Ledger, causal graph or score. Terminal cleanup
accepts only the derived key and the Docker adapter verifies exact v2 ownership
and session labels before removal.

This reuses containment *principles* from the historical `sandbox/` system but
imports none of its datasets, managers, scenario logic, route APIs, labels or
evaluation oracles. The historical `docker/sandbox-target/`, `sandbox/`,
`evaluation/formal_run.py`, `evaluation/rewindsec_formal_run.py`, their
specifications, `evaluation/results_manifest.json` and prior results remain v1.

The new harness is separately versioned under `evaluation/rewindsec2/` and
writes to `evaluation/results/rewindsec2/`. Its registry is
`evaluation/rewindsec2/evidence_registry.json`. A run declares repository
revision, dirtiness, source-tree fingerprint, environment, samples, failures,
skips and limitations. Dirty Batch 6 artifacts are engineering/pre-commit
evidence, not final-paper results. A later clean-final-commit run uses the same
methodology unchanged.

Default production wiring no longer mounts v1 training, learning, study,
resources or instructor-sandbox blueprints. They remain available only through
the explicit `REWINDSEC_ENABLE_LEGACY_V1_SURFACES=1` provenance/regression mode.
The 2.0 `/prototype/api/dev/*` controls are also disabled by default. None of
these routing decisions deletes or reinterprets historical source or data.

The final productization pass gives the same Batch 6 implementation clean public
browser routes (`/start`, `/workstation`, `/results`, `/trainer/...`) and
canonical `/api/...` traffic. Historical `/prototype/...` browser paths only
redirect, and exact old API paths remain compatibility aliases. Internal
`rewindsec/prototype/`, template and static directory names are intentionally
retained: they are implementation provenance, not product claims. Clipboard
integrity controls now load only in the active workstation; login, enrollment,
results and trainer administration retain normal browser clipboard behavior.

Batch 6 technical checks may support bounded claims about deterministic replay,
resume equality, authorization/misuse controls, session isolation, containment
configuration/runtime observations and measured machine-local latency. They do
not support human-effect, usability, realism, preference, competence, learning,
retention, transfer, superiority or psychometric claims.
