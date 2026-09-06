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

**What is still fixture-backed, deliberately:** the trainer console (Batch 5)
and the numeric scores on the results screen (Batch 4). The results page's
timeline, decisions, causal consequence tree and evidence counts are real and
come from the persisted session; its six dimension figures are an authored
browser-side demonstration, labelled as such on the screen, in the API
(`debrief.scoring.engine == "none"`) and here. **They are not RewindSec 2.0
scoring and must never be cited as a measurement.**

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

---

## 7. Quick reference

| Category | Verdict |
|---|---|
| Reusable infrastructure (§2) | Port or reuse freely. Carries no experimental claim. |
| v1 learner architecture (§3) | Frozen for reference. Replaced by 2.0, not edited to suit it. |
| v1 study artifacts (§4) | Frozen. Never extended or repointed for 2.0. |
| v1 evaluation harnesses and results (§5) | Frozen. Never re-run against 2.0 and reported as continuous. |
| RewindSec 2.0 (§6) | New names, new tables, new harness, framework-free deterministic core. |
| RewindSec 2.0 results screen | Timeline, decisions, consequence chains and evidence are real session facts. The six dimension scores are an authored demonstration until Batch 4. |
| RewindSec 2.0 event selection (§6, Batch 3) | Deterministic authored scheduling policy, versioned `training-engine/v1`. No claim is made that it improves learning, retention, realism or difficulty calibration; those require human evidence. |
