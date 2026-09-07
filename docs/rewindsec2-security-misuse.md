# RewindSec 2.0 security and misuse boundary

Version: `rewindsec2-security-boundary/v1`

RewindSec is browser-based cybersecurity training. It is not malware analysis,
an exploit laboratory, a phishing-delivery service, or a credential collector.

## Learner safety

The workstation exposes only server-authored synthetic mail, files, URLs,
credentials and workplace records. Browser destinations are a closed content
catalogue; URLs are inert training identifiers. Documents are structured,
sanitized presentation data rather than Office files opened by a native parser.
Learner input cannot select a host path, command, executable, container, mount,
network, seed, scheduler event, score, attempt owner, or another session.

The ransomware technical layer holds four allowlisted synthetic file IDs. An
impact is a deterministic rename plus replacement with a plainly labelled
locked marker. It performs no encryption, propagation, persistence, discovery,
recursion, code execution, binary handling, download, credential handling or
network operation. Recovery reconstructs the known synthetic baseline from the
persisted world; it does not decrypt anything.

## Authorization and secrecy

The learner's active session ID and opaque learner reference live in the signed
server session and are never accepted in learner request bodies, paths, query
strings or headers. Service-layer ownership checks return the same not-found
response for absent and foreign sessions. Enrollment codes are single-use and
bind only the server-minted browser reference. Assessment creation is forced
through a persistent Attempt. Active learner projections exclude scores,
dimension results, correctness, hostile/benign truth, decision/opportunity IDs,
rubric internals and trainer analytics.

Every trainer page and API is wrapped by the application's instructor guard.
State changes are POST-only and remain under the global CSRF gate. Development
controls under `/prototype/api/dev/*` are unmounted by policy (404) unless an
operator explicitly enables them. Historical v1 learner/study routes are also
unmounted by default.

## Docker controls actually configured

Each session uses a one-way SHA-256-derived management key and its own container.
Names and labels contain no learner PII. Every creation fixes:

- network mode `none`, no published or exposed port;
- numeric user/group `10001:10001`;
- read-only root filesystem;
- all Linux capabilities dropped and `no-new-privileges`;
- privileged mode off;
- one 8 MiB `/workspace` tmpfs with `noexec,nosuid,nodev`;
- no bind mount, named volume, device, host path or Docker socket;
- 64 MiB memory, 32 PIDs and 0.50 CPU;
- a fixed image entrypoint with no listener or shell server.

These are configuration facts. Runtime claims require a successful record from
`python -m evaluation.rewindsec2.containment`; blocked/unsupported checks are
never treated as passes.

The only production port operations are reconcile, inspect and destroy. Inputs
are typed and require the complete fixed allowlist. Docker commands use argument
arrays with `shell=False`. Cleanup first verifies both the exact v2 name and the
two strict ownership/session labels. It never invokes prune or enumerates/removes
unrelated containers, images or volumes.

## Failure behavior

The persisted RewindSec world is factual. Docker reconciliation runs only after
a successful persistence write. A missing daemon/image/container, timeout,
malformed response, version mismatch or cleanup failure becomes an operational
diagnostic; it cannot consume simulation RNG, advance simulation time, select a
consequence, rewrite incident history or leak raw daemon output to an Assessment
client. A later load reconciles from persisted truth, so a missing sandbox is
recreated and a stale sandbox never becomes authoritative.

## Misuse analysis and residual limitations

- Hosting phishing content: the product has no unrestricted content-hosting or
  outbound-browser API. An operator who edits source code can of course change
  authored content; normal authorization cannot defend against a malicious
  deployment owner.
- Capturing credentials: sign-in fields accept only synthetic training values,
  and learner payloads are not a general credential ingestion API. Operators
  must still protect the application database and logs.
- Executing commands or accessing host files: neither learner nor trainer APIs
  accept commands or paths. Docker daemon administrators remain outside this
  boundary and can control containers by definition.
- Exposing learner records: trainer APIs require instructor authentication, but
  this project does not establish regulatory compliance, multi-role enterprise
  IAM, database encryption, backup policy or a formal retention regime.
- Denial of service: request-size, simulation-step, SSE lifetime, Docker resource
  and rendered-list bounds reduce accidental exhaustion. This validation is not
  a denial-of-service test or penetration test.

## Stored learner data

The v2 database stores an opaque learner reference, optional trainer-entered
display/reference/cohort fields, group membership, assignments, attempts,
synthetic learner actions, deterministic session state and finalized results.
These support enrollment, resume, audit, scoring and trainer progress views.
Enrollment codes are stored as lifecycle records; raw browser cookies and real
credentials are not training data. Deployment owners remain responsible for
access control, backups, retention and deletion policy appropriate to their use.
