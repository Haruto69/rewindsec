# RewindSec 2.0 final manual validation

This is the final human checkpoint. Record browser/OS, date, tester, build
revision and any defect. Do not treat the checklist itself as evidence that a
human completed it.

## Learner

- Open `/` and confirm the browser settles on the canonical `/start` surface.
- Paste a fresh enrollment code into the one-time-code field; confirm surrounding
  whitespace is harmless, replay fails and refresh/resume preserves identity.
- Start Practice, Simulation, self-directed Assessment and assigned Assessment.
- Exercise Mail, Files, Browser, Notifications, Notes, Authenticator, Messages and Directory.
- Complete representative phishing, ransomware, MFA, BEC and Mixed activity.
- Confirm natural consequences, workstation isolation, containment and ransomware recovery.
- End Training and inspect the debrief/result; refresh and resume at several points.
- While Assessment is active, verify no score, correctness, answer truth, rubric detail or trainer analytics appears.

## Trainer

- Open `/trainer/login`; verify password paste, error, lockout and unavailable
  states use the RewindSec trainer design.
- Verify login/logout and that an unauthenticated browser cannot guess trainer pages/APIs.
- Inspect dashboard, students and real (not fixture) empty states/counts.
- Create a student and enrollment code; use **Copy code** and confirm only the
  displayed single-use code reaches the clipboard. Create a group and add/remove membership.
- Create an assessment; verify feasible scored-interaction limits are enforced.
- Assign directly and by group; exercise duplicate warning and explicit confirmation.
- Complete an attempt and verify attempt/result history and analytics reflect stored data only.

## Product surface

- Confirm learner navigation uses `/start`, `/workstation` and `/results`, and
  trainer navigation stays under `/trainer`; no normal address uses `/prototype`.
- Confirm no visible page, empty state or error calls the product a prototype,
  demo, fixture or developer tool.
- Confirm copy and paste work in login, enrollment and trainer management forms,
  while the active workstation retains its documented exercise restriction.
- Confirm `/prototype/...` browser bookmarks immediately redirect to clean URLs
  and development controls are absent in a default startup.

## Safety

- With Docker enabled, trigger ransomware and verify only the four synthetic files change.
- Confirm browser destinations stay inside the authored synthetic catalogue.
- Confirm no host path/file is visible and the container has no network route.
- End the session and verify its labelled sandbox is removed without affecting another active session.
