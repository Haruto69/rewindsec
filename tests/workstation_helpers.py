"""Shared scaffolding for the Batch 2 workstation suites.

What every one of these suites needs and should not each invent: a
:class:`~rewindsec.workstation.service.WorkstationService` on a throwaway
database, and a small driver that acts on a session the way a browser does.

Nothing here has to pin a clock. The service reads no real clock at all --
simulation time moves only when a test (or an endpoint) explicitly asks it to,
by a stated number of milliseconds -- so "the same actions produce the same
session" is true on any machine, at any speed, without help.
"""

import sqlalchemy as sa

from rewindsec.persistence.sqlalchemy_adapter import SqlAlchemySessionRepository
from rewindsec.workstation.actions import parse_action_request
from rewindsec.workstation.seeds import FixedSeedSource
from rewindsec.workstation.service import WorkstationService

LEARNER = "learner-test-1"
OTHER_LEARNER = "learner-test-2"


def sqlite_uri(tmp_path, name="workstation.db"):
    return "sqlite:///" + str(tmp_path / name).replace("\\", "/")


def build_service(uri, seed=4242, ids=None, updates=None):
    """A service and its repository over *uri*, with the schema created.

    Calling this twice against the same URI is how a test reconstructs the
    whole object graph -- new engine, new repository, new service -- against
    the same stored data, which is the resume path that matters.
    """
    engine = sa.create_engine(uri)
    repository = SqlAlchemySessionRepository(engine)
    repository.create_schema()
    id_source = None
    if ids is not None:
        counter = iter(ids)
        id_source = lambda: next(counter)  # noqa: E731
    service = WorkstationService(repository, seed_source=FixedSeedSource(seed),
                                 id_source=id_source, updates=updates)
    return service, repository


class Driver(object):
    """A tiny convenience wrapper: start a session and act on it.

    Deliberately does *not* hide the revision. Every action carries the
    revision the caller last saw, exactly as the browser does, so a test that
    means to submit a stale one can, and a test that does not, cannot do it by
    accident.
    """

    def __init__(self, service, session_id, learner_ref=LEARNER):
        self.service = service
        self.session_id = session_id
        self.learner_ref = learner_ref

    @classmethod
    def start(cls, service, focus="phishing", mode="simulation",
              learner_ref=LEARNER):
        session_id = service.start_session(learner_ref, focus, mode)
        return cls(service, session_id, learner_ref)

    @property
    def revision(self):
        return self.service.revision(self.session_id, self.learner_ref)

    def snapshot(self):
        return self.service.snapshot(self.session_id, self.learner_ref)

    def session(self):
        return self.service.require_owned(self.session_id, self.learner_ref)

    def act(self, action, target=None, params=None, revision=None):
        payload = {"action": action,
                   "revision": self.revision if revision is None else revision}
        if target is not None:
            payload["target"] = target
        if params is not None:
            payload["params"] = params
        return self.service.apply_action(
            self.session_id, parse_action_request(payload), self.learner_ref)

    def advance(self, milliseconds):
        return self.service.dev_advance(self.session_id, milliseconds,
                                        self.learner_ref)

    def tick(self, times=1):
        """One or more heartbeat steps, each of exactly one authored quantum."""
        snapshot = None
        for _ in range(times):
            snapshot = self.service.tick(self.session_id, self.learner_ref)
        return snapshot

    def deliver_next(self):
        return self.service.dev_deliver_next(self.session_id, self.learner_ref)

    def deliver_until(self, mail_id, limit=8):
        """Release authored arrivals until *mail_id* is in the mailbox."""
        for _ in range(limit):
            snapshot = self.snapshot()
            if any(m["id"] == mail_id for m in snapshot["mail"]["messages"]):
                return snapshot
            self.deliver_next()
        raise AssertionError("%s never arrived" % mail_id)


def message(snapshot, mail_id):
    for entry in snapshot["mail"]["messages"]:
        if entry["id"] == mail_id:
            return entry
    return None


def file_row(snapshot, file_id):
    for entry in snapshot["files"]["files"]:
        if entry["id"] == file_id:
            return entry
    return None


def contact(snapshot, contact_id):
    for entry in snapshot["directory"]:
        if entry["id"] == contact_id:
            return entry
    return None


def conversation(snapshot, conversation_id):
    for entry in snapshot["messages"]:
        if entry["id"] == conversation_id:
            return entry
    return None


def incident(snapshot, key):
    for entry in snapshot["incidents"]:
        if entry["key"] == key:
            return entry
    return None


def walk(value, path="$"):
    """Yield every ``(path, value)`` pair in a JSON document, recursively.

    The leakage suite needs to inspect *everything* that reaches a browser,
    not the fields somebody remembered to check.
    """
    yield path, value
    if isinstance(value, dict):
        for key, item in value.items():
            for pair in walk(item, "%s.%s" % (path, key)):
                yield pair
    elif isinstance(value, list):
        for index, item in enumerate(value):
            for pair in walk(item, "%s[%d]" % (path, index)):
                yield pair
