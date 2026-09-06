"""Shared scaffolding for the Batch 5 management suites.

What every one of these suites needs and should not each invent: a
:class:`~rewindsec.management.service.ManagementService` and a
:class:`~rewindsec.workstation.service.WorkstationService` over one throwaway
database, with deterministic ids and a deterministic administrative clock.

Two things are pinned here that production leaves to the environment, and both
are pinned for the same reason -- a test that reads a real clock or a random id
is a test that can fail for reasons unrelated to what it asserts:

``SequenceIdSource``
    Administrative ids count from one per prefix. Production uses
    :class:`~rewindsec.management.ids.SecretsIdSource`; neither draws from any
    simulation RNG stream, which is the property that actually matters and is
    asserted directly in ``test_rewindsec2_management_attempts.py``.
``StubClock``
    Administrative timestamps advance one second per call. No simulation
    decision reads a clock of any kind -- see
    ``test_determinism_is_unperturbed_by_management_metadata``.
"""

import sqlalchemy as sa

from rewindsec.management.ids import SequenceIdSource
from rewindsec.management.service import ManagementService
from rewindsec.persistence.management_adapter import \
    SqlAlchemyManagementRepository
from rewindsec.persistence.sqlalchemy_adapter import SqlAlchemySessionRepository
from rewindsec.workstation.seeds import FixedSeedSource
from rewindsec.workstation.service import WorkstationService

LEARNER = "learner-mgmt-1"
OTHER_LEARNER = "learner-mgmt-2"


class StubClock(object):
    """A deterministic administrative clock. One second per call."""

    def __init__(self, start=0):
        self._n = start

    def __call__(self):
        self._n += 1
        return "2026-09-07T10:%02d:%02d+00:00" % (self._n // 60, self._n % 60)


def sqlite_uri(tmp_path, name="management.db"):
    return "sqlite:///" + str(tmp_path / name).replace("\\", "/")


def build(uri, seed=4242, ids=None, clock=None):
    """A management service and a workstation service over the same database.

    Returns ``(management, workstation, session_repository)``. Calling this
    twice against the same URI is how a test reconstructs the whole object
    graph -- new engine, new repositories, new services -- against the same
    stored rows, which is the persistence path that matters. Pass the same
    ``ids`` back in when doing so, or the second graph will start minting ids
    that the first one already used.
    """
    engine = sa.create_engine(uri)
    sessions = SqlAlchemySessionRepository(engine)
    sessions.create_schema()
    records = SqlAlchemyManagementRepository(engine)
    records.create_schema()
    workstation = WorkstationService(sessions, seed_source=FixedSeedSource(seed))
    management = ManagementService(
        repository=records, sessions=sessions, directory=sessions,
        workstation=workstation, id_source=ids or SequenceIdSource(),
        clock=clock or StubClock())
    return management, workstation, sessions


def roster(management, students=("Alice Doe", "Bob Roe")):
    """A small roster: the named students, all active."""
    return [management.create_student(name) for name in students]
