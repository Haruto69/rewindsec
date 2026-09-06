"""Server-to-browser update transport: a small, bounded revision broker.

The learner's browser needs to hear about changes it did not itself cause --
an authored consequence arriving a minute after a decision, a colleague's
message, a file that has stopped opening. Architecture spec S18 chooses
server-sent events for this, and this module is the part of that which does
not know what HTTP is: it tracks, per session, the latest revision the server
has committed, and lets a waiting reader block until that number moves.

What this deliberately is not
-----------------------------
* **Not a message queue.** It carries a revision number, never a payload. A
  woken client re-fetches the authoritative snapshot through the ordinary
  read path, which means the update transport can never become a second,
  differently-filtered way for state to reach a browser -- and therefore can
  never become a second place hidden truth could leak from.
* **Not a broker process.** No Redis, no external queue, no background thread
  pool. One dict, one :class:`threading.Condition`, bounded by session count,
  appropriate to the single-process Flask application this runs inside.
* **Not a clock.** Nothing here advances simulation time, fires an event, or
  touches a session. A connection opening, waiting, timing out, dropping or
  reconnecting changes no simulation state whatsoever. Keepalives exist so
  that proxies do not close an idle connection, and they are comments on the
  wire that carry no event and no revision.

Reconnection
------------
Revisions are monotonic per session, so they are a natural event id. A client
that reconnects sends the last revision it saw (as ``Last-Event-ID``); if the
server has already moved past it, the wait returns immediately and the client
reconciles by re-fetching. Nothing is replayed and nothing needs to be
retained, because the client's recovery is "ask for the current truth" rather
than "catch up on a log of deltas".
"""

import threading

__all__ = ["UpdateBroker", "SESSION_LIMIT"]

#: Bound on tracked sessions, so a long-running process cannot accumulate one
#: entry per session that ever existed.
SESSION_LIMIT = 1024


class UpdateBroker(object):
    """Latest committed revision per session, with a blocking wait."""

    def __init__(self, limit=SESSION_LIMIT):
        self._condition = threading.Condition()
        self._revisions = {}
        self._order = []
        self._limit = limit

    def publish(self, session_id, revision):
        """Record that *session_id* has committed *revision* and wake waiters.

        Called from the service after a successful save. Monotonic by
        construction: a revision that is not greater than the one already
        recorded is ignored, so an out-of-order publish cannot make a client
        believe the world went backwards.
        """
        with self._condition:
            current = self._revisions.get(session_id)
            if current is not None and revision <= current:
                return
            if session_id not in self._revisions:
                self._order.append(session_id)
                while len(self._order) > self._limit:
                    evicted = self._order.pop(0)
                    self._revisions.pop(evicted, None)
            self._revisions[session_id] = revision
            self._condition.notify_all()

    def current(self, session_id):
        with self._condition:
            return self._revisions.get(session_id)

    def wait_for_change(self, session_id, since_revision, timeout):
        """Block until the session passes *since_revision*, or time out.

        Returns the new revision, or ``None`` on timeout. ``timeout`` is a
        real-time bound on how long a reader holds a connection open before
        sending a keepalive -- transport pacing, and the only place in this
        module that real time appears at all.
        """
        deadline_reached = False
        with self._condition:
            current = self._revisions.get(session_id)
            if current is not None and (since_revision is None
                                        or current > since_revision):
                return current
            deadline_reached = not self._condition.wait(timeout)
            current = self._revisions.get(session_id)
        if deadline_reached:
            return None
        if current is not None and (since_revision is None
                                    or current > since_revision):
            return current
        return None

    def forget(self, session_id):
        with self._condition:
            self._revisions.pop(session_id, None)
            if session_id in self._order:
                self._order.remove(session_id)
