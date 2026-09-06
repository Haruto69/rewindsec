"""Server-sent events: the update transport, and what it must not become.

The stream exists so a consequence that lands while the learner is reading can
reach the screen without the browser polling for it. Everything else about it
is a constraint:

* it carries **revision numbers, not content**. A woken client re-reads the
  authoritative snapshot through the ordinary path, so there is exactly one
  place learner-facing state is filtered and exactly one place to keep safe;
* it is scoped to the session in the signed cookie. There is no session
  parameter, so there is nothing to point at somebody else's session;
* it is **not a clock**. Connecting, waiting, timing out, dropping and
  reconnecting change no simulation state, and a keepalive is a comment on the
  wire that carries no event and no id;
* revisions are monotonic, which makes them a usable ``Last-Event-ID``.

Every test here is bounded. A streaming test that can hang is a test that will
eventually hang in CI, so the broker is exercised directly wherever the
question is about blocking, and the HTTP surface is read one frame at a time
with the connection closed straight afterwards.
"""

import json
import re
import threading
import time

import pytest

from rewindsec.workstation.updates import UpdateBroker

CSRF_META = re.compile(rb'name="csrf-token" content="([^"]+)"')
WORKSTATION = "/prototype/workstation"
EVENTS = "/prototype/api/events"


def headers(client):
    match = CSRF_META.search(client.get(WORKSTATION).data)
    assert match
    return {"X-CSRF-Token": match.group(1).decode(),
            "Content-Type": "application/json", "Accept": "application/json"}


def start(client, focus="phishing", mode="simulation"):
    response = client.post("/prototype/api/session/start",
                           data=json.dumps({"focus": focus, "mode": mode}),
                           headers=headers(client))
    assert response.status_code == 201
    return response.get_json()["snapshot"]


def first_frame(response, limit=8192):
    """Read just enough of the stream to see its first frame, then stop.

    Bounded twice over -- by bytes and by the generator ending -- so a broken
    server cannot turn this into a hanging test.
    """
    buffer = b""
    for chunk in response.response:
        buffer += chunk
        if b"\n\n" in buffer or len(buffer) >= limit:
            break
    response.close()
    return buffer.decode("utf-8", "replace")


def parse_frame(text):
    fields = {}
    for line in text.split("\n"):
        if not line or line.startswith(":"):
            continue
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


# ===========================================================================
# The HTTP surface
# ===========================================================================

def test_the_stream_declares_itself_as_an_event_stream(client):
    start(client)
    response = client.get(EVENTS)
    assert response.status_code == 200
    assert response.mimetype == "text/event-stream"
    assert "no-cache" in response.headers.get("Cache-Control", "")
    response.close()


def test_the_first_frame_states_the_current_revision(client):
    """So a client that reconnected after missing an update reconciles at once."""
    snapshot = start(client)
    response = client.get(EVENTS)
    frame = parse_frame(first_frame(response))
    assert frame["event"] == "revision"
    assert int(frame["id"]) == snapshot["session"]["revision"]
    assert json.loads(frame["data"])["revision"] == snapshot["session"]["revision"]


def test_the_stream_carries_no_content(client):
    """Only a number. Not a projection, not a payload, not a diff."""
    start(client)
    response = client.get(EVENTS)
    text = first_frame(response)
    payload = json.loads(parse_frame(text)["data"])
    assert set(payload) == {"revision"}


def test_a_reconnect_with_last_event_id_is_accepted(client):
    snapshot = start(client)
    response = client.get(EVENTS, headers={
        "Last-Event-ID": str(snapshot["session"]["revision"])})
    frame = parse_frame(first_frame(response))
    # The reconciliation frame is sent regardless, which is what makes a
    # client that missed an update while disconnected safe.
    assert int(frame["id"]) == snapshot["session"]["revision"]


def test_a_nonsense_last_event_id_is_ignored_rather_than_fatal(client):
    snapshot = start(client)
    for value in ("not-a-number", "-5", "99999999999999999999999"):
        response = client.get(EVENTS, headers={"Last-Event-ID": value})
        assert response.status_code == 200
        frame = parse_frame(first_frame(response))
        assert int(frame["id"]) == snapshot["session"]["revision"]


def test_the_stream_requires_a_session_of_your_own(client):
    response = client.get(EVENTS)
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "no_session"
    response.close()


def test_there_is_no_way_to_name_a_session_on_the_stream(flask_app):
    """The scoping is structural: the route takes no session parameter."""
    rule = [r for r in flask_app.url_map.iter_rules()
            if r.rule == "/prototype/api/events"][0]
    assert rule.arguments == set()
    assert rule.methods & {"POST", "PUT", "PATCH", "DELETE"} == set()


def test_two_browsers_see_their_own_revisions(client, other_client):
    a = start(client, focus="phishing")
    for _ in range(3):
        client.post("/prototype/api/dev/deliver-next", data="{}",
                    headers=headers(client))
    b = start(other_client, focus="bec")

    a_frame = parse_frame(first_frame(client.get(EVENTS)))
    b_frame = parse_frame(first_frame(other_client.get(EVENTS)))
    assert int(a_frame["id"]) != int(b_frame["id"])
    assert int(b_frame["id"]) == b["session"]["revision"]
    assert int(a_frame["id"]) > a["session"]["revision"]


def test_connecting_to_the_stream_changes_no_simulation_state(client, flask_app):
    """Opening, reading and closing a stream is not an event."""
    import app as app_module
    from rewindsec.prototype.api import SESSION_KEY

    start(client)
    with client.session_transaction() as flask_session:
        session_id = flask_session[SESSION_KEY]

    def stored():
        with flask_app.app_context():
            return app_module.workstation_repository().load(
                session_id).capture_state()

    before = stored()
    for _ in range(3):
        first_frame(client.get(EVENTS))
    assert stored() == before


# ===========================================================================
# The broker
# ===========================================================================

def test_a_publish_wakes_a_waiter():
    broker = UpdateBroker()
    broker.publish("s1", 4)
    result = {}

    def wait():
        result["revision"] = broker.wait_for_change("s1", 4, timeout=5)

    thread = threading.Thread(target=wait)
    thread.start()
    time.sleep(0.05)
    broker.publish("s1", 5)
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result["revision"] == 5


def test_a_waiter_that_is_already_behind_returns_at_once():
    broker = UpdateBroker()
    broker.publish("s1", 9)
    started = time.monotonic()
    assert broker.wait_for_change("s1", 3, timeout=5) == 9
    assert time.monotonic() - started < 1.0


def test_a_wait_that_sees_nothing_times_out_rather_than_hanging():
    broker = UpdateBroker()
    broker.publish("s1", 2)
    started = time.monotonic()
    assert broker.wait_for_change("s1", 2, timeout=0.2) is None
    assert time.monotonic() - started < 2.0


def test_revisions_are_monotonic():
    """An out-of-order publish cannot make a client think time went backwards."""
    broker = UpdateBroker()
    broker.publish("s1", 7)
    broker.publish("s1", 3)
    assert broker.current("s1") == 7


def test_one_sessions_publish_does_not_wake_another():
    broker = UpdateBroker()
    broker.publish("a", 1)
    broker.publish("b", 1)
    broker.publish("b", 2)
    assert broker.current("a") == 1


def test_the_broker_is_bounded():
    """A long-running process cannot accumulate one entry per session ever seen."""
    broker = UpdateBroker(limit=4)
    for index in range(20):
        broker.publish("s%d" % index, 1)
    tracked = [index for index in range(20)
               if broker.current("s%d" % index) is not None]
    assert len(tracked) <= 4


def test_the_broker_holds_no_content():
    """Structural: there is no parameter through which a payload could pass."""
    import inspect
    signature = inspect.signature(UpdateBroker.publish)
    assert list(signature.parameters) == ["self", "session_id", "revision"]


# ===========================================================================
# Assessment
# ===========================================================================

def test_the_stream_is_the_same_in_an_assessment_attempt(client):
    """Nothing pedagogical rides on the transport, so nothing is suppressed here.

    The suppression lives in the projection, which the woken client re-reads;
    if it lived in the stream instead there would be two filters to keep in
    step and one of them would eventually drift.
    """
    snapshot = start(client, focus="phishing", mode="assessment")
    frame = parse_frame(first_frame(client.get(EVENTS)))
    assert set(json.loads(frame["data"])) == {"revision"}
    assert int(frame["id"]) == snapshot["session"]["revision"]
