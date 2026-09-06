"""The closed, server-side vocabulary of learner actions.

The single most important property of this module is what it *refuses*. The
client submits a semantic action -- "report this message", "approve this
request" -- and never a mutation. There is no path here by which a request
body can say what the world should become; the only thing a body can choose is
which entry in :data:`ACTION_SPECS` to invoke, and which of that entry's
narrowly typed parameters to supply. Everything else about the resulting state
change is decided by :mod:`rewindsec.workstation.service`.

Consequently the parser is strict rather than forgiving:

* an unknown action type is rejected, not ignored;
* an unknown key anywhere in the body is rejected, not dropped -- a silently
  dropped key is how a client comes to believe it is setting something;
* ``True`` is not accepted where an integer is expected (``bool`` is an
  ``int`` subclass in Python, and accepting it silently turns a type error
  into an off-by-one);
* ``NaN`` and the infinities are rejected: they are not JSON values, they do
  not compare usefully, and they cannot be persisted canonically;
* every string is length-bounded, and the whole body is size-bounded, so a
  learner-authored note cannot become an unbounded write.

``classification`` on each spec is the domain's
:class:`~rewindsec.domain.enums.ActionClass`: observational actions reveal
information, consequential ones can change security state. It is recorded on
the :class:`~rewindsec.domain.actions.LearnerAction` and is what later batches
will read. It is not a hint to the client and is never projected -- telling a
learner that "approve" is consequential and "details" is not would be a nudge.
"""

import math

from rewindsec.domain.enums import ActionClass
from rewindsec.workstation.errors import (InvalidRequestError,
                                          UnknownActionError)

__all__ = [
    "ActionSpec", "SemanticAction", "ACTION_SPECS", "ACTION_TYPES",
    "parse_action_request", "reject_non_finite", "MAX_BODY_BYTES",
    "MAX_NOTE_BODY", "MAX_NOTE_TITLE", "MAX_REPLY_TEXT", "MAX_MESSAGE_TEXT",
    "MAX_URL", "MAX_FILE_NAME", "MAX_ACCOUNT_REF",
]

#: Hard ceiling on a request body. Notes are the largest legitimate payload
#: and are bounded well below this; anything larger is not a learner typing.
MAX_BODY_BYTES = 64 * 1024

MAX_NOTE_TITLE = 120
MAX_NOTE_BODY = 8000
MAX_REPLY_TEXT = 4000
MAX_MESSAGE_TEXT = 1000
MAX_URL = 200
MAX_FILE_NAME = 120
MAX_ACCOUNT_REF = 80
MAX_RESOURCE_REF = 64

#: Identifiers the client may name. Deliberately narrow: these are ids the
#: server itself minted and handed out in a projection, so anything outside
#: this shape was invented by the client.
_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.:")
MAX_ID = 128

#: What a synthetic browser address may contain. No scheme, no credentials, no
#: query string, and no host resolution of any kind -- the browser never
#: fetches anything, and an address that is not an authored page renders as
#: "not reachable". Restricting the charset also keeps an address from
#: carrying markup or control characters into a projection.
_URL_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789-._~/")


class ActionSpec(object):
    """One allowlisted action: its class, its target, and its parameters."""

    __slots__ = ("action_type", "classification", "target", "params")

    def __init__(self, action_type, classification, target=None, params=None):
        self.action_type = action_type
        self.classification = classification
        #: ``None`` when the action has no target, else a short label naming
        #: what kind of thing the target is (used only in error messages).
        self.target = target
        #: ``{name: (kind, required, bound)}`` where *kind* is one of
        #: ``"str"``, ``"int"``, ``"bool"``, ``"url"``, ``"enum"``.
        self.params = dict(params or {})

    @property
    def is_consequential(self):
        return self.classification is ActionClass.CONSEQUENTIAL


def _obs(action_type, target=None, params=None):
    return ActionSpec(action_type, ActionClass.OBSERVATIONAL, target, params)


def _con(action_type, target=None, params=None):
    return ActionSpec(action_type, ActionClass.CONSEQUENTIAL, target, params)


#: The whole learner action surface. Adding a button to the workstation means
#: adding a line here and a handler in the service -- which is the point: a new
#: way to change the world cannot arrive by accident from the front end.
ACTION_SPECS = {spec.action_type: spec for spec in (
    # -- Mail ---------------------------------------------------------------
    _obs("mail.open", target="message"),
    _obs("mail.inspect_headers", target="message"),
    _obs("mail.inspect_link", target="message",
         params={"index": ("int", True, 64)}),
    _obs("mail.inspect_attachment", target="message",
         params={"index": ("int", True, 64)}),
    _obs("mail.open_link", target="message",
         params={"index": ("int", True, 64)}),
    _con("mail.report", target="message"),
    _con("mail.delete", target="message"),
    _con("mail.forward", target="message"),
    _con("mail.reply", target="message",
         params={"text": ("str", False, MAX_REPLY_TEXT)}),
    _con("mail.download_attachment", target="message",
         params={"index": ("int", True, 64)}),

    # -- Browser ------------------------------------------------------------
    _obs("browser.navigate", params={"url": ("url", True, MAX_URL)}),
    _con("browser.sign_in", params={"url": ("url", True, MAX_URL)}),
    _con("browser.sign_in_retry", params={"url": ("url", True, MAX_URL)}),
    #: ``context`` names *which release-queue entry* on that page is being
    #: settled -- the payment-context id the projection handed the client,
    #: never an invoice, an occurrence or a decision. Optional: a client that
    #: sends none settles the page's first outstanding entry, which is what
    #: every single-entry payments page has always done. See
    #: ``rewindsec.workstation.service._resolve_payment_context``.
    _con("browser.release_payment",
         params={"url": ("url", True, MAX_URL),
                 "account": ("str", True, MAX_ACCOUNT_REF),
                 "context": ("str", False, MAX_RESOURCE_REF)}),
    #: ``reconnect`` (Batch 3) and ``restore`` (Batch 4) are deliberately in
    #: the same allowlist as ``isolate``: each is a consequential operational
    #: decision, not a settings toggle, and each is recorded as one. Narrow on
    #: purpose -- there is no network-management or IT-recovery surface here,
    #: only the things a person at a Service Desk page can actually do.
    #: ``restore`` is recovery, not containment: it is only meaningful once an
    #: incident exists and has already been contained, and it never undoes
    #: the incident itself -- see ``rewindsec.workstation.service._restore``.
    _con("browser.support_action",
         params={"choice": ("enum", True,
                            ("isolate", "raise", "reconnect", "restore"))}),
    #: A download from a synthetic page. The client names the page and the
    #: *resource id* the projection gave it; it cannot name a filename, a
    #: path or an address to fetch, and nothing is fetched. The server decides
    #: what the file is and what it ends up called.
    _con("browser.download",
         params={"url": ("url", True, MAX_URL),
                 "resource": ("str", True, MAX_RESOURCE_REF)}),

    # -- Files --------------------------------------------------------------
    _obs("files.inspect", target="file"),
    _con("files.open", target="file"),
    _con("files.delete", target="file"),
    _con("files.rename", target="file",
         params={"name": ("str", True, MAX_FILE_NAME)}),

    # -- Notifications ------------------------------------------------------
    _obs("notifications.open", target="notification"),
    _obs("notifications.mark_read"),

    # -- Notes --------------------------------------------------------------
    _obs("notes.create"),
    _obs("notes.open", target="note"),
    _obs("notes.save", target="note",
         params={"title": ("str", False, MAX_NOTE_TITLE),
                 "body": ("str", False, MAX_NOTE_BODY)}),
    _obs("notes.delete", target="note"),

    # -- Authenticator ------------------------------------------------------
    _obs("auth.inspect_request", target="request"),
    _obs("auth.inspect_history"),
    _con("auth.approve", target="request"),
    _con("auth.deny", target="request"),

    # -- Messages -----------------------------------------------------------
    _obs("messages.open", target="conversation"),
    _con("messages.send", target="conversation",
         params={"text": ("str", True, MAX_MESSAGE_TEXT)}),
    _con("messages.verify", target="conversation"),

    # -- Directory ----------------------------------------------------------
    _obs("directory.open", target="contact"),
    _con("directory.call", target="contact"),

    # -- Session ------------------------------------------------------------
    #: Dismisses the safer-alternative comparison. It changes no factual state
    #: -- explicitly *not* a rewind -- so it is observational.
    _obs("session.acknowledge"),
)}

ACTION_TYPES = frozenset(ACTION_SPECS)

#: Keys a learner action request may carry. Anything else is rejected outright
#: rather than ignored, so a client that believes it is setting ``sim_time``,
#: ``session_id``, ``seed``, ``world`` or ``score`` learns immediately that it
#: is not.
_REQUEST_KEYS = frozenset({"action", "target", "params", "revision", "csrf_token"})


class SemanticAction(object):
    """A validated, allowlisted action request. Carries no mutation."""

    __slots__ = ("spec", "target", "params", "expected_revision")

    def __init__(self, spec, target, params, expected_revision):
        self.spec = spec
        self.target = target
        self.params = params
        self.expected_revision = expected_revision

    @property
    def action_type(self):
        return self.spec.action_type

    @property
    def classification(self):
        return self.spec.classification

    def __repr__(self):
        return "SemanticAction(%r, target=%r, revision=%r)" % (
            self.spec.action_type, self.target, self.expected_revision)


def parse_action_request(payload):
    """Validate a decoded JSON body and return a :class:`SemanticAction`.

    Raises :class:`~rewindsec.workstation.errors.InvalidRequestError` or
    :class:`~rewindsec.workstation.errors.UnknownActionError`. Nothing here
    reads world state: this is a purely syntactic gate. The semantic gate --
    "does that message exist, and may you touch it?" -- is the service's job,
    because only the service has the session in front of it.
    """
    if not isinstance(payload, dict):
        raise InvalidRequestError("The request body must be a JSON object.")
    reject_non_finite(payload, "body")

    unknown = sorted(set(payload) - _REQUEST_KEYS)
    if unknown:
        raise InvalidRequestError(
            "Unrecognised field(s) in the request: %s." % ", ".join(unknown))

    action_type = payload.get("action")
    if isinstance(action_type, bool) or not isinstance(action_type, str) \
            or not action_type:
        raise InvalidRequestError("An action type is required.")
    if len(action_type) > 96:
        raise UnknownActionError("That action type is not recognised.")
    spec = ACTION_SPECS.get(action_type)
    if spec is None:
        raise UnknownActionError("That action type is not recognised.")

    target = payload.get("target")
    if spec.target is None:
        if target is not None:
            raise InvalidRequestError("%s takes no target." % spec.action_type)
    else:
        target = _validate_id(target, spec.target)

    raw_params = payload.get("params")
    if raw_params is None:
        raw_params = {}
    if not isinstance(raw_params, dict):
        raise InvalidRequestError("params must be a JSON object.")
    params = _validate_params(spec, raw_params)

    revision = payload.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise InvalidRequestError(
            "A numeric revision is required so a stale or repeated submission "
            "cannot be applied twice.")
    if revision < 0 or revision > 2 ** 53 - 1:
        raise InvalidRequestError("That revision is out of range.")

    return SemanticAction(spec, target, params, revision)


def _validate_params(spec, raw):
    unknown = sorted(set(raw) - set(spec.params))
    if unknown:
        raise InvalidRequestError(
            "Unrecognised parameter(s) for %s: %s."
            % (spec.action_type, ", ".join(unknown)))

    out = {}
    for name in sorted(spec.params):
        kind, required, bound = spec.params[name]
        if name not in raw or raw[name] is None:
            if required:
                raise InvalidRequestError(
                    "%s requires the %r parameter." % (spec.action_type, name))
            continue
        out[name] = _validate_value(raw[name], kind, bound, name)
    return out


def _validate_value(value, kind, bound, name):
    if kind == "int":
        if isinstance(value, bool):
            raise InvalidRequestError("%s must be a number, not a boolean." % name)
        if not isinstance(value, int):
            raise InvalidRequestError("%s must be a whole number." % name)
        if not 0 <= value <= bound:
            raise InvalidRequestError("%s is out of range." % name)
        return value

    if kind == "bool":
        if not isinstance(value, bool):
            raise InvalidRequestError("%s must be true or false." % name)
        return value

    if kind == "enum":
        if isinstance(value, bool) or not isinstance(value, str) \
                or value not in bound:
            raise InvalidRequestError("%s is not one of the allowed values." % name)
        return value

    if kind == "url":
        return _validate_url(value, bound, name)

    if kind == "str":
        return _validate_text(value, bound, name)

    raise InvalidRequestError("%s could not be validated." % name)


def _validate_text(value, bound, name):
    if isinstance(value, bool) or not isinstance(value, str):
        raise InvalidRequestError("%s must be text." % name)
    if len(value) > bound:
        raise InvalidRequestError(
            "%s is longer than the %d characters allowed." % (name, bound))
    for char in value:
        # Newline and tab are ordinary in a note or a reply; the rest of the
        # C0 range is not, and a NUL or an escape sequence in stored content is
        # never something a learner typed on purpose.
        if ord(char) < 32 and char not in "\n\r\t":
            raise InvalidRequestError("%s contains a control character." % name)
        if ord(char) == 127:
            raise InvalidRequestError("%s contains a control character." % name)
    return value


def _validate_url(value, bound, name):
    if isinstance(value, bool) or not isinstance(value, str):
        raise InvalidRequestError("%s must be text." % name)
    cleaned = value.strip()
    if cleaned.lower().startswith("https://"):
        cleaned = cleaned[8:]
    elif cleaned.lower().startswith("http://"):
        cleaned = cleaned[7:]
    cleaned = cleaned.rstrip("/").lower()
    if not cleaned:
        raise InvalidRequestError("An address is required.")
    if len(cleaned) > bound:
        raise InvalidRequestError("That address is too long.")
    for char in cleaned:
        if char not in _URL_CHARS:
            raise InvalidRequestError("That address is not a valid address.")
    if ".." in cleaned:
        raise InvalidRequestError("That address is not a valid address.")
    return cleaned


def _validate_id(value, what):
    if isinstance(value, bool) or not isinstance(value, str) or not value:
        raise InvalidRequestError("A %s reference is required." % what)
    if len(value) > MAX_ID:
        raise InvalidRequestError("That %s reference is not valid." % what)
    for char in value:
        if char not in _ID_CHARS:
            raise InvalidRequestError("That %s reference is not valid." % what)
    return value


def reject_non_finite(value, path="value", depth=0):
    """Raise if *value* contains a NaN or an infinity anywhere inside it.

    ``json.loads`` accepts ``NaN``/``Infinity`` by default, and the domain
    would reject them later at freeze time with a message naming a field the
    caller never wrote. Catching them at the door keeps the error close to the
    mistake. The depth bound also stops a deeply nested body from recursing
    this walk into a stack overflow.
    """
    if depth > 24:
        raise InvalidRequestError("The request body is nested too deeply.")
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise InvalidRequestError("%s is not a JSON number." % path)
    elif isinstance(value, dict):
        for key, item in value.items():
            reject_non_finite(item, "%s.%s" % (path, key), depth + 1)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_non_finite(item, "%s[%d]" % (path, index), depth + 1)
    return value
