"""The :class:`Candidate` value object.

Kept in its own module so the family modules can build candidates without
importing :mod:`rewindsec.training.catalog`, which imports *them*. A cycle
there would be resolvable with a late import, but a value object that every
layer can depend on is simply the right shape.
"""

__all__ = ["Candidate"]


class Candidate(object):
    """One selectable piece of workplace activity, and its preconditions."""

    __slots__ = ("candidate_id", "family", "activity", "prerequisites",
                 "max_occurrences", "cooldown_ms", "weight", "delivery",
                 "content_ref", "hostile", "requires_network", "focus_only",
                 "delivers_mail", "streams")

    def __init__(self, candidate_id, family, activity, delivery, content_ref,
                 prerequisites=(), max_occurrences=1, cooldown_ms=0, weight=10,
                 hostile=False, requires_network=True, focus_only=None,
                 delivers_mail=None, streams=("threat_selection",)):
        #: Stable internal identity. Persisted in engine state, so renaming one
        #: is a catalogue-version change, not a refactor.
        self.candidate_id = candidate_id
        self.family = family
        #: What kind of thing arrives: ``"mail"``, ``"mfa"``, ``"message"``,
        #: ``"task"``, ``"notification"``. Behavioural, never a classification.
        self.activity = activity
        #: Which adapter in :mod:`rewindsec.training.delivery` materialises it.
        self.delivery = delivery
        #: The authored content id the adapter resolves.
        self.content_ref = content_ref
        self.prerequisites = tuple(prerequisites)
        #: ``None`` means "may recur without limit"; the cooldown still applies.
        self.max_occurrences = max_occurrences
        #: Per-candidate cooldown, on top of the family cooldown.
        self.cooldown_ms = cooldown_ms
        #: Relative weight within its family once eligible.
        self.weight = weight
        #: Authored ground truth. Read by the engine's trace and by nothing
        #: that can reach a browser.
        self.hostile = bool(hostile)
        #: Whether delivering this requires the workstation to be online.
        self.requires_network = bool(requires_network)
        #: ``None``, or the tuple of focus ids under which this candidate may
        #: be selected at all. Distinct from weighting: this is a hard gate.
        self.focus_only = tuple(focus_only) if focus_only else None
        #: The mail id this candidate delivers, if any -- used to make
        #: "already in the mailbox" an eligibility fact rather than a surprise.
        self.delivers_mail = delivers_mail
        #: Which named RNG streams this candidate's delivery may consume.
        #: Declared so the stream partition is inspectable from the catalogue
        #: rather than only from the code that happens to draw.
        self.streams = tuple(streams)

    @property
    def is_primary(self):
        """Whether this is a *primary* arrival rather than ambient activity.

        Architecture S45's distinction, in one predicate. A message or an
        approval request is something the learner is expected to deal with; a
        line in the team channel or a storage notice is the room they are
        sitting in. It matters in exactly one place -- Practice will not put a
        second primary arrival on a learner who has not finished with the
        first, but a Practice session in which nothing at all happens until
        the learner clicks is not learner-paced, it is dead.
        """
        return self.activity in ("mail", "mfa")

    def __repr__(self):
        return "Candidate(%r, family=%r, activity=%r)" % (
            self.candidate_id, self.family, self.activity)
