"""Identifier minting for administrative records.

Two rules, and they are the whole module:

1. **Never the simulation's randomness.** A session's named RNG streams
   (``threat``, ``background``, ``timing``, ``content_variation``, ...) decide
   what happens *inside* the simulation. Drawing an administrative id from one
   would make the simulation's future depend on how many students a trainer
   happened to create, which is precisely the coupling
   :mod:`rewindsec.core.rng` exists to prevent. Administrative ids come from
   :mod:`secrets`, or are derived with SHA-256 from something already stable.

2. **Never ``hash()``.** Python's built-in hash is salted per process, so an
   id derived from it would not survive a restart -- the same defect
   :mod:`rewindsec.domain.identifiers` already documents for the domain's own
   derived ids.

Every id produced here satisfies
:func:`rewindsec.domain.identifiers.validate_identity`'s charset, so an
administrative id can be stored in a session's ``learner_ref`` or in a world
value without a second vocabulary.
"""

import hashlib
import secrets

from rewindsec.domain.identifiers import validate_identity

__all__ = ["IdSource", "SecretsIdSource", "SequenceIdSource",
           "derive_student_id", "STUDENT_ID_LABEL", "ENROLLMENT_CODE_BYTES"]

#: Bytes of entropy in an enrolment code. 16 bytes -- 128 bits -- so guessing
#: one is not an attack this system has to defend against with rate limiting,
#: and the code can be quoted to a learner as an ordinary opaque string.
ENROLLMENT_CODE_BYTES = 16

#: Domain-separation label for a student id derived from a learner reference.
#: Distinct from every label :mod:`rewindsec.domain.identifiers` uses, so a
#: derived student id can never collide with a derived action or event id.
STUDENT_ID_LABEL = "rewindsec2/management-student-id/v1"

#: Hex characters kept from a derivation. 16 bytes of a SHA-256 digest.
_DERIVED_LENGTH = 24


class IdSource(object):
    """How this deployment mints a brand-new administrative id.

    An object rather than a bare function so a test can hand the management
    service a deterministic source and get reproducible ids, exactly as
    :class:`~rewindsec.workstation.seeds.FixedSeedSource` already does for
    session seeds.
    """

    def new_id(self, prefix):
        raise NotImplementedError

    def new_code(self, prefix="enr"):
        """A single-use secret, not an identifier.

        Separate from :meth:`new_id` because the two have different jobs and
        must not accidentally share a generator: an id is allowed to be
        guessable and appears in URLs and logs, and a code must not be either.
        A deterministic test source overrides this too, so a suite never has
        to read a random code back out of a database to use it.
        """
        return self.new_id(prefix)


class SecretsIdSource(IdSource):
    """The production source: cryptographically random, never the session RNG."""

    def new_id(self, prefix):
        return validate_identity("%s-%s" % (prefix, secrets.token_hex(8)),
                                 "%s id" % prefix)

    def new_code(self, prefix="enr"):
        return validate_identity(
            "%s-%s" % (prefix, secrets.token_hex(ENROLLMENT_CODE_BYTES)),
            "%s code" % prefix)


class SequenceIdSource(IdSource):
    """A deterministic source for tests. Counts per prefix, from one."""

    def __init__(self):
        self._counters = {}

    def new_id(self, prefix):
        nth = self._counters.get(prefix, 0) + 1
        self._counters[prefix] = nth
        return validate_identity("%s-%08d" % (prefix, nth), "%s id" % prefix)

    def new_code(self, prefix="enr"):
        return self.new_id("%s-code" % prefix)


def derive_student_id(learner_ref):
    """The stable student id for a server-minted learner reference.

    Used only when a learner reference arrives with no student bound to it and
    one has to be provisioned. Deriving rather than minting means the same
    reference always resolves to the same student id -- so a lost binding row
    is recoverable, and a re-provision cannot silently split one person's
    history across two records.
    """
    learner_ref = validate_identity(learner_ref, "learner_ref")
    material = "%s|%s" % (STUDENT_ID_LABEL, learner_ref)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return validate_identity("stu-%s" % digest[:_DERIVED_LENGTH], "student id")
