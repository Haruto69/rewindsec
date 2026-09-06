"""The candidate catalogue: every activity the engine may ever select.

A *candidate* is a piece of workplace activity the simulation could produce,
together with everything the engine needs to decide whether producing it now
would make sense. It is not content: the content is the authored record in
:mod:`rewindsec.workstation.content`, and a candidate points at it by id.

Every field is metadata the engine reads and the learner never sees. In
particular ``family`` and ``hostile`` are the two most sensitive values in the
whole system -- they are the answer key in one word -- and neither has any path
to a projection: candidates are never projected, and the world namespace their
state lives in is not one the projection names.

Ordering
--------
:func:`all_candidates` returns candidates sorted by id, always. Selection
iterates that order, so the outcome of a draw cannot depend on dictionary
insertion order, set iteration, ``PYTHONHASHSEED`` or the order in which
family modules happened to be imported.
"""

from rewindsec.training import policy
from rewindsec.training.candidate import Candidate
from rewindsec.training.families import background, bec, mfa, phishing, ransomware

__all__ = ["Candidate", "all_candidates", "by_id", "for_family",
           "candidates_by_family", "CATALOG_VERSION"]

CATALOG_VERSION = policy.CATALOG_VERSION


def _collect():
    entries = []
    for module in (background, bec, mfa, phishing, ransomware):
        entries.extend(module.candidates())
    ids = [entry.candidate_id for entry in entries]
    if len(set(ids)) != len(ids):
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        raise ValueError("duplicate candidate id(s): %s" % ", ".join(duplicates))
    return tuple(sorted(entries, key=lambda entry: entry.candidate_id))


#: Built once at import and never mutated. Immutable authored definition, in
#: exactly the same sense as the content index.
_ALL = _collect()
_BY_ID = {entry.candidate_id: entry for entry in _ALL}
_BY_FAMILY = {}
for _entry in _ALL:
    _BY_FAMILY.setdefault(_entry.family, []).append(_entry)
_BY_FAMILY = {family: tuple(entries) for family, entries in _BY_FAMILY.items()}


def all_candidates():
    """Every candidate, sorted by id. The only iteration order there is."""
    return _ALL


def by_id(candidate_id):
    return _BY_ID.get(candidate_id)


def for_family(family):
    """This family's candidates, sorted by id."""
    return _BY_FAMILY.get(family, ())


def candidates_by_family():
    """``{family: candidates}`` with families in the authored fixed order."""
    return {family: for_family(family) for family in policy.FAMILIES}
