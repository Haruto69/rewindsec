"""Bind generated content to the one RewindSec fictional organisation.

Architecture Spec v1.1 (Batch 4) S44: generated content must reference
synthetic employees, departments, vendors, domains and document names that
are internally consistent with the rest of the product's fictional world --
never a contextless, isolated message.

Northbridge Systems (and its people, vendors and domains) already exists as
the one fictional organisation the whole of RewindSec 2.0 is set in --
:mod:`rewindsec.workstation.content.world`. This module reads that same
authored world rather than inventing a second one, so a generated document
referencing "the vendor" or "the finance approver" names the same entity the
rest of the workstation already knows about.
"""

from rewindsec.workstation.content import world as workplace

__all__ = ["organization", "learner", "vendor", "employee_by_role", "bind_fields"]


def organization():
    return dict(workplace.ORGANIZATION)


def learner():
    return dict(workplace.LEARNER)


def vendor():
    """The one fictional external vendor already used throughout the world:
    Calderwood Facilities Ltd, referenced by the authored invoice/BEC content."""
    for contact in workplace.DIRECTORY:
        if contact.get("kind") == "vendor":
            return dict(contact)
    return None


def employee_by_role(role_substring):
    """The first directory entry whose authored role mentions *role_substring*."""
    for contact in workplace.DIRECTORY:
        if role_substring.lower() in str(contact.get("role", "")).lower():
            return dict(contact)
    return None


def bind_fields(template, **fields):
    """Fill ``{name}``-style placeholders in *template* from *fields*.

    A plain ``str.format_map`` wrapper with one addition: an unresolved
    placeholder raises rather than silently leaving ``{stray}`` in learner-
    facing text, which would otherwise look like a template-engine bug on
    screen rather than failing where the mistake was made.
    """
    class _Strict(dict):
        def __missing__(self, key):
            raise KeyError("unbound placeholder %r in synthetic content template" % key)
    return template.format_map(_Strict(fields))
