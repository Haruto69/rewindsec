"""One module per threat family, plus one for ordinary work.

Each module here owns three things and no others:

* the **candidates** its family can contribute, declared as
  :class:`~rewindsec.training.catalog.Candidate` metadata over authored
  content;
* which of its authored consequence steps depend on the workstation being on
  the network, so containment can actually contain something;
* any family-specific synthetic content that has no home in the workstation's
  own content modules -- which in practice means short benign message and
  notification text, because everything a mailbox holds belongs in
  :mod:`rewindsec.workstation.content`.

What is deliberately *not* here is a family branch in the engine. The engine
never asks "which family is this?" in order to decide what to do; it selects a
candidate and calls the candidate's delivery adapter. That is what keeps the
alternative -- one long ``if phishing / elif ransomware / elif mfa / elif
bec`` -- from reappearing as the system grows.
"""

from rewindsec.training.candidate import Candidate

__all__ = ["background", "bec", "mfa", "phishing", "ransomware", "Candidate"]


def _candidate(candidate_id, family, **kwargs):
    """Build one candidate. A thin alias, kept so every family reads alike."""
    return Candidate(candidate_id, family, **kwargs)
