"""RewindSec 2.0 deterministic scoring: evidence, rubric, and results.

Pure Python. This package depends on :mod:`rewindsec.domain` types and on
carefully defined training/workstation content metadata (the authored
decision taxonomy in :mod:`rewindsec.workstation.content.scenario`); it
never imports Flask, SQLAlchemy, or anything UI-facing, and nothing in
:mod:`rewindsec.training` depends on it -- the dependency direction is
strictly workstation/debrief -> scoring -> domain + content metadata.

See :mod:`rewindsec.scoring.versions` for what "RewindSec 2.0 scoring" means
as a set of independently-versioned identifiers, and
:mod:`rewindsec.scoring.result` for the human-competence disclaimer every
result carries.
"""

from rewindsec.scoring.dimensions import DIMENSION_IDS
from rewindsec.scoring.evaluator import evaluate
from rewindsec.scoring.versions import (EVIDENCE_MODEL_VERSION, RUBRIC_VERSION,
                                        SCORING_VERSION)

__all__ = ["DIMENSION_IDS", "evaluate", "SCORING_VERSION", "RUBRIC_VERSION",
           "EVIDENCE_MODEL_VERSION"]
