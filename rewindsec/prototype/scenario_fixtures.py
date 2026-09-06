"""Compatibility view of the authored scenario content.

See :mod:`rewindsec.prototype.world_fixtures` for why this indirection exists.
The content now lives in :mod:`rewindsec.workstation.content.scenario`.
"""

from rewindsec.workstation.content.scenario import *  # noqa: F401,F403
from rewindsec.workstation.content.scenario import (  # noqa: F401
    CADENCE, CONSEQUENCE_CHAINS, CONSEQUENCE_MAIL, DECISIONS, DEMO_WEIGHTS,
    FOCUS_OPTIONS, MODES, SAFER_ALTERNATIVES, SCORE_DIMENSIONS, TASKS,
    TIMELINES)
