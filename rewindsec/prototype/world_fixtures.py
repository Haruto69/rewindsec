"""Compatibility view of the authored workplace content.

The content itself moved to :mod:`rewindsec.workstation.content.world` in
Batch 2, because it is application content that a *session* is seeded from,
not presentation data owned by the UI prototype. The dependency direction has
to be

    prototype (HTTP/UI adapter)  ->  workstation (application)  ->  domain

and it would be backwards for the application layer to import the prototype
package to find out what a mail message is.

This module stays so that the prototype's own fixture assembly and its
guardrail suite keep one stable import path. It adds nothing and holds no
state of its own.
"""

from rewindsec.workstation.content.world import *  # noqa: F401,F403
from rewindsec.workstation.content.world import (  # noqa: F401
    AUTH_HISTORY, BROWSER_BOOKMARKS, BROWSER_HISTORY, BROWSER_HOME,
    BROWSER_PAGES, CONVERSATIONS, DIRECTORY, FILE_TREE, LEARNER, MAIL,
    MFA_PROMPTS, NOTES, OPENING_NOTIFICATIONS, ORGANIZATION)
