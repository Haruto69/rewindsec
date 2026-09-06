"""Deterministic weighted choice over an explicitly ordered sequence.

Small, and worth its own module because every property the engine claims about
reproducibility bottoms out here.

* **Order is an argument, not an accident.** Callers pass a list they have
  already sorted; nothing in this module iterates a dict, a set, or anything
  whose order depends on ``PYTHONHASHSEED``, insertion history or a database's
  row order.
* **One draw per decision.** The cumulative-weight walk consumes exactly one
  value from the stream, whatever the number of options -- so adding an option
  that ends up not being chosen still costs one draw and not zero or two, and
  the arithmetic is the same on every platform because it is all integers.
* **Zero-weight options cannot be chosen** but do not break the walk, and an
  all-zero or empty sequence returns ``None`` rather than drawing at all,
  because there was no decision to make.
"""

__all__ = ["weighted_choice", "roll_percent"]


def weighted_choice(stream, options):
    """Pick one ``(item, weight)`` pair. Consumes one draw, or none.

    *options* must already be in a deterministic order. Weights are integers;
    anything at or below zero is treated as ineligible for the pick.
    """
    entries = [(item, int(weight)) for item, weight in options if int(weight) > 0]
    if not entries:
        return None
    total = sum(weight for _, weight in entries)
    if total <= 0:
        return None
    # ``randrange(total)`` rather than ``randint``: a half-open range makes the
    # cumulative comparison below the obvious one, with no off-by-one to argue
    # about at either end.
    pick = stream.randrange(total)
    running = 0
    for item, weight in entries:
        running += weight
        if pick < running:
            return item
    # Unreachable: ``pick`` is strictly below ``total`` and ``running`` ends at
    # ``total``. Returning the last entry rather than falling off the end keeps
    # a future arithmetic mistake from becoming a ``None`` three layers away.
    return entries[-1][0]


def roll_percent(stream, threshold):
    """Whether a 1-100 draw lands at or below *threshold*. One draw, always.

    A threshold of zero still draws. That is deliberate: whether an event
    *could* have happened must not change how many values the stream has
    consumed, or a quiet pulse and a busy one would leave the generator in
    different places and two sessions with the same seed would diverge on the
    first uneventful minute.
    """
    return stream.randint(1, 100) <= int(threshold)
