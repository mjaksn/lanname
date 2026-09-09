"""lanname harness: a window for exercising lanname against a live network.

Where the poker tool beside it crafts the replies lanname parses, this drives
the package itself: a resolver built from every argument its constructor takes,
addresses asked about on a repeating tick so that the first miss and the later
name are both visible, the counters and the observed hosts as they move, the
module level ceilings, the two probe functions on their own, and the records
the package logs.

:mod:`lanname_harness.session` holds all of that and imports no Qt, so a
harness or a test can drive a resolver the same way without a display.
"""

from .session import Options, Session, Watch

__version__ = "0.1.0"

__all__ = [
    "Options",
    "Session",
    "Watch",
    "__version__",
]
