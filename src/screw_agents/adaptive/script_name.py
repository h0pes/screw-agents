"""Shared script-name validation for the adaptive-scripts subsystem.

``SCRIPT_NAME_RE`` is the single source of truth for the allowlist regex.
Both ``_sign_script_bytes`` (engine-layer, T2) and ``staging.py``
(staging-layer, T1) import from here — one regex, one definition.

The ``\\A...\\Z`` anchors (instead of ``^...$``) are load-bearing: ``^``/``$``
in Python match the START/END OF LINE, not the start/end of the string, so a
name like ``"abc\\n"`` would pass ``^[a-z0-9][a-z0-9-]{2,62}$`` because ``$``
matches before the terminal newline. ``\\A``/``\\Z`` match the absolute
string boundaries regardless of embedded newlines (I-new-1 fix).

``USER_FACING_NAME_REGEX`` uses the familiar ``^...$`` notation that users
recognize from documentation and error messages; the internal match always
uses the precise ``SCRIPT_NAME_RE`` (``\\A...\\Z``) form.
"""

import re

__all__ = ["SCRIPT_NAME_RE", "USER_FACING_NAME_REGEX", "validate_script_name"]

# Anchored with \A...\Z so trailing newlines (and any other multi-line tricks)
# are rejected. Lowercase alphanum first char, then 2-62 chars of lowercase
# alphanum + dash. Total length 3-63 chars.
SCRIPT_NAME_RE = re.compile(r"\A[a-z0-9][a-z0-9-]{2,62}\Z")

# String constant for error messages shown to users. Keeps the familiar
# ^...$ notation users recognize from docs; the internal match uses SCRIPT_NAME_RE.
USER_FACING_NAME_REGEX = "^[a-z0-9][a-z0-9-]{2,62}$"


def validate_script_name(script_name: str) -> None:
    """Raise ``ValueError`` if ``script_name`` does not match the allowlist.

    Uses ``SCRIPT_NAME_RE`` (``\\A...\\Z`` anchors) for the match so that
    trailing newlines and other multi-line tricks are rejected (I-new-1).
    The error message uses ``USER_FACING_NAME_REGEX`` (``^...$``) because
    that is the notation users see in documentation.

    Args:
        script_name: Candidate script name to validate.

    Raises:
        ValueError: If ``script_name`` does not match ``SCRIPT_NAME_RE``.
    """
    if not SCRIPT_NAME_RE.match(script_name):
        raise ValueError(
            f"script_name {script_name!r} does not match "
            f"{USER_FACING_NAME_REGEX} "
            f"(3-63 chars, lowercase alnum + dash, must start with alnum)"
        )
