"""CWE long-name lookup table for user-facing output.

Only covers CWEs in the Phase 1 active set. Extend as agents are added.
"""

CWE_LONG_NAMES: dict[str, str] = {
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-1336": "Improper Neutralization of Special Elements Used in a Template Engine",
}


def long_name(cwe_id: str) -> str:
    """Return the long name for a CWE id, or the id itself if unknown."""
    return CWE_LONG_NAMES.get(cwe_id, cwe_id)
