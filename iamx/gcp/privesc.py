"""
GCP Privilege Escalation Detection

Checks a set of discovered GCP IAM permissions against known privilege
escalation paths from pathfinding.cloud.
"""

import json
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).parent / "data" / "privesc_paths.json"


def _load_paths() -> list[dict[str, Any]]:
    with open(_DATA_FILE) as f:
        return json.load(f)


def extract_permissions(results: dict[str, Any]) -> set[str]:
    """
    Build a flat set of granted GCP IAM permissions from enumeration results.

    GCP's testIamPermissions already returns exact permission strings
    (e.g. "iam.serviceAccounts.actAs"), so no translation is needed —
    unlike AWS, where bruteforce call names have to be mapped to
    service:Action form.
    """
    permissions = results.get("permissions", [])
    if isinstance(permissions, dict):
        # enumerate_by_service() groups permissions by service
        flat: set[str] = set()
        for perms in permissions.values():
            flat.update(perms)
        return flat
    return {p for p in permissions if isinstance(p, str)}


def check_privesc(permissions: set[str]) -> list[dict[str, Any]]:
    """
    Return privilege escalation paths achievable with the given permission set.

    Args:
        permissions: granted GCP IAM permissions (e.g. "iam.serviceAccounts.actAs")

    Returns:
        List of matching paths, each with id, name, category, description,
        and required_permissions.
    """
    matches = []
    for path in _load_paths():
        required = [p["permission"] for p in path.get("permissions", {}).get("required", [])]
        if not required:
            continue
        if all(perm in permissions for perm in required):
            matches.append(
                {
                    "id": path["id"],
                    "name": path["name"],
                    "category": path["category"],
                    "description": path["description"],
                    "required_permissions": required,
                }
            )
    return matches
