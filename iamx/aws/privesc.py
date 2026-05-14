import json
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).parent / "data" / "privesc_paths.json"


def _load_paths() -> list[dict[str, Any]]:
    with open(_DATA_FILE) as f:
        return json.load(f)


def _snake_to_pascal(name: str) -> str:
    return "".join(word.capitalize() for word in name.split("_"))


def _collect_statements(data: Any, statements: list[dict[str, Any]]) -> None:
    """Recursively collect all IAM policy Statement arrays from nested dicts."""
    if isinstance(data, dict):
        if "Statement" in data:
            stmt = data["Statement"]
            if isinstance(stmt, list):
                statements.extend(stmt)
            elif isinstance(stmt, dict):
                statements.append(stmt)
        for value in data.values():
            _collect_statements(value, statements)
    elif isinstance(data, list):
        for item in data:
            _collect_statements(item, statements)


def extract_permissions(results: dict[str, Any]) -> set[str]:
    """
    Build a flat set of IAM permissions (service:Action format) from enumeration results.

    Sources:
    - Brute-force successful calls: "iam.list_users" -> "iam:ListUsers"
    - IAM policy documents: parses Allow statements from any discovered policy docs
    """
    permissions: set[str] = set()

    # Brute-force results: "service.method_name" -> "service:MethodName"
    for key in results.get("permissions", {}).get("bruteforce", {}):
        if "." in key:
            service, method = key.split(".", 1)
            permissions.add(f"{service}:{_snake_to_pascal(method)}")

    # IAM policy documents
    statements: list[dict[str, Any]] = []
    _collect_statements(results.get("permissions", {}).get("iam", {}), statements)

    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            permissions.add(action)

    return permissions


def _matches(required: str, permissions: set[str]) -> bool:
    if required in permissions or "*" in permissions:
        return True
    service = required.split(":")[0]
    return f"{service}:*" in permissions


def check_privesc(permissions: set[str]) -> list[dict[str, Any]]:
    """
    Return privilege escalation paths achievable with the given permission set.

    Args:
        permissions: IAM permissions in "service:Action" format

    Returns:
        List of matching paths, each with id, name, category, description,
        required_permissions, and exploitation steps.
    """
    matches = []
    for path in _load_paths():
        required = [p["permission"] for p in path.get("permissions", {}).get("required", [])]
        if not required:
            continue
        if all(_matches(perm, permissions) for perm in required):
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
