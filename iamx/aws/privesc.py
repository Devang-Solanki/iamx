import json
from pathlib import Path
from typing import Any

_DATA_FILE = Path(__file__).parent / "data" / "privesc_paths.json"


def _load_paths() -> list[dict[str, Any]]:
    with open(_DATA_FILE) as f:
        return json.load(f)


def _snake_to_pascal(name: str) -> str:
    return "".join(word.capitalize() for word in name.split("_"))


def _parse_statements(doc: Any, permissions: set[str]) -> None:
    """Extract Allow actions from a policy document into the permissions set."""
    if not isinstance(doc, dict):
        return
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            permissions.add(action)


def _extract_from_account_details(
    data: dict[str, Any], identity: dict[str, Any], permissions: set[str]
) -> None:
    """
    Parse only the current principal's policies from get_account_authorization_details.

    Walks user inline policies, user attached managed policies, group inline policies,
    and group attached managed policies — scoped to the current user or role only.
    """
    # Build a lookup of managed policy ARN -> default version document
    policy_docs: dict[str, Any] = {}
    for policy in data.get("Policies", []):
        arn = policy.get("PolicyArn", "")
        for version in policy.get("PolicyVersionList", []):
            if version.get("IsDefaultVersion"):
                policy_docs[arn] = version.get("Document", {})
                break

    user_name = identity.get("user_name")
    principal_arn = identity.get("arn", "")

    # --- User path ---
    if user_name and ":user/" in principal_arn:
        for user in data.get("UserDetailList", []):
            if user.get("UserName") != user_name:
                continue

            # User inline policies
            for inline in user.get("UserPolicyList", []):
                _parse_statements(inline.get("PolicyDocument", {}), permissions)

            # User attached managed policies
            for attached in user.get("AttachedManagedPolicies", []):
                doc = policy_docs.get(attached.get("PolicyArn", ""))
                if doc:
                    _parse_statements(doc, permissions)

            # Group policies for the user's groups
            user_groups = set(user.get("GroupList", []))
            for group in data.get("GroupDetailList", []):
                if group.get("GroupName") not in user_groups:
                    continue
                for inline in group.get("GroupPolicyList", []):
                    _parse_statements(inline.get("PolicyDocument", {}), permissions)
                for attached in group.get("AttachedManagedPolicies", []):
                    doc = policy_docs.get(attached.get("PolicyArn", ""))
                    if doc:
                        _parse_statements(doc, permissions)
            break

    # --- Role path ---
    elif ":assumed-role/" in principal_arn or ":role/" in principal_arn:
        # Extract role name from ARN: arn:aws:iam::id:role/RoleName or assumed-role/RoleName/session
        role_name = None
        parts = principal_arn.split("/")
        if len(parts) >= 2:
            role_name = parts[1]

        if role_name:
            for role in data.get("RoleDetailList", []):
                if role.get("RoleName") != role_name:
                    continue
                for inline in role.get("RolePolicyList", []):
                    _parse_statements(inline.get("PolicyDocument", {}), permissions)
                for attached in role.get("AttachedManagedPolicies", []):
                    doc = policy_docs.get(attached.get("PolicyArn", ""))
                    if doc:
                        _parse_statements(doc, permissions)
                break


def extract_permissions(results: dict[str, Any]) -> set[str]:
    """
    Build a flat set of IAM permissions (service:Action format) from enumeration results,
    scoped strictly to the current principal.

    Sources:
    - Brute-force successful calls: "iam.list_users" -> "iam:ListUsers"
    - IAM policy documents: only policies attached to the current user/role
    """
    permissions: set[str] = set()

    # Brute-force results: "service.method_name" -> "service:MethodName"
    for key in results.get("permissions", {}).get("bruteforce", {}):
        if "." in key:
            service, method = key.split(".", 1)
            permissions.add(f"{service}:{_snake_to_pascal(method)}")

    # IAM policy documents — scoped to current principal only
    iam_data = results.get("permissions", {}).get("iam", {})
    account_details = iam_data.get("get_account_authorization_details")
    identity = results.get("identity", {})

    if account_details:
        _extract_from_account_details(account_details, identity, permissions)

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
