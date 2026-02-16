"""
Azure API Operations Generator

This module generates Azure API operation definitions from Azure REST API specs
for permission enumeration testing.
"""

import json
import logging
import re
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def generate_azure_operations(
    source_file: Optional[str] = None,
    source_url: Optional[str] = None,
    output_file: str = "iamx/azure/operations.py",
    verbose: bool = False,
    safe_only: bool = True,
) -> int:
    """
    Generate Azure API operations from Azure REST API specs.

    Args:
        source_file: Path to local JSON file with Azure API specs
        source_url: URL to download Azure API specs JSON
        output_file: Output Python file path
        verbose: Enable verbose logging
        safe_only: Only include safe (GET) operations

    Returns:
        Number of operations generated
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
    logger = logging.getLogger(__name__)

    # Load the Azure API specs
    if source_file:
        logger.info(f"Loading Azure API specs from file: {source_file}")
        with open(source_file, "r") as f:
            api_specs = json.load(f)
    elif source_url:
        logger.info(f"Downloading Azure API specs from: {source_url}")
        with urllib.request.urlopen(source_url, timeout=60) as response:
            api_specs = json.loads(response.read().decode("utf-8"))
    else:
        raise ValueError("Either source_file or source_url must be provided")

    # Parse the API specs and extract operations
    operations = _parse_azure_specs(api_specs, safe_only, logger)

    # Generate the Python file
    _write_operations_file(operations, output_file, logger)

    logger.info(f"Generated {len(operations)} Azure API operations")
    return len(operations)


def _parse_azure_specs(
    api_specs: Dict[str, Any], safe_only: bool, logger: logging.Logger
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Parse Azure API specs and extract operations.

    Args:
        api_specs: The Azure API specs dictionary
        safe_only: Only include GET operations
        logger: Logger instance

    Returns:
        Dictionary mapping resource providers to their operations
    """
    operations: Dict[str, List[Dict[str, Any]]] = {}

    for provider_name, provider_data in api_specs.items():
        if not isinstance(provider_data, dict):
            continue

        provider_ops: List[Dict[str, Any]] = []

        # Iterate through HTTP methods
        for method, endpoints in provider_data.items():
            # Skip non-GET methods if safe_only is True
            if safe_only and method.lower() != "get":
                continue

            if not isinstance(endpoints, dict):
                continue

            # Iterate through endpoints
            for endpoint_path, endpoint_data in endpoints.items():
                if not isinstance(endpoint_data, dict):
                    continue

                operation = {
                    "method": method.upper(),
                    "path": endpoint_path,
                    "operation_id": endpoint_data.get("operationId", ""),
                    "description": endpoint_data.get("description", ""),
                    "versions": endpoint_data.get("versions", []),
                    "client_hint": endpoint_data.get("clientHint", ""),
                }

                # Determine if this operation requires parameters
                operation["requires_params"] = _check_requires_params(endpoint_path)

                # Only include operations that don't require specific resource IDs
                # (subscription-level or resource-group-level list operations)
                if _is_enumerable_operation(endpoint_path, method):
                    provider_ops.append(operation)
                    logger.debug(
                        f"Added: {provider_name} - {method.upper()} {endpoint_path}"
                    )

        if provider_ops:
            operations[provider_name] = provider_ops
            logger.info(f"Provider {provider_name}: {len(provider_ops)} operations")

    return operations


def _check_requires_params(path: str) -> bool:
    """
    Check if an endpoint path requires specific parameters beyond subscription/resource group.

    Args:
        path: The API endpoint path

    Returns:
        True if requires additional parameters
    """
    # Count path parameters
    params = re.findall(r"\{([^}]+)\}", path)

    # Standard parameters that we can provide
    standard_params = {"subscriptionId", "resourceGroupName", "api-version"}

    # Check if there are any non-standard parameters
    for param in params:
        if param not in standard_params:
            return True

    return False


def _is_enumerable_operation(path: str, method: str) -> bool:
    """
    Determine if an operation is suitable for enumeration.

    We want operations that:
    - Are GET requests (read-only)
    - List resources at subscription or resource group level
    - Don't require specific resource names/IDs

    Args:
        path: The API endpoint path
        method: HTTP method

    Returns:
        True if operation is suitable for enumeration
    """
    if method.lower() != "get":
        return False

    # Patterns for enumerable operations
    enumerable_patterns = [
        # Subscription-level list operations
        r"^/subscriptions/\{subscriptionId\}/providers/[^/]+$",
        r"^/subscriptions/\{subscriptionId\}/providers/[^/]+/[^{]+$",
        # Resource group level list operations
        r"^/subscriptions/\{subscriptionId\}/resourceGroups/\{resourceGroupName\}/providers/[^/]+$",
        r"^/subscriptions/\{subscriptionId\}/resourceGroups/\{resourceGroupName\}/providers/[^/]+/[^{]+$",
        # Location-based list operations
        r"^/subscriptions/\{subscriptionId\}/providers/[^/]+/locations/\{[^}]+\}/[^{]+$",
    ]

    for pattern in enumerable_patterns:
        if re.match(pattern, path):
            return True

    # Also include paths that end with a list-like segment (no trailing parameter)
    # e.g., /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines
    if not path.endswith("}") and "/providers/" in path:
        # Count parameters - should only have subscriptionId and optionally resourceGroupName
        params = re.findall(r"\{([^}]+)\}", path)
        allowed_params = {"subscriptionId", "resourceGroupName", "location", "locationName"}
        extra_params = set(params) - allowed_params
        if not extra_params:
            return True

    return False


def _write_operations_file(
    operations: Dict[str, List[Dict[str, Any]]],
    output_file: str,
    logger: logging.Logger,
) -> None:
    """
    Write the operations to a Python file.

    Args:
        operations: Dictionary of operations by provider
        output_file: Output file path
        logger: Logger instance
    """
    total_ops = sum(len(ops) for ops in operations.values())

    content = f'''"""
Azure API Operations for Permission Enumeration

Auto-generated file containing Azure REST API operations for testing.
Generated: {datetime.now(timezone.utc).isoformat()}

Total providers: {len(operations)}
Total operations: {total_ops}
"""

from typing import Any, Dict, List

# Azure API operations organized by resource provider
# Each operation contains:
#   - method: HTTP method (GET for read-only)
#   - path: API endpoint path with placeholders
#   - operation_id: Azure operation identifier
#   - description: Operation description
#   - versions: Supported API versions
#   - requires_params: Whether additional parameters are needed

AZURE_OPERATIONS: Dict[str, List[Dict[str, Any]]] = {{
'''

    for provider_name in sorted(operations.keys()):
        provider_ops = operations[provider_name]
        content += f'    "{provider_name}": [\n'

        for op in provider_ops:
            content += "        {\n"
            content += f'            "method": "{op["method"]}",\n'
            content += f'            "path": "{op["path"]}",\n'
            content += f'            "operation_id": "{op["operation_id"]}",\n'
            content += f'            "description": {repr(op["description"])},\n'
            content += f'            "versions": {op["versions"]},\n'
            content += f'            "requires_params": {op["requires_params"]},\n'
            content += "        },\n"

        content += "    ],\n"

    content += "}\n"

    # Write the file
    with open(output_file, "w") as f:
        f.write(content)

    logger.info(f"Wrote {total_ops} operations to {output_file}")


def generate_from_iam_dataset(
    output_file: str = "iamx/azure/operations.py",
    verbose: bool = False,
    dataset_url: str = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/azure/map.json",
) -> int:
    """
    Generate Azure operations from the IAM Dataset repository.

    Args:
        output_file: Output Python file path
        verbose: Enable verbose logging
        dataset_url: URL to the Azure IAM dataset

    Returns:
        Number of operations generated
    """
    return generate_azure_operations(
        source_url=dataset_url,
        output_file=output_file,
        verbose=verbose,
        safe_only=True,
    )
