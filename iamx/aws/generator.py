"""
AWS Bruteforce Test Generator

This module generates bruteforce test definitions from:
1. AWS SDK JS API definitions (legacy method)
2. IAM Dataset JSON from https://github.com/iann0036/iam-dataset (recommended)
"""

import json
import os
import re
import urllib.request
from typing import Any, Dict, List, Optional, Set


# Operations that are safe to call (read-only)
OPERATION_PREFIXES: Set[str] = {
    "list_",
    "describe_",
    "get_",
}

# Operations to blacklist (known to cause issues)
BLACKLIST_OPERATIONS: Set[str] = {
    "get_apis",
    "get_bucket_notification",
    "get_bucket_notification_configuration",
    "list_web_ac_ls",
    "get_hls_streaming_session_url",
    "describe_scaling_plans",
    "list_certificate_authorities",
    "list_event_sources",
    "get_geo_location",
    "get_checker_ip_ranges",
    "list_geo_locations",
    "list_public_keys",
    # Known to cause issues with certain accounts
    "describe_stacks",
    "describe_service_errors",
    "describe_application_versions",
    "describe_applications",
    "describe_environments",
    "describe_events",
    "list_available_solution_stacks",
    "list_platform_versions",
}

# IAM Dataset URL
IAM_DATASET_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/map.json"


def to_underscore(name: str) -> str:
    """
    Convert CamelCase to snake_case.

    Args:
        name: CamelCase string

    Returns:
        snake_case string
    """
    s1 = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def is_safe_operation(operation_name: str) -> bool:
    """
    Check if an operation is safe (read-only).

    Args:
        operation_name: Operation name in snake_case

    Returns:
        True if safe, False otherwise
    """
    for prefix in OPERATION_PREFIXES:
        if operation_name.startswith(prefix):
            return True
    return False


def download_iam_dataset(url: str = IAM_DATASET_URL) -> Dict[str, Any]:
    """
    Download the IAM dataset JSON from GitHub.

    Args:
        url: URL to the IAM dataset JSON

    Returns:
        Parsed JSON data
    """
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"Downloading IAM dataset from {url}")
    
    with urllib.request.urlopen(url) as response:
        data = response.read().decode("utf-8")
        return json.loads(data)


def generate_from_iam_dataset(
    dataset: Optional[Dict[str, Any]] = None,
    dataset_url: str = IAM_DATASET_URL,
    output_file: str = "iamx/aws/bruteforce_tests.py",
    verbose: bool = False,
) -> int:
    """
    Generate bruteforce test definitions from IAM dataset.

    The IAM dataset has the structure:
    {
        "sdk_method_iam_mappings": {
            "ServiceName.MethodName": [...],
            ...
        },
        "sdk_permissionless_actions": [...]
    }

    Args:
        dataset: Pre-loaded dataset (optional)
        dataset_url: URL to download dataset from
        output_file: Output file path
        verbose: Enable verbose output

    Returns:
        Number of services processed
    """
    import logging
    logger = logging.getLogger(__name__)

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Download or use provided dataset
    if dataset is None:
        dataset = download_iam_dataset(dataset_url)

    sdk_mappings = dataset.get("sdk_method_iam_mappings", {})
    permissionless_actions = dataset.get("sdk_permissionless_actions", [])

    logger.info(f"Found {len(sdk_mappings)} SDK method mappings")
    logger.info(f"Found {len(permissionless_actions)} permissionless actions")

    bruteforce_tests: Dict[str, List[str]] = {}

    # Process SDK method mappings
    for method_key in sdk_mappings.keys():
        # Method key format: "ServiceName.MethodName"
        parts = method_key.split(".")
        if len(parts) != 2:
            logger.debug(f"Skipping invalid method key: {method_key}")
            continue

        service_name, method_name = parts
        
        # Convert to boto3 style names
        service_name_lower = service_name.lower()
        operation_name = to_underscore(method_name)

        # Only include safe operations
        if not is_safe_operation(operation_name):
            continue

        # Skip blacklisted operations
        if operation_name in BLACKLIST_OPERATIONS:
            continue

        # Add to bruteforce tests
        if service_name_lower not in bruteforce_tests:
            bruteforce_tests[service_name_lower] = []

        if operation_name not in bruteforce_tests[service_name_lower]:
            bruteforce_tests[service_name_lower].append(operation_name)

    # Process permissionless actions (these are always safe to call)
    for action in permissionless_actions:
        parts = action.split(".")
        if len(parts) != 2:
            continue

        service_name, method_name = parts
        service_name_lower = service_name.lower()
        operation_name = to_underscore(method_name)

        if service_name_lower not in bruteforce_tests:
            bruteforce_tests[service_name_lower] = []

        if operation_name not in bruteforce_tests[service_name_lower]:
            bruteforce_tests[service_name_lower].append(operation_name)

    # Sort operations within each service
    for service in bruteforce_tests:
        bruteforce_tests[service] = sorted(list(set(bruteforce_tests[service])))

    # Generate output
    output_content = '''"""
AWS Bruteforce Tests

This file contains a dictionary of AWS services and their safe API operations
that can be called without required parameters. These are used for brute-force
permission enumeration.

Generated from IAM Dataset: https://github.com/iann0036/iam-dataset
"""

BRUTEFORCE_TESTS = '''

    output_content += json.dumps(bruteforce_tests, indent=4, sort_keys=True)
    output_content += "\n"

    # Write output file
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    with open(output_file, "w") as f:
        f.write(output_content)

    logger.info(f"Generated {len(bruteforce_tests)} service definitions to {output_file}")

    return len(bruteforce_tests)


def generate_bruteforce_tests(
    sdk_path: Optional[str] = None,
    output_file: str = "iamx/aws/bruteforce_tests.py",
    verbose: bool = False,
    use_iam_dataset: bool = True,
    dataset_url: str = IAM_DATASET_URL,
) -> int:
    """
    Generate bruteforce test definitions.

    This function supports two methods:
    1. From IAM Dataset (recommended, default)
    2. From AWS SDK JS API definitions (legacy)

    Args:
        sdk_path: Path to aws-sdk-js/apis directory (for legacy method)
        output_file: Output file path
        verbose: Enable verbose output
        use_iam_dataset: Use IAM dataset instead of SDK (default: True)
        dataset_url: URL to IAM dataset JSON

    Returns:
        Number of services processed
    """
    if use_iam_dataset or sdk_path is None:
        return generate_from_iam_dataset(
            dataset_url=dataset_url,
            output_file=output_file,
            verbose=verbose,
        )
    else:
        return generate_from_sdk(
            sdk_path=sdk_path,
            output_file=output_file,
            verbose=verbose,
        )


def generate_from_sdk(
    sdk_path: str,
    output_file: str,
    verbose: bool = False,
) -> int:
    """
    Generate bruteforce test definitions from AWS SDK (legacy method).

    Args:
        sdk_path: Path to aws-sdk-js/apis directory
        output_file: Output file path
        verbose: Enable verbose output

    Returns:
        Number of services processed
    """
    import logging

    logger = logging.getLogger(__name__)

    if verbose:
        logging.basicConfig(level=logging.DEBUG)

    bruteforce_tests: Dict[str, List[str]] = {}

    for filename in os.listdir(sdk_path):
        if not filename.endswith(".min.json"):
            continue

        filepath = os.path.join(sdk_path, filename)

        try:
            with open(filepath, "r") as f:
                api_json = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Failed to parse {filename}: {e}")
            continue

        service_name = _extract_service_name(filename, api_json)

        if service_name is None:
            logger.debug(f"{filename} does not define a service name")
            continue

        operations = _extract_operations(api_json)

        if not operations:
            logger.debug(f"{service_name} has no safe operations")
            continue

        if service_name in bruteforce_tests:
            bruteforce_tests[service_name].extend(operations)
            bruteforce_tests[service_name] = list(set(bruteforce_tests[service_name]))
            bruteforce_tests[service_name].sort()
        else:
            bruteforce_tests[service_name] = operations

        logger.debug(f"Processed {service_name}: {len(operations)} operations")

    # Generate output
    output_content = '''"""
AWS Bruteforce Tests

This file contains a dictionary of AWS services and their safe API operations
that can be called without required parameters. These are used for brute-force
permission enumeration.

Generated from AWS SDK JS API definitions.
"""

BRUTEFORCE_TESTS = '''

    output_content += json.dumps(bruteforce_tests, indent=4, sort_keys=True)
    output_content += "\n"

    # Write output file
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    with open(output_file, "w") as f:
        f.write(output_content)

    logger.info(f"Generated {len(bruteforce_tests)} service definitions")

    return len(bruteforce_tests)


def _extract_service_name(filename: str, api_json: Dict[str, Any]) -> Optional[str]:
    """Extract service name from API definition."""
    try:
        endpoint = api_json["metadata"]["endpointPrefix"]
    except KeyError:
        return None

    endpoint = endpoint.replace("api.", "")
    endpoint = endpoint.replace("opsworks-cm", "opsworks")
    endpoint = endpoint.replace("acm-pca", "acm")

    return endpoint


def _extract_operations(api_json: Dict[str, Any]) -> List[str]:
    """Extract safe operations from API definition."""
    operations = []

    items = api_json.get("operations", {}).items()

    for operation_name, operation_data in items:
        operation_name = to_underscore(operation_name)

        if not is_safe_operation(operation_name):
            continue

        if operation_name in BLACKLIST_OPERATIONS:
            continue

        inputs = operation_data.get("input", None)

        if inputs is None:
            operations.append(operation_name)
            continue

        inputs_str = str(inputs)

        if "required" not in inputs_str:
            operations.append(operation_name)
            continue

    operations = list(set(operations))
    operations.sort()

    return operations
