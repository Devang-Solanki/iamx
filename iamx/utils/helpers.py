"""
Helper utilities for Brute IAM.
"""

from datetime import datetime
from typing import Any, Dict


def remove_metadata(response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove AWS response metadata from API response.

    Args:
        response: AWS API response dictionary

    Returns:
        Response with metadata removed
    """
    if not isinstance(response, dict):
        return response

    # Create a copy to avoid modifying the original
    result = {}

    for key, value in response.items():
        # Skip metadata keys
        if key in ("ResponseMetadata", "HTTPHeaders", "RetryAttempts"):
            continue

        # Recursively process nested dictionaries
        if isinstance(value, dict):
            result[key] = remove_metadata(value)
        elif isinstance(value, list):
            result[key] = [
                remove_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value

    return result


def json_encoder(obj: Any) -> Any:
    """
    Custom JSON encoder for objects that aren't JSON serializable.

    Args:
        obj: Object to encode

    Returns:
        JSON-serializable representation
    """
    if isinstance(obj, datetime):
        return obj.isoformat()

    if hasattr(obj, "__dict__"):
        return obj.__dict__

    if hasattr(obj, "to_dict"):
        return obj.to_dict()

    # For bytes, decode to string
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.hex()

    # For sets, convert to list
    if isinstance(obj, set):
        return list(obj)

    # Default: convert to string
    return str(obj)


def chunk_list(lst: list, chunk_size: int) -> list:
    """
    Split a list into chunks of specified size.

    Args:
        lst: List to split
        chunk_size: Size of each chunk

    Returns:
        List of chunks
    """
    return [lst[i : i + chunk_size] for i in range(0, len(lst), chunk_size)]


def format_permission(service: str, action: str) -> str:
    """
    Format a permission string.

    Args:
        service: Service name
        action: Action name

    Returns:
        Formatted permission string
    """
    return f"{service}.{action}"


def parse_arn(arn: str) -> Dict[str, str]:
    """
    Parse an AWS ARN into its components.

    Args:
        arn: AWS ARN string

    Returns:
        Dictionary with ARN components
    """
    # ARN format: arn:partition:service:region:account-id:resource
    parts = arn.split(":")

    if len(parts) < 6:
        return {"raw": arn}

    return {
        "arn": arn,
        "partition": parts[1],
        "service": parts[2],
        "region": parts[3],
        "account_id": parts[4],
        "resource": ":".join(parts[5:]),
    }
