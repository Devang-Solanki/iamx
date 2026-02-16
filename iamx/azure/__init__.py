"""
Azure IAM Permission Enumeration Module

This module provides functionality to enumerate Azure RBAC permissions
by testing which API operations the provided credentials can perform.
"""

from iamx.azure.enumerator import AzureEnumerator

__all__ = ["AzureEnumerator"]
