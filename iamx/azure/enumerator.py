"""
Azure Permission Enumerator

This module provides functionality to enumerate Azure RBAC permissions
by testing which API operations the provided credentials can perform.
"""

import logging
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

try:
    from azure.identity import (
        ClientSecretCredential,
        DefaultAzureCredential,
        InteractiveBrowserCredential,
    )
    from azure.core.credentials import AccessToken
    from azure.mgmt.resource import SubscriptionClient
    import requests

    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False


class AzureEnumerator:
    """
    Azure Permission Enumerator.

    Enumerates Azure RBAC permissions by testing which API operations
    the provided credentials can perform.
    """

    MAX_THREADS = 10
    AZURE_MANAGEMENT_URL = "https://management.azure.com"

    def __init__(
        self,
        subscription_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        access_token: Optional[str] = None,
        resource_group: Optional[str] = None,
        verbose: bool = False,
    ):
        """
        Initialize the Azure Enumerator.

        Args:
            subscription_id: Azure Subscription ID
            tenant_id: Azure AD Tenant ID
            client_id: Azure AD Application (Client) ID
            client_secret: Azure AD Client Secret
            access_token: Pre-obtained access token
            resource_group: Optional resource group to test against
            verbose: Enable verbose logging
        """
        if not AZURE_AVAILABLE:
            raise ImportError(
                "Azure SDK not installed. Install with: pip install azure-identity azure-mgmt-resource requests"
            )

        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.resource_group = resource_group
        self.verbose = verbose

        self._credential = None
        self._token = None
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(process)d - [%(levelname)s] %(message)s",
        )

        # Suppress Azure SDK verbose logging
        logging.getLogger("azure").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)

        self.logger = logging.getLogger(__name__)

    def _get_credential(self) -> Any:
        """
        Get or create Azure credentials.

        Returns:
            Azure credential object
        """
        if self._credential is not None:
            return self._credential

        if self.access_token:
            # Use a simple token credential wrapper
            self._credential = _StaticTokenCredential(self.access_token)
        elif self.client_id and self.client_secret and self.tenant_id:
            # Service principal authentication
            self._credential = ClientSecretCredential(
                tenant_id=self.tenant_id,
                client_id=self.client_id,
                client_secret=self.client_secret,
            )
        else:
            # Try default credential chain
            self._credential = DefaultAzureCredential()

        return self._credential

    def _get_access_token(self) -> str:
        """
        Get an access token for Azure Management API.

        Returns:
            Access token string
        """
        if self._token:
            return self._token

        if self.access_token:
            self._token = self.access_token
        else:
            credential = self._get_credential()
            token = credential.get_token("https://management.azure.com/.default")
            self._token = token.token

        return self._token

    def _discover_subscription(self) -> Optional[str]:
        """
        Discover subscription ID if not provided.

        Returns:
            Subscription ID or None
        """
        if self.subscription_id:
            return self.subscription_id

        try:
            credential = self._get_credential()
            sub_client = SubscriptionClient(credential)

            # Get first available subscription
            for sub in sub_client.subscriptions.list():
                self.logger.info(f"Discovered subscription: {sub.display_name} ({sub.subscription_id})")
                return sub.subscription_id

        except Exception as e:
            self.logger.error(f"Failed to discover subscription: {e}")

        return None

    def enumerate(self) -> Dict[str, Any]:
        """
        Enumerate Azure permissions.

        Returns:
            Dictionary containing identity info and discovered permissions.
        """
        results: Dict[str, Any] = {
            "identity": {},
            "permissions": {},
            "errors": [],
        }

        self.logger.info("Starting Azure permission enumeration")

        try:
            # Get identity information
            identity_info = self._get_identity_info()
            results["identity"] = identity_info

            # Discover subscription if needed
            subscription_id = self._discover_subscription()
            if not subscription_id:
                error_msg = "No subscription ID provided and could not discover one"
                self.logger.error(error_msg)
                results["errors"].append(error_msg)
                return results

            self.subscription_id = subscription_id
            results["identity"]["subscription_id"] = subscription_id

            # Get role assignments for the identity
            role_info = self._get_role_assignments()
            results["permissions"]["role_assignments"] = role_info

            # Brute-force API operations
            bruteforce_results = self._enumerate_using_bruteforce()
            results["permissions"]["api_operations"] = bruteforce_results

        except Exception as e:
            error_msg = f"Enumeration failed: {str(e)}"
            self.logger.error(error_msg)
            results["errors"].append(error_msg)

        return results

    def _get_identity_info(self) -> Dict[str, Any]:
        """
        Get information about the current identity.

        Returns:
            Dictionary with identity information
        """
        identity: Dict[str, Any] = {}

        try:
            token = self._get_access_token()

            # Decode JWT to get identity info (without verification)
            import base64
            import json

            # Split the token and decode the payload
            parts = token.split(".")
            if len(parts) >= 2:
                # Add padding if needed
                payload = parts[1]
                padding = 4 - len(payload) % 4
                if padding != 4:
                    payload += "=" * padding

                decoded = base64.urlsafe_b64decode(payload)
                claims = json.loads(decoded)

                identity["object_id"] = claims.get("oid", "")
                identity["tenant_id"] = claims.get("tid", "")
                identity["app_id"] = claims.get("appid", claims.get("azp", ""))
                identity["upn"] = claims.get("upn", claims.get("unique_name", ""))
                identity["name"] = claims.get("name", "")

                self.logger.info(f"Identity: {identity.get('upn') or identity.get('app_id', 'Unknown')}")

        except Exception as e:
            self.logger.debug(f"Could not decode token: {e}")

        return identity

    def _get_role_assignments(self) -> List[Dict[str, Any]]:
        """
        Get role assignments for the current identity.

        Returns:
            List of role assignments
        """
        assignments: List[Dict[str, Any]] = []

        try:
            token = self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            # Get role assignments at subscription level
            url = (
                f"{self.AZURE_MANAGEMENT_URL}/subscriptions/{self.subscription_id}"
                f"/providers/Microsoft.Authorization/roleAssignments"
                f"?api-version=2022-04-01"
            )

            response = requests.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                for assignment in data.get("value", []):
                    props = assignment.get("properties", {})
                    assignments.append({
                        "id": assignment.get("id", ""),
                        "role_definition_id": props.get("roleDefinitionId", ""),
                        "principal_id": props.get("principalId", ""),
                        "scope": props.get("scope", ""),
                    })
                self.logger.info(f"Found {len(assignments)} role assignments")
            else:
                self.logger.debug(f"Could not get role assignments: {response.status_code}")

        except Exception as e:
            self.logger.debug(f"Error getting role assignments: {e}")

        return assignments

    def _enumerate_using_bruteforce(self) -> Dict[str, Any]:
        """
        Enumerate permissions by testing API operations.

        Returns:
            Dictionary of successful API operations
        """
        results: Dict[str, Any] = {}

        try:
            from iamx.azure.operations import AZURE_OPERATIONS
        except ImportError:
            self.logger.warning(
                "Azure operations not generated. Run 'iamx generate azure' first."
            )
            return results

        self.logger.info("Starting API operation brute-force enumeration")

        # Generate test cases
        test_cases = list(self._generate_test_cases(AZURE_OPERATIONS))
        total_tests = len(test_cases)

        self.logger.info(f"Running {total_tests} API tests across {len(AZURE_OPERATIONS)} providers")

        # Run tests in parallel
        with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
            future_to_test = {
                executor.submit(self._check_operation, provider, operation): (provider, operation)
                for provider, operation in test_cases
            }

            completed = 0
            for future in as_completed(future_to_test):
                completed += 1
                if completed % 100 == 0:
                    self.logger.info(f"Progress: {completed}/{total_tests} tests completed")

                result = future.result()
                if result:
                    key, response = result
                    results[key] = response

        self.logger.info(f"Brute-force complete. Found {len(results)} working API operations.")
        return results

    def _generate_test_cases(
        self, operations: Dict[str, List[Dict[str, Any]]]
    ) -> List[Tuple[str, Dict[str, Any]]]:
        """
        Generate randomized test cases.

        Args:
            operations: Dictionary of operations by provider

        Yields:
            Tuples of (provider_name, operation)
        """
        providers = list(operations.keys())
        random.shuffle(providers)

        for provider in providers:
            ops = list(operations[provider])
            random.shuffle(ops)

            for op in ops:
                # Skip operations that require additional parameters
                if op.get("requires_params", False):
                    continue
                yield provider, op

    def _check_operation(
        self, provider: str, operation: Dict[str, Any]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        """
        Check if a specific API operation is permitted.

        Args:
            provider: Resource provider name
            operation: Operation details

        Returns:
            Tuple of (key, response) if successful, None otherwise
        """
        try:
            token = self._get_access_token()
            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            # Build the URL
            path = operation["path"]
            path = path.replace("{subscriptionId}", self.subscription_id)

            if self.resource_group:
                path = path.replace("{resourceGroupName}", self.resource_group)
            elif "{resourceGroupName}" in path:
                # Skip resource group operations if no resource group specified
                return None

            # Use the latest API version
            versions = operation.get("versions", [])
            api_version = versions[0] if versions else "2023-01-01"

            url = f"{self.AZURE_MANAGEMENT_URL}{path}?api-version={api_version}"

            self.logger.debug(f"Testing: {operation['method']} {path}")

            response = requests.request(
                method=operation["method"],
                url=url,
                headers=headers,
                timeout=10,
            )

            if response.status_code == 200:
                key = f"{provider}.{operation['operation_id']}"
                self.logger.info(f"-- {key} worked!")
                return key, {
                    "path": path,
                    "method": operation["method"],
                    "status_code": response.status_code,
                }
            elif response.status_code == 403:
                # Access denied - no permission
                return None
            elif response.status_code == 404:
                # Resource not found - but we might have permission
                # This could mean the resource doesn't exist, not that we lack permission
                return None
            else:
                self.logger.debug(
                    f"Unexpected status {response.status_code} for {operation['operation_id']}"
                )
                return None

        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            self.logger.debug(f"Error testing {operation['operation_id']}: {e}")
            return None


class _StaticTokenCredential:
    """Simple credential class that returns a static token."""

    def __init__(self, token: str):
        self.token = token

    def get_token(self, *scopes: str, **kwargs: Any) -> "AccessToken":
        """Return the static token."""
        # AccessToken expects (token, expires_on)
        # Set a far future expiry since we don't know the actual expiry
        return AccessToken(self.token, 9999999999)
