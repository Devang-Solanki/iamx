"""
GCP IAM Permission Enumerator

This module provides functionality to enumerate GCP IAM permissions
by testing which permissions the provided credentials have.
"""

import logging
from typing import Any, Dict, List, Optional

from iamx.gcp.permissions import GCP_PERMISSIONS


class GCPEnumerator:
    """
    GCP IAM Permission Enumerator.

    Enumerates GCP IAM permissions by testing which permissions
    the provided credentials have on a project.
    """

    # GCP API limits permissions per request to 100
    PERMISSIONS_CHUNK_SIZE = 100

    def __init__(
        self,
        project_id: str,
        credentials_file: Optional[str] = None,
        access_token: Optional[str] = None,
        verbose: bool = False,
    ):
        """
        Initialize the GCP Enumerator.

        Args:
            project_id: GCP Project ID
            credentials_file: Path to service account JSON key file
            access_token: Access token for authentication
            verbose: Enable verbose logging
        """
        self.project_id = project_id
        self.credentials_file = credentials_file
        self.access_token = access_token
        self.verbose = verbose

        self._setup_logging()
        self._credentials = None

    def _setup_logging(self) -> None:
        """Configure logging."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(process)d - [%(levelname)s] %(message)s",
        )
        self.logger = logging.getLogger(__name__)

    def _get_credentials(self) -> Any:
        """
        Get or create credentials.

        Returns:
            Google credentials object
        """
        if self._credentials is not None:
            return self._credentials

        if self.credentials_file:
            import google.oauth2.service_account

            self._credentials = (
                google.oauth2.service_account.Credentials.from_service_account_file(
                    self.credentials_file
                )
            )
        elif self.access_token:
            from google.oauth2.credentials import Credentials

            self._credentials = Credentials(token=self.access_token)
        else:
            raise ValueError(
                "Either credentials_file or access_token must be provided"
            )

        return self._credentials

    def enumerate(self) -> Dict[str, Any]:
        """
        Enumerate all GCP IAM permissions.

        Returns:
            Dictionary containing identity info and discovered permissions.
        """
        results: Dict[str, Any] = {
            "identity": {
                "project_id": self.project_id,
            },
            "permissions": [],
            "errors": [],
        }

        self.logger.info(f'Starting permission enumeration for project "{self.project_id}"')

        try:
            from googleapiclient import discovery

            credentials = self._get_credentials()

            # Build Cloud Resource Manager API client
            crm_api = discovery.build(
                "cloudresourcemanager",
                "v1",
                credentials=credentials,
            )

            # Test permissions in chunks
            all_permissions = GCP_PERMISSIONS
            total_permissions = len(all_permissions)
            discovered_permissions: List[str] = []

            self.logger.info(f"Testing {total_permissions} permissions...")

            # Split permissions into chunks
            chunks = [
                all_permissions[i : i + self.PERMISSIONS_CHUNK_SIZE]
                for i in range(0, total_permissions, self.PERMISSIONS_CHUNK_SIZE)
            ]

            for i, chunk in enumerate(chunks):
                self.logger.debug(
                    f"Testing chunk {i + 1}/{len(chunks)} ({len(chunk)} permissions)"
                )

                try:
                    response = (
                        crm_api.projects()
                        .testIamPermissions(
                            resource=self.project_id,
                            body={"permissions": chunk},
                        )
                        .execute()
                    )

                    # Add discovered permissions
                    if "permissions" in response:
                        discovered_permissions.extend(response["permissions"])
                        self.logger.info(
                            f"Chunk {i + 1}: Found {len(response['permissions'])} permissions"
                        )

                except Exception as e:
                    error_msg = f"Error testing chunk {i + 1}: {str(e)}"
                    self.logger.error(error_msg)
                    results["errors"].append(error_msg)

            results["permissions"] = sorted(discovered_permissions)

            self.logger.info(
                f"Enumeration complete. Found {len(discovered_permissions)} permissions."
            )

        except ImportError as e:
            error_msg = (
                f"Missing required dependency: {e}. "
                "Install with: pip install google-api-python-client google-auth"
            )
            self.logger.error(error_msg)
            results["errors"].append(error_msg)

        except Exception as e:
            error_msg = f"Enumeration failed: {str(e)}"
            self.logger.error(error_msg)
            results["errors"].append(error_msg)

        return results

    def enumerate_by_service(self) -> Dict[str, Any]:
        """
        Enumerate permissions grouped by service.

        Returns:
            Dictionary with permissions grouped by service.
        """
        results = self.enumerate()

        # Group permissions by service
        permissions_by_service: Dict[str, List[str]] = {}

        for permission in results.get("permissions", []):
            parts = permission.split(".")
            if len(parts) >= 2:
                service = parts[0]
                if service not in permissions_by_service:
                    permissions_by_service[service] = []
                permissions_by_service[service].append(permission)

        results["permissions"] = permissions_by_service

        return results
