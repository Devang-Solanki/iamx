"""
AWS IAM Permission Enumerator

This module provides functionality to enumerate AWS IAM permissions
by attempting various API calls and checking which ones succeed.
"""

import logging
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import boto3
import botocore
from botocore.client import Config

from iamx.aws.bruteforce_tests import BRUTEFORCE_TESTS
from iamx.utils.helpers import remove_metadata


class AWSEnumerator:
    """
    AWS IAM Permission Enumerator.

    Enumerates AWS IAM permissions by attempting various API calls
    and checking which ones succeed.
    """

    MAX_THREADS = 25

    def __init__(
        self,
        access_key: str,
        secret_key: str,
        session_token: Optional[str] = None,
        region: str = "us-east-1",
        verbose: bool = False,
    ):
        """
        Initialize the AWS Enumerator.

        Args:
            access_key: AWS Access Key ID
            secret_key: AWS Secret Access Key
            session_token: AWS Session Token (for temporary credentials)
            region: AWS Region
            verbose: Enable verbose logging
        """
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.region = region
        self.verbose = verbose

        self._client_pool: Dict[str, Any] = {}
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configure logging."""
        level = logging.DEBUG if self.verbose else logging.INFO
        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(process)d - [%(levelname)s] %(message)s",
        )

        # Suppress boto INFO
        logging.getLogger("boto3").setLevel(logging.WARNING)
        logging.getLogger("botocore").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        # Suppress urllib3 warnings including connection pool warnings
        logging.getLogger("urllib3").setLevel(logging.ERROR)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

        # Disable SSL warnings
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.logger = logging.getLogger(__name__)

    def enumerate(self) -> Dict[str, Any]:
        """
        Enumerate all AWS IAM permissions.

        Returns:
            Dictionary containing identity info and discovered permissions.
        """
        results: Dict[str, Any] = {
            "identity": {},
            "permissions": {},
            "errors": [],
        }

        self.logger.info(f'Starting permission enumeration for access-key-id "{self.access_key}"')

        # First, try to get identity information via IAM
        try:
            iam_results = self._enumerate_using_iam()
            results["identity"] = iam_results.get("identity", {})
            results["permissions"]["iam"] = iam_results.get("permissions", {})
        except Exception as e:
            results["errors"].append(f"IAM enumeration error: {str(e)}")
            self.logger.error(f"IAM enumeration failed: {e}")

        # Check if this is a root account - if so, skip brute-force enumeration
        # Root accounts have full access to all AWS services
        if results["identity"].get("root_account", False):
            self.logger.warning("🚨 ROOT ACCOUNT DETECTED! Skipping brute-force enumeration.")
            self.logger.warning("Root credentials have FULL ACCESS to all AWS services and resources.")
            results["permissions"]["bruteforce"] = {
                "_note": "Brute-force enumeration skipped - root account has full access to all AWS services"
            }
            return results

        # Then, brute-force common API calls (only for non-root accounts)
        try:
            bruteforce_results = self._enumerate_using_bruteforce()
            results["permissions"]["bruteforce"] = bruteforce_results
        except Exception as e:
            results["errors"].append(f"Bruteforce enumeration error: {str(e)}")
            self.logger.error(f"Bruteforce enumeration failed: {e}")

        return results

    def _get_client(self, service_name: str) -> Optional[Any]:
        """
        Get or create a boto3 client for the specified service.

        Args:
            service_name: AWS service name

        Returns:
            boto3 client or None if service is unavailable
        """
        key = f"{self.access_key}-{service_name}-{self.region}"

        if key in self._client_pool:
            return self._client_pool[key]

        self.logger.debug(f"Getting client for {service_name} in region {self.region}")

        config = Config(
            connect_timeout=5,
            read_timeout=5,
            retries={"max_attempts": 3},
            max_pool_connections=self.MAX_THREADS + 5,  # Match thread count + buffer
        )

        try:
            client = boto3.client(
                service_name,
                aws_access_key_id=self.access_key,
                aws_secret_access_key=self.secret_key,
                aws_session_token=self.session_token,
                region_name=self.region,
                verify=False,
                config=config,
            )
            self._client_pool[key] = client
            return client
        except Exception as e:
            self.logger.debug(f"Failed to create client for {service_name}: {e}")
            return None

    def _enumerate_using_iam(self) -> Dict[str, Any]:
        """
        Enumerate permissions using IAM API calls.

        Returns:
            Dictionary with identity and IAM-specific permissions.
        """
        results: Dict[str, Any] = {
            "identity": {},
            "permissions": {},
        }

        iam_client = self._get_client("iam")
        if not iam_client:
            return results

        # Try to get account authorization details (jackpot if this works)
        try:
            everything = iam_client.get_account_authorization_details()
            self.logger.info("get_account_authorization_details worked!")
            results["permissions"]["get_account_authorization_details"] = remove_metadata(everything)
        except (botocore.exceptions.ClientError, botocore.exceptions.EndpointConnectionError):
            pass

        # Try to get user information
        user_info = self._enumerate_user(iam_client)
        if user_info:
            results["identity"].update(user_info.get("identity", {}))
            results["permissions"].update(user_info.get("permissions", {}))

        # Try to get role information
        role_info = self._enumerate_role(iam_client, results["identity"].get("arn"))
        if role_info:
            results["identity"].update(role_info.get("identity", {}))
            results["permissions"].update(role_info.get("permissions", {}))

        return results

    def _enumerate_user(self, iam_client: Any) -> Optional[Dict[str, Any]]:
        """
        Enumerate user-specific IAM information.

        Args:
            iam_client: boto3 IAM client

        Returns:
            Dictionary with user identity and permissions.
        """
        results: Dict[str, Any] = {
            "identity": {"root_account": False},
            "permissions": {},
        }

        # Try to get user
        try:
            user = iam_client.get_user()
            results["permissions"]["get_user"] = remove_metadata(user)
        except botocore.exceptions.ClientError as err:
            arn, arn_id, arn_path = self._extract_arn(str(err))
            if arn:
                results["identity"]["arn"] = arn
                results["identity"]["arn_id"] = arn_id
                results["identity"]["arn_path"] = arn_path
            return results

        user_obj = user.get("User", {})
        if user_obj:
            arn = user_obj.get("Arn")
            user_name = user_obj.get("UserName")
            results["identity"]["arn"] = arn
            
            # Handle root account explicitly
            if arn and arn.endswith(":root"):
                results["identity"]["user_name"] = "root"
                results["identity"]["root_account"] = True
                return results
            else:
                results["identity"]["user_name"] = user_name
                results["identity"]["root_account"] = False

        # Get attached user policies
        try:
            user_policies = iam_client.list_attached_user_policies(UserName=user_name)
            results["permissions"]["list_attached_user_policies"] = remove_metadata(user_policies)
            self.logger.info(
                f'User "{user_name}" has {len(user_policies.get("AttachedPolicies", []))} attached policies'
            )
        except botocore.exceptions.ClientError:
            pass

        # Get inline user policies
        try:
            inline_policies = iam_client.list_user_policies(UserName=user_name)
            results["permissions"]["list_user_policies"] = remove_metadata(inline_policies)
            self.logger.info(
                f'User "{user_name}" has {len(inline_policies.get("PolicyNames", []))} inline policies'
            )
        except botocore.exceptions.ClientError:
            pass

        # Get user groups
        try:
            user_groups = iam_client.list_groups_for_user(UserName=user_name)
            results["permissions"]["list_groups_for_user"] = remove_metadata(user_groups)
            self.logger.info(
                f'User "{user_name}" has {len(user_groups.get("Groups", []))} groups'
            )

            # Get group policies
            results["permissions"]["list_group_policies"] = {}
            for group in user_groups.get("Groups", []):
                try:
                    group_policy = iam_client.list_group_policies(GroupName=group["GroupName"])
                    results["permissions"]["list_group_policies"][group["GroupName"]] = remove_metadata(
                        group_policy
                    )
                except botocore.exceptions.ClientError:
                    pass
        except botocore.exceptions.ClientError:
            pass

        return results

    def _enumerate_role(self, iam_client: Any, arn: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Enumerate role-specific IAM information.

        Args:
            iam_client: boto3 IAM client
            arn: ARN from previous enumeration

        Returns:
            Dictionary with role identity and permissions.
        """
        if not arn:
            return None

        results: Dict[str, Any] = {
            "identity": {},
            "permissions": {},
        }

        # Try to get role
        try:
            role = iam_client.get_role(RoleName=arn)
            results["permissions"]["get_role"] = remove_metadata(role)
            role_name = role["Role"]["RoleName"]
        except botocore.exceptions.ClientError as err:
            new_arn, arn_id, arn_path = self._extract_arn(str(err))
            if new_arn:
                results["identity"]["arn"] = new_arn
                results["identity"]["arn_id"] = arn_id
                results["identity"]["arn_path"] = arn_path

            if "role" not in str(arn).lower():
                return results
            role_name = arn

        # Get attached role policies
        try:
            role_policies = iam_client.list_attached_role_policies(RoleName=role_name)
            results["permissions"]["list_attached_role_policies"] = remove_metadata(role_policies)
            self.logger.info(
                f'Role has {len(role_policies.get("AttachedPolicies", []))} attached policies'
            )
        except botocore.exceptions.ClientError:
            pass

        # Get inline role policies
        try:
            inline_policies = iam_client.list_role_policies(RoleName=role_name)
            results["permissions"]["list_role_policies"] = remove_metadata(inline_policies)
            self.logger.info(
                f'Role has {len(inline_policies.get("PolicyNames", []))} inline policies'
            )
        except botocore.exceptions.ClientError:
            pass

        return results

    def _extract_arn(self, error_message: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Extract ARN from error message.

        Args:
            error_message: Error message string

        Returns:
            Tuple of (arn, arn_id, arn_path) or (None, None, None)
        """
        arn_search = re.search(r".*(arn:aws:.*?) .*", error_message)

        if arn_search:
            arn = arn_search.group(1)
            parts = arn.split(":")
            if len(parts) >= 6:
                arn_id = parts[4]
                arn_path = parts[5]
                self.logger.info(f"Account ARN: {arn}")
                self.logger.info(f"Account Id: {arn_id}")
                self.logger.info(f"Account Path: {arn_path}")
                return arn, arn_id, arn_path

        return None, None, None

    def _enumerate_using_bruteforce(self) -> Dict[str, Any]:
        """
        Enumerate permissions using brute-force API calls.

        Returns:
            Dictionary of successful API calls and their responses.
        """
        results: Dict[str, Any] = {}

        self.logger.info("Attempting common-service describe/list brute force.")

        # Generate all test cases
        test_cases = list(self._generate_test_cases())
        total_tests = len(test_cases)

        self.logger.info(f"Running {total_tests} API tests across {len(BRUTEFORCE_TESTS)} services")

        # Run tests in parallel
        with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as executor:
            future_to_test = {
                executor.submit(self._check_permission, service, operation): (service, operation)
                for service, operation in test_cases
            }

            completed = 0
            for future in as_completed(future_to_test):
                completed += 1
                if completed % 1000 == 0:
                    self.logger.info(f"Progress: {completed}/{total_tests} tests completed")

                result = future.result()
                if result:
                    key, response = result
                    results[key] = response

        self.logger.info(f"Bruteforce enumeration complete. Found {len(results)} working API calls.")
        return results

    def _generate_test_cases(self) -> List[Tuple[str, str]]:
        """
        Generate randomized test cases.

        Yields:
            Tuples of (service_name, operation_name)
        """
        service_names = list(BRUTEFORCE_TESTS.keys())
        random.shuffle(service_names)

        for service_name in service_names:
            operations = list(BRUTEFORCE_TESTS[service_name])
            random.shuffle(operations)

            for operation in operations:
                yield service_name, operation

    def _check_permission(
        self, service_name: str, operation_name: str
    ) -> Optional[Tuple[str, Any]]:
        """
        Check if a specific API operation is permitted.

        Args:
            service_name: AWS service name
            operation_name: API operation name

        Returns:
            Tuple of (key, response) if successful, None otherwise
        """
        client = self._get_client(service_name)
        if not client:
            return None

        try:
            action_function = getattr(client, operation_name)
        except AttributeError:
            self.logger.debug(f"Operation {service_name}.{operation_name} not found")
            return None

        self.logger.debug(f"Testing {service_name}.{operation_name}() in region {self.region}")

        try:
            response = action_function()
            self.logger.info(f"-- {service_name}.{operation_name}() worked!")
            key = f"{service_name}.{operation_name}"
            return key, remove_metadata(response)
        except (
            botocore.exceptions.ClientError,
            botocore.exceptions.EndpointConnectionError,
            botocore.exceptions.ConnectTimeoutError,
            botocore.exceptions.ReadTimeoutError,
        ):
            return None
        except botocore.exceptions.ParamValidationError:
            self.logger.debug(f"Parameter validation error for {service_name}.{operation_name}")
            return None
        except Exception as e:
            self.logger.debug(f"Unexpected error for {service_name}.{operation_name}: {e}")
            return None
