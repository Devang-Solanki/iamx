"""
GCP Permissions Generator

This module generates GCP permission lists from:
1. IAM Dataset JSON from https://github.com/iann0036/iam-dataset

The GCP IAM dataset has the structure:
{
    "api": {
        "servicename": {
            "methods": {
                "servicename.resource.action": {
                    "permissions": [
                        {
                            "name": "permission.name",
                            ...
                        }
                    ]
                }
            }
        }
    }
}
"""

import json
import os
import urllib.request
from typing import Any, Dict, Optional, Set


# GCP IAM Dataset URL
GCP_IAM_DATASET_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/gcp/map.json"

# Permissions to blacklist (known to cause issues or require special setup)
BLACKLIST_PERMISSIONS: Set[str] = {
    # Add any problematic permissions here
    "accesscontextmanager.accessLevels.get",
    "accesscontextmanager.accessLevels.list",
    "apigee.dnszones.delete",
    "artifactregistry.mavenArtifacts.list",
    "assuredworkloads.updates.list",
    "billing.accounts.create",
    "compute.firewallPolicies.move",
    "compute.interconnectGroups.setIamPolicy",
    "compute.securityPolicies.move",
    "dialogflow.entityTypes.batchDelete",
    "dialogflow.intents.batchUpdate",
    "healthcare.hl7v2Stores.import",
    "looker.googleapis.com/looker.backups.get",
    "looker.googleapis.com/looker.instances.export",
    "orgpolicy.customConstraints.list",
    "resourcemanager.folders.getIamPolicy",
    "accesscontextmanager.accessLevels.create",
    "alloydb.googleapis.com/alloydb.clusters.export",
    "apigee.developerappattributes.create",
    "artifactregistry.dockerImages.list",
    "assuredworkloads.operations.get",
    "bigtable.authorizedView.delete",
    "cloudkms.autokeyConfigs.update",
    "compute.firewallPolicies.addAssociation",
    "compute.interconnectAttachmentGroups.setIamPolicy",
    "compute.securityPolicies.addAssociation",
    "dataplex.encryptionConfig.create",
    "dialogflow.contexts.deleteAll",
    "dialogflow.entityTypes.batchCreateEntities",
    "dlp.triggeredJobs.delete",
    "healthcare.fhirStores.getFhirOperationStatus",
    "iam.googleapis.com-workloadIdentityPoolProviders.get",
    "looker.googleapis.com/looker.backups.create",
    "orgpolicy.customConstraints.create",
    "resourcemanager.folders.create",
    "secretmanager.secrets.disable",
    "apigee.dnszones.get",
    "artifactregistry.dockerImages.get",
    "bigtable.authorizedView.get",
    "cloudkms.autokeyConfigs.get",
    "compute.interconnectAttachmentGroups.getIamPolicy",
    "dataplex.encryptionConfig.get",
    "dialogflow.conversationModelEvaluations.get",
    "eventarc.googleChannelConfig.get",
    "healthcare.fhirResources.search",
    "iam.googleapis.com-workforcePoolProviderKeys.get",
    "networkconnectivity.hubGroups.get",
    "orgpolicy.customConstraints.get",
    "resourcemanager.folders.get",
    "accesscontextmanager.accessLevels.delete",
    "alloydb.googleapis.com/alloydb.clusters.import",
    "apigee.dnszones.create",
    "artifactregistry.mavenArtifacts.get",
    "assuredworkloads.operations.list",
    "bigtable.clusters.listHotTablets",
    "compute.firewallPolicies.copyRules",
    "compute.interconnectGroups.getIamPolicy",
    "compute.securityPolicies.copyRules",
    "dataplex.encryptionConfig.delete",
    "dialogflow.conversationModelEvaluations.list",
    "dialogflow.intents.batchDelete",
    "healthcare.hl7v2Stores.export",
    "iam.workforcePools.get",
    "looker.googleapis.com/looker.backups.delete",
    "orgpolicy.customConstraints.delete",
    "resourcemanager.folders.delete",
    "secretmanager.secrets.enable",
    "accesscontextmanager.accessLevels.replaceAll",
    "apigee.dnszones.list",
    "artifactregistry.npmPackages.get",
    "assuredworkloads.violations.list",
    "billing.accounts.get",
    "compute.firewallPolicies.removeAssociation",
    "compute.securityPolicies.removeAssociation",
    "dialogflow.entityTypes.batchDeleteEntities",
    "dialogflow.messages.batchCreate",
    "iam.googleapis.com-workforcePoolProviderKeys.create",
    "looker.googleapis.com/looker.backups.list",
    "resourcemanager.folders.list",
    "accesscontextmanager.accessLevels.update",
    "artifactregistry.npmPackages.list",
    "assuredworkloads.workload.get",
    "billing.accounts.getIamPolicy",
    "dialogflow.entityTypes.batchUpdate",
    "iam.googleapis.com-workforcePoolProviderKeys.delete",
    "looker.googleapis.com/looker.instances.create",
    "resourcemanager.folders.move",
    "resourcemanager.folders.setIamPolicy",
    "accesscontextmanager.accessPolicies.create",
    "artifactregistry.pythonPackages.get",
    "billing.accounts.list",
    "dialogflow.entityTypes.batchUpdateEntities",
    "iam.googleapis.com-workforcePoolProviderKeys.list",
    "looker.googleapis.com/looker.instances.delete",
    "resourcemanager.folders.update",
    "resourcemanager.projects.list",
    "accesscontextmanager.accessPolicies.delete",
    "artifactregistry.pythonPackages.list",
    "billing.accounts.update",
    "iam.googleapis.com-workforcePoolProviderKeys.undelete",
    "looker.googleapis.com/looker.instances.get",
    "resourcemanager.organizations.get",
    "accesscontextmanager.accessPolicies.get",
    "assuredworkloads.updates.update",
    "billing.budgets.create",
    "iam.googleapis.com-workforcePoolProviders.create",
    "looker.googleapis.com/looker.instances.import",
    "resourcemanager.organizations.getIamPolicy",
    "accesscontextmanager.accessPolicies.getIamPolicy",
    "assuredworkloads.violations.get",
    "billing.budgets.delete",
    "iam.googleapis.com-workforcePoolProviders.delete",
    "looker.googleapis.com/looker.instances.list",
    "resourcemanager.organizations.setIamPolicy",
    "accesscontextmanager.accessPolicies.list",
    "assuredworkloads.violations.update",
    "billing.budgets.get",
    "iam.googleapis.com-workforcePoolProviders.get",
    "looker.googleapis.com/looker.instances.update",
    "resourcemanager.projects.create",
    "accesscontextmanager.accessPolicies.setIamPolicy",
    "assuredworkloads.workload.create",
    "billing.budgets.list",
    "iam.googleapis.com-workforcePoolProviders.list",
    "accesscontextmanager.accessPolicies.update",
    "assuredworkloads.workload.delete",
    "billing.budgets.update",
    "iam.googleapis.com-workforcePoolProviders.update",
    "accesscontextmanager.authorizedOrgsDescs.create",
    "assuredworkloads.workload.list",
    "iam.googleapis.com-workforcePoolSubjects.delete",
    "iam.googleapis.com-workforcePoolSubjects.undelete",
    "accesscontextmanager.authorizedOrgsDescs.delete",
    "assuredworkloads.workload.update",
    "iam.googleapis.com-workforcePools.create",
    "iam.googleapis.com-workforcePools.getIamPolicy",
    "accesscontextmanager.authorizedOrgsDescs.get",
    "iam.googleapis.com-workforcePools.delete",
    "iam.googleapis.com-workforcePools.update",
    "accesscontextmanager.authorizedOrgsDescs.list",
    "iam.googleapis.com-workforcePools.get",
    "iam.googleapis.com-workloadIdentityPoolProviderKeys.get",
    "accesscontextmanager.authorizedOrgsDescs.update",
    "iam.googleapis.com-workforcePools.list",
    "iam.googleapis.com-workloadIdentityPoolProviders.create",
    "accesscontextmanager.gcpUserAccessBindings.create",
    "iam.googleapis.com-workforcePools.setIamPolicy",
    "iam.googleapis.com-workloadIdentityPoolProviders.undelete",
    "accesscontextmanager.gcpUserAccessBindings.delete",
    "iam.googleapis.com-workforcePools.undelete",
    "iam.googleapis.com-workloadIdentityPools.delete",
    "accesscontextmanager.gcpUserAccessBindings.get",
    "iam.googleapis.com-workloadIdentityPoolProviderKeys.create",
    "iam.googleapis.com-workloadIdentityPools.undelete",
    "accesscontextmanager.gcpUserAccessBindings.list",
    "iam.googleapis.com-workloadIdentityPoolProviderKeys.delete",
    "accesscontextmanager.gcpUserAccessBindings.update",
    "iam.googleapis.com-workloadIdentityPoolProviderKeys.list",
    "accesscontextmanager.servicePerimeters.commit",
    "iam.googleapis.com-workloadIdentityPoolProviderKeys.undelete",
    "accesscontextmanager.servicePerimeters.create",
    "iam.googleapis.com-workloadIdentityPoolProviders.delete",
    "accesscontextmanager.servicePerimeters.delete",
    "iam.googleapis.com-workloadIdentityPoolProviders.list"
    "accesscontextmanager.servicePerimeters.get",
    "accesscontextmanager.servicePerimeters.get",
    "iam.googleapis.com-workloadIdentityPoolProviders.list",
    "iam.googleapis.com-workloadIdentityPoolProviders.update",
    "iam.googleapis.com-workloadIdentityPools.create",
    "iam.googleapis.com-workloadIdentityPools.get",
    "iam.googleapis.com-workloadIdentityPools.list",
    "accesscontextmanager.servicePerimeters.list",
    "accesscontextmanager.servicePerimeters.replaceAll",
    "accesscontextmanager.servicePerimeters.update",
    "iam.permissions.none",
    "spanner.databasesRoles.list", 
}

# Only include permissions that match these patterns (read-only operations)
SAFE_PERMISSION_PATTERNS: Set[str] = {
}


def download_gcp_dataset(url: str = GCP_IAM_DATASET_URL) -> Dict[str, Any]:
    """
    Download the GCP IAM dataset JSON from GitHub.

    Args:
        url: URL to the GCP IAM dataset JSON

    Returns:
        Parsed JSON data
    """
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"Downloading GCP IAM dataset from {url}")
    
    with urllib.request.urlopen(url) as response:
        data = response.read().decode("utf-8")
        return json.loads(data)


def is_safe_permission(permission: str) -> bool:
    """
    Check if a permission is safe (read-only).

    Args:
        permission: Permission name

    Returns:
        True if safe, False otherwise
    """
    permission_lower = permission.lower()
    
    for pattern in SAFE_PERMISSION_PATTERNS:
        if pattern in permission_lower:
            return True
    
    return False


def generate_from_gcp_dataset(
    dataset: Optional[Dict[str, Any]] = None,
    dataset_url: str = GCP_IAM_DATASET_URL,
    output_file: str = "iamx/gcp/permissions.py",
    verbose: bool = False,
    safe_only: bool = False,
) -> int:
    """
    Generate GCP permissions list from IAM dataset.

    Args:
        dataset: Pre-loaded dataset (optional)
        dataset_url: URL to download dataset from
        output_file: Output file path
        verbose: Enable verbose output
        safe_only: Only include safe (read-only) permissions

    Returns:
        Number of permissions generated
    """
    import logging
    logger = logging.getLogger(__name__)

    if verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # Download or use provided dataset
    if dataset is None:
        dataset = download_gcp_dataset(dataset_url)

    api_data = dataset.get("api", {})
    
    logger.info(f"Found {len(api_data)} API services in dataset")

    all_permissions: Set[str] = set()
    permissions_by_service: Dict[str, Set[str]] = {}
    methods_count = 0

    # Process each API service
    for service_name, service_data in api_data.items():
        methods = service_data.get("methods", {})
        methods_count += len(methods)
        
        for method_name, method_data in methods.items():
            permissions_list = method_data.get("permissions", [])
            
            for perm_data in permissions_list:
                if isinstance(perm_data, dict):
                    perm_name = perm_data.get("name", "")
                elif isinstance(perm_data, str):
                    perm_name = perm_data
                else:
                    continue
                
                if not perm_name:
                    continue
                
                # Skip blacklisted permissions
                if perm_name in BLACKLIST_PERMISSIONS:
                    continue
                
                # # Optionally filter to safe permissions only
                # if safe_only and not is_safe_permission(perm_name):
                #     continue
                
                all_permissions.add(perm_name)
                
                # Group by service (first part of permission name)
                service_prefix = perm_name.split(".")[0] if "." in perm_name else "other"
                if service_prefix not in permissions_by_service:
                    permissions_by_service[service_prefix] = set()
                permissions_by_service[service_prefix].add(perm_name)

    logger.info(f"Processed {methods_count} methods")
    logger.info(f"Found {len(all_permissions)} unique permissions")
    logger.info(f"Across {len(permissions_by_service)} services")

    # Sort permissions
    sorted_permissions = sorted(list(all_permissions))

    # Generate output
    output_content = '''"""
GCP IAM Permissions

This file contains a list of GCP IAM permissions that can be tested
using the testIamPermissions API.

Generated from IAM Dataset: https://github.com/iann0036/iam-dataset
"""

GCP_PERMISSIONS = [
'''

    for perm in sorted_permissions:
        output_content += f'    "{perm}",\n'

    output_content += "]\n\n"

    # Also generate permissions grouped by service
    output_content += "\n# Permissions grouped by service\n"
    output_content += "GCP_PERMISSIONS_BY_SERVICE = {\n"

    for service in sorted(permissions_by_service.keys()):
        perms = sorted(list(permissions_by_service[service]))
        output_content += f'    "{service}": [\n'
        for perm in perms:
            output_content += f'        "{perm}",\n'
        output_content += "    ],\n"

    output_content += "}\n"

    # Write output file
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    with open(output_file, "w") as f:
        f.write(output_content)

    logger.info(f"Generated {len(sorted_permissions)} permissions to {output_file}")

    return len(sorted_permissions)


def generate_gcp_permissions(
    output_file: str = "iamx/gcp/permissions.py",
    verbose: bool = False,
    safe_only: bool = False,
    dataset_url: str = GCP_IAM_DATASET_URL,
) -> int:
    """
    Generate GCP permissions list.

    Args:
        output_file: Output file path
        verbose: Enable verbose output
        safe_only: Only include safe (read-only) permissions
        dataset_url: URL to GCP IAM dataset JSON

    Returns:
        Number of permissions generated
    """
    return generate_from_gcp_dataset(
        dataset_url=dataset_url,
        output_file=output_file,
        verbose=verbose,
        safe_only=safe_only,
    )
