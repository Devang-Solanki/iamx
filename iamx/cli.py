"""
IAMX CLI - Main entry point for the CLI tool.
"""

import click
import json
import sys
from typing import Optional

from iamx import __version__


@click.group()
@click.version_option(version=__version__, prog_name="iamx")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """
    IAMX - Cloud IAM Permission Enumeration Tool

    A CLI tool for enumerating IAM permissions on AWS, GCP, and Azure cloud platforms.
    Use this tool to discover what permissions a given set of credentials has.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.group()
@click.pass_context
def aws(ctx: click.Context) -> None:
    """AWS IAM permission enumeration commands."""
    pass


@aws.command("enumerate")
@click.option(
    "--access-key",
    "-a",
    envvar="AWS_ACCESS_KEY_ID",
    help="AWS Access Key ID (or set AWS_ACCESS_KEY_ID env var)",
)
@click.option(
    "--secret-key",
    "-s",
    envvar="AWS_SECRET_ACCESS_KEY",
    help="AWS Secret Access Key (or set AWS_SECRET_ACCESS_KEY env var)",
)
@click.option(
    "--session-token",
    "-t",
    envvar="AWS_SESSION_TOKEN",
    default=None,
    help="AWS Session Token for temporary credentials (or set AWS_SESSION_TOKEN env var)",
)
@click.option(
    "--region",
    "-r",
    envvar="AWS_DEFAULT_REGION",
    default="us-east-1",
    help="AWS Region (default: us-east-1)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout",
)
@click.pass_context
def aws_enumerate(
    ctx: click.Context,
    access_key: Optional[str],
    secret_key: Optional[str],
    session_token: Optional[str],
    region: str,
    output: str,
    output_file: Optional[str],
) -> None:
    """
    Enumerate AWS IAM permissions using brute-force API calls.

    This command attempts to discover what permissions the provided AWS
    credentials have by making various AWS API calls and checking which
    ones succeed.

    Examples:

        # Using command line options
        iamx aws enumerate --access-key AKIA... --secret-key ...

        # Using environment variables
        export AWS_ACCESS_KEY_ID=AKIA...
        export AWS_SECRET_ACCESS_KEY=...
        iamx aws enumerate

        # With session token (temporary credentials)
        iamx aws enumerate -a ASIA... -s ... -t ...

        # Output to JSON file
        iamx aws enumerate -o json -f results.json
    """
    if not access_key or not secret_key:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "AWS credentials are required. Provide --access-key and --secret-key "
            "or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.",
            err=True,
        )
        sys.exit(1)

    from iamx.aws.enumerator import AWSEnumerator

    verbose = ctx.obj.get("verbose", False)

    click.echo(
        click.style("🔍 ", fg="cyan")
        + f"Starting AWS IAM enumeration for access key: {access_key[:8]}..."
    )
    click.echo(click.style("🌍 ", fg="cyan") + f"Region: {region}")

    if session_token:
        click.echo(click.style("🔑 ", fg="cyan") + "Using session token (temporary credentials)")

    enumerator = AWSEnumerator(
        access_key=access_key,
        secret_key=secret_key,
        session_token=session_token,
        region=region,
        verbose=verbose,
    )

    try:
        results = enumerator.enumerate()
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)

    _output_results(results, output, output_file)


@cli.group()
@click.pass_context
def gcp(ctx: click.Context) -> None:
    """GCP IAM permission enumeration commands."""
    pass


@gcp.command("enumerate")
@click.option(
    "--project",
    "-p",
    envvar="GOOGLE_CLOUD_PROJECT",
    required=True,
    help="GCP Project ID (or set GOOGLE_CLOUD_PROJECT env var)",
)
@click.option(
    "--credentials",
    "-c",
    type=click.Path(exists=True),
    default=None,
    help="Path to service account JSON key file",
)
@click.option(
    "--token",
    "-t",
    default=None,
    help="Access token for authentication",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout",
)
@click.pass_context
def gcp_enumerate(
    ctx: click.Context,
    project: str,
    credentials: Optional[str],
    token: Optional[str],
    output: str,
    output_file: Optional[str],
) -> None:
    """
    Enumerate GCP IAM permissions for a project.

    This command tests which IAM permissions the provided credentials
    have on the specified GCP project.

    Examples:

        # Using service account key file
        iamx gcp enumerate -p my-project -c service-account.json

        # Using access token
        iamx gcp enumerate -p my-project -t ya29...

        # Using environment variables
        export GOOGLE_CLOUD_PROJECT=my-project
        export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
        iamx gcp enumerate

        # Output to JSON file
        iamx gcp enumerate -p my-project -c key.json -o json -f results.json
    """
    if not credentials and not token:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "Either --credentials (service account key file) or --token (access token) is required.",
            err=True,
        )
        sys.exit(1)

    from iamx.gcp.enumerator import GCPEnumerator

    verbose = ctx.obj.get("verbose", False)

    click.echo(click.style("🔍 ", fg="cyan") + f"Starting GCP IAM enumeration for project: {project}")

    if credentials:
        click.echo(click.style("🔑 ", fg="cyan") + f"Using service account key: {credentials}")
    else:
        click.echo(click.style("🔑 ", fg="cyan") + f"Using access token: {token[:8]}...{token[-4:]}")

    enumerator = GCPEnumerator(
        project_id=project,
        credentials_file=credentials,
        access_token=token,
        verbose=verbose,
    )

    try:
        results = enumerator.enumerate()
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)

    _output_results(results, output, output_file)


@cli.group()
@click.pass_context
def azure(ctx: click.Context) -> None:
    """Azure RBAC permission enumeration commands."""
    pass


@azure.command("enumerate")
@click.option(
    "--subscription",
    "-s",
    envvar="AZURE_SUBSCRIPTION_ID",
    default=None,
    help="Azure Subscription ID (or set AZURE_SUBSCRIPTION_ID env var)",
)
@click.option(
    "--tenant",
    "-t",
    envvar="AZURE_TENANT_ID",
    default=None,
    help="Azure AD Tenant ID (or set AZURE_TENANT_ID env var)",
)
@click.option(
    "--client-id",
    "-c",
    envvar="AZURE_CLIENT_ID",
    default=None,
    help="Azure AD Application (Client) ID (or set AZURE_CLIENT_ID env var)",
)
@click.option(
    "--client-secret",
    envvar="AZURE_CLIENT_SECRET",
    default=None,
    help="Azure AD Client Secret (or set AZURE_CLIENT_SECRET env var)",
)
@click.option(
    "--credentials-file",
    type=click.Path(exists=True),
    default=None,
    help="Path to JSON file with Azure credentials (clientId, clientSecret, tenantId)",
)
@click.option(
    "--token",
    default=None,
    help="Pre-obtained access token for authentication",
)
@click.option(
    "--resource-group",
    "-g",
    default=None,
    help="Resource group to test against (optional)",
)
@click.option(
    "--output",
    "-o",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format (default: text)",
)
@click.option(
    "--output-file",
    "-f",
    type=click.Path(),
    default=None,
    help="Write output to file instead of stdout",
)
@click.pass_context
def azure_enumerate(
    ctx: click.Context,
    subscription: Optional[str],
    tenant: Optional[str],
    client_id: Optional[str],
    client_secret: Optional[str],
    credentials_file: Optional[str],
    token: Optional[str],
    resource_group: Optional[str],
    output: str,
    output_file: Optional[str],
) -> None:
    """
    Enumerate Azure RBAC permissions.

    This command tests which Azure API operations the provided credentials
    can perform, discovering effective permissions.

    Examples:

        # Using credentials JSON file
        iamx azure enumerate --credentials-file creds.json

        # Using service principal (client credentials)
        iamx azure enumerate -t <tenant-id> -c <client-id> --client-secret <secret>

        # Using environment variables
        export AZURE_TENANT_ID=...
        export AZURE_CLIENT_ID=...
        export AZURE_CLIENT_SECRET=...
        iamx azure enumerate

        # Using access token
        iamx azure enumerate --token eyJ0...

        # With specific subscription and resource group
        iamx azure enumerate -s <subscription-id> -g <resource-group>

        # Output to JSON file
        iamx azure enumerate -o json -f results.json

    Credentials JSON file format:
        {
            "clientId": "...",
            "clientSecret": "...",
            "tenantId": "..."
        }
    """
    # Load credentials from JSON file if provided
    if credentials_file:
        try:
            with open(credentials_file, "r") as f:
                creds = json.load(f)
            # Support both camelCase and snake_case keys
            if not client_id:
                client_id = creds.get("clientId") or creds.get("client_id")
            if not client_secret:
                client_secret = creds.get("clientSecret") or creds.get("client_secret")
            if not tenant:
                tenant = creds.get("tenantId") or creds.get("tenant_id")
            if not subscription:
                subscription = creds.get("subscriptionId") or creds.get("subscription_id")
            click.echo(click.style("📄 ", fg="cyan") + f"Loaded credentials from: {credentials_file}")
        except json.JSONDecodeError as e:
            click.echo(
                click.style("Error: ", fg="red", bold=True)
                + f"Invalid JSON in credentials file: {e}",
                err=True,
            )
            sys.exit(1)
        except Exception as e:
            click.echo(
                click.style("Error: ", fg="red", bold=True)
                + f"Failed to read credentials file: {e}",
                err=True,
            )
            sys.exit(1)

    # Check for valid authentication method
    has_sp_creds = client_id and client_secret and tenant
    has_token = token is not None

    if not has_sp_creds and not has_token:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "Azure credentials are required. Provide either:\n"
            "  - Service principal: --tenant, --client-id, and --client-secret\n"
            "  - Access token: --token\n"
            "Or set environment variables: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET",
            err=True,
        )
        sys.exit(1)

    try:
        from iamx.azure.enumerator import AzureEnumerator
    except ImportError as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + f"Azure SDK not installed: {e}\n"
            "Install with: pip install iamx[azure]",
            err=True,
        )
        sys.exit(1)

    verbose = ctx.obj.get("verbose", False)

    click.echo(click.style("🔍 ", fg="cyan") + "Starting Azure permission enumeration")

    if subscription:
        click.echo(click.style("📋 ", fg="cyan") + f"Subscription: {subscription}")
    else:
        click.echo(click.style("📋 ", fg="cyan") + "Subscription: (will auto-discover)")

    if has_sp_creds:
        click.echo(click.style("🔑 ", fg="cyan") + f"Using service principal: {client_id}")
    else:
        click.echo(click.style("🔑 ", fg="cyan") + f"Using access token: {token[:20]}...")

    enumerator = AzureEnumerator(
        subscription_id=subscription,
        tenant_id=tenant,
        client_id=client_id,
        client_secret=client_secret,
        access_token=token,
        resource_group=resource_group,
        verbose=verbose,
    )

    try:
        results = enumerator.enumerate()
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)

    _output_results(results, output, output_file)


@cli.group()
@click.pass_context
def generate(ctx: click.Context) -> None:
    """Generate bruteforce test definitions from IAM datasets."""
    pass


@generate.command("aws")
@click.option(
    "--source",
    "-s",
    type=click.Choice(["iam-dataset", "sdk"]),
    default="iam-dataset",
    help="Source for generating tests (default: iam-dataset)",
)
@click.option(
    "--sdk-path",
    type=click.Path(exists=True),
    default=None,
    help="Path to aws-sdk-js/apis directory (required if source=sdk)",
)
@click.option(
    "--dataset-url",
    "-u",
    default="https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/map.json",
    help="URL to IAM dataset JSON (for iam-dataset source)",
)
@click.option(
    "--output-file",
    "-o",
    type=click.Path(),
    default="iamx/aws/bruteforce_tests.py",
    help="Output file path (default: iamx/aws/bruteforce_tests.py)",
)
@click.pass_context
def generate_aws(
    ctx: click.Context,
    source: str,
    sdk_path: Optional[str],
    dataset_url: str,
    output_file: str,
) -> None:
    """
    Generate AWS bruteforce test definitions.

    This command generates a Python file containing safe AWS API operations
    to test for permission enumeration.

    Sources:
        - iam-dataset: Downloads from https://github.com/iann0036/iam-dataset (recommended)
        - sdk: Parses local AWS SDK JS API definitions

    Examples:

        # Generate from IAM dataset (recommended)
        iamx generate aws

        # Generate from IAM dataset with custom URL
        iamx generate aws -u https://example.com/map.json

        # Generate from AWS SDK (legacy)
        iamx generate aws -s sdk --sdk-path ./aws-sdk-js/apis

        # Custom output file
        iamx generate aws -o custom_tests.py
    """
    from iamx.aws.generator import generate_bruteforce_tests

    verbose = ctx.obj.get("verbose", False)

    if source == "sdk" and not sdk_path:
        click.echo(
            click.style("Error: ", fg="red", bold=True)
            + "--sdk-path is required when using source=sdk",
            err=True,
        )
        sys.exit(1)

    if source == "iam-dataset":
        click.echo(click.style("🔧 ", fg="cyan") + "Generating AWS bruteforce tests from IAM dataset...")
        click.echo(click.style("📥 ", fg="cyan") + f"Downloading from: {dataset_url}")
    else:
        click.echo(click.style("🔧 ", fg="cyan") + f"Generating AWS bruteforce tests from SDK: {sdk_path}")

    try:
        count = generate_bruteforce_tests(
            sdk_path=sdk_path,
            output_file=output_file,
            verbose=verbose,
            use_iam_dataset=(source == "iam-dataset"),
            dataset_url=dataset_url,
        )
        click.echo(
            click.style("✅ ", fg="green")
            + f"Generated {count} service definitions to: {output_file}"
        )
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)


@generate.command("gcp")
@click.option(
    "--dataset-url",
    "-u",
    default="https://raw.githubusercontent.com/iann0036/iam-dataset/main/gcp/map.json",
    help="URL to GCP IAM dataset JSON",
)
@click.option(
    "--output-file",
    "-o",
    type=click.Path(),
    default="iamx/gcp/permissions.py",
    help="Output file path (default: iamx/gcp/permissions.py)",
)
@click.option(
    "--safe-only",
    is_flag=True,
    default=False,
    help="Only include safe (read-only) permissions",
)
@click.pass_context
def generate_gcp(
    ctx: click.Context,
    dataset_url: str,
    output_file: str,
    safe_only: bool,
) -> None:
    """
    Generate GCP permissions list from IAM dataset.

    This command downloads the GCP IAM dataset and generates a Python file
    containing all GCP IAM permissions for testing.

    Source: https://github.com/iann0036/iam-dataset

    Examples:

        # Generate all permissions
        iamx generate gcp

        # Generate only safe (read-only) permissions
        iamx generate gcp --safe-only

        # Custom output file
        iamx generate gcp -o custom_permissions.py

        # Custom dataset URL
        iamx generate gcp -u https://example.com/gcp-map.json
    """
    from iamx.gcp.generator import generate_gcp_permissions

    verbose = ctx.obj.get("verbose", False)

    click.echo(click.style("🔧 ", fg="cyan") + "Generating GCP permissions from IAM dataset...")
    click.echo(click.style("📥 ", fg="cyan") + f"Downloading from: {dataset_url}")

    if safe_only:
        click.echo(click.style("🔒 ", fg="yellow") + "Filtering to safe (read-only) permissions only")

    try:
        count = generate_gcp_permissions(
            output_file=output_file,
            verbose=verbose,
            safe_only=safe_only,
            dataset_url=dataset_url,
        )
        click.echo(
            click.style("✅ ", fg="green")
            + f"Generated {count} permissions to: {output_file}"
        )
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)


@generate.command("azure")
@click.option(
    "--source-file",
    "-s",
    type=click.Path(exists=True),
    default=None,
    help="Path to local Azure API specs JSON file",
)
@click.option(
    "--dataset-url",
    "-u",
    default="https://raw.githubusercontent.com/iann0036/iam-dataset/refs/heads/main/azure/api.json",
    help="URL to Azure API dataset JSON",
)
@click.option(
    "--output-file",
    "-o",
    type=click.Path(),
    default="iamx/azure/operations.py",
    help="Output file path (default: iamx/azure/operations.py)",
)
@click.pass_context
def generate_azure(
    ctx: click.Context,
    source_file: Optional[str],
    dataset_url: str,
    output_file: str,
) -> None:
    """
    Generate Azure API operations from IAM dataset.

    This command downloads the Azure IAM dataset and generates a Python file
    containing Azure REST API operations for permission testing.

    Source: https://github.com/iann0036/iam-dataset

    Examples:

        # Generate from IAM dataset (recommended)
        iamx generate azure

        # Generate from local file
        iamx generate azure -s /path/to/azure-map.json

        # Custom output file
        iamx generate azure -o custom_operations.py

        # Custom dataset URL
        iamx generate azure -u https://example.com/azure-map.json
    """
    from iamx.azure.generator import generate_azure_operations

    verbose = ctx.obj.get("verbose", False)

    if source_file:
        click.echo(click.style("🔧 ", fg="cyan") + f"Generating Azure operations from file: {source_file}")
    else:
        click.echo(click.style("🔧 ", fg="cyan") + "Generating Azure operations from IAM dataset...")
        click.echo(click.style("📥 ", fg="cyan") + f"Downloading from: {dataset_url}")

    try:
        count = generate_azure_operations(
            source_file=source_file,
            source_url=None if source_file else dataset_url,
            output_file=output_file,
            verbose=verbose,
            safe_only=True,
        )
        click.echo(
            click.style("✅ ", fg="green")
            + f"Generated {count} operations to: {output_file}"
        )
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)


# Keep legacy command for backwards compatibility
@generate.command("aws-tests", hidden=True)
@click.option(
    "--sdk-path",
    "-s",
    type=click.Path(exists=True),
    required=True,
    help="Path to aws-sdk-js/apis directory",
)
@click.option(
    "--output-file",
    "-o",
    type=click.Path(),
    default="iamx/aws/bruteforce_tests.py",
    help="Output file path (default: iamx/aws/bruteforce_tests.py)",
)
@click.pass_context
def generate_aws_tests_legacy(
    ctx: click.Context,
    sdk_path: str,
    output_file: str,
) -> None:
    """
    [DEPRECATED] Generate AWS bruteforce test definitions from AWS SDK.

    Use 'iamx generate aws' instead.
    """
    click.echo(
        click.style("⚠️  ", fg="yellow")
        + "This command is deprecated. Use 'iamx generate aws -s sdk --sdk-path ...' instead."
    )
    
    from iamx.aws.generator import generate_bruteforce_tests

    verbose = ctx.obj.get("verbose", False)

    try:
        count = generate_bruteforce_tests(
            sdk_path=sdk_path,
            output_file=output_file,
            verbose=verbose,
            use_iam_dataset=False,
        )
        click.echo(
            click.style("✅ ", fg="green")
            + f"Generated {count} service definitions to: {output_file}"
        )
    except Exception as e:
        click.echo(
            click.style("Error: ", fg="red", bold=True) + str(e),
            err=True,
        )
        sys.exit(1)


def _output_results(results: dict, output_format: str, output_file: Optional[str]) -> None:
    """Output results in the specified format."""
    if output_format == "json":
        output_str = json.dumps(results, indent=2, default=str)
    else:
        output_str = _format_text_output(results)

    if output_file:
        with open(output_file, "w") as f:
            f.write(output_str)
        click.echo(click.style("✅ ", fg="green") + f"Results written to: {output_file}")
    else:
        click.echo("\n" + output_str)


def _format_text_output(results: dict) -> str:
    """Format results as human-readable text."""
    lines = []
    lines.append(click.style("=" * 60, fg="cyan"))
    lines.append(click.style("  IAM Enumeration Results", fg="cyan", bold=True))
    lines.append(click.style("=" * 60, fg="cyan"))

    # Check if this is a root account
    is_root = results.get("identity", {}).get("root_account", False)
    
    # Check if this is Azure output (has role_assignments or api_operations)
    is_azure = (
        "permissions" in results
        and isinstance(results["permissions"], dict)
        and ("role_assignments" in results["permissions"] or "api_operations" in results["permissions"])
    )

    if "identity" in results:
        lines.append("\n" + click.style("📋 Identity Information:", fg="yellow", bold=True))
        for key, value in results["identity"].items():
            if key == "root_account" and value:
                lines.append(f"   {key}: {click.style('TRUE - FULL ACCESS', fg='red', bold=True)}")
            elif value:  # Only show non-empty values
                lines.append(f"   {key}: {value}")

    # Special handling for root account
    if is_root:
        lines.append("\n" + click.style("🚨 ROOT ACCOUNT DETECTED!", fg="red", bold=True))
        lines.append(click.style("   This account has FULL ACCESS to all AWS services.", fg="red"))
        lines.append(click.style("   No brute-force enumeration needed.", fg="red"))
        
        # Show IAM permissions that were discovered
        if "permissions" in results and "iam" in results["permissions"]:
            lines.append("\n" + click.style("🔓 IAM Permissions Verified:", fg="green", bold=True))
            iam_perms = results["permissions"]["iam"]
            if isinstance(iam_perms, dict):
                for action in sorted(iam_perms.keys()):
                    if not action.startswith("_"):  # Skip internal notes
                        lines.append(f"   ✓ iam.{action}")
    elif is_azure:
        # Azure-specific output formatting
        permissions = results["permissions"]
        
        # Format role assignments
        if "role_assignments" in permissions and permissions["role_assignments"]:
            lines.append("\n" + click.style("🎭 Role Assignments:", fg="yellow", bold=True))
            for assignment in permissions["role_assignments"]:
                # Extract role name from role_definition_id
                role_def_id = assignment.get("role_definition_id", "")
                role_name = role_def_id.split("/")[-1] if role_def_id else "Unknown"
                scope = assignment.get("scope", "")
                # Shorten scope for display
                if "/resourceGroups/" in scope:
                    scope_display = scope.split("/resourceGroups/")[-1]
                    scope_display = f"RG: {scope_display.split('/')[0]}"
                elif "/subscriptions/" in scope:
                    scope_display = "Subscription"
                else:
                    scope_display = scope[-40:] if len(scope) > 40 else scope
                lines.append(f"   • Role: {click.style(role_name, fg='blue')} | Scope: {scope_display}")
        
        # Format API operations
        if "api_operations" in permissions and permissions["api_operations"]:
            lines.append("\n" + click.style("🔓 Accessible API Operations:", fg="green", bold=True))
            api_ops = permissions["api_operations"]
            
            # Group by provider
            providers: dict = {}
            for op_key, op_data in api_ops.items():
                parts = op_key.split(".", 1)
                provider = parts[0] if len(parts) > 1 else "Unknown"
                operation = parts[1] if len(parts) > 1 else op_key
                if provider not in providers:
                    providers[provider] = []
                providers[provider].append(operation)
            
            # Display grouped by provider
            for provider in sorted(providers.keys()):
                operations = sorted(providers[provider])
                lines.append(f"\n   {click.style(provider, fg='blue', bold=True)} ({len(operations)} operations):")
                for op in operations:
                    lines.append(f"      ✓ {op}")
    else:
        # Normal permission output for non-root accounts (AWS/GCP)
        if "permissions" in results:
            lines.append("\n" + click.style("🔓 Discovered Permissions:", fg="green", bold=True))
            permissions = results["permissions"]
            if isinstance(permissions, list):
                # Handle list of strings (GCP style)
                str_perms = [p for p in permissions if isinstance(p, str)]
                for perm in sorted(str_perms):
                    lines.append(f"   ✓ {perm}")
            elif isinstance(permissions, dict):
                for service, actions in sorted(permissions.items()):
                    # Skip internal notes
                    if service.startswith("_"):
                        continue
                    lines.append(f"\n   {click.style(service, fg='blue', bold=True)}:")
                    if isinstance(actions, list):
                        # Handle list - could be strings or dicts
                        for action in sorted(actions) if all(isinstance(a, str) for a in actions) else actions:
                            if isinstance(action, str):
                                if not action.startswith("_"):
                                    lines.append(f"      ✓ {action}")
                            elif isinstance(action, dict):
                                # Dict with operation details
                                action_name = action.get("name", action.get("operation_id", str(action)))
                                lines.append(f"      ✓ {action_name}")
                    elif isinstance(actions, dict):
                        # Handle dict of actions (AWS style)
                        for action, data in sorted(actions.items()):
                            if not action.startswith("_"):
                                lines.append(f"      ✓ {action}")

    if "errors" in results and results["errors"]:
        lines.append("\n" + click.style("⚠️  Errors:", fg="red", bold=True))
        for error in results["errors"]:
            lines.append(f"   • {error}")

    lines.append("\n" + click.style("=" * 60, fg="cyan"))

    # Calculate total permissions (excluding internal notes)
    total_perms = 0
    total_roles = 0
    
    if not is_root and "permissions" in results:
        if is_azure:
            # Azure-specific counting
            permissions = results["permissions"]
            if "role_assignments" in permissions:
                total_roles = len(permissions["role_assignments"])
            if "api_operations" in permissions:
                total_perms = len(permissions["api_operations"])
        elif isinstance(results["permissions"], list):
            # Handle list of strings or dicts (GCP style)
            for p in results["permissions"]:
                if isinstance(p, str):
                    if not p.startswith("_"):
                        total_perms += 1
                elif isinstance(p, dict):
                    total_perms += 1
        elif isinstance(results["permissions"], dict):
            # AWS style
            for service, actions in results["permissions"].items():
                if service.startswith("_"):
                    continue
                if isinstance(actions, list):
                    for a in actions:
                        if isinstance(a, str):
                            if not a.startswith("_"):
                                total_perms += 1
                        elif isinstance(a, dict):
                            total_perms += 1
                elif isinstance(actions, dict):
                    total_perms += len([a for a in actions.keys() if not a.startswith("_")])

    if is_root:
        lines.append(f"  Access Level: {click.style('ROOT (FULL ACCESS)', fg='red', bold=True)}")
    elif is_azure:
        lines.append(f"  Role assignments: {click.style(str(total_roles), fg='yellow', bold=True)}")
        lines.append(f"  API operations accessible: {click.style(str(total_perms), fg='green', bold=True)}")
    else:
        lines.append(f"  Total permissions discovered: {click.style(str(total_perms), fg='green', bold=True)}")
    lines.append(click.style("=" * 60, fg="cyan"))

    return "\n".join(lines)


def main() -> None:
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
