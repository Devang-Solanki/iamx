"""
Brute IAM CLI - Main entry point for the CLI tool.
"""

import click
import json
import sys
from typing import Optional

from iamx import __version__


@click.group()
@click.version_option(version=__version__, prog_name="brute-iam")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """
    Brute IAM - Cloud IAM Permission Enumeration Tool

    A CLI tool for enumerating IAM permissions on AWS and GCP cloud platforms.
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
        brute-iam aws enumerate --access-key AKIA... --secret-key ...

        # Using environment variables
        export AWS_ACCESS_KEY_ID=AKIA...
        export AWS_SECRET_ACCESS_KEY=...
        brute-iam aws enumerate

        # With session token (temporary credentials)
        brute-iam aws enumerate -a ASIA... -s ... -t ...

        # Output to JSON file
        brute-iam aws enumerate -o json -f results.json
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
        brute-iam gcp enumerate -p my-project -c service-account.json

        # Using access token
        brute-iam gcp enumerate -p my-project -t ya29...

        # Using environment variables
        export GOOGLE_CLOUD_PROJECT=my-project
        export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
        brute-iam gcp enumerate

        # Output to JSON file
        brute-iam gcp enumerate -p my-project -c key.json -o json -f results.json
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
        brute-iam generate aws

        # Generate from IAM dataset with custom URL
        brute-iam generate aws -u https://example.com/map.json

        # Generate from AWS SDK (legacy)
        brute-iam generate aws -s sdk --sdk-path ./aws-sdk-js/apis

        # Custom output file
        brute-iam generate aws -o custom_tests.py
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
        brute-iam generate gcp

        # Generate only safe (read-only) permissions
        brute-iam generate gcp --safe-only

        # Custom output file
        brute-iam generate gcp -o custom_permissions.py

        # Custom dataset URL
        brute-iam generate gcp -u https://example.com/gcp-map.json
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

    Use 'brute-iam generate aws' instead.
    """
    click.echo(
        click.style("⚠️  ", fg="yellow")
        + "This command is deprecated. Use 'brute-iam generate aws -s sdk --sdk-path ...' instead."
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

    if "identity" in results:
        lines.append("\n" + click.style("📋 Identity Information:", fg="yellow", bold=True))
        for key, value in results["identity"].items():
            lines.append(f"   {key}: {value}")

    if "permissions" in results:
        lines.append("\n" + click.style("🔓 Discovered Permissions:", fg="green", bold=True))
        permissions = results["permissions"]
        if isinstance(permissions, list):
            for perm in sorted(permissions):
                lines.append(f"   ✓ {perm}")
        elif isinstance(permissions, dict):
            for service, actions in sorted(permissions.items()):
                lines.append(f"\n   {click.style(service, fg='blue', bold=True)}:")
                if isinstance(actions, list):
                    for action in sorted(actions):
                        lines.append(f"      ✓ {action}")
                elif isinstance(actions, dict):
                    for action, data in actions.items():
                        lines.append(f"      ✓ {action}")

    if "errors" in results and results["errors"]:
        lines.append("\n" + click.style("⚠️  Errors:", fg="red", bold=True))
        for error in results["errors"]:
            lines.append(f"   • {error}")

    lines.append("\n" + click.style("=" * 60, fg="cyan"))

    total_perms = 0
    if "permissions" in results:
        if isinstance(results["permissions"], list):
            total_perms = len(results["permissions"])
        elif isinstance(results["permissions"], dict):
            for actions in results["permissions"].values():
                if isinstance(actions, list):
                    total_perms += len(actions)
                elif isinstance(actions, dict):
                    total_perms += len(actions)

    lines.append(f"  Total permissions discovered: {click.style(str(total_perms), fg='green', bold=True)}")
    lines.append(click.style("=" * 60, fg="cyan"))

    return "\n".join(lines)


def main() -> None:
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
