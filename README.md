# IAMX

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-%20%20GNU%20GPLv3%20-green)](https://opensource.org/licenses/MIT)

Disclaimer: No AI was harmed during development.

A powerful CLI tool for enumerating IAM permissions across AWS, GCP, and Azure cloud platforms. Discover what permissions a given set of credentials actually has — and for AWS, whether those permissions can be abused to escalate access.

## Features

- 🔍 **AWS IAM Enumeration**: Test AWS credentials against 400+ services and thousands of API operations
- 🔍 **GCP IAM Enumeration**: Test GCP credentials against 4000+ IAM permissions
- 🧪 **Azure RBAC Enumeration**: Test Azure credentials against 2000+ API operations
- 🚨 **Privilege Escalation Detection**: Automatically checks discovered AWS permissions against 66+ known escalation paths (powered by [pathfinding.cloud](https://pathfinding.cloud))
- 🎯 **Service Groups**: Target specific service areas (`--group compute`, `--group security`, etc.) for faster, focused enumeration on both AWS and Azure
- ⚡ **EC2 Write Permission Testing**: Uses AWS DryRun to confirm 43 EC2 write permissions without creating any resources
- 🏷️ **Identity Enrichment**: Shows attached policy names, group memberships, and highlights admin-level policies
- 🛑 **Fast Credential Validation**: Stops enumeration immediately on expired or invalid credentials across all clouds
- 🚀 **Multi-threaded**: Fast parallel execution for API testing
- 📊 **Multiple Output Formats**: JSON or human-readable text output
- 🔧 **Auto-Update**: Sync bruteforce test definitions from [IAM Dataset](https://github.com/iann0036/iam-dataset) and privilege escalation paths from [pathfinding.cloud](https://pathfinding.cloud)
- 🛡️ **Safe**: Read-only operations for enumeration; EC2 write permissions tested via DryRun only

## Installation

### From pipx (recommended)

```bash
pipx install git+https://github.com/devang-solanki/iamx
```

### From Source

```bash
git clone https://github.com/Devang-Solanki/iamx.git
cd iamx
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/Devang-Solanki/iamx.git
cd iamx
pip install -e ".[dev]"
```

## Quick Start

### AWS Enumeration

```bash
# Using environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
iamx aws enumerate

# Using command line options
iamx aws enumerate --access-key AKIA... --secret-key ...

# With session token (temporary credentials)
iamx aws enumerate -a ASIA... -s ... -t ...

# Target only specific service groups (much faster)
iamx aws enumerate --access-key AKIA... --secret-key ... --group compute
iamx aws enumerate --access-key AKIA... --secret-key ... --group serverless --group iam

# Output to JSON file
iamx aws enumerate -o json -f results.json
```

**Available AWS service groups:** `serverless`, `compute`, `iam`, `storage`, `databases`, `network`, `devops`, `security`, `monitoring`, `ai`

### GCP Enumeration

```bash
# Using service account key file
export GOOGLE_CLOUD_PROJECT=my-project
iamx gcp enumerate -c service-account.json

# Using access token
iamx gcp enumerate -p my-project -t ya29...

# Target only specific service groups (much faster)
iamx gcp enumerate -p my-project -c key.json --group storage
iamx gcp enumerate -p my-project -c key.json --group iam --group security

# Output to JSON file
iamx gcp enumerate -p my-project -c key.json -o json -f results.json
```

**Available GCP service groups:** `compute`, `network`, `storage`, `databases`, `serverless`, `iam`, `security`, `monitoring`, `ai`, `devops`, `data`

### Azure Enumeration

```bash
# Using credentials JSON file
iamx azure enumerate --credentials-file azure-creds.json

# Using service principal (client credentials)
iamx azure enumerate -t <tenant-id> -c <client-id> --client-secret <secret>

# Using environment variables
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
iamx azure enumerate

# Target only specific service groups
iamx azure enumerate -t <tenant-id> -c <client-id> --client-secret <secret> --group compute
iamx azure enumerate -t <tenant-id> -c <client-id> --client-secret <secret> --group security --group iam

# With specific subscription and resource group
iamx azure enumerate -s <subscription-id> -g <resource-group>

# Output to JSON file
iamx azure enumerate -o json -f results.json
```

**Available Azure service groups:** `compute`, `network`, `storage`, `databases`, `iam`, `security`, `monitoring`, `serverless`, `ai`, `devops`

**Credentials JSON file format:**
```json
{
    "clientId": "your-client-id",
    "clientSecret": "your-client-secret",
    "tenantId": "your-tenant-id",
    "subscriptionId": "optional-subscription-id"
}
```

## Usage

### Command Structure

```
iamx [OPTIONS] COMMAND [ARGS]...

Options:
  --version      Show the version and exit.
  -v, --verbose  Enable verbose output
  --help         Show this message and exit.

Commands:
  aws       AWS IAM permission enumeration commands
  gcp       GCP IAM permission enumeration commands
  azure     Azure RBAC permission enumeration commands
  generate  Generate bruteforce test definitions
```

### AWS Commands

#### Enumerate Permissions

```bash
iamx aws enumerate [OPTIONS]

Options:
  -a, --access-key TEXT      AWS Access Key ID (or set AWS_ACCESS_KEY_ID env var)
  -s, --secret-key TEXT      AWS Secret Access Key (or set AWS_SECRET_ACCESS_KEY env var)
  -t, --session-token TEXT   AWS Session Token for temporary credentials
  -r, --region TEXT          AWS Region (default: us-east-1)
  -g, --group TEXT           Limit enumeration to a service group. Can be specified multiple times.
                             Choices: serverless, compute, iam, storage, databases, network,
                             devops, security, monitoring, ai
  -o, --output [json|text]   Output format (default: text)
  -f, --output-file PATH     Write output to file instead of stdout
  --help                     Show this message and exit.
```

### GCP Commands

#### Enumerate Permissions

```bash
iamx gcp enumerate [OPTIONS]

Options:
  -p, --project TEXT         GCP Project ID (required, or set GOOGLE_CLOUD_PROJECT env var)
  -c, --credentials PATH     Path to service account JSON key file
  -t, --token TEXT           Access token for authentication
  -g, --group TEXT           Limit enumeration to a service group. Can be specified multiple times.
                             Choices: compute, network, storage, databases, serverless, iam,
                             security, monitoring, ai, devops, data
  -o, --output [json|text]   Output format (default: text)
  -f, --output-file PATH     Write output to file instead of stdout
  --help                     Show this message and exit.
```

### Azure Commands

#### Enumerate Permissions

```bash
iamx azure enumerate [OPTIONS]

Options:
  -s, --subscription TEXT    Azure Subscription ID (or set AZURE_SUBSCRIPTION_ID env var)
  -t, --tenant TEXT          Azure AD Tenant ID (or set AZURE_TENANT_ID env var)
  -c, --client-id TEXT       Azure AD Application (Client) ID (or set AZURE_CLIENT_ID env var)
  --client-secret TEXT       Azure AD Client Secret (or set AZURE_CLIENT_SECRET env var)
  --credentials-file PATH    Path to JSON file with Azure credentials
  --token TEXT               Pre-obtained access token for authentication
  -g, --resource-group TEXT  Resource group to test against (optional)
  --group TEXT               Limit enumeration to a service group. Can be specified multiple times.
                             Choices: compute, network, storage, databases, iam, security,
                             monitoring, serverless, ai, devops
  -o, --output [json|text]   Output format (default: text)
  -f, --output-file PATH     Write output to file instead of stdout
  --help                     Show this message and exit.
```

### Generate Commands

The generate commands allow you to update the test definitions from the [IAM Dataset](https://github.com/iann0036/iam-dataset) repository, which maintains comprehensive mappings of cloud API methods to IAM permissions.

#### Generate AWS Tests

```bash
iamx generate aws [OPTIONS]

Options:
  -s, --source [iam-dataset|sdk]  Source for generating tests (default: iam-dataset)
  --sdk-path PATH                 Path to aws-sdk-js/apis directory (required if source=sdk)
  -u, --dataset-url TEXT          URL to IAM dataset JSON
  -o, --output-file PATH          Output file path (default: iamx/aws/bruteforce_tests.py)
  --privesc-url TEXT              URL to fetch privilege escalation paths from
                                  (default: https://pathfinding.cloud/paths.json)
  --help                          Show this message and exit.
```

#### Generate GCP Permissions

```bash
iamx generate gcp [OPTIONS]

Options:
  -u, --dataset-url TEXT  URL to GCP IAM dataset JSON
  -o, --output-file PATH  Output file path (default: iamx/gcp/permissions.py)
  --safe-only             Only include safe (read-only) permissions
  --help                  Show this message and exit.
```

#### Generate Azure Operations

```bash
iamx generate azure [OPTIONS]

Options:
  -s, --source-file PATH    Path to local Azure API specs JSON file
  -u, --dataset-url TEXT    URL to Azure API dataset JSON
  -o, --output-file PATH    Output file path (default: iamx/azure/operations.py)
  --help                    Show this message and exit.
```

## Output Examples

### Text Output

```
============================================================
  IAM Enumeration Results
============================================================

📋 Identity Information:
   arn: arn:aws:iam::123456789012:user/AdminDev
   user_name: AdminDev
   attached_policies:
      • ⚡ AdministratorAccess [ADMIN]
   groups:
      • Developers

🔓 Discovered Permissions:

   ⚠️  High Value: get_account_authorization_details succeeded — full account IAM policies are readable

   bruteforce:
      ✓ ec2.describe_instances
      ✓ ec2.describe_vpcs
      ✓ ec2.run_instances
      ✓ ec2.terminate_instances
      ✓ ec2.create_security_group
      ✓ lambda.list_functions
      ✓ s3.list_buckets
      ...

🚨 Privilege Escalation Paths Detected:

   ec2:ModifyInstanceAttribute + ec2:StopInstances + ec2:StartInstances  [PassRole → Existing Resource]
   ID: ec2-002
   Required: ec2:ModifyInstanceAttribute, ec2:StopInstances, ec2:StartInstances

============================================================
  Total permissions discovered: 260
============================================================
```

### JSON Output

```json
{
  "identity": {
    "user_name": "deploy-user",
    "arn": "arn:aws:iam::123456789012:user/deploy-user"
  },
  "permissions": {
    "iam": {
      "get_user": {},
      "list_attached_user_policies": {}
    },
    "bruteforce": {
      "ec2.describe_instances": {},
      "s3.list_buckets": {},
      "ec2.run_instances": {"dryrun": true, "permitted": true}
    }
  },
  "privilege_escalation": {
    "paths_found": 1,
    "paths": [
      {
        "id": "lambda-001",
        "name": "iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction",
        "category": "new-passrole",
        "description": "...",
        "required_permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"]
      }
    ]
  },
  "errors": []
}
```

## How It Works

### AWS Enumeration

1. **Identity & IAM Discovery**: Gathers identity information and attached policies:
   - `get_user` / `get_role` — resolve current principal
   - `get_account_authorization_details` — full account IAM policies (high-value if permitted)
   - `list_attached_user_policies` / `list_attached_role_policies` — attached managed policies
   - `list_groups_for_user` — group memberships
   - Attached policy names and admin-level policies are highlighted in the output

2. **Bruteforce Enumeration**: Tests hundreds of read-only API operations in parallel:
   - Only uses `list_*`, `describe_*`, and `get_*` operations
   - Use `--group` to target a specific service area and reduce test count significantly
   - 25 threads by default, randomized order

3. **EC2 Write Permission Testing**: Uses AWS `DryRun=True` to confirm 43 EC2 write permissions without creating any resources:
   - AWS checks authorization before resource validation — any response other than `UnauthorizedOperation` means the permission is confirmed
   - Covers instance lifecycle, volumes/snapshots, networking, security groups, key pairs, launch templates, and more

4. **Privilege Escalation Detection**: Checks all discovered permissions against 66+ known escalation paths:
   - Scoped strictly to the current principal's policies (no false positives from other users)
   - Handles wildcards (`*`, `iam:*`) correctly
   - Powered by [pathfinding.cloud](https://pathfinding.cloud)
   - Four categories: PassRole (new resource), PassRole (existing resource), self-escalation, direct principal access

### GCP Enumeration

1. Uses the Cloud Resource Manager API's `testIamPermissions` method
2. Tests 4000+ GCP IAM permissions in batches of 100
3. Returns all permissions the credentials have on the specified project

> **Note**: Requires the Cloud Resource Manager API to be enabled on the project.

### Azure Enumeration

1. **Role Assignment Discovery**: Retrieves RBAC role assignments for the authenticated identity
2. **API Operation Testing**: Tests 2000+ Azure REST API operations:
   - Only uses read-only GET operations
   - Use `--group` to restrict to a specific service area (e.g. `--group compute` tests ~66 ops instead of 2000+)
   - Operations requiring a resource group are skipped unless `--resource-group` is provided
   - 10 threads by default, randomized order

## Security Considerations

- **Read-Only Operations**: Enumeration uses only read-only API calls and will not modify any resources
- **DryRun for Writes**: EC2 write permissions are tested via `DryRun=True` — AWS confirms or denies the permission without executing the operation
- **Credential Safety**: Enumeration stops immediately on invalid or expired credentials (401/403 fatal errors)
- **Detection**: Cloud providers log API activity; enumeration may appear in CloudTrail, GCP Audit Logs, or Azure Monitor
- **Credentials**: Never commit credentials to version control

## Updating Test Definitions

The tool can automatically download and generate test definitions from the [IAM Dataset](https://github.com/iann0036/iam-dataset) repository.

### Update AWS Tests

```bash
# Generate from IAM dataset and sync privilege escalation paths
iamx generate aws

# This will:
# - Download the latest AWS IAM mappings from GitHub
# - Extract all list_*, describe_*, get_* operations
# - Generate iamx/aws/bruteforce_tests.py
# - Fetch the latest privilege escalation paths from pathfinding.cloud
# - Merge new/updated paths into the local privesc database

# Use a custom privesc source URL
iamx generate aws --privesc-url https://pathfinding.cloud/paths.json
```

### Update GCP Permissions

```bash
# Generate all GCP permissions
iamx generate gcp

# Generate only safe (read-only) permissions
iamx generate gcp --safe-only
```

### Update Azure Operations

```bash
# Generate from IAM dataset (downloads automatically)
iamx generate azure
```

### Legacy: Generate from AWS SDK

```bash
# Clone the AWS SDK JS repository
git clone --depth 1 https://github.com/aws/aws-sdk-js.git

# Generate tests from SDK (legacy method)
iamx generate aws -s sdk --sdk-path ./aws-sdk-js/apis

# Clean up
rm -rf aws-sdk-js
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Original GCP enumeration concept from [NicholasSpringer's thunder-ctf](https://github.com/NicholasSpringer/thunder-ctf/tree/master/scripts)
- Original AWS enumeration concept from [andresriancho's enumerate-iam](https://github.com/andresriancho/enumerate-iam)
- [IAM Dataset](https://github.com/iann0036/iam-dataset) by Ian Mckay for comprehensive AWS and GCP IAM mappings
- [pathfinding.cloud](https://pathfinding.cloud) for the AWS privilege escalation path database
- Inspired by [cliam](https://github.com/securisec/cliam) for service group and DryRun enumeration concepts

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before testing any cloud credentials. The authors are not responsible for any misuse or damage caused by this tool.
