# IAMX

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-%20%20GNU%20GPLv3%20-green)](https://opensource.org/licenses/MIT)

A powerful CLI tool for enumerating IAM permissions on AWS, GCP, and Azure cloud platforms. Discover what permissions a given set of credentials actually has through brute-force API testing.

## Features

- 🔍 **AWS IAM Enumeration**: Test AWS credentials against 400+ services and thousands of API operations
- 🔍 **GCP IAM Enumeration**: Test GCP credentials against 4000+ IAM permissions
- 🧪 **Azure RBAC Enumeration** *(Experimental)*: Test Azure credentials against 2000+ API operations
- 🚀 **Multi-threaded**: Fast parallel execution for API testing
- 📊 **Multiple Output Formats**: JSON or human-readable text output
- 🔧 **Auto-Update**: Generate test definitions from [IAM Dataset](https://github.com/iann0036/iam-dataset)
- 🛡️ **Safe**: Only uses read-only operations (list, describe, get)

## Installation

### From PyPI (recommended)

```bash
# Install with AWS support
pip install iamx[aws]

# Install with GCP support
pip install iamx[gcp]

# Install with Azure support (experimental)
pip install iamx[azure]

# Install with all cloud providers
pip install iamx[all]
```

### From Source

```bash
git clone https://github.com/Devang-Solanki/iamx.git
cd iamx
pip install -e ".[all]"
```

### Development Installation

```bash
git clone https://github.com/Devang-Solanki/iamx.git
cd iamx
pip install -e ".[all,dev]"
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

# Output to JSON file
iamx aws enumerate -o json -f results.json

# Verbose mode
iamx -v aws enumerate
```

### GCP Enumeration

```bash
# Using service account key file
export GOOGLE_CLOUD_PROJECT=my-project
iamx gcp enumerate -c service-account.json

# Using access token
iamx gcp enumerate -p my-project -t ya29...

# Output to JSON file
iamx gcp enumerate -p my-project -c key.json -o json -f results.json
```

### Azure Enumeration *(Experimental)*

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

# With specific subscription
iamx azure enumerate -s <subscription-id>

# Output to JSON file
iamx azure enumerate -o json -f results.json
```

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
  azure     Azure RBAC permission enumeration commands (experimental)
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
  -o, --output [json|text]   Output format (default: text)
  -f, --output-file PATH     Write output to file instead of stdout
  --help                     Show this message and exit.
```

### Azure Commands *(Experimental)*

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
   root_account: False
   arn: arn:aws:iam::762876141233:userstorage
   arn_id: 762876141233
   arn_path: user/storage

🔓 Discovered Permissions:

   bruteforce:
      ✓ sts.get_caller_identity
      ✓ sts.get_session_token
      ✓ dynamodb.describe_endpoints

   iam:

============================================================
  Total permissions discovered: 3
============================================================
```

### JSON Output

```json
{
  "identity": {
    "user_name": "admin-user",
    "arn": "arn:aws:iam::123456789012:user/admin-user",
    "account_id": "123456789012"
  },
  "permissions": {
    "iam": {
      "get_user": {...},
      "list_users": {...}
    },
    "bruteforce": {
      "ec2.describe_instances": {...},
      "s3.list_buckets": {...}
    }
  },
  "errors": []
}
```

## How It Works

### AWS Enumeration

1. **IAM API Enumeration**: First attempts to gather identity information using IAM API calls:
   - `get_user` / `get_role` - Get current identity
   - `get_account_authorization_details` - Get all IAM policies (if permitted)
   - `list_attached_user_policies` / `list_attached_role_policies`
   - `list_user_policies` / `list_role_policies`
   - `list_groups_for_user`

2. **Bruteforce Enumeration**: Tests hundreds of read-only API operations across AWS services:
   - Only uses `list_*`, `describe_*`, and `get_*` operations
   - Operations that require parameters are excluded
   - Multi-threaded execution (25 threads by default)
   - Randomized order to avoid detection patterns

### GCP Enumeration

1. Uses the Cloud Resource Manager API's `testIamPermissions` method
2. Tests 4000+ GCP IAM permissions in batches of 100
3. Returns all permissions the credentials have on the specified project

### Azure Enumeration *(Experimental)*

1. **Role Assignment Discovery**: Retrieves role assignments for the authenticated identity
2. **API Operation Testing**: Tests 2000+ Azure REST API operations (GET requests only)
   - Only uses read-only operations (GET methods)
   - Operations are grouped by resource provider
   - Multi-threaded execution (10 threads by default)
   - Randomized order to avoid detection patterns

> ⚠️ **Note**: Azure support is experimental. The author has limited Azure experience and welcomes community contributions to improve this feature. See [Contributing](#contributing) section below.

## Security Considerations

- **Read-Only Operations**: This tool only uses read-only API operations and will not modify any resources
- **Rate Limiting**: AWS may rate-limit requests; the tool includes retry logic
- **Detection**: Cloud providers may log and alert on enumeration activity
- **Credentials**: Never commit credentials to version control

## Updating Test Definitions

The tool can automatically download and generate test definitions from the [IAM Dataset](https://github.com/iann0036/iam-dataset) repository.

### Update AWS Tests (Recommended)

```bash
# Generate from IAM dataset (downloads automatically)
iamx generate aws

# This will:
# - Download the latest AWS IAM mappings from GitHub
# - Extract all list_*, describe_*, get_* operations
# - Generate iamx/aws/bruteforce_tests.py
```

### Update GCP Permissions

```bash
# Generate all GCP permissions
iamx generate gcp

# Generate only safe (read-only) permissions
iamx generate gcp --safe-only

# This will:
# - Download the latest GCP IAM mappings from GitHub
# - Extract all permissions from API methods
# - Generate iamx/gcp/permissions.py
```

### Update Azure Operations

```bash
# Generate from IAM dataset (downloads automatically)
iamx generate azure

# This will:
# - Download the latest Azure API specs from GitHub
# - Extract all GET operations (read-only)
# - Generate iamx/azure/operations.py
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

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before testing any cloud credentials. The authors are not responsible for any misuse or damage caused by this tool.
