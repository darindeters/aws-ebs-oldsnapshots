# AWS EBS Old Snapshots Toolkit

## Project overview
This repository provides two operational helpers for AWS environments. The scripts were
initially authored for use inside **AWS CloudShell** so that platform teams could run
audits without installing anything on their local machines, but they work equally well
from any machine that can reach the AWS APIs:

* **`list_old_snapshots.py`** — audits Amazon EBS snapshots that are older than a configurable age across multiple accounts and regions. The tool supports AWS Organizations discovery, Identity Center (SSO) based authentication, and STS `AssumeRole` fallbacks, producing both console and CSV reports.
* **`sso_env.py`** — simplifies the IAM Identity Center device-authorization flow by emitting environment exports for a configured permission set. The helper script is primarily consumed by `list_old_snapshots.py`, but it can also be used standalone for shell sessions.

Typical use cases include:

* Finding unused or aged snapshots to reduce storage spend.
* Reporting per-account/per-region snapshot counts and sizes for governance.
* Quickly seeding shell environments with temporary Identity Center credentials.

## Prerequisites

* **Python**: 3.9 or later.
* **Dependencies**: [`boto3`](https://pypi.org/project/boto3/) and [`botocore`](https://pypi.org/project/botocore/) (installed automatically when using `pip install boto3`).
* **AWS credentials and permissions**:
  * The caller must have permission to invoke the AWS APIs used by the scripts (Organizations, STS, EC2, Pricing, SSO). Refer to the scripts for the exact API calls.
  * For Organizations-wide scans, the management account (or delegated admin) needs access to `organizations:ListAccounts`, `organizations:ListParents`, and related operations.
  * When using `--auth-mode assume-role`, ensure the specified role name exists in each target account with permissions to describe snapshots, describe images, and list volumes.
  * When using the Identity Center helper, the configured permission set must be assigned to each account you plan to audit.

## Setup

1. (Optional) Create and activate a virtual environment (CloudShell already ships with an
   isolated Python environment, so you can usually skip this step there):
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
2. Install the Python dependencies (CloudShell includes `boto3` out of the box, but the
   command is shown here for portability):
   ```bash
   pip install --upgrade pip
   pip install boto3
   ```
3. Clone this repository (if you have not already) and navigate into it:
   ```bash
   git clone https://github.com/your-org/aws-ebs-oldsnapshots.git
   cd aws-ebs-oldsnapshots
   ```

## `list_old_snapshots.py`

### Overview
`list_old_snapshots.py` is a command-line tool that discovers and reports on EBS snapshots that exceed a configurable age threshold. It can operate in a single account or across all accounts within an AWS Organization, with flexible region scoping and multiple authentication strategies.

### Key CLI arguments

| Argument | Description |
| --- | --- |
| `--days` | Age threshold in days (default: `30`). |
| `--region` | One or more regions (space or comma separated). Defaults to all commercial regions supported by your account session. |
| `--csv PATH` | Write the detailed results to the provided CSV file path. |
| `--profile` | Base AWS profile for the management account session. Helpful when multiple shared config profiles exist. |
| `--verbose` | Emit per-account authentication and identity details. Useful for troubleshooting permissions. |
| `--org-all` | Scan every **ACTIVE** account in the organization (optionally filtered by OU/root flags). |
| `--accounts` | Explicit list of 12-digit account IDs to include. |
| `--exclude-accounts` | Optional list of accounts to skip when running with `--org-all` or `--accounts`. |
| `--list-ous` / `--select-ou` / `--ou` / `--ou-recursive` / `--root` | Organization scoping helpers for targeting specific organizational units. |
| `--auth-mode` | Authentication strategy: `auto` (default), `sso-env`, or `assume-role`. |
| `--assume-role-name` | Role name to assume in each target account when `--auth-mode assume-role` (or when `auto` falls back). |
| `--sso-env-path` | Path to the Identity Center helper (default: `./sso_env.py`). |
| `--dry-run` | Preview targeted accounts/regions without calling `DescribeSnapshots`. |
| `--summary-only` | Print a concise per-account/per-region summary while suppressing snapshot row output. |
| `--used-by-ami` | Filter based on AMI usage (`all`, `only-unused`, `only-used`). |
| `--estimate-cost` | Enable storage cost calculations for the reported snapshots. |
| `--util-factor` | Utilization factor (0-1) used when snapshots lack `FullSnapshotSizeInBytes` metadata (default: `0.40`). |

Run `python list_old_snapshots.py --help` to view all supported options.

### Authentication modes

* **Auto (default)** — attempt to invoke `sso_env.py` to obtain temporary credentials. If that fails (e.g., permission set not assigned), fall back to `AssumeRole` using the provided role name.
* **SSO environment** (`--auth-mode sso-env`) — force Identity Center usage through the helper script.
* **AssumeRole** (`--auth-mode assume-role`) — skip Identity Center and directly assume the named role in each account.

When using the Identity Center flow, the script determines the session region in this order: the first valid region from `--region`, the base session region, or `us-west-2`.

### Example: organization-wide audit with CSV output

```bash
python list_old_snapshots.py \
  --org-all \
  --assume-role-name AuditRole \
  --days 90 \
  --region us-east-1 us-west-2 \
  --csv reports/ebs-old-snapshots.csv
```

Sample console output (truncated):

```text
[info] Scanning 24 accounts across 2 regions (threshold: 90 days)
[info] Account 123456789012 us-east-1 -> 8 snapshots (total 1.9 TiB)
[info] Account 123456789012 us-west-2 -> 3 snapshots (total 0.6 TiB)
...
[summary] 42 snapshots across 18 accounts (~9.4 TiB logical, ~$476/mo)
```

Sample CSV rows:

```csv
account_id,region,snapshot_id,age_days,size_gib,used_by_ami,storage_tier,estimated_monthly_usd
123456789012,us-east-1,snap-0abc123,427,75.0,unused,standard,3.75
123456789012,us-west-2,snap-09def456,312,15.0,used,archive,0.19
```

### Additional tips

* Use `--dry-run --verbose` to confirm account discovery and authentication before running the full audit.
* Pair `--summary-only` with `--estimate-cost` to get a quick financial view without detailed rows.
* The tool automatically deduplicates regions and warns about invalid region tokens.

## `sso_env.py`

### Configuration constants
At the top of the script, adjust the following constants to match your Identity Center environment:

```python
START_URL  = "https://example.awsapps.com/start"  # Identity Center start URL
SSO_REGION = "us-west-2"                           # Identity Center region
ROLE_NAME  = "Audit-ReadOnly"                      # Permission set/role name
```

### Behavior summary

* Loads cached Identity Center tokens when available.
* Falls back to the device-authorization flow if the cache is empty or expired, prompting you to approve the session in a browser.
* Validates that the configured permission set is assigned to the requested account before returning credentials.
* Emits shell-ready exports for the AWS access key, secret key, session token, region, and disables the AWS pager.

### Example usage

To open a new shell with temporary credentials for account `999999999999` in `us-west-2`:

```bash
account_id=999999999999
region=us-west-2
source <(python sso_env.py "$account_id" "$region")
aws sts get-caller-identity
```

Sample output:

```text
To authorize this session, open the following URL and, if asked, enter the code:
  URL : https://device.sso.us-west-2.amazonaws.com/verify?user_code=ABCD-EFGH
  Code: ABCD-EFGH
(Waiting for approval...)
...
{
    "UserId": "AIDAEXAMPLE",
    "Account": "999999999999",
    "Arn": "arn:aws:iam::999999999999:user/Audit-ReadOnly"
}
```

## Operational guidance

* **API rate limits**: The scripts use boto3 clients with the default retry configuration. For extremely large organizations, consider running during off-peak hours or limiting regions to reduce API volume.
* **Pagination**: `list_old_snapshots.py` paginates through Organizations, EC2 `DescribeSnapshots`, and SSO listings transparently. There is no user action required, but scans may take several minutes depending on the number of accounts and snapshots.
* **Known limitations**:
  * Only commercial AWS partitions are tested. GovCloud or China regions may require additional adjustments.
  * Cost estimation relies on AWS Pricing API data when available, falling back to hard-coded USD/GB-month figures (`standard` and `archive`). Verify pricing before acting on the estimates.
  * `sso_env.py` expects access to the local Identity Center cache at `~/.aws/sso/cache`. Non-standard cache locations are not currently supported.

## Contributions and testing

* Run `python list_old_snapshots.py --dry-run --verbose` against a small account set to validate new changes without incurring API-heavy operations.
* Keep `boto3` and `botocore` up to date to pick up API improvements.
* Contributions are welcome—open pull requests with a clear description of the enhancements or fixes. Please include manual testing notes or sample command outputs to demonstrate the change.
* For larger feature additions, consider adding docstrings or inline comments in the scripts to maintain clarity.

