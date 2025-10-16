#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
List EBS snapshots older than N days across one or many AWS accounts and regions.

This build:
- QUIET by default (use --verbose for per-account auth/identity logs).
- --region accepts space- and comma-separated values.
- Auth modes:
    * --auth-mode sso-env  -> use sso_env.py
    * --auth-mode assume-role -> STS AssumeRole into members
    * --auth-mode auto (default) -> try sso_env.py first, then AssumeRole fallback
- Defaults to ./sso_env.py (override with --sso-env-path).
- No --sso-env-region flag; we pass a single *session* region to sso_env.py derived from args/env.
- Cost estimate uses FullSnapshotSizeInBytes when present; util_factor only if missing.
- Fast AMI usage check (one DescribeImages per region).
- OU scoping: --list-ous, --select-ou, --ou, --ou-recursive, --root.
"""

import argparse
import csv
import sys
import time
import json
import os
import re
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Iterable, List, Dict, Any, Optional, Set, Tuple
from collections import defaultdict

import boto3
from boto3.session import Session as BotoSession
from botocore.config import Config
from botocore.exceptions import ClientError, EndpointConnectionError

# --------- Pricing fallbacks (USD/GB-month) ---------
FALLBACK_PRICES = {"standard": 0.05, "archive": 0.0125}

# --------- Region code -> AWS Pricing "location" text ---------
AWS_LOCATION_NAME = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-central-2": "EU (Zurich)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "eu-south-2": "EU (Spain)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-east-1": "Asia Pacific (Hong Kong)",
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
    "af-south-1": "Africa (Cape Town)",
    "sa-east-1": "South America (São Paulo)",
}

BYTES_PER_GIB = 1024.0 ** 3
ENV_LINE = re.compile(r'^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$')

# ---------------------- ARGS ----------------------

def parse_args():
    p = argparse.ArgumentParser(description="List EBS snapshots older than N days across accounts.")
    p.add_argument("--days", type=int, default=30, help="Age threshold in days (default: 30).")
    p.add_argument("--region", nargs="*", default=[],
                   help="One or more regions; supports comma-separated too (e.g. us-east-1,us-west-2 eu-central-1).")
    p.add_argument("--csv", dest="csv_path", help="Optional CSV output path.")
    p.add_argument("--profile", help="AWS profile for the base session (optional in CloudShell).")
    p.add_argument("--verbose", action="store_true", help="Verbose logging (show per-account auth, identities, etc.).")

    # Discovery / scoping
    p.add_argument("--org-all", action="store_true",
                   help="Scan all ACTIVE org accounts (unless limited by --ou/--root).")
    p.add_argument("--accounts", nargs="*", default=[],
                   help="Explicit list of 12-digit account IDs to scan.")
    p.add_argument("--exclude-accounts", nargs="*", default=[],
                   help="Optional list of account IDs to exclude.")
    p.add_argument("--list-ous", action="store_true",
                   help="List Org Roots and OUs and exit.")
    p.add_argument("--select-ou", action="store_true",
                   help="Interactive OU picker; then proceed to scan selected OUs.")
    p.add_argument("--ou", nargs="*", default=[],
                   help="One or more OU IDs (ou-xxxx) to include. Use --ou-recursive to include descendants.")
    p.add_argument("--ou-recursive", action="store_true",
                   help="Include descendant OUs of any --ou (or --select-ou) passed.")
    p.add_argument("--root", help="Root ID (r-xxxx) to scope OU listing or account discovery.")

    # Auth selection
    p.add_argument("--auth-mode", choices=["auto", "sso-env", "assume-role"], default="auto",
                   help="How to auth into member accounts: 'sso-env', 'assume-role', or 'auto' (default).")
    p.add_argument("--assume-role-name",
                   help="Role name to assume in target accounts (used with --auth-mode=assume-role or auto fallback).")

    # SSO env integration
    p.add_argument("--sso-env", action="store_true",
                   help="(Deprecated) Alias for --auth-mode sso-env.")
    p.add_argument("--sso-env-path", default="./sso_env.py",
                   help="Path to sso_env.py (default: ./sso_env.py).")

    # Preview / summary
    p.add_argument("--dry-run", action="store_true",
                   help="Preview target accounts/regions; no DescribeSnapshots.")
    p.add_argument("--summary-only", action="store_true",
                   help="Print a per-account/region summary (count, total GiB) and suppress row output.")

    # Filters + cost estimate
    p.add_argument("--used-by-ami", choices=["all", "only-unused", "only-used"], default="all",
                   help="Filter snapshots by whether they back an AMI (default: all).")
    p.add_argument("--estimate-cost", action="store_true",
                   help="Estimate monthly $ for results and sum potential savings if deleted.")
    p.add_argument("--util-factor", type=float, default=0.40,
                   help="Estimated billed GiB fraction of *logical* size (0-1). Used only when FullSnapshotSizeInBytes is missing.")

    return p.parse_args()

# ----------------- UTIL / NORMALIZATION -----------------

def normalize_regions(arg_regions: List[str]) -> List[str]:
    """Accept ['us-east-1,us-west-2', 'eu-central-1'] or ['us-east-1','us-west-2']; return flat validated list."""
    flat: List[str] = []
    for token in arg_regions or []:
        parts = [p.strip() for p in token.split(",") if p.strip()]
        flat.extend(parts)
    out: List[str] = []
    for r in flat:
        # Looser pattern to allow gov/cn if needed; still basic sanity
        if re.fullmatch(r"[a-z0-9-]+-\d", r):
            out.append(r)
        else:
            print(f"[warn] Ignoring invalid region token: {r}", file=sys.stderr)
    seen = set(); deduped = []
    for r in out:
        if r not in seen:
            seen.add(r); deduped.append(r)
    return deduped

def pick_session_region_for_sso_env(args, base_sess: BotoSession) -> str:
    """
    Ensure sso_env.py receives exactly one *session* region.
    Priority:
    1) first valid from --region
    2) current session/env region
    3) 'us-west-2'
    """
    regs = normalize_regions(args.region)
    if regs:
        return regs[0]
    env_region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
    if env_region and re.fullmatch(r"[a-z0-9-]+-\d", env_region):
        return env_region
    if base_sess.region_name and re.fullmatch(r"[a-z0-9-]+-\d", base_sess.region_name):
        return base_sess.region_name
    return "us-west-2"

# ---------------- SESSION / IDENTITY ----------------

def get_base_session(profile: Optional[str] = None) -> BotoSession:
    return boto3.Session(profile_name=profile) if profile else boto3.Session()

def get_current_account_and_role(sess: BotoSession) -> Tuple[str, Optional[str]]:
    sts = sess.client("sts")
    ident = sts.get_caller_identity()
    account_id = ident["Account"]
    arn = ident["Arn"]  # arn:aws:sts::123:assumed-role/RoleName/Session
    role_name = None
    parts = arn.split(":")[-1].split("/")
    if len(parts) >= 2 and parts[0].endswith("assumed-role"):
        role_name = parts[1]
    return account_id, role_name

def assume_into_account(sess: BotoSession, account_id: str, role_name: str) -> Optional[BotoSession]:
    arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = sess.client("sts")
    try:
        resp = sts.assume_role(RoleArn=arn, RoleSessionName=f"snapshot-audit-{int(time.time())}")
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError as e:
        print(f"[warn] AssumeRole failed for {arn}: {e}", file=sys.stderr)
        return None

def session_from_sso_env(py_path: str, account_id: str, region: str) -> Optional[BotoSession]:
    """
    Run: python sso_env.py <account_id> <region>
    Parse lines like 'export AWS_ACCESS_KEY_ID=...' and build a boto3.Session with those creds.
    """
    if not os.path.isabs(py_path):
        py_path = os.path.abspath(py_path)
    if not os.path.exists(py_path):
        print(f"[warn] sso_env.py not found at {py_path}", file=sys.stderr)
        return None

    try:
        out = subprocess.check_output([sys.executable, py_path, account_id, region], text=True)
    except subprocess.CalledProcessError as e:
        print(f"[warn] sso_env.py failed for {account_id}: {e}", file=sys.stderr)
        return None

    env: Dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = ENV_LINE.match(line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if len(v) >= 2 and ((v[0] == v[-1] == '"') or (v[0] == v[-1] == "'")):
            v = v[1:-1]
        env[k] = v

    ak = env.get("AWS_ACCESS_KEY_ID")
    sk = env.get("AWS_SECRET_ACCESS_KEY")
    tk = env.get("AWS_SESSION_TOKEN")
    rg = env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or region

    if not (ak and sk and tk):
        print(f"[warn] sso_env.py did not return complete credentials for {account_id}. Got: {list(env.keys())}", file=sys.stderr)
        return None

    return boto3.Session(
        aws_access_key_id=ak,
        aws_secret_access_key=sk,
        aws_session_token=tk,
        region_name=rg,
    )

def validate_session_identity(sess: BotoSession, expect_account: str, verbose: bool) -> None:
    if not verbose:
        return
    try:
        sts = sess.client("sts")
        ident = sts.get_caller_identity()
        print(f"    identity: account={ident.get('Account')} arn={ident.get('Arn')}")
        if ident.get("Account") != expect_account:
            print(f"    [warn] expected account {expect_account} but got {ident.get('Account')}", file=sys.stderr)
    except Exception as e:
        print(f"    [warn] STS validation failed for {expect_account}: {e}", file=sys.stderr)

# -------------------- ORGANIZATIONS --------------------

def org_client(sess: BotoSession):
    return sess.client("organizations")

def list_roots(sess: BotoSession) -> List[Dict[str, Any]]:
    return org_client(sess).list_roots().get("Roots", [])

def list_child_ous(sess: BotoSession, parent_id: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    token = None
    while True:
        kwargs = {"ParentId": parent_id}
        if token:
            kwargs["NextToken"] = token
        resp = org_client(sess).list_organizational_units_for_parent(**kwargs)
        out.extend(resp.get("OrganizationalUnits", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out

def list_accounts_for_parent(sess: BotoSession, parent_id: str) -> List[str]:
    out: List[str] = []
    token = None
    while True:
        kwargs = {"ParentId": parent_id}
        if token:
            kwargs["NextToken"] = token
        resp = org_client(sess).list_accounts_for_parent(**kwargs)
        for a in resp.get("Accounts", []):
            if a.get("Status") == "ACTIVE":
                out.append(a.get("Id"))
        token = resp.get("NextToken")
        if not token:
            break
    return out

def walk_ou_tree(sess: BotoSession, start_ids: List[str]) -> Set[str]:
    seen: Set[str] = set()
    stack: List[str] = list(start_ids)
    while stack:
        pid = stack.pop()
        if pid in seen:
            continue
        seen.add(pid)
        for child in list_child_ous(sess, pid):
            stack.append(child["Id"])
    return seen

def build_ou_paths(sess: BotoSession, root_id: str, root_name: str) -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    def _walk(parent_id: str, prefix: str):
        for child in list_child_ous(sess, parent_id):
            ou_id = child["Id"]
            ou_name = child.get("Name", "")
            path = (prefix + "/" + ou_name) if prefix else ou_name
            items.append({"Id": ou_id, "Name": ou_name, "Path": path})
            _walk(ou_id, path)
    _walk(root_id, root_name)
    return items

def list_all_org_accounts(sess: BotoSession) -> List[str]:
    out: List[str] = []
    token = None
    while True:
        kwargs = {}
        if token:
            kwargs["NextToken"] = token
        resp = org_client(sess).list_accounts(**kwargs)
        for a in resp.get("Accounts", []):
            if a.get("Status") == "ACTIVE":
                out.append(a.get("Id"))
        token = resp.get("NextToken")
        if not token:
            break
    return out

# ------------------ EC2 / PRICING HELPERS ------------------

def list_regions(sess: BotoSession, explicit_regions: List[str]) -> List[str]:
    expl = normalize_regions(explicit_regions)
    if expl:
        return expl
    try:
        ec2 = sess.client("ec2")
        resp = ec2.describe_regions(AllRegions=False)
        return sorted([r["RegionName"] for r in resp.get("Regions", [])])
    except ClientError as e:
        print(f"Error describing regions: {e}", file=sys.stderr)
        return []

def paginate_snapshots(ec2_client) -> Iterable[Dict[str, Any]]:
    paginator = ec2_client.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"], PaginationConfig={"PageSize": 1000}):
        for snap in page.get("Snapshots", []):
            yield snap

def build_ami_snapshot_set(ec2_client) -> Set[str]:
    """
    One paginated DescribeImages per region; returns set of SnapshotIds referenced by owned AMIs.
    """
    used: Set[str] = set()
    token = None
    while True:
        kwargs = {
            "Owners": ["self"],
            "Filters": [{"Name": "state", "Values": ["available"]}],
            "MaxResults": 1000,
        }
        if token:
            kwargs["NextToken"] = token
        resp = ec2_client.describe_images(**kwargs)
        for img in resp.get("Images", []):
            for bdm in img.get("BlockDeviceMappings", []):
                ebs = bdm.get("Ebs") or {}
                sid = ebs.get("SnapshotId")
                if sid:
                    used.add(sid)
        token = resp.get("NextToken")
        if not token:
            break
    return used

def _pricing_lookup(pricing_client, location_text: str, usagetype_substring: str) -> Optional[float]:
    try:
        resp = pricing_client.get_products(
            ServiceCode="AmazonEC2",
            Filters=[
                {"Type": "TERM_MATCH", "Field": "productFamily", "Value": "Storage Snapshot"},
                {"Type": "TERM_MATCH", "Field": "location", "Value": location_text},
                {"Type": "TERM_MATCH", "Field": "usagetype", "Value": usagetype_substring},
            ],
            MaxResults=100
        )
        for item in resp.get("PriceList", []):
            data = json.loads(item)
            terms = data.get("terms", {}).get("OnDemand", {})
            for _k, term in terms.items():
                for _dk, dim in term.get("priceDimensions", {}).items():
                    if dim.get("unit") == "GB-Mo":
                        usd = dim.get("pricePerUnit", {}).get("USD")
                        if usd:
                            return float(usd)
    except Exception:
        pass
    return None

def get_snapshot_prices(sess: BotoSession, region_name: str) -> Dict[str, float]:
    prices = {"standard": FALLBACK_PRICES["standard"], "archive": FALLBACK_PRICES["archive"]}
    try:
        location = AWS_LOCATION_NAME.get(region_name)
        if not location:
            return prices
        pricing = sess.client("pricing", region_name="us-east-1")
        p_std = _pricing_lookup(pricing, location, "EBS:SnapshotUsage")
        p_arc = _pricing_lookup(pricing, location, "EBS:SnapshotArchiveUsage")
        if p_std is not None:
            prices["standard"] = p_std
        if p_arc is not None:
            prices["archive"] = p_arc
    except Exception:
        pass
    return prices

# --------------------- COLLECTION ---------------------

def collect_old_snapshots_for_session(
    sess: BotoSession,
    account_id: str,
    regions: List[str],
    cutoff: datetime,
    cfg: Config,
    used_by_ami_filter: str = "all",
    estimate_cost: bool = False,
    util_factor: float = 0.40
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    regional_prices_cache: Dict[str, Dict[str, float]] = {}

    for region in regions:
        try:
            ec2 = sess.client("ec2", region_name=region, config=cfg)

            # Build AMI snapshot index once per region (fast)
            ami_snapshot_ids: Optional[Set[str]] = None
            need_ami_flag = (used_by_ami_filter != "all")
            populate_usedbyami_column = True
            ami_lookup_available = False
            if need_ami_flag or populate_usedbyami_column:
                try:
                    ami_snapshot_ids = build_ami_snapshot_set(ec2)
                    ami_lookup_available = True
                except ClientError as e:
                    err_code = str(e.response.get("Error", {}).get("Code", "")) if hasattr(e, "response") else ""
                    if err_code in {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"}:
                        if need_ami_flag:
                            print(
                                f"[warn] {account_id}: missing DescribeImages permission in {region}; skipping AMI usage filter.",
                                file=sys.stderr,
                            )
                            continue
                        else:
                            print(
                                f"[warn] {account_id}: missing DescribeImages permission in {region}; continuing without AMI usage column.",
                                file=sys.stderr,
                            )
                            populate_usedbyami_column = False
                    else:
                        raise

            # Pricing per region (cached)
            prices = None
            if estimate_cost:
                if region not in regional_prices_cache:
                    regional_prices_cache[region] = get_snapshot_prices(sess, region)
                prices = regional_prices_cache[region]

            for snap in paginate_snapshots(ec2):
                start = snap.get("StartTime")
                if not isinstance(start, datetime):
                    continue
                if start > cutoff:
                    continue

                snap_id = snap.get("SnapshotId", "")

                # AMI usage flag from prebuilt set
                used_by_ami: Any
                if ami_lookup_available and ami_snapshot_ids is not None and snap_id:
                    used_by_ami = snap_id in ami_snapshot_ids
                elif populate_usedbyami_column:
                    used_by_ami = False
                else:
                    used_by_ami = ""

                if used_by_ami_filter == "only-unused" and used_by_ami:
                    continue
                if used_by_ami_filter == "only-used" and not used_by_ami:
                    continue

                vol_size_gib = float(snap.get("VolumeSize", 0) or 0.0)
                full_bytes = snap.get("FullSnapshotSizeInBytes")
                # Prefer logical size from full bytes; fallback to VolumeSizeGiB
                logical_gib = (float(full_bytes) / BYTES_PER_GIB) if isinstance(full_bytes, (int, float)) else vol_size_gib

                tier = str(snap.get("StorageTier") or "standard").lower()
                if tier not in ("standard", "archive"):
                    tier = "standard"

                # --- Cost estimation ---
                est_monthly_usd = ""
                est_billed_gib = ""
                price_used = ""
                util_applied = ""

                if estimate_cost:
                    price_used = round(prices.get(tier, FALLBACK_PRICES.get(tier, FALLBACK_PRICES["standard"])), 5)

                    if isinstance(full_bytes, (int, float)):
                        # We have the full snapshot size in bytes -> bill on that directly
                        est_billed_gib = round(logical_gib, 2)
                        util_applied = ""  # not applied
                    else:
                        # No full-bytes info -> apply util_factor to fallback logical size
                        uf = max(0.0, min(1.0, util_factor))
                        est_billed_gib = round(logical_gib * uf, 2)
                        util_applied = uf

                    est_monthly_usd = round(est_billed_gib * price_used, 2)

                rows.append({
                    "AccountId": account_id,
                    "Region": region,
                    "SnapshotId": snap_id,
                    "VolumeId": snap.get("VolumeId", ""),
                    "StartTime": start.isoformat(),
                    "AgeDays": int((datetime.now(timezone.utc) - start).days),
                    "State": snap.get("State", ""),
                    "VolumeSizeGiB": int(vol_size_gib),
                    "FullSnapshotSizeInBytes": full_bytes if full_bytes is not None else "",
                    "Encrypted": snap.get("Encrypted", False),
                    "KmsKeyId": snap.get("KmsKeyId", ""),
                    "Description": (snap.get("Description") or ""),
                    "Tags": ";".join([f"{t.get('Key')}={t.get('Value')}" for t in (snap.get("Tags") or [])]),
                    "OwnerId": snap.get("OwnerId", ""),
                    "StorageTier": tier,
                    "Progress": snap.get("Progress", ""),
                    "UsedByAMI": used_by_ami,
                    # Cost fields
                    "UtilFactor": util_applied,            # "" when not applied
                    "PriceUSDperGBMo": price_used,
                    "EstBilledGiB": est_billed_gib,
                    "EstMonthlyUSD": est_monthly_usd,
                })
        except EndpointConnectionError:
            print(f"[skip] {account_id}: region not reachable: {region}", file=sys.stderr)
        except ClientError as e:
            print(f"[warn] {account_id}: error in region {region}: {e}", file=sys.stderr)
    return rows

# ------------------ INTERACTIVE PICKER ------------------

def prompt_select_from_list(items: List[Dict[str, str]], title: str) -> List[int]:
    print("\n" + title)
    for idx, it in enumerate(items, 1):
        print(f"  {idx:>3}) {it.get('Path', it.get('Name', ''))}  [{it.get('Id','')}]")
    raw = input("\nSelect one or more numbers (e.g., 1,4,7-9): ").strip()
    if not raw:
        return []
    selected = set()
    parts = [p.strip() for p in raw.split(",")]
    for p in parts:
        if "-" in p:
            a, b = p.split("-", 1)
            try:
                a_i = int(a); b_i = int(b)
                for i in range(min(a_i, b_i), max(a_i, b_i)+1):
                    selected.add(i-1)
            except ValueError:
                pass
        else:
            try:
                selected.add(int(p)-1)
            except ValueError:
                pass
    return sorted([i for i in selected if 0 <= i < len(items)])

# ---------------- AUTH LOGIC (AUTO MODE) ----------------

def obtain_member_session_auto(
    base_sess: BotoSession,
    current_account: str,
    target_account: str,
    args,
    target_role_name: Optional[str],
) -> Optional[BotoSession]:
    """
    Auto mode: try sso_env.py first; if that fails, try AssumeRole with target_role_name.
    """
    if target_account == current_account:
        return base_sess

    # Try sso_env.py first
    sess_region = pick_session_region_for_sso_env(args, base_sess)
    sso_sess = session_from_sso_env(args.sso_env_path, target_account, sess_region)
    if sso_sess:
        if args.verbose:
            print(f"[info] {target_account}: auth via sso_env.py")
            validate_session_identity(sso_sess, target_account, args.verbose)
        return sso_sess

    # Fallback to AssumeRole if we have a role name
    if target_role_name:
        if args.verbose:
            print(f"[info] {target_account}: sso_env failed; falling back to AssumeRole:{target_role_name}")
        assumed = assume_into_account(base_sess, target_account, target_role_name)
        if assumed:
            if args.verbose:
                validate_session_identity(assumed, target_account, args.verbose)
            return assumed

    if args.verbose:
        print(f"[warn] {target_account}: auto auth failed (no sso_env and no assume-role).", file=sys.stderr)
    return None

# -------------------------- MAIN --------------------------

def main():
    args = parse_args()
    # Back-compat: if --sso-env supplied, treat as --auth-mode sso-env
    if args.sso_env and args.auth_mode == "auto":
        args.auth_mode = "sso-env"

    base_sess = get_base_session(args.profile)
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)

    cfg = Config(
        retries={"max_attempts": 10, "mode": "standard"},
        connect_timeout=5,
        read_timeout=25,
    )

    current_acct, current_role = get_current_account_and_role(base_sess)
    target_role_name = args.assume_role_name if args.assume_role_name else (current_role or None)

    # --list-ous
    if args.list_ous:
        try:
            roots = list_roots(base_sess) if args.root is None else [{"Id": args.root, "Name": "(specified root)"}]
            print("Organizational Units")
            for r in roots:
                for ou in build_ou_paths(base_sess, r["Id"], "Root"):
                    print(f"  {ou['Path']}  [{ou['Id']}]")
            return
        except ClientError as e:
            print(f"[error] listing OUs failed: {e}", file=sys.stderr)
            return

    # OU selection
    selected_ou_ids: List[str] = []
    if args.select_ou:
        try:
            roots = list_roots(base_sess) if args.root is None else [{"Id": args.root, "Name": "(specified root)"}]
            ou_items: List[Dict[str, str]] = []
            for r in roots:
                ou_items.extend(build_ou_paths(base_sess, r["Id"], r.get("Name", r["Id"])))
            if not ou_items:
                print("[warn] No OUs found under the specified scope.", file=sys.stderr)
            else:
                idxs = prompt_select_from_list(ou_items, "Organizational Units")
                if idxs:
                    selected_ou_ids = [ou_items[i]["Id"] for i in idxs]
        except ClientError as e:
            print(f"[error] interactive OU selection failed: {e}", file=sys.stderr)

    # Target accounts
    target_accounts: List[str] = []
    if selected_ou_ids:
        parents = selected_ou_ids[:]
        if args.ou_recursive:
            parents = sorted(list(walk_ou_tree(base_sess, parents)))
        for pid in parents:
            target_accounts.extend(list_accounts_for_parent(base_sess, pid))
    elif args.ou:
        parents = args.ou[:]
        if args.ou_recursive:
            parents = sorted(list(walk_ou_tree(base_sess, parents)))
        for pid in parents:
            target_accounts.extend(list_accounts_for_parent(base_sess, pid))
    elif args.org_all:
        if args.root:
            target_accounts = list_accounts_for_parent(base_sess, args.root)
        else:
            target_accounts = list_all_org_accounts(base_sess)

    if args.accounts:
        target_accounts.extend(args.accounts)
    if not target_accounts:
        target_accounts = [current_acct]
    if args.exclude_accounts:
        ex = set(args.exclude_accounts)
        target_accounts = [a for a in target_accounts if a not in ex]
    target_accounts = sorted(list(set(target_accounts)))

    # DRY RUN
    if args.dry_run:
        print("\n=== DRY RUN PREVIEW ===")
        print(f"Current account: {current_acct} | current role: {current_role or '(none)'}")
        print(f"Auth mode for member accounts: {args.auth_mode}")
        print(f"Used-by-AMI filter: {args.used_by_ami}")
        if args.estimate_cost:
            print(f"Cost estimate ON | util_factor={args.util_factor:.2f} (applied only if FullSnapshotSizeInBytes missing)")
        print(f"Target accounts ({len(target_accounts)}): {', '.join(target_accounts)}")

        total_regions = 0
        for acct in target_accounts:
            # Determine session according to chosen auth mode
            if acct == current_acct:
                use_sess = base_sess
            elif args.auth_mode == "sso-env":
                sess_region = pick_session_region_for_sso_env(args, base_sess)
                use_sess = session_from_sso_env(args.sso_env_path, acct, sess_region)
                if not use_sess:
                    if args.verbose:
                        print(f"  {acct} -> [warn] sso_env failed; skipping region listing", file=sys.stderr)
                    continue
                if args.verbose:
                    validate_session_identity(use_sess, acct, args.verbose)
            elif args.auth_mode == "assume-role":
                if not target_role_name:
                    if args.verbose:
                        print(f"  {acct} -> [warn] no role name to assume; skipping", file=sys.stderr)
                    continue
                use_sess = assume_into_account(base_sess, acct, target_role_name)
                if not use_sess:
                    if args.verbose:
                        print(f"  {acct} -> [warn] assume failed; skipping", file=sys.stderr)
                    continue
                if args.verbose:
                    validate_session_identity(use_sess, acct, args.verbose)
            else:  # auto
                use_sess = obtain_member_session_auto(base_sess, current_acct, acct, args, target_role_name)
                if not use_sess:
                    if args.verbose:
                        print(f"  {acct} -> [warn] auto auth failed; skipping region listing", file=sys.stderr)
                    continue

            regs = list_regions(use_sess, args.region)
            total_regions += len(regs)
            if args.verbose:
                print(f"  {acct} -> regions ({len(regs)}): {', '.join(regs)}")
        print(f"Total regions across accounts: {total_regions}")
        print("No snapshots were queried because --dry-run was specified.")
        return

    # Collect + summaries
    all_rows: List[Dict[str, Any]] = []
    summary: Dict[Tuple[str, str], Dict[str, float]] = defaultdict(lambda: {"count": 0, "total_gib": 0.0, "est_usd": 0.0})

    for acct in target_accounts:
        # Determine session by mode
        if acct == current_acct:
            use_sess = base_sess
        elif args.auth_mode == "sso-env":
            if args.verbose:
                print(f"[info] {acct}: obtaining creds via sso_env.py")
            sess_region = pick_session_region_for_sso_env(args, base_sess)
            use_sess = session_from_sso_env(args.sso_env_path, acct, sess_region)
            if not use_sess:
                print(f"[warn] Skipping account {acct} (sso_env failed).", file=sys.stderr)
                continue
            if args.verbose:
                validate_session_identity(use_sess, acct, args.verbose)
        elif args.auth_mode == "assume-role":
            if not target_role_name:
                print(f"[warn] No role to assume for {acct}; skipping.", file=sys.stderr)
                continue
            if args.verbose:
                print(f"[info] {acct}: assuming role {target_role_name}")
            use_sess = assume_into_account(base_sess, acct, target_role_name)
            if use_sess is None:
                print(f"[warn] Skipping account {acct} (assume role failed).", file=sys.stderr)
                continue
            if args.verbose:
                validate_session_identity(use_sess, acct, args.verbose)
        else:  # auto
            use_sess = obtain_member_session_auto(base_sess, current_acct, acct, args, target_role_name)
            if not use_sess:
                print(f"[warn] Skipping account {acct} (auto auth failed).", file=sys.stderr)
                continue

        regions = list_regions(use_sess, args.region)
        if not regions:
            print(f"[warn] {acct}: no regions discovered; skipping.", file=sys.stderr)
            continue

        rows = collect_old_snapshots_for_session(
            use_sess, acct, regions, cutoff, cfg,
            used_by_ami_filter=args.used_by_ami,
            estimate_cost=args.estimate_cost, util_factor=max(0.0, min(1.0, args.util_factor))
        )

        for r in rows:
            key = (r["AccountId"], r["Region"])
            summary[key]["count"] += 1
            try:
                summary[key]["total_gib"] += float(r.get("VolumeSizeGiB") or 0.0)
            except Exception:
                pass
            try:
                if args.estimate_cost and r.get("EstMonthlyUSD") not in ("", None):
                    summary[key]["est_usd"] += float(r.get("EstMonthlyUSD") or 0.0)
            except Exception:
                pass

        if args.verbose:
            print(f"[info] {acct}: found {len(rows)} old snapshots across {len(regions)} region(s).")
        all_rows.extend(rows)

    if not all_rows:
        print(f"No snapshots older than {args.days} days were found across {len(target_accounts)} account(s).")
        return

    if args.summary_only:
        print(f"\n=== SUMMARY (older than {args.days} days) ===")
        grand_count = 0; grand_gib = 0.0; grand_usd = 0.0
        for (acct, region) in sorted(summary.keys()):
            data = summary[(acct, region)]
            grand_count += data["count"]; grand_gib += data["total_gib"]; grand_usd += data["est_usd"]
            if args.estimate_cost:
                print(f"  {acct} | {region:>12} | {int(data['count']):>5} snaps | {data['total_gib']:.2f} GiB | ${data['est_usd']:.2f}/mo")
            else:
                print(f"  {acct} | {region:>12} | {int(data['count']):>5} snaps | {data['total_gib']:.2f} GiB")
        if args.estimate_cost:
            print(f"\nGlobal total: {int(grand_count)} snaps | {grand_gib:.2f} GiB | ${grand_usd:.2f}/mo (est.)")
        else:
            print(f"\nGlobal total: {int(grand_count)} snaps | {grand_gib:.2f} GiB")

        if args.csv_path:
            try:
                with open(args.csv_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    hdr = ["AccountId","Region","SnapshotCount","TotalVolumeSizeGiB"]
                    if args.estimate_cost: hdr.append("EstMonthlyUSD")
                    writer.writerow(hdr)
                    for (acct, region), data in sorted(summary.items()):
                        row = [acct, region, int(data["count"]), f"{data['total_gib']:.2f}"]
                        if args.estimate_cost: row.append(f"{data['est_usd']:.2f}")
                        writer.writerow(row)
                print(f"Wrote summary CSV: {args.csv_path}")
            except OSError as e:
                print(f"Failed to write summary CSV: {e}", file=sys.stderr)
        return

    # Detailed preview (first 80 rows)
    header = ["AccountId","Region","SnapshotId","VolumeId","StartTime","AgeDays",
              "VolumeSizeGiB","FullSnapshotSizeInBytes","State","Encrypted","StorageTier","UsedByAMI","Description"]
    if args.estimate_cost:
        header.extend(["UtilFactor","PriceUSDperGBMo","EstBilledGiB","EstMonthlyUSD"])
    print("\n=== Old EBS Snapshots ===")
    print("\t".join(header))
    shown = 0
    for r in all_rows:
        if shown >= 80:
            break
        desc = r.get("Description", "")
        if len(desc) > 60:
            desc = desc[:57] + "..."
        vals = [str(r.get(k, "")) for k in [
            "AccountId","Region","SnapshotId","VolumeId","StartTime","AgeDays",
            "VolumeSizeGiB","FullSnapshotSizeInBytes","State","Encrypted","StorageTier","UsedByAMI"
        ]]
        vals.append(desc)
        if args.estimate_cost:
            vals.extend([str(r.get("UtilFactor","")), str(r.get("PriceUSDperGBMo","")),
                         str(r.get("EstBilledGiB","")), str(r.get("EstMonthlyUSD",""))])
        print("\t".join(vals))
        shown += 1
    if len(all_rows) > shown:
        print(f"... ({len(all_rows) - shown} more)")

    if args.csv_path:
        fieldnames = ["AccountId","Region","SnapshotId","VolumeId","StartTime","AgeDays",
                      "State","VolumeSizeGiB","FullSnapshotSizeInBytes","Encrypted","KmsKeyId","Description","Tags",
                      "OwnerId","StorageTier","Progress","UsedByAMI",
                      "UtilFactor","PriceUSDperGBMo","EstBilledGiB","EstMonthlyUSD"]
        try:
            with open(args.csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=fieldnames)
                w.writeheader(); w.writerows(all_rows)
            print(f"Wrote CSV: {args.csv_path}")
        except OSError as e:
            print(f"Failed to write CSV: {e}", file=sys.stderr)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted by user.", file=sys.stderr)
        sys.exit(130)