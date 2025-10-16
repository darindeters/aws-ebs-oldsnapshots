#!/usr/bin/env python3
# Prints shell exports for a given account using IAM Identity Center role "Global-Slalom".
# Usage:
#   eval $(python sso_env.py <ACCOUNT_ID> [AWS_REGION])
#   aws sts get-caller-identity
#
# Behavior:
# - Tries cached SSO token first.
# - If it's invalid/expired, performs device authorization flow, then retries.
# - Verifies the permission set exists in the target account for clearer errors.
# - Emits concrete region values (no shell indirection).

import os
import sys
import json
import glob
import time
import boto3
from botocore.exceptions import ClientError

# -------- configure these to your environment --------
START_URL  = "https://d-9267474431.awsapps.com/start"  # IAM Identity Center start URL
SSO_REGION = "us-west-2"                                # Identity Center (SSO) region
ROLE_NAME  = "Global-Slalom"                            # Permission set/role name
# ----------------------------------------------------

def load_token_from_cache(start_url: str, sso_region: str):
    """Attempt to load an Identity Center access token from local cache."""
    # 1) Prefer botocore SSOTokenLoader
    try:
        from botocore.utils import SSOTokenLoader
        cache_dir = os.path.expanduser("~/.aws/sso/cache")
        loader = SSOTokenLoader(cache_dir=cache_dir)
        if hasattr(loader, "load_token"):
            tok = loader.load_token(start_url, sso_region)
        else:
            tok = loader.get_token()
        if tok and "accessToken" in tok:
            return tok["accessToken"]
    except Exception:
        pass

    # 2) Fallback: scan cache files
    try:
        cache_dir = os.path.expanduser("~/.aws/sso/cache")
        files = glob.glob(os.path.join(cache_dir, "*.json"))
        newest = None
        for path in files:
            try:
                with open(path, "r") as f:
                    data = json.load(f)
                if data.get("startUrl") == start_url and data.get("region") == sso_region and "accessToken" in data:
                    return data["accessToken"]
                if "accessToken" in data:
                    if newest is None or os.path.getmtime(path) > os.path.getmtime(newest):
                        newest = path
            except Exception:
                continue
        if newest:
            with open(newest, "r") as f:
                data = json.load(f)
            if "accessToken" in data:
                return data["accessToken"]
    except Exception:
        pass
    return None

def device_auth_access_token(start_url: str, sso_region: str) -> str:
    """Run the device authorization flow to obtain a fresh Identity Center access token."""
    oidc = boto3.client("sso-oidc", region_name=sso_region)

    reg = oidc.register_client(clientName="sso-env.py", clientType="public")
    client_id = reg["clientId"]
    client_secret = reg.get("clientSecret")

    # Build kwargs without clientSecret if absent
    sda_kwargs = {"clientId": client_id, "startUrl": start_url}
    if client_secret:
        sda_kwargs["clientSecret"] = client_secret
    dev = oidc.start_device_authorization(**sda_kwargs)

    verification_uri = dev.get("verificationUriComplete") or dev["verificationUri"]
    user_code = dev.get("userCode", "")
    interval = dev.get("interval", 5)
    expires_in = dev.get("expiresIn", 600)

    print("\nTo authorize this session, open the following URL and, if asked, enter the code:")
    print(f"  URL : {verification_uri}")
    if user_code:
        print(f"  Code: {user_code}")
    print("(Waiting for approval...)")

    deadline = time.time() + expires_in
    while time.time() < deadline:
        try:
            ct_kwargs = {
                "clientId": client_id,
                "grantType": "urn:ietf:params:oauth:grant-type:device_code",
                "deviceCode": dev["deviceCode"],
            }
            if client_secret:
                ct_kwargs["clientSecret"] = client_secret
            tok = oidc.create_token(**ct_kwargs)
            return tok["accessToken"]
        except oidc.exceptions.AuthorizationPendingException:
            time.sleep(interval)
        except oidc.exceptions.SlowDownException:
            interval += 2
            time.sleep(interval)
        except oidc.exceptions.ExpiredTokenException:
            sys.exit("Device authorization expired; please rerun.")
        except Exception as e:
            sys.exit(f"SSO OIDC error: {e}")

    sys.exit("Timed out waiting for device authorization.")

def ensure_role_exists(sso_client, access_token: str, account_id: str, role_name: str) -> None:
    """Verify the permission set/role is assigned in this account; exit with a clear message if not."""
    next_token = None
    while True:
        kwargs = {"accessToken": access_token, "accountId": account_id}
        if next_token:
            kwargs["nextToken"] = next_token
        resp = sso_client.list_account_roles(**kwargs)
        roles = [r["roleName"] for r in resp.get("roleList", [])]
        if role_name in roles:
            return
        next_token = resp.get("nextToken")
        if not next_token:
            break
    sys.exit(f"[error] IAM Identity Center permission set '{role_name}' is not assigned in account {account_id}.")

def get_role_creds_with_auto_refresh(account_id: str):
    """
    Try cached token -> GetRoleCredentials.
    If Unauthorized (expired/invalid), do device auth to refresh token, then retry once.
    """
    sso = boto3.client("sso", region_name=SSO_REGION)

    # 1) try cache
    access_token = load_token_from_cache(START_URL, SSO_REGION)
    if access_token:
        try:
            ensure_role_exists(sso, access_token, account_id, ROLE_NAME)
            return sso.get_role_credentials(
                roleName=ROLE_NAME, accountId=account_id, accessToken=access_token
            )["roleCredentials"]
        except sso.exceptions.UnauthorizedException:
            pass  # fall through to device auth
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "UnauthorizedException":
                raise

    # 2) refresh via device code
    access_token = device_auth_access_token(START_URL, SSO_REGION)
    ensure_role_exists(sso, access_token, account_id, ROLE_NAME)
    return sso.get_role_credentials(
        roleName=ROLE_NAME, accountId=account_id, accessToken=access_token
    )["roleCredentials"]

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: sso_env.py <ACCOUNT_ID> [AWS_REGION]")
    account_id = sys.argv[1]
    aws_region = sys.argv[2] if len(sys.argv) > 2 else "us-west-2"

    try:
        creds = get_role_creds_with_auto_refresh(account_id)
    except ClientError as e:
        sys.exit(f"[error] SSO GetRoleCredentials failed for {account_id}: {e}")

    # Export concrete region values (no shell indirection)
    print(f"export AWS_ACCESS_KEY_ID='{creds['accessKeyId']}'")
    print(f"export AWS_SECRET_ACCESS_KEY='{creds['secretAccessKey']}'")
    print(f"export AWS_SESSION_TOKEN='{creds['sessionToken']}'")
    print(f"export AWS_DEFAULT_REGION='{aws_region}'")
    print(f"export AWS_REGION='{aws_region}'")
    print("export AWS_PAGER=")

if __name__ == "__main__":
    main()