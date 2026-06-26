#!/usr/bin/env python3
"""
DNSSEC Onboarding Automation

Reads config.yaml, processes all domains, and enables DNSSEC on
Cloudflare (and optionally Azure), extracts DS records, and registers
them at GoDaddy.

Idempotent — safe to re-run. Each step checks if work is already done.

Usage:
  python onboard_domains.py --dry-run          # Preview only
  python onboard_domains.py                    # Apply changes

Environment:
  CLOUDFLARE_API_TOKEN  — Cloudflare API token  (dash.cloudflare.com/profile/api-tokens)
  GODADDY_API_KEY       — GoDaddy API key       (developer.godaddy.com/keys)
  GODADDY_API_SECRET    — GoDaddy API secret    (developer.godaddy.com/keys)
  GODADDY_CUSTOMER_ID   — GoDaddy customer number
                          (GoDaddy portal → Account Settings → Customer Number)
  SLACK_WEBHOOK_URL     — Slack incoming webhook (optional, for notifications)
"""

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests
import yaml

CF_API = "https://api.cloudflare.com/client/v4"
GODADDY_API = "https://api.godaddy.com"

DEFAULT_RG = "My-site-rg"
DEFAULT_SUB = "Pay-As-You-Go"


# ── Helpers ──────────────────────────────────────────────


def load_config(path: Path) -> dict:
    """Load and return config.yaml."""
    with open(path) as f:
        return yaml.safe_load(f)


def get_all_domains(config: dict) -> list[tuple[str, dict]]:
    """Return list of (domain, settings) for all domains in config."""
    domains = config.get("domains", {})
    if not domains:
        return []
    return [
        (domain, settings if isinstance(settings, dict) else {})
        for domain, settings in domains.items()
    ]


# ── Cloudflare ───────────────────────────────────────────


def cf_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def cf_get_zone_id(token: str, domain: str) -> str | None:
    """Look up Cloudflare zone ID by domain name."""
    resp = requests.get(
        f"{CF_API}/zones", params={"name": domain}, headers=cf_headers(token), timeout=30
    )
    resp.raise_for_status()
    results = resp.json().get("result", [])
    if results:
        return results[0]["id"]
    return None


def cf_enable_dnssec(token: str, zone_id: str) -> str:
    """Enable DNSSEC on a Cloudflare zone. Returns status. Idempotent."""
    # Check if already active before patching
    resp = requests.get(
        f"{CF_API}/zones/{zone_id}/dnssec",
        headers=cf_headers(token),
        timeout=30,
    )
    resp.raise_for_status()
    current_status = resp.json()["result"].get("status")
    if current_status == "active":
        return "active (already enabled)"

    resp = requests.patch(
        f"{CF_API}/zones/{zone_id}/dnssec",
        headers=cf_headers(token),
        json={"status": "active"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["result"]["status"]


def cf_get_ds(token: str, zone_id: str, retries: int = 6, delay: int = 15) -> dict | None:
    """Extract DS record from Cloudflare. Retries while DNSSEC provisions."""
    for attempt in range(1, retries + 1):
        resp = requests.get(
            f"{CF_API}/zones/{zone_id}/dnssec",
            headers=cf_headers(token),
            timeout=30,
        )
        resp.raise_for_status()
        result = resp.json()["result"]
        key_tag = result.get("key_tag")
        if key_tag:
            return {
                "key_tag": key_tag,
                "algorithm": result["algorithm"],
                "digest_type": result["digest_type"],
                "digest": result["digest"],
            }
        if attempt < retries:
            print(f"    Cloudflare DS not ready, retrying in {delay}s ({attempt}/{retries})...")
            time.sleep(delay)
    return None


# ── Azure ────────────────────────────────────────────────


def az_set_subscription(subscription: str) -> None:
    """Set active Azure subscription."""
    subprocess.run(
        ["az", "account", "set", "--subscription", subscription],
        check=True,
        capture_output=True,
        text=True,
    )


def az_enable_dnssec(rg: str, zone: str) -> bool:
    """Enable DNSSEC on an Azure DNS zone. Returns True on success. Idempotent."""
    result = subprocess.run(
        ["az", "network", "dns", "dnssec-config", "create",
         "--resource-group", rg, "--zone-name", zone, "--output", "none"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        return True

    # Already enabled? Check with show
    result = subprocess.run(
        ["az", "network", "dns", "dnssec-config", "show",
         "--resource-group", rg, "--zone-name", zone, "--output", "none"],
        capture_output=True, text=True,
    )
    return result.returncode == 0


def az_get_ds(rg: str, zone: str) -> dict | None:
    """Extract DS record (KSK) from Azure DNS."""
    result = subprocess.run(
        ["az", "network", "dns", "dnssec-config", "show",
         "--resource-group", rg, "--zone-name", zone,
         "--query", "signingKeys[?flags==`257`] | [0]", "-o", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None

    data = json.loads(result.stdout)
    if not data:
        return None

    ds_info = data.get("delegationSignerInfo", [{}])[0]
    return {
        "key_tag": data["keyTag"],
        "algorithm": data["securityAlgorithmType"],
        "digest_type": ds_info.get("digestAlgorithmType"),
        "digest": ds_info.get("digestValue"),
    }


# ── GoDaddy ──────────────────────────────────────────────


def gd_headers(api_key: str, api_secret: str) -> dict:
    return {
        "Authorization": f"sso-key {api_key}:{api_secret}",
        "Content-Type": "application/json",
    }


def gd_get_existing_ds(domain: str) -> list:
    """Get DS records currently registered at GoDaddy via public DNS query."""
    result = subprocess.run(
        ["dig", domain, "DS", "+short", "@8.8.8.8"],
        capture_output=True, text=True,
    )
    records = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 3)  # key_tag alg digest_type digest
        if len(parts) == 4:
            try:
                records.append({
                    "keyTag": int(parts[0]),
                    "algorithm": int(parts[1]),
                    "digestType": int(parts[2]),
                    "digest": parts[3].strip(),
                })
            except ValueError:
                pass
    return records


def gd_add_ds(
    api_key: str, api_secret: str, customer_id: str, domain: str,
    key_tag: int, algorithm: int, digest_type: int, digest: str,
    label: str,
) -> bool:
    """Add a DS record to GoDaddy as registrar."""
    resp = requests.patch(
        f"{GODADDY_API}/v2/customers/{customer_id}/domains/{domain}/dnssecRecords",
        headers=gd_headers(api_key, api_secret),
        json=[{"algorithm": algorithm, "digest": digest, "digestType": digest_type, "keyTag": key_tag}],
        timeout=30,
    )
    if resp.status_code in (200, 201, 202, 204):
        print(f"    GoDaddy DS ({label}): key_tag={key_tag} added")
        return True
    error_text = resp.text.lower()
    if resp.status_code in (409, 422) or "duplicate" in error_text or "already" in error_text:
        print(f"    GoDaddy DS ({label}): key_tag={key_tag} already registered — skipped")
        return True
    print(f"    GoDaddy DS ({label}) failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return False


# ── Slack notification ───────────────────────────────────


def notify_slack(
    webhook_url: str, succeeded: list[str], failed: list[str]
) -> None:
    """Send onboarding result to Slack."""
    if not webhook_url:
        print("  (Slack notification skipped — SLACK_WEBHOOK_URL not set)")
        return

    if succeeded and not failed:
        header = "✅ DNSSEC Onboarding Completed"
        body = f"Successfully onboarded: {', '.join(f'`{d}`' for d in succeeded)}"
    elif failed and not succeeded:
        header = "🚨 DNSSEC Onboarding Failed"
        body = f"Failed: {', '.join(f'`{d}`' for d in failed)}"
    else:
        header = "⚠️ DNSSEC Onboarding Partial"
        body = (
            f"Succeeded: {', '.join(f'`{d}`' for d in succeeded)}\n"
            f"Failed: {', '.join(f'`{d}`' for d in failed)}"
        )

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": body},
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "See dnssec/README.md for runbook"}],
            },
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        print("  Slack notification sent")
    except requests.exceptions.RequestException as e:
        print(f"  Slack notification failed: {e}")


# ── Onboard one domain ──────────────────────────────────


def onboard_domain(
    domain: str,
    settings: dict,
    cf_token: str,
    gd_api_key: str,
    gd_api_secret: str,
    gd_customer_id: str,
    dry_run: bool,
) -> bool:
    """
    Enable DNSSEC for a single domain on Cloudflare (and optionally Azure),
    then register DS records at GoDaddy.
    Idempotent — each step checks if already done before acting.

    Returns True on success, False on failure.
    """
    azure_enabled = settings.get("azure", True)
    rg = settings.get("azure_resource_group", DEFAULT_RG)
    subscription = settings.get("azure_subscription", DEFAULT_SUB)

    print(f"\n{'=' * 60}")
    print(f"  Onboarding: {domain}")
    if azure_enabled:
        print(f"  Azure RG: {rg}  |  Subscription: {subscription}")
    else:
        print(f"  Provider: Cloudflare only (azure: false)")
    print(f"{'=' * 60}")

    if dry_run:
        print("  [DRY-RUN] Validating config values...")
        valid = True

        # Check if already fully onboarded via public DS records at the TLD
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8"]
            resolver.lifetime = 10
            ds_answers = resolver.resolve(domain, "DS")
            already_onboarded = len(list(ds_answers)) >= 1
        except Exception:
            already_onboarded = False

        # Validate Cloudflare zone exists
        zone_id = cf_get_zone_id(cf_token, domain)
        if zone_id:
            print(f"    ✓ Cloudflare zone found: {zone_id}")
        else:
            print(f"    ✗ Cloudflare zone NOT found for {domain}")
            valid = False

        # Validate Azure resources only if Azure is enabled for this domain
        if azure_enabled:
            result = subprocess.run(
                ["az", "account", "show", "--subscription", subscription, "--output", "none"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(f"    ✓ Azure subscription exists: {subscription}")
            else:
                print(f"    ✗ Azure subscription NOT found: {subscription}")
                valid = False

            if result.returncode == 0:
                rg_result = subprocess.run(
                    ["az", "group", "show", "--name", rg, "--subscription", subscription, "--output", "none"],
                    capture_output=True, text=True,
                )
                if rg_result.returncode == 0:
                    print(f"    ✓ Azure resource group exists: {rg}")
                else:
                    print(f"    ✗ Azure resource group NOT found: {rg} (in {subscription})")
                    valid = False
        else:
            print(f"    ✓ Azure: skipped (azure: false in config)")

        if valid:
            if already_onboarded:
                print("  [DRY-RUN] Already onboarded — DNSSEC is active, no changes needed")
                return "already_done"
            else:
                providers = "Cloudflare" + (" + Azure" if azure_enabled else "")
                print(f"  [DRY-RUN] All checks passed — would enable DNSSEC on {providers}, add DS to GoDaddy")
        else:
            print("  [DRY-RUN] Validation FAILED — fix config.yaml before merging")
        return valid

    # Step 1: Get Cloudflare Zone ID
    print("  Step 1/6: Getting Cloudflare Zone ID...")
    zone_id = cf_get_zone_id(cf_token, domain)
    if not zone_id:
        print(f"  ERROR: Cloudflare zone not found for {domain}")
        return False
    print(f"    Zone ID: {zone_id}")

    # Step 2: Enable DNSSEC on Cloudflare
    print("  Step 2/6: Enabling DNSSEC on Cloudflare...")
    cf_status = cf_enable_dnssec(cf_token, zone_id)
    print(f"    Cloudflare DNSSEC: {cf_status}")

    # Step 3: Enable DNSSEC on Azure (skip if azure: false)
    if azure_enabled:
        print("  Step 3/6: Enabling DNSSEC on Azure...")
        az_set_subscription(subscription)
        if not az_enable_dnssec(rg, domain):
            print(f"  ERROR: Failed to enable Azure DNSSEC for {domain}")
            return False
        print("    Azure DNSSEC: enabled")
    else:
        print("  Step 3/6: Azure DNSSEC: skipped (azure: false)")

    # Step 4: Extract DS records
    print("  Step 4/6: Extracting DS records...")
    cf_ds = cf_get_ds(cf_token, zone_id)
    if not cf_ds:
        print("  ERROR: Could not extract Cloudflare DS record after retries")
        return False
    print(f"    Cloudflare DS: {cf_ds['key_tag']} {cf_ds['algorithm']} {cf_ds['digest_type']} {cf_ds['digest'][:20]}...")

    az_ds = None
    if azure_enabled:
        az_ds = az_get_ds(rg, domain)
        if not az_ds:
            print("  ERROR: Could not extract Azure DS record")
            return False
        print(f"    Azure DS:      {az_ds['key_tag']} {az_ds['algorithm']} {az_ds['digest_type']} {az_ds['digest'][:20]}...")

    # Step 5: Add DS records to GoDaddy
    print("  Step 5/6: Adding DS records to GoDaddy...")
    existing = gd_get_existing_ds(domain)
    existing_tags = {str(r.get("keyTag", r.get("key_tag", ""))) for r in existing}

    ds_to_add = [("Cloudflare", cf_ds)]
    if az_ds:
        ds_to_add.append(("Azure", az_ds))

    for label, ds in ds_to_add:
        if str(ds["key_tag"]) in existing_tags:
            print(f"    GoDaddy DS ({label}): key_tag={ds['key_tag']} already exists — skipped")
        else:
            if not gd_add_ds(
                gd_api_key, gd_api_secret, gd_customer_id, domain,
                ds["key_tag"], ds["algorithm"], ds["digest_type"], ds["digest"],
                label,
            ):
                print(f"  ERROR: Failed to add {label} DS to GoDaddy")
                return False

    # Step 6: Validate
    print("  Step 6/6: Validating DNSSEC...")
    print("    Waiting 10s for propagation...")
    time.sleep(10)

    result = subprocess.run(
        ["dig", domain, "A", "@8.8.8.8", "+dnssec", "+noall", "+comments"],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        if "status:" in line:
            status = line.split("status:")[1].split(",")[0].strip()
            print(f"    DNSSEC validation: {status}")
            break

    return True


# ── Main ─────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="DNSSEC onboarding automation")
    parser.add_argument("--dry-run", action="store_true", help="Preview only, no changes")
    parser.add_argument(
        "--config", default=str(Path(__file__).parent / "config.yaml"),
        help="Path to config.yaml (default: dnssec/config.yaml)",
    )
    args = parser.parse_args()

    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config not found: {config_path}")
        sys.exit(1)

    config = load_config(config_path)
    all_domains = get_all_domains(config)

    if not all_domains:
        print("No domains found in config.yaml")
        sys.exit(0)

    print(f"Found {len(all_domains)} domain(s): {', '.join(d for d, _ in all_domains)}")

    if args.dry_run:
        print("\n[DRY-RUN MODE] No changes will be made.\n")

    # Validate environment
    cf_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    gd_api_key = os.environ.get("GODADDY_API_KEY", "")
    gd_api_secret = os.environ.get("GODADDY_API_SECRET", "")
    gd_customer_id = os.environ.get("GODADDY_CUSTOMER_ID", "")
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")

    if not args.dry_run:
        missing = []
        if not cf_token:
            missing.append("CLOUDFLARE_API_TOKEN")
        if not gd_api_key:
            missing.append("GODADDY_API_KEY")
        if not gd_api_secret:
            missing.append("GODADDY_API_SECRET")
        if not gd_customer_id:
            missing.append("GODADDY_CUSTOMER_ID")
        if missing:
            print(f"Missing environment variables: {', '.join(missing)}")
            sys.exit(1)

    # Process each domain
    succeeded = []
    failed = []
    already_done = []

    for domain, settings in all_domains:
        ok = onboard_domain(domain, settings, cf_token, gd_api_key, gd_api_secret, gd_customer_id, args.dry_run)
        if ok == "already_done":
            already_done.append(domain)
        elif ok:
            succeeded.append(domain)
        else:
            failed.append(domain)

    # Summary
    print(f"\n{'=' * 60}")
    if args.dry_run:
        parts = []
        if succeeded:
            parts.append(f"{len(succeeded)} new: {', '.join(succeeded)}")
        if already_done:
            parts.append(f"{len(already_done)} already onboarded: {', '.join(already_done)}")
        summary = " | ".join(parts) if parts else "none"
        print(f"  [DRY-RUN] Dry-run complete: {summary}")
    else:
        print(f"  Summary: {len(succeeded)} succeeded, {len(failed)} failed, {len(all_domains)} total")
        if failed:
            print(f"  Failed: {', '.join(failed)}")
    print(f"{'=' * 60}")

    # Notify Slack (real runs only)
    if not args.dry_run:
        notify_slack(slack_webhook, succeeded, failed)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
