#!/usr/bin/env python3
"""
KSK Rotation Handler

Detects KSK rotation by comparing each provider's current key_tag against
DS records registered at CSC. When a mismatch is found, adds the new DS record
to CSC, waits for propagation, then removes the stale DS record.

Idempotent — safe to run on a schedule. No action is taken when all DS records
already match the active provider keys.

Usage:
  python ksk_rotation.py --dry-run    # Preview only, no changes
  python ksk_rotation.py              # Detect and fix

Environment:
  CLOUDFLARE_API_TOKEN  — Cloudflare API token  (dash.cloudflare.com/profile/api-tokens)
  GODADDY_API_KEY       — GoDaddy API key       (developer.godaddy.com/keys)
  GODADDY_API_SECRET    — GoDaddy API secret    (developer.godaddy.com/keys)
  GODADDY_CUSTOMER_ID   — GoDaddy customer number
                          (GoDaddy portal → Account Settings → Customer Number)
  SLACK_WEBHOOK_URL     — Slack incoming webhook (optional)
  DS_PROPAGATION_WAIT   — Seconds to wait between DS add and DS remove (default: 900)
"""

import argparse
import datetime
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

# Wait between adding new DS and removing old DS.
# Covers GoDaddy propagation (~2-5 min) + DNS propagation at TLD (~10 min TTL).
DS_PROPAGATION_WAIT = int(os.environ.get("DS_PROPAGATION_WAIT", "900"))


# ── Helpers ──────────────────────────────────────────────


def load_config(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


def get_all_domains(config: dict) -> list[tuple[str, dict]]:
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
    resp = requests.get(
        f"{CF_API}/zones", params={"name": domain}, headers=cf_headers(token), timeout=30
    )
    resp.raise_for_status()
    results = resp.json().get("result", [])
    return results[0]["id"] if results else None


def cf_get_ds(token: str, zone_id: str) -> dict | None:
    """Get the current active DS record from Cloudflare."""
    resp = requests.get(
        f"{CF_API}/zones/{zone_id}/dnssec",
        headers=cf_headers(token),
        timeout=30,
    )
    resp.raise_for_status()
    result = resp.json().get("result", {})
    if not result.get("key_tag"):
        return None
    return {
        "key_tag": result["key_tag"],
        "algorithm": result["algorithm"],
        "digest_type": result["digest_type"],
        "digest": result["digest"],
    }


# ── Azure ────────────────────────────────────────────────


def az_set_subscription(subscription: str) -> None:
    subprocess.run(
        ["az", "account", "set", "--subscription", subscription],
        check=True, capture_output=True, text=True,
    )


def az_get_ds(rg: str, zone: str) -> dict | None:
    """Get the current active DS record (KSK, flags=257) from Azure DNS."""
    result = subprocess.run(
        ["az", "network", "dns", "dnssec-config", "show",
         "--resource-group", rg, "--zone-name", zone,
         "--query", "signingKeys[?flags==`257`] | [0]", "-o", "json"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    try:
        data = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        return None
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
#
# DS records are managed via GoDaddy Domains API v2.
# Auth header: sso-key {GODADDY_API_KEY}:{GODADDY_API_SECRET}
# Customer ID: your GoDaddy Customer Number
#              (GoDaddy portal → Account Settings → Customer Number)
#
# GoDaddy's v2 API does not expose a GET endpoint for registered DS records,
# so gd_get_ds_records() queries public DNS via dig instead. Records become
# visible in DNS within ~2-5 minutes of being registered at GoDaddy.


def gd_headers(api_key: str, api_secret: str) -> dict:
    return {
        "Authorization": f"sso-key {api_key}:{api_secret}",
        "Content-Type": "application/json",
    }


def gd_get_ds_records(domain: str) -> list:
    """
    Return DS records for a domain by querying public DNS (8.8.8.8).

    GoDaddy's v2 API has no GET endpoint for registered DS records, so we
    query DNS directly. Each record has: keyTag, algorithm, digestType, digest.
    """
    result = subprocess.run(
        ["dig", domain, "DS", "+short", "@8.8.8.8"],
        capture_output=True, text=True,
    )
    records = []
    for line in result.stdout.splitlines():
        # DS output format: "<key_tag> <algorithm> <digest_type> <digest>"
        parts = line.split(None, 3)
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


def _gd_manual_instructions(action: str, domain: str, key_tag: int, algorithm: int, digest_type: int, digest: str) -> None:
    """Print GoDaddy web portal instructions when the API is unavailable for personal accounts."""
    print(f"    *** MANUAL ACTION REQUIRED in GoDaddy portal ***")
    print(f"    URL: https://dcc.godaddy.com/manage/{domain}/dns")
    print(f"    DNS tab -> DS Records -> {action} DS Record")
    print(f"      Key Tag:     {key_tag}")
    print(f"      Algorithm:   {algorithm}")
    print(f"      Digest Type: {digest_type}")
    print(f"      Digest:      {digest}")


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
        print(f"    GoDaddy ADD ({label}): key_tag={key_tag} added")
        return True
    # Treat duplicate/already-exists responses as success (idempotent)
    error_text = resp.text.lower()
    if resp.status_code in (409, 422) or "duplicate" in error_text or "already" in error_text:
        print(f"    GoDaddy ADD ({label}): key_tag={key_tag} already registered — skipped")
        return True
    if resp.status_code == 403:
        print(f"    GoDaddy ADD ({label}): API returned 403 — v2 DNSSEC API requires a reseller account.")
        print(f"    Add this DS record manually in the GoDaddy portal:")
        _gd_manual_instructions("Add", domain, key_tag, algorithm, digest_type, digest)
        return False
    print(f"    GoDaddy ADD ({label}) failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return False


def gd_delete_ds(
    api_key: str, api_secret: str, customer_id: str, domain: str,
    key_tag: int, algorithm: int, digest_type: int, digest: str,
    label: str,
) -> bool:
    """Remove a DS record from GoDaddy as registrar."""
    resp = requests.delete(
        f"{GODADDY_API}/v2/customers/{customer_id}/domains/{domain}/dnssecRecords",
        headers=gd_headers(api_key, api_secret),
        json=[{"algorithm": algorithm, "digest": digest, "digestType": digest_type, "keyTag": key_tag}],
        timeout=30,
    )
    if resp.status_code in (200, 201, 202, 204):
        print(f"    GoDaddy DELETE ({label}): key_tag={key_tag} removed")
        return True
    # Treat 404 as success — record was already removed (idempotent)
    if resp.status_code == 404:
        print(f"    GoDaddy DELETE ({label}): key_tag={key_tag} not found — already removed")
        return True
    if resp.status_code == 403:
        print(f"    GoDaddy DELETE ({label}): API returned 403 — v2 DNSSEC API requires a reseller account.")
        print(f"    Remove this DS record manually in the GoDaddy portal:")
        _gd_manual_instructions("Delete", domain, key_tag, algorithm, digest_type, digest)
        return False
    print(f"    GoDaddy DELETE ({label}) failed: HTTP {resp.status_code} — {resp.text[:200]}")
    return False


# ── Slack ────────────────────────────────────────────────


def notify_slack(
    webhook_url: str,
    rotated: list[str],
    failed: list[str],
    no_change_count: int,
    phase: str | None = None,
) -> None:
    """
    Send a Slack notification.

    phase='detect-add' — rotation detected, new DS added, approval pending.
    phase='remove'     — stale DS removed, rotation complete.
    phase=None         — single-run mode (all phases in one job).
    """
    if not webhook_url:
        print("  (Slack notification skipped — SLACK_WEBHOOK_URL not set)")
        return

    if not rotated and not failed:
        return  # silent when nothing changed

    parts: list[str] = []

    if phase == "detect-add":
        if rotated and not failed:
            header = "🔄 KSK Rotation Detected — Approval Required"
        elif failed and not rotated:
            header = "🚨 KSK Rotation — Detection/Add Failed"
        else:
            header = "⚠️ KSK Rotation — Partial Detection"
        if rotated:
            parts.append(
                f"New DS added to CSC for: {', '.join(f'`{d}`' for d in rotated)}"
            )
            run_url = _github_run_url()
            note = "Approve the *review-and-remove* job in GitHub Actions to remove stale DS records."
            if run_url:
                note += f" <{run_url}|View run →>"
            parts.append(note)

    elif phase == "remove":
        if rotated and not failed:
            header = "✅ KSK Rotation Complete"
        elif failed and not rotated:
            header = "🚨 KSK Rotation — Stale Removal Failed"
        else:
            header = "⚠️ KSK Rotation — Partial Completion"
        if rotated:
            parts.append(
                f"Stale DS removed from CSC for: {', '.join(f'`{d}`' for d in rotated)}"
            )

    else:  # single-run mode
        if rotated and not failed:
            header = "🔄 KSK Rotation Detected & Updated"
        elif failed and not rotated:
            header = "🚨 KSK Rotation — Update Failed"
        else:
            header = "⚠️ KSK Rotation — Partial Update"
        if rotated:
            parts.append(f"Updated ({len(rotated)}): {', '.join(f'`{d}`' for d in rotated)}")

    if failed:
        parts.append(f"Failed ({len(failed)}): {', '.join(f'`{d}`' for d in failed)}")
    if no_change_count:
        parts.append(f"No change: {no_change_count} domain(s)")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(parts)},
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "See dnssec/README.md → KSK Rotation for runbook"}],
            },
        ]
    }

    try:
        resp = requests.post(webhook_url, json=payload, timeout=10)
        resp.raise_for_status()
        print("  Slack notification sent")
    except requests.exceptions.RequestException as e:
        print(f"  Slack notification failed: {e}")


# ── Plan file helpers (split-phase workflow) ──────────────────


def _github_run_url() -> str:
    """Return the GitHub Actions workflow run URL when running in CI, else empty string."""
    server = os.environ.get("GITHUB_SERVER_URL", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if server and repo and run_id:
        return f"{server}/{repo}/actions/runs/{run_id}"
    return ""


def write_plan_file(
    path: str,
    confirmed: dict[str, list],
    timed_out: list[str],
    rotated: list[str],
    failed: list[str],
) -> None:
    """Write rotation plan to JSON for hand-off to the approval-gated remove job."""
    plan = {
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
        "confirmed": confirmed,   # domain → stale CSC records to delete
        "timed_out": timed_out,
        "rotated": rotated,
        "failed": failed,
    }
    with open(path, "w") as f:
        json.dump(plan, f, indent=2)
    print(f"  Plan written to {path} ({len(confirmed)} domain(s) queued for stale removal)")


def read_plan_file(path: str) -> dict:
    """Read rotation plan written by the detect-add phase."""
    with open(path) as f:
        return json.load(f)


def set_github_output(key: str, value: str) -> None:
    """Set a GitHub Actions step output via the GITHUB_OUTPUT environment file."""
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a") as f:
            f.write(f"{key}={value}\n")


# ── Core: three-phase processing ────────────────────────
#
# Phase 1 (detect_and_add)  — run for ALL domains first.
#   Detect rotation, add new DS records to GoDaddy, collect stale records to remove.
#
# Phase 2 (poll_for_propagation) — poll DNS for ALL domains round-robin.
#   Each domain is checked every 60s. As soon as a domain's new DS key_tag is
#   visible in DNS it is moved to 'confirmed' and no longer blocks the others.
#   Domains that don't propagate within max_wait are skipped and retried next run.
#
# Phase 3 (remove_stale_records) — run only for confirmed domains.
#   Safe to remove the old DS now that the new one is live in DNS.


def detect_and_add(
    domain: str,
    settings: dict,
    cf_token: str,
    gd_api_key: str,
    gd_api_secret: str,
    gd_customer_id: str,
    dry_run: bool,
) -> tuple[str, list, set]:
    """
    Phase 1: Detect KSK rotation and add new DS records to GoDaddy.

    Compares each provider's current key_tag against what is registered at GoDaddy.
    Adds any missing DS records immediately. Azure is skipped when the domain
    has 'azure: false' in config.yaml.

    Returns: (status, stale_records, new_key_tags)
      status        — 'ok' | 'added' | 'error'
      stale_records — registrar records to remove in Phase 3 (after propagation)
      new_key_tags  — key_tags just added to GoDaddy; used by Phase 2 to poll DNS
    """
    azure_enabled = settings.get("azure", True)

    print(f"\n{'─' * 60}")
    print(f"  {domain}")
    print(f"{'─' * 60}")

    # Fetch DS records currently visible in public DNS (== registered at GoDaddy)
    reg_records = gd_get_ds_records(domain)
    reg_tags = {r.get("keyTag", r.get("key_tag")) for r in reg_records}
    print(f"  GoDaddy registered key_tags: {sorted(reg_tags) if reg_tags else 'none'}")

    # Fetch current KSK from Cloudflare
    zone_id = cf_get_zone_id(cf_token, domain)
    if not zone_id:
        print(f"  ERROR: Cloudflare zone not found for {domain}")
        return "error", [], set()

    cf_ds = cf_get_ds(cf_token, zone_id)
    if not cf_ds:
        print(f"  ERROR: Could not retrieve Cloudflare DS for {domain} — DNSSEC inactive?")
        return "error", [], set()
    print(f"  Cloudflare current KSK:      key_tag={cf_ds['key_tag']}")

    # Fetch current KSK from Azure (only if enabled for this domain)
    az_ds = None
    if azure_enabled:
        rg = settings.get("azure_resource_group", DEFAULT_RG)
        subscription = settings.get("azure_subscription", DEFAULT_SUB)
        az_set_subscription(subscription)
        az_ds = az_get_ds(rg, domain)
        if not az_ds:
            print(f"  ERROR: Could not retrieve Azure DS for {domain} — DNSSEC inactive?")
            return "error", [], set()
        print(f"  Azure current KSK:           key_tag={az_ds['key_tag']}")
    else:
        print(f"  Azure: skipped (azure: false in config)")

    # Determine what is missing from GoDaddy and what is stale
    active_tags = {cf_ds["key_tag"]}
    if az_ds:
        active_tags.add(az_ds["key_tag"])

    to_add = []
    if cf_ds["key_tag"] not in reg_tags:
        to_add.append(("Cloudflare", cf_ds))
    if az_ds and az_ds["key_tag"] not in reg_tags:
        to_add.append(("Azure", az_ds))

    # Stale = registered at GoDaddy but matches neither active provider key
    stale = [r for r in reg_records if r.get("keyTag", r.get("key_tag")) not in active_tags]

    if not to_add and not stale:
        print("  ✅ All DS records match active KSKs — no rotation detected")
        return "ok", [], set()

    # Describe the detected mismatch
    for label, ds in to_add:
        print(f"  🔄 {label} KSK rotated — key_tag={ds['key_tag']} not in GoDaddy")
    for r in stale:
        old_tag = r.get("keyTag", r.get("key_tag"))
        print(f"  🗑  Stale DS at GoDaddy: key_tag={old_tag} (queued for removal after propagation check)")

    new_key_tags = {ds["key_tag"] for _, ds in to_add}

    if dry_run:
        if to_add:
            print(f"  [DRY-RUN] Would add {len(to_add)} DS record(s) to GoDaddy")
        if stale:
            print(f"  [DRY-RUN] Would remove {len(stale)} stale DS record(s) from GoDaddy (after propagation confirmed)")
        return "added", stale, new_key_tags

    # Add new DS records now (always before any removal)
    for label, ds in to_add:
        success = gd_add_ds(
            gd_api_key, gd_api_secret, gd_customer_id, domain,
            ds["key_tag"], ds["algorithm"], ds["digest_type"], ds["digest"],
            label,
        )
        if not success:
            print(f"  ERROR: Failed to add {label} DS to GoDaddy — old DS kept to avoid SERVFAIL")
            return "error", [], set()

    # new_key_tags tells Phase 2 what to poll for in DNS before removing stale records
    return "added", stale, new_key_tags


def poll_for_propagation(
    pending: dict[str, tuple[set, list]],
    max_wait: int = DS_PROPAGATION_WAIT,
    poll_interval: int = 60,
) -> tuple[dict[str, list], list[str]]:
    """
    Phase 2: Poll DNS for all domains round-robin until each domain's new DS
    key_tags are visible in the public DNS (8.8.8.8).

    Domains are checked every `poll_interval` seconds. As soon as a domain's
    new key_tag appears in DNS it is moved to 'confirmed' — it does NOT wait
    for domains that are still pending. Domains that do not propagate within
    `max_wait` seconds are skipped; their stale records will be cleaned up on
    the next scheduled run (an extra stale DS at CSC does not break DNSSEC).

    Args:
      pending       — {domain: (new_key_tags, stale_records)}
      max_wait      — total seconds before giving up on unconfirmed domains
      poll_interval — seconds between each DNS poll round

    Returns: (confirmed, timed_out)
      confirmed  — {domain: stale_records} — safe to remove stale DS now
      timed_out  — domains whose new DS was not visible within max_wait
    """
    if not pending:
        return {}, []

    start = time.time()
    unconfirmed = dict(pending)   # mutable working copy
    confirmed: dict[str, list] = {}

    print(f"  Polling DNS every {poll_interval}s (max {max_wait // 60} min) "
          f"for {len(pending)} domain(s)...")

    while unconfirmed:
        elapsed = int(time.time() - start)
        if elapsed >= max_wait:
            break

        newly_confirmed: list[str] = []
        for domain, (new_tags, stale) in unconfirmed.items():
            result = subprocess.run(
                ["dig", domain, "DS", "+short", "@8.8.8.8"],
                capture_output=True, text=True,
            )
            # DS output lines: "<key_tag> <alg> <digest_type> <digest>"
            visible_tags: set[int] = set()
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts:
                    try:
                        visible_tags.add(int(parts[0]))
                    except ValueError:
                        pass

            if new_tags.issubset(visible_tags):
                print(f"  ✅ {domain}: new DS key_tag(s) {sorted(new_tags)} visible in DNS — queuing stale removal")
                confirmed[domain] = stale
                newly_confirmed.append(domain)
            else:
                missing = new_tags - visible_tags
                print(f"  ⏳ {domain}: key_tag(s) {sorted(missing)} not yet visible in DNS")

        for d in newly_confirmed:
            del unconfirmed[d]

        if unconfirmed:
            elapsed = int(time.time() - start)
            remaining = max_wait - elapsed
            if remaining <= 0:
                break
            sleep_secs = min(poll_interval, remaining)
            print(f"  {len(unconfirmed)} domain(s) still pending — "
                  f"next poll in {sleep_secs}s "
                  f"({elapsed}s elapsed / {max_wait}s max)...")
            time.sleep(sleep_secs)

    timed_out = list(unconfirmed.keys())
    for domain in timed_out:
        print(f"  ⚠️  {domain}: DS not visible after {max_wait}s — "
              f"stale removal deferred (next run will retry)")

    return confirmed, timed_out


def remove_stale_records(
    domain: str,
    stale: list,
    gd_api_key: str,
    gd_api_secret: str,
    gd_customer_id: str,
) -> bool:
    """
    Phase 3: Remove stale DS records from GoDaddy.

    Called for all confirmed domains after the shared propagation wait in main().
    A stale record is one whose key_tag no longer matches either active provider.

    Returns True if all deletions succeeded (failures are logged but non-fatal —
    an extra stale DS at GoDaddy does not break DNSSEC, and the next run retries).
    """
    all_ok = True
    for r in stale:
        old_tag = r.get("keyTag", r.get("key_tag"))
        old_alg = r.get("algorithm", 13)
        old_digest_type = r.get("digestType", r.get("digest_type", 2))
        old_digest = r.get("digest", "")

        # Check if the record is already gone from public DNS (e.g. manually removed
        # from the registrar portal before this job ran). If it's not visible, treat
        # deletion as already done — no API call needed.
        current_tags = {r2.get("keyTag") for r2 in gd_get_ds_records(domain)}
        if old_tag not in current_tags:
            print(f"    stale key_tag={old_tag}: already gone from DNS — skipped API call")
            continue

        success = gd_delete_ds(
            gd_api_key, gd_api_secret, gd_customer_id, domain,
            old_tag, old_alg, old_digest_type, old_digest,
            f"stale key_tag={old_tag}",
        )
        if not success:
            print(f"  WARNING: Failed to remove stale DS key_tag={old_tag} — next run will retry")
            all_ok = False

    if not all_ok:
        print(f"  ⚠️  New DS added but stale DS removal failed — DNSSEC is intact, cleanup retries on next run")

    return all_ok


# ── Main ─────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(
        description="KSK rotation handler — detects provider KSK changes and updates GoDaddy DS records"
    )
    parser.add_argument("--dry-run", action="store_true", help="Preview only, no changes made")
    parser.add_argument(
        "--config", default=str(Path(__file__).parent / "config.yaml"),
        help="Path to config.yaml (default: same directory as this script)",
    )
    parser.add_argument(
        "--phase",
        choices=["detect-add", "remove"],
        default=None,
        help=(
            "Run a single phase for split workflows with an approval gate. "
            "'detect-add': Phase 1+2 — detect rotation, add new DS to CSC, poll propagation, "
            "write plan file, set GitHub Actions output. "
            "'remove': Phase 3 — read plan file, remove stale DS from CSC. "
            "Omit to run all three phases in sequence (default)."
        ),
    )
    parser.add_argument(
        "--plan-file",
        default="rotation-plan.json",
        help="Plan file for split-phase workflows (default: rotation-plan.json)",
    )
    args = parser.parse_args()

    # ── Phase 3 only: read plan file and remove stale DS records ─────────
    # Runs in the approval-gated 'review-and-remove' GitHub Actions job.
    # Does not need Cloudflare token or config.yaml — all data is in the plan file.
    if args.phase == "remove":
        gd_api_key = os.environ.get("GODADDY_API_KEY", "")
        gd_api_secret = os.environ.get("GODADDY_API_SECRET", "")
        gd_customer_id = os.environ.get("GODADDY_CUSTOMER_ID", "")
        slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")

        if not args.dry_run:
            missing = [v for v in ["GODADDY_API_KEY", "GODADDY_API_SECRET", "GODADDY_CUSTOMER_ID"] if not os.environ.get(v)]
            if missing:
                print(f"Missing environment variables: {', '.join(missing)}")
                sys.exit(1)

        plan_path = Path(args.plan_file)
        if not plan_path.exists():
            print(f"Plan file not found: {plan_path}")
            sys.exit(1)

        plan = read_plan_file(args.plan_file)
        confirmed: dict[str, list] = plan.get("confirmed", {})
        rotated: list[str] = plan.get("rotated", [])
        prior_failed: list[str] = plan.get("failed", [])

        print("KSK Rotation — Phase 3: Remove stale DS records")
        print(f"  Plan generated: {plan.get('generated_at', 'unknown')}")
        print(f"  Domains to clean: {list(confirmed.keys()) or 'none'}")
        if args.dry_run:
            print("[DRY-RUN MODE] No changes will be made.")

        if not confirmed:
            print("  No confirmed domains in plan — nothing to remove")
            sys.exit(0)

        remove_failed: list[str] = []
        print("\n── Phase 3: Remove stale DS records ──")
        for domain, stale in confirmed.items():
            print(f"\n{'─' * 60}")
            print(f"  {domain} — removing stale DS")
            print(f"{'─' * 60}")
            if not args.dry_run:
                ok = remove_stale_records(domain, stale, gd_api_key, gd_api_secret, gd_customer_id)
                if not ok:
                    remove_failed.append(domain)
            else:
                for r in stale:
                    old_tag = r.get("keyTag", r.get("key_tag"))
                    print(f"  [DRY-RUN] Would remove stale DS key_tag={old_tag}")

        all_failed = list(set(prior_failed + remove_failed))
        print(f"\n{'=' * 60}")
        print(f"  Summary: {len(confirmed)} stale removed | {len(remove_failed)} failed")
        if remove_failed:
            print(f"  Failed: {', '.join(remove_failed)}")
        print(f"{'=' * 60}")

        if not args.dry_run:
            notify_slack(slack_webhook, rotated, all_failed, 0, phase="remove")

        if remove_failed:
            sys.exit(1)
        return

    # ── Phase 1 + 2 (always) and optionally Phase 3 (when no --phase) ───
    config_path = Path(args.config)
    if not config_path.exists():
        print(f"Config not found: {config_path}")
        sys.exit(1)

    config = load_config(config_path)
    all_domains = get_all_domains(config)

    if not all_domains:
        print("No domains found in config.yaml")
        sys.exit(0)

    print(f"KSK Rotation Check — {len(all_domains)} domain(s)")
    if args.dry_run:
        print("[DRY-RUN MODE] No changes will be made.\n")

    cf_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    gd_api_key = os.environ.get("GODADDY_API_KEY", "")
    gd_api_secret = os.environ.get("GODADDY_API_SECRET", "")
    gd_customer_id = os.environ.get("GODADDY_CUSTOMER_ID", "")
    slack_webhook = os.environ.get("SLACK_WEBHOOK_URL", "")

    if not args.dry_run:
        missing = [v for v in ["CLOUDFLARE_API_TOKEN", "GODADDY_API_KEY", "GODADDY_API_SECRET", "GODADDY_CUSTOMER_ID"]
                   if not os.environ.get(v)]
        if missing:
            print(f"Missing environment variables: {', '.join(missing)}")
            sys.exit(1)

    rotated: list[str] = []
    failed: list[str] = []
    no_change_count = 0

    # ── Phase 1: detect rotation and add new DS records for ALL domains ──
    print("\n── Phase 1: Detect rotation & add new DS records ──")
    # domain → (new_key_tags_added, stale_registrar_records_to_remove)
    pending_removal: dict[str, tuple[set, list]] = {}

    for domain, settings in all_domains:
        status, stale, new_key_tags = detect_and_add(
            domain, settings, cf_token, gd_api_key, gd_api_secret, gd_customer_id, args.dry_run
        )
        if status == "ok":
            no_change_count += 1
        elif status == "added":
            rotated.append(domain)
            if stale:  # only need Phase 2/3 when there are stale records to clean up
                pending_removal[domain] = (new_key_tags, stale)
        else:
            failed.append(domain)

    # ── Phase 2: poll DNS per domain until new DS is visible ─────────────
    # Each domain is polled independently every 60s. A domain moves to Phase 3
    # as soon as its new key_tag appears in DNS — it does not wait for others.
    # Domains that exceed max_wait are skipped; next run will retry.
    if pending_removal and not args.dry_run:
        print("\n── Phase 2: Polling DNS for DS propagation ──")
        confirmed, timed_out = poll_for_propagation(pending_removal)
    elif pending_removal and args.dry_run:
        print("\n── Phase 2: [DRY-RUN] Would poll DNS until new DS key_tags are visible ──")
        confirmed = {d: stale for d, (_, stale) in pending_removal.items()}
        timed_out = []
    else:
        confirmed, timed_out = {}, []

    # ── detect-add phase: hand off to approval-gated remove job ─────────
    if args.phase == "detect-add":
        if not args.dry_run:
            write_plan_file(args.plan_file, confirmed, timed_out, rotated, failed)
            set_github_output("has_pending_removals", "true" if confirmed else "false")

        print(f"\n{'=' * 60}")
        print(f"  Summary: {no_change_count} unchanged | {len(rotated)} rotated | {len(failed)} failed")
        if confirmed:
            print(f"  Queued for stale removal (pending approval): {', '.join(confirmed)}")
        if timed_out:
            print(f"  Propagation timed out (next run retries):    {', '.join(timed_out)}")
        print(f"{'=' * 60}")

        if not args.dry_run:
            notify_slack(slack_webhook, rotated, failed, no_change_count, phase="detect-add")

        if failed:
            sys.exit(1)
        return

    # ── Phase 3: remove stale DS records (single-run mode only) ─────────
    if confirmed:
        print("\n── Phase 3: Remove stale DS records ──")
        for domain, stale in confirmed.items():
            print(f"\n{'─' * 60}")
            print(f"  {domain} — removing stale DS")
            print(f"{'─' * 60}")
            if not args.dry_run:
                remove_stale_records(domain, stale, gd_api_key, gd_api_secret, gd_customer_id)
            else:
                for r in stale:
                    old_tag = r.get("keyTag", r.get("key_tag"))
                    print(f"  [DRY-RUN] Would remove stale DS key_tag={old_tag}")

    print(f"\n{'=' * 60}")
    print(f"  Summary: {no_change_count} unchanged | {len(rotated)} updated | {len(failed)} failed")
    if rotated:
        print(f"  Rotated: {', '.join(rotated)}")
    if failed:
        print(f"  Failed:  {', '.join(failed)}")
    print(f"{'=' * 60}")

    if not args.dry_run:
        notify_slack(slack_webhook, rotated, failed, no_change_count)

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
