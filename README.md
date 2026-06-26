# DNSSEC

Multi-provider DNSSEC with Cloudflare (primary) and Azure DNS (failover). CSC Global is the domain registrar.

```
                    ┌──────────────┐
                    │  CSC Global  │
                    │  (Registrar) │
                    │              │
                    │ NS → active  │
                    │ DS → both    │
                    └──────┬───────┘
                           │
              ┌────────────┴────────────┐
              │                         │
       ┌──────┴──────┐          ┌───────┴─────┐
       │  Cloudflare │          │  Azure DNS  │
       │  (Primary)  │          │ (Failover)  │
       │             │          │             │
       │  Own KSK    │          │  Own KSK    │
       │  Own ZSK    │          │  Own ZSK    │
       │  Signs zone │          │  Signs zone │
       └─────────────┘          └─────────────┘
```

Each provider independently signs the zone with its own keys (**Independent Signer** model). Both DS records are registered at CSC so a failover only requires an NS change — no DS updates needed.

## Contents

- [How It Works](#how-it-works)
- [Onboarding a New Domain](#onboarding-a-new-domain)
- [Health Check](#health-check)
- [Failover](#failover)
- [KSK Rotation](#ksk-rotation)
- [Troubleshooting](#troubleshooting)
- [Azure Resource Groups & Subscriptions](#azure-resource-groups--subscriptions)
- [References](#references)
- [DNSSEC Teardown](#dnssec-teardown-for-testing--full-reset)

## How It Works

### What this project contains

```
dnssec/
├── config.yaml          # Domain registry: all DNSSEC-enabled domains + Azure settings
├── health-check.sh      # DNSSEC validation + Slack alerts (zero API calls, dig only)
├── onboard_domains.py   # Automated: enables DNSSEC on all domains in config.yaml
├── requirements.txt     # Python dependencies for onboard_domains.py
└── README.md            # This runbook

.github/workflows/
├── dnssec-onboard.yml        # Runs on config.yaml push: dry-run on feature branches, approval-gated onboard on main
└── dnssec-health-check.yml   # Runs health-check.sh twice a month (1st and 15th) at 07:00 UTC
```

### What this project does NOT do

- **NS updates** — handled by the [`dns-nameservers`](../dns-nameservers/README.md) project (`domains.yaml` + `update_nameservers.py`)
- **DNS record management** — handled by Terraform in `terraform/dns-zones/`
- **DNSSEC teardown / disable** — automation is one-directional (enable only). Removing DNSSEC is always a manual process: wrong teardown order causes SERVFAIL globally, and CSC DS deletions involve variable-time order processing. See [DNSSEC Teardown](#dnssec-teardown-for-testing--full-reset) for the step-by-step procedure.

### Workflow overview

```
┌─────────────────────────────────────────────────────────────────┐
│                                                                 │
│  1. ONBOARDING (automated via GitHub Actions)                   │
│     a. Add domain to config.yaml                                │
│     b. Raise PR (feature branch)                                │
│        └── dnssec-onboard workflow runs dry-run automatically   │
│     c. Merge PR to main                                         │
│        └── dnssec-onboard workflow:                             │
│            ├── Dry-run job runs automatically                   │
│            ├── Onboard job queues for approval                  │
│            │   (reviewers: cloud-platform, network-security)    │
│            └── After approval:                                  │
│                ├── Enable DNSSEC on Cloudflare  (API call)      │
│                ├── Enable DNSSEC on Azure       (az command)    │
│                ├── Extract DS from both providers               │
│                ├── Add both DS records to CSC   (API calls)     │
│                └── Slack notification on success or failure     │
│                                                                 │
│  2. HEALTH MONITORING (automated, once daily via GitHub Actions)   │
│     └── health-check.sh reads config.yaml                       │
│         ├── dig +dnssec → DNSSEC working?                       │
│         ├── dig DS      → Both DS records present?              │
│         ├── dig DNSKEY  → KSK still present? (zone signed?)     │
│         └── On failure → Slack alert + pipeline fails           │
│                                                                 │
│  3. FAILOVER (manual, rare) — see Failover section             │
│     ├── Edit dns-nameservers/domains.yaml (change NS)           │
│     └── Run update_nameservers.py (push NS to CSC)              │
│         No DS changes needed — both already at CSC              │
│                                                                 │
│  4. KSK ROTATION (manual response, very rare)                  │
│     ├── Slack alert: SERVFAIL or DS count drop                  │
│     ├── Extract new DS from rotated provider                    │
│     └── Add new DS to CSC, remove old DS                        │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### config.yaml

Domain registry. Add a domain here to have it DNSSEC-enabled and monitored.

```yaml
domains:
  sasdigital.io:
    azure_resource_group: kubility-shared        # default: SAS-WEU-DNS_Zones-RG
    azure_subscription: adp-kubility-management  # default: SAS-DMZ-Infrastructure

  anotherdomain.com: {}   # uses both defaults
```

- Presence in the file = should be DNSSEC-enabled and monitored by health check
- `azure_resource_group` → needed for `az` commands (default: `SAS-WEU-DNS_Zones-RG`)
- `azure_subscription` → needed for `az account set` (default: `SAS-DMZ-Infrastructure`)
- No `status` field — onboarding is idempotent, safe to re-run on any domain
- No DS records stored — health check uses `dig` only, not config values

---

## Onboarding a New Domain

### Automated (recommended)

Add the domain to `config.yaml` on a feature branch and raise a PR. The workflow dry-runs automatically on the PR. Merge to `main` to trigger the onboarding — reviewers from `cloud-platform` and `network-security` must approve the onboard job before it runs.

**Minimal entry** (uses defaults `RG=SAS-WEU-DNS_Zones-RG`, `Sub=SAS-DMZ-Infrastructure`):

```yaml
domains:
  newdomain.com: {}
```

**Custom resource group / subscription:**

```yaml
domains:
  sasdigital.io:
    azure_resource_group: kubility-shared
    azure_subscription: adp-kubility-management
```

After the PR is merged, the `dnssec-onboard` workflow:
1. Runs a dry-run job (no gate) — output visible in the Actions UI
2. Pauses the onboard job for approval from `cloud-platform` and `network-security` reviewers
3. After approval: enables DNSSEC on Cloudflare + Azure (idempotent — skips if already enabled)
4. Extracts DS records from both providers
5. Adds both DS records to CSC (skips if already present)
6. Sends a Slack notification with the result

No config.yaml write-back — no branch protection bypass needed.

You can also trigger the workflow manually via **Actions → DNSSEC Onboard → Run workflow** (with dry-run option).

### Secrets required

The workflow uses these GitHub Actions secrets (same ones used by existing workflows):

| Secret | Purpose |
|--------|---------|
| `CF_DNS_API_TOKEN` | Cloudflare API token |
| `CSC_API_KEY` | CSC Global API key |
| `CSC_BEARER_TOKEN` | CSC Global bearer token |
| `CDX_ADMIN_CLIENT_ID` | Azure service principal (for `az login`) |
| `CDX_ADMIN_CLIENT_SECRET` | Azure service principal secret |

### Manual steps (if needed)

The individual commands are documented below for troubleshooting or partial re-runs.

<details>
<summary>Click to expand manual steps</summary>

### Step 0 — Set environment variables from Key Vault

Fetch all credentials from `sas-cdx-management-kv` (sub: `cdx-common`, RG: `management-rg`) — never hardcode them:

```bash
az account set --subscription "cdx-common"

export CLOUDFLARE_API_TOKEN=$(az keyvault secret show --vault-name sas-cdx-management-kv --name cf-dns-api-token --query value -o tsv)
export CSC_API_KEY=$(az keyvault secret show --vault-name sas-cdx-management-kv --name CSC-API-KEY --query value -o tsv)
export CSC_BEARER_TOKEN=$(az keyvault secret show --vault-name sas-cdx-management-kv --name CSC-BEARER-TOKEN --query value -o tsv)
```

Verify (shows only the first 8 chars — enough to confirm they loaded):

```bash
echo "CF: ${CLOUDFLARE_API_TOKEN:0:8}..."
echo "CSC_KEY: ${CSC_API_KEY:0:8}..."
echo "CSC_TOKEN: ${CSC_BEARER_TOKEN:0:8}..."
```

### Step 1 — Get Cloudflare Zone ID

The zone ID is auto-discovered from the domain name — no need to look it up manually.

```bash
ZONE_ID=$(curl -s \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  | jq -r '.result[0].id')

echo "Zone ID: $ZONE_ID"
```

### Step 2 — Enable DNSSEC on Cloudflare

```bash
curl -s -X PATCH \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"active"}' \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dnssec" | jq '.result.status'
```

### Step 3 — Enable DNSSEC on Azure

```bash
# Set subscription + RG (check config.yaml or use defaults)
az account set --subscription "SAS-DMZ-Infrastructure"
RG="SAS-WEU-DNS_Zones-RG"

az network dns dnssec-config create \
  --resource-group "$RG" \
  --zone-name "$DOMAIN"
```

### Step 4 — Extract DS records

**From Cloudflare:**

```bash
curl -s \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dnssec" \
  | jq '.result | {key_tag, algorithm, digest_type, digest}'
```

**From Azure:**

```bash
az network dns dnssec-config show \
  --resource-group "$RG" \
  --zone-name "$DOMAIN" \
  --query "signingKeys[?flags==\`257\`].{keyTag:keyTag, algorithm:securityAlgorithmType, digestType:delegationSignerInfo[0].digestAlgorithmType, digest:delegationSignerInfo[0].digestValue}" \
  -o table
```

### Step 5 — Add both DS records to CSC

Run this twice — once with Cloudflare DS values, once with Azure DS values:

```bash
KEY_TAG=2371
DIGEST="4E5820..."

# Check existing DS records:
curl -s \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/$DOMAIN" | jq .

# Add DS record:
curl -s -X POST \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"qualifiedDomainName\": \"$DOMAIN\",
    \"customFields\": [],
    \"showPrice\": true,
    \"notifications\": {
      \"enabled\": false,
      \"additionalNotificationEmails\": []
    },
    \"dsRecord\": {
      \"keyTag\": $KEY_TAG,
      \"algorithm\": 13,
      \"digestType\": 2,
      \"digest\": \"$DIGEST\"
    }
  }" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord"

# Delete a DS record:
curl -s -X DELETE \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"qualifiedDomainName\": \"$DOMAIN\",
    \"customFields\": [],
    \"showPrice\": true,
    \"notifications\": {\"enabled\": false, \"additionalNotificationEmails\": []},
    \"dsRecord\": {\"keyTag\": $KEY_TAG, \"algorithm\": 13, \"digestType\": 2, \"digest\": \"$DIGEST\"}
  }" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/single"
```

### Step 6 — Validate

```bash
# Should return NOERROR (not SERVFAIL)
dig "$DOMAIN" +dnssec @8.8.8.8

# Should show 2 DS records
dig "$DOMAIN" DS +short

# Visual: https://dnssec-analyzer.verisignlabs.com/$DOMAIN
```

If the domain is already in `config.yaml`, `health-check.sh` will monitor it automatically from the next daily run.

</details>

---

## Health Check

### Automated (twice a month)

A GitHub Actions workflow runs `health-check.sh` on the 1st and 15th of each month at 07:00 UTC.

- Workflow: `.github/workflows/dnssec-health-check.yml`
- On failure: sends a Slack alert with issue details, pipeline marked as failed
- Requires: `SLACK_WEBHOOK_URL` stored as a GitHub Actions secret

### Manual

```bash
./health-check.sh                   # All domains
./health-check.sh sasdigital.io     # Single domain
```

### What it checks

Reads all domains from `config.yaml`. Uses `dig` only — zero API calls.

| Check | What it does | Alert condition |
|-------|-------------|------------------|
| DNSSEC validation | `dig +dnssec @8.8.8.8` | SERVFAIL = chain of trust broken |
| DS record count | `dig DS +short` | Count < 2 = one provider missing from CSC |
| DNSKEY KSK present | `dig DNSKEY +short` — checks for flag=257 | No KSK = zone may have been unsigned |

### Setup

1. Create a Slack Incoming Webhook for your channel
2. Add it as a secret `SLACK_WEBHOOK_URL` in the GitHub repo (Settings → Secrets → Actions)
3. The workflow triggers on the 1st and 15th of each month at 07:00 UTC — or manually via Actions → "Run workflow"

---

## Failover

Both DS records are already at CSC, so failover is just an NS change — no DS record updates needed.

1. In the [`dns-nameservers`](../dns-nameservers/README.md) project, edit `domains.yaml` — set NS to Azure nameservers
2. Run `python dns-nameservers/update_nameservers.py`
3. Wait 15–60 minutes for NS propagation
4. Validate: `./health-check.sh <domain>`

Failback = same process, change NS back to Cloudflare.

---

## KSK Rotation

Rare (years). `health-check.sh` detects it via:
- **Check 1 (SERVFAIL)**: chain of trust broken — DS at CSC no longer matches the live DNSKEY
- **Check 3 (no KSK)**: zone was unsigned, DNSKEY removed — SERVFAIL imminent

### Cloudflare rotation policy (confirmed)

Confirmed directly with Cloudflare DNS engineering team (March 2026):

| Scenario | Notice | Old + new KSK coexist | Customer notification |
|---|---|---|---|
| **Planned rotation** | ≥ 1 month in advance | Until Cloudflare observes customer DS records updated — no fixed deadline, they wait | Status page + email + account manager |
| **Emergency rotation** | ASAP after rotation starts | Cloudflare adheres to TTLs — DNS will not break immediately | All available channels (status page, email, account manager) |

> On planned rotation: Cloudflare adds the new KSK to the DNSKEY set and monitors until customer DS records at the registrar are updated, then removes the old KSK after at least one DS record TTL has elapsed.
>
> On emergency rotation: Cloudflare starts the roll immediately but deliberately avoids breaking customer DNS during the process — serving a potentially compromised key briefly is considered preferable to causing widespread SERVFAIL.

**Our response on emergency rotation: [failover to Azure DNS immediately](#failover)** — change NS records via the [`dns-nameservers`](../dns-nameservers/README.md) project to Azure nameservers. Azure DS is already registered at CSC, so no DS changes needed. Then update the Cloudflare DS at CSC at your own pace.

### Key_tag behaviour by provider

- **Cloudflare** — all zones within the same Cloudflare account use the same ZSK/KSK pair ([Cloudflare Foundation DNS — DNSSEC keys](https://developers.cloudflare.com/dns/foundation-dns/dnssec-keys/)). **All Cloudflare-managed domains in the account share the same key_tag.** When Cloudflare rotates the KSK, every domain is impacted simultaneously and requires a DS update at CSC. Each domain still has a unique DS digest — the digest is computed over owner name + key material (RFC 4034 §5.1.4), so different domain names produce different digest values even with the same key. You must extract and register the correct digest per domain from the CF API.
- **Azure** — generates a per-zone KSK. Each domain has its own unique key_tag and digest. A rotation only affects the specific domain — one DS update, one config.yaml change.

**Cloudflare rotation blast radius**: the health check will fire alerts for every Cloudflare-managed domain in `config.yaml` at the same time. For each domain you must: extract the new DS from the CF API (digest is domain-specific), add the new DS to CSC, remove the old DS, update `config.yaml`. The number of simultaneous alerts is the signal — all firing with the same old key_tag = shared KSK rotation.

**A rotated KSK always produces a new key_tag** — it is a 16-bit checksum computed directly from the key material (RFC 4034 §B.1), so any key change produces a different value.

**Impact if missed**: SERVFAIL on all DNSSEC-validating resolvers once the provider removes the old KSK. For planned rotations Cloudflare gives ≥1 month — for emergency rotations failover to Azure immediately.

### Response procedure

Example: Cloudflare rotated KSK for `sasdigital.io`.

```bash
DOMAIN="sasdigital.io"
ZONE_ID="ea22c5f778c7542c7a06a542d46cf089"
RG="kubility-shared"

# 1. Extract the new DS from the provider that rotated

# From Cloudflare:
curl -s -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dnssec" \
  | jq '.result | {key_tag, algorithm, digest_type, digest}'

# From Azure (if Azure rotated instead):
az account set --subscription "adp-kubility-management"
az network dns dnssec-config show \
  --resource-group "$RG" \
  --zone-name "$DOMAIN" \
  --query "signingKeys[?flags==\`257\`].{keyTag:keyTag, algorithm:securityAlgorithmType, digestType:delegationSignerInfo[0].digestAlgorithmType, digest:delegationSignerInfo[0].digestValue}" \
  -o table

# 2. Add the new DS to CSC
NEW_KEY_TAG=9999        # from step 1
NEW_DIGEST="ABCDEF..."  # from step 1

curl -s -X POST \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"qualifiedDomainName\": \"$DOMAIN\",
    \"customFields\": [],
    \"showPrice\": true,
    \"notifications\": {\"enabled\": false, \"additionalNotificationEmails\": []},
    \"dsRecord\": {\"keyTag\": $NEW_KEY_TAG, \"algorithm\": 13, \"digestType\": 2, \"digest\": \"$NEW_DIGEST\"}
  }" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord"

# 3. Verify new DS is present (wait 15-30 min for propagation)
dig "$DOMAIN" DS +short

# 4. Remove old DS from CSC (only after new DS is confirmed)
OLD_KEY_TAG=2371            # the old key_tag from config.yaml
 OLD_DIGEST="4E5820B0..."    # the old digest from config.yaml

curl -s -X DELETE \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"qualifiedDomainName\": \"$DOMAIN\",
    \"customFields\": [],
    \"showPrice\": true,
    \"notifications\": {\"enabled\": false, \"additionalNotificationEmails\": []},
    \"dsRecord\": {\"keyTag\": $OLD_KEY_TAG, \"algorithm\": 13, \"digestType\": 2, \"digest\": \"$OLD_DIGEST\"}
  }" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/single"

# 5. Verify
./health-check.sh "$DOMAIN"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| SERVFAIL on `dig +dnssec` | DS doesn't match active KSK | Extract current DS, update CSC — see [KSK Rotation](#ksk-rotation) |
| Only 1 DS record | Missing provider's DS | Add DS (Step 5 in manual steps) |
| "Not delegated" in Azure | NS points to Cloudflare | Expected — see note below |
| DNSKEY KSK missing | Zone was unsigned | Re-enable DNSSEC in Cloudflare + Azure portal |

### Azure portal health alerts — false positives while Cloudflare is primary

All Azure DNS zones will permanently show the following warnings in the Azure portal Resource Health blade **as long as Cloudflare is the active/primary DNS provider**:

- *"Your zone's chain of trust cannot be validated"* / *"Signed but not delegated"*
- *"Your DNS zone is unavailable"* (Unavailable / Unplanned) — appears repeatedly in alert history

**These are false positives.** Azure's health check expects its own nameservers to be authoritative. Since NS records point to Cloudflare, Azure sees its zones as signed but never served, and reports them as unavailable.

The actual chain-of-trust health can be verified independently:

```bash
# Should return 2 DS records — one from Cloudflare (tag ~2371), one from Azure
dig <domain> DS +short

# End-to-end DNSSEC validation
https://dnssec-analyzer.verisignlabs.com/<domain>
```

Once a failover is performed (NS records switched to Azure), **the alerts will clear automatically** — confirming that Azure is fully active. Do not suppress these alerts, as their disappearance after a failover is a useful confirmation signal.

### Useful dig commands

```bash
dig +dnssec +multi "$DOMAIN" @8.8.8.8              # Full validation
dig "$DOMAIN" DS +short                             # DS at registry
dig "$DOMAIN" DNSKEY +short @elinore.ns.cloudflare.com   # Cloudflare keys
dig "$DOMAIN" DNSKEY +short @ns1-37.azure-dns.com        # Azure keys
dig "$DOMAIN" SOA +short                            # Which provider is active
```

## Azure Resource Groups & Subscriptions

Zones live in different resource groups and subscriptions. Always check `config.yaml` for the correct values before running `az` commands.

| Resource Group | Subscription | Domains |
|---|---|---|
| `kubility-shared` | `adp-kubility-management` | sasdigital.io |
| `SAS-WEU-DNS_Zones-RG` | `SAS-DMZ-Infrastructure` | flysas.com, sas.dk, sas.fi, sas.no, sas.se, sascargo.com, airside.app, sassalesinfo.com, scandinavian.net |
| `management-rg` | `SAS-DMZ-Infrastructure` | flysas.tech |

## References

- [Cloudflare DNSSEC](https://developers.cloudflare.com/dns/dnssec/)
- [Azure DNSSEC](https://learn.microsoft.com/en-us/azure/dns/dnssec)
- [Verisign DNSSEC Analyzer](https://dnssec-analyzer.verisignlabs.com/)
- [RFC 6781 — DNSSEC Operational Practices](https://datatracker.ietf.org/doc/html/rfc6781)

---

## DNSSEC Teardown (for testing / full reset)

Complete removal of DNSSEC for a domain. **Order matters** — remove DS from registrar first, then disable providers.

Example using `sasdigital.io` (sub: `adp-kubility-management`, RG: `kubility-shared`, CF zone: `ea22c5f778c7542c7a06a542d46cf089`).

### Step 1 — Get current DS records from CSC

```bash
curl -s -H "apikey: $CSC_API_KEY" -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/sasdigital.io" | jq .
```

### Step 2 — Delete DS records from CSC

Delete one at a time. Wait ~1-2 min between deletes (CSC processes them as orders).

```bash
# Delete Cloudflare DS (key_tag 2371)
curl -s -X DELETE \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "qualifiedDomainName": "sasdigital.io",
    "customFields": [],
    "showPrice": true,
    "notifications": {"enabled": false, "additionalNotificationEmails": []},
    "dsRecord": {"keyTag": 2371, "algorithm": 13, "digestType": 2, "digest": "4E5820B0F01EC1191498145DCBB3BC7E1F0F5E066E7C86B38474568F0BC03054"}
  }' \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/single"

# Wait ~1-2 min, then delete Azure DS (key_tag 55553)
curl -s -X DELETE \
  -H "apikey: $CSC_API_KEY" \
  -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "qualifiedDomainName": "sasdigital.io",
    "customFields": [],
    "showPrice": true,
    "notifications": {"enabled": false, "additionalNotificationEmails": []},
    "dsRecord": {"keyTag": 55553, "algorithm": 13, "digestType": 2, "digest": "7B93FD53415443ED8E8963343371C2C60692E6EB5AEE0F11811790FEB16399F8"}
  }' \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/single"

# Confirm empty
curl -s -H "apikey: $CSC_API_KEY" -H "Authorization: Bearer $CSC_BEARER_TOKEN" \
  "https://apis.cscglobal.com/dbs/api/v2/dsrecord/sasdigital.io" | jq .
```

### Step 3 — Disable DNSSEC on Azure

```bash
az account set --subscription "adp-kubility-management"
az network dns dnssec-config delete \
  --resource-group kubility-shared \
  --zone-name sasdigital.io \
  --yes
```

### Step 4 — Disable DNSSEC on Cloudflare

Cloudflare requires disable first, then delete:

```bash
# Disable
curl -s -X PATCH \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"disabled"}' \
  "https://api.cloudflare.com/client/v4/zones/ea22c5f778c7542c7a06a542d46cf089/dnssec" \
  | jq '.result.status'

# Delete (once status shows disabled)
curl -s -X DELETE \
  -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN" \
  "https://api.cloudflare.com/client/v4/zones/ea22c5f778c7542c7a06a542d46cf089/dnssec" | jq .
```

### Step 5 — Verify cleanup

Wait 15-30 min for DS propagation, then:

```bash
dig sasdigital.io DS +short          # should be empty
dig sasdigital.io +dnssec @8.8.8.8   # should return NOERROR (unsigned)
```

### Step 6 — Remove domain from config.yaml

Remove the domain entry from `config.yaml` and push to `main` (or raise a PR). The domain will no longer be monitored by the health check.

### Step 7 — Re-onboard

When ready to re-enable DNSSEC, add the domain back to `config.yaml` on a feature branch, raise a PR (dry-run runs automatically), then merge to `main`. See [Onboarding a New Domain](#onboarding-a-new-domain).

```yaml
domains:
  sasdigital.io:
    azure_resource_group: kubility-shared
    azure_subscription: adp-kubility-management
```
