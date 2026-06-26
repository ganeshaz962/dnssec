#!/bin/bash
# ──────────────────────────────────────────────────────────
# DNSSEC Health Check
#
# Reads all domains from config.yaml and validates DNSSEC health.
# Zero API calls — all checks use public DNS queries via dig.
#
# Sends a Slack alert when issues are detected (if SLACK_WEBHOOK_URL is set).
# Designed to run on a schedule via GitHub Actions.
#
# Checks per domain:
#   1. DNSSEC validation: resolver returns NOERROR (not SERVFAIL)
#   2. DS record count:   at least 2 DS records at registrar (CF + Azure)
#   3. DNSKEY KSK present: zone is still signed (flag=257 record exists)
#
# Usage:
#   ./health-check.sh                   # Check all domains
#   ./health-check.sh sasdigital.io     # Check one domain
#
# Environment:
#   SLACK_WEBHOOK_URL  — Slack incoming webhook (optional, for alerts)
#
# Requires: dig, grep, awk, curl (for Slack)
# ──────────────────────────────────────────────────────────

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/config.yaml"
RESOLVER="8.8.8.8"
ISSUES_LOG=""

# ── Colors ───────────────────────────────────────────────
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[0;33m"
NC="\033[0m"

ok()   { echo -e "  ${GREEN}✅ $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }

# ── Parse config.yaml ────────────────────────────────────
# Extracts all domain names from config.yaml.
# Simple awk parser — no python/yq dependency needed.
# Handles Windows line endings (CRLF).

parse_config() {
  tr -d '\r' < "$CONFIG" | awk '
    /^  [a-zA-Z][a-zA-Z0-9._-]+:/ {
      domain = $0; gsub(/^  /, "", domain); gsub(/:.*$/, "", domain)
      print domain
    }
  '
}

# ── Check one domain ─────────────────────────────────────
check_domain() {
  local domain="$1"
  local issues=0

  echo ""
  echo "── $domain ──"

  # Check 1: DNSSEC validation (SERVFAIL = broken, NOERROR = ok)
  local status
  status=$(dig "$domain" A @"$RESOLVER" +dnssec +noall +comments 2>/dev/null \
    | grep -o "status: [A-Z]*" | awk '{print $2}')

  if [[ "$status" == "NOERROR" ]]; then
    ok "DNSSEC validation: NOERROR"
  elif [[ "$status" == "SERVFAIL" ]]; then
    fail "DNSSEC validation: SERVFAIL — chain of trust broken"
    ISSUES_LOG+="$domain: SERVFAIL — chain of trust broken\n"
    ISSUES_LOG+="  → Run: dig $domain DS +short && dig $domain DNSKEY +short\n"
    ((issues++))
  else
    warn "DNSSEC validation: $status"
    ISSUES_LOG+="$domain: unexpected DNS status $status\n"
    ((issues++))
  fi

  # Check 2: DS record count at registry (expect 2: Cloudflare + Azure)
  local ds_output
  ds_output=$(dig "$domain" DS +short @"$RESOLVER" 2>/dev/null)
  local ds_count
  ds_count=$(echo "$ds_output" | grep -c "^[0-9]" || true)

  if [[ "$ds_count" -ge 2 ]]; then
    ok "DS records: $ds_count present (both providers covered)"
  elif [[ "$ds_count" -eq 1 ]]; then
    warn "DS records: 1 present (expected 2) — one provider not covered"
    ISSUES_LOG+="$domain: only 1/2 DS records — failover provider missing from CSC\n"
    ((issues++))
  else
    fail "DS records: none found"
    ISSUES_LOG+="$domain: no DS records found at registry\n"
    ((issues++))
  fi

  # Check 3: DNSKEY KSK presence — confirms zone is still signed
  local ksk_count
  ksk_count=$(dig "$domain" DNSKEY +short @"$RESOLVER" 2>/dev/null | grep -c "^257 " || true)

  if [[ "$ksk_count" -ge 1 ]]; then
    ok "DNSKEY KSK (flag=257): $ksk_count present — zone is signed"
  else
    fail "DNSKEY KSK (flag=257): none found — zone may have been unsigned"
    ISSUES_LOG+="$domain: no KSK DNSKEY found — zone may be unsigned or DNSSEC removed\n"
    ISSUES_LOG+="  → Verify DNSSEC is enabled in Cloudflare + Azure portal\n"
    ((issues++))
  fi

  return $issues
}

# ── Slack notification ───────────────────────────────────
send_slack_notification() {
  local issue_count="$1"
  local domain_count="$2"

  if [[ -z "${SLACK_WEBHOOK_URL:-}" ]]; then
    echo ""
    echo "(Slack notification skipped — SLACK_WEBHOOK_URL not set)"
    return
  fi

  local payload
  if [[ $issue_count -eq 0 ]]; then
    payload=$(cat <<EOF
{
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": "✅ DNSSEC Health Check Passed"}
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "All *${domain_count} domain(s)* passed DNSSEC validation."}
    },
    {
      "type": "context",
      "elements": [{"type": "mrkdwn", "text": "$(date -u '+%Y-%m-%d %H:%M UTC') | <https://dnssec-analyzer.verisignlabs.com/|Verisign Analyzer>"}]
    }
  ]
}
EOF
)
  else
    payload=$(cat <<EOF
{
  "blocks": [
    {
      "type": "header",
      "text": {"type": "plain_text", "text": "🚨 DNSSEC Health Check Failed"}
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "*${issue_count} issue(s)* across ${domain_count} domain(s)"}
    },
    {
      "type": "section",
      "text": {"type": "mrkdwn", "text": "\`\`\`$(echo -e "$ISSUES_LOG")\`\`\`"}
    },
    {
      "type": "context",
      "elements": [{"type": "mrkdwn", "text": "$(date -u '+%Y-%m-%d %H:%M UTC') | Run \`./health-check.sh\` locally for full details | <https://dnssec-analyzer.verisignlabs.com/|Verisign Analyzer> | See KSK Rotation section in dnssec/README.md"}]
    }
  ]
}
EOF
)
  fi

  curl -s -X POST -H "Content-Type: application/json" \
    -d "$payload" "$SLACK_WEBHOOK_URL" > /dev/null 2>&1

  echo "  Slack notification sent"
}

# ── Main ─────────────────────────────────────────────────

if [[ ! -f "$CONFIG" ]]; then
  echo "Error: config.yaml not found at $CONFIG"
  exit 1
fi

echo "🔐 DNSSEC Health Check"
echo "======================"

# Read domains from config.yaml
mapfile -t DOMAINS < <(parse_config)

if [[ ${#DOMAINS[@]} -eq 0 ]]; then
  echo ""
  echo "No domains found in config.yaml"
  exit 0
fi

total_issues=0
checked=0

if [[ $# -gt 0 ]]; then
  # Check specific domain
  found=0
  for domain in "${DOMAINS[@]}"; do
    if [[ "$domain" == "$1" ]]; then
      check_domain "$domain" || ((total_issues += $?))
      ((checked++))
      found=1
    fi
  done
  if [[ $found -eq 0 ]]; then
    echo ""
    echo "Domain '$1' not found in config.yaml"
    exit 1
  fi
else
  # Check all domains
  for domain in "${DOMAINS[@]}"; do
    check_domain "$domain" || ((total_issues += $?))
    ((checked++))
  done
fi

echo ""
echo "======================"
if [[ $total_issues -eq 0 ]]; then
  echo -e "${GREEN}✅ All checks passed ($checked domain(s))${NC}"
  send_slack_notification 0 "$checked"
  exit 0
else
  echo -e "${YELLOW}⚠️  $total_issues issue(s) across $checked domain(s)${NC}"
  send_slack_notification "$total_issues" "$checked"
  exit 1
fi
