#!/usr/bin/env bash
#
# VulnRadar Demo Reset Script
# ===========================
# Wipes the local demo repo and rebuilds it from a fresh shallow clone
# of VulnRadar. No history is carried over — just the latest code,
# a demo watchlist, and a single clean commit.
#
# Usage:
#   ./scripts/reset_demo.sh [path_to_vulnradar_demo]
#
# Default: ~/Documents/Github/RogoLabs/VulnRadar-Demo
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Defaults
DEMO_REPO="${1:-$HOME/Documents/Github/RogoLabs/VulnRadar-Demo}"
DEMO_REMOTE="https://github.com/RogoLabs/VulnRadar-Demo.git"
UPSTREAM_REMOTE="https://github.com/RogoLabs/VulnRadar.git"

echo -e "${BLUE}🛡️ VulnRadar Demo Reset Script${NC}"
echo "================================"
echo ""

# ── Step 1: Detect existing demo remote (before we wipe it) ─────────
if [ -d "$DEMO_REPO/.git" ]; then
    DETECTED_REMOTE=$(git -C "$DEMO_REPO" remote get-url origin 2>/dev/null || true)
    if [ -n "$DETECTED_REMOTE" ]; then
        DEMO_REMOTE="$DETECTED_REMOTE"
    fi
    echo -e "${YELLOW}🗑️  Step 1: Removing old demo repo...${NC}"
    rm -rf "$DEMO_REPO"
    echo -e "  ${GREEN}→ Removed $DEMO_REPO${NC}"
else
    echo -e "${YELLOW}📁 Step 1: No existing demo repo at $DEMO_REPO${NC}"
fi

echo ""

# ── Step 2: Shallow clone upstream VulnRadar (depth 1 = no history) ──
echo -e "${YELLOW}📦 Step 2: Fresh shallow clone from VulnRadar...${NC}"
git clone --depth 1 "$UPSTREAM_REMOTE" "$DEMO_REPO"
echo -e "  ${GREEN}→ Cloned latest VulnRadar (single commit, no history)${NC}"

cd "$DEMO_REPO"

echo ""

# ── Step 3: Swap origin to point at the demo repo ───────────────────
echo -e "${YELLOW}🔗 Step 3: Setting origin to demo remote...${NC}"
git remote set-url origin "$DEMO_REMOTE"
echo "  → origin → $DEMO_REMOTE"

echo ""

# ── Step 4: Clean state for first run ────────────────────────────────
echo -e "${YELLOW}🔄 Step 4: Resetting state for first run...${NC}"

mkdir -p data
rm -f data/state.json
echo "  → Ensured no data/state.json (triggers first-run behavior)"

echo ""

# ── Step 5: Install demo watchlist ───────────────────────────────────
echo -e "${YELLOW}📋 Step 5: Installing demo watchlist...${NC}"

cat > watchlist.yaml << 'WATCHLIST'
# VulnRadar Demo Watchlist
# ========================
# A comprehensive demo watchlist with major vendors.
# Uses min_cvss: 7.0 threshold to keep data size under GitHub's 100MB limit.

# ============================================================================
# VENDORS - Major software vendors for comprehensive demo coverage
# ============================================================================
vendors:
  # Big tech (Patch Tuesday, monthly updates)
  - microsoft           # Windows, Office, Azure, Exchange
  - apple               # macOS, iOS, Safari
  - google              # Chrome, Android, GCP

  # Infrastructure & security
  - cisco               # IOS, ASA, WebEx
  - vmware              # ESXi, vCenter, Horizon
  - linux               # Linux kernel
  - apache              # httpd, Tomcat, Log4j, Kafka

  # Security vendors (often in KEV)
  - fortinet            # FortiGate, FortiOS
  - paloaltonetworks    # PAN-OS firewalls
  - ivanti              # VPN/MDM

# ============================================================================
# PRODUCTS - High-signal products
# ============================================================================
products:
  - log4j               # Log4Shell and variants
  - chrome              # Google Chrome browser
  - openssl             # Heartbleed, etc.
  - jenkins             # CI/CD - many CVEs

# ============================================================================
# EXCLUSIONS
# ============================================================================
exclude_vendors:
  - n/a
  - unknown
  - unspecified

# ============================================================================
# THRESHOLDS - High+ severity only to keep file size manageable
# ============================================================================
thresholds:
  min_cvss: 7.0         # High (7.0-8.9) and Critical (9.0+) only
WATCHLIST

echo "  → Created demo watchlist (min_cvss: 7.0)"

echo ""

# ── Step 6: Commit everything as a single clean commit ───────────────
echo -e "${YELLOW}💾 Step 6: Creating single clean commit...${NC}"

git add -A
changes=$(git status --porcelain | wc -l | tr -d ' ')

if [ "$changes" -gt "0" ]; then
    git commit --amend --no-edit -m "chore: reset demo from VulnRadar $(date +%Y-%m-%d)

Fresh shallow clone with demo watchlist (min_cvss: 7.0).
No prior history carried over."
    echo -e "  ${GREEN}→ Single clean commit created${NC}"
else
    echo "  → No extra changes to commit"
fi

echo ""

# ── Step 7: Force push the single commit ─────────────────────────────
echo -e "${YELLOW}🚀 Step 7: Force pushing clean repo...${NC}"
git push --force origin main
echo -e "  ${GREEN}→ Pushed! (single commit, no bloated history)${NC}"

echo ""

# ── Step 8: Trigger ETL workflow ─────────────────────────────────────
echo -e "${YELLOW}⚡ Step 8: Triggering ETL workflow...${NC}"

if ! command -v gh &> /dev/null; then
    echo -e "  ${YELLOW}⚠️ GitHub CLI (gh) not installed. Skipping workflow trigger.${NC}"
    echo "  Install with: brew install gh"
    echo "  Then run manually: gh workflow run update.yml"
else
    REPO_NAME=$(echo "$DEMO_REMOTE" | sed -E 's/.*[:/]([^/]+\/[^/]+)(\.git)?$/\1/' | sed 's/\.git$//')

    echo "  → Triggering update.yml workflow on $REPO_NAME..."
    if gh workflow run update.yml --repo "$REPO_NAME"; then
        echo -e "  ${GREEN}→ ETL workflow triggered!${NC}"
        echo ""
        echo "  View progress at:"
        echo "  https://github.com/$REPO_NAME/actions/workflows/update.yml"
    else
        echo -e "  ${YELLOW}⚠️ Failed to trigger workflow. You may need to:${NC}"
        echo "  1. Run: gh auth login"
        echo "  2. Then: gh workflow run update.yml --repo $REPO_NAME"
    fi
fi

echo ""

# ── Summary ──────────────────────────────────────────────────────────
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ Demo repo ready and workflow triggered!${NC}"
echo ""
echo "What happens next:"
echo "  1. ETL workflow runs (~2-3 minutes)"
echo "  2. Notify workflow triggers automatically after ETL"
echo "  3. First run creates baseline summary issue"
echo ""
echo "For conference demo:"
echo "  - Your watchlist will find matching CVEs"
echo "  - Check GitHub Issues for the baseline summary"
echo "  - Use --demo flag to inject a fake critical CVE for live demo"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════${NC}"
