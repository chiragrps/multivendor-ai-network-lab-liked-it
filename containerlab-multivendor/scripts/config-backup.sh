#!/usr/bin/env bash
# ============================================================================
#  GESH Config Backup — Collects running configs from all 9 network devices
#  Stores timestamped backups in configs/backups/YYYY-MM-DD/
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DATE=$(date +%Y-%m-%d_%H%M)
BACKUP_DIR="${PROJECT_DIR}/configs/backups/${DATE}"

mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  Config Backup — ${DATE}                          ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

TOTAL=0
OK=0
FAIL=0

backup_srl() {
    local node=$1
    local container="clab-clos-evpn-${node}"
    echo -n "  [SRL] ${node}... "
    if docker exec "$container" sr_cli "info flat" > "${BACKUP_DIR}/${node}-srl.cfg" 2>/dev/null; then
        local lines=$(wc -l < "${BACKUP_DIR}/${node}-srl.cfg")
        echo -e "${GREEN}OK${NC} (${lines} lines)"
        OK=$((OK + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

backup_ceos() {
    local node=$1
    local container="clab-clos-evpn-${node}"
    echo -n "  [cEOS] ${node}... "
    if docker exec "$container" Cli -p 15 -c "show running-config" > "${BACKUP_DIR}/${node}-eos.cfg" 2>/dev/null; then
        local lines=$(wc -l < "${BACKUP_DIR}/${node}-eos.cfg")
        echo -e "${GREEN}OK${NC} (${lines} lines)"
        OK=$((OK + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

backup_frr() {
    local node=$1
    local container="clab-clos-evpn-${node}"
    echo -n "  [FRR] ${node}... "
    if docker exec "$container" vtysh -c "show running-config" > "${BACKUP_DIR}/${node}-frr.cfg" 2>/dev/null; then
        local lines=$(wc -l < "${BACKUP_DIR}/${node}-frr.cfg")
        echo -e "${GREEN}OK${NC} (${lines} lines)"
        OK=$((OK + 1))
    else
        echo -e "${RED}FAIL${NC}"
        FAIL=$((FAIL + 1))
    fi
    TOTAL=$((TOTAL + 1))
}

echo -e "${CYAN}Collecting running configs...${NC}"
echo ""

# Spines
backup_srl spine1
backup_ceos spine2
backup_frr spine3

# Leafs
backup_ceos leaf1
backup_srl leaf2
backup_frr leaf3
backup_ceos leaf4
backup_srl leaf5
backup_frr leaf6

# Generate summary
echo ""
echo -e "${BOLD}Summary: ${GREEN}${OK}/${TOTAL} OK${NC}, ${RED}${FAIL} failed${NC}"
echo -e "Backup dir: ${CYAN}${BACKUP_DIR}${NC}"
echo ""

# Create latest symlink
ln -sfn "${BACKUP_DIR}" "${PROJECT_DIR}/configs/backups/latest"

# Generate diff against previous backup if exists
PREV=$(ls -1d "${PROJECT_DIR}/configs/backups/20"* 2>/dev/null | sort | tail -2 | head -1)
if [[ -n "$PREV" && "$PREV" != "$BACKUP_DIR" ]]; then
    echo -e "${CYAN}Changes since last backup:${NC}"
    DIFF_COUNT=0
    for f in "${BACKUP_DIR}"/*.cfg; do
        fname=$(basename "$f")
        prev_file="${PREV}/${fname}"
        if [[ -f "$prev_file" ]]; then
            changes=$(diff "$prev_file" "$f" 2>/dev/null | grep -c "^[<>]" || true)
            if (( changes > 0 )); then
                echo -e "  ${fname}: ${changes} lines changed"
                DIFF_COUNT=$((DIFF_COUNT + changes))
            fi
        fi
    done
    if (( DIFF_COUNT == 0 )); then
        echo "  No changes detected"
    fi
fi
echo ""
