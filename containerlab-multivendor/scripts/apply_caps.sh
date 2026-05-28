#!/usr/bin/env bash
# apply_caps.sh — non-destructive runtime memory cap enforcer for clos-evpn lab
#
# WHY: The clab YAML kinds block sets per-kind memory limits, but those only
# take effect on the next `clab redeploy`. Until then, run this to apply the
# same caps live via `docker update` — no container restart, no BGP/EVPN state
# loss. Idempotent: safe to re-run.
#
# WHAT: Filters containers by clab-node-kind label (not by name substring,
# which produces wrong matches because container names mix kinds — e.g.
# leaf2 is SRL, leaf3 is linux/FRR). Caps mirror clos-evpn.clab.yml verbatim.
#
# USAGE:
#   ./apply_caps.sh            # apply caps to all running clos-evpn containers
#   ./apply_caps.sh --dry-run  # show what would be done, change nothing
#   ./apply_caps.sh --verify   # report current limits vs target, no changes

set -eo pipefail

# Targets MUST match clos-evpn.clab.yml `kinds:` block. If you edit one, edit
# the other in the same commit. Format: "kind:megabytes" (kept as parallel
# strings to stay compatible with macOS bash 3.2 — no associative arrays).
KIND_TARGETS=(
  "ceos:2560"   # observed cEOS working set 2.5–2.8 GiB; 2560 MB + ~10% headroom
  "srl:2048"    # Nokia recommends 1.5–2 GB for ixrd3l
  "linux:512"   # FRR ≤ 60 MiB, hosts ≤ 6 MiB; defense-in-depth
)

LAB_PREFIX="clab-clos-evpn"
MODE="apply"
case "${1:-}" in
  --dry-run) MODE="dry-run" ;;
  --verify)  MODE="verify"  ;;
  "")        ;;
  *) echo "Usage: $0 [--dry-run|--verify]"; exit 2 ;;
esac

containers_for_kind() {
  # Print "name<TAB>id" for every running clos-evpn container of the given kind.
  docker ps \
    --filter "label=clab-node-kind=$1" \
    --filter "name=${LAB_PREFIX}" \
    --format '{{.Names}}\t{{.ID}}'
}

apply_one() {
  local name="$1" id="$2" mb="$3"
  case "$MODE" in
    apply)
      docker update --memory "${mb}m" --memory-swap "${mb}m" "$id" >/dev/null
      printf "  ✓ %-40s capped at %5d MB\n" "$name" "$mb"
      ;;
    dry-run)
      printf "  [dry-run] would cap %-40s at %5d MB\n" "$name" "$mb"
      ;;
    verify)
      local current_bytes
      current_bytes=$(docker inspect "$id" --format '{{.HostConfig.Memory}}')
      local current_mb=$(( current_bytes / 1024 / 1024 ))
      local target_bytes=$(( mb * 1024 * 1024 ))
      if [[ "$current_bytes" -eq "$target_bytes" ]]; then
        printf "  ✓ %-40s %4d MB (matches)\n" "$name" "$current_mb"
      elif [[ "$current_bytes" -eq 0 ]]; then
        printf "  ✗ %-40s UNCAPPED (target %d MB)\n" "$name" "$mb"
      else
        printf "  ! %-40s %4d MB (target %d MB — drift)\n" "$name" "$current_mb" "$mb"
      fi
      ;;
  esac
}

echo "apply_caps.sh — mode=${MODE}  prefix=${LAB_PREFIX}"
echo

total=0
for entry in "${KIND_TARGETS[@]}"; do
  kind="${entry%%:*}"
  mb="${entry##*:}"
  matches=$(containers_for_kind "$kind" || true)
  if [[ -z "$matches" ]]; then
    echo "kind=${kind} (target ${mb} MB): no running containers"
    continue
  fi
  echo "kind=${kind} (target ${mb} MB):"
  while IFS=$'\t' read -r name id; do
    [[ -z "$name" ]] && continue
    apply_one "$name" "$id" "$mb"
    total=$((total + 1))
  done <<< "$matches"
  echo
done

echo "Processed ${total} container(s)."
if [[ "$MODE" == "apply" ]]; then
  echo "Run \`$0 --verify\` to confirm, or \`docker stats --no-stream\` for live usage."
fi
