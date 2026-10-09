#!/bin/bash
#
# Synopsis:    Test SSH (TCP 22) reachability of network devices, filtered by client and device type.
# Platform:    macOS / Linux (bash; uses nc if present)
# Permissions: None (read access to ~/.ssh/config.d)
# When to use: Before or after a network change window, to confirm which switches, routers and firewalls answer.
# Safety:      Read-only (opens a TCP connection, sends no data)
#
# Device lists live OUTSIDE this repo, one file per client in ~/.ssh/config.d/<client>.conf.
# Each host block is preceded by a tag comment that drives the filtering:
#     # client=contoso type=switch site=HQ
#     Host core-sw1 core-sw1.contoso.com
#         HostName 192.0.2.10
#
# Examples:
#   ./ssh-check.sh                        test every device, every client
#   ./ssh-check.sh contoso                only the contoso devices
#   ./ssh-check.sh contoso --type switch  only contoso switches
#   ./ssh-check.sh --type firewall        firewalls across all clients
#   ./ssh-check.sh contoso --port 443     test a different port
#   ./ssh-check.sh --list                 list available clients and exit
#   ./ssh-check.sh --help

set -u

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
DIM='\033[2m'
NC='\033[0m'

CONF_DIR="$HOME/.ssh/config.d"
PORT=22
CLIENT=""
TYPE=""

usage() { awk 'NR>1 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"; exit "${1:-0}"; }

list_clients() {
    echo "Available clients in $CONF_DIR:"
    if compgen -G "$CONF_DIR/*.conf" >/dev/null; then
        for f in "$CONF_DIR"/*.conf; do
            n=$(grep -c '^Host ' "$f")
            printf "  %-10s (%s devices)\n" "$(basename "${f%.conf}")" "$n"
        done
    else
        echo "  (none found)"
    fi
}

# ---- parse arguments ----------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage 0 ;;
        --list)    list_clients; exit 0 ;;
        --type)    TYPE="${2:-}"; shift 2 || { echo "--type needs a value"; exit 1; } ;;
        --port)    PORT="${2:-}"; shift 2 || { echo "--port needs a value"; exit 1; } ;;
        -*)        echo "Unknown option: $1"; usage 1 ;;
        *)         CLIENT="$1"; shift ;;
    esac
done

# ---- work out which config files to scan --------------------------------
if [[ -n "$CLIENT" ]]; then
    FILES=("$CONF_DIR/$CLIENT.conf")
    if [[ ! -f "${FILES[0]}" ]]; then
        echo -e "${RED}No config file for client '$CLIENT'${NC} (looked for ${FILES[0]})"
        echo
        list_clients
        exit 1
    fi
else
    if ! compgen -G "$CONF_DIR/*.conf" >/dev/null; then
        echo -e "${RED}No client configs found in $CONF_DIR${NC}"
        exit 1
    fi
    FILES=("$CONF_DIR"/*.conf)
fi

# ---- port test helper (nc if present, else bash /dev/tcp) ---------------
port_open() {
    local ip="$1" port="$2"
    if command -v nc >/dev/null 2>&1; then
        nc -z -w3 "$ip" "$port" >/dev/null 2>&1
    else
        timeout 3 bash -c "exec 3<>/dev/tcp/$ip/$port" 2>/dev/null
    fi
}

# ---- extract "alias<TAB>hostname<TAB>type" from a config file -----------
# Relies on the generated order: tag comment -> Host -> HostName.
extract_hosts() {
    awk -v want="$(printf '%s' "$TYPE" | tr '[:upper:]' '[:lower:]')" '
        /^# / { for (i=1;i<=NF;i++) if ($i ~ /^type=/) t=substr($i,6); next }
        $1=="Host"     { a=$2; next }
        $1=="HostName" { h=$2;
                         if (want=="" || tolower(t)==want) print a"\t"h"\t"t;
                         a=""; h=""; t=""; next }
    ' "$1"
}

# ---- header -------------------------------------------------------------
echo -e "${BLUE}"
echo "==============================================================="
printf " SSH Port %s Connectivity Test" "$PORT"
[[ -n "$CLIENT" ]] && printf "  |  client: %s" "$CLIENT"
[[ -n "$TYPE"   ]] && printf "  |  type: %s"   "$TYPE"
echo; echo "==============================================================="
echo -e "${NC}"

PASS=0
FAIL=0
TOTAL=0

for f in "${FILES[@]}"; do
    client_name=$(basename "${f%.conf}")
    [[ ${#FILES[@]} -gt 1 ]] && echo -e "${DIM}# $client_name${NC}"

    while IFS=$'\t' read -r HOST IP DTYPE; do
        [[ -z "$HOST" ]] && continue
        TOTAL=$((TOTAL+1))

        printf "%-32s %-16s %-9s " "$HOST" "$IP" "$DTYPE"

        if port_open "$IP" "$PORT"; then
            echo -e "${GREEN}UP${NC}"
            PASS=$((PASS+1))
        else
            echo -e "${RED}DOWN${NC}"
            FAIL=$((FAIL+1))
        fi
    done < <(extract_hosts "$f")
done

# ---- summary ------------------------------------------------------------
echo
echo -e "${BLUE}---------------------------------------------------------------${NC}"
printf "Tested %d   ${GREEN}UP %d${NC}   ${RED}DOWN %d${NC}\n" "$TOTAL" "$PASS" "$FAIL"
