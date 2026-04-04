#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: add_wifi.sh <ssid> [password]

Adds or updates a Wi-Fi connection profile on wlan0 and attempts to connect.
If no password is provided, the network is treated as open.
USAGE
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 1
fi

SSID="$1"
PASSWORD="${2:-}"
IFACE="wlan0"

# Ensure filesystem and NM are writable/ready
mount -o remount,rw / || true
systemctl restart NetworkManager || true

# Remove old profile if it exists
nmcli connection delete "$SSID" 2>/dev/null || true

# Create new profile
nmcli connection add type wifi ifname "$IFACE" con-name "$SSID" ssid "$SSID"
nmcli connection modify "$SSID" connection.autoconnect yes

if [[ -n "$PASSWORD" ]]; then
    nmcli connection modify "$SSID" 802-11-wireless.mode infrastructure wifi-sec.key-mgmt wpa-psk
    nmcli connection modify "$SSID" wifi-sec.psk "$PASSWORD"
else
    nmcli connection modify "$SSID" 802-11-wireless.mode infrastructure
    nmcli connection modify "$SSID" 802-11-wireless-security.key-mgmt ""
fi

# Switch from Hotspot to this network
nmcli connection down bleedio-ap 2>/dev/null || true
nmcli radio wifi on || true
nmcli connection up "$SSID" 2>/dev/null || true
