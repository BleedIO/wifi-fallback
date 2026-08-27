#!/bin/bash
set -euo pipefail

usage() {
    cat <<'USAGE'
Usage: add_wifi.sh <ssid> [password]

Adds or updates a Wi-Fi connection profile on wlan0 and attempts to connect.
If no password is provided, the network is treated as open.

Set WIFI_PASSWORD_STDIN=1 to read the password from stdin instead of argv
(keeps it out of the process command line).
USAGE
}

if [[ $# -lt 1 || $# -gt 2 ]]; then
    usage
    exit 1
fi

SSID="$1"
# Password may be given positionally (portal) or, to keep it out of the process
# command line, on stdin via WIFI_PASSWORD_STDIN=1 (usb_wifi.sh).
if [[ "${WIFI_PASSWORD_STDIN:-0}" == "1" ]]; then
    IFS= read -r PASSWORD || PASSWORD=""
else
    PASSWORD="${2:-}"
fi
IFACE="wlan0"

# Ensure filesystem and NM are writable/ready. Only restart NM when it is not
# already responding — an unconditional restart drops every active connection,
# including the operator's own portal/SSH session.
mount -o remount,rw / || true
if ! nmcli general status >/dev/null 2>&1; then
    systemctl restart NetworkManager || true
fi

# Remove old profile if it exists
nmcli connection delete "$SSID" 2>/dev/null || true

# Create new profile. Guarded as one block (not `set -e` implicit exit): if
# creation fails partway through, the old profile is already gone (line 40),
# so dying silently here would strand the reader with neither the old nor the
# new network and no diagnostic. Report clearly and exit 1 instead.
if ! {
    nmcli connection add type wifi ifname "$IFACE" con-name "$SSID" ssid "$SSID" &&
    nmcli connection modify "$SSID" connection.autoconnect yes &&
    if [[ -n "$PASSWORD" ]]; then
        nmcli connection modify "$SSID" 802-11-wireless.mode infrastructure wifi-sec.key-mgmt wpa-psk &&
        nmcli connection modify "$SSID" wifi-sec.psk "$PASSWORD"
    else
        nmcli connection modify "$SSID" 802-11-wireless.mode infrastructure &&
        nmcli connection modify "$SSID" 802-11-wireless-security.key-mgmt ""
    fi
}; then
    echo "add_wifi: failed to create profile '$SSID' (previous profile, if any, was already removed)" >&2
    exit 1
fi

# Switch from Hotspot to this network
nmcli connection down bleedio-ap 2>/dev/null || true
nmcli radio wifi on || true
# Surface the connect error (to stderr) instead of discarding it: callers such
# as usb_wifi.sh report it back to the operator. Still exits 0 here — a failed
# *connect* (as opposed to a failed profile create, above) leaves a valid
# profile in place that autoconnect/a retry can still use, so callers should
# not treat it as fatal to the whole run.
nmcli connection up "$SSID" || true
