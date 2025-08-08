#!/bin/bash

# Config
WIFI_CHECK_TIMEOUT=20
AP_SSID="bleedio-"$(hostname)
AP_PASS="bleedio12"
AP_IFACE="wlan0"

# Function: check Wi-Fi
check_wifi() {
    echo "⏳ Checking WiFi..."
    for i in $(seq 1 $WIFI_CHECK_TIMEOUT); do
        if nmcli -t -f WIFI g | grep -q "enabled" && nmcli -t -f STATE g | grep -q "connected"; then
            echo "✅ Connected to WiFi."
            exit 0
        fi
        sleep 1
    done
    echo "❌ No WiFi connection detected."
}

# Function: bring up AP
start_ap() {
    echo "📡 Starting AP Mode: $AP_SSID"

    nmcli device set $AP_IFACE managed yes
    nmcli radio wifi on
    nmcli dev wifi hotspot ifname $AP_IFACE ssid "$AP_SSID" password "$AP_PASS"

    echo "🌐 Hosting WiFi Config Portal..."
    python3 /opt/wifi-fallback/webserver.py
}

# Main logic
check_wifi
start_ap

