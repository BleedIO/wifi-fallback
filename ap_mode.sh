#!/bin/bash

# ap_mode.sh

# Config
WIFI_CHECK_TIMEOUT=20
AP_SSID="bleedio-$(hostname)"
AP_PASS="bleedio12"
AP_IFACE="wlan0"
WEB_CMD="sudo /usr/bin/python3 /opt/wifi-fallback/webserver.py"
IP_CACHE_FILE="/tmp/wifi-fallback.lastip"
LOGFILE="/tmp/wifi-fallback.log"
LOGWEB="/tmp/wifi-fallback-web.log"
TIMER="/tmp/wifi-fallback-hotspot-since"

mkdir -p /run/wifi-fallback

log() {
    echo "$(date '+%F %T') | $1" | tee -a "$LOGFILE"
}

get_ip() {
    ip -4 addr show "$AP_IFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "none"
}

is_webserver_running() {
    pgrep -f webserver.py > /dev/null
}

start_webserver() {
    log "🚀 Starting webserver..."
    echo "[$(date)] Attempting: $WEB_CMD" >> "$LOGWEB"
    nohup $WEB_CMD >> "$LOGWEB" 2>&1 &
    disown
    sleep 1
    pgrep -af webserver.py >> "$LOGWEB"
}

restart_webserver() {
    pkill -f webserver.py && log "🔁 Restarted webserver due to IP change."
    start_webserver
}

# Function: check Wi-Fi
# check_wifi() {
#     #log "⏳ Checking WiFi..."

#     for i in $(seq 1 "$WIFI_CHECK_TIMEOUT"); do
#         WIFI_STATE=$(nmcli -t -f DEVICE,TYPE,STATE dev | grep "^$AP_IFACE:" | cut -d: -f3)

#         if [[ "$WIFI_STATE" == "connected" ]]; then
#             #log "✅ WiFi ($AP_IFACE) is connected."
#             return 0
#         fi

#         sleep 5
#     done

#     log "⏳ Checking WiFi..."
#     log "❌ No WiFi connection detected on $AP_IFACE."
#     return 1
# }
check_wifi() {
    for i in $(seq 1 "$WIFI_CHECK_TIMEOUT"); do
        WIFI_STATE=$(nmcli -t -f DEVICE,TYPE,STATE dev | grep "^$AP_IFACE:" | cut -d: -f3)

        if [[ "$WIFI_STATE" == "connected" ]]; then
            return 0
        fi

        log "⏳ Checking WiFi... Attempt $i/$WIFI_CHECK_TIMEOUT"
        log "WIFI_STATE: $WIFI_STATE"

        #if profile not existing, create and start hotspot
        if ! nmcli connection show | grep -q "^bleedio-ap"; then
            log "📡 bleedio-ap profile not found — creating it"
            start_ap
        else
            log "📡 bleedio-ap profile exists — checking status"
        fi

        WIFI_STATE=$(nmcli -t -f DEVICE,TYPE,STATE dev | grep "^$AP_IFACE:" | cut -d: -f3)

        # If disconnected, try to re-activate the hotspot profile right away
        if [[ "$WIFI_STATE" == "disconnected" ]]; then
            log "📡 $AP_IFACE is disconnected — bringing up bleedio-ap"
            nmcli connection up bleedio-ap 2>>$LOGFILE || true
        fi

        sleep 5
    done

    log "⏳ Checking WiFi..."
    log "❌ No WiFi connection detected on $AP_IFACE."
    return 1
}


# Function: bring up AP
start_ap() {
    log "📡 Starting AP Mode: $AP_SSID"

    sudo mount -o remount,rw /
    sudo mount -o remount,size=64M /run
    sudo systemctl restart NetworkManager 2>>$LOGFILE

    # Create the drop-in and point lease file to /tmp
    sudo install -d -m 755 /etc/NetworkManager/dnsmasq-shared.d
    echo 'dhcp-leasefile=/tmp/nm-dnsmasq-wlan0.leases' | \
    sudo tee /etc/NetworkManager/dnsmasq-shared.d/10-leasefile.conf    

    nmcli device set "$AP_IFACE" managed yes 2>>$LOGFILE
    nmcli radio wifi on 2>>$LOGFILE
    #nmcli dev wifi ifname "$AP_IFACE" con-name bleedio-ap ssid "$AP_SSID"  2>>$LOGFILE
    nmcli connection add type wifi ifname "$AP_IFACE" con-name bleedio-ap ssid "$AP_SSID" 2>>$LOGFILE
    nmcli connection modify bleedio-ap \
        802-11-wireless.mode ap \
        802-11-wireless.band bg \
        ipv4.method shared \
        ipv6.method ignore \
        802-11-wireless-security.key-mgmt wpa-psk \
        802-11-wireless-security.proto rsn \
        802-11-wireless-security.group ccmp \
        802-11-wireless-security.pairwise ccmp \
        802-11-wireless-security.psk "bleedio12" 2>>$LOGFILE
    nmcli connection up bleedio-ap 2>>$LOGFILE

    sleep 2
}

# Main loop
while true; do
    
    check_wifi
    if [[ $? -ne 0 ]]; then
        start_ap 
        log "🔄 AP Mode started: $AP_SSID"
    fi

    CURRENT_IP=$(get_ip)

    if [[ ! -f "$IP_CACHE_FILE" ]] || [[ "$CURRENT_IP" != "$(cat "$IP_CACHE_FILE")" ]]; then
        echo "$CURRENT_IP" > "$IP_CACHE_FILE"
        log "🌐 IP change detected: $CURRENT_IP"
        restart_webserver
    else
        if is_webserver_running; then
            log "✅ IP unchanged and webserver already running."
        else
            log "📭 IP unchanged but webserver was not running. Starting it."
            start_webserver
        fi
    fi

    # Check if we’re currently running as fallback Hotspot
    CURRENT_CON=$(nmcli -t -f NAME,DEVICE connection show --active | grep "$AP_IFACE" | cut -d: -f1)

    if [[ "$CURRENT_CON" == "bleedio-ap" ]]; then
        HOTSPOT_TIMER_FILE="$TIMER"

        if [[ ! -f "$HOTSPOT_TIMER_FILE" ]]; then
            date +%s > "$HOTSPOT_TIMER_FILE"
            log "🕐 Hotspot active — timer started"
        else
            NOW=$(date +%s)
            STARTED=$(cat "$HOTSPOT_TIMER_FILE")
            DIFF=$((NOW - STARTED))

            if (( DIFF > 100 )); then  # 600 seconds = 10 minutes
                log "🕑 Hotspot has been running for 10 minutes. Trying to reconnect to normal Wi-Fi."

                # Stop the AP
                nmcli connection down bleedio-ap
                rm -f "$HOTSPOT_TIMER_FILE"

                # Trigger a scan and let system reconnect
                nmcli radio wifi off
                sleep 2
                nmcli radio wifi on
                sleep 2
                nmcli device wifi rescan

                # Optional: force connect if known SSID exists
                # nmcli device wifi connect "YourSSID" password "yourpassword"
            fi
        fi
    else
        rm -f /tmp/wifi-fallback-hotspot-since
    fi

    sleep 60  # Check every 30 seconds
done