#!/bin/bash

#/opt/wifi-fallback/watch_ip.sh

WEB_CMD="sudo python3 /opt/wifi-fallback/webserver.py"
LOGFILE="/var/log/wifi-fallback-ipwatch.log"

get_ip() {
    ip -4 addr show wlan0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "none"
}

current_ip=""
while true; do
    new_ip=$(get_ip)

    if [[ "$new_ip" != "$current_ip" ]]; then
        echo "$(date): IP changed from $current_ip to $new_ip" >> "$LOGFILE"
        current_ip="$new_ip"

        # Kill old webserver if running
        pkill -f webserver.py || true
        echo "$(date): Restarting webserver..." >> "$LOGFILE"

        # Start in background
        $WEB_CMD &
    fi

    sleep 5
done
