#!/bin/bash
set -e

echo "🔧 Preflight: Checking mounts..."

# Remount root as read-write
echo "🔧 Remounting / as read-write..."
sudo mount -o remount,rw /

# Check available space on /run/systemd
FREE_KB=$(df --output=avail /run/systemd | tail -n1)
FREE_MB=$((FREE_KB / 1024))

echo "ℹ️ /run/systemd free: ${FREE_MB}M"

if [[ $FREE_MB -lt 16 ]]; then
    echo "🚨 /run/systemd too small, remounting with larger size..."

    # Unmount and remount /run with larger size (64M)
    sudo mount -o remount,size=64m /run || {
        echo "⚠️ Failed to remount /run directly. Trying full remount..."
        sudo umount /run
        sudo mount -t tmpfs -o size=64m tmpfs /run
    }

    echo "✅ /run resized to 64M"
else
    echo "✅ /run/systemd has enough space."
fi

sudo apt update
sudo apt install python3-pip -y
sudo pip3 install flask --break-system-packages
sudo pip3 install waitress --break-system-packages



