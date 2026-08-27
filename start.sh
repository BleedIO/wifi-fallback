#!/bin/bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Run preflight
./preflight.sh

echo "🛠️ Installing fallback AP system..."

# Copy systemd service
cp ap_mode.service /etc/systemd/system/
chmod 644 /etc/systemd/system/ap_mode.service

# Reload systemd (now should work)
systemctl daemon-reexec
systemctl daemon-reload

# Enable service
systemctl enable ap_mode.service

echo "✅ Setup complete. Reboot to apply changes."

