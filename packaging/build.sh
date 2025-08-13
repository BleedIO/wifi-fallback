#!/usr/bin/env bash
set -euo pipefail

# ---- config you can tweak ----
PKG=wifi-fallback
VERSION="${VERSION:-0.4.1}"                   # or inject via: VERSION=0.4.0 packaging/build.sh
ARCH="$(dpkg --print-architecture)"           # arm64 / armhf / amd64, etc.
STAGE="packaging/deb/${PKG}_${VERSION}_${ARCH}"

# clean
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/opt/wifi-fallback"
mkdir -p "$STAGE/etc/systemd/system"

# app files (copy your tree exactly)
cp -a ap_mode.sh webserver.py preflight.sh start.sh watch_ip.sh "$STAGE/opt/wifi-fallback/"
cp -a static "$STAGE/opt/wifi-fallback/"
cp -a templates "$STAGE/opt/wifi-fallback/"
# install the unit into the correct system path
cp -a ap_mode.service "$STAGE/etc/systemd/system/ap_mode.service"

# perms
chmod 755 "$STAGE/opt/wifi-fallback"/ap_mode.sh
chmod 755 "$STAGE/opt/wifi-fallback"/webserver.py
find "$STAGE/opt/wifi-fallback/static" -type f -exec chmod 644 {} +
find "$STAGE/opt/wifi-fallback/templates" -type f -exec chmod 644 {} +

# control metadata
cat > "$STAGE/DEBIAN/control" <<CTRL
Package: ${PKG}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: BleedIO Tech <connect@bleedio.com>
Depends: python3, python3-flask, python3-waitress, network-manager, iproute2
Description: Wi-Fi fallback AP + web portal for headless setup
 Provides a local AP and a Flask-based portal to enter Wi‑Fi credentials, status, and uploading .deb packages.
CTRL

# maintainer scripts
cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e

check_dep() {
    PKG="$1"
    if ! dpkg-query -W -f='${Status}' "$PKG" 2>/dev/null | grep -q "install ok installed"; then
        echo "📦 Installing missing dependency: $PKG"
        apt-get update
        apt-get install -y "$PKG"
    fi
}

# Make sure these are installed
check_dep python3
check_dep python3-flask
check_dep python3-waitress
check_dep network-manager
check_dep iproute2


# ensure dir + sane perms
chmod 755 /opt/wifi-fallback || true
chmod 644 /etc/systemd/system/ap_mode.service || true
# pick one starter (NetworkManager needed)
systemctl daemon-reload
systemctl enable ap_mode.service >/dev/null 2>&1 || true
systemctl restart ap_mode.service || true
exit 0
POST
chmod 755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
systemctl stop ap_mode.service >/dev/null 2>&1 || true
exit 0
PRERM
chmod 755 "$STAGE/DEBIAN/prerm"

cat > "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
  systemctl disable ap_mode.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/ap_mode.service
  systemctl daemon-reload || true
fi
exit 0
POSTRM
chmod 755 "$STAGE/DEBIAN/postrm"

# build
dpkg-deb --build "$STAGE"

mv "${STAGE}.deb" "packaging/${PKG}_${VERSION}_${ARCH}.deb"
echo "Built: /packaging/${PKG}_${VERSION}_${ARCH}.deb"