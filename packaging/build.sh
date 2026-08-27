#!/usr/bin/env bash
set -euo pipefail

# ---- config you can tweak ----
PKG=wifi-fallback
VERSION="${VERSION:-0.6.1}"                   # or inject via: VERSION=0.6.2 packaging/build.sh
# arm64 / armhf / amd64, etc. Defaults to the build host, but the package is
# pure shell/Python with no compiled code, so it can be cross-built for a
# reader from any host: ARCH=arm64 packaging/build.sh
ARCH="${ARCH:-$(dpkg --print-architecture)}"
STAGE="packaging/deb/${PKG}_${VERSION}_${ARCH}"

# clean
rm -rf "$STAGE"
mkdir -p "$STAGE/DEBIAN"
mkdir -p "$STAGE/opt/wifi-fallback"
mkdir -p "$STAGE/etc/systemd/system"
mkdir -p "$STAGE/etc/udev/rules.d"
mkdir -p "$STAGE/usr/bin"

# app files (copy your tree exactly)
cp -a ap_mode.sh webserver.py preflight.sh start.sh watch_ip.sh install.sh "$STAGE/opt/wifi-fallback/"
cp -a add_wifi.sh "$STAGE/usr/bin/add_wifi.sh"
cp -a static "$STAGE/opt/wifi-fallback/"
cp -a templates "$STAGE/opt/wifi-fallback/"
# install the unit into the correct system path
cp -a ap_mode.service "$STAGE/etc/systemd/system/wifi-fallback.service"
# USB Wi-Fi provisioning: udev rule + templated unit + worker script
cp -a usb_wifi.sh "$STAGE/usr/bin/usb_wifi.sh"
cp -a usb-wifi@.service "$STAGE/etc/systemd/system/usb-wifi@.service"
cp -a 99-usb-wifi.rules "$STAGE/etc/udev/rules.d/99-usb-wifi.rules"

# perms
chmod 755 "$STAGE/opt/wifi-fallback"/ap_mode.sh
chmod 755 "$STAGE/opt/wifi-fallback"/webserver.py
chmod 755 "$STAGE/opt/wifi-fallback"/install.sh
# start.sh/preflight.sh are the manual (non-deb) install path; they are
# documented as `sudo ./start.sh`, so they must ship executable.
chmod 755 "$STAGE/opt/wifi-fallback"/start.sh
chmod 755 "$STAGE/opt/wifi-fallback"/preflight.sh
chmod 755 "$STAGE/usr/bin/add_wifi.sh"
chmod 755 "$STAGE/usr/bin/usb_wifi.sh"
chmod 644 "$STAGE/etc/systemd/system/usb-wifi@.service"
chmod 644 "$STAGE/etc/udev/rules.d/99-usb-wifi.rules"
find "$STAGE/opt/wifi-fallback/static" -type f -exec chmod 644 {} +
find "$STAGE/opt/wifi-fallback/templates" -type f -exec chmod 644 {} +

# control metadata
#Pre-Depends: python3, network-manager, iproute2
#Pre-Depends: python3, python3-flask, python3-waitress, network-manager, iproute2

cat > "$STAGE/DEBIAN/control" <<CTRL
Package: ${PKG}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: BleedIO Tech <connect@bleedio.com>
Depends: python3, python3-flask, python3-waitress, network-manager, iproute2, iw
Description: Wi-Fi fallback AP + web portal for headless setup
 Provides a local AP and a Flask-based portal to enter Wi‑Fi credentials, status, and uploading .deb packages.
CTRL

# --- preinst (dependency check happens BEFORE unpack) ---
cat > "$STAGE/DEBIAN/preinst" <<'PREINST'
#!/bin/sh
set -e

need() {
  PKG="$1"
  if ! dpkg-query -W -f='${Status}' "$PKG" 2>/dev/null | grep -q "install ok installed"; then
    echo "Missing required dependency: $PKG"
    return 1
  fi
  return 0
}

MISSING=0
for p in python3 python3-flask python3-waitress network-manager iproute2 iw; do
  if ! need "$p"; then
    MISSING=1
  fi
done

if [ "$MISSING" -ne 0 ]; then
  echo "Error: dependencies are not installed."
  echo "Easiest fix — use the wrapper, which installs deps then the package:"
  echo "                                sudo ./install.sh <this.deb>"
  echo "Or let apt resolve them:        sudo apt install ./<this.deb>"
  echo "Or after a failed 'dpkg -i':    sudo apt-get -f install"
  # Deliberately NOT auto-installing here: preinst runs inside dpkg, which
  # already holds the dpkg lock, so apt-get would deadlock. install.sh does
  # the apt step outside dpkg instead.
  exit 1
fi

exit 0
PREINST
chmod 755 "$STAGE/DEBIAN/preinst"

# postinst: — only service setup
cat > "$STAGE/DEBIAN/postinst" <<'POST'
#!/bin/sh
set -e
# ensure dir + sane perms
chmod 755 /opt/wifi-fallback || true
chmod 644 /etc/systemd/system/wifi-fallback.service || true

systemctl daemon-reload
systemctl enable wifi-fallback.service >/dev/null 2>&1 || true
systemctl restart wifi-fallback.service || true

# USB Wi-Fi provisioning: load the new rule for future insertions.
# Deliberately no `udevadm trigger --action=add`: replaying add events would
# re-provision from any stick still plugged in during an upgrade (restarting
# NetworkManager and dropping the admin's own SSH session mid-dpkg).
# A stick present at install time is picked up by unplugging and re-inserting.
udevadm control --reload-rules || true
exit 0
POST

chmod 755 "$STAGE/DEBIAN/postinst"

cat > "$STAGE/DEBIAN/prerm" <<'PRERM'
#!/bin/sh
set -e
systemctl stop wifi-fallback.service >/dev/null 2>&1 || true
# Stop any in-flight USB provisioning run before the worker script is removed.
# `systemctl stop` does not glob unit names itself, so enumerate active
# instances of the template explicitly.
UNITS=$(systemctl list-units --state=active --no-legend --plain 'usb-wifi@*.service' 2>/dev/null | awk '{print $1}')
if [ -n "$UNITS" ]; then
  # shellcheck disable=SC2086
  systemctl stop $UNITS >/dev/null 2>&1 || true
fi
exit 0
PRERM
chmod 755 "$STAGE/DEBIAN/prerm"

cat > "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
  systemctl disable wifi-fallback.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/wifi-fallback.service
  rm -f /etc/systemd/system/usb-wifi@.service
  rm -f /etc/udev/rules.d/99-usb-wifi.rules
  systemctl daemon-reload || true
  udevadm control --reload-rules || true
fi
exit 0
POSTRM
chmod 755 "$STAGE/DEBIAN/postrm"

# build
# --root-owner-group: record files as root:root rather than the build user,
# which may not exist on the reader.
dpkg-deb --root-owner-group --build "$STAGE"

mv "${STAGE}.deb" "packaging/${PKG}_${VERSION}_${ARCH}.deb"
echo "Built: /packaging/${PKG}_${VERSION}_${ARCH}.deb"
