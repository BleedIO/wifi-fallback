#!/bin/bash
# Install wifi-fallback on a reader, pulling in missing dependencies first.
#
# The package's preinst deliberately refuses to install when a dependency is
# missing, and cannot install them itself: preinst runs inside dpkg, which
# already holds the dpkg lock, so apt-get would deadlock. This wrapper does the
# apt step first, outside dpkg, then hands the deb to dpkg.
#
# Usage: sudo ./install.sh [package.deb]
#        (with no argument, picks the newest wifi-fallback_*.deb next to this script)
set -euo pipefail

# Keep in sync with the Depends: line in packaging/build.sh
DEPS="python3 python3-flask python3-waitress network-manager iproute2 iw"

if [[ $EUID -ne 0 ]]; then
    echo "Must run as root: sudo $0 $*" >&2
    exit 1
fi

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ $# -ge 1 ]]; then
    DEB="$1"
else
    # Newest matching deb beside this script, or under packaging/ in a checkout.
    DEB="$(ls -1t "$DIR"/wifi-fallback_*.deb "$DIR"/packaging/wifi-fallback_*.deb 2>/dev/null | head -1 || true)"
    if [[ -z "$DEB" ]]; then
        echo "No wifi-fallback_*.deb found next to $0; pass one explicitly." >&2
        exit 1
    fi
    echo "Using $DEB"
fi

if [[ ! -f "$DEB" ]]; then
    echo "No such file: $DEB" >&2
    exit 1
fi

# Only touch apt if something is actually missing — keeps the common case fast
# and avoids needing the network on an already-provisioned reader.
MISSING=""
for p in $DEPS; do
    if ! dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "install ok installed"; then
        MISSING="$MISSING $p"
    fi
done

if [[ -n "$MISSING" ]]; then
    echo "Installing missing dependencies:$MISSING"
    # Root may be mounted read-only on a reader (see preflight.sh/add_wifi.sh).
    mount -o remount,rw / || true
    apt-get update
    # shellcheck disable=SC2086
    apt-get install -y $MISSING
else
    echo "All dependencies already present."
fi

echo "Installing $DEB"
dpkg -i "$DEB"
