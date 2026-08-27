#!/bin/bash
# USB Wi-Fi provisioning worker, started by usb-wifi@.service for each
# inserted USB partition (see 99-usb-wifi.rules).
#
# Flow:
#   1. mount the partition read-only on a private mountpoint
#   2. no /wifi.conf at root -> unmount and exit 0 (not a provisioning stick)
#   3. parse wifi.conf (SSID=... / PASSWORD=..., CRLF+BOM tolerant)
#   4. call add_wifi.sh (single source of nmcli logic; rewrites same-SSID profile)
#   5. wait for wlan0 to actually connect + get a routable IP
#   6. remount rw, append wifi-result.log + write wifi-status.txt, sync, unmount
#
# Exit status is meaningful: 0 = provisioned (or stick ignored), 1 = provisioning
# was attempted and failed, so `systemctl status usb-wifi@sdX1` shows the truth.
set -uo pipefail

DEV="${1:?usage: usb_wifi.sh /dev/sdX1}"
IFACE="wlan0"
MNT="/run/usb-wifi/$(basename "$DEV").$$"   # unique per run: a pending lazy
                                           # detach from a yanked stick must
                                           # never block the next insertion
LOCK="/run/usb-wifi.lock"
CONNECT_WAIT=45   # seconds to wait for connection + IP
LOCK_WAIT=120     # seconds to wait for another partition's run to finish

log() { echo "usb-wifi[$DEV]: $*"; }   # goes to the journal via systemd

# Serialize: two partitions on one stick (or a fast replug) must not run two
# connect attempts concurrently. Bounded wait so a second partition reports a
# real outcome instead of being SIGKILLed by the unit's start timeout.
exec 9>"$LOCK"
if ! flock -w "$LOCK_WAIT" 9; then
    log "another partition is still provisioning, skipping"
    exit 0
fi

# Sweep mountpoints left by earlier runs that were killed mid-flight (stick
# yanked): detach anything still mounted, then drop the empty directories.
# Safe to do here because the lock guarantees no other run is in progress.
mkdir -p /run/usb-wifi
for stale in /run/usb-wifi/*; do
    [[ -d "$stale" ]] || continue
    mountpoint -q "$stale" && umount -l "$stale" 2>/dev/null
    rmdir "$stale" 2>/dev/null || true
done
mkdir -p "$MNT"

# --- 1. polite read-only probe ---------------------------------------------
if ! mount -o ro "$DEV" "$MNT" 2>/dev/null; then
    log "cannot mount, skipping"
    rmdir "$MNT" 2>/dev/null || true
    exit 0
fi

cleanup() {
    sync
    # Lazy unmount as fallback: if the stick was pulled mid-run the plain
    # umount fails and would otherwise leak the mountpoint (see above).
    umount "$MNT" 2>/dev/null || umount -l "$MNT" 2>/dev/null || true
    rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

# --- 2. not a provisioning stick? leave it completely alone -----------------
CONF="$MNT/wifi.conf"
if [[ ! -f "$CONF" ]]; then
    log "no wifi.conf, ignoring stick"
    exit 0
fi

# --- 3. parse wifi.conf -----------------------------------------------------
# Tolerate Windows editing: strip a UTF-8 BOM, CR line endings, and leading
# whitespace. Only SSID= and PASSWORD= are recognized; PASSWORD is optional
# (open network). Values may contain spaces; a matched pair of surrounding
# double quotes is stripped.
SSID=""
PASSWORD=""
HAS_PASSWORD_LINE=0   # distinguishes "open network" from "empty PASSWORD="
unquote() {
    local v="$1"
    # Strip only a genuine matched pair of surrounding double quotes.
    if [[ ${#v} -ge 2 && "${v:0:1}" == '"' && "${v: -1}" == '"' ]]; then
        v="${v:1:${#v}-2}"
    fi
    printf '%s' "$v"
}
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#$'\xef\xbb\xbf'}"
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    case "$line" in
        SSID=*)     SSID="$(unquote "${line#SSID=}")" ;;
        PASSWORD=*) PASSWORD="$(unquote "${line#PASSWORD=}")"; HAS_PASSWORD_LINE=1 ;;
    esac
done < "$CONF"

# Result writing needs rw; define it before the first failure path uses it.
# Logs its own failure to the journal (e.g. write-protected stick) so that is
# visible even though callers only use its return value to avoid tripping
# `set -e` (`|| true`) — the write itself is the last thing we do either way.
write_results() {
    # $1 = OK|FAIL, $2 = detail text
    if ! mount -o remount,rw "$MNT" 2>/dev/null; then
        log "cannot remount rw — results not written to stick (write-protected?)"
        return 1
    fi
    local rc=0
    echo "$(date -Is) host=$(hostname) ssid='${SSID:-?}' result=$1 $2" \
        >> "$MNT/wifi-result.log" || rc=1
    # Field-diagnostics snapshot (overwritten each run)
    {
        echo "=== $(hostname) @ $(date -Is) ==="
        nmcli device status 2>&1
        echo "--- active connection ---"
        nmcli -f GENERAL.CONNECTION,GENERAL.STATE,IP4.ADDRESS device show "$IFACE" 2>&1
        echo "--- signal ---"
        nmcli -f IN-USE,SSID,SIGNAL device wifi list ifname "$IFACE" 2>&1 | head -15
    } > "$MNT/wifi-status.txt" || rc=1
    sync
    # Back to read-only immediately: the stick must not be left dirty if the
    # operator pulls it in the window before the cleanup trap runs.
    mount -o remount,ro "$MNT" 2>/dev/null || true
    if [[ $rc -ne 0 ]]; then
        log "failed to write results to stick (full or faulty filesystem?)"
    fi
    return $rc
}

if [[ -z "$SSID" ]]; then
    log "wifi.conf present but no SSID= line"
    write_results FAIL "error='wifi.conf has no SSID= line'" || true
    exit 1
fi
if [[ $HAS_PASSWORD_LINE == 1 && -z "$PASSWORD" ]]; then
    # A `PASSWORD=` line with nothing (or "") after it is almost certainly a
    # mistake, not a request for an open network — refuse rather than
    # silently create an unsecured profile.
    log "wifi.conf has an empty PASSWORD= line; refusing (omit the line entirely for an open network)"
    write_results FAIL "error='PASSWORD= present but empty; omit the line for an open network'" || true
    exit 1
fi

# --- 4. provision via the existing nmcli wrapper ----------------------------
log "provisioning SSID '$SSID'"
if [[ -n "$PASSWORD" ]]; then
    # Password on stdin, not argv: it must not be visible in `ps` on the reader.
    ERR=$(printf '%s\n' "$PASSWORD" \
          | WIFI_PASSWORD_STDIN=1 /usr/bin/add_wifi.sh "$SSID" 2>&1)
    ADD_RC=$?
else
    ERR=$(/usr/bin/add_wifi.sh "$SSID" 2>&1)
    ADD_RC=$?
fi

# add_wifi.sh exits 1 only when it could not even create the profile (the old
# profile, if any, is already gone at that point) — a distinct, immediate
# failure that must not be reported as a 45s connection timeout.
if [[ $ADD_RC -ne 0 ]]; then
    log "failed to create profile for '$SSID': $(echo "$ERR" | tail -3 | tr '\n' ' ')"
    write_results FAIL "error='profile creation failed: $(echo "$ERR" | tail -3 | tr '\n' ' ')'" || true
    exit 1
fi

# --- 5. verify: associated with *this* SSID, with a routable IP -------------
# `nmcli connection up` returning 0 doesn't guarantee DHCP finished, so poll.
# Compare the SSID the radio actually joined (not just the profile name), and
# reject link-local 169.254.x.x — that means DHCP failed and the reader has no
# route, which must not be reported as success.
OK=0
IP=""
FAILREASON="timed out waiting for connection"
# Bound by wall clock, not iteration count: each pass also spends time inside
# nmcli, so a counter would overrun the unit's start timeout.
DEADLINE=$((SECONDS + CONNECT_WAIT))
while (( SECONDS < DEADLINE )); do
    STATE=$(nmcli -g GENERAL.STATE device show "$IFACE" 2>/dev/null || true)
    # Ask the driver which SSID we actually joined. `nmcli -t ... device wifi
    # list` is unusable here: it escapes colons in SSIDs and can force a rescan
    # that disturbs the association we are trying to confirm.
    JOINED=$(iw dev "$IFACE" link 2>/dev/null | sed -n 's/^[[:space:]]*SSID: //p')
    if [[ "$STATE" == *"100"* && "$JOINED" == "$SSID" ]]; then
        # IP4.ADDRESS is CIDR (192.168.1.5/24); strip the prefix for the log.
        IP=$(nmcli -g IP4.ADDRESS device show "$IFACE" 2>/dev/null | head -1)
        IP="${IP%%/*}"
        if [[ -n "$IP" && "$IP" != 169.254.* ]]; then
            OK=1
            break
        fi
        [[ "$IP" == 169.254.* ]] && FAILREASON="associated but DHCP failed (link-local $IP)"
    elif [[ "$STATE" == *"disconnected"* || "$STATE" == "30" ]]; then
        # NM gave up retrying (e.g. wrong PSK rejected by the AP) and parked
        # the device — this is terminal, not "not yet associated". Stop
        # polling immediately instead of burning the rest of CONNECT_WAIT and
        # reporting a misleading timeout that sends the operator chasing
        # signal strength instead of the actual typo.
        FAILREASON="disconnected/rejected by AP (wrong password or AP unreachable) — check GENERAL.STATE=$STATE"
        break
    fi
    sleep 1
done

# --- 6. write results back to the stick -------------------------------------
if [[ "$OK" == 1 ]]; then
    log "connected to '$SSID' ip=$IP"
    write_results OK "ip=$IP" || true
    exit 0
fi

log "failed to connect to '$SSID': $FAILREASON"
write_results FAIL "error='$FAILREASON; $(echo "$ERR" | tail -3 | tr '\n' ' ')'" || true
exit 1
