#!/bin/bash
# Visual provisioning feedback on the board's activity LED.
#
#   led_signal.sh ok    -> ~10 rapid blinks, then steady on (provisioned)
#   led_signal.sh fail  -> slow blink for 3 minutes, then the LED's default
#                          trigger is restored (provisioning failed)
#
# Runs detached (setsid) so callers return their real status immediately: a
# 3 minute blocking blink would outrun usb-wifi@.service's 250s start timeout.
# It must be a new session rather than just `&`, and that unit sets
# KillMode=process: a oneshot otherwise SIGKILLs every remaining process in
# its cgroup as soon as ExecStart exits.
#
# Exits 0 on a board with no usable LED: this is cosmetic feedback and must
# never fail a provisioning run.
set -uo pipefail

MODE="${1:-}"
# Validate before detaching — past the re-exec the caller only sees exit 0.
case "$MODE" in
    ok|fail) ;;
    *) echo "Usage: led_signal.sh ok|fail" >&2; exit 1 ;;
esac

if [[ "${LED_SIGNAL_DETACHED:-0}" != "1" ]] && command -v setsid >/dev/null 2>&1; then
    # No trailing `&`: setsid already forks and returns immediately.
    LED_SIGNAL_DETACHED=1 setsid "$0" "$MODE" </dev/null >/dev/null 2>&1
    exit 0
fi

# ACT on a Pi; led0 on older kernels/boards. First one that exists wins.
LED=""
for candidate in /sys/class/leds/ACT /sys/class/leds/led0; do
    [[ -w "$candidate/brightness" ]] && { LED="$candidate"; break; }
done
[[ -n "$LED" ]] || exit 0

FAIL_DURATION=180   # seconds of slow blinking on failure
FAIL_DELAY=0.5      # slow
OK_COUNT=10
OK_DELAY=0.1        # rapid

# Stop any pattern still running so the newest result is the one displayed.
# Match the exact process name and skip our own PID: a `-f` (full command
# line) match would also hit this process, and any shell whose command line
# happens to mention the script, killing the caller.
for prev in $(pgrep -x "$(basename "$0")" 2>/dev/null); do
    [[ "$prev" == "$$" ]] || kill "$prev" 2>/dev/null
done

# A superseded run leaves the trigger at `none` (see the trap below), so read
# the default only after that and never restore to `none` — that would leave
# the LED inert. mmc0 is the Pi's stock activity trigger.
DEFAULT_TRIGGER=$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$LED/trigger" 2>/dev/null)
[[ -n "$DEFAULT_TRIGGER" && "$DEFAULT_TRIGGER" != "none" ]] || DEFAULT_TRIGGER=mmc0

# Superseded mid-pattern: leave the LED alone, the newer signal owns it now.
trap 'exit 0' TERM INT

blink() {
    # $1 = number of on/off cycles, $2 = delay per half-cycle
    local i
    for ((i = 0; i < $1; i++)); do
        echo 1 > "$LED/brightness" 2>/dev/null || return 0
        sleep "$2"
        echo 0 > "$LED/brightness" 2>/dev/null || return 0
        sleep "$2"
    done
}

echo none > "$LED/trigger" 2>/dev/null

case "$MODE" in
    ok)
        blink "$OK_COUNT" "$OK_DELAY"
        # Steady on until the next reboot, so an operator arriving late still
        # sees the result.
        echo 1 > "$LED/brightness" 2>/dev/null
        ;;
    fail)
        # Wall clock, so the pattern lasts 3 minutes regardless of write time.
        SECONDS=0
        while (( SECONDS < FAIL_DURATION )); do
            blink 1 "$FAIL_DELAY"
        done
        echo 0 > "$LED/brightness" 2>/dev/null
        echo "$DEFAULT_TRIGGER" > "$LED/trigger" 2>/dev/null
        ;;
esac

exit 0
