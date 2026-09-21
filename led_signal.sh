#!/bin/bash
# Visual provisioning feedback on the board's activity LED.
#
#   led_signal.sh ok    -> off 10s, 5 rapid blinks, off 10s, then the LED's
#                          default trigger is restored (provisioned)
#   led_signal.sh fail  -> red/green alternating slow blink for 3 minutes,
#                          then both LEDs go back to normal (provisioning
#                          failed). The board must end up looking powered as
#                          usual — only the blink reports the failure.
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

# Green activity LED: ACT on a Pi, led0 on older kernels/boards.
LED=""
for candidate in /sys/class/leds/ACT /sys/class/leds/led0; do
    [[ -w "$candidate/brightness" ]] && { LED="$candidate"; break; }
done
[[ -n "$LED" ]] || exit 0

# Red power LED, used only to alternate against green on failure. On several
# Pi models PWR is wired to the power rail and is not software-controllable,
# so treat it as optional: with no writable red the fail pattern degrades to
# a green-only slow blink rather than not signalling at all.
RED=""
for candidate in /sys/class/leds/PWR /sys/class/leds/led1; do
    [[ -w "$candidate/brightness" ]] && { RED="$candidate"; break; }
done

FAIL_DURATION=180   # seconds of slow blinking on failure
FAIL_DELAY=0.5      # slow
OK_COUNT=5
OK_DELAY=0.1        # rapid
OK_PAUSE=10         # dark gap before and after the blinks, so the burst reads
                    # as a deliberate signal rather than ordinary disk activity

# Stop any pattern still running so the newest result is the one displayed.
# Match the exact process name and skip our own PID: a `-f` (full command
# line) match would also hit this process, and any shell whose command line
# happens to mention the script, killing the caller.
for prev in $(pgrep -x "$(basename "$0")" 2>/dev/null); do
    [[ "$prev" == "$$" ]] && continue
    kill "$prev" 2>/dev/null
    # `kill` only requests termination. Wait for the process to actually go:
    # it writes to the LED on its way out, and reading the trigger below
    # while it is still running captures the `none` it set rather than the
    # real default — which would strand the LED with nothing driving it.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        kill -0 "$prev" 2>/dev/null || break
        sleep 0.1
    done
done

# A superseded run leaves the trigger at `none` (see the trap below), so read
# the default only after that and never restore to `none` — that would leave
# the LED inert.
# Record the resting state so the LED can be put back exactly as found. Do
# not substitute a trigger of our own: on a Pi 5 both ACT and PWR sit at
# `[none]` and are driven directly by brightness, so forcing e.g. `mmc0` here
# would leave green flashing on SD-card activity — a behaviour change, not a
# restore. Whatever the board did before provisioning is what it does after.
DEFAULT_TRIGGER=$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$LED/trigger" 2>/dev/null)
DEFAULT_BRIGHTNESS=$(cat "$LED/brightness" 2>/dev/null)
[[ -n "${DEFAULT_BRIGHTNESS//[!0-9]/}" ]] || DEFAULT_BRIGHTNESS=0

# Record red's resting state so it can be put back exactly as found. Do not
# assume a trigger: on a Pi 5 PWR sits at `[none]` with brightness 0, i.e.
# driven directly and normally unlit. Forcing `default-on` here would leave a
# provisioned reader glowing red for good.
RED_DEFAULT_TRIGGER=""
RED_DEFAULT_BRIGHTNESS=0
if [[ -n "$RED" ]]; then
    RED_DEFAULT_TRIGGER=$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$RED/trigger" 2>/dev/null)
    RED_DEFAULT_BRIGHTNESS=$(cat "$RED/brightness" 2>/dev/null)
    [[ -n "${RED_DEFAULT_BRIGHTNESS//[!0-9]/}" ]] || RED_DEFAULT_BRIGHTNESS=0
fi

# Put both LEDs back exactly as they were found.
restore_led() {
    [[ -n "$DEFAULT_TRIGGER" ]] && echo "$DEFAULT_TRIGGER" > "$LED/trigger" 2>/dev/null
    # With trigger `none` the LED is driven directly, so brightness is the
    # state that matters; write it after the trigger to keep that intact.
    echo "$DEFAULT_BRIGHTNESS" > "$LED/brightness" 2>/dev/null
    # Red back exactly as found, so the board is indistinguishable from one
    # that was never provisioned — only the blink reported the failure.
    if [[ -n "$RED" ]]; then
        [[ -n "$RED_DEFAULT_TRIGGER" ]] && \
            echo "$RED_DEFAULT_TRIGGER" > "$RED/trigger" 2>/dev/null
        # With trigger `none` the LED is driven directly, so brightness is the
        # state that matters; writing it after the trigger keeps that intact.
        echo "$RED_DEFAULT_BRIGHTNESS" > "$RED/brightness" 2>/dev/null
    fi
}

# Superseded mid-pattern: leave green to the newer signal, which owns it now.
# Red must still be released here — the successor only drives green, so a red
# left mid-alternation would stay frozen under manual control.
trap '[[ -n "$RED" ]] && echo "$RED_DEFAULT_BRIGHTNESS" > "$RED/brightness" 2>/dev/null; exit 0' TERM INT

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
        echo 0 > "$LED/brightness" 2>/dev/null
        sleep "$OK_PAUSE"
        blink "$OK_COUNT" "$OK_DELAY"
        echo 0 > "$LED/brightness" 2>/dev/null
        sleep "$OK_PAUSE"
        # Hand the LED back to its normal trigger: that is the board's usual
        # powered indication. Leaving it forced on with trigger=none would
        # freeze it under manual control, and anything that later cleared
        # brightness would strand it dark with no trigger to drive it.
        restore_led
        ;;
    fail)
        # Red must be under manual control to alternate against green.
        [[ -n "$RED" ]] && echo none > "$RED/trigger" 2>/dev/null
        # Wall clock, so the pattern lasts 3 minutes regardless of write time.
        SECONDS=0
        while (( SECONDS < FAIL_DURATION )); do
            if [[ -n "$RED" ]]; then
                # Alternate: red on/green off, then green on/red off.
                echo 1 > "$RED/brightness" 2>/dev/null
                echo 0 > "$LED/brightness" 2>/dev/null
                sleep "$FAIL_DELAY"
                echo 0 > "$RED/brightness" 2>/dev/null
                echo 1 > "$LED/brightness" 2>/dev/null
                sleep "$FAIL_DELAY"
            else
                # No controllable red: green-only slow blink.
                blink 1 "$FAIL_DELAY"
            fi
        done
        echo 0 > "$LED/brightness" 2>/dev/null
        restore_led
        ;;
esac

exit 0
