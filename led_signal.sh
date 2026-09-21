#!/bin/bash
# Visual provisioning feedback on the board's activity LED.
#
#   led_signal.sh start -> 2 rapid red+green blinks together, then slow green
#                          blinking for as long as the attempt runs. The
#                          outcome signal supersedes it (see below), so this
#                          is a "working on it" indicator, not a fixed-length
#                          pattern: it ends when ok/fail fires.
#   led_signal.sh ok    -> fast green blinking for 10s, then both LEDs are
#                          returned to their factory behaviour. Same shape as
#                          the failure pattern at the same rapid rate as the
#                          start blinks, so the two outcomes differ by colour
#                          and duration rather than by rhythm.
#   led_signal.sh fail  -> red+green driven on together, then both off, slow
#                          blink for 3 minutes, then both LEDs go back as
#                          found.
#
#                          NOTE ON WHAT THIS LOOKS LIKE: on a Pi 5 this is
#                          observed as ALTERNATING red/green, not as a single
#                          rose/amber flash, and that is expected — see the
#                          "Why the failure signal looks alternating" section
#                          in ARCHITECTURE.md. The code drives both LEDs in
#                          the same direction; do not "fix" it by alternating
#                          them explicitly, which is what an earlier version
#                          did and produced the same visual result.
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
    start|ok|fail) ;;
    *) echo "Usage: led_signal.sh start|ok|fail" >&2; exit 1 ;;
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
OK_DURATION=10      # seconds of fast green blinking on success
OK_DELAY=0.1        # rapid — same rate as the start blinks
START_COUNT=2       # rapid red+green blinks marking the start of an attempt
START_DELAY=0.1     # rapid
WORK_DELAY=0.8      # slow green blink while the attempt is in progress
WORK_MAX=300        # safety stop: never blink forever if no outcome arrives

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
# Restoring means putting each LED back under the trigger the board ships
# with, NOT whatever it happens to be set to now: a previous run of this
# script leaves the trigger at `none`, so reading the live value and calling
# it the default is how a single interrupted run permanently strands the LED.
# The device tree is the authoritative source for the factory value
# (/proc/device-tree/leds/led-act/linux,default-trigger — `mmc0` for ACT and
# `none` for PWR on a Pi 5).
dt_trigger() {
    # $1 = device-tree node name (led-act / led-pwr)
    tr -d '\0' < "/proc/device-tree/leds/$1/linux,default-trigger" 2>/dev/null
}
DEFAULT_TRIGGER=$(dt_trigger led-act)
RED_DEFAULT_TRIGGER=$(dt_trigger led-pwr)
# Fall back to the live value only if the device tree cannot be read, and
# never adopt `none` for green — that is the state this script itself leaves
# behind, not a board default.
if [[ -z "$DEFAULT_TRIGGER" ]]; then
    DEFAULT_TRIGGER=$(sed -n 's/.*\[\(.*\)\].*/\1/p' "$LED/trigger" 2>/dev/null)
    [[ -n "$DEFAULT_TRIGGER" && "$DEFAULT_TRIGGER" != "none" ]] || DEFAULT_TRIGGER=mmc0
fi
[[ -n "$RED_DEFAULT_TRIGGER" ]] || RED_DEFAULT_TRIGGER=none

# LED polarity — MEASURED on a Pi 5, not derived from the device tree.
#
# The device tree marks BOTH led-act and led-pwr as GPIO_ACTIVE_LOW (gpios
# flag 0x01000000), but that is only true of green. Verified on the hardware:
#
#   green (ACT):  0 = lit,  1 = dark   (active low, matches the DT flag)
#   red   (PWR):  1 = lit,  0 = dark   (active HIGH, contradicts the DT flag)
#
# Trusting the flag for red inverts it and lights red whenever the code means
# to turn it off, which shows up as an unwanted rose glow. Note also that the
# sysfs readback cannot be used to check any of this: gpio_led_get() returns
# LED_FULL (255) for any non-zero line level, so brightness reads back 255
# after writing 1 whether or not the LED is physically lit.
GREEN_ON=0;  GREEN_OFF=1
RED_ON=1;    RED_OFF=0

green_on()  { echo "$GREEN_ON"  > "$LED/brightness" 2>/dev/null; }
green_off() { echo "$GREEN_OFF" > "$LED/brightness" 2>/dev/null; }
red_on()    { [[ -n "$RED" ]] && echo "$RED_ON"  > "$RED/brightness" 2>/dev/null; return 0; }
red_off()   { [[ -n "$RED" ]] && echo "$RED_OFF" > "$RED/brightness" 2>/dev/null; return 0; }

# Put both LEDs back under their factory triggers.
#
# The trigger is written LAST and nothing is written to brightness after it:
# per Documentation/ABI/testing/sysfs-class-led, writing 0 to brightness
# clears the active trigger, so a trailing brightness write silently undoes
# the restore.
restore_led() {
    # Red first, and explicitly dark: its factory trigger is `none`, which
    # does not drive the line, so simply restoring the trigger would leave red
    # lit at whatever the pattern last wrote — an unwanted rose glow.
    if [[ -n "$RED" ]]; then
        red_off
        echo "$RED_DEFAULT_TRIGGER" > "$RED/trigger" 2>/dev/null
    fi
    # Green last: a trigger takes ownership of brightness, so nothing may be
    # written to brightness after this point (the LED core reads a later 0 as
    # "clear the active trigger").
    echo "$DEFAULT_TRIGGER" > "$LED/trigger" 2>/dev/null
    return 0
}

# Superseded mid-pattern: leave green to the newer signal, which owns it now.
# Red must still be released here — the successor only drives green, so a red
# left mid-alternation would stay frozen under manual control.
trap '[[ -n "$RED" ]] && echo "$RED_DEFAULT_TRIGGER" > "$RED/trigger" 2>/dev/null; exit 0' TERM INT

blink() {
    # $1 = number of on/off cycles, $2 = delay per half-cycle
    local i
    for ((i = 0; i < $1; i++)); do
        green_on
        sleep "$2"
        green_off
        sleep "$2"
    done
}

echo none > "$LED/trigger" 2>/dev/null

case "$MODE" in
    start)
        # Both LEDs together: a brief rose flicker marking "stick seen,
        # starting". The sustained rose flash of `fail` is the same colour but
        # runs for 3 minutes, so the two cannot be confused in practice.
        [[ -n "$RED" ]] && echo none > "$RED/trigger" 2>/dev/null
        for ((i = 0; i < START_COUNT; i++)); do
            green_on; red_on
            sleep "$START_DELAY"
            green_off; red_off
            sleep "$START_DELAY"
        done
        # Red is done; green now blinks slowly to show the attempt is running.
        [[ -n "$RED" ]] && echo "$RED_DEFAULT_TRIGGER" > "$RED/trigger" 2>/dev/null
        # No fixed length: the ok/fail signal supersedes this process and takes
        # over the LED. WORK_MAX only stops a runaway if no outcome ever
        # arrives (caller killed mid-attempt), so the LED cannot blink forever.
        SECONDS=0
        while (( SECONDS < WORK_MAX )); do
            blink 1 "$WORK_DELAY"
        done
        restore_led
        ;;
    ok)
        # Wall clock, so the burst lasts its full length regardless of how
        # long each write takes.
        SECONDS=0
        while (( SECONDS < OK_DURATION )); do
            blink 1 "$OK_DELAY"
        done
        # Back to the board's factory LED behaviour, same as every other
        # pattern: the blink burst is the whole signal, and nothing is left
        # behind afterwards to be misread later.
        restore_led
        ;;
    fail)
        # Red must be under manual control to be driven alongside green.
        [[ -n "$RED" ]] && echo none > "$RED/trigger" 2>/dev/null
        # Wall clock, so the pattern lasts 3 minutes regardless of write time.
        SECONDS=0
        while (( SECONDS < FAIL_DURATION )); do
            # Both together, then both dark: a rose/amber flash that cannot be
            # confused with the green-only success pattern.
            green_on; red_on
            sleep "$FAIL_DELAY"
            green_off; red_off
            sleep "$FAIL_DELAY"
        done
        restore_led
        ;;
esac

exit 0
