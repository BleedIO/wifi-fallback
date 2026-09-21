# ARCHITECTURE.md

> **What this is:** the deep spec for `wifi-fallback` — how both provisioning flows work, what installs where, and the constraints of the target device.
> **See also:** [README.md](README.md) (entry point, operator tasks), [VISION.md](VISION.md) (roadmap), [CLAUDE.md](CLAUDE.md) (working rules).

## Purpose

Headless Wi-Fi provisioning for Raspberry Pi readers (BleedIO locMESH). Two independent flows share one nmcli entry point:

```
                    ┌──────────────────────────┐
  boot, no wifi ──▶ │ ap_mode.sh (hotspot)     │──▶ webserver.py ──┐
                    └──────────────────────────┘   (portal form)   │
                                                                   ├──▶ add_wifi.sh ──▶ nmcli / NetworkManager
                    ┌──────────────────────────┐                   │
  USB stick add ──▶ │ udev → usb-wifi@.service │──▶ usb_wifi.sh ───┘
                    └──────────────────────────┘   (wifi.conf)
```

## Flow 1: Fallback AP + Web Portal

1. **`wifi-fallback.service`** (source file in repo: `ap_mode.service`; renamed at package build) starts `ap_mode.sh` at boot (`After=network-online.target`, 10s delay, `Restart=always`).
2. **`ap_mode.sh`** waits `WIFI_CHECK_TIMEOUT` (20s) for a normal Wi-Fi connection. If none appears, it creates a NetworkManager hotspot:
   - SSID `bleedio-<hostname>`, password `bleedio12`, connection name `bleedio-ap`, interface `wlan0`, portal IP `10.24.0.1`
   - then starts `webserver.py` (nohup, background) and keeps supervising: restarts the webserver on IP change, logs to `/tmp/wifi-fallback.log` / `/tmp/wifi-fallback-web.log`.
   The hotspot is torn down again once it has sat **idle** for `HOTSPOT_IDLE_TIMEOUT` (100s), at which point the reader retries normal Wi-Fi. "Idle" means nobody is associated: while an operator is connected, `has_ap_clients` (`iw dev wlan0 station dump`) resets the timer every pass, so the AP stays up for as long as they are attached and only starts counting down after they disconnect. If `iw` is unavailable the check fails closed — it reports no clients, so the hotspot times out as it did before rather than staying up forever.
3. **`webserver.py`** — Flask app served by waitress, templates in `templates/`, logo in `static/`. Routes:
   - `/` status page (configured networks, current connection). **Public — no login.** It shows fields from `/etc/rssi-gatewayapi/config.json`, filtered through the `PUBLIC_CONFIG_KEYS` allowlist in `webserver.py`: the file also contains `IDScope`, which readers use as the shared secret for signing status reports to the reader-status-app API, and this page is reachable by anyone who joins the fallback hotspot. Add new keys to that allowlist only after confirming they carry nothing sensitive — an allowlist is used precisely so a future secret-bearing key is hidden by default. The `systemctl status rssi-gatewayapi` output shown below it is also scrubbed of `ID_SCOPE:` values, which the service prints at startup.
   - `/login`, `/logout`, `/logout_basic` — session login guarding all pages (`require_auth`)
   - `/wifi` (GET/POST) — credential form; POST runs its own inline `nmcli`/`os.system` calls in `webserver.py` (does **not** call `add_wifi.sh` — pre-existing divergence, not introduced by the USB flow; see VISION.md)
   - `/confirmation`, `/cancel` — post-submit flow
   - `/reboot` (GET/POST)
   - `/upload` (GET/POST) — upload and install a deb package on the reader
4. **`watch_ip.sh`** — standalone loop that restarts the webserver when the wlan0 IP changes (overlaps with `ap_mode.sh`'s own supervision; see VISION.md known limitations).

## Flow 2: USB Stick Provisioning

Event chain: **`99-usb-wifi.rules`** → **`usb-wifi@.service`** → **`usb_wifi.sh`**.

### udev rule (`99-usb-wifi.rules`)

Matches `ACTION=="add"` on block partitions that (a) sit on the USB bus (`SUBSYSTEMS=="usb"` — the Pi's own SD slot never triggers) and (b) carry a filesystem (`ENV{ID_FS_USAGE}=="filesystem"` — skips hubs, empty card readers, unformatted sticks). It tags the device for systemd (`TAG+="systemd"` — mandatory, without it `SYSTEMD_WANTS` is ignored) and wants `usb-wifi@%k.service`. A systemd unit is used instead of `RUN+=` because udev kills long-running children and udev-namespace mounts are invisible system-wide.

### Templated unit (`usb-wifi@.service`)

`Type=oneshot`, runs `usb_wifi.sh /dev/%i`, ordered `After=dev-%i.device`. Deliberately **not** `BindsTo=` — that would SIGTERM the worker mid-write on an early unplug, leaving a partial log and a stale mountpoint; the worker handles a vanished device itself (lazy unmount) instead. `TimeoutStartSec=200` bounds the run and exceeds the worker's own lock wait (120s) plus connect wait (45s), so the script always reaches its own error path rather than being killed. The unit's exit status is meaningful: failure to provision exits 1, so `systemctl status usb-wifi@sdX1` shows the truth.

### Worker (`usb_wifi.sh`)

1. `flock -w 120` on `/run/usb-wifi.lock` — two partitions on one stick (or a fast replug) never run concurrent connect attempts; the bounded wait means a second partition logs "another partition is still provisioning, skipping" instead of being killed by the unit timeout.
2. Clear any stale mountpoint left by a killed previous run, then mount **read-only** on `/run/usb-wifi/<dev>`. Unmountable → log to journal, exit 0.
3. No `/wifi.conf` at the root → unmount, exit 0 — a stick plugged in for any other purpose is untouched ("polite probe" posture; see VISION.md for the stricter label-gated alternative).
4. Parse `wifi.conf`: `SSID=` and optional `PASSWORD=` (open network); CRLF stripped, UTF-8 BOM stripped, surrounding quotes stripped.
5. Call `add_wifi.sh` (see below). If it exits non-zero — it could not even create the profile, meaning any previous working profile is already gone — that is reported as an immediate `FAIL` without entering the verify loop below.
6. Verify for up to 45s: `nmcli` device state must reach `100 (connected)`, the SSID the radio actually joined must match the requested one (checked via `iw dev wlan0 link`, not just the profile name), and the interface must hold a **routable** IPv4 address — a link-local `169.254.x.x` means DHCP failed and is reported as `FAIL`, not `OK`. `nmcli connection up` returning 0 does not guarantee DHCP finished. If NM instead parks the device in `disconnected` (e.g. the AP rejected the PSK), the loop stops immediately rather than waiting out the full 45s and reporting a generic timeout.
7. Remount **rw** only now, write results, `sync`, unmount:
   - `wifi-result.log` (append): `<ISO timestamp> host=<hostname> ssid='<ssid>' result=OK|FAIL ip=…|error='…'`
   - `wifi-status.txt` (overwrite): `nmcli device status`, active connection + IP, top of the visible-network scan
8. `wifi.conf` is never modified or deleted — one stick provisions many readers.

## nmcli Logic: `add_wifi.sh`

**`add_wifi.sh`** (installed to `/usr/bin/`) is the standalone entry point for creating/rewriting a connection profile by SSID:

- remounts `/` rw (read-only-rootfs tolerance) and restarts NetworkManager only if it is not already responding — an unconditional restart would drop the operator's own portal/SSH session
- reads the password from stdin when `WIFI_PASSWORD_STDIN=1` (used by `usb_wifi.sh`) so the PSK never appears in the process command line
- leaves the `nmcli connection up` error on stderr so callers can report why a connect failed
- deletes any existing profile with the same SSID, then re-adds it (rewrite semantics)
- open network (no password) or WPA-PSK
- sets autoconnect with `connection.autoconnect-priority` 10 (override with the `AUTOCONNECT_PRIORITY` env var), tears down `bleedio-ap`, brings the new connection up

**Autoconnect priority.** Profiles NetworkManager creates by default sit at priority `0`, and NM breaks ties by preferring the most recently active connection — so a reader that can still see an older network might autoconnect back to it instead of the one just provisioned. Newly provisioned networks are therefore set to `10`, above any pre-existing profile. The hotspot (`bleedio-ap`) is pinned at `-10` with `autoconnect no`, so it never competes with real connectivity and comes up only when `ap_mode.sh` explicitly raises it. The portal sets the same `10` inline.

`usb_wifi.sh` calls it. **The portal does not** — `webserver.py`'s `/wifi` route runs its own inline `nmcli` calls via `os.system` (pre-existing, not changed by the USB feature). The two implementations have drifted: the portal's copy restarts NetworkManager unconditionally. New nmcli logic should go in `add_wifi.sh`, not be duplicated further; unifying the portal onto `add_wifi.sh` is tracked in VISION.md.

## LED Provisioning Feedback

`led_signal.sh` (installed to `/usr/bin/`) gives an operator with no screen a visual provisioning outcome on the board's activity LED (`/sys/class/leds/ACT`, falling back to `led0`):

- `led_signal.sh start` — **2 rapid red+green blinks together, then slow green blinking** for as long as the attempt runs. It has no fixed length: the `ok`/`fail` signal supersedes the process and takes over the LED, so the slow blink is a live "working on it" indicator rather than a timed pattern. `WORK_MAX` (300s) only stops a runaway if no outcome ever arrives.
- `led_signal.sh ok` — **green lit for 10s, 5 rapid blinks, dark for 10s, then green stays lit**. ACT rests dark on a Pi 5, so the hold is lit rather than dark — there would otherwise be nothing to see turn off. Green is deliberately left on afterwards as a "provisioned" state visible at a glance until the next reboot.
- `led_signal.sh fail` — **red+green driven together, slow blink (0.5s) for 3 minutes**, then both LEDs back as found. On a Pi 5 this is *seen* as alternating red/green rather than as one rose flash — see "Why the failure signal looks alternating" below; the behaviour is accepted, not a bug. Either way it is unmistakable against the green-only success pattern. The red PWR LED is optional — with no writable red the pattern degrades to a green-only slow blink.

### Why the failure signal looks alternating

The `fail` pattern drives red and green **in the same direction** — both on, then both off — yet on a Pi 5 it is observed as *alternating* red/green rather than as a single rose/amber flash. This is expected, and the code should not be changed to chase it.

What was measured on a reader (`srv-mesh4`, Pi 5 Model B Rev 1.0):

- The two sysfs writes are **under 1ms apart** (`ACT` then `PWR`, ~800µs and ~650µs respectively) — far below the ~50ms the eye needs to resolve two events as sequential. The pattern is not alternating in software.
- Sampling `brightness` at 0.05s shows only `GR` (both lit) and `--` (both dark). No frame ever shows one LED lit alone.
- Held statically, both LEDs report lit simultaneously (`ACT=255 PWR=255`), so this is not a case of one write cancelling the other.

The cause is physical, not logical. `ACT` and `PWR` are separate single-colour GPIO LEDs (`max_brightness=1`, no PWM) sitting side by side on the board rather than a single RGB package. Two adjacent point sources do not blend into one colour the way an RGB emitter does; depending on viewing angle and distance, the eye picks out whichever is brighter at each flash and reads the pair as alternation.

An earlier version alternated the LEDs explicitly (red on/green off, then green on/red off). It looked **the same** to the observer. Driving them together was kept because it is simpler and its intent is unambiguous in the code. The practical consequence is what matters and it holds either way: the failure signal is visually distinct from the green-only success pattern, which is the point.

Both patterns end by putting each LED back exactly as it was found — trigger and brightness are both recorded up front and rewritten afterwards. Nothing is substituted: on a Pi 5 both `ACT` and `PWR` sit at `[none]` and are driven directly by brightness (ACT lit, PWR dark), so forcing a trigger such as `mmc0` would leave green flashing on SD-card activity — a behaviour change, not a restore. Only the blink reports the outcome; nothing is left lit or dark afterwards to be misread later.

Both patterns fork into the background, so callers return their real status immediately — a blocking 3-minute blink would outrun `usb-wifi@.service`'s 250s start timeout and be SIGKILLed mid-pattern, leaving the LED stuck. On a board with no writable LED the script exits 0 silently: this is cosmetic feedback and must never fail a provisioning run.

Both flows signal. `usb_wifi.sh` calls it on every terminal outcome (parse error, profile-creation failure, connect failure, success). The portal's `/wifi` route calls it after `nmcli connection up`, gated on a new `wlan_connected_to()` helper that polls `iw dev wlan0 link` plus a non-link-local IP for up to 20s — `nmcli connection up` returns before DHCP finishes, so without that check every submission would blink success. This matters most in the portal, where the operator is dropped off the hotspot the moment the reader switches networks and never sees the confirmation page.

## File → Install Path Map

| Repo file | Installed to |
|---|---|
| `ap_mode.sh`, `webserver.py`, `preflight.sh`, `start.sh`, `watch_ip.sh`, `install.sh`, `static/`, `templates/` | `/opt/wifi-fallback/` |
| `add_wifi.sh`, `usb_wifi.sh`, `led_signal.sh` | `/usr/bin/` |
| `ap_mode.service` | `/etc/systemd/system/wifi-fallback.service` (renamed at build) |
| `usb-wifi@.service` | `/etc/systemd/system/` |
| `99-usb-wifi.rules` | `/etc/udev/rules.d/` |

## Packaging

`packaging/build.sh` stages the tree under `packaging/deb/<pkg>_<version>_<arch>/`, generates the DEBIAN maintainer scripts inline (heredocs), and builds with `dpkg-deb`:

- **preinst** — verifies deps are installed before unpack (python3, python3-flask, python3-waitress, network-manager, iproute2, iw — `iw` is required by `usb_wifi.sh`'s connection-verification step); fails with install guidance otherwise. It deliberately does **not** install them itself: `preinst` runs inside dpkg, which already holds the dpkg lock that `apt-get` would need, so an auto-install there deadlocks. `install.sh` does the apt step outside dpkg instead.
- **postinst** — `daemon-reload`, enable + restart `wifi-fallback.service`, then `udevadm control --reload-rules`. Deliberately no `udevadm trigger --action=add`: replaying add events would re-provision from any stick still plugged in during an upgrade, restarting NetworkManager and dropping the admin's SSH session mid-`dpkg`. A stick present at install time is picked up by re-inserting it.
- **prerm** — stops `wifi-fallback.service` and any in-flight `usb-wifi@*.service`.
- **postrm** (purge) — removes both units and the udev rule, `daemon-reload`, reloads udev rules.

Default version lives in `build.sh` (`VERSION=` env overrides). Old staged trees under `packaging/deb/` are build artifacts — never edit them.

## Target Environment Constraints

- **Read-only rootfs** is possible — anything touching `/` remounts rw first (`add_wifi.sh`, `preflight.sh`).
- **Small `/run`** — `preflight.sh` resizes to 64M if `/run/systemd` has < 16M free.
- **Root, NetworkManager only** — everything runs as root; `nmcli` is the only supported network stack (no wpa_supplicant config files, no dhcpcd).
- **Volatile logs** — `/tmp/wifi-fallback*.log` disappear on reboot by design; durable trail is the journal and (for USB) the stick itself.

## Testing

No automated tests. Manual verification on a real Raspberry Pi:

- **Portal:** boot without known Wi-Fi → hotspot `bleedio-<hostname>` appears → `http://10.24.0.1` accepts credentials → reader connects and drops the hotspot.
- **USB, happy path:** stick with valid `wifi.conf` → `wifi-result.log` gains an `OK` line with an IP.
- **USB, bad password:** `FAIL` line with the reason and the nmcli error text.
- **USB, DHCP down:** `FAIL` line saying "associated but DHCP failed (link-local …)" — must not report `OK`.
- **USB, unit status:** `systemctl status usb-wifi@sdX1` shows failed (exit 1) for a failed provisioning, success for a connected one or an ignored stick.
- **USB, plain stick:** nothing written to the stick; journal shows only "no wifi.conf, ignoring stick".
- Always `bash -n` changed shell scripts before shipping.
