# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Core Rule: Minimal Changes Only

Make the smallest safe change that solves the request.

Do not refactor, rename, reorganize, reformat, or "clean up" unrelated code unless explicitly asked.

Every changed line must be directly traceable to the requested task.

## Editing Rules

- Reuse existing variables, functions, components, hooks, file structure, and naming.
- Match the current code style, even if you would normally write it differently.
- Do not introduce new abstractions unless required.
- Do not move code between files unless required.
- Do not change public APIs, function signatures, routes, schemas, or environment variables unless required.
- Do not modify unrelated comments, whitespace, imports, or formatting.
- Remove only imports/variables/functions that become unused because of your own change.
- If you notice unrelated dead code or bugs, mention them separately instead of fixing them.

## Commands

```bash
# Syntax check the shell scripts
bash -n ap_mode.sh add_wifi.sh usb_wifi.sh preflight.sh start.sh watch_ip.sh install.sh

# Build the deb package (default version is set in packaging/build.sh)
chmod +x packaging/build.sh
VERSION=0.6.1 packaging/build.sh

# Install on a reader
sudo dpkg -i packaging/wifi-fallback_0.6.1_$(dpkg --print-architecture).deb
# if deps missing:
sudo apt -f -y install

# Manual (non-deb) install on a reader — copies unit, enables service
sudo ./start.sh

# Add/rewrite a Wi-Fi profile by hand (same entry point USB + portal use)
sudo /usr/bin/add_wifi.sh <ssid> [password]
```

There is no test suite — verification is manual on a Raspberry Pi (see Testing below).

## Architecture

### Purpose

Headless Wi-Fi provisioning for Raspberry Pi readers (BleedIO locMESH). When the reader can't join a known Wi-Fi, it raises its own hotspot with a captive web portal; alternatively, a USB stick with credentials provisions it without any UI. Ships as a deb package built by `packaging/build.sh`.

### Fallback AP + Web Portal (primary flow)

1. `wifi-fallback.service` (source file: `ap_mode.service`) runs `ap_mode.sh` at boot.
2. `ap_mode.sh` waits `WIFI_CHECK_TIMEOUT` for normal Wi-Fi; if none, starts a NetworkManager hotspot `bleedio-<hostname>` (connection name `bleedio-ap`, default password `bleedio12`) and launches `webserver.py`.
3. `webserver.py` — Flask + waitress portal at `http://10.24.0.1`: login-protected pages for status, Wi-Fi credential entry (its own inline `nmcli`/`os.system` calls — does not call `add_wifi.sh`), reboot, and deb-package upload/install. Templates in `templates/`, logo in `static/`.
4. `watch_ip.sh` restarts the webserver when the wlan0 IP changes.

### USB Wi-Fi Provisioning (secondary flow)

`99-usb-wifi.rules` (udev, USB partitions with a filesystem only) → `usb-wifi@.service` (oneshot, ordered `After=` the device, 250s timeout) → `usb_wifi.sh`:
mounts the stick read-only, exits silently if no `/wifi.conf`, otherwise parses `SSID=`/`PASSWORD=` (CRLF/BOM tolerant), calls `add_wifi.sh`, polls nmcli for a real connection + IP, then remounts rw and writes `wifi-result.log` (append) and `wifi-status.txt` (snapshot) back to the stick. `wifi.conf` is left in place so one stick provisions many readers.

### nmcli Logic: `add_wifi.sh`

`add_wifi.sh` (installed to `/usr/bin/`) deletes any existing profile with the same SSID, re-adds it (open or WPA-PSK), tears down `bleedio-ap`, and connects. `usb_wifi.sh` calls it; the portal (`webserver.py`) has its own separate inline nmcli calls (pre-existing, not unified). New nmcli logic goes in `add_wifi.sh`, not duplicated elsewhere.

### File → Install Path Map

| Repo file | Installed to |
|---|---|
| `ap_mode.sh`, `webserver.py`, `preflight.sh`, `start.sh`, `watch_ip.sh`, `install.sh`, `static/`, `templates/` | `/opt/wifi-fallback/` |
| `add_wifi.sh`, `usb_wifi.sh` | `/usr/bin/` |
| `ap_mode.service` | `/etc/systemd/system/wifi-fallback.service` (renamed at build) |
| `usb-wifi@.service` | `/etc/systemd/system/` |
| `99-usb-wifi.rules` | `/etc/udev/rules.d/` |

### Packaging

`packaging/build.sh` stages the tree under `packaging/deb/`, generates DEBIAN control/preinst/postinst/prerm/postrm inline (heredocs), and builds with `dpkg-deb`. Postinst enables/restarts the service and reloads udev rules (deliberately without replaying `add` events, which would re-provision from a stick left plugged in during an upgrade). Deps: python3, python3-flask, python3-waitress, network-manager, iproute2, iw. Old staged versions remain under `packaging/deb/` — do not edit those; they are build artifacts.

**Bump `VERSION` whenever package contents change — never rebuild a released version in place.** Readers gate installs on `dpkg --compare-versions "$REMOTE_VER" gt "$INST_VER"` (reader-status-app `public/update_test.sh`); the version string is the only identity, and nothing compares checksums. Because the test is strictly greater-than, a same-version republish is actively skipped and any reader already on the old build stays there permanently. This also means a release cannot be rolled back by re-publishing an earlier version — fix forward with a higher one. Bump even for a one-line change, and even if the previous version was only staged briefly.

When bumping, keep the version in sync across `packaging/build.sh` (the `VERSION` default), `README.md`, `VISION.md`, and this file — `grep -rn '<old-version>' --include='*.md' --include='*.sh' . | grep -v packaging/deb` finds them all. Leave historical statements alone (e.g. "`iw` is new in 0.6.0" stays as written). Then rebuild the deb and regenerate its `.sha256`.

### Target Environment Constraints

- Root filesystem may be mounted read-only — scripts `mount -o remount,rw /` before touching it (`add_wifi.sh`, `preflight.sh`).
- `/run` may be too small for systemd operations; `preflight.sh` resizes it.
- Everything runs as root on the reader; NetworkManager (`nmcli`) is the only supported network stack (no wpa_supplicant config, no dhcpcd).
- Logs go to `/tmp/wifi-fallback*.log` and the journal — `/tmp` is volatile by design.

### Testing

No automated tests. Verify on a real Raspberry Pi:
- Portal: boot without known Wi-Fi → hotspot `bleedio-<hostname>` appears → portal at `http://10.24.0.1` accepts credentials and connects.
- USB: stick with valid `wifi.conf` connects and writes `wifi-result.log` `OK` + IP; wrong password writes `FAIL` + nmcli error; stick without `wifi.conf` is untouched (journal only: "no wifi.conf, ignoring stick").
- Always `bash -n` changed shell scripts before shipping.

## Key Docs

- `README.md` — entry point, documentation map, operator tasks
- `ARCHITECTURE.md` — deep spec: both provisioning flows, install paths, packaging
- `VISION.md` — roadmap and known limitations
