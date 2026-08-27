# wifi-fallback

> **What this is:** the entry point and documentation map for the headless Wi-Fi provisioning package for BleedIO readers.
> **See also:** ARCHITECTURE.md (how the system works), VISION.md (roadmap), CLAUDE.md (agent/contributor working rules).
> **Audience:** anyone landing in the repo for the first time, and operators provisioning readers in the field.

`wifi-fallback` gives a headless Raspberry Pi reader two ways to get onto Wi-Fi without a keyboard or screen:

1. **Fallback AP + web portal** — when the reader can't join a known network, it raises its own hotspot (`bleedio-<hostname>`, default password `bleedio12`) with a captive web portal at `http://10.24.0.1` for entering credentials, checking status, rebooting, and uploading deb packages.
2. **USB stick provisioning** — plug in a stick with a `wifi.conf` at its root; the reader connects and writes the result back to the stick. No UI at all.

The USB flow and `add_wifi.sh` (also callable by hand) manage NetworkManager profiles via nmcli; the portal currently uses its own inline nmcli calls (see ARCHITECTURE.md). Ships as a deb package. Used for http://Bleedio.com readers for locMESH; the status page is customizable.

## Documentation map

| File | What it's for | When to read |
|---|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Deep spec: both provisioning flows, install paths, packaging, target constraints | Changing scripts, units, or packaging |
| [VISION.md](VISION.md) | Roadmap / direction and known limitations | Planning improvements |
| [CLAUDE.md](CLAUDE.md) | Agent/contributor working rules | Before making changes |

## Common operator tasks

### Provision a reader with a USB stick

1. Save a file named exactly `wifi.conf` in the **top-level folder** of a USB stick:

   ```
   SSID=MyNetwork
   PASSWORD=secret123
   ```

2. Plug the stick into the reader. Within about a minute it adds (or rewrites) the connection profile and connects.
3. Pull the stick and open the two files written back to it:
   - `wifi-result.log` — one line appended per attempt: timestamp, hostname, SSID, then `OK` with the IP address, or `FAIL` with the reason (wrong password, DHCP failure, timeout) and the nmcli error text
   - `wifi-status.txt` — a status snapshot: interfaces, active connection, nearby networks and signal

`wifi.conf` is left in place, so the same stick can provision one reader after another. Sticks without a `wifi.conf` are left completely untouched.

A newly provisioned network is given a higher autoconnect priority than any network already saved on the reader, so it wins if several are in range. Provisioning the same reader again with a different network makes that new one preferred in turn.

#### The `wifi.conf` file

Two keys, one per line. `SSID` is required; `PASSWORD` is optional.

```
SSID=MyNetwork
PASSWORD=secret123
```

Open network — **omit the `PASSWORD` line entirely** (a `PASSWORD=` line left empty is treated as a mistake and rejected, rather than silently joining an unsecured network):

```
SSID=GuestWiFi
```

Values with spaces work as-is; quotes are optional and stripped if you use a matched pair:

```
SSID=Front Office 2.4G
PASSWORD="p@ss word!"
```

Details that matter in practice:

- Everything after `=` is the value, including `#`, `=`, and spaces. There are no comments — a line starting with `#` is simply ignored, since it matches neither key.
- Leading whitespace before `SSID`/`PASSWORD` is ignored. The key names are case-sensitive and must be uppercase.
- Editing on Windows is fine: CRLF line endings and a UTF-8 BOM (which Notepad adds) are both handled, and a missing final newline is fine.
- If a key appears more than once, the last one wins.
- The SSID must match the network name exactly, including case.

#### What kind of USB stick

Any ordinary USB flash drive. Specifically:

- **Formatted FAT32 or exFAT** — the default for a store-bought stick, and readable/writable on Windows and macOS. NTFS and ext4 also work if the reader has the driver.
- **Partitioned normally** — i.e. formatted the usual way by Windows, macOS, or Disk Utility. A stick written as a raw filesystem with no partition table will not be detected.
- **Not write-protected** — the reader needs to write the two result files back. If the stick has a physical write-lock switch, turn it off; otherwise provisioning still works but you get no result files, and the journal says so.
- **`wifi.conf` at the top level**, not inside a folder.
- Size and speed are irrelevant — the file is a few bytes.

The reader mounts the stick read-only first and only remounts it writable if a `wifi.conf` is actually there, so plugging in an unrelated stick does not modify it.

### Provision a reader through the portal

1. Boot the reader out of range of any known network; the hotspot `bleedio-<hostname>` appears (password `bleedio12`).
2. Connect and open `http://10.24.0.1`, log in.
3. Enter SSID + password on the Wi-Fi page; the reader drops the hotspot and connects. The portal also offers status, reboot, and deb upload/install.

The hotspot stays up for as long as you are connected to it — the reader only gives up and retries normal Wi-Fi after the hotspot has been idle (nobody connected) for about 100 seconds. So you will not be disconnected mid-configuration, however long you take.

### Install on a reader

Current release: **`packaging/wifi-fallback_0.6.2_arm64.deb`** (checksum in `.sha256` alongside it).

Copy the deb and `install.sh` to the reader, then:

```bash
sudo ./install.sh wifi-fallback_0.6.2_arm64.deb
```

`install.sh` installs any missing apt dependencies first, then the package. It only touches apt if something is actually missing, so a routine upgrade on an already-provisioned reader needs no network.

Equivalent alternatives, if you'd rather not copy the wrapper:

```bash
sudo apt install ./wifi-fallback_0.6.2_arm64.deb   # note the ./ — apt resolves deps
sudo dpkg -i wifi-fallback_0.6.2_arm64.deb && sudo apt -f -y install
```

A bare `dpkg -i` with a dependency missing fails cleanly and prints these options. The package's `preinst` cannot install dependencies itself: it runs inside dpkg, which already holds the lock `apt-get` would need.

**Dependencies:** `python3`, `python3-flask`, `python3-waitress`, `network-manager`, `iproute2`, `iw`. All are present on stock Raspberry Pi OS. `iw` is new in 0.6.0 (used to verify which SSID the radio actually joined) — on a minimally-imaged reader, `sudo apt install iw` first. If a reader is offline *and* missing a dependency, install it while the reader still has connectivity, or carry the dep debs on the USB stick.

After install, `wifi-fallback.service` is enabled and restarted and the udev rules are reloaded. A USB stick **already plugged in** during install is not processed — postinst deliberately doesn't replay udev `add` events (that would re-provision the reader and could drop your own SSH session mid-upgrade). Unplug and re-insert to trigger it.

Verify the install:

```bash
systemctl status wifi-fallback.service
systemctl cat usb-wifi@.service >/dev/null && echo "USB unit installed"
ls /etc/udev/rules.d/99-usb-wifi.rules
```

### Build the package

```bash
# on the reader (or any arm64 host)
VERSION=0.6.2 ./packaging/build.sh

# cross-build for a reader from an amd64 machine — the package has no compiled
# code, so only the architecture label differs
ARCH=arm64 VERSION=0.6.2 ./packaging/build.sh
```

The artifact lands in `packaging/wifi-fallback_<version>_<arch>.deb`. Bump `VERSION` for a new release (the default lives at the top of `packaging/build.sh`). To publish a checksum alongside it:

```bash
cd packaging && sha256sum wifi-fallback_0.6.2_arm64.deb > wifi-fallback_0.6.2_arm64.deb.sha256
```

Staged build trees under `packaging/deb/` are intermediate artifacts — ignore them; only the `.deb` ships.

#### Always bump the version when contents change

**Never rebuild a released version in place.** If the package contents change, bump `VERSION` — even for a one-line fix, and even if the previous version was only staged for minutes.

Readers decide whether to install using `dpkg --compare-versions "$REMOTE_VER" gt "$INST_VER"` (`public/update_test.sh` in reader-status-app). The version string is the *only* identity: nothing compares checksums. So republishing changed contents under an unchanged version is not merely missed — the comparison is strictly greater-than, so it is actively skipped, and any reader that already installed the old build stays on it permanently with no indication anything is wrong. The same rule makes downgrades impossible: shipping a lower version number is refused, so a bad release is rolled back by publishing a *higher* version containing the fix, never by re-publishing the previous one.

### Manual (non-deb) install

`sudo ./start.sh` runs `preflight.sh`, copies the unit, and enables the service; reboot to apply. This is the legacy pre-deb path: it installs **only** the AP portal, not the USB provisioning feature, and does not check system dependencies. Prefer the deb.

## Script reference

| Script | Purpose |
|---|---|
| `ap_mode.sh` | Boot entry (via `wifi-fallback.service`): waits for Wi-Fi, else raises hotspot + starts the portal |
| `webserver.py` | Flask + waitress portal: login, status, Wi-Fi entry, reboot, deb upload |
| `add_wifi.sh` | Standalone nmcli helper; called by `usb_wifi.sh` (the portal has its own inline nmcli calls, see ARCHITECTURE.md) |
| `usb_wifi.sh` | USB worker: probe stick → parse `wifi.conf` → connect → write results back |
| `watch_ip.sh` | Restarts the portal when the wlan0 IP changes |
| `install.sh` | Installs missing apt dependencies, then the deb (works around preinst not being able to) |
| `preflight.sh` | Remounts `/` rw, resizes `/run` if too small, installs python deps |
| `start.sh` | Manual installer (non-deb path) |

Trigger chain for USB: `99-usb-wifi.rules` (udev) → `usb-wifi@.service` (oneshot) → `usb_wifi.sh`.
