# VISION.md

> **What this is:** roadmap, direction, and known limitations for `wifi-fallback`.
> **See also:** [README.md](README.md) (entry point), [ARCHITECTURE.md](ARCHITECTURE.md) (current design).

## Direction

`wifi-fallback` should make a factory-fresh or relocated reader join Wi-Fi with zero technical skill in the field: either "join the reader's hotspot and fill a form" or "plug in the stick the office prepared". The package stays small, shell-first, NetworkManager-only, and shippable as a single deb through the reader-status-app OTA channel.

## Roadmap

### Near term

1. **Password protection hardening for the admin portal** — carried over from the pre-0.6 notes: proper credential storage for the admin page (persisted, changeable password instead of the built-in default).
2. **Field validation of the USB flow (0.6.2)** — run the manual test matrix (OK / bad password / plain stick / yank mid-run) on real readers before promoting to the prod OTA channel.

### Later

3. **Multiple networks per `wifi.conf`** — numbered suffixes (`SSID_2=`, `PASSWORD_2=`) so one stick carries site-wide credentials; try in order until one connects.
4. **Optional label-gated USB posture** — a stricter mode where only sticks labeled `BLEEDIO*` (matched via `ENV{ID_FS_LABEL}` in the udev rule, no mount needed) trigger provisioning at all, for deployments where the reader must never touch foreign sticks. Ship as an alternative rule file or a build flag; keep probe-every-stick as the default because an unlabeled stick failing silently is the worse field experience.
5. **Richer write-back diagnostics** — optionally append the last N NetworkManager journal lines to the stick on failure, for deeper remote debugging.
6. **Portal/USB status convergence** — surface "last USB provisioning attempt" on the portal status page so both flows report in one place.

## Known limitations

- **Manual install path has no dependency check** — `preflight.sh` (used by `start.sh`) installs only python3-flask/waitress and never installs or checks for `network-manager`, `iproute2`, or `iw`; it also never installs the USB provisioning files at all, so the manual path is portal-only today. The deb path (which does install USB provisioning) declares all of these in `Depends:`.
- **Portal and `add_wifi.sh` have drifted** — `webserver.py`'s `/wifi` route runs its own inline nmcli calls instead of calling `add_wifi.sh`, and unconditionally restarts NetworkManager (dropping the operator's own session) where `add_wifi.sh` now checks first. Should be unified so there is one nmcli implementation.
- **Duplicated webserver supervision** — both `ap_mode.sh` and `watch_ip.sh` restart `webserver.py` on IP change with overlapping `pkill -f webserver.py` logic; racy if both run. Should be consolidated into one supervisor.
- **Portal credentials** — the admin page password handling predates the hardening item above; treat the portal as local-network-trust-only until item 1 lands.
- **Plaintext credentials on the stick** — `wifi.conf` is intentionally left in place for provision-many workflows; the stick is the operator's responsibility. A `wifi.conf.done` rename mode could be added if a customer requires it.
- **No automated tests** — everything is manual-on-Pi; at minimum the `wifi.conf` parser in `usb_wifi.sh` could get a host-side bats/bash test.
- **Hotspot password is a fixed default** (`bleedio12`) baked into `ap_mode.sh`.
