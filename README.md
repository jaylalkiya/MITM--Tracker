# MITM Tracker

Detect and undo man-in-the-middle attacks on your network — a Windows defence console with a phosphor-green terminal UI.

[![Download MITM-Tracker.exe](https://img.shields.io/github/v/release/jaylalkiya/MITM--Tracker?label=Download%20.exe&style=for-the-badge)](https://github.com/jaylalkiya/MITM--Tracker/releases/latest)

![MITM Tracker console](screenshots/watchdog.png)

## What it does

It fingerprints the network you trust (SSID, access point, gateway IP/MAC, DNS, subnet, public IP), then keeps comparing the live network against that baseline. Three different attacks produce three different symptoms — and telling them apart is the whole point:

| Symptom | Meaning | Response |
|---|---|---|
| Router MAC changed, IP did not | ARP spoofing, or a rogue router | Re-teach the LAN the real MAC, pin the gateway, block the attacker |
| Gateway IP / subnet / DHCP changed, Wi-Fi did not | Something is answering DHCP in your router's place | Renew the lease, and take the address back statically if the rogue server keeps winning |
| Wi-Fi / access point / adapter changed | You're not on the trusted network any more | Reconnect to the one you were on |

Everything it changes (ARP pins, firewall blocks, DHCP leases) can be undone with one command.

## Quick start

[Download the latest `MITM-Tracker.exe`](https://github.com/jaylalkiya/MITM--Tracker/releases/latest) — no installer, no Python needed. Then:

```
MITM-Tracker.exe                 # opens the console
MITM-Tracker.exe --init          # once: trust the current network
MITM-Tracker.exe --protect       # full protection until Ctrl+C
```

Needs Administrator to pin the gateway, block an attacker, or take an address back — detection alone works without it.

Running from source instead: `python mitm_tracker.py` (needs Python 3; `pip install scapy` + [Npcap](https://npcap.com) to un-poison other hosts on the LAN, not just this one).

## Reading the console

- **STANDBY** — not scanning · **ARMED** — scanning and set to fight back · **SECURE** — scanned, nothing changed · **INTRUSION** — something changed · **NO BASELINE** — run `--init` first · **LINK DOWN** — no network right now
- **NETWORK FINGERPRINT** — baseline vs. live, one row per marker; `[ !! ]` means that row changed
- Three tabs: **WATCHDOG** (fingerprint + arm/scan), **DEVICES** (everyone on your network), **DEFENDER** (countermeasures + block list)

Full command reference, troubleshooting, and the phone-notification setup are in [`README.txt`](README.txt).

## Every command

```
--init              record this network as trusted
--protect            full protection until Ctrl+C
--status             trusted vs. now, plus what's available
--watch 60            keep checking every 60s, warn only
--defend / --restore / --harden / --strict      individual responses
--devices             every host on your network
--networks            access points in range
--block IP / --unblock IP
--clear               undo every change this tool made
--test-notify          check that alerts reach you
--help                 everything, grouped
```

## Safety

Only use this on a network you own or are authorised to defend. It sends ARP packets, ping-sweeps the subnet, and edits the Windows Firewall — the same behaviours an attack tool would have, which is also why antivirus tools sometimes flag the packaged `.exe`. Run `python mitm_tracker.py` instead if you'd rather avoid that.
