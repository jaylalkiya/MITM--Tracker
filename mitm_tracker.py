"""MITM Tracker - detect and undo man-in-the-middle attacks on your network.

Everything is in this one file. Double-click it to open the app, or run it
from a terminal. Nothing else to install: pure Python + Tkinter.

    python mitm_tracker.py                    open the app (asks for admin)
    python mitm_tracker.py --init             record this network as trusted
    python mitm_tracker.py --protect          set-and-forget: watch + defend + repair
    python mitm_tracker.py --status           where am I vs where should I be
    python mitm_tracker.py --help             every other flag

HOW IT WORKS

Record a fingerprint of the network you trust once (--init), then poll the
live network and diff it against that. Every alert and every countermeasure
comes out of that diff. Three different problems get three different answers:

  * The gateway MAC changed while its IP stayed the same -> ARP spoofing or a
    rogue router. Answer: corrective ARP, pin the real gateway, block them.
  * The gateway IP, subnet or DHCP server changed while the Wi-Fi and access
    point did NOT -> your router did not move, so something on this network is
    answering DHCP in its place. Answer: renew, and if the rogue server keeps
    winning the race, take the address back statically.
  * The Wi-Fi, access point or adapter changed -> you are not on the network
    you trusted any more. Answer: reconnect to the one you were.

The distinction between the last two is the whole point: 'the gateway changed'
means opposite things depending on whether the network under it changed too.

WHAT NEEDS WHAT

    Detecting everything          nothing - always works
    Reconnecting to your Wi-Fi    nothing
    Pinning the gateway           Administrator
    Blocking the attacker         Administrator
    Taking an address back        Administrator
    Un-poisoning the rest of the  scapy + Npcap (https://npcap.com - tick
    LAN, not just this PC         'WinPcap API-compatible mode' at setup)

Missing pieces are skipped and SAID OUT LOUD, never failed silently. This
asks for Administrator by itself when it needs it.

Windows is the primary target (netsh). Linux gets a best-effort nmcli path
for detection and reconnection; the countermeasures above are Windows-only.
The netsh parsers read English output; on a localised Windows the labels
differ and detection falls back to "unknown" rather than guessing wrong.

ONLY use this on a network you own or are authorised to defend. It sends
packets to other hosts and changes the local firewall.
"""

import argparse
import ctypes
import ipaddress
import json
import locale
import os
import queue
import random
import re
import subprocess
import sys
import threading
import time
import urllib.request
from datetime import datetime

FROZEN = getattr(sys, "frozen", False)   # True when running as a built .exe

# Where the baseline and log live. When frozen, __file__ points inside the
# temporary folder PyInstaller unpacks to and then DELETES on exit - writing
# the baseline there would lose your trusted network on every single run.
# Next to the .exe is the only stable place.
BASE_DIR = os.path.dirname(os.path.abspath(
    sys.executable if FROZEN else __file__))

# How to tell the user to re-run us. As a built .exe, "" + CMD + ""
# is advice they cannot follow - there may be no Python on the machine at all.
CMD = os.path.basename(sys.executable) if FROZEN else "python mitm_tracker.py"
BASELINE_FILE = os.path.join(BASE_DIR, "router_baseline.json")
LOG_FILE = os.path.join(BASE_DIR, "router_watch.log")
MAX_LOG_BYTES = 1_000_000

PUBLIC_IP_SERVICES = [
    "https://checkip.amazonaws.com",
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
]

MAC_RE = re.compile(r"([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

FIREWALL_TAG = "MITM-Tracker block"   # every firewall rule we add is named this

CONNECT_TIMEOUT = 25     # seconds to wait for a Wi-Fi association
CONNECT_POLL = 2
MAX_DEFEND_TRIES = 3     # per distinct problem, then stop and let the alert stand
MAX_RESTORE_TRIES = 3

IS_WIN = sys.platform == "win32"


# ==========================================================================
# 1. Shell, platform and capability helpers
# ==========================================================================

def _decode(raw):
    """Bytes -> text, without mangling non-ASCII network names.

    netsh emits UTF-8 for names that need it (an SSID with an emoji, an
    accented adapter name), but Python's text mode would decode it with the
    machine's ANSI codepage and turn the SSID into mojibake - which then never
    matches the baseline. Try UTF-8 first, fall back to the local codepage for
    tools that really do use it.
    """
    if not raw:
        return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode(locale.getpreferredencoding(False), "replace")


def _run(cmd, timeout=20):
    """Run a command; return (returncode, stdout, stderr). Never raises."""
    try:
        out = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return out.returncode, _decode(out.stdout), _decode(out.stderr)
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "", str(exc)


def _out(cmd, timeout=20):
    """Run a command and return just stdout, or '' if it fails."""
    return _run(cmd, timeout)[1]


def _ps(script):
    """Run a PowerShell one-liner and return its stdout."""
    return _out(["powershell", "-NoProfile", "-Command", script])


def _field(text, label):
    """Pull 'Label : value' out of netsh output. '' when absent."""
    m = re.search(rf"^\s*{re.escape(label)}\s*:\s*(.+?)\s*$", text, re.MULTILINE)
    return m.group(1).strip() if m else ""


def _psq(value):
    """Quote a value for a PowerShell single-quoted string.

    Adapter aliases really do contain apostrophes ("Bob's iPhone" shared over
    USB), and one of those would otherwise end the string early and break the
    command.
    """
    return "'" + str(value).replace("'", "''") + "'"


def is_admin():
    """True if we are running with Administrator rights."""
    if not IS_WIN:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(args=None, gui=False):
    """Re-run this same file elevated, so there is no .bat launcher to keep.

    Returns True if an elevated copy was started (this process should then
    exit). Returns False if we are already admin, this is not Windows, or the
    user declined the UAC prompt - in which case carry on unelevated, because
    detection still works and saying so is better than refusing to run.
    """
    if not IS_WIN or is_admin():
        return False

    argv = list(sys.argv[1:] if args is None else args)
    exe = sys.executable

    def quote(a):
        return '"' + str(a).replace('"', r'\"') + '"'

    if FROZEN:
        # The .exe IS the program - there is no script to pass to it.
        params = " ".join(quote(a) for a in argv)
    else:
        if gui:
            # pythonw runs the GUI with no console window behind it.
            pythonw = os.path.join(os.path.dirname(exe), "pythonw.exe")
            if os.path.exists(pythonw):
                exe = pythonw
        params = " ".join(quote(a) for a in [os.path.abspath(__file__)] + argv)
    try:
        # ShellExecuteW with 'runas' is what raises the UAC prompt.
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", exe, params, BASE_DIR, 1)
        return int(rc) > 32   # <=32 is an error code, incl. 5 = user said No
    except Exception:
        return False


ICON_NAME = "mitm_tracker.ico"
# The header logo has to be a PNG, not the .ico: Tk's PhotoImage reads PNG and
# GIF only, and iconbitmap - which does read .ico - cannot draw into a widget.
LOGO_NAME = "mitm_logo.png"


def resource_path(name):
    """Locate a bundled file, frozen or not.

    PyInstaller unpacks data files to sys._MEIPASS, which is NOT where the
    .exe lives - so this is deliberately different from BASE_DIR, which has to
    stay next to the .exe because it is where we WRITE.
    """
    base = getattr(sys, "_MEIPASS", None) or BASE_DIR
    packed = os.path.join(base, name)
    if os.path.exists(packed):
        return packed
    loose = os.path.join(BASE_DIR, name)
    return loose if os.path.exists(loose) else None


def _attach_console():
    """Put CLI output back on screen when running as a windowed .exe.

    A windowed build has no console of its own, so sys.stdout is None and
    every print vanishes. Attaching to the console of whatever launched us
    sends output back to that PowerShell window. Double-clicked from Explorer
    there is no parent console, this quietly does nothing, and the GUI opens
    with no black box behind it - which is the point of a windowed build.
    """
    if not (FROZEN and IS_WIN):
        return
    try:
        if ctypes.windll.kernel32.AttachConsole(-1):   # ATTACH_PARENT_PROCESS
            sys.stdout = open("CONOUT$", "w", encoding="utf-8", buffering=1)
            sys.stderr = open("CONOUT$", "w", encoding="utf-8", buffering=1)
    except Exception:
        pass   # no console to attach to; the GUI path does not need one


def have_scapy():
    """True only if scapy can actually SEND raw frames.

    Importing scapy is NOT enough. On Windows the packet-sending backend is
    Npcap, a separate download - without it every import succeeds and every
    send fails. A check that only imported would report a capability we do not
    have, which is the exact silent failure this whole tool tries to avoid.
    """
    try:
        from scapy.all import conf
    except Exception:
        return False
    if not IS_WIN:
        return True   # raw sockets, no pcap driver needed

    if getattr(conf, "use_pcap", False):
        return True
    # Fall back to looking for the driver ourselves, in case a scapy version
    # reports this differently.
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    return any(os.path.exists(os.path.join(system32, dll))
               for dll in ("Npcap\\wpcap.dll", "wpcap.dll"))


def scapy_problem():
    """Which half is missing, so the fix can be specific rather than generic."""
    try:
        import scapy.all  # noqa: F401
    except Exception:
        return ("scapy is not installed. Install it with:  pip install scapy"
                "   (then Npcap, below)")
    if not have_scapy():
        return ("scapy is installed but Npcap is not, so it cannot send "
                "packets. Install Npcap from https://npcap.com and tick "
                "'WinPcap API-compatible mode' during setup.")
    return None


def mac_dashed(mac):
    """netsh wants aa-bb-cc-dd-ee-ff; we store colons everywhere else."""
    return mac.lower().replace(":", "-") if mac else mac


def mask_from_prefix(prefix):
    """24 -> '255.255.255.0'. netsh wants a dotted mask, not a prefix length."""
    try:
        bits = int(prefix)
    except (TypeError, ValueError):
        return None
    if not 0 <= bits <= 32:
        return None
    packed = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF if bits else 0
    return ".".join(str((packed >> shift) & 0xFF) for shift in (24, 16, 8, 0))


# ==========================================================================
# 2. Logging
# ==========================================================================

# Extra places to send every log line (the GUI adds one). Each sink is called
# with the fully formatted line. Empty for normal CLI use.
LOG_SINKS = []


def _rotate_log():
    """Keep one previous log so a 24/7 watch cannot fill the disk."""
    try:
        if os.path.getsize(LOG_FILE) < MAX_LOG_BYTES:
            return
        old = LOG_FILE + ".1"
        if os.path.exists(old):
            os.remove(old)
        os.replace(LOG_FILE, old)
    except OSError:
        pass


def log(message, to_file=True):
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {message}"
    try:
        print(line, flush=True)
    except (UnicodeEncodeError, AttributeError, OSError):
        # A network name the console codepage cannot draw (emoji SSIDs are
        # common on phone hotspots), or no console at all under pythonw.
        # Never let cosmetics kill the watchdog.
        try:
            enc = getattr(sys.stdout, "encoding", None) or "ascii"
            print(line.encode(enc, "replace").decode(enc, "replace"), flush=True)
        except Exception:
            pass
    for sink in list(LOG_SINKS):
        try:
            sink(line)
        except Exception:
            pass
    if not to_file:
        return
    try:
        _rotate_log()
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


# Put a URL in this file (or in the MITM_WEBHOOK environment variable) and
# every alert is POSTed there as JSON - Slack, Teams, Discord, ntfy, your own
# endpoint. That is how an alert reaches you when you are not at the desk.
WEBHOOK_FILE = os.path.join(BASE_DIR, "notify_webhook.txt")


def _webhook_url():
    url = os.environ.get("MITM_WEBHOOK", "").strip()
    if url:
        return url
    try:
        with open(WEBHOOK_FILE, "r", encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    return line
    except OSError:
        pass
    return None


def _toast(title, message):
    """Windows notification centre popup.

    Built from raw XML on purpose: the documented GetTemplateContent form
    throws 'Collection was modified' on current PowerShell builds, so the
    obvious way to write this fails on exactly the machines it targets.
    """
    if not IS_WIN:
        return False

    def esc(t):
        return (str(t).replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace('"', "&quot;"))

    xml = (f'<toast><visual><binding template="ToastText02">'
           f'<text id="1">{esc(title)}</text>'
           f'<text id="2">{esc(message)}</text>'
           f'</binding></visual></toast>')
    script = (
        "[Windows.UI.Notifications.ToastNotificationManager, "
        "Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, "
        "ContentType=WindowsRuntime] | Out-Null; "
        "$x = New-Object Windows.Data.Xml.Dom.XmlDocument; "
        f"$x.LoadXml('{xml}'); "
        "$n = [Windows.UI.Notifications.ToastNotification]::new($x); "
        "[Windows.UI.Notifications.ToastNotificationManager]::"
        "CreateToastNotifier('Microsoft.Windows.Powershell').Show($n)"
    )
    return _run(["powershell", "-NoProfile", "-Command", script], timeout=15)[0] == 0


def _post_webhook(title, message):
    url = _webhook_url()
    if not url:
        return False
    payload = json.dumps({
        "text": f"{title}\n{message}",          # Slack / Mattermost / ntfy
        "content": f"**{title}**\n{message}",   # Discord
        "title": title,
        "message": message,
        "host": os.environ.get("COMPUTERNAME") or "",
        "at": datetime.now().isoformat(timespec="seconds"),
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            url, data=payload,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8):
            return True
    except Exception as exc:
        log(f"   [notify] webhook failed ({exc}).", to_file=False)
        return False


def notify(title, message):
    """Reach the human. Never raises - a failed notification must not stop
    the defence that triggered it."""
    sent = []
    try:
        if _toast(title, message):
            sent.append("toast")
    except Exception:
        pass
    try:
        if _post_webhook(title, message):
            sent.append("webhook")
    except Exception:
        pass
    return sent


def alert(message, beep=True):
    """Log a change loudly. `beep` is off for all but the first alert of a
    cycle - one event can change seven fields at once, and 21 beeps takes
    eight seconds during which nothing else runs.

    The same flag gates the notification, so one event sends one popup rather
    than seven.
    """
    log("!! ALERT !! " + message)
    if not beep:
        return
    try:
        import winsound
        for _ in range(3):
            winsound.Beep(1000, 400)
    except Exception:
        print("\a", end="", flush=True)
    # Reach the user even when they are not looking at this machine.
    threading.Thread(
        target=notify, args=("MITM Tracker - network changed", message),
        daemon=True).start()


# ==========================================================================
# 3. Reading the network
# ==========================================================================

def get_gateway_ip():
    """Default gateway (the router's LAN address)."""
    if IS_WIN:
        out = _ps(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
            " Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop"
        )
        found = IPV4_RE.search(out)
        if found and found.group(0) != "0.0.0.0":
            return found.group(0)

        # Fallback for machines where Get-NetRoute is unavailable.
        for line in _out(["ipconfig"]).splitlines():
            if "Default Gateway" in line:
                found = IPV4_RE.search(line)
                if found and found.group(0) != "0.0.0.0":
                    return found.group(0)
        return None

    out = _out(["ip", "route", "show", "default"]) or \
        _out(["route", "-n", "get", "default"])
    found = re.search(r"(?:via|gateway:)\s*(" + IPV4_RE.pattern + ")", out)
    return found.group(1) if found else None


def get_gateway_mac(gateway_ip):
    """Hardware address of the gateway, read from the ARP table."""
    if not gateway_ip:
        return None
    # Touch the gateway first so it is guaranteed to be in the ARP cache.
    _run(["ping", "-n" if IS_WIN else "-c", "1",
          "-w" if IS_WIN else "-W", "1000", gateway_ip], timeout=15)

    for line in _out(["arp", "-a"]).splitlines():
        if gateway_ip in line:
            found = MAC_RE.search(line)
            if found:
                return found.group(0).lower().replace("-", ":")
    return None


def get_public_ip():
    """Your WAN address as the outside world sees it."""
    for url in PUBLIC_IP_SERVICES:
        try:
            with urllib.request.urlopen(url, timeout=8) as resp:
                text = resp.read().decode("utf-8", "replace").strip()
            found = IPV4_RE.search(text)
            if found:
                return found.group(0)
        except Exception:
            continue
    return None


def default_interface():
    """(alias, index) of the adapter carrying the default route."""
    if not IS_WIN:
        m = re.search(r"\bdev\s+(\S+)", _out(["ip", "route", "show", "default"]))
        return (m.group(1), None) if m else (None, None)

    out = _ps(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Sort-Object RouteMetric | Select-Object -First 1 |"
        " ForEach-Object { \"$($_.InterfaceAlias)|$($_.ifIndex)\" }"
    )
    line = out.strip().splitlines()[0] if out.strip() else ""
    if "|" not in line:
        return None, None
    alias, _, idx = line.partition("|")
    return alias.strip() or None, idx.strip() or None


def wifi_state():
    """Current Wi-Fi association: interface, ssid, bssid, profile.

    Every value is None when there is no Wi-Fi adapter or nothing is
    associated (e.g. a wired-only machine) - that is not an error.
    """
    blank = {"wifi_interface": None, "ssid": None, "bssid": None,
             "wifi_profile": None}

    if not IS_WIN:
        rc, out, _ = _run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,DEVICE",
                           "dev", "wifi"], timeout=30)
        if rc != 0:
            return blank
        for line in out.splitlines():
            # nmcli -t escapes the colons inside a MAC as '\:'
            parts = line.replace("\\:", "%%").split(":")
            if parts and parts[0] == "yes" and len(parts) >= 4:
                return {"wifi_interface": parts[3] or None,
                        "ssid": parts[1] or None,
                        "bssid": (parts[2].replace("%%", ":").lower() or None),
                        "wifi_profile": parts[1] or None}
        return blank

    rc, out, _ = _run(["netsh", "wlan", "show", "interfaces"], timeout=30)
    if rc != 0 or "SSID" not in out:
        return blank
    # A disconnected adapter still prints its name, so check the state first.
    if _field(out, "State").lower() not in ("connected", ""):
        return dict(blank, wifi_interface=_field(out, "Name") or None)

    bssid = _field(out, "AP BSSID") or _field(out, "BSSID")
    return {
        "wifi_interface": _field(out, "Name") or None,
        # 'SSID' matches the 'AP BSSID' line too, so read SSID first-match only.
        "ssid": _field(out, "SSID") or None,
        "bssid": bssid.lower().replace("-", ":") or None,
        "wifi_profile": _field(out, "Profile") or None,
    }


def ip_config(alias, index=None):
    """This machine's own IPv4 identity on `alias`.

    Three fields, and each one is load-bearing for the self-healing:

        local_ip     the address we hold - what we must be able to take back
        subnet       '192.168.0.0/24' - a changed subnet means a changed network
        dhcp_server  who handed out the lease. This is the single best rogue-DHCP
                     tell there is: on your own network it is the router, and a
                     rogue server cannot hide - it has to put its own address here.
    """
    empty = {"local_ip": None, "subnet": None, "dhcp_server": None}
    if not alias:
        return empty

    if not IS_WIN:
        rc, out, _ = _run(["ip", "-4", "-o", "addr", "show", "dev", alias])
        if rc != 0:
            return empty
        m = re.search(r"inet\s+(\S+?)/(\d+)", out)
        if not m:
            return empty
        return {"local_ip": m.group(1), "subnet": None, "dhcp_server": None}

    rc, out, _ = _run(["netsh", "interface", "ipv4", "show", "config",
                       f"name={alias}"], timeout=30)
    if rc != 0:
        return empty

    ip = IPV4_RE.search(_field(out, "IP Address") or "")
    # 'Subnet Prefix: 192.168.0.0/24 (mask 255.255.255.0)' - keep the CIDR half.
    net = re.search(r"((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})",
                    _field(out, "Subnet Prefix") or "")
    dhcp_on = (_field(out, "DHCP enabled") or "").strip().lower().startswith("y")

    server = None
    if dhcp_on and index and str(index).isdigit():
        # Only Win32_NetworkAdapterConfiguration exposes which server answered.
        raw = _ps(
            "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter"
            f" 'IPEnabled=True AND InterfaceIndex={int(index)}'"
            " | Select-Object -First 1 -ExpandProperty DHCPServer"
        )
        found = IPV4_RE.search(raw)
        server = found.group(0) if found else None

    return {
        "local_ip": ip.group(0) if ip else None,
        "subnet": net.group(1) if net else None,
        "dhcp_server": server,
    }


def dns_config(alias):
    """DNS for one adapter -> {'dns_source': 'dhcp'|'static'|None, 'dns_servers': str}.

    Servers are kept as one comma-joined string so they diff and store exactly
    like every other baseline field.
    """
    empty = {"dns_source": None, "dns_servers": None}
    if not alias:
        return empty

    if not IS_WIN:
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as fh:
                servers = re.findall(r"^nameserver\s+(\S+)", fh.read(), re.MULTILINE)
        except OSError:
            return empty
        return {"dns_source": None, "dns_servers": ", ".join(servers) or None}

    rc, out, _ = _run(["netsh", "interface", "ipv4", "show", "dnsservers",
                       f"name={alias}"], timeout=30)
    if rc != 0:
        return empty
    servers = IPV4_RE.findall(out)
    source = None
    if re.search(r"through DHCP", out, re.IGNORECASE):
        source = "dhcp"
    elif re.search(r"Statically", out, re.IGNORECASE):
        source = "static"
    return {"dns_source": source,
            "dns_servers": ", ".join(servers) if servers else None}


def net_snapshot():
    """The network-identity half of a baseline: adapter, Wi-Fi, IP, DNS."""
    alias, index = default_interface()
    wifi = wifi_state()
    # Only trust the Wi-Fi reading if Wi-Fi is the adapter actually in use;
    # otherwise you are on Ethernet and the (idle) Wi-Fi radio is irrelevant.
    if alias and wifi["wifi_interface"] and alias != wifi["wifi_interface"]:
        wifi = {k: None for k in wifi}
    return {
        "interface": alias,
        **wifi,
        **ip_config(alias, index),
        **dns_config(alias),
    }


def snapshot(check_public=True):
    """Everything we fingerprint about the current network."""
    gateway = get_gateway_ip()
    return {
        "gateway_ip": gateway,
        "gateway_mac": get_gateway_mac(gateway),
        "public_ip": get_public_ip() if check_public else None,
        **net_snapshot(),
        "checked_at": datetime.now().isoformat(timespec="seconds"),
    }


def visible_networks():
    """{ssid: [bssid, ...]} for every access point currently in range."""
    found = {}
    if not IS_WIN:
        rc, out, _ = _run(["nmcli", "-t", "-f", "SSID,BSSID", "dev", "wifi", "list"],
                          timeout=30)
        if rc != 0:
            return found
        for line in out.splitlines():
            ssid, _, bssid = line.replace("\\:", "%%").partition(":")
            if ssid:
                found.setdefault(ssid, []).append(bssid.replace("%%", ":").lower())
        return found

    rc, out, _ = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30)
    if rc != 0:
        return found
    ssid = None
    for line in out.splitlines():
        m = re.match(r"\s*SSID\s+\d+\s*:\s*(.*)$", line)
        if m:
            ssid = m.group(1).strip()
            found.setdefault(ssid, [])
            continue
        m = re.match(r"\s*BSSID\s+\d+\s*:\s*(.+)$", line)
        if m and ssid is not None:
            found[ssid].append(m.group(1).strip().lower().replace("-", ":"))
    return found


def in_range(ssid):
    """True if that SSID is currently being broadcast."""
    return bool(ssid) and ssid in visible_networks()


# ==========================================================================
# 4. The baseline - the network you trust
# ==========================================================================

def load_baseline():
    if not os.path.exists(BASELINE_FILE):
        return None
    try:
        # utf-8-sig: tolerate a BOM, which Notepad and PowerShell add when
        # the baseline is edited by hand.
        with open(BASELINE_FILE, "r", encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def save_baseline(data):
    with open(BASELINE_FILE, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def init_hazards(current, previous=None):
    """Reasons not to trust what we are about to record as 'normal'.

    Baselining mid-attack is the one mistake that quietly disables everything
    else: it saves the attacker's MAC as the trusted router, after which every
    check reports that all is well - forever. Cheap to check, so always check.
    """
    reasons = []
    gw, mac = current.get("gateway_ip"), current.get("gateway_mac")

    try:
        for dup_mac, ips in duplicate_macs().items():
            if gw and gw in ips:
                others = ", ".join(i for i in ips if i != gw)
                reasons.append(
                    f"the gateway {gw} and {others} both answer to {dup_mac} - "
                    "one machine is holding your router's address as well as "
                    "its own, which is exactly what ARP spoofing looks like")
    except Exception:
        pass

    # Same Wi-Fi, same access point, but the router's hardware changed since
    # the last baseline: routers do not swap MACs on their own.
    if previous and mac and previous.get("gateway_mac") \
            and previous.get("ssid") == current.get("ssid") \
            and previous.get("bssid") == current.get("bssid") \
            and previous["gateway_mac"] != mac:
        reasons.append(
            f"on this same Wi-Fi and access point, the router MAC was "
            f"{previous['gateway_mac']} and is now {mac}. Real routers do not "
            "change hardware address by themselves")
    return reasons


# ==========================================================================
# 5. Comparing now against trusted
# ==========================================================================

# Each field is tagged with what a change to it MEANS, which decides the
# response:
#   "arp"  - the router's hardware changed under a fixed IP: ARP spoofing.
#   "net"  - you are no longer on the network you trusted (different Wi-Fi,
#            different access point, different subnet, different resolvers).
#   "info" - worth reporting, but nothing to undo locally.
WATCHED = [
    ("gateway_mac",  "Router MAC address",      "arp"),
    ("ssid",         "Wi-Fi network (SSID)",    "net"),
    ("bssid",        "Access point (BSSID)",    "net"),
    ("gateway_ip",   "Router (gateway) IP",     "net"),
    ("subnet",       "Subnet",                  "net"),
    ("dhcp_server",  "DHCP server",             "net"),
    ("dns_servers",  "DNS servers",             "net"),
    ("interface",    "Network adapter",         "net"),
    ("public_ip",    "Public / WAN IP",         "info"),
]

# Why each "net" change matters, printed under the alert.
WHY = {
    "ssid": "You are on a different Wi-Fi network than the one you trusted.",
    "bssid": "Same network name, different access point hardware. This is the "
             "fake-hotspot (evil twin) signature - unless your network "
             "legitimately has several access points.",
    "gateway_ip": "Different gateway means a different subnet, i.e. a "
                  "different network - or a rogue DHCP server handing out "
                  "its own address.",
    "subnet": "You have been moved onto a different range of addresses than "
              "the one your router hands out.",
    "dhcp_server": "A different machine answered when you asked for an "
                   "address. Whoever does that chooses your gateway and your "
                   "DNS, so it decides where all your traffic goes.",
    "dns_servers": "Your name lookups are now going somewhere else. This is "
                   "the quietest way to be redirected, and it is invisible "
                   "in the browser.",
    "interface": "Traffic is leaving through a different adapter than usual "
                 "(e.g. a phone or USB device now provides your route).",
}


def _why(key, baseline, current, changed):
    """Explain a "net" change, given what else changed alongside it."""
    if key == "bssid" and "ssid" in changed:
        return ("Different access point hardware, as expected: the Wi-Fi "
                "network itself changed.")
    if key == "gateway_ip" and baseline.get("subnet")             and baseline["subnet"] == current.get("subnet"):
        return ("The gateway moved to another address in the same subnet. A "
                "router reconfiguration can do that, and so can a rogue DHCP "
                "server handing out its own address.")
    return WHY.get(key, "You are no longer on the trusted network.")


def compare(baseline, current):
    """Return a list of (key, label, old, new, kind) for changed fields."""
    changes = []
    for key, label, kind in WATCHED:
        old, new = baseline.get(key), current.get(key)
        if new is None:
            continue   # not collected this run - don't cry wolf
        if old is not None and old != new:
            changes.append((key, label, old, new, kind))
    return changes


def rogue_dhcp(baseline, current):
    """True when the addressing changed but the network did NOT.

    'Gateway IP changed' can mean two opposite things:

        different Wi-Fi / access point -> you walked onto another network.
            Nothing to defend; just go home.
        SAME Wi-Fi, SAME access point  -> your router did not move, so someone
            on this network is answering DHCP in its place and pointing you at
            themselves. That is a MITM, and it is the one an ARP-only defence
            never sees, because no ARP entry was ever poisoned.
    """
    if not baseline or not current:
        return False

    addressing_moved = any(
        baseline.get(k) and current.get(k) and baseline[k] != current[k]
        for k in ("gateway_ip", "subnet", "dhcp_server")
    )
    if not addressing_moved:
        return False

    # Still the same radio link? Then the network itself did not change.
    if baseline.get("ssid"):
        if current.get("ssid") != baseline["ssid"]:
            return False
        if baseline.get("bssid") and current.get("bssid") \
                and current["bssid"] != baseline["bssid"]:
            return False   # different AP hardware: evil twin, handled elsewhere
        return True

    # Wired baseline: the adapter staying put is the equivalent signal.
    return bool(baseline.get("interface")) and \
        current.get("interface") == baseline["interface"]


# ==========================================================================
# 6. ARP layer - see the poisoning, undo it, and cut the attacker off
# ==========================================================================

# Addresses that legitimately share a hardware address, so they must never be
# read as one machine holding several IPs.
_NOT_A_HOST = re.compile(r"^(ff:ff:ff:ff:ff:ff|01:00:5e|33:33|00:00:00:00:00:00)")


def arp_table():
    """Parse `arp -a` -> list of (ip, mac) with colon-separated lower MACs."""
    entries = []
    out = _out(["arp", "-a"])
    for line in out.splitlines():
        ip_m = IPV4_RE.search(line)
        mac_m = MAC_RE.search(line)
        if ip_m and mac_m:
            entries.append((ip_m.group(0), mac_m.group(0).lower().replace("-", ":")))
    return entries


def duplicate_macs():
    """MACs that own more than one IP right now -> {mac: [ip, ...]}.

    One machine answering for several addresses is the ARP-spoofing footprint,
    and it shows up even when the gateway entry itself looks clean: an attacker
    mid-poison, or one poisoning a neighbour rather than you, is visible here
    while a baseline comparison still says everything is fine.
    """
    by_mac = {}
    for ip, mac in arp_table():
        if _NOT_A_HOST.match(mac):
            continue
        if 224 <= int(ip.split(".")[0]) <= 239:
            continue
        by_mac.setdefault(mac, set()).add(ip)
    return {mac: sorted(ips) for mac, ips in by_mac.items() if len(ips) > 1}


def own_mac(alias=None):
    """This machine's own hardware address on the adapter carrying the route."""
    if not IS_WIN:
        return None
    alias = alias or default_interface()[0]
    if not alias:
        return None
    out = _ps("Get-NetAdapter -ErrorAction SilentlyContinue |"
              " Where-Object { $_.Name -eq " + _psq(alias) + " } |"
              " Select-Object -First 1 -ExpandProperty MacAddress")
    found = MAC_RE.search(out or "")
    return found.group(0).lower().replace("-", ":") if found else None


def randomised_mac(mac):
    """True if this MAC was chosen by software rather than burned in.

    Bit 1 of the first octet is the U/L flag. Real hardware ships with a
    globally-unique address from a vendor's OUI block, so that bit is clear.
    Set means locally administered: phone Wi-Fi privacy does it legitimately,
    and so does anyone who has just set their own MAC. Worth showing next to a
    device rather than hiding, because on a small home LAN an unexpected one
    is the cheapest spoofing tell there is.
    """
    try:
        return bool(int(str(mac).split(":")[0], 16) & 0b10)
    except (ValueError, IndexError, AttributeError):
        return False


def lan_devices(gateway_ip=None, local_ip=None):
    """Every real host currently on the LAN, annotated.

    -> [{ip, mac, role, flags, also}], sorted by address. Multicast, broadcast
    and the all-zero entry are dropped: they are protocol machinery, not
    machines, and listing them buries the handful of rows that matter.
    """
    if gateway_ip is None:
        gateway_ip = get_gateway_ip()
    alias = None
    if local_ip is None:
        snap = net_snapshot()
        local_ip, alias = snap.get("local_ip"), snap.get("interface")

    dupes = duplicate_macs()
    rows = []
    for ip, mac in arp_table():
        if _NOT_A_HOST.match(mac):
            continue
        try:
            if 224 <= int(ip.split(".")[0]) <= 239:
                continue
        except (ValueError, IndexError):
            continue

        role = ""
        if ip == gateway_ip:
            role = "GATEWAY"
        elif ip == local_ip:
            role = "THIS PC"

        flags = []
        if mac in dupes:
            flags.append("DUPLICATE")
        if randomised_mac(mac):
            flags.append("RANDOM MAC")

        rows.append({
            "ip": ip, "mac": mac, "role": role, "flags": flags,
            "also": [other for other in dupes.get(mac, []) if other != ip],
        })

    # A machine never ARPs for itself, so this PC is absent from its own
    # table. Leaving it out makes the list look like it missed a device.
    if local_ip and not any(r["ip"] == local_ip for r in rows):
        rows.append({"ip": local_ip, "mac": own_mac(alias) or "(this machine)",
                     "role": "THIS PC", "flags": [], "also": []})

    def as_number(row):
        try:
            return tuple(int(p) for p in row["ip"].split("."))
        except ValueError:
            return (0, 0, 0, 0)
    rows.sort(key=as_number)
    return rows


def sweep_lan(subnet=None, workers=64, on_progress=None):
    """Ping every address on the subnet so the ARP table fills up.

    `arp -a` only lists hosts this machine has actually talked to, so without
    a sweep the device list shows the gateway and almost nothing else. One
    ping per address populates the cache; the replies themselves are ignored,
    because a host that refuses ICMP still has to answer ARP to receive it.

    Bounded to /22 and larger prefixes (max 1022 hosts) - sweeping a /8 would
    take hours and is never what someone means by "my network".
    """
    if subnet is None:
        subnet = net_snapshot().get("subnet")
    if not subnet:
        return 0
    try:
        net = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        return 0
    if net.version != 4 or net.prefixlen < 22:
        log(f"   [scan] {subnet} is too large to sweep - skipping the ping "
            "sweep and showing only what is already known.")
        return 0

    hosts = list(net.hosts())
    total = len(hosts)
    done = [0]
    lock = threading.Lock()

    def ping(ip):
        _run(["ping", "-n", "1", "-w", "300", str(ip)] if IS_WIN
             else ["ping", "-c", "1", "-W", "1", str(ip)], timeout=6)
        if on_progress:
            with lock:
                done[0] += 1
                if done[0] % 16 == 0 or done[0] == total:
                    on_progress(done[0], total)

    threads = []
    queue_of = list(hosts)
    def worker():
        while True:
            with lock:
                if not queue_of:
                    return
                ip = queue_of.pop()
            ping(ip)

    for _ in range(min(workers, total)):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=60)
    return total


def find_attacker_ips(spoofed_mac, gateway_ip):
    """IP(s), other than the gateway, that share the attacker's MAC.

    When a host poisons the gateway entry, its own real IP still resolves to
    the same MAC in the ARP table - that pairing is what exposes it.
    """
    if not spoofed_mac:
        return []
    spoofed = spoofed_mac.lower()
    return sorted({ip for ip, mac in arp_table()
                   if mac == spoofed and ip != gateway_ip})


def send_corrective_arp(gateway_ip, real_mac, rounds=5, interval=1.0):
    """Broadcast the truth: gateway_ip is at real_mac.

    Sends, on each round:
      * a gratuitous ARP reply to the broadcast address (every host hears it), and
      * a targeted reply to each host currently in our ARP table,
    all announcing gateway_ip -> real_mac. This overwrites the attacker's lie.

    Needs scapy + Npcap. Returns True if anything was sent.
    """
    if not have_scapy():
        log("   [corrective ARP] skipping the LAN broadcast - "
            + (scapy_problem() or "no packet-sending backend available.")
            + " Self-protection still applies.")
        return False

    from scapy.all import ARP, Ether, sendp, conf

    # Targeted victims = everyone we currently see, except the gateway itself.
    victims = [ip for ip, _ in arp_table() if ip != gateway_ip]

    def reply_to(dst_ip, dst_mac="ff:ff:ff:ff:ff:ff"):
        # op=2 is an ARP *reply*; psrc/hwsrc carry the correct mapping.
        eth = Ether(src=real_mac, dst=dst_mac)
        arp = ARP(op=2, psrc=gateway_ip, hwsrc=real_mac,
                  pdst=dst_ip, hwdst=dst_mac)
        return eth / arp

    try:
        for r in range(rounds):
            pkts = [reply_to(gateway_ip)]   # gratuitous broadcast for the gateway
            pkts += [reply_to(ip) for ip in victims]
            sendp(pkts, iface=conf.iface, verbose=False)
            log(f"   [corrective ARP] round {r + 1}/{rounds}: announced "
                f"{gateway_ip} is at {real_mac} to {len(victims) + 1} target(s)")
            if r < rounds - 1:
                time.sleep(interval)
        return True
    except Exception as exc:
        log(f"   [corrective ARP] could not send ({exc}). On Windows this "
            "usually means Npcap is missing or you are not elevated.")
        return False


def get_if_index(gateway_ip=None):
    """Interface index of the route that reaches the gateway (needed by netsh)."""
    if not IS_WIN:
        return None
    out = _ps(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |"
        " Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty ifIndex"
    )
    found = re.search(r"\d+", out)
    return found.group(0) if found else None


def pin_gateway(gateway_ip, real_mac):
    """Lock gateway_ip -> real_mac as a STATIC ARP entry on this machine."""
    if not gateway_ip or not real_mac:
        log("   [pin] no gateway or trusted MAC to pin - skipped.")
        return False

    if not IS_WIN:
        rc, _, err = _run(["arp", "-s", gateway_ip, mac_dashed(real_mac)])
        ok = rc == 0
        log(f"   [pin] static ARP {'set' if ok else 'FAILED'} for {gateway_ip}"
            + (f" ({err.strip()})" if not ok else ""))
        return ok

    if not is_admin():
        log("   [pin] need Administrator to set a static ARP entry - skipped. "
            "Re-run and click YES on the prompt to lock the gateway.")
        return False

    idx = get_if_index(gateway_ip)
    if not idx:
        log("   [pin] could not find the network interface index - skipped.")
        return False

    # Remove any existing (possibly poisoned) entry, then add the trusted one.
    _run(["netsh", "interface", "ipv4", "delete", "neighbors", idx, gateway_ip])
    rc, _, err = _run([
        "netsh", "interface", "ipv4", "add", "neighbors",
        idx, gateway_ip, mac_dashed(real_mac),
    ])
    ok = rc == 0
    if ok:
        log(f"   [pin] gateway {gateway_ip} is now PINNED to {real_mac} "
            "(static). ARP poisoning of the gateway will no longer stick.")
    else:
        log(f"   [pin] failed to pin gateway ({err.strip()}).")
    return ok


def unpin_gateway(gateway_ip):
    """Remove the static ARP entry (return the gateway to normal, dynamic ARP)."""
    if not IS_WIN:
        _run(["arp", "-d", gateway_ip])
        log(f"   [pin] removed static ARP entry for {gateway_ip}.")
        return True
    if not is_admin():
        log("   [pin] need Administrator to remove the static entry - skipped.")
        return False
    idx = get_if_index(gateway_ip)
    if idx:
        _run(["netsh", "interface", "ipv4", "delete", "neighbors", idx, gateway_ip])
        log(f"   [pin] removed static ARP entry for {gateway_ip}.")
    return True


def static_neighbors():
    """Every permanent (pinned) ARP entry that a human could have made:
    list of (if_index, ip).

    Windows keeps its own permanent entries for the multicast and subnet
    broadcast addresses (192.168.0.255 and friends). Those are load-bearing
    parts of the stack, not pins, so they are filtered out by their hardware
    address - the IP alone cannot tell you that 192.168.0.255 is a broadcast,
    since that depends on the subnet mask.
    """
    if not IS_WIN:
        return []
    out = _ps(
        "Get-NetNeighbor -AddressFamily IPv4 -State Permanent"
        " -ErrorAction SilentlyContinue |"
        " ForEach-Object { \"$($_.ifIndex)|$($_.IPAddress)|$($_.LinkLayerAddress)\" }"
    )
    found = []
    for line in out.splitlines():
        parts = line.strip().split("|")
        if len(parts) != 3:
            continue
        idx, ip, mac = (p.strip() for p in parts)
        if not idx.isdigit() or not IPV4_RE.fullmatch(ip):
            continue
        # 224-239 is multicast by definition, so that one IS safe to judge by
        # address. On the loopback interface these carry no MAC at all.
        if 224 <= int(ip.split(".")[0]) <= 239:
            continue
        if not mac or _NOT_A_HOST.match(mac.lower().replace("-", ":")):
            continue
        found.append((idx, ip))
    return found


def clean_stale_pins(keep_ip=None):
    """Drop pins left over from networks you are no longer on.

    A pin is protection on the network it was made for and dead weight
    everywhere else: it survives reboots and Wi-Fi changes, so yesterday's
    defence silently overrides ARP on a network it knows nothing about.
    """
    stale = [(idx, ip) for idx, ip in static_neighbors() if ip != keep_ip]
    if not stale:
        return 0
    if not is_admin():
        log(f"   [pin] {len(stale)} stale pin(s) from other networks "
            f"({', '.join(ip for _, ip in stale)}) - need Administrator to "
            "remove them.")
        return 0
    removed = 0
    for idx, ip in stale:
        rc, _, _ = _run(["netsh", "interface", "ipv4", "delete", "neighbors", idx, ip])
        if rc == 0:
            removed += 1
    if removed:
        log(f"   [pin] cleared {removed} stale pin(s) from previous networks: "
            + ", ".join(ip for _, ip in stale))
    return removed


def harden(baseline, clean=True):
    """Lock in the trusted network BEFORE anything attacks it.

    Detection always lags: with a 15s poll your traffic can spend 15s inside an
    attacker's machine before the first alert. A pin placed while the network is
    still healthy removes that window - the poisoning never takes hold at all,
    so there is nothing to detect and nothing to undo.

    Refuses to pin anything that does not already match the baseline, so this
    can never bake an attacker's MAC in as trusted.
    """
    gw = get_gateway_ip()
    mac = get_gateway_mac(gw)
    base_gw, base_mac = baseline.get("gateway_ip"), baseline.get("gateway_mac")

    if clean:
        clean_stale_pins(keep_ip=base_gw if base_gw == gw else None)

    if not base_gw or not base_mac:
        log("   [harden] the baseline has no gateway recorded - nothing to pin. "
            "Run:  " + CMD + " --init")
        return False
    if gw != base_gw:
        log(f"   [harden] not on the trusted network (gateway {gw}, trusted "
            f"{base_gw}) - not pinning anything here.")
        return False
    if mac and mac != base_mac:
        log(f"   [harden] the gateway MAC is already {mac}, not the trusted "
            f"{base_mac}. This is the spoofing signature, not a clean network - "
            "refusing to pin. Responding instead.")
        return False

    return pin_gateway(base_gw, base_mac)


def block_ip(ip):
    """Add inbound + outbound Windows Firewall rules blocking this IP."""
    if not IS_WIN:
        log(f"   [block] firewall blocking is Windows-only here - skipped {ip}.")
        return False
    if not is_admin():
        log(f"   [block] need Administrator to add a firewall rule - {ip} NOT "
            "blocked. Re-run elevated to block the attacker.")
        return False

    name = f"{FIREWALL_TAG} {ip}"
    ok = True
    for direction in ("in", "out"):
        rc, _, err = _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={name}", f"dir={direction}", "action=block",
            f"remoteip={ip}",
        ])
        if rc != 0:
            ok = False
            log(f"   [block] {direction}bound rule for {ip} failed ({err.strip()}).")
    if ok:
        log(f"   [block] attacker {ip} BLOCKED at the firewall (in + out).")
    return ok


def unblock_ip(ip):
    """Remove the firewall rules we added for this IP."""
    if not IS_WIN or not is_admin():
        log("   [block] need Administrator on Windows to remove rules - skipped.")
        return False
    name = f"{FIREWALL_TAG} {ip}"
    rc, _, _ = _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={name}"])
    log(f"   [block] removed firewall block for {ip}."
        if rc == 0 else f"   [block] no firewall rule found for {ip}.")
    return rc == 0


def list_blocks():
    """Names of the firewall rules this tool has created."""
    if not IS_WIN:
        return []
    out = _out(["netsh", "advfirewall", "firewall", "show", "rule",
                f"name={FIREWALL_TAG} all"])
    return sorted(set(IPV4_RE.findall(out)))


def clear_all():
    """Undo everything: unpin the gateway and remove every block we added."""
    gw = get_gateway_ip()
    if gw:
        unpin_gateway(gw)
    # Pins from other networks are ours too, so clear those as well.
    clean_stale_pins()
    removed = 0
    for ip in list_blocks():
        if unblock_ip(ip):
            removed += 1
    log(f"   [clear] done. Removed {removed} firewall block(s).")


# ==========================================================================
# 7. Network layer - get back onto the network you trust
# ==========================================================================

def _wait_for_ssid(ssid, timeout=CONNECT_TIMEOUT):
    """Poll until we are associated with `ssid`. Returns the final wifi_state."""
    deadline = time.time() + timeout
    state = wifi_state()
    while time.time() < deadline:
        if state.get("ssid") == ssid:
            return state
        time.sleep(CONNECT_POLL)
        state = wifi_state()
    return state


def disconnect_wifi(interface=None):
    cmd = ["netsh", "wlan", "disconnect"] if IS_WIN else ["nmcli", "dev", "disconnect"]
    if interface:
        cmd.append(f"interface={interface}" if IS_WIN else interface)
    rc, _, err = _run(cmd, timeout=30)
    log("   [restore] disconnected Wi-Fi." if rc == 0
        else f"   [restore] disconnect failed ({err.strip()}).")
    return rc == 0


def connect_wifi(ssid, profile=None, interface=None):
    """Associate with the trusted network using its saved profile."""
    profile = profile or ssid
    if not ssid:
        return False

    if not IS_WIN:
        cmd = ["nmcli", "dev", "wifi", "connect", ssid]
        if interface:
            cmd += ["ifname", interface]
        rc, _, err = _run(cmd, timeout=30)
        if rc != 0:
            log(f"   [restore] nmcli could not connect to '{ssid}' ({err.strip()}).")
        return rc == 0

    cmd = ["netsh", "wlan", "connect", f"name={profile}", f"ssid={ssid}"]
    if interface:
        cmd.append(f"interface={interface}")
    rc, out, err = _run(cmd, timeout=30)
    if rc != 0:
        detail = (err or out).strip()
        log(f"   [restore] could not start the connection to '{ssid}' ({detail}). "
            "The saved Wi-Fi profile may have been deleted - reconnect once "
            "by hand, then re-run:  " + CMD + " --init")
        return False
    return True


def rejoin_trusted(baseline, verify_bssid=True, strict=False):
    """Reconnect to the baseline's Wi-Fi network.

    verify_bssid: after associating, confirm we landed on the SAME access
        point hardware. A matching SSID on different hardware is exactly what
        an evil-twin hotspot looks like.
    strict: if the BSSID still will not match, disconnect rather than stay on
        an access point we cannot vouch for. Off by default, because networks
        with several legitimate APs (offices, mesh kits) roam between BSSIDs
        normally, and dropping the link there would cost you connectivity for
        no gain.
    """
    ssid = baseline.get("ssid")
    profile = baseline.get("wifi_profile") or ssid
    iface = baseline.get("wifi_interface") or baseline.get("interface")
    want_bssid = baseline.get("bssid")

    if not ssid:
        log("   [restore] the baseline has no Wi-Fi network recorded (it was "
            "saved before this feature, or you were on Ethernet). Reconnect "
            "to your normal network and run:  " + CMD + " --init")
        return False

    now = wifi_state()
    if now.get("ssid") == ssid and (not verify_bssid or not want_bssid
                                    or now.get("bssid") == want_bssid):
        log(f"   [restore] already on the trusted network '{ssid}'.")
        return True

    if not in_range(ssid):
        log(f"   [restore] trusted network '{ssid}' is not in range right now, "
            "so there is nothing to reconnect to. Nothing changed.")
        return False

    for attempt in range(1, 4):
        log(f"   [restore] attempt {attempt}/3: connecting to '{ssid}'"
            + (f" on {iface}" if iface else "") + " ...")
        if now.get("ssid") and now.get("ssid") != ssid:
            disconnect_wifi(iface)
            time.sleep(1)
        if not connect_wifi(ssid, profile, iface):
            return False

        now = _wait_for_ssid(ssid)
        if now.get("ssid") != ssid:
            log(f"   [restore] did not associate with '{ssid}' within "
                f"{CONNECT_TIMEOUT}s.")
            continue

        if not verify_bssid or not want_bssid or now.get("bssid") == want_bssid:
            log(f"   [restore] back on '{ssid}' (AP {now.get('bssid')}).")
            return True

        log(f"   [restore] connected to '{ssid}' but the access point is "
            f"{now.get('bssid')}, not the trusted {want_bssid}.")
        disconnect_wifi(iface)
        time.sleep(2)

    # Every attempt landed on the wrong hardware.
    log(f"!! The network named '{ssid}' is being served by an access point "
        f"that is not yours ({now.get('bssid')} instead of {want_bssid}). "
        "That is the fake-hotspot (evil twin) pattern. If this network has "
        "more than one legitimate access point, this is normal roaming - "
        "re-baseline. Otherwise do not send anything sensitive over it.")
    if strict:
        disconnect_wifi(iface)
        log("   [restore] strict mode: stayed off the untrusted access point.")
    else:
        connect_wifi(ssid, profile, iface)   # leave the user online
    return False


def renew_dhcp(alias):
    """Release + renew the lease, then flush the resolver cache."""
    if not IS_WIN:
        rc, _, _ = _run(["dhclient", "-r"], timeout=30)
        _run(["dhclient"], timeout=30)
        return rc == 0
    ok = True
    for verb in ("release", "renew"):
        rc, out, err = _run(["ipconfig", f"/{verb}", alias or "*"], timeout=60)
        if rc != 0:
            ok = False
            log(f"   [restore] ipconfig /{verb} failed ({(err or out).strip()[:120]}). "
                "This usually needs Administrator.")
    _run(["ipconfig", "/flushdns"])
    if ok:
        log(f"   [restore] renewed the DHCP lease on {alias} and flushed DNS.")
    return ok


def restore_dns(alias, source, servers):
    """Put the adapter's DNS servers back to the baseline values."""
    if not alias or not IS_WIN:
        log("   [restore] automatic DNS restore is Windows-only here - skipped.")
        return False
    if not is_admin():
        log("   [restore] need Administrator to set DNS servers - skipped. "
            "Re-run elevated to undo a DNS hijack.")
        return False

    if source == "dhcp" or not servers:
        rc, _, err = _run(["netsh", "interface", "ipv4", "set", "dnsservers",
                           f"name={alias}", "source=dhcp"], timeout=30)
        ok = rc == 0
        log("   [restore] DNS handed back to DHCP (the router)." if ok
            else f"   [restore] could not reset DNS ({err.strip()}).")
    else:
        addrs = [s.strip() for s in servers.split(",") if s.strip()]
        rc, _, err = _run(["netsh", "interface", "ipv4", "set", "dnsservers",
                           f"name={alias}", "source=static",
                           f"address={addrs[0]}", "register=primary",
                           "validate=no"], timeout=30)
        ok = rc == 0
        for i, extra in enumerate(addrs[1:], start=2):
            _run(["netsh", "interface", "ipv4", "add", "dnsservers",
                  f"name={alias}", f"address={extra}", f"index={i}",
                  "validate=no"], timeout=30)
        log(f"   [restore] DNS servers set back to {', '.join(addrs)}." if ok
            else f"   [restore] could not set DNS ({err.strip()}).")
    _run(["ipconfig", "/flushdns"])
    return ok


def set_static_ip(alias, ip, prefix, gateway):
    """Nail the adapter to a fixed address/gateway, ignoring DHCP entirely.

    This is the answer to a rogue DHCP server you cannot out-race: renewing the
    lease is a race you may lose every time, but a static address is not a race
    at all - the attacker's replies stop mattering because we stop asking.
    """
    mask = mask_from_prefix(prefix)
    if not (alias and ip and mask and gateway):
        log("   [ip] baseline has no saved address/subnet/gateway to pin to - "
            "skipped. Re-baseline on the trusted network to enable this.")
        return False
    if not IS_WIN:
        log("   [ip] forcing a static address is Windows-only here - skipped.")
        return False
    if not is_admin():
        log("   [ip] need Administrator to set a static address - skipped. "
            "Re-run elevated to take the address back from a rogue DHCP server.")
        return False

    rc, out, err = _run(["netsh", "interface", "ipv4", "set", "address",
                         f"name={alias}", "static", ip, mask, gateway, "1"],
                        timeout=30)
    ok = rc == 0
    if ok:
        log(f"   [ip] address forced back to {ip}/{prefix} via {gateway} "
            "(static - the rogue DHCP server can no longer move you).")
    else:
        log(f"   [ip] could not set the static address ({(err or out).strip()[:160]}).")
    return ok


def set_dhcp_ip(alias):
    """Hand the adapter back to DHCP (undo set_static_ip)."""
    if not alias or not IS_WIN:
        return False
    if not is_admin():
        log("   [ip] need Administrator to hand the address back to DHCP - skipped.")
        return False
    rc, out, err = _run(["netsh", "interface", "ipv4", "set", "address",
                         f"name={alias}", "source=dhcp"], timeout=30)
    log("   [ip] address handed back to DHCP." if rc == 0
        else f"   [ip] could not switch back to DHCP ({(err or out).strip()[:160]}).")
    return rc == 0


def reclaim_address(baseline, alias, tries=2):
    """Get back onto the baseline's subnet after a DHCP-level hijack.

    Try the polite way first (renew the lease - if the real server wins the
    race we are done and stay on DHCP), then the decisive one (static address).
    Returns True once the gateway matches the baseline again.
    """
    want_gw = baseline.get("gateway_ip")
    want_ip = baseline.get("local_ip")
    prefix = (baseline.get("subnet") or "").partition("/")[2] or None

    for attempt in range(1, tries + 1):
        log(f"   [ip] renew attempt {attempt}/{tries} - asking for a fresh lease ...")
        renew_dhcp(alias)
        if get_gateway_ip() == want_gw:
            log(f"   [ip] the real DHCP server answered - gateway is {want_gw} again.")
            return True
        time.sleep(1)

    log("   [ip] the rogue server keeps winning the lease. Taking the address "
        "back by force.")
    if not set_static_ip(alias, want_ip, prefix, want_gw):
        return False
    # A static address is only useful if the real gateway is actually reachable
    # from it; say so plainly rather than leaving a silently dead link.
    time.sleep(1)
    if get_gateway_ip() != want_gw:
        log("   [ip] the static address did not take effect - check the adapter by hand.")
        return False
    if not get_gateway_mac(want_gw):
        log("   [ip] WARNING: pinned to the trusted address, but the real "
            "gateway is not answering. You may be on an attacker-controlled "
            "access point where your router does not exist. Treat this link "
            "as hostile; switch networks if you can.")
    return True


def quarantine(baseline, reason=""):
    """Last resort: cut the link rather than keep using a hijacked one.

    Only ever called with --strict. Being offline is a safe state; being
    silently proxied is not.
    """
    iface = baseline.get("wifi_interface") or baseline.get("interface")
    log(f"   [quarantine] {reason} Disconnecting rather than staying on a "
        "network we cannot trust.")
    return disconnect_wifi(iface)


def restore(baseline, current=None, strict=False):
    """Put the machine back on the network recorded in `baseline`.

    Handles, in order, the things that actually move you off your network:
      wrong SSID / wrong access point       -> reconnect to the trusted one
      wrong gateway IP on the right network -> renew the DHCP lease
      changed DNS servers                   -> set them back

    Returns True when the machine ends up matching the baseline again.
    """
    current = current or snapshot(check_public=False)

    if not baseline:
        log("   [restore] no baseline to return to. Run: " + CMD + " --init")
        return False

    log("Restoring the trusted network:")

    # 1. Right network, right hardware.
    wifi_ok = True
    if baseline.get("ssid"):
        cur_ssid, cur_bssid = current.get("ssid"), current.get("bssid")
        if cur_ssid is None:
            # A failed read is not evidence of being on the wrong network.
            # compare() already ignores None for exactly this reason, and
            # acting on one here would drop a perfectly good connection over a
            # single unlucky poll - a repair worse than the problem.
            log("   [restore] could not read the Wi-Fi state this cycle, so "
                "there is nothing trustworthy to act on. Leaving the "
                "connection alone.")
        elif (cur_ssid != baseline["ssid"]
              or (baseline.get("bssid") and cur_bssid
                  and cur_bssid != baseline["bssid"])):
            wifi_ok = rejoin_trusted(baseline, strict=strict)
        else:
            log(f"   [restore] Wi-Fi already correct ('{baseline['ssid']}').")
    elif current.get("ssid"):
        log(f"   [restore] baseline was not on Wi-Fi, but you are now on "
            f"'{current['ssid']}'. Not touching it - re-baseline if that is "
            "your normal network.")

    # Settings below are per-adapter, so read the adapter we ended up on.
    fresh = net_snapshot()
    alias = fresh.get("interface") or baseline.get("interface")

    # 2. Right subnet. On the right Wi-Fi this is a DHCP-level hijack; on the
    #    wrong one it is just a stale lease from the network we came from.
    gw_ok = True
    base_gw, cur_gw = baseline.get("gateway_ip"), get_gateway_ip()
    base_srv = baseline.get("dhcp_server")
    cur_srv = fresh.get("dhcp_server")
    hijacked = rogue_dhcp(baseline, {**current, "gateway_ip": cur_gw, **fresh})

    if base_gw and cur_gw and base_gw != cur_gw and wifi_ok:
        if hijacked:
            log(f"   [restore] gateway is {cur_gw}, expected {base_gw} - and "
                "this is the trusted Wi-Fi and access point. Something on "
                "this network is answering DHCP in the router's place.")
            if base_srv and cur_srv and base_srv != cur_srv:
                log(f"   [restore] the lease came from {cur_srv}, not the "
                    f"trusted {base_srv}.")
            gw_ok = reclaim_address(baseline, alias)
            if not gw_ok and strict:
                quarantine(baseline, "Could not take the address back.")
        else:
            log(f"   [restore] gateway is {cur_gw}, expected {base_gw} - renewing "
                "the DHCP lease.")
            renew_dhcp(alias)
            gw_ok = get_gateway_ip() == base_gw
    elif hijacked and base_srv and cur_srv and base_srv != cur_srv:
        # Same gateway address, different server behind it: a rogue server can
        # copy the router's gateway value and still hijack DNS. Force a clean
        # lease so the real server's options win.
        log(f"   [restore] the DHCP lease now comes from {cur_srv}, not the "
            f"trusted {base_srv}, on the same gateway address. Renewing.")
        renew_dhcp(alias)

    # 3. Right resolvers - but only once we are actually back on the trusted
    #    network. A baseline's DNS server is usually its own router (a private
    #    LAN address), so applying it from a different network would point the
    #    resolver at an address that does not exist there and take DNS down
    #    completely. Repairing must never be worse than the problem.
    dns_ok = True
    base_dns = baseline.get("dns_servers")
    fresh = net_snapshot()   # step 2 may have changed the addressing
    if base_dns and fresh.get("dns_servers") and fresh["dns_servers"] != base_dns:
        if wifi_ok and gw_ok:
            log(f"   [restore] DNS is {fresh['dns_servers']}, expected {base_dns}.")
            dns_ok = restore_dns(alias, baseline.get("dns_source"), base_dns)
        else:
            log(f"   [restore] DNS is {fresh['dns_servers']}, expected "
                f"{base_dns} - leaving it alone, because we are not back on "
                "the trusted network and those servers would not be "
                "reachable from here.")
            dns_ok = False

    # Verify against the baseline rather than trusting the steps above.
    after = snapshot(check_public=False)
    left = [label for _, label, old, new, _ in compare(baseline, after)]
    if not left:
        log("   [restore] done - you are back on the trusted network.")
        return True
    log("   [restore] still different after restoring: " + ", ".join(left)
        + ". If this network is legitimately your new normal, re-baseline "
          "with:  " + CMD + " --init")
    return wifi_ok and gw_ok and dns_ok and not left


# ==========================================================================
# 8. The response - pick the right countermeasure for what was actually found
# ==========================================================================

def defend_rogue_dhcp(baseline, current, do_block=True, do_pin=True):
    """React to a DHCP-level hijack: the router's ADDRESS moved, not its MAC.

    No ARP entry was poisoned here, so there is nothing to correct with ARP.
    The machine was simply handed a lease pointing at the attacker. The order
    below matters: take the address back FIRST, because while the attacker is
    still our default gateway, blocking them at the firewall would cut off our
    own connectivity instead of theirs.
    """
    rogue_gw = current.get("gateway_ip")
    rogue_mac = current.get("gateway_mac")
    real_gw = baseline.get("gateway_ip")
    real_mac = baseline.get("gateway_mac")

    log(f"   [defend] the gateway ADDRESS changed ({real_gw} -> {rogue_gw}) "
        "while the Wi-Fi and access point stayed the same. Your router did "
        "not move, so something here is answering DHCP in its place and "
        "pointing you at itself.")
    if rogue_mac:
        log(f"   [defend] the impostor gateway {rogue_gw} is at {rogue_mac}.")

    alias = current.get("interface") or baseline.get("interface")
    recovered = reclaim_address(baseline, alias)

    if not recovered:
        log("   [defend] still on the hijacked lease - NOT blocking the "
            "impostor, because it is currently your only route out. Treat "
            "this link as hostile until it is fixed.")
        return False

    # Now that traffic no longer depends on them, cut them off.
    if do_block and rogue_mac:
        suspects = {rogue_gw} | set(find_attacker_ips(rogue_mac, real_gw))
        suspects.discard(real_gw)
        for ip in sorted(s for s in suspects if s):
            block_ip(ip)

    if do_pin and real_gw and real_mac:
        pin_gateway(real_gw, real_mac)
    return True


def defend(baseline, current, do_correct=True, do_pin=True, do_block=True):
    """React to a detected gateway-MAC change (i.e. ARP spoofing).

    The real MAC is the baseline's; the spoofed MAC is what we see now.
    """
    gateway_ip = current.get("gateway_ip") or baseline.get("gateway_ip")
    real_mac = baseline.get("gateway_mac")
    spoofed_mac = current.get("gateway_mac")

    if not gateway_ip or not real_mac:
        log("   [defend] missing gateway IP or trusted MAC - cannot respond. "
            "Re-baseline on a clean network with:  " + CMD + " --init")
        return

    # Spoofing = SAME gateway IP, DIFFERENT MAC. A changed gateway ADDRESS is a
    # different problem with a different answer, so hand it to the code that
    # owns it - correcting ARP with a stale MAC would poison our own table.
    if baseline.get("gateway_ip") and current.get("gateway_ip") \
            and baseline["gateway_ip"] != current["gateway_ip"]:
        if rogue_dhcp(baseline, current):
            return defend_rogue_dhcp(baseline, current)
        log(f"   [defend] gateway IP changed ({baseline['gateway_ip']} -> "
            f"{current['gateway_ip']}) and so did the Wi-Fi, so this is a "
            "different network, not spoofing. Not responding. Re-baseline "
            "here if it is trusted:  " + CMD + " --init")
        return

    log(f"   [defend] responding: real gateway {gateway_ip} = {real_mac}, "
        f"currently spoofed as {spoofed_mac}.")

    # 1. Re-teach the LAN (and ourselves) the correct mapping.
    if do_correct:
        send_corrective_arp(gateway_ip, real_mac)

    # 2. Pin the real gateway so a repeat poisoning of the gateway entry fails.
    if do_pin:
        pin_gateway(gateway_ip, real_mac)

    # 3. Find who did it and cut them off.
    if do_block:
        suspects = find_attacker_ips(spoofed_mac, gateway_ip)
        if suspects:
            log(f"   [defend] attacker MAC {spoofed_mac} also owns IP(s): "
                + ", ".join(suspects))
            for ip in suspects:
                block_ip(ip)
        else:
            log(f"   [defend] the spoofing MAC {spoofed_mac} does not expose a "
                "second IP in the ARP table, so there is no attacker IP to "
                "block yet. The gateway pin above still stops the poisoning.")


def _defend_bounded(baseline, current, state=None):
    """Fire the countermeasures, but not forever.

    A response that cannot clear the problem should not re-run every cycle for
    hours - the alert already stands.
    """
    tries = state.get("defend_tries", 0) if state is not None else 0
    if tries >= MAX_DEFEND_TRIES:
        if tries == MAX_DEFEND_TRIES:   # say this once, then stay quiet
            log(f"     (responded {tries}x to this same change without clearing "
                "it - not retrying. The alert stands: treat this connection as "
                "hostile until it is fixed.)")
            if state is not None:
                state["defend_tries"] = tries + 1
        return
    if state is not None:
        state["defend_tries"] = tries + 1
    try:
        defend(baseline, current)
    except Exception as exc:
        log(f"     (defense error: {exc})")


def _restore_bounded(baseline, current, state, strict=False):
    """Reconnect to the trusted network, with a per-problem attempt count so a
    network we simply cannot get back onto (out of range, profile deleted) does
    not send us into an endless reconnect loop every cycle."""
    tries = state.get("restore_tries", 0) if state is not None else 0
    if tries >= MAX_RESTORE_TRIES:
        if tries == MAX_RESTORE_TRIES:   # say this once, then stop repeating it
            log(f"     (tried to reconnect {tries}x for this change without "
                "success - not retrying. Reconnect by hand, or re-baseline if "
                "this network is now your normal one.)")
            if state is not None:
                state["restore_tries"] = tries + 1
        return
    if state is not None:
        state["restore_tries"] = tries + 1
    try:
        restore(baseline, current, strict=strict)
    except Exception as exc:
        log(f"     (restore error: {exc})")


def _harden_once(baseline, state=None):
    """Pin the trusted gateway while the network is still clean. Runs once."""
    if state is not None and state.get("hardened"):
        return
    try:
        ok = harden(baseline)
    except Exception as exc:
        log(f"     (harden error: {exc})")
        ok = False
    # Only mark it done if it actually stuck; a failure here should be retried
    # on the next healthy cycle (e.g. the adapter was still coming up).
    if state is not None and ok:
        state["hardened"] = True


def _report_duplicates(state=None):
    """Warn when one machine is answering for several addresses.

    Visible even when the baseline comparison is clean - an attacker poisoning
    a neighbour, or one caught mid-poison, shows up here first.
    """
    try:
        dupes = duplicate_macs()
    except Exception:
        return
    signature = tuple(sorted((mac, tuple(ips)) for mac, ips in dupes.items()))
    if state is not None and state.get("dupes") == signature:
        return   # already said this
    if state is not None:
        state["dupes"] = signature
    for mac, ips in dupes.items():
        log(f"NOTE: {mac} is answering for {len(ips)} addresses ({', '.join(ips)}). "
            "One machine holding several addresses is the ARP-spoofing "
            "footprint - worth knowing who that is.")


def _report_capabilities():
    """Say up front which countermeasures can actually run.

    Every active step degrades silently by design, so without this the log
    reads like you are protected when in fact nothing can be undone.
    """
    admin, scapy = is_admin(), have_scapy()
    log(f"   Administrator: {'yes' if admin else 'NO'}    "
        f"scapy+Npcap: {'yes' if scapy else 'no'}")
    if not admin:
        log("   Without Administrator this can detect and warn, but it cannot "
            "pin the gateway, block anyone, or take an address back. Re-run "
            "and click YES on the prompt for real protection.")
    if not scapy:
        log("   This PC can still be protected, but the rest of the LAN cannot "
            "be re-taught the real gateway MAC. " + (scapy_problem() or ""))


def _respond(baseline, current, spoofed, hijacked, left_net, state,
             do_defend, do_restore, strict, repeat=False):
    """Do something about what we found, according to what it actually is.

    On a `repeat` cycle the responses still run, but the advice and headers
    have already been said once, so they are not said again.
    """
    def say(message):
        if not repeat:
            log(message)

    # A hijack is both a MAC change and an address change, so it must be
    # decided first - and it has one owner, not two, or the address would be
    # reclaimed twice per cycle.
    if hijacked:
        if do_defend:
            say("Active defense enabled - taking the network back:")
            _defend_bounded(baseline, current, state)
        elif do_restore:
            say("Auto-restore enabled - taking the address back:")
            _restore_bounded(baseline, current, state, strict=strict)
        else:
            say("     To take the network back:  " + CMD + " --protect")
        return

    if do_defend and spoofed:
        say("Active defense enabled - responding to the spoofing:")
        _defend_bounded(baseline, current, state)
    elif spoofed:
        say("     To respond to this:  " + CMD + " --protect")

    if do_restore and left_net:
        say("Auto-restore enabled - returning to the trusted network:")
        _restore_bounded(baseline, current, state, strict=strict)
    elif left_net:
        say("     To go back to your normal network:  " + CMD + " --restore")


def check(check_public=True, state=None, do_defend=False, do_restore=False,
          strict=False, do_harden=False):
    """One check cycle.

    `state` carries memory across cycles in watch mode so a change that is
    still present is not re-alerted (with beeps) every single cycle.

    `do_defend` (opt-in) fires active countermeasures: corrective ARP + pin +
    block for ARP spoofing, and taking the address back for a DHCP hijack.

    `do_restore` (opt-in) reconnects you to the baseline network when the
    change means you have left it (different Wi-Fi, AP, subnet or DNS).

    `do_harden` (opt-in) pins the trusted gateway while the network is still
    clean, so poisoning never takes hold in the gap between two polls.
    """
    baseline = load_baseline()
    if baseline is None:
        log("No baseline found. Run:  " + CMD + " --init")
        return 2

    current = snapshot(check_public)
    if current["gateway_ip"] is None:
        log("WARNING: could not read the default gateway (network down?)")
        # Being dropped off the network entirely is exactly the case where you
        # want to be put back on it, so try - don't just warn and give up.
        if do_restore and baseline.get("ssid"):
            if state is not None and state.get("last") != "NETDOWN":
                state["restore_tries"] = 0   # a fresh problem gets fresh tries
                state["last"] = "NETDOWN"
            log("Auto-restore enabled - trying to get back on the trusted network:")
            _restore_bounded(baseline, current, state, strict=strict)
        return 3

    changes = compare(baseline, current)
    signature = tuple(sorted((label, old, new) for _, label, old, new, _ in changes))
    repeat = state is not None and state.get("last") == signature
    if state is not None:
        if not repeat:
            # A new/changed problem gets a fresh budget of attempts.
            state["restore_tries"] = 0
            state["defend_tries"] = 0
        state["last"] = signature
        state["cycle"] = state.get("cycle", 0) + 1

    if not changes:
        if state is not None:
            state["restore_tries"] = 0   # healthy again: allow future attempts
            state["defend_tries"] = 0
        # The network is clean, which is exactly when locking it down works.
        if do_harden:
            _harden_once(baseline, state)
        _report_duplicates(state)
        if repeat:
            # Steady state: log to file only every 10th cycle to keep it small.
            log(f"OK - router unchanged (gateway {current['gateway_ip']})",
                to_file=state["cycle"] % 10 == 0)
        else:
            log(f"OK - router unchanged (gateway {current['gateway_ip']}, "
                f"mac {current['gateway_mac']}, public {current['public_ip']})")
        return 0

    # Same Wi-Fi and same access point, but the addressing moved: the router
    # did not go anywhere, so something here is impersonating it.
    hijacked = rogue_dhcp(baseline, current)

    # ARP spoofing is specifically a NEW MAC ON THE SAME ADDRESS. If the gateway
    # address moved too, the MAC was always going to differ - it is a different
    # router - so calling that spoofing would be a false positive every time you
    # join another network.
    gw_moved = any(key == "gateway_ip" for key, *_ in changes)
    spoofed = (not gw_moved) and any(kind == "arp" for *_, kind in changes)
    left_net = (not hijacked) and any(kind == "net" for *_, kind in changes)

    if repeat:
        log("Change still present (already alerted above) - staying quiet.",
            to_file=False)
        # Keep responding, up to the try limits: the trusted network may simply
        # have been out of range, or the attacker may still be pushing.
        _respond(baseline, current, spoofed, hijacked, left_net, state,
                 do_defend, do_restore, strict, repeat=True)
        return 1

    changed = {key for key, *_ in changes}
    # Only "Expected" if you really did join something else. On the same Wi-Fi
    # name, a new router is a hijack or an evil twin, not a reason to relax.
    joined_other = bool(changed & {"ssid", "interface"})

    for position, (key, label, old, new, kind) in enumerate(changes):
        alert(f"{label} CHANGED:  {old}  ->  {new}", beep=position == 0)
        if kind == "arp" and spoofed:
            log("     ^ Same network, same router address, different hardware. "
                "This is what ARP spoofing or a rogue router looks like. "
                "Investigate before sending anything sensitive over this "
                "connection.")
        elif kind == "arp" and joined_other:
            log("     ^ Expected: the gateway address changed too, so this is "
                "simply a different router answering - not ARP spoofing.")
        elif kind == "arp":
            log("     ^ The gateway address changed too, so this is not ARP "
                "spoofing - but a different machine is acting as your router "
                "on what should be the same network. See below.")
        elif kind == "net":
            log("     ^ " + _why(key, baseline, current, changed))

    if hijacked:
        log("     ^^ You are still on the SAME Wi-Fi and the SAME access point, "
            "so your router did not move. Something on this network is "
            "impersonating it and your traffic is going through that machine.")

    _respond(baseline, current, spoofed, hijacked, left_net, state,
             do_defend, do_restore, strict)

    log("If this change was you (new router, new Wi-Fi, ISP reset), re-baseline "
        "with: " + CMD + " --init")
    return 1


def watch_forever(interval, check_public=True, do_defend=False,
                  do_restore=False, strict=False, do_harden=False):
    """Keep checking until Ctrl+C."""
    extras = [name for name, on in (("hardening", do_harden),
                                    ("active defense", do_defend),
                                    ("auto-restore", do_restore)) if on]
    log(f"Watching router every {interval}s"
        + (" with " + ", ".join(extras) if extras else "")
        + ". Ctrl+C to stop.")
    if extras:
        _report_capabilities()
    state = {}
    try:
        while True:
            check(check_public, state, do_defend=do_defend,
                  do_restore=do_restore, strict=strict, do_harden=do_harden)
            time.sleep(interval)
    except KeyboardInterrupt:
        log("Stopped.")
    return 0


def do_init(check_public=True, force=False):
    """Record the current network as the one you trust."""
    current = snapshot(check_public)
    if current["gateway_ip"] is None:
        log("Cannot baseline: no default gateway found. Are you connected?")
        return 3

    hazards = init_hazards(current, load_baseline())
    if hazards and not force:
        log("REFUSING to record this network as trusted:")
        for reason in hazards:
            log("   - " + reason)
        log("Saving now would store the attacker as your router, and every "
            "check afterwards would say everything is fine. Get onto a "
            "clean network first.")
        log("If you are certain this is legitimate (you really did change "
            "router or ISP hardware), override with:  "
            "" + CMD + " --init --force")
        return 4
    if hazards:
        log("--force given: saving despite the warnings above.")

    # Pins are per-network. Carrying yesterday's into a new baseline leaves a
    # static ARP entry silently overriding a network it knows nothing of.
    try:
        clean_stale_pins(keep_ip=current["gateway_ip"])
    except Exception:
        pass

    save_baseline(current)
    log("Baseline saved:")
    print(json.dumps(current, indent=2))
    log("Protect this network with:  " + CMD + " --protect")
    return 0


# ==========================================================================
# 9. IP comparison helper
# ==========================================================================

def parse_ip(value):
    """Return an IPv4Address/IPv6Address, or None if the text is not an IP."""
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None


def normalize(ip):
    """Collapse IPv4-mapped IPv6 (::ffff:1.2.3.4) down to plain IPv4.

    Without this, ::ffff:192.168.1.10 and 192.168.1.10 compare as different
    even though they address the same host.
    """
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def ip_in_network(ip_str, net_str):
    """True if ip_str falls inside the CIDR range net_str (e.g. 10.0.0.0/8)."""
    ip = parse_ip(ip_str)
    if ip is None:
        return False
    try:
        net = ipaddress.ip_network(str(net_str).strip(), strict=False)
    except ValueError:
        return False
    return normalize(ip).version == net.version and normalize(ip) in net


def compare_ips(first, second):
    """Compare two inputs; the second may be an IP or a CIDR network."""
    ip_a = parse_ip(first)
    if ip_a is None:
        return False, f"'{first}' is not a valid IP address"

    if "/" in str(second):
        if ip_in_network(first, second):
            return True, f"{first} is INSIDE the range {second}"
        return False, f"{first} is NOT inside the range {second}"

    ip_b = parse_ip(second)
    if ip_b is None:
        return False, f"'{second}' is not a valid IP address"

    if normalize(ip_a) == normalize(ip_b):
        return True, f"SAME  -> {first} and {second} are the same IP ({normalize(ip_a)})"
    return False, f"DIFFERENT -> {first} and {second} are not the same IP"


# ==========================================================================
# 10. The desktop app
# ==========================================================================

POLL_MS = 100   # how often the UI drains its work queue

# --- console palette ------------------------------------------------------
# Monochrome phosphor-green terminal, Matrix/old-hacker-movie style: pure
# black background, everything else a shade of green except the two colours
# that carry real meaning (amber = degraded, red = intrusion) - those stay
# visually distinct on purpose, so a red row is still unmistakable.
DEEP   = "#000000"    # window background
PANEL  = "#001a02"    # cards
PANEL2 = "#002b05"    # raised rows / headers
TERM   = "#000000"    # the log
EDGE   = "#124a1f"    # borders
GRID   = "#0b3312"    # separators

GREEN  = "#00ff41"    # good / armed - the Matrix green
GREENQ = "#0a5c1f"    # dim green - selection fill
CYAN   = "#39ff6a"    # headings, accents (bright green, kept as CYAN name
                       # so every existing reference below just goes green)
AMBER  = "#ffcc00"    # warning / degraded
RED    = "#ff3b3b"    # bad / intrusion
TEXT   = "#8fff9f"    # normal text
DIM    = "#4f9a5e"    # muted text - still has to be readable on PANEL

MONO   = "Courier New"

BANNER = {
    "ok":       (GREEN, "SECURE", "no intrusion detected"),
    "alert":    (RED,   "INTRUSION", "your network changed"),
    "nobase":   (AMBER, "NO BASELINE", "nothing to compare against yet"),
    "netdown":  (AMBER, "LINK DOWN", "cannot read the gateway"),
    "idle":     (DIM,   "STANDBY", "not scanning"),
    "watching": (CYAN,  "ARMED", "scanning this network"),
}
CODE_TO_STATE = {0: "ok", 1: "alert", 2: "nobase", 3: "netdown"}

# Cosmetic only: a boxed banner dropped into the console the moment the
# console *actually* enters that state (never spammed on every re-check of
# the same state - see _set_banner). The state itself is always genuine.
def _box(text, width=46):
    top = "╔" + "═" * width + "╗"
    mid = "║" + text.center(width) + "║"
    bot = "╚" + "═" * width + "╝"
    return "\n".join((top, mid, bot))

ASCII_ART = {
    "alert":    _box("!! INTRUSION DETECTED - NETWORK COMPROMISED !!"),
    "watching": _box("DEFENSE MATRIX :: ARMED"),
}

RAIN_CHARS   = "01ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%&*+=<>/\\|"
GLITCH_CHARS = "!@#$%^&*<>/\\|01XO#?"


class App:
    # The fingerprint table, in display order.
    ROWS = [
        ("SSID",        "ssid"),
        ("AP / BSSID",  "bssid"),
        ("GATEWAY IP",  "gateway_ip"),
        ("GATEWAY MAC", "gateway_mac"),
        ("DNS",         "dns_servers"),
        ("WAN IP",      "public_ip"),
    ]

    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk

        self.root = root
        root.title("MITM TRACKER  //  defence console")
        # Fit the screen we are actually on: a fixed 900px tall window gets
        # clamped on a 768/864px laptop display, which silently crushes the
        # console pane down to a couple of lines.
        # Sizes below are at 100% display scaling; fonts follow Windows scaling
        # on their own, so the window has to grow with them.
        self.ui_scale = max(1.0, root.winfo_fpixels("1i") / 96)
        s = self.ui_scale
        want_h = min(int(880 * s),
                     max(int(620 * s), root.winfo_screenheight() - int(120 * s)))
        want_w = min(int(1000 * s),
                     max(int(970 * s), root.winfo_screenwidth() - int(120 * s)))
        root.geometry(f"{want_w}x{want_h}")
        # 970 is what the widest row (fingerprint + verdict column) actually
        # needs; below that the right-hand controls fall off the edge.
        root.minsize(int(970 * s), int(560 * s))
        root.configure(bg=DEEP)

        icon = resource_path(ICON_NAME)
        if icon:
            try:
                root.iconbitmap(icon)
            except Exception:
                pass   # a missing or unreadable icon must never stop the app

        # Cross-thread work queue: background threads push callables, the UI
        # thread runs them. This is the only safe way to touch widgets.
        self.ui_q = queue.Queue()
        self.busy = threading.Lock()        # serialises heavy manual actions
        self.watch_stop = threading.Event()
        self.watch_thread = None
        self.tabs = {}

        self._build()

        # Route every log line into our console pane.
        LOG_SINKS.append(lambda line: self.ui_q.put(lambda: self._append(line)))

        self.root.after(POLL_MS, self._drain)
        self._boot_lines()
        self.refresh_status()
        self.refresh_defender()
        self.refresh_devices()

    # ------------------------------------------------------- small widgets
    def _blink_cursor(self):
        """Toggle the block cursor beside the title, like a live terminal prompt."""
        # Blink the colour, not the text: an empty label has no width, which
        # made everything to the right of the cursor jump on every blink.
        shown = self.title_cursor.cget("fg") == GREEN
        self.title_cursor.config(fg=DEEP if shown else GREEN)
        self.root.after(530, self._blink_cursor)

    def _btn(self, parent, text, command, kind="ghost", width=None):
        """A flat console button with a hover state.

        Plain tk.Button, not ttk: on Windows the native ttk themes ignore
        background colour outright, so a dark theme is impossible with them.
        """
        tk = self.tk
        colours = {
            "primary": (GREEN,  DEEP,  "#8cffad"),
            "danger":  (RED,    DEEP,  "#ff7a7a"),
            "ghost":   (PANEL2, TEXT,  "#0a3d16"),
        }
        bg, fg, hover = colours[kind]
        b = tk.Button(parent, text=text, command=command,
                      bg=bg, fg=fg, activebackground=hover, activeforeground=fg,
                      font=(MONO, 9, "bold" if kind != "ghost" else "normal"),
                      relief="flat", bd=0, padx=14, pady=7,
                      cursor="hand2", highlightthickness=1,
                      highlightbackground=EDGE, highlightcolor=EDGE,
                      # DIM vanishes on the red of a disabled STOP.
                      disabledforeground="#6e0f0f" if kind == "danger" else DIM)
        if width:
            b.config(width=width)
        b.bind("<Enter>", lambda e: b["state"] == "normal" and b.config(bg=hover))
        b.bind("<Leave>", lambda e: b.config(bg=bg))
        b._base_bg = bg
        return b

    def _check(self, parent, text, var):
        tk = self.tk
        return tk.Checkbutton(parent, text=text, variable=var,
                              bg=PANEL, fg=TEXT, selectcolor=DEEP,
                              activebackground=PANEL, activeforeground=CYAN,
                              font=(MONO, 9), bd=0, highlightthickness=0,
                              cursor="hand2")

    def _panel(self, parent, title=None):
        """A bordered card with an optional header strip."""
        tk = self.tk
        outer = tk.Frame(parent, bg=EDGE)          # 1px border via padding
        inner = tk.Frame(outer, bg=PANEL)
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        if title:
            head = tk.Frame(inner, bg=PANEL2)
            head.pack(fill="x")
            tk.Label(head, text="  " + title, bg=PANEL2, fg=CYAN,
                     font=(MONO, 8, "bold"), anchor="w").pack(
                side="left", pady=5)
        return outer, inner

    # -------------------------------------------------------------- layout
    def _build(self):
        tk = self.tk

        # ---------- title bar ----------
        top = tk.Frame(self.root, bg=DEEP)
        top.pack(fill="x", padx=16, pady=(14, 0))

        logo = resource_path(LOGO_NAME)
        logo_shown = False
        if logo:
            try:
                # Held on self because Tk keeps only a weak reference to image
                # data - drop the last Python reference and the logo blanks out.
                self.logo_img = tk.PhotoImage(file=logo)
                tk.Label(top, image=self.logo_img, bg=DEEP).pack(
                    side="left", padx=(0, 10))
                logo_shown = True
            except Exception:
                pass   # same rule as the window icon: art must never block boot
        if not logo_shown:
            # No image asset on disk (or it failed to load) - an ASCII mark
            # keeps the title bar from looking bare, no art file required.
            tk.Label(top, text="☠", bg=DEEP, fg=GREEN,
                     font=(MONO, 16, "bold")).pack(side="left", padx=(0, 8))

        tk.Label(top, text=">_ MITM TRACKER", bg=DEEP, fg=GREEN,
                 font=(MONO, 15, "bold")).pack(side="left")
        self.title_cursor = tk.Label(top, text="█", bg=DEEP, fg=GREEN,
                                     font=(MONO, 15, "bold"))
        self.title_cursor.pack(side="left")
        self._blink_cursor()
        tk.Label(top, text="  //  man-in-the-middle defence console",
                 bg=DEEP, fg=DIM, font=(MONO, 9)).pack(side="left", pady=(6, 0))

        admin = is_admin()
        self.priv_lbl = tk.Label(
            top, bg=DEEP, font=(MONO, 9, "bold"),
            fg=GREEN if admin else AMBER,
            text=("[ PRIVILEGE: ADMIN ]" if admin else "[ PRIVILEGE: LIMITED ]"))
        self.priv_lbl.pack(side="right", pady=(4, 0))

        if not admin:
            tk.Label(self.root, bg=DEEP, fg=AMBER, font=(MONO, 8),
                     anchor="w", justify="left", wraplength=int(940 * self.ui_scale),
                     text="! running without Administrator - it can DETECT and "
                          "warn, but it cannot pin the gateway, block anyone, "
                          "or take an address back. Close this and reopen it, "
                          "clicking YES."
                     ).pack(fill="x", padx=16, pady=(4, 0))

        # ---------- status readout ----------
        wrap, self.status_card = self._panel(self.root)
        wrap.pack(fill="x", padx=16, pady=9)
        bar = tk.Frame(self.status_card, bg=PANEL)
        bar.pack(fill="x", padx=14, pady=9)

        self.dot = tk.Frame(bar, bg=DIM, width=12, height=12)
        self.dot.pack(side="left", pady=(4, 0))
        self.dot.pack_propagate(False)

        texts = tk.Frame(bar, bg=PANEL)
        texts.pack(side="left", padx=12, fill="x", expand=True)
        self.banner = tk.Label(texts, text="", bg=PANEL, fg=DIM,
                               font=(MONO, 17, "bold"), anchor="w")
        self.banner.pack(fill="x")
        self.subtitle = tk.Label(texts, text="", bg=PANEL, fg=DIM,
                                 font=(MONO, 9), anchor="w")
        self.subtitle.pack(fill="x")

        self.clock = tk.Label(bar, text="", bg=PANEL, fg=DIM, font=(MONO, 9))
        self.clock.pack(side="right", pady=(4, 0))
        self._set_banner("idle")

        # ---------- tab strip (custom: ttk notebooks will not go dark) -----
        strip = tk.Frame(self.root, bg=DEEP)
        strip.pack(fill="x", padx=16)
        self.tabbtns = {}
        for name in ("WATCHDOG", "DEVICES", "DEFENDER"):
            b = tk.Label(strip, text=f"  {name}  ", bg=DEEP, fg=DIM,
                         font=(MONO, 10, "bold"), pady=8, cursor="hand2")
            b.pack(side="left", padx=(0, 2))
            b.bind("<Button-1>", lambda e, n=name: self.show_tab(n))
            self.tabbtns[name] = b
        tk.Frame(self.root, bg=EDGE, height=1).pack(fill="x", padx=16)

        body = tk.Frame(self.root, bg=DEEP)
        self.body = body
        # The tabs live in a canvas so that a tab taller than the window can
        # scroll. Without this, whatever did not fit was simply unreachable:
        # on a laptop screen that was SET BASELINE, SCAN ONCE and MANUAL SCAN.
        self.tab_canvas = tk.Canvas(body, bg=DEEP, highlightthickness=0, bd=0,
                                    height=1, yscrollincrement=24)
        self.tab_scroll = tk.Scrollbar(body, command=self.tab_canvas.yview,
                                       bg=PANEL2, troughcolor=TERM,
                                       activebackground=CYAN, bd=0,
                                       highlightthickness=0, width=12)
        self.tab_canvas.config(yscrollcommand=self.tab_scroll.set)
        self.tab_canvas.pack(side="left", fill="both", expand=True)
        self.tab_host = tk.Frame(self.tab_canvas, bg=DEEP)
        host_id = self.tab_canvas.create_window(0, 0, window=self.tab_host,
                                                anchor="nw")
        self.tab_canvas.bind(
            "<Configure>",
            lambda e: self.tab_canvas.itemconfigure(host_id, width=e.width))
        self.tab_host.bind("<Configure>", lambda e: self._fit_tabs())
        self.root.bind("<Configure>", lambda e: self._fit_tabs(), add="+")
        self.root.bind_all("<MouseWheel>", self._on_tab_wheel, add="+")
        self._build_watch_tab(self.tab_host)
        self._build_devices_tab(self.tab_host)
        self._build_defender_tab(self.tab_host)

        # ---------- console log ----------
        # Packed to the BOTTOM before the tab area, so it always keeps its
        # own height. Packed after, it is last in line for leftover space and
        # collapses to a single line on a short screen.
        logwrap, loginner = self._panel(self.root)
        logwrap.pack(side="bottom", fill="both", expand=True,
                     padx=16, pady=(10, 14))

        lbar = tk.Frame(loginner, bg=PANEL2)
        lbar.pack(fill="x")
        tk.Label(lbar, text="  CONSOLE", bg=PANEL2, fg=CYAN,
                 font=(MONO, 8, "bold")).pack(side="left", pady=5)
        self.logcount = tk.Label(lbar, text="0 lines", bg=PANEL2, fg=DIM,
                                 font=(MONO, 8))
        self.logcount.pack(side="left", padx=10)
        # Clearing matters: start/stop/start/stop piles up thousands of lines
        # and there is no terminal to reach for.
        self._btn(lbar, "CLEAR", self.clear_log).pack(side="right", padx=6, pady=3)
        self.autoscroll_var = self.tk.BooleanVar(value=True)
        c = self._check(lbar, "auto-scroll", self.autoscroll_var)
        c.config(bg=PANEL2, activebackground=PANEL2)
        c.pack(side="right")

        holder = tk.Frame(loginner, bg=TERM)
        holder.pack(fill="both", expand=True)
        self.logbox = tk.Text(holder, height=4, wrap="word", bd=0,
                              padx=10, pady=8, bg=TERM, fg=TEXT,
                              font=(MONO, 9), insertbackground=GREEN,
                              selectbackground=GREENQ,
                              highlightthickness=0)
        sb = tk.Scrollbar(holder, command=self.logbox.yview, bg=PANEL2,
                          troughcolor=TERM, activebackground=CYAN,
                          bd=0, highlightthickness=0, width=12)
        self.logbox.config(yscrollcommand=sb.set, state="disabled")
        sb.pack(side="right", fill="y")
        self.logbox.pack(side="left", fill="both", expand=True)
        self.logbox.tag_config("alert", foreground=RED)
        self.logbox.tag_config("ok", foreground=GREEN)
        self.logbox.tag_config("note", foreground=AMBER)
        self.logbox.tag_config("dim", foreground=DIM)

        # Matrix-rain overlay for the console, same footprint as the log -
        # shown only in STANDBY (see _show_rain/_stop_rain, driven by
        # _set_banner) and place_forget()'d the moment there is anything
        # real to look at instead, so it never covers real output.
        self.rain_canvas = tk.Canvas(holder, bg=TERM, highlightthickness=0, bd=0)

        # The tab area takes whatever the console did not need.
        body.pack(side="top", fill="both", expand=False, padx=16)
        self.show_tab("WATCHDOG")

        self._tick_clock()

    def show_tab(self, name):
        for n, frame in self.tabs.items():
            frame.pack_forget()
            self.tabbtns[n].config(fg=DIM, bg=DEEP)
        self.tabs[name].pack(fill="both", expand=True, pady=(9, 0))
        self.tabbtns[name].config(fg=GREEN, bg=PANEL)
        self.tab_canvas.yview_moveto(0)
        self.root.after_idle(self._fit_tabs)

    def _fit_tabs(self):
        """Give the open tab all the height it needs, up to what the console
        can spare, and offer a scrollbar only if it still does not fit."""
        canvas = self.tab_canvas
        want = self.tab_host.winfo_reqheight()
        s = self.ui_scale
        room = (self.root.winfo_height() - self.body.winfo_y() - int(125 * s))
        height = max(int(120 * s), min(want, room))
        if int(canvas.cget("height")) != height:
            canvas.config(height=height)
        canvas.config(scrollregion=(0, 0, 0, want))
        if want > height:
            if not self.tab_scroll.winfo_manager():
                self.tab_scroll.pack(side="right", fill="y", before=canvas)
        elif self.tab_scroll.winfo_manager():
            self.tab_scroll.pack_forget()
            canvas.yview_moveto(0)

    def _on_tab_wheel(self, event):
        """Wheel scrolls the tab, except over a box with its own scrolling."""
        w = event.widget
        if isinstance(w, str) or w.winfo_class() in ("Text", "Listbox"):
            return
        if str(w).startswith(str(self.tab_canvas))                 and self.tab_scroll.winfo_manager():
            self.tab_canvas.yview_scroll(-1 if event.delta > 0 else 1, "units")

    def _tick_clock(self):
        try:
            self.clock.config(text=datetime.now().strftime("%H:%M:%S"))
            self.root.after(1000, self._tick_clock)
        except Exception:
            pass   # window closed

    # ---------------------------------------------------------- watchdog
    def _build_watch_tab(self, parent):
        tk = self.tk
        tab = tk.Frame(parent, bg=DEEP)
        self.tabs["WATCHDOG"] = tab

        # ---- fingerprint table ----
        wrap, card = self._panel(tab, "NETWORK FINGERPRINT")
        wrap.pack(fill="x")
        grid = tk.Frame(card, bg=PANEL)
        grid.pack(fill="x", padx=14, pady=(8, 4))
        grid.columnconfigure(1, weight=1)
        grid.columnconfigure(2, weight=1)

        for c, text in enumerate(("MARKER", "BASELINE", "LIVE", "")):
            tk.Label(grid, text=text, bg=PANEL, fg=DIM,
                     font=(MONO, 8, "bold"), anchor="w").grid(
                row=0, column=c, sticky="ew", padx=(0, 10), pady=(0, 4))
        tk.Frame(grid, bg=GRID, height=1).grid(row=1, column=0, columnspan=4,
                                               sticky="ew", pady=(0, 4))

        # cells[key] = (baseline label, live label, verdict label)
        self.cells = {}
        for r, (label, key) in enumerate(self.ROWS, start=2):
            tk.Label(grid, text=label, bg=PANEL, fg=TEXT, font=(MONO, 9),
                     anchor="w", width=13).grid(row=r, column=0, sticky="w",
                                                pady=1)
            base = tk.Label(grid, text="-", bg=PANEL, fg=DIM, font=(MONO, 9),
                            anchor="w")
            base.grid(row=r, column=1, sticky="w", padx=(0, 10))
            live = tk.Label(grid, text="-", bg=PANEL, fg=TEXT, font=(MONO, 9),
                            anchor="w")
            live.grid(row=r, column=2, sticky="w", padx=(0, 10))
            verdict = tk.Label(grid, text="", bg=PANEL, fg=DIM,
                               font=(MONO, 9, "bold"), anchor="e", width=8)
            verdict.grid(row=r, column=3, sticky="e")
            self.cells[key] = (base, live, verdict)

        self.public_var = tk.BooleanVar(value=True)
        self._check(card, "include WAN IP lookup (needs internet)",
                    self.public_var).pack(anchor="w", padx=12, pady=(0, 10))

        # ---- the one control that matters ----
        wrap2, hero = self._panel(tab)
        wrap2.pack(fill="x", pady=7)
        inner = tk.Frame(hero, bg=PANEL)
        inner.pack(fill="x", padx=14, pady=9)
        left = tk.Frame(inner, bg=PANEL)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text="ARM DEFENCE", bg=PANEL, fg=GREEN,
                 font=(MONO, 12, "bold"), anchor="w").pack(anchor="w")
        tk.Label(left, text="scan every 15s  >  pin the real gateway  >  "
                            "active defence  >  repair the link",
                 bg=PANEL, fg=DIM, font=(MONO, 8), anchor="w").pack(anchor="w",
                                                                    pady=(3, 0))
        self.protect_btn = self._btn(inner, "  ENGAGE  ", self.protect_now,
                                     kind="primary")
        self.protect_btn.pack(side="right")

        # ---- secondary actions ----
        row1 = tk.Frame(tab, bg=DEEP)
        row1.pack(fill="x", pady=(0, 7))
        self._btn(row1, "SET BASELINE", self.set_baseline).pack(side="left")
        self._btn(row1, "SCAN ONCE", self.check_once).pack(side="left", padx=6)
        self._btn(row1, "REFRESH", self.refresh_status).pack(side="left")
        self._btn(row1, "RECONNECT", self.restore_network).pack(side="left", padx=6)

        # ---- manual watch ----
        wrap3, watch = self._panel(tab, "MANUAL SCAN")
        wrap3.pack(fill="x")
        l1 = tk.Frame(watch, bg=PANEL)
        l1.pack(fill="x", padx=14, pady=(8, 3))
        tk.Label(l1, text="interval", bg=PANEL, fg=TEXT,
                 font=(MONO, 9)).pack(side="left")
        self.interval_var = tk.StringVar(value="60")
        tk.Entry(l1, width=5, textvariable=self.interval_var, bg=DEEP, fg=GREEN,
                 font=(MONO, 9), relief="flat", bd=0, insertbackground=GREEN,
                 highlightthickness=1, highlightbackground=EDGE,
                 highlightcolor=CYAN, justify="center").pack(side="left", padx=8)
        tk.Label(l1, text="sec", bg=PANEL, fg=DIM,
                 font=(MONO, 9)).pack(side="left")
        self.stop_btn = self._btn(l1, "STOP", self.stop_watch, kind="danger")
        self.stop_btn.config(state="disabled")
        self.stop_btn.pack(side="right")
        self.start_btn = self._btn(l1, "START SCAN", self.start_watch)
        self.start_btn.pack(side="right", padx=6)

        l2 = tk.Frame(watch, bg=PANEL)
        l2.pack(fill="x", padx=12, pady=(0, 8))
        self.defend_var = tk.BooleanVar(value=False)
        self._check(l2, "active defence", self.defend_var).pack(side="left")
        self.restore_var = tk.BooleanVar(value=False)
        self._check(l2, "auto-reconnect", self.restore_var).pack(side="left",
                                                                 padx=12)
        self.harden_var = tk.BooleanVar(value=False)
        self._check(l2, "pin gateway", self.harden_var).pack(side="left")

    # ----------------------------------------------------------- devices
    def _build_devices_tab(self, parent):
        tk = self.tk
        tab = tk.Frame(parent, bg=DEEP)
        self.tabs["DEVICES"] = tab

        wrap, card = self._panel(tab, "HOSTS ON THIS NETWORK")
        wrap.pack(fill="both", expand=True)

        bar = tk.Frame(card, bg=PANEL)
        bar.pack(fill="x", padx=14, pady=(8, 4))
        self.dev_status = tk.Label(bar, text="not scanned yet", bg=PANEL,
                                   fg=DIM, font=(MONO, 9), anchor="w")
        self.dev_status.pack(side="left")
        self.dev_scan_btn = self._btn(bar, "SCAN NETWORK", self.scan_devices,
                                      kind="primary")
        self.dev_scan_btn.pack(side="right")
        self._btn(bar, "REFRESH", self.refresh_devices).pack(side="right", padx=6)

        head = tk.Frame(card, bg=PANEL)
        head.pack(fill="x", padx=14)
        for text, w in (("ADDRESS", 17), ("HARDWARE (MAC)", 21),
                        ("ROLE", 10), ("NOTES", 20)):
            tk.Label(head, text=text, bg=PANEL, fg=DIM, width=w,
                     font=(MONO, 8, "bold"), anchor="w").pack(side="left")
        tk.Frame(card, bg=GRID, height=1).pack(fill="x", padx=14, pady=(3, 0))

        holder = tk.Frame(card, bg=PANEL)
        holder.pack(fill="both", expand=True, padx=14, pady=(4, 10))
        self.devbox = tk.Text(holder, height=8, wrap="none", bd=0, bg=PANEL,
                              fg=TEXT, font=(MONO, 9), highlightthickness=0,
                              padx=0, pady=0)
        dsb = tk.Scrollbar(holder, command=self.devbox.yview, bg=PANEL2,
                           troughcolor=PANEL, activebackground=CYAN, bd=0,
                           highlightthickness=0, width=12)
        self.devbox.config(yscrollcommand=dsb.set, state="disabled")
        dsb.pack(side="right", fill="y")
        self.devbox.pack(side="left", fill="both", expand=True)
        self.devbox.tag_config("gw", foreground=CYAN)
        self.devbox.tag_config("me", foreground=GREEN)
        self.devbox.tag_config("warn", foreground=AMBER)
        self.devbox.tag_config("bad", foreground=RED)
        self.devbox.tag_config("plain", foreground=TEXT)

        tk.Label(card, bg=PANEL, fg=DIM, font=(MONO, 8), justify="left",
                 anchor="w", wraplength=int(900 * self.ui_scale),
                 text="SCAN NETWORK pings every address on your subnet so the "
                      "ARP table fills up - without it you only see hosts this "
                      "PC happened to talk to. DUPLICATE means one machine is "
                      "answering for two addresses, which is the ARP-spoofing "
                      "footprint."
                 ).pack(fill="x", padx=14, pady=(0, 10))

    def _render_devices(self, devices):
        self.devbox.config(state="normal")
        self.devbox.delete("1.0", "end")
        if not devices:
            self.devbox.insert("end", "  no hosts found - press SCAN NETWORK\n",
                               "warn")
        for d in devices:
            if d["flags"]:
                tag = "bad" if "DUPLICATE" in d["flags"] else "warn"
            elif d["role"] == "GATEWAY":
                tag = "gw"
            elif d["role"] == "THIS PC":
                tag = "me"
            else:
                tag = "plain"
            note = ", ".join(d["flags"])
            if d["also"]:
                note += "  also " + ", ".join(d["also"])
            self.devbox.insert(
                "end",
                f"{d['ip']:<17}{d['mac']:<21}{d['role']:<10}{note}\n", tag)
        self.devbox.config(state="disabled")

        gw = sum(1 for d in devices if d["role"] == "GATEWAY")
        odd = [d for d in devices if d["flags"]]
        bits = [f"{len(devices)} host(s)"]
        if not gw:
            bits.append("no gateway seen")
        if odd:
            bits.append(f"{len(odd)} flagged")
        self.dev_status.config(
            text="   |   ".join(bits) + "   |   "
                 + datetime.now().strftime("%H:%M:%S"),
            fg=RED if any("DUPLICATE" in d["flags"] for d in odd) else DIM)

    def refresh_devices(self):
        """Show what is already in the ARP table - instant, no sweep."""
        self._run_bg(lan_devices, self._render_devices, exclusive=False)

    def scan_devices(self):
        """Ping the whole subnet first, then list what answered."""
        self.dev_scan_btn.config(state="disabled")
        self.dev_status.config(text="sweeping the subnet ...", fg=CYAN)

        def progress(done, total):
            self.ui_q.put(lambda: self.dev_status.config(
                text=f"sweeping {done}/{total} addresses ...", fg=CYAN))

        def work():
            sweep_lan(on_progress=progress)
            return lan_devices()

        def done(devices):
            self.dev_scan_btn.config(state="normal")
            self._render_devices(devices)
            log(f"Network scan: {len(devices)} host(s) on this network.")
            for d in devices:
                if "DUPLICATE" in d["flags"]:
                    log(f"   ! {d['ip']} ({d['mac']}) also answers for "
                        + ", ".join(d["also"]) + " - ARP spoofing footprint.")
        self._run_bg(work, done)

    # ---------------------------------------------------------- defender
    def _build_defender_tab(self, parent):
        tk = self.tk
        tab = tk.Frame(parent, bg=DEEP)
        self.tabs["DEFENDER"] = tab

        wrap, cap = self._panel(tab, "CAPABILITY")
        wrap.pack(fill="x")
        g = tk.Frame(cap, bg=PANEL)
        g.pack(fill="x", padx=14, pady=10)
        g.columnconfigure(0, weight=1)
        tk.Label(g, text="pin gateway + block attacker", bg=PANEL, fg=TEXT,
                 font=(MONO, 9), anchor="w").grid(row=0, column=0, sticky="w",
                                                  pady=3)
        self.cap_admin = tk.Label(g, text="-", bg=PANEL, fg=DIM,
                                  font=(MONO, 9, "bold"), anchor="e")
        self.cap_admin.grid(row=0, column=1, sticky="e")
        tk.Label(g, text="un-poison the rest of the LAN", bg=PANEL, fg=TEXT,
                 font=(MONO, 9), anchor="w").grid(row=1, column=0, sticky="w",
                                                  pady=3)
        self.cap_scapy = tk.Label(g, text="-", bg=PANEL, fg=DIM,
                                  font=(MONO, 9, "bold"), anchor="e")
        self.cap_scapy.grid(row=1, column=1, sticky="e")

        wrap2, act = self._panel(tab, "COUNTERMEASURES")
        wrap2.pack(fill="x", pady=10)
        row = tk.Frame(act, bg=PANEL)
        row.pack(fill="x", padx=12, pady=10)
        self._btn(row, "DEFEND NOW", lambda: self.defender_action("defend"),
                  kind="primary").pack(side="left")
        self._btn(row, "CORRECTIVE ARP",
                  lambda: self.defender_action("correct")).pack(side="left", padx=6)
        self._btn(row, "PIN GATEWAY",
                  lambda: self.defender_action("pin")).pack(side="left")
        self._btn(row, "UNDO ALL", lambda: self.defender_action("clear"),
                  kind="danger").pack(side="left", padx=6)

        wrap3, blk = self._panel(tab, "BLOCKED ADDRESSES")
        wrap3.pack(fill="both", expand=True)
        r = tk.Frame(blk, bg=PANEL)
        r.pack(fill="x", padx=14, pady=10)
        tk.Label(r, text="target", bg=PANEL, fg=TEXT,
                 font=(MONO, 9)).pack(side="left")
        self.block_ip_var = tk.StringVar()
        tk.Entry(r, width=18, textvariable=self.block_ip_var, bg=DEEP, fg=GREEN,
                 font=(MONO, 9), relief="flat", bd=0, insertbackground=GREEN,
                 highlightthickness=1, highlightbackground=EDGE,
                 highlightcolor=CYAN).pack(side="left", padx=8)
        self._btn(r, "BLOCK", lambda: self.block_action(True),
                  kind="danger").pack(side="left")
        self._btn(r, "UNBLOCK", lambda: self.block_action(False)).pack(
            side="left", padx=6)
        self._btn(r, "REFRESH", self.refresh_defender).pack(side="left")

        holder = tk.Frame(blk, bg=TERM)
        holder.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.blocklist = tk.Listbox(holder, height=7, bg=TERM, fg=RED,
                                    font=(MONO, 9), bd=0, highlightthickness=0,
                                    selectbackground=GREENQ,
                                    selectforeground=TEXT)
        self.blocklist.pack(fill="both", expand=True, padx=8, pady=6)

    # ---------------------------------------------------------- plumbing
    def _boot_lines(self):
        """Cosmetic startup cascade. Every line names a thing this process
        genuinely just did (imported modules, read the baseline, opened the
        log) - it is only the staggered, typed-out presentation that is for
        show, not the content.
        """
        cascade = [
            ("dim", "booting defense console ..."),
            ("dim", "mounting network fingerprint module ... OK"),
            ("dim", "binding firewall hooks ... OK"),
            ("dim", "arp watchdog ready ... OK"),
            ("ok",  "console ready."),
        ]

        def step(i=0):
            if i < len(cascade):
                tag, text = cascade[i]
                self._append_raw(text, tag)
                self.root.after(110, step, i + 1)
            else:
                for line in (f"baseline file : {os.path.basename(BASELINE_FILE)}",
                             f"log file      : {os.path.basename(LOG_FILE)}",
                             "press ENGAGE to arm, or SCAN ONCE to look now."):
                    self._append_raw(line, "dim")

        step()

    def _drain(self):
        try:
            while True:
                job = self.ui_q.get_nowait()
                try:
                    job()
                except Exception:
                    # A background job that finished after its widget was
                    # destroyed (window closed mid-scan) must not take the
                    # drain loop down with it - that would freeze the whole UI.
                    pass
        except queue.Empty:
            pass
        try:
            self.root.after(POLL_MS, self._drain)
        except Exception:
            pass   # interpreter is gone; nothing left to schedule

    def _append_raw(self, line, tag=None):
        self.logbox.config(state="normal")
        self.logbox.insert("end", line + "\n", tag or ())
        if self.autoscroll_var.get():
            self.logbox.see("end")
        self.logbox.config(state="disabled")
        self._update_logcount()

    def _append(self, line):
        if "ALERT" in line:
            tag = "alert"
        elif "OK -" in line:
            tag = "ok"
        elif any(m in line for m in ("NOTE:", "[restore]", "[defend]", "[pin]",
                                     "[block]", "[ip]", "[corrective",
                                     "[quarantine]", "[clear]", "[harden]")):
            tag = "note"
        else:
            tag = None
        self._append_raw(line, tag)

    def clear_log(self):
        """Empty the console pane. The log FILE on disk is untouched.

        Start/stop/start/stop piles up thousands of lines and there is no
        terminal to reach for, so this is the only way to get a clean view.
        """
        self.logbox.config(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.config(state="disabled")
        self._update_logcount()

    def _update_logcount(self):
        # Text always ends with a trailing newline, hence the -1.
        n = max(0, int(self.logbox.index("end-1c").split(".")[0]) - 1)
        self.logcount.config(text=f"{n} line{'' if n == 1 else 's'}")

    def _set_banner(self, state, note=None):
        is_new = state != getattr(self, "_last_state", None)
        art = ASCII_ART.get(state)
        if art is not None and is_new:
            tag = "alert" if state == "alert" else "ok"
            for line in art.splitlines():
                self._append_raw(line, tag)
        self._last_state = state

        # Matrix rain is a STANDBY-only backdrop - anything real to show
        # (armed, secure, alert, ...) takes the console back immediately.
        if state == "idle":
            self._show_rain()
        else:
            self._stop_rain()

        # The status dot breathes while actively armed, otherwise it is a
        # plain solid colour for the state.
        if state == "watching":
            self._start_pulse()
        else:
            self._stop_pulse()

        colour, title, default_note = BANNER[state]
        if note is None:
            note = default_note

        if state == "alert" and is_new:
            self._glitch_banner(title, colour)
        else:
            self.banner.config(text=title, fg=colour)
        if state != "watching":
            self.dot.config(bg=colour)
        self.status_card.config(bg=PANEL)
        self._type_subtitle(note, DIM if state != "alert" else RED)

    def _set_subtitle(self, text):
        job = getattr(self, "_type_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
            self._type_job = None
        self.subtitle.config(text=text)

    # ---------------------------------------------------- cosmetic effects
    def _type_subtitle(self, text, colour):
        """Reveal the subtitle character by character, like a live terminal."""
        job = getattr(self, "_type_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
        self.subtitle.config(fg=colour)

        def step(i=0):
            if not self.subtitle.winfo_exists():
                return
            self.subtitle.config(text=text[:i])
            if i < len(text):
                self._type_job = self.root.after(14, step, i + 1)
            else:
                self._type_job = None

        step()

    def _glitch_banner(self, final_text, colour, frames=6):
        """Scramble the banner for a few frames before settling on the real
        text - only used on a genuine transition into INTRUSION."""
        def step(i=0):
            if not self.banner.winfo_exists():
                return
            if i < frames:
                scrambled = "".join(random.choice(GLITCH_CHARS)
                                     for _ in final_text)
                self.banner.config(text=scrambled,
                                   fg=random.choice((RED, TEXT, AMBER)))
                self.root.after(45, step, i + 1)
            else:
                self.banner.config(text=final_text, fg=colour)

        step()

    def _start_pulse(self):
        if getattr(self, "_pulse_job", None):
            return
        self._pulse_i = 0
        self._pulse_tick()

    def _pulse_tick(self):
        dot = getattr(self, "dot", None)
        if dot is None or not dot.winfo_exists():
            self._pulse_job = None
            return
        dot.config(bg=GREEN if self._pulse_i % 2 == 0 else GREENQ)
        self._pulse_i += 1
        self._pulse_job = self.root.after(550, self._pulse_tick)

    def _stop_pulse(self):
        job = getattr(self, "_pulse_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
            self._pulse_job = None

    def _show_rain(self):
        canvas = getattr(self, "rain_canvas", None)
        if canvas is None:
            return   # console pane not built yet - refresh_status() retries
        canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        # Canvas shadows both .lift() and .tkraise() with its own item-
        # stacking method (tag_raise, which needs a tag argument), so the
        # widget-stacking order has to be set with the raw Tk command.
        canvas.tk.call("raise", str(canvas))
        self.root.after(30, self._start_rain)

    def _start_rain(self):
        canvas = getattr(self, "rain_canvas", None)
        if canvas is None or not canvas.winfo_ismapped():
            return
        if getattr(self, "_rain_job", None):
            return
        w = max(200, canvas.winfo_width())
        h = max(100, canvas.winfo_height())
        col_w = 16
        ncols = max(4, w // col_w)
        self._rain_cols = [{
            "x": i * col_w + 6,
            "y": random.uniform(-h, 0),
            "speed": random.uniform(2.5, 6.0),
            "len": random.randint(6, 14),
        } for i in range(ncols)]
        self._rain_tick()

    def _rain_tick(self):
        canvas = getattr(self, "rain_canvas", None)
        if canvas is None or not canvas.winfo_exists() or not canvas.winfo_ismapped():
            self._rain_job = None
            return
        canvas.delete("all")
        h = max(100, canvas.winfo_height())
        for col in self._rain_cols:
            col["y"] += col["speed"]
            if col["y"] - col["len"] * 15 > h:
                col["y"] = random.uniform(-h * 0.4, 0)
                col["speed"] = random.uniform(2.5, 6.0)
                col["len"] = random.randint(6, 14)
            for j in range(col["len"]):
                yy = col["y"] - j * 15
                if 0 <= yy <= h:
                    shade = (GREEN if j == 0 else
                             CYAN if j < 3 else
                             GREENQ if j < col["len"] - 2 else DIM)
                    canvas.create_text(col["x"], yy, text=random.choice(RAIN_CHARS),
                                       fill=shade, font=(MONO, 10, "bold"),
                                       anchor="n")
        self._rain_job = self.root.after(80, self._rain_tick)

    def _stop_rain(self):
        job = getattr(self, "_rain_job", None)
        if job:
            try:
                self.root.after_cancel(job)
            except Exception:
                pass
            self._rain_job = None
        canvas = getattr(self, "rain_canvas", None)
        if canvas is not None:
            canvas.place_forget()

    def _run_bg(self, fn, done=None, exclusive=True):
        """Run fn() off the UI thread; push result to `done` on the UI thread."""
        def worker():
            if exclusive and not self.busy.acquire(blocking=False):
                self.ui_q.put(lambda: self._append_raw(
                    "busy - wait for the current action to finish.", "note"))
                return
            try:
                result = fn()
                if done:
                    self.ui_q.put(lambda: done(result))
            except Exception as exc:
                # Bind the message now: Python clears `exc` when the except
                # block ends, long before the UI thread runs this lambda.
                msg = f"error: {exc}"
                self.ui_q.put(lambda m=msg: self._append_raw(m, "alert"))
            finally:
                if exclusive:
                    self.busy.release()
        threading.Thread(target=worker, daemon=True).start()

    # ----------------------------------------------------------- actions
    def _paint_row(self, key, baseline, live, skipped=False):
        """Fill one row and say plainly whether it matches."""
        b_lbl, l_lbl, v_lbl = self.cells[key]
        b_lbl.config(text=baseline or "-")
        l_lbl.config(text=("skipped" if skipped else (live or "-")))

        if skipped or baseline is None or live is None:
            v_lbl.config(text="", fg=DIM)
            l_lbl.config(fg=DIM)
        elif baseline == live:
            v_lbl.config(text="[ OK ]", fg=GREEN)
            l_lbl.config(fg=TEXT)
        else:
            v_lbl.config(text="[ !! ]", fg=RED)
            l_lbl.config(fg=RED)

    def refresh_status(self):
        base = load_baseline() or {}
        for _, key in self.ROWS:
            self._paint_row(key, base.get(key), None)
        if not base:
            self._set_subtitle("no baseline saved - press SET BASELINE while "
                               "on a network you trust")

        # Read the Tk variable HERE, on the UI thread. Touching a widget or a
        # Tk variable from a worker thread is not safe.
        pub = self.public_var.get()

        def done(cur):
            changed = 0
            for _, key in self.ROWS:
                skipped = key == "public_ip" and not pub
                self._paint_row(key, base.get(key), cur.get(key), skipped)
                if not skipped and base.get(key) and cur.get(key) \
                        and base[key] != cur[key]:
                    changed += 1
            when = datetime.now().strftime("%H:%M:%S")
            if not base:
                return
            total = len(self.ROWS)
            if changed:
                self._set_subtitle(f"{changed} of {total} markers differ from "
                                   f"baseline   |   scanned {when}")
            else:
                self._set_subtitle(f"all {total} markers match baseline   |   "
                                   f"scanned {when}")
        # Read-only, so it does not need the exclusive lock - otherwise the two
        # refreshes fired at startup would knock each other out.
        self._run_bg(lambda: snapshot(check_public=pub), done, exclusive=False)

    def restore_network(self):
        """Put the machine back on the baseline network, on demand."""
        from tkinter import messagebox
        base = load_baseline()
        if not base:
            messagebox.showwarning("MITM Tracker",
                                   "No baseline yet. Connect to your normal "
                                   "network and press SET BASELINE first.")
            return
        if not base.get("ssid"):
            messagebox.showwarning(
                "MITM Tracker",
                "The baseline has no Wi-Fi network recorded - it was saved "
                "before this feature existed, or you were on Ethernet.\n\n"
                "Connect to your normal network and press SET BASELINE to "
                "record it.")
            return
        if not messagebox.askyesno(
                "MITM Tracker",
                f"Reconnect to '{base['ssid']}'?\n\nThis will drop the current "
                "connection while it reassociates."):
            return
        self._run_bg(lambda: restore(base), lambda _: self.refresh_status())

    def check_once(self):
        pub = self.public_var.get()
        self._run_bg(lambda: check(pub, do_defend=self.defend_var.get()),
                     lambda code: (self._set_banner(CODE_TO_STATE.get(code, "idle")),
                                   self.refresh_status()))

    def set_baseline(self):
        from tkinter import messagebox
        pub = self.public_var.get()

        def work():
            # Only look; saving happens on the UI thread once the warnings
            # below have been shown, so an attacker's MAC cannot be recorded
            # as trusted without the user seeing why that is a bad idea.
            cur = snapshot(check_public=pub)
            if cur["gateway_ip"] is None:
                log("Cannot baseline: no default gateway found.")
                return None, []
            return cur, init_hazards(cur, load_baseline())

        def done(result):
            cur, hazards = result
            if not cur:
                return
            if hazards:
                log("Baseline requested on a network that looks attacked:")
                for reason in hazards:
                    log("   - " + reason)
                if not messagebox.askyesno(
                        "MITM Tracker - this network looks attacked",
                        "This network is NOT safe to record as trusted:\n\n"
                        + "\n\n".join("- " + r for r in hazards)
                        + "\n\nSaving now would store the attacker as your "
                          "router, and every check afterwards would report "
                          "that everything is fine.\n\nSave anyway?"):
                    log("Baseline cancelled - nothing was saved.")
                    return

            save_baseline(cur)
            log("Baseline saved from the console.")
            # Pins belong to the network they were made on; clearing them here
            # stops a stale one silently overriding ARP on the new baseline.
            self._run_bg(lambda: clean_stale_pins(keep_ip=cur["gateway_ip"]),
                         lambda _: None)
            self.refresh_status()
            self._set_banner("ok")
        self._run_bg(work, done)

    def protect_now(self):
        """Set-and-forget: everything on, 15s interval. The twin of --protect."""
        from tkinter import messagebox
        if not load_baseline():
            messagebox.showwarning(
                "MITM Tracker",
                "No trusted network recorded yet.\n\nConnect to your normal "
                "network and press SET BASELINE first - protection works by "
                "comparing against that.")
            return
        self.interval_var.set("15")
        self.defend_var.set(True)
        self.restore_var.set(True)
        self.harden_var.set(True)
        self.start_watch()

    def start_watch(self):
        from tkinter import messagebox
        if self.watch_thread and self.watch_thread.is_alive():
            return
        try:
            interval = max(5, int(self.interval_var.get()))
        except ValueError:
            messagebox.showerror("MITM Tracker",
                                 "Interval must be a whole number of seconds.")
            return
        if (self.defend_var.get() or self.harden_var.get()) and not is_admin():
            if not messagebox.askyesno(
                "MITM Tracker",
                "You are NOT running as administrator, so this can detect and "
                "warn but it cannot actually undo an attack: pinning the "
                "gateway, blocking the attacker and taking an address back from "
                "a rogue DHCP server will all be skipped.\n\nClose this window "
                "and open it again, clicking YES, for real protection.\n\n"
                "Scan anyway (detection only)?"):
                return

        if self.restore_var.get() and not (load_baseline() or {}).get("ssid"):
            if not messagebox.askyesno(
                "MITM Tracker",
                "Auto-reconnect is on, but the baseline has no Wi-Fi network "
                "recorded, so there is nothing to reconnect to. Press SET "
                "BASELINE while on your normal network to record it.\n\n"
                "Start scanning anyway?"):
                return

        self.watch_stop.clear()
        pub, do_defend = self.public_var.get(), self.defend_var.get()
        do_restore, do_harden = self.restore_var.get(), self.harden_var.get()

        def loop():
            state = {}
            while not self.watch_stop.is_set():
                code = check(pub, state, do_defend=do_defend,
                             do_restore=do_restore, do_harden=do_harden)
                st = "watching" if code == 0 else CODE_TO_STATE.get(code, "idle")
                self.ui_q.put(lambda s=st: self._set_banner(
                    s, self._armed_note(interval, do_defend, do_restore,
                                        do_harden)))
                self.ui_q.put(self.refresh_status)
                for _ in range(interval * 10):
                    if self.watch_stop.is_set():
                        break
                    time.sleep(0.1)
            self.ui_q.put(lambda: self._set_banner(
                "idle", "stopped - nothing is being scanned"))

        self.watch_thread = threading.Thread(target=loop, daemon=True)
        self.watch_thread.start()
        self.start_btn.config(state="disabled")
        self.protect_btn.config(state="disabled", bg=PANEL2, fg=DIM)
        self.stop_btn.config(state="normal")
        self._set_banner("watching",
                         self._armed_note(interval, do_defend, do_restore,
                                          do_harden))

    @staticmethod
    def _armed_note(interval, do_defend, do_restore, do_harden):
        on = [n for n, v in (("active defence", do_defend),
                             ("auto-reconnect", do_restore),
                             ("gateway pinned", do_harden)) if v]
        return (f"every {interval}s   |   "
                + (", ".join(on) if on else "warn only")
                + "   |   press STOP to disarm")

    def stop_watch(self):
        self.watch_stop.set()
        self.start_btn.config(state="normal")
        self.protect_btn.config(state="normal", bg=GREEN, fg=DEEP)
        self.stop_btn.config(state="disabled")
        self._set_banner("idle", "stopped - nothing is being scanned")

    def defender_action(self, kind):
        from tkinter import messagebox
        base = load_baseline()
        if kind in ("defend", "correct", "pin") and not base:
            messagebox.showwarning("MITM Tracker",
                                   "No baseline yet. Set one on the WATCHDOG "
                                   "tab first.")
            return

        def work():
            if kind == "clear":
                clear_all()
                return
            cur = snapshot(check_public=False)
            gw = cur.get("gateway_ip") or base.get("gateway_ip")
            if kind == "defend":
                defend(base, cur)
            elif kind == "correct":
                send_corrective_arp(gw, base.get("gateway_mac"))
            elif kind == "pin":
                pin_gateway(gw, base.get("gateway_mac"))
        self._run_bg(work, lambda _: self.refresh_defender())

    def block_action(self, block):
        ip = self.block_ip_var.get().strip()
        if not ip:
            return
        self._run_bg(lambda: block_ip(ip) if block else unblock_ip(ip),
                     lambda _: self.refresh_defender())

    def refresh_defender(self):
        admin, scapy = is_admin(), have_scapy()
        self.cap_admin.config(text="READY" if admin else "NEEDS ADMIN",
                              fg=GREEN if admin else AMBER)
        self.cap_scapy.config(text="READY" if scapy else "NEEDS NPCAP",
                              fg=GREEN if scapy else AMBER)

        def done(blocks):
            self.blocklist.delete(0, "end")
            if blocks:
                for ip in blocks:
                    self.blocklist.insert("end", f"  {ip}")
            else:
                self.blocklist.insert("end", "  (nothing blocked)")
                self.blocklist.itemconfig(0, foreground=DIM)
        self._run_bg(lambda: list_blocks(), done, exclusive=False)


def _enable_dpi_awareness():
    """Draw at the display's real resolution. Otherwise Windows renders the
    window at 100% and stretches the bitmap, which blurs all text at 125%+."""
    if not IS_WIN:
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)   # system DPI aware
    except Exception:
        pass   # purely cosmetic; never a reason not to open


def run_gui():
    """Open the defence console."""
    try:
        import tkinter as tk
    except ImportError:
        print("Tkinter is not available in this Python build, so the console "
              "cannot open. The command line still works - try:\n"
              "    " + CMD + " --status")
        return 1

    _enable_dpi_awareness()
    root = tk.Tk()
    app = App(root)

    def on_close():
        app.watch_stop.set()
        root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()
    return 0


# ==========================================================================
# 11. Command line
# ==========================================================================

def print_status():
    """One combined view: trusted vs now, plus what the defender can do."""
    base = load_baseline() or {}
    cur = snapshot(check_public=False)

    rows = [
        ("Adapter", "interface"),
        ("Wi-Fi network (SSID)", "ssid"),
        ("Access point (BSSID)", "bssid"),
        ("Wi-Fi profile", "wifi_profile"),
        ("Gateway IP", "gateway_ip"),
        ("Gateway MAC", "gateway_mac"),
        ("My address", "local_ip"),
        ("Subnet", "subnet"),
        ("DHCP server", "dhcp_server"),
        ("DNS servers", "dns_servers"),
    ]
    print("MITM Tracker status")
    print("-" * 74)
    print(f"  {'':22} {'trusted':<24} {'now':<24}")
    drift = []
    for label, key in rows:
        old, new = base.get(key), cur.get(key)
        mark = " " if old in (None, new) or new is None else "*"
        if mark == "*":
            drift.append(label)
        print(f" {mark}{label:<22} {str(old or '-'):<24} {str(new or '-'):<24}")
    print("-" * 74)

    print(f"  Administrator rights  : {'YES' if is_admin() else 'no  (pin + block will be skipped)'}")
    print(f"  scapy + Npcap         : {'YES' if have_scapy() else 'no  (corrective broadcast will be skipped)'}")
    if not have_scapy():
        print(f"       ^ {scapy_problem()}")
    pins = [ip for _, ip in static_neighbors()]
    print(f"  Pinned (static) ARP   : {', '.join(pins) if pins else '(none)'}")
    blocks = list_blocks()
    print(f"  Active firewall blocks: {', '.join(blocks) if blocks else '(none)'}")

    dupes = duplicate_macs()
    if dupes:
        print("  *** One machine is answering for several addresses:")
        for mac, ips in dupes.items():
            print(f"        {mac}  ->  {', '.join(ips)}")
        print("      That is the ARP-spoofing footprint. If one of those "
              "addresses is your gateway, you are being MITM'd.")

    print("-" * 74)
    if not base:
        print("  No baseline yet. Run:  " + CMD + " --init")
    elif drift == ["My address"]:
        # Not a watched marker: DHCP handing you a new address is routine.
        print("  You are on the trusted network. Only your own address "
              "changed, which is normal when a DHCP lease renews.")
    elif drift:
        same_gw = base.get("gateway_ip") == cur.get("gateway_ip")
        if same_gw and base.get("gateway_mac") and cur.get("gateway_mac") \
                and base["gateway_mac"] != cur["gateway_mac"]:
            print("  *** MAC MISMATCH on the SAME gateway IP - this is the "
                  "ARP-spoofing signature.")
            print("      Respond with:  " + CMD + " --defend")
        elif not same_gw:
            print("  (different gateway IP - you are on another network, not "
                  "spoofing. Re-baseline here if it's trusted.)")
        print("  * changed since the baseline: " + ", ".join(drift))
        print("  Put yourself back with:  " + CMD + " --restore")
    else:
        print("  You are on the trusted network.")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog=CMD.split()[-1] if FROZEN else "mitm_tracker.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Detect and undo man-in-the-middle attacks on your network.",
        epilog=f"""
the three you actually need
  {CMD:<38} open the app (asks for admin)
  {CMD + ' --init':<38} record this network as trusted (once)
  {CMD + ' --protect':<38} full protection, until you press Ctrl+C

everything is optional after that. --status tells you where you stand,
--clear puts every change this tool made back the way it was.

Only use this on a network you own or are allowed to defend.
""")

    g = p.add_argument_group("the main ones")
    g.add_argument("--ui", action="store_true",
                   help="open the desktop app (the default with no arguments)")
    g.add_argument("--init", action="store_true",
                   help="record the current network as the one you trust")
    g.add_argument("--protect", nargs="?", const=15, type=int, metavar="SECONDS",
                   help="set-and-forget protection: watch every SECONDS "
                        "(default 15), pin the gateway, defend and repair. "
                        "Asks for Administrator by itself")
    g.add_argument("--status", action="store_true",
                   help="trusted vs now, and what the defender can do")

    g = p.add_argument_group("checking")
    g.add_argument("--watch", type=int, metavar="SECONDS",
                   help="keep checking every SECONDS (no countermeasures "
                        "unless you add them)")
    g.add_argument("--no-public", action="store_true",
                   help="skip the public IP lookup (LAN only, works offline)")
    g.add_argument("--force", action="store_true",
                   help="with --init: save the baseline even if this network "
                        "looks like it is under attack")

    g = p.add_argument_group("responding (each also works as a --watch option)")
    g.add_argument("--defend", action="store_true",
                   help="on ARP spoofing: corrective ARP + pin the gateway + "
                        "block the attacker")
    g.add_argument("--restore", action="store_true",
                   help="when the network itself changed (Wi-Fi, access point, "
                        "subnet, DNS), reconnect to the trusted one")
    g.add_argument("--harden", action="store_true",
                   help="pin the trusted gateway while the network is still "
                        "clean, so poisoning never takes hold")
    g.add_argument("--strict", action="store_true",
                   help="with --restore: stay off an access point whose BSSID "
                        "does not match the baseline, even if that means "
                        "going offline")

    g = p.add_argument_group("by hand")
    g.add_argument("--correct-only", action="store_true",
                   help="only re-broadcast the true gateway MAC to the LAN")
    g.add_argument("--pin", action="store_true",
                   help="only pin the trusted gateway MAC (static ARP)")
    g.add_argument("--clean-pins", action="store_true",
                   help="remove static ARP entries left behind by earlier defences")
    g.add_argument("--block", metavar="IP", help="block one IP at the firewall")
    g.add_argument("--unblock", metavar="IP", help="remove a firewall block")
    g.add_argument("--clear", action="store_true",
                   help="put everything back: unpin the gateway and remove "
                        "every block this tool added")
    g.add_argument("--devices", action="store_true",
                   help="list every host on your network (sweeps the subnet "
                        "first so you see all of them, not just the ones this "
                        "PC has talked to)")
    g.add_argument("--no-sweep", action="store_true",
                   help="with --devices: skip the ping sweep, show only what "
                        "is already in the ARP table")
    g.add_argument("--test-notify", action="store_true",
                   help="send a test notification, to check alerts will "
                        "actually reach you")
    g.add_argument("--networks", action="store_true",
                   help="list the access points in range")
    g.add_argument("--dhcp", action="store_true",
                   help="hand the adapter back to DHCP (undo a forced static "
                        "address left behind by a rogue-DHCP defence)")
    g.add_argument("--compare", nargs=2, metavar=("IP", "IP-OR-CIDR"),
                   help="are these the same address? (or is the first inside "
                        "the second?)")

    p.add_argument("--no-elevate", action="store_true",
                   help="never ask for Administrator, just run with what we have")
    return p


def main():
    # Before anything prints: a windowed .exe needs to borrow the caller's
    # console or all CLI output is lost.
    if len(sys.argv) > 1:
        _attach_console()

    parser = build_parser()
    args = parser.parse_args()
    check_public = not args.no_public

    # --protect is the whole toolkit behind one flag: the point is that you
    # should not have to know which countermeasure a given attack needs.
    if args.protect is not None:
        args.watch = args.protect
        args.defend = args.restore = args.harden = True

    # --- things that never need elevation -------------------------------
    if args.compare:
        matched, message = compare_ips(*args.compare)
        print(message)
        return 0 if matched else 1

    if args.test_notify:
        sent = notify("MITM Tracker", "This is a test alert. If you can see "
                                      "this, real alerts will reach you too.")
        print("Sent via: " + (", ".join(sent) if sent else "nothing"))
        if "webhook" not in sent:
            print(f"No webhook configured. Put a URL in {WEBHOOK_FILE}\n"
                  "(or set MITM_WEBHOOK) to get alerts on your phone.")
        return 0 if sent else 1

    if args.devices:
        if not args.no_sweep:
            print("Sweeping the subnet so every host answers ...")
            sweep_lan(on_progress=lambda d, t: print(
                f"\r  {d}/{t}", end="", flush=True))
            print()
        devices = lan_devices()
        print(f"{len(devices)} host(s) on this network")
        print(f"  {'ADDRESS':<17}{'HARDWARE (MAC)':<21}{'ROLE':<10}NOTES")
        for d in devices:
            note = ", ".join(d["flags"])
            if d["also"]:
                note += "  also " + ", ".join(d["also"])
            print(f"  {d['ip']:<17}{d['mac']:<21}{d['role']:<10}{note}")
        if any("DUPLICATE" in d["flags"] for d in devices):
            print("\n  *** One machine is answering for several addresses. "
                  "That is the ARP-spoofing footprint - if one of them is your "
                  "gateway, your traffic is going through that machine.")
        return 0

    if args.networks:
        nets = visible_networks()
        if not nets:
            print("No networks visible (no Wi-Fi adapter, or the radio is off).")
            return 0
        base_ssid = (load_baseline() or {}).get("ssid")
        for ssid, bssids in sorted(nets.items()):
            tag = "  <- trusted" if ssid == base_ssid else ""
            print(f"{ssid or '(hidden)'}{tag}")
            for b in bssids:
                print(f"    {b}")
        return 0

    if args.status:
        return print_status()

    # --- ask for Administrator when the job actually needs it ------------
    # This is why there are no .bat launchers any more: the file elevates
    # itself. If the user declines the prompt we carry on unelevated, because
    # detection still works and saying so is better than refusing to run.
    wants_admin = bool(args.protect is not None or args.defend or args.harden
                       or args.pin or args.clean_pins or args.clear
                       or args.block or args.unblock or args.dhcp)
    gui = args.ui or len(sys.argv) == 1

    if (gui or wants_admin) and not args.no_elevate and not is_admin():
        if relaunch_as_admin(gui=gui):
            return 0   # the elevated copy has taken over
        if not gui:
            log("Continuing without Administrator - the steps that change the "
                "system will be skipped and said so.")

    if gui:
        return run_gui()

    # --- one-shot actions ------------------------------------------------
    if args.clear:
        clear_all()
        return 0
    if args.clean_pins:
        clean_stale_pins()
        return 0
    if args.block:
        return 0 if block_ip(args.block) else 1
    if args.unblock:
        return 0 if unblock_ip(args.unblock) else 1
    if args.dhcp:
        alias = default_interface()[0] or (load_baseline() or {}).get("interface")
        if not alias:
            print("No adapter found.")
            return 2
        return 0 if set_dhcp_ip(alias) else 1

    if args.init:
        return do_init(check_public, force=args.force)

    base = load_baseline()

    if args.correct_only or args.pin:
        if not base:
            log("No baseline. Run:  " + CMD + " --init  (on a clean network)")
            return 2
        gw = get_gateway_ip() or base.get("gateway_ip")
        if args.correct_only:
            send_corrective_arp(gw, base.get("gateway_mac"))
            return 0
        return 0 if pin_gateway(gw, base.get("gateway_mac")) else 1

    # --- watching --------------------------------------------------------
    if args.watch:
        return watch_forever(args.watch, check_public, do_defend=args.defend,
                             do_restore=args.restore, strict=args.strict,
                             do_harden=args.harden)

    # --- a single action, right now (no --watch given) -------------------
    # Without --watch these read as imperatives ("harden now", "restore now"),
    # which is how the separate tools used to behave.
    if args.harden:
        if not base:
            log("No baseline yet. Run:  " + CMD + " --init")
            return 2
        return 0 if harden(base) else 1

    if args.restore:
        if not base:
            print("No baseline. Connect to your normal network and run: "
                  "" + CMD + " --init")
            return 2
        return 0 if restore(base, strict=args.strict) else 1

    if args.defend:
        if not base:
            log("No baseline. Run:  " + CMD + " --init  (on a clean network)")
            return 2
        defend(base, snapshot(check_public=False))
        return 0

    # Nothing specific asked for: one plain check.
    return check(check_public)


if __name__ == "__main__":
    sys.exit(main())
