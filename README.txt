===============================================================
 MITM TRACKER
 Detect and undo man-in-the-middle attacks on your network.
===============================================================

 Two ways to run it, same program:

   MITM-Tracker.exe   no Python needed. Just double-click.
   mitm_tracker.py    the source. Needs Python 3.

 It asks for Administrator by itself. Nothing to install.

 IMPORTANT: keep MITM-Tracker.exe in THIS folder. It reads and
 writes router_baseline.json and router_watch.log next to
 itself, so moving the .exe somewhere else starts it over with
 no trusted network.


===============================================================
 START HERE
===============================================================


   1. Double-click:   MITM-Tracker.exe
      Click YES on the prompt Windows shows.

   2. Press:  SET BASELINE      <- once only, on a network you trust
   3. Press:  ENGAGE

   That is it. Leave the window open. You are protected.


   READING THE CONSOLE

   The top line is the state, and it is the only thing you have
   to understand:

      STANDBY      not scanning
      ARMED        scanning, and set to fight back
      SECURE       scanned, nothing has changed
      INTRUSION    something changed - read the console
      NO BASELINE  press SET BASELINE first
      LINK DOWN    no network right now

   NETWORK FINGERPRINT compares BASELINE against LIVE, one row
   per marker, and marks each:

      [ OK ]   this marker matches the network you trusted
      [ !! ]   this marker CHANGED - the row turns red

   Three tabs:

      WATCHDOG   the fingerprint, ENGAGE, and manual scanning
      DEVICES    every host on your network
      DEFENDER   what the console is allowed to do, the manual
                 countermeasures, and the blocked address list

   The black pane at the bottom is the live console. CLEAR
   empties it - the log FILE on disk is never touched, so your
   history survives.


   Rather type? Same thing, two lines:

       .\MITM-Tracker.exe --init
       .\MITM-Tracker.exe --protect

   Press Ctrl+C when you want to stop.


===============================================================
 TOMORROW, AND EVERY DAY AFTER
===============================================================

   Do NOT set the baseline again.

   Just open MITM-Tracker.exe and press ENGAGE,
   or run:   .\MITM-Tracker.exe --protect

   Your normal network is already saved in router_baseline.json.


   Re-run --init ONLY when your normal network really changes:

       you buy a new router
       you move to a new home or office Wi-Fi
       your ISP changes your connection


===============================================================
 WHAT IT ACTUALLY DOES
===============================================================

  It records a fingerprint of the network you trust, then keeps
  comparing the live network against it. Three problems, three
  different answers - and telling them apart is the whole point:

  1. Router MAC changed, IP did NOT
       = ARP spoofing, or a rogue router.
       -> re-teaches the LAN the real MAC, pins your router so
          the poisoning cannot stick, blocks the attacker.

  2. Gateway IP / subnet / DHCP server changed, but the Wi-Fi
     and access point did NOT
       = your router did not move, so something on this network
         is answering DHCP in its place and pointing at itself.
       -> renews the lease, and if the rogue server keeps winning
          the race, takes the address back statically.

  3. Wi-Fi, access point or adapter changed
       = you are not on the network you trusted any more.
       -> reconnects you to the one you were on.

  "The gateway changed" means opposite things depending on
  whether the network under it changed too. That distinction is
  why 2 and 3 are handled separately.


===============================================================
 WHO ELSE IS ON MY NETWORK?
===============================================================

   DEVICES tab  ->  press SCAN NETWORK
   or:          .\MITM-Tracker.exe --devices

   It pings every address on your subnet first, because your PC
   only remembers hosts it has actually talked to. Takes about
   six seconds on a normal home network.

   What the notes mean:

      GATEWAY      your router
      THIS PC      you
      RANDOM MAC   this address was chosen by software, not
                   burned into the hardware. Phones do this on
                   purpose for privacy, so it is usually normal
                   - but so does anyone spoofing a MAC.
      DUPLICATE    one machine is answering for TWO addresses.
                   This is the ARP-spoofing footprint. If one of
                   them is your gateway, your traffic is going
                   through that machine RIGHT NOW.


===============================================================
 TELL ME EVEN WHEN I AM AWAY
===============================================================

   Every alert already pops a Windows notification.

   Check it works:   .\MITM-Tracker.exe --test-notify

   To reach your PHONE as well, put one URL in a file called
   notify_webhook.txt next to this README:

      https://hooks.slack.com/services/...        (Slack)
      https://discord.com/api/webhooks/...        (Discord)
      https://ntfy.sh/your-private-topic-name     (ntfy, easiest)

   ntfy needs no account: pick an unguessable topic name, install
   the ntfy app on your phone, subscribe to that topic, and every
   alert arrives as a push notification.

   Or set the MITM_WEBHOOK environment variable instead.

   One notification per event, not one per changed field.


===============================================================
 IS IT REALLY WORKING?
===============================================================

   .\MITM-Tracker.exe --status

   Shows trusted vs now, side by side, plus:

       Administrator rights   : YES     <- you want YES
       scapy + Npcap          : YES

   If Administrator says "no", you missed the prompt. Close the
   window and open it again.


===============================================================
 WHAT HAPPENED WHILE I WAS AWAY?
===============================================================

   Select-String -Path router_watch.log -Pattern "ALERT"


===============================================================
 SOMETHING BROKE - PUT EVERYTHING BACK
===============================================================

   .\MITM-Tracker.exe --clear

   Undoes every change the tool made: unpins your router and
   removes every firewall block it added.

   Internet still not working?

   .\MITM-Tracker.exe --dhcp


===============================================================
 MAKE IT STRONGER (optional)
===============================================================

   Without Npcap, the tool protects THIS PC only. With it, the
   tool can also un-poison everyone else on your network.

   Download Npcap:   https://npcap.com

   During setup, TICK the box:
       "Install Npcap in WinPcap API-compatible mode"

   Check it took effect:   .\MITM-Tracker.exe --status
   You want:               scapy + Npcap : YES

   (scapy itself:  pip install scapy)


===============================================================
 EVERY COMMAND
===============================================================

   .\MITM-Tracker.exe --help

   shows all of them, grouped. The short version:

   THE MAIN ONES
     (no arguments)     open the app
     --init             record this network as trusted
     --protect          full protection until Ctrl+C
     --status           trusted vs now, and what's available

   CHECKING
     --watch 60         keep checking every 60s, warn only
     --no-public        skip the internet lookup (works offline)
     --force            with --init: save even if it looks attacked

   RESPONDING  (add to --watch, or use alone to do it right now)
     --defend           respond to ARP spoofing
     --restore          get back on the trusted network
     --harden           pin the gateway while things are clean
     --strict           with --restore: refuse a wrong access
                        point even if that means going offline

   BY HAND
     --correct-only     re-broadcast the true gateway MAC
     --pin              pin the trusted gateway MAC
     --clean-pins       remove pins left over from other networks
     --block IP         block one IP at the firewall
     --unblock IP       remove that block
     --clear            put everything back
     --devices          every host on your network (sweeps first)
     --no-sweep         with --devices: skip the sweep, show cache
     --test-notify      check that alerts will reach you
     --networks         list the access points in range
     --dhcp             hand the adapter back to DHCP
     --compare A B      are these the same IP? (B may be a CIDR)
     --no-elevate       never ask for Administrator


===============================================================
 WHAT NEEDS WHAT
===============================================================

   Detecting everything            nothing - always works
   Reconnecting to your Wi-Fi      nothing
   Pinning the gateway             Administrator
   Blocking the attacker           Administrator
   Taking an address back          Administrator
   Un-poisoning the whole LAN      scapy + Npcap

   Anything missing is skipped and SAID OUT LOUD in the log,
   never failed silently.


===============================================================
 FILES IN THIS FOLDER
===============================================================

   MITM-Tracker.exe       Double-click this. No Python needed.
   mitm_tracker.py        The source for the above.
   mitm.ico               The logo. The .exe has it built in, so
                          this is only kept for rebuilding.
   router_baseline.json   Your trusted network fingerprint.
   notify_webhook.txt     Optional: one URL, to get alerts on
                          your phone. Create it yourself.
   router_watch.log       History of all checks and alerts.
   router_watch.log.1     Previous log (auto-rotated at 1 MB).
   README.txt             This file.


===============================================================
 TROUBLESHOOTING
===============================================================

   "No baseline found"
       Run:  .\MITM-Tracker.exe --init

   "could not read the default gateway"
       You are not connected to any network. Reconnect and retry.

   You get an ALERT but YOU made the change (new router, new
   Wi-Fi, ISP reset)
       Re-trust the new network:
           .\MITM-Tracker.exe --init

   It says "need Administrator"
       You declined the prompt. Close it and open it again,
       clicking YES this time.

   "python is not recognized"
       Use the full path:
           "C:\Program Files\Python312\python.exe" mitm_tracker.py

   The watchdog stops after you restart the PC
       That is normal. Start it again, or ask to have it added
       to Windows startup.

   It refuses to save a baseline
       Good. It thinks this network is under attack right now,
       and saving would store the attacker as your router - after
       which every check would say everything is fine, forever.
       Get onto a clean network first. Override with --force only
       if you are certain.


===============================================================
 Only use this on a network you own or are allowed to defend.
 It sends packets to other hosts and changes the local firewall.
===============================================================


===============================================================
 WINDOWS MAY WARN ABOUT THE .EXE
===============================================================

   Expect it, and here is the honest reason.

   A packaged Python .exe is a very common malware wrapper, so
   the packaging alone draws attention - before anything this
   tool DOES is considered. On top of that this program:

       forges ARP replies         (that is how it un-poisons)
       ping-sweeps your subnet    (that is the DEVICES list)
       edits the Windows Firewall (that is how it blocks)
       changes DNS and IP config  (that is how it repairs)
       asks for Administrator

   Every one of those is also what an attack tool does. Your
   antivirus cannot see intent, only behaviour, so it is not
   being stupid - it is doing its job.

   If you would rather not fight it, run the .py instead:

       python mitm_tracker.py

   Identical program, far less likely to be flagged, because it
   is plain readable text rather than a packed binary.

   Do NOT disable your antivirus. If you choose to allow this,
   allow THIS FOLDER ONLY.
