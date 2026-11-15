DD Cleaner 3.0
==============

Driver checker, system health tools and security audit for Windows 10/11 (64-bit).
It focuses on what Windows does not already provide in one place.
Author: Benoit (BSM) Saint-Moulin


1. PACKAGE CONTENTS
-------------------
  DD_Cleaner\             Program folder: DD_Cleaner.exe and its _internal\ folder
                          (no Python needed)
  README.txt              This file


2. REQUIREMENTS
---------------
  - Windows 10 or 11, 64-bit
  - Administrator rights: the program asks for elevation (UAC prompt) at every start
  - Antivirus tab only: ClamAV for Windows (clamav.net), installed in
    C:\Program Files\ClamAV. Not bundled with DD Cleaner.
  - Install location: C:\Program Files\DD Cleaner (see 3). The program runs as
    administrator, so its folder must be one that only administrators can
    change. A folder you create yourself (C:\Tools, Desktop, Downloads, D:\...)
    stays writable by your account: any program running under your account
    could then place a DLL there and have it run as administrator. The program
    checks its folder at every start and warns if it is not protected.


3. GETTING STARTED
------------------
  1. Run DD_Cleaner_Setup_<version>.exe and accept the UAC prompt: it installs to
     C:\Program Files\DD Cleaner (only administrators can change that folder, which
     is why the installer does not offer another location) and adds Start Menu /
     optional desktop shortcuts. Without the installer: copy the DD_Cleaner folder
     to C:\Program Files\ yourself, so you get
     C:\Program Files\DD_Cleaner\DD_Cleaner.exe.
  2. Run DD_Cleaner.exe (or its shortcut) and accept the UAC prompt.
  3. Recommended before applying a hardening profile or tweaks: create a Windows
     restore point (Start > "Create a restore point"). The program tries to create
     one itself too.

  Driver checks, the health report, the firewall/network analysis and the audit
  are read-only. Every action that changes the system asks
  for confirmation.


4. TABS
-------
  Driver Checker     - Vulnerable drivers: checks every driver file (loaded kernel
                       modules, installed driver services, System32\drivers) against
                       the Microsoft vulnerable driver blocklist, the same rules Windows
                       uses when it blocks them (Authenticode hash, signer certificate,
                       file name and version). Read-only. Also shows whether Windows
                       enforces the blocklist on this PC (on Windows 10 it usually does
                       not, unless Memory integrity or the blocklist setting is on).
                       "Download latest blocklist" fetches the current list from
                       Microsoft (internet needed, about 330 KB); it is kept in
                       driver_blocklist\ next to the exe. Export to CSV.
                       Limit: signer rules are checked on embedded signatures only
                       (catalog-signed drivers are checked by hash and version).
                     - Driver age: lists third-party drivers with their age.
                       Export to CSV.

  System Health      - Health report (read-only, last 30 days): disk health, SMART
                       prediction, temperature and wear (administrator), free space,
                       Windows reliability index, blue screens with their stop code,
                       unexpected shutdowns, hardware errors (WHEA; disk resets are
                       traced back to the disk model and serial number), disk and
                       NTFS errors, programs that crash most, uptime, pending
                       restart. "Save report" writes it to a text file.
                     - Repair tools: SFC verify / scan and repair, DISM CheckHealth /
                       ScanHealth / RestoreHealth, component store cleanup, network
                       stack reset (reboot recommended afterwards).

  Firewall &         - Live traffic: every application using the network, refreshed
  Network              every 2 seconds: inbound / outbound connections, remote
                       address and host name (Internet, local network or this PC),
                       ports it listens on or binds, and, as administrator, bytes
                       received/sent and current download/upload per connection and
                       per application (counted from the moment a connection is
                       first seen). Filter by application, site, owner, port or
                       address; Pause stops sampling. Read-only.
                       Where the data goes / who comes in: for every connection,
                       the site name the program asked for (Windows DNS cache),
                       the owner of the address (organization and country, from
                       the regional Internet registry: ARIN, RIPE, APNIC, LACNIC,
                       AFRINIC), your router and local devices (with their MAC
                       address). "Group by: Destination" lists every destination
                       with the programs talking to it; "Only inbound" shows who
                       connects to this PC (red when it comes from the Internet).
                       Owner lookups send public IP addresses (once per network
                       block) to the registries; untick "Look up owners" to stop.
                       Programs using their own encrypted DNS (some browsers) do
                       not appear in the Windows DNS cache: their destinations are
                       named by reverse DNS or by owner.
                     - World map: countries the PC talks to, with an arc from your
                       country (Windows region setting) to each destination, circles
                       sized by the number of connections, red when a computer from
                       that country connects to this PC. Hover for programs, sites
                       and volumes; click a country to list its connections; wheel
                       to zoom, drag to move, double click for the whole world.
                       Server locations: "Download DB-IP City Lite" (World map page,
                       about 60 MB, free, updated monthly) places every server in its
                       real city; the list gets a Location column. Lookups then run
                       on this PC, nothing is sent. IP Geolocation by DB-IP
                       (db-ip.com), licensed under Creative Commons Attribution 4.0.
                       Without it, the country where the network is registered is
                       used (large providers and CDNs then often appear as US).
                       Map outlines: Natural Earth (public domain), bundled.
                     - Firewall: profile state, networks in use (Private/Public),
                       rule statistics and risky rules: rules that open the PC to
                       everything, program rules reachable on public networks, edge
                       traversal, rules left for missing programs (a warning when
                       the path is in a folder any user can write to, such as
                       C:\Temp). Rules are read, never modified: use "Open Windows
                       Firewall (advanced)" to edit them.
                     - Blocked traffic: statistics from the firewall log (most
                       blocked ports, who tried to come in with the owner of the
                       address, blocked outbound, per day). Windows
                       does not log by default; "Enable dropped-packet logging" turns
                       it on for all profiles (asks first, can be turned off again).
                     - Network: adapters (speed, traffic, errors, discards, IP,
                       gateway, DNS), TCP retransmission rate, UDP errors, and every
                       listening port with its process and services, and whether
                       the firewall lets the network reach it (and through which
                       rule).

  Security           - Run Full Audit: score out of 100 for System, Accounts,
                       Network and Data, with the top critical issues (read-only).
                       Also checks memory integrity (HVCI), LSA protection, WDigest,
                       the SMBv1 server and NetBIOS over TCP/IP. Memory integrity and
                       LSA protection are only reported, never switched on by the
                       program: Windows checks driver compatibility when you turn
                       memory integrity on from Windows Security, and LSA protection
                       cannot be undone by editing the registry on UEFI PCs.
                     - Apply Hardening Profile:
                         Basic (4 actions)        Defender, firewall, Guest account,
                                                  auto-logon
                         Recommended (8 actions)  Basic + anonymous SAM access
                                                  restriction, built-in Administrator
                                                  disabled (with safety checks), WDigest
                                                  clear-text passwords off, SMBv1 server
                                                  off (connecting to an old NAS as a
                                                  client still works)
                         Strict (13 actions)      Recommended + RDP off, NTLMv2 only,
                                                  UAC maximum, Remote Registry off,
                                                  NetBIOS over TCP/IP off (takes effect
                                                  when the network reconnects). May break
                                                  RDP access, old NAS devices and
                                                  workgroup browsing.
                     - Advanced tweaks: telemetry services, Windows Script Host
                       (turned off, user settings ignored so a program cannot turn it
                       back on through HKCU, failures logged), .js/.vbs/.vbe/.jse/
                       .wsf/.hta associations (presets Safe/Medium/Aggressive/Custom),
                       plus a 30-second telemetry connection scanner (read-only).
                       "Open blocked scripts in Notepad" shows a script's text on
                       double click instead of removing its association.
                     - Undo a Change: restores the exact state saved before a
                       profile or advanced tweaks were applied.


  System Health      - Startup programs: Run / RunOnce keys, Startup folders and
  (more pages)         logon/boot scheduled tasks, with the program file, who signed it
                       and warnings: file missing, not signed, or (for everyone or the
                       highest privileges) in a folder a standard user can write to.
                       It also reads each program's first bytes to find its real type:
                       an executable or script hiding under a document/image name (a PE
                       called update.pdf) is flagged in red, and a program whose bytes
                       are close to random (high entropy, possibly packed or encrypted,
                       a common malware trait) in orange. This complements the antivirus:
                       ClamAV catches known malware, these heuristics catch the suspect
                       and the unknown. "Scan with ClamAV" sends the selected programs to
                       the Antivirus tab. Read-only; export to CSV.
                     - DPC / ISR load: five one-second samples of the processor time
                       spent in drivers (the usual cause of audio crackling). Read-only.
                     - Inventory: Windows edition and activation (the last five
                       characters of the key only), graphics cards with their real video
                       memory, installed programs (filter, CSV export).
                       "Saved Wi-Fi passwords and Windows key" shows the secrets this
                       PC keeps for you, on screen only, after a confirmation and as
                       administrator: Wi-Fi passwords and the firmware Windows key;
                       Windows Credential Manager entries (saved web, app and Remote
                       Desktop logins); software license keys (Office, Adobe, Autodesk,
                       VMware); and website passwords saved in Chrome, Edge, Brave and
                       Firefox. Browser and credential passwords are decrypted with the
                       Windows and browser crypto for your own account (DPAPI, AES-GCM
                       via CNG, and Firefox's own NSS, which is loaded only from its
                       administrator-protected install folder). Nothing is written to a
                       file or to the log (only counts are logged); the browser login
                       database is copied to a temporary file read once and deleted; the
                       clipboard is cleared 30 seconds after a copy; and the window
                       empties itself when closed. Domain passwords and Firefox logins
                       behind a primary password are shown as present but not readable.
                       The Wi-Fi part needs the Wireless AutoConfig service (PCs without
                       Wi-Fi have none).

  Antivirus          - Scan: files, folders, "Quick scan" (Downloads, Desktop, temporary
                       folder) or "Full scan" (every fixed disk, can take hours), with
                       ClamAV (clamscan). Shows files scanned, threats, current file and
                       a log; Stop ends the scan. A scan never deletes anything: with
                       "Move threats to quarantine" on, infected files are moved to the
                       quarantine folder. Options: scan archives, size limit,
                       "Detect unwanted apps (PUA)" (adware, bundleware, hacktools),
                       and "Thorough", which also flags encrypted archives, OLE2
                       macros and broken files and raises the archive limits (catches
                       more, but a legitimate password-protected archive or macro
                       document can then be flagged and quarantined).
                     - Quarantine: restore a file to where it came from (never over an
                       existing file), delete it for good, or open the folder.
                     - Signature update: downloads the virus signatures with freshclam
                       from database.clamav.net (about 300 MB the first time, small
                       afterwards). Asks before connecting. The scan needs this first.
                       ClamAV is used only from C:\Program Files\ClamAV, and only if that
                       folder can be changed by administrators only (same rule as the
                       program folder): otherwise the tab says so and does not run it.
                       ClamAV is a signature scanner: it finds known malware, not new
                       or unknown threats. It does not protect in real time.


5. SAFETY FEATURES
------------------
  Firewall
    - The only change the Firewall & Network tab can make is turning dropped-packet
      logging on or off, after a confirmation.

  Security hardening
    - The current state is saved to a JSON file before any change. A system
      restore point is attempted too (Windows allows only one per 24 hours; if
      it is refused, the JSON backup still allows undo).
    - The built-in Administrator is never disabled if it is the current account
      or the only enabled administrator. RDP is never disabled from an RDP session.


6. DATA FOLDER: C:\ProgramData\DD Cleaner
------------------------------------------
  logs\                    Daily log files (View > Show Logs)
  driver_blocklist\        Microsoft blocklist (DriverPolicy_Enforced.xml) + its date
  geoip\                   DB-IP City Lite database (dbip-city-lite.mmdb, ~130 MB) + date
  clamav\                  database\ (ClamAV signatures), quarantine\ (infected files and
                           manifest.json, the list of their original locations),
                           freshclam.conf and freshclam.log
  hardening_backups\       hardening_backup_*.json (profiles),
                           tweaks_backup_*.json (advanced tweaks)

  The program creates this folder with permissions for SYSTEM and Administrators
  only: "Undo a Change" trusts these backups and the driver check trusts the
  downloaded list, so no standard program may alter them. If the folder already
  exists with other permissions (created by someone else, or a link), the
  program refuses to start and asks you to delete it.
  Nothing here is cleaned automatically. Backups made by older versions stay in
  their old folder next to the exe and are no longer used.


7. UNDO / RESTORE
-----------------
  Hardening/tweaks     Security tab > Undo a Change.
  Anything else        Windows System Restore.


8. KEYBOARD SHORTCUTS
---------------------
  Ctrl+L  Show logs
  Ctrl+Q  Quit


9. UNINSTALL
------------
  Installed with the setup program: Settings > Apps, or Start Menu > DD Cleaner >
  Uninstall DD Cleaner.
  Copied by hand (no installer): delete the folder. Either way, nothing is written
  inside the program's own folder at runtime (see section 6), so deleting it is
  enough; changes you applied (hardening profiles, tweaks) stay in place: undo them
  from the program first if you want Windows back to its previous state.


10. TROUBLESHOOTING
-------------------
  - "Unsafe program folder" at start: move the whole DD_Cleaner folder to
    C:\Program Files\ (see 2).
  - "ClamAV was found but its folder is not protected": the folder
    C:\Program Files\ClamAV can be changed without administrator rights.
    Reinstall ClamAV there, or fix its permissions, so only administrators can
    write to it.
  - "Unsafe data folder" at start: delete C:\ProgramData\DD Cleaner and start the
    program again; it recreates the folder with the right permissions.
  - Antivirus warning: packaged Python programs are sometimes flagged as
    suspicious. Only use a copy you built or received from a trusted source.
  - An operation seems stuck: DISM RestoreHealth can take 30+ minutes. Closing
    the window asks before stopping running operations.
  - Report problems with the log file (View > Show Logs > Open Logs Folder).


DISCLAIMER
----------
  The hardening and tweak features modify system settings. Even with the
  safeguards above, use it at your own risk and keep a restore point or a full
  backup of your system.
