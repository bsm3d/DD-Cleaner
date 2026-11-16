DD Cleaner 3.0
==============

Driver checks, system health, network view, security audit, antivirus pages and
cleanup for Windows 10/11 (64-bit).
It focuses on what Windows does not already provide in one place.
Author: Benoit (BSM) Saint-Moulin
License: MIT


1. PACKAGE CONTENTS
-------------------
  DD_Cleaner\             Program folder: DD_Cleaner.exe and its _internal\ folder
                          (no Python needed)
  README.txt              This file


2. REQUIREMENTS
---------------
  - Windows 10 or 11, 64-bit
  - Administrator rights: the program asks for elevation (UAC prompt) at every start
  - Antivirus scans only: ClamAV for Windows (clamav.net), installed in
    C:\Program Files\ClamAV. Not bundled with DD Cleaner. Every other page works
    without it.
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

  How the program behaves everywhere:
  - Scans, listings, reports and the audit are read-only.
  - Every action that changes the system asks for confirmation, and the answer
    selected by default is always "No". When a confirmation lists many items, its
    "Show Details" button gives the full list.
  - Removal acts on the rows you TICK (checkbox), never on the rows that are only
    selected. A row without a checkbox is protected and cannot be removed here.
  - A long operation shows a progress bar and a Stop button in the status bar
    (bottom of the window). Stop ends the running scans; a deletion or a repair
    finishes what it started.
  - The window remembers its size, the pages on screen, column widths and scan
    options. "Delete permanently" is never remembered.


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
                       Microsoft (internet needed, about 330 KB). Export to CSV.
                       Limit: signer rules are checked on embedded signatures only
                       (catalog-signed drivers are checked by hash and version).
                     - Driver age: lists third-party drivers with their age, oldest
                       first (orange: older than 3 years, red: older than 5 years).
                       Export to CSV.
                     - Unused drivers: driver packages that no connected device uses
                       (hardware that is gone, old versions that piled up). "Safe": a
                       newer version of the same driver is installed. "Check": the
                       hardware may still be yours, only unplugged. A copy of each
                       driver is saved before it is removed. Windows refuses to
                       remove a driver that is in use.
                     - Uninstall drivers: complete uninstall of a third-party driver,
                       even one a connected device uses ("Danger": the device falls
                       back to a generic driver or stops working until a driver is
                       installed again). A copy is saved and a restore point is
                       created first; the service and file a driver leaves behind
                       are offered for removal afterwards. Core drivers are locked.
                       To put a driver back: pnputil /add-driver on the saved copy.

  System Health      - Health report (read-only, last 30 days): disk health, SMART
                       prediction, temperature and wear (administrator), free space,
                       Windows reliability index, blue screens with their stop code,
                       unexpected shutdowns, hardware errors (WHEA; disk resets are
                       traced back to the disk model and serial number), disk and
                       NTFS errors, programs that crash most, uptime, pending
                       restart. "Save report" writes it to a text file.
                     - Repair tools: SFC verify / scan and repair, DISM CheckHealth /
                       ScanHealth / RestoreHealth, component store cleanup, network
                       stack reset (administrator; reboot recommended afterwards).
                       The output of SFC and DISM is shown while the tool runs, one
                       repair runs at a time, and "Stop..." ends it after a
                       confirmation.
                     - Startup programs: Run / RunOnce keys, Startup folders and
                       logon/boot scheduled tasks, with the program file, who signed it
                       and warnings: file missing, not signed, or (for everyone or the
                       highest privileges) in a folder a standard user can write to.
                       It also reads each program's first bytes to find its real type:
                       an executable or script hiding under a document/image name (a PE
                       called update.pdf) is flagged in red, and a program whose bytes
                       are close to random (high entropy, possibly packed or encrypted,
                       a common malware trait) in orange. "Scan with ClamAV" scans the
                       selected programs. Listing changes nothing; export to CSV.
                       "Remove ticked entries..." stops the ticked programs from
                       starting with Windows: the Run value is deleted, the file is
                       moved out of the Startup folder, or the scheduled task is
                       deleted. The program itself stays installed, and each entry is
                       saved first. Entries for all users and scheduled tasks need
                       administrator rights. To switch an entry off without removing
                       it: Task Manager > Startup.
                       "Persistence hunt" opens the Antivirus > Persistence page,
                       which covers more places (services, hijacked settings...).
                     - DPC / ISR load: five one-second samples of the processor time
                       spent in drivers (the usual cause of audio crackling). Read-only.
                     - Inventory: Windows edition and activation (the last five
                       characters of the key only), graphics cards with their real video
                       memory, installed programs (filter, CSV export).
                       "Saved Wi-Fi passwords and Windows key" shows the secrets this
                       PC keeps for you, on screen only, as administrator and after a
                       confirmation that starts with a PERSONAL USE ONLY warning: use it
                       only on your own PC and for your own passwords (reading someone
                       else's without permission is forbidden and may be a crime): Wi-Fi passwords and the firmware Windows key;
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

  Firewall &         - "Analyze firewall & network" fills the Firewall and Network
  Network              pages (read-only). Live traffic and World map run by themselves.
                     - Live traffic: every application using the network, refreshed
                       every 2 seconds: inbound / outbound connections, remote
                       address and host name (Internet, local network or this PC),
                       ports it listens on or binds, and, as administrator, bytes
                       received/sent and current download/upload per connection and
                       per application (counted from the moment a connection is
                       first seen). Filter by application, site, owner, port or
                       address; Pause stops sampling. Read-only.
                       Where the data goes / who comes in: for every connection,
                       the site name the program asked for (Windows DNS cache),
                       your router and local devices (with their MAC address).
                       "Group by: Destination" lists every destination with the
                       programs talking to it; "Only inbound" shows who connects to
                       this PC (red when it comes from the Internet).
                       "Look up owners (RDAP)" adds the owner of each address
                       (organization and country, from the regional Internet
                       registry: ARIN, RIPE, APNIC, LACNIC, AFRINIC). It is OFF until
                       you tick it, because it sends public IP addresses (once per
                       network block) to the registries. "Resolve host names" sends
                       remote addresses to your DNS server for reverse lookups.
                       Programs using their own encrypted DNS (some browsers) do
                       not appear in the Windows DNS cache: their destinations are
                       named by reverse DNS or by owner.
                     - World map: countries the PC talks to, with an arc from your
                       country (Windows region setting) to each destination, circles
                       sized by the number of connections, red when a computer from
                       that country connects to this PC. Hover a city, a country or a
                       link for its programs, sites, addresses, volumes and current
                       speed; click to list its connections; double-click a city to
                       look it up on VirusTotal in your browser (the destination
                       itself is not contacted); Shift+click a city to trace the
                       route to it hop by hop (Windows tracert, up to 30 hops): the
                       hops placed from the local DB-IP file are drawn on the map as a
                       dashed line, and a window lists every hop. Right-click a city
                       for a menu: show its connections, look it up, trace the route,
                       open the site itself (this connects to it), copy its addresses,
                       clear the route. Names that would overlap are left out (zoom
                       in to see them). Wheel to zoom, drag to move, double-click
                       elsewhere for the whole world.
                       Server locations: "Download DB-IP City Lite" (World map page,
                       about 60 MB, free, updated monthly) places every server in its
                       real city; the list gets a Location column. Lookups then run
                       on this PC, nothing is sent. IP Geolocation by DB-IP
                       (db-ip.com), licensed under Creative Commons Attribution 4.0.
                       Without it, the country where the network is registered is
                       used (needs "Look up owners"; large providers and CDNs then
                       often appear as US).
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

  Security           - Run full audit: score out of 100 for System, Accounts,
                       Network and Data, with the top critical issues (read-only).
                       Also checks memory integrity (HVCI), LSA protection, WDigest,
                       the SMBv1 server and NetBIOS over TCP/IP. Memory integrity and
                       LSA protection are only reported, never switched on by the
                       program: Windows checks driver compatibility when you turn
                       memory integrity on from Windows Security, and LSA protection
                       cannot be undone by editing the registry on UEFI PCs.
                       If the audit cannot run, the page says "The audit failed" and
                       shows no score.
                     - Apply hardening profile (after an audit, administrator):
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
                     - Advanced tweaks: a separate list of tweaks, chosen with
                       "Tweak set" (Safe / Medium / Aggressive / Custom): telemetry
                       services, Windows Script Host (turned off, user settings
                       ignored so a program cannot turn it back on through HKCU,
                       failures logged), .js/.vbs/.vbe/.jse/.wsf/.hta associations.
                       "Open blocked scripts in Notepad" shows a script's text on
                       double click instead of removing its association.
                       "Scan telemetry (30 s)" watches connections for 30 seconds and
                       lists those going to Microsoft / telemetry hosts (read-only).
                     - Undo a change: lists the saved states (date, what was changed,
                       number of settings) and restores the one you choose: the exact
                       state saved before a profile or tweaks were applied.

  Antivirus          - Scan: "Scan these items" (the files and folders of the list),
                       "Quick scan" (Downloads, Desktop, temporary folder) or "Full
                       scan" (every fixed disk, can take hours), with ClamAV
                       (clamscan). Several clamscan processes work in parallel, and
                       files unchanged since a clean scan can be skipped for a number
                       of days ("Forget scan memory" resets this). Shows progress,
                       files scanned, threats, current file and a log; Stop ends the
                       scan. A scan never deletes anything: with "Move threats to
                       quarantine" on, infected files are moved to the quarantine
                       folder. Options: scan archives, size limit, "Fast mode" (no
                       archives, no heuristics: quicker, catches less), "Detect
                       unwanted apps (PUA)" (adware, bundleware, hacktools), and
                       "Thorough", which also flags encrypted archives, OLE2 macros
                       and broken files (catches more, but a legitimate
                       password-protected archive or macro document can then be
                       flagged and quarantined).
                     - Quarantine: restore a file to where it came from (never over an
                       existing file), delete it for good, look it up on VirusTotal,
                       or open the folder.
                     - Signature update: downloads the virus signatures with freshclam
                       from database.clamav.net (about 300 MB the first time, small
                       afterwards). Asks before connecting; Stop ends the download.
                       The scan needs this first.
                     - Processes: every running program with its signature, folder
                       and Internet connections. Red: a Windows name outside the
                       Windows folder, a program running from Temp or Downloads, a
                       file deleted from disk, or an unsigned program talking to the
                       Internet. Orange: not signed. Read-only. A flag is a reason to
                       look, not a verdict: scan the file to know.
                     - Persistence: the places malware uses to come back after a
                       restart: services, scheduled tasks, hijacked Windows settings,
                       WMI subscriptions, hosts file, proxy, browser extensions. The
                       hunt changes nothing. Scheduled tasks, services and startup
                       values have a checkbox and can be removed ("Remove ticked
                       entries...", administrator); each one is saved first (.xml for
                       tasks, .reg for the rest). Entries that start a program that
                       no longer exists are ticked for you after a hunt.
                     - Protection (only while the program is open, there is no
                       background service): watch folders and scan each new file
                       once it is complete; a quick scan every N hours; custom YARA
                       rule files (.yar / .yara), checked by ClamAV before they are
                       installed.
                     - VirusTotal: looks up the selected files by hash (up to 10 at
                       once). Needs your own API key (File > Preferences). Only the
                       hash is sent; "Send selected file for analysis" uploads the
                       file itself, after an explicit confirmation.
                       ClamAV is used only from C:\Program Files\ClamAV, and only if that
                       folder can be changed by administrators only (same rule as the
                       program folder): otherwise the tab says so and does not run it.
                       ClamAV is a signature scanner: it finds known malware, not new
                       or unknown threats.

  Garbage            - "Scan all" runs every file preset, the search for leftovers of
                       uninstalled programs, then every registry preset. Searching
                       changes nothing: you tick what to delete.
                     - Files and folders: search by word or wildcard (*.tmp;*.bak,
                       a name in double quotes for an exact match), or pick a preset
                       (temporary files, lock files, incomplete downloads, backups
                       and old copies, crash dumps, log files, caches, installers...).
                       Choose where (user profile, AppData / ProgramData / Temp, all
                       fixed drives, or a folder) and a minimum age. "Leftovers of
                       uninstalled programs" lists folders no installed program
                       claims. Red: very likely leftovers. Orange: no installed
                       program matches and nothing touched it for 90 days. Portable
                       tools you copied yourself look the same: read before ticking.
                       "Tick likely" ticks the red and orange rows only. Deleted
                       items go to the Recycle Bin unless "Delete permanently" is
                       ticked. Grey rows are protected. A folder whose name ends
                       with ~ is never listed.
                     - Registry: search HKCU\SOFTWARE and HKLM\SOFTWARE by word or
                       wildcard, or scan presets (dead uninstall entries, dead App
                       Paths, dead startup entries, traces of removed programs,
                       usage history lists, and more, each marked Safe / Check /
                       Review). Every key is exported to a .reg file before it is
                       deleted; to undo, double-click that file. Entries under HKLM
                       need administrator rights.
                     - Overview: charts of the disks, what was found by kind, the
                       biggest items, registry entries by kind, space freed over the
                       last 30 days, and the size of the folders of a drive.


5. LISTS, FILTERS AND SHORTCUTS
-------------------------------
  In the result lists:
    Filter box           Hides the rows that do not contain the text. A hidden row is
                         never ticked, deleted or exported.
    Tick all / Untick all  Act on the rows shown.
    Space                Ticks or unticks every selected row.
    Right-click          Open location, Open in Regedit, Copy path, Copy row.
    Double click         Opens the location of the row.
    Ctrl+C               Copies the selected rows.
    Export to CSV        Saves the rows shown.

  Keyboard shortcuts:
    F5       Run the main scan or listing of the page on screen
    Esc      Stop the running scans
    Ctrl+F   Go to the filter of the list on screen
    Ctrl+L   Show the log
    Ctrl+,   Preferences (VirusTotal API key)
    Ctrl+Q   Quit


6. SAFETY FEATURES
------------------
  Confirmations
    - The default answer is always "No": pressing Enter by reflex changes nothing.

  Firewall
    - The only change the Firewall & Network tab can make is turning dropped-packet
      logging on or off, after a confirmation.

  Security hardening
    - The current state is saved to a JSON file before any change. A system
      restore point is attempted too (Windows allows only one per 24 hours; if
      it is refused, the JSON backup still allows undo).
    - The built-in Administrator is never disabled if it is the current account
      or the only enabled administrator. RDP is never disabled from an RDP session.

  Removals
    - Registry keys, scheduled tasks, services and driver packages are saved
      before they are removed (see the backups folders in section 7).
    - Core Windows keys, core drivers and protected paths have no checkbox.


7. DATA FOLDER: C:\ProgramData\DD Cleaner
------------------------------------------
  logs\                    Daily log files (View > Show Logs)
  driver_blocklist\        Microsoft blocklist (DriverPolicy_Enforced.xml) + its date
  geoip\                   DB-IP City Lite database (dbip-city-lite.mmdb, ~130 MB) + date
  clamav\                  database\ (ClamAV signatures and your YARA rules),
                           quarantine\ (infected files and manifest.json, the list of
                           their original locations), scan_cache.sqlite (files found
                           clean), protection.json (watched folders and schedule),
                           freshclam.conf and freshclam.log
  hardening_backups\       hardening_backup_*.json (profiles),
                           tweaks_backup_*.json (advanced tweaks)
  garbage_backups\         .reg exports of the registry keys deleted in Garbage
  hunt_backups\            What was removed from the Persistence page
  startup_backups\         What was removed from the Startup programs page
  driver_backups\          Copies of the drivers removed or uninstalled
  api_keys.json            Your VirusTotal API key
  garbage_stats.json       What was freed (for the Overview charts)
  ui_state.ini             Window size, pages, column widths and options

  The program creates this folder with permissions for SYSTEM and Administrators
  only: "Undo a change" trusts these backups and the driver check trusts the
  downloaded list, so no standard program may alter them. If the folder already
  exists with other permissions (created by someone else, or a link), the
  program refuses to start and asks you to delete it.
  Nothing here is cleaned automatically.


8. INTERNET CONNECTIONS
-----------------------
  The program works offline. It connects only for the features below.
    Download latest blocklist       Microsoft. Nothing is sent.
    Signature update                database.clamav.net (freshclam). Nothing is sent.
    Download DB-IP City Lite        db-ip.com. Nothing is sent.
    Resolve host names              Your DNS server: remote addresses (reverse lookups).
    Look up owners (off by default) Internet registries: public IP addresses.
    VirusTotal (your own key)       virustotal.com: a file's hash, and a file itself
                                    only after an explicit confirmation.


9. UNDO / RESTORE
-----------------
  Hardening/tweaks     Security tab > Undo a change.
  Deleted files        Windows Recycle Bin (unless "Delete permanently" was ticked).
  Registry (Garbage)   Double-click the .reg file in garbage_backups\.
  Persistence entries  The .xml / .reg files in hunt_backups\.
  Startup entries      In startup_backups\: double-click the .reg file, import the
                       .xml file in Task Scheduler, or move the file back to its
                       Startup folder.
  Drivers              pnputil /add-driver <saved folder>\*.inf /install, or the
                       restore point created before a complete uninstall.
  Anything else        Windows System Restore.


10. UNINSTALL
-------------
  Installed with the setup program: Settings > Apps, or Start Menu > DD Cleaner >
  Uninstall DD Cleaner.
  Copied by hand (no installer): delete the folder. Either way, nothing is written
  inside the program's own folder at runtime (see section 7), so deleting it is
  enough; changes you applied (hardening profiles, tweaks) stay in place: undo them
  from the program first if you want Windows back to its previous state.
  The data folder (section 7) is not removed: delete it yourself if you want.


11. TROUBLESHOOTING
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
  - An operation seems long: DISM RestoreHealth can take 30+ minutes; its output is
    shown while it runs. Closing the window asks before stopping running operations.
  - Text hard to read with a dark Windows theme: the program always uses its own
    light theme.
  - Report problems with the log file (View > Show Logs > Open logs folder).


DISCLAIMER
----------
  The hardening, tweak, repair and removal features modify system settings. Even
  with the safeguards above, use it at your own risk and keep a restore point or a
  full backup of your system.
