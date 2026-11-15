"""
Advanced tweaks: catalogue, command building, snapshot and revert. Pure logic: nothing is executed,
the registry reader is faked, snapshot files go to tmp_path.
"""

import json
import shlex
import os
import winreg

import pytest

from ddcleaner import tweaks
from ddcleaner.system_utils import SystemUtils

SYSROOT = os.environ["SystemRoot"].lower()


def fake_reader(state):
    """Reader returning values from a dict {(key, value): (data, type)}; anything else is absent."""
    def read(key, value):
        hit = state.get((key, value))
        return {"exists": True, "data": hit[0], "type": hit[1]} if hit else {"exists": False}
    return read


SVC = r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services"
WSH = r"HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings"
WSH_FULL = SystemUtils.normalize_registry_path(WSH)


# ---------------------------------------------------------------- catalogue and argv

def test_presets_are_nested_and_known():
    names = lambda p: [t[1] for t in tweaks.PRESETS[p]]  # noqa: E731
    assert set(names("Safe (Recommended)")) < set(names("Medium")) < set(names("Aggressive"))
    assert names("Custom") == names("Aggressive")
    for _, _, cmd, _, risk in tweaks.PRESETS["Custom"]:
        assert risk in ("Low", "Medium", "High")
        assert tweaks.parse_target(cmd)["kind"] in ("service", "reg", "assoc")


def test_every_catalogue_target_is_revertible():
    allowed = tweaks.allowed_targets()
    assert {"diagtrack", "remoteregistry", "xblgamesave"} <= allowed["service"]
    assert {".js", ".vbs", ".jse", ".wsf", ".vbe", ".hta"} <= allowed["assoc"]
    assert len(allowed["reg"]) == 4  # WSH Enabled, IgnoreUserSettings, LogSecurityFailures + the feedback value


@pytest.mark.parametrize("cmd, exe", [
    ("sc config DiagTrack start= disabled", "sc.exe"),
    ('reg add "HKLM\\SOFTWARE\\X Y" /v A /t REG_DWORD /d 0 /f', "reg.exe"),
    ("assoc .js=", "cmd.exe"),
])
def test_argv_uses_absolute_system_binaries(cmd, exe):
    argv = tweaks.hardening_argv(cmd)
    assert argv[0].lower().startswith(SYSROOT) and argv[0].lower().endswith(exe)
    if exe == "cmd.exe":
        assert argv[1:4] == ["/d", "/c", "assoc"]
    if exe == "reg.exe":
        assert argv[2] == "HKLM\\SOFTWARE\\X Y"  # quoted path kept in one argument, backslashes intact


@pytest.mark.parametrize("cmd", ["powershell -c evil", "cmd /c del x", "", "net user a b /add"])
def test_argv_rejects_other_tools(cmd):
    with pytest.raises(ValueError):
        tweaks.hardening_argv(cmd)


# ---------------------------------------------------------------- snapshot -> revert

def test_snapshot_then_revert_restores_exact_state(tmp_path):
    state = {
        (SVC + r"\DiagTrack", "Start"): (2, winreg.REG_DWORD),
        (SVC + r"\DiagTrack", "DelayedAutostart"): (1, winreg.REG_DWORD),
        (SVC + r"\RemoteRegistry", "Start"): (4, winreg.REG_DWORD),
        ("HKEY_LOCAL_MACHINE\\SOFTWARE\\Classes\\.js", None): ("JSFile", winreg.REG_SZ),
        # WSH "Enabled" absent -> revert must delete it
    }
    selected = [("Disable DiagTrack", "sc config DiagTrack start= disabled"),
                ("Disable RemoteRegistry", "sc config RemoteRegistry start= disabled"),
                ("Unassociate .js", "assoc .js="),
                ("Unassociate .vbs", "assoc .vbs="),
                ("Disable WSH", f'reg add "{WSH}" /v Enabled /t REG_DWORD /d 0 /f')]
    path = tweaks.snapshot_tweaks(selected, str(tmp_path), reader=fake_reader(state))
    assert path and os.path.basename(path).startswith("tweaks_backup_")

    commands = [c for _, c in tweaks.revert_commands_from_snapshot(path)]
    argvs = [shlex.split(c) for c in commands]
    assert ["sc", "config", "DiagTrack", "start=", "delayed-auto"] in argvs
    assert ["sc", "config", "RemoteRegistry", "start=", "disabled"] in argvs
    assert ["assoc", ".js=JSFile"] in argvs
    assert ["assoc", ".vbs="] in argvs                    # was absent -> association removed again
    assert ["reg", "delete", WSH_FULL, "/v", "Enabled", "/f"] in argvs
    for cmd in commands:
        tweaks.hardening_argv(cmd)                         # every revert command is executable


def test_revert_restores_dword_value(tmp_path):
    state = {(WSH, "Enabled"): (1, winreg.REG_DWORD)}
    path = tweaks.snapshot_tweaks([("Disable WSH", f'reg add "{WSH}" /v Enabled /t REG_DWORD /d 0 /f')],
                                  str(tmp_path), reader=fake_reader(state))
    assert [shlex.split(c) for _, c in tweaks.revert_commands_from_snapshot(path)] == [
        ["reg", "add", WSH_FULL, "/v", "Enabled", "/t", "REG_DWORD", "/d", "1", "/f"]]


def test_revert_refuses_argument_smuggling(tmp_path):
    """Audit finding: trailing backslash in the key + crafted REG_SZ data split into extra reg.exe args."""
    import json
    snap = tmp_path / "tweaks_backup_x.json"
    snap.write_text(json.dumps({"entries": [
        {"kind": "reg", "key": WSH + "\\", "value": "Enabled",
         "state": {"exists": True, "type": winreg.REG_SZ, "data": 'Sub /v Evil /t REG_SZ /d pwn /reg:32 \\'}},
        {"kind": "reg", "key": WSH, "value": "Enabled",
         "state": {"exists": True, "type": winreg.REG_SZ, "data": 'a\\" /f /v x'}},
    ]}), encoding="utf-8")
    assert tweaks.revert_commands_from_snapshot(str(snap)) == []  # both crafted entries refused

    snap.write_text(json.dumps({"entries": [
        {"kind": "reg", "key": WSH, "value": "Enabled",
         "state": {"exists": True, "type": winreg.REG_SZ, "data": "a value with spaces"}}]}), encoding="utf-8")
    [(_, cmd)] = tweaks.revert_commands_from_snapshot(str(snap))
    assert shlex.split(cmd) == ["reg", "add", WSH_FULL, "/v", "Enabled", "/t", "REG_SZ", "/d",
                                "a value with spaces", "/f"]


def test_snapshot_failure_returns_none(tmp_path):
    blocker = tmp_path / "file_not_dir"
    blocker.write_text("x")
    assert tweaks.snapshot_tweaks([("x", "assoc .js=")], str(blocker / "sub")) is None


# ---------------------------------------------------------------- tampered snapshot (runs as admin!)

@pytest.mark.parametrize("entry", [
    {"kind": "service", "service": "WinDefend", "start": {"exists": True, "data": 4}},        # not in catalogue
    {"kind": "service", "service": "DiagTrack", "start": {"exists": True, "data": 9}},        # bad start type
    {"kind": "service", "service": "DiagTrack & calc", "start": {"exists": True, "data": 2}},
    {"kind": "reg", "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "value": "evil",
     "state": {"exists": True, "type": winreg.REG_SZ, "data": r"C:\evil.exe"}},              # arbitrary key
    {"kind": "reg", "key": WSH, "value": "Enabled",
     "state": {"exists": True, "type": winreg.REG_SZ, "data": 'x" /f & calc "'}},             # quote injection
    {"kind": "reg", "key": WSH, "value": "Enabled",
     "state": {"exists": True, "type": winreg.REG_BINARY, "data": "00"}},                     # unsupported type
    {"kind": "assoc", "ext": ".exe", "state": {"exists": True, "data": "evil"}},              # not in catalogue
    {"kind": "assoc", "ext": ".js", "state": {"exists": True, "data": "JSFile & calc"}},      # bad ProgID
    {"kind": "unknown"},
    "not a dict",
])
def test_tampered_entries_are_ignored(entry):
    assert tweaks.revert_commands([entry]) == []


def test_tampered_file_keeps_only_valid_entries(tmp_path):
    good = {"kind": "service", "service": "DiagTrack", "start": {"exists": True, "data": 2}}
    evil = {"kind": "reg", "key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "value": "x",
            "state": {"exists": True, "type": winreg.REG_SZ, "data": "c:\\evil.exe"}}
    path = tmp_path / "tweaks_backup_x.json"
    path.write_text(json.dumps({"entries": [good, evil]}), encoding="utf-8")
    assert tweaks.revert_commands_from_snapshot(str(path)) == [("Restore DiagTrack (auto)",
                                                                "sc config DiagTrack start= auto")]


def test_malformed_snapshot_files(tmp_path):
    bad = tmp_path / "a.json"
    bad.write_text("[1, 2, 3]", encoding="utf-8")
    assert tweaks.revert_commands_from_snapshot(str(bad)) == []
    broken = tmp_path / "b.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        tweaks.revert_commands_from_snapshot(str(broken))


def test_win10_defaults_are_valid_commands():
    for _, cmd in tweaks.WIN10_DEFAULT_RESTORE:
        tweaks.hardening_argv(cmd)


# ---------------------------------------------------------------- WSH hardening and scripts opened in Notepad

def test_wsh_medium_preset_ignores_user_settings_and_logs_failures():
    cmds = [c for _, _, c, _, _ in tweaks.PRESETS["Medium"]]
    for value in ("Enabled", "IgnoreUserSettings", "LogSecurityFailures"):
        assert any(f"/v {value} " in c and "Windows Script Host" in c and c.startswith("reg add") for c in cmds)
    # none of them is in the Safe preset: it only touches telemetry and associations
    assert not any("Windows Script Host" in c for _, _, c, _, _ in tweaks.PRESETS["Safe (Recommended)"])


def test_wsh_extra_values_are_reverted_by_deleting_them(tmp_path):
    cmds = [(n, c) for _, n, c, _, _ in tweaks.PRESETS["Medium"] if "IgnoreUserSettings" in c or "LogSecurityFailures" in c]
    path = tweaks.snapshot_tweaks(cmds, str(tmp_path), reader=fake_reader({}))
    reverts = [shlex.split(c) for _, c in tweaks.revert_commands_from_snapshot(path)]
    assert sorted(r[4] for r in reverts) == ["IgnoreUserSettings", "LogSecurityFailures"]
    assert all(r[1] == "delete" for r in reverts)  # the values did not exist before


def test_script_extensions_cover_vbe_and_hta():
    cmds = [c for _, _, c, _, _ in tweaks.PRESETS["Safe (Recommended)"]]
    assert "assoc .vbe=" in cmds and "assoc .hta=" in cmds


def test_open_in_editor_only_rewrites_association_removals():
    assert tweaks.open_in_editor("assoc .js=") == "assoc .js=txtfile"
    assert tweaks.open_in_editor("assoc .hta=") == "assoc .hta=txtfile"
    assert tweaks.open_in_editor("assoc .js=JSFile") == "assoc .js=JSFile"
    for cmd in ("sc config DiagTrack start= disabled", r'reg add "HKLM\X" /v A /t REG_DWORD /d 0 /f'):
        assert tweaks.open_in_editor(cmd) == cmd
    assert tweaks.parse_target("assoc .js=txtfile") == {"kind": "assoc", "ext": ".js"}
    tweaks.hardening_argv("assoc .js=txtfile")  # still an allowed command
