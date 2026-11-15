"""Audit checks and hardening actions for WDigest, SMBv1, NetBIOS, memory integrity and LSA protection.
Uses the in-memory Windows of test_security_engine: nothing real is read or written."""

import json
import os

import security_audit as sa
from security_audit import HardeningEngine, HardeningProfile, SecurityAuditor

from test_security_engine import (  # noqa: F401  (fixtures and helpers)
    fake, guard, HKLM, REG_DWORD, LSA, WDIGEST, NETBT, IFACE_A, IFACE_B, load, REG_SZ,
)

BS = chr(92)
HVCI = "SYSTEM" + BS + "CurrentControlSet" + BS + "Control" + BS + "DeviceGuard" + BS + "Scenarios" + BS + \
    "HypervisorEnforcedCodeIntegrity"


def iface(name):
    return NETBT + BS + name


# region Audit

def test_wdigest_only_flagged_when_explicitly_enabled(fake):
    assert SecurityAuditor()._check_wdigest().id == "wdigest_enabled"
    fake.reg_set(HKLM, WDIGEST, "UseLogonCredential", 0, REG_DWORD)
    assert SecurityAuditor()._check_wdigest() is None
    del fake.reg[(HKLM, WDIGEST.lower(), "uselogoncredential")]  # absent = Windows default = safe
    assert SecurityAuditor()._check_wdigest() is None


def test_smb1_check_follows_the_server_setting(fake):
    issue = SecurityAuditor()._check_smb1()
    assert issue.id == "smb1_enabled" and "Set-SmbServerConfiguration" in issue.fix_command
    fake.smb1_enabled = False
    assert SecurityAuditor()._check_smb1() is None


def test_smb1_unknown_when_the_cmdlet_fails(fake):
    fake.ps_overrides.append(("Get-SmbServerConfiguration", 1, ""))
    assert SecurityAuditor()._check_smb1() is None


def test_netbios_flags_every_interface_not_disabled(fake):
    issue = SecurityAuditor()._check_netbios()
    assert issue.id == "netbios_enabled" and "2/2" in issue.current_state
    fake.reg_set(HKLM, iface(IFACE_A), "NetbiosOptions", 2, REG_DWORD)
    assert "1/2" in SecurityAuditor()._check_netbios().current_state
    fake.reg_set(HKLM, iface(IFACE_B), "NetbiosOptions", 2, REG_DWORD)
    assert SecurityAuditor()._check_netbios() is None


def test_netbios_ignores_keys_that_are_not_interfaces(fake):
    fake.reg_set(HKLM, NETBT + BS + "Not_An_Interface", "NetbiosOptions", 0, REG_DWORD)
    assert sorted(sa._netbios_interfaces()) == sorted([IFACE_A, IFACE_B])


def test_memory_integrity_uses_the_running_state(fake):
    issue = SecurityAuditor()._check_memory_integrity()
    assert issue.id == "memory_integrity_off" and issue.fix_command is None  # never a one-click registry write
    fake.audit_hvci = {"Running": True}
    assert SecurityAuditor()._check_memory_integrity() is None


def test_memory_integrity_falls_back_to_the_configured_value(fake):
    fake.audit_hvci = {"Running": None}
    assert SecurityAuditor()._check_memory_integrity() is not None
    fake.reg_set(HKLM, HVCI, "Enabled", 1, REG_DWORD)
    assert SecurityAuditor()._check_memory_integrity() is None


def test_lsass_protection_values(fake):
    # neither RunAsPPL nor RunAsPPLBoot set: Windows 11 can protect LSASS by default here, so this is
    # reported as uncertain, not a confident "off"
    assert SecurityAuditor()._check_lsass_protection().id == "lsass_unknown"
    for ok in (1, 2):
        fake.reg_set(HKLM, LSA, "RunAsPPL", ok, REG_DWORD)
        assert SecurityAuditor()._check_lsass_protection() is None
    fake.reg_set(HKLM, LSA, "RunAsPPL", 0, REG_DWORD)
    assert SecurityAuditor()._check_lsass_protection().id == "lsass_unprotected"


def test_lsass_protection_accepts_the_boot_only_value(fake):
    fake.reg_set(HKLM, LSA, "RunAsPPLBoot", 2, REG_DWORD)
    assert SecurityAuditor()._check_lsass_protection() is None


def test_credential_protections_are_never_written_by_a_profile(fake):
    HardeningEngine().apply_profile(HardeningProfile.STRICT, create_restore_point=False)
    assert fake.reg_get(HKLM, LSA, "RunAsPPL") is None       # offered by the audit only
    assert fake.reg_get(HKLM, HVCI, "Enabled") is None

# endregion


# region Actions

def test_netbios_disable_sets_every_interface_and_reverts_exactly(fake):
    eng = HardeningEngine()
    assert eng.apply_profile(HardeningProfile.STRICT, custom_actions=["netbios_disable"],
                             create_restore_point=False)[:2] == (1, 0)
    for name in (IFACE_A, IFACE_B):
        assert fake.reg_get(HKLM, iface(name), "NetbiosOptions") == (2, REG_DWORD)
    assert eng.revert_last() == (1, 0)
    assert fake.reg_get(HKLM, iface(IFACE_A), "NetbiosOptions") == (0, REG_DWORD)
    assert fake.reg_get(HKLM, iface(IFACE_B), "NetbiosOptions") == (1, REG_DWORD)


def test_netbios_skipped_when_already_disabled(fake):
    for name in (IFACE_A, IFACE_B):
        fake.reg_set(HKLM, iface(name), "NetbiosOptions", 2, REG_DWORD)
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.STRICT, custom_actions=["netbios_disable"], create_restore_point=False)
    assert (s, f) == (0, 0) and any("already disabled" in x for x in eng.last_skipped)
    assert fake.writes() == []


def test_netbios_revert_never_recreates_a_removed_adapter(fake):
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.STRICT, custom_actions=["netbios_disable"], create_restore_point=False)
    for key in [k for k in fake.reg if k[1] == iface(IFACE_B).lower()]:
        del fake.reg[key]                                      # adapter removed in the meantime
    assert eng.revert_last() == (1, 0)
    assert fake.reg_get(HKLM, iface(IFACE_B), "NetbiosOptions") is None
    assert fake.reg_get(HKLM, iface(IFACE_A), "NetbiosOptions") == (0, REG_DWORD)


def test_netbios_revert_refuses_a_backup_naming_another_key(fake):
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.STRICT, custom_actions=["netbios_disable"], create_restore_point=False)
    data = load(eng.last_backup_path)
    entry = data["entries"][0]
    entry["before"]["interfaces"] = {
        BS.join(["..", "..", "Lsa"]): {"exists": True, "type": REG_DWORD, "data": 0},
        "Tcpip_not-a-guid": {"exists": True, "type": REG_DWORD, "data": 0},
    }
    entry["status"] = "applied"
    with open(eng.last_backup_path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    fake.reg_ops.clear()
    assert eng.revert_backup(eng.last_backup_path) == (0, 1)
    assert fake.writes() == []


def test_smb1_disable_is_verified_and_reverts_to_the_recorded_state(fake):
    eng = HardeningEngine()
    assert eng.apply_profile(HardeningProfile.RECOMMENDED, custom_actions=["smb1_disable"],
                             create_restore_point=False)[:2] == (1, 0)
    assert fake.smb1_enabled is False
    assert eng.revert_last() == (1, 0)
    assert fake.smb1_enabled is True


def test_smb1_already_off_is_skipped(fake):
    fake.smb1_enabled = False
    eng = HardeningEngine()
    s, f, _ = eng.apply_profile(HardeningProfile.RECOMMENDED, custom_actions=["smb1_disable"],
                                create_restore_point=False)
    assert (s, f) == (0, 0) and any("already off" in x for x in eng.last_skipped)
    assert not any("Set-SmbServerConfiguration" in s for s in fake.ps_scripts())


def test_smb1_failure_is_reported_when_the_setting_does_not_change(fake):
    fake.ps_overrides.append(("Set-SmbServerConfiguration", 0, "true"))  # cmdlet "succeeds", value still true
    s, f, errs = HardeningEngine().apply_profile(HardeningProfile.RECOMMENDED, custom_actions=["smb1_disable"],
                                                 create_restore_point=False)
    assert (s, f) == (0, 1) and any("Failed: Turn the SMBv1 server off" in e for e in errs)


def test_wdigest_disable_reverts_to_the_previous_value(fake):
    eng = HardeningEngine()
    eng.apply_profile(HardeningProfile.RECOMMENDED, custom_actions=["wdigest_disable"], create_restore_point=False)
    assert fake.reg_get(HKLM, WDIGEST, "UseLogonCredential") == (0, REG_DWORD)
    assert eng.revert_last() == (1, 0)
    assert fake.reg_get(HKLM, WDIGEST, "UseLogonCredential") == (1, REG_DWORD)


def test_new_actions_are_in_the_expected_profiles():
    ids = lambda p: {a["id"] for a in HardeningEngine()._get_profile_actions(p)}  # noqa: E731
    assert {"wdigest_disable", "smb1_disable"} <= ids(HardeningProfile.RECOMMENDED)
    assert not {"wdigest_disable", "smb1_disable", "netbios_disable"} & ids(HardeningProfile.BASIC)
    assert "netbios_disable" not in ids(HardeningProfile.RECOMMENDED)
    assert "netbios_disable" in ids(HardeningProfile.STRICT)
    assert [sa.profile_action_count(p) for p in (HardeningProfile.BASIC, HardeningProfile.RECOMMENDED,
                                                 HardeningProfile.STRICT)] == [4, 8, 13]

# endregion


# region Cross-thread signal marshaling (the class of bug that silently drops a QThread signal's payload)
#
# A plain method call to a slot (e.g. window._on_x_complete(args)) runs in the test's own thread and never
# goes through Qt's queued-connection marshaling, so it cannot catch a Signal() declared with a C++ type that
# does not actually fit the Python value being emitted (PySide6/Shiboken then logs "Cannot copy-convert ...
# to C++" and the slot receives nothing usable for that argument - no Python exception is raised). These
# tests run the real QThread via .start() and wait on a real event loop, the only way to exercise that path.

from PySide6.QtCore import QCoreApplication, QEventLoop, QTimer


def run_worker_thread_and_wait(worker, timeout_ms=10000):
    """Start a real QThread and pump a real event loop until it finishes (or times out)."""
    QCoreApplication.instance() or QCoreApplication([])
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    QTimer.singleShot(timeout_ms, loop.quit)
    worker.start()
    loop.exec()
    assert not worker.isRunning(), "worker did not finish within the timeout"


def test_security_audit_worker_delivers_domain_scores_across_threads(fake):  # noqa: F811
    """Regression: SecurityAuditWorker.finished used to be Signal(int, dict). A dict whose values are
    DomainScore objects is not a Qt-convertible type, so Shiboken silently dropped it on delivery to the GUI
    thread: the int (global_score) arrived, the dict (domain_scores) did not, and every 'Scores by Domain'
    tile stayed stuck on its placeholder ('-- / 25', 'Not audited') after a real audit run."""
    from security_audit import SecurityAuditor, SecurityDomain
    from ddcleaner.workers import SecurityAuditWorker

    worker = SecurityAuditWorker(SecurityAuditor())
    received = {}
    worker.finished.connect(lambda score, domains: received.update(score=score, domains=domains))
    run_worker_thread_and_wait(worker)

    assert received.get("score") is not None
    domains = received.get("domains")
    assert isinstance(domains, dict) and len(domains) == 4
    assert set(domains) == set(SecurityDomain)
    for domain_score in domains.values():
        assert hasattr(domain_score, "current_score") and hasattr(domain_score, "max_score")
        assert domain_score.max_score > 0  # the actual field the UI divides by: must not be a dropped/empty value

# endregion
