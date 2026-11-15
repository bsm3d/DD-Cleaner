"""
Health report evaluators: fed with fake collector data, nothing is read from or changed on the system
(except the read-only smoke test at the end).
"""

import struct
import uuid
from datetime import timedelta

from ddcleaner import health as h


def cper(notification: str, section: bytes = b"") -> str:
    """Minimal CPER record as WHEA-Logger stores it (decimal byte values separated by spaces)."""
    raw = bytearray(b"CPER" + bytes(124))
    raw[80:96] = uuid.UUID(notification).bytes_le
    raw += section
    return " ".join(str(b) for b in raw)


STORPORT = cper("0033f803-2e70-4e88-992c-6f26daf3db7a",
                b"STORPORT\x01\x00\x06\x01" + bytes(16) + "storahci".encode("utf-16-le") + bytes(20)
                + b"WDC     \x00WD2003FZEX-00SRL\x00\xa4\x00")
MCE = cper("e8f56ffe-919c-4cc5-ba88-65abe14913bb")


def event(eid, time="2026-09-20T10:00:00", level=2, props=(), provider="", message=""):
    return {"Id": eid, "Time": time, "Level": level, "Props": list(props), "Provider": provider, "Message": message}


def statuses(items):
    return {(i.category, i.status) for i in items}


# region Decoding

def test_bugcheck_parsing():
    assert h.parse_bugcheck("0x0000009f (0x0000000000000003, 0xffff)") == 0x9F
    assert h.parse_bugcheck("159") == 159
    assert h.parse_bugcheck("") is None
    assert h.bugcheck_name(0x133) == "DPC_WATCHDOG_VIOLATION"


def test_whea_storport_record_names_driver_and_disk():
    rec = h.decode_whea_record(STORPORT)
    assert rec == {"source": "Storage controller (storport)", "driver": "storahci", "device": "WDC WD2003FZEX-00SRL"}


def test_whea_cpu_record_and_garbage():
    assert h.decode_whea_record(MCE)["source"] == "Machine check (CPU)"
    assert h.decode_whea_record("1 2 3") == {}
    assert h.decode_whea_record("not numbers") == {}

# endregion


# region Crashes and hardware

def test_no_events_is_all_ok():
    items = h.evaluate_crashes({"bugchecks": None, "kernel_power": [], "whea": None, "storage": None}, [])
    assert all(i.status == h.OK for i in items)


def test_blue_screens_are_counted_once_and_named():
    events = {
        "bugchecks": [event(1001, "2026-09-20T10:05:00", props=["0x00000133 (0x1, 0x2)"])],
        # same crash seen by Kernel-Power 41 a few minutes earlier -> not counted twice
        "kernel_power": [event(41, "2026-09-20T10:03:00", props=["307"]),
                         event(41, "2026-09-22T08:00:00", props=["0"])],
    }
    items = h.evaluate_crashes(events, [])
    bsod = next(i for i in items if "blue screen" in i.title)
    assert bsod.title.startswith("1 blue screen") and bsod.status == h.WARNING
    assert any("DPC_WATCHDOG_VIOLATION" in d for d in bsod.details)
    resets = next(i for i in items if "unexpected shutdown" in i.title)
    assert resets.title.startswith("1 unexpected") and resets.status == h.INFO


def test_three_blue_screens_are_critical():
    events = {"bugchecks": [event(1001, f"2026-09-{d}T10:00:00", props=["0x0000009f"]) for d in (10, 12, 14)]}
    bsod = next(i for i in h.evaluate_crashes(events, []) if "blue screen" in i.title)
    assert bsod.status == h.CRITICAL


def test_storport_whea_goes_to_storage_with_disk_identity():
    disks = {"disks": [{"DeviceId": "0", "Name": "WDC WD2003FZEX-00SRLA0", "Serial": "AAA"},
                       {"DeviceId": "1", "Name": "WDC WD2003FZEX-00SRLA0", "Serial": "BBB"},
                       {"DeviceId": "2", "Name": "Samsung SSD", "Serial": "CCC"}]}
    events = {"whea": [event(1, props=["462", STORPORT], provider="Microsoft-Windows-WHEA-Logger")] * 2,
              "storage": [event(157, level=3, provider="disk", message="Disk 0 has been surprise removed.")]}
    items = h.evaluate_crashes(events, [], disks)
    disk_item = next(i for i in items if i.title.startswith("Disk WDC"))
    assert disk_item.status == h.CRITICAL and "2 fatal device error(s) reported by storahci" in disk_item.title
    assert any("Disk 0 (serial AAA), Disk 1 (serial BBB)" in d for d in disk_item.details)
    assert any("'Disk 0' in the events = WDC WD2003FZEX-00SRLA0 (serial AAA)" in d for d in disk_item.details)
    hardware = next(i for i in items if i.category == "Hardware")
    assert hardware.status == h.OK  # not reported as a CPU/memory problem


def test_cpu_whea_is_hardware():
    items = h.evaluate_crashes({"whea": [event(18, level=2, props=["1", MCE], message="fatal")]}, [])
    hardware = next(i for i in items if i.category == "Hardware")
    assert hardware.status == h.CRITICAL and "Machine check" in hardware.details[1]

# endregion


# region Disks, space, stability, apps, uptime

def test_disk_health_thresholds():
    data = {"disks": [
        {"Name": "A", "Media": "SSD", "Health": "Healthy", "Size": 1e12,
         "Reliability": {"Temperature": 45, "Wear": 10, "ReadErrorsUncorrected": 0, "PowerOnHours": 100}},
        {"Name": "B", "Media": "HDD", "Health": "Healthy", "Size": 2e12, "Reliability": {"Temperature": 58}},
        {"Name": "C", "Media": "SSD", "Health": "Healthy", "Size": 1e12, "Reliability": {"Wear": 95}},
        {"Name": "D", "Media": "SSD", "Health": "Unhealthy", "Size": 1e12, "Reliability": None},
    ], "smart": [{"Instance": "X", "PredictFailure": False}]}
    by_name = {i.title[0]: i.status for i in h.evaluate_disks(data)}
    assert by_name == {"A": h.OK, "B": h.WARNING, "C": h.CRITICAL, "D": h.CRITICAL}


def test_smart_prediction_and_unreadable_disks():
    failing = h.evaluate_disks({"disks": [], "smart": [{"Instance": "IDE\\Disk1", "PredictFailure": True}]})
    assert any(i.status == h.CRITICAL and "SMART predicts" in i.title for i in failing)
    assert h.evaluate_disks(None)[0].status == h.UNKNOWN


def test_free_space_thresholds():
    gb = 1e9
    items = h.evaluate_volumes([
        {"root": "C:\\", "total": 500 * gb, "free": 200 * gb, "system": True},
        {"root": "D:\\", "total": 1000 * gb, "free": 80 * gb},
        {"root": "E:\\", "total": 100 * gb, "free": 3 * gb, "system": True},
    ])
    assert [i.status for i in items] == [h.OK, h.WARNING, h.CRITICAL]
    assert items[2].details  # system drive gets an explanation


def test_stability_index():
    assert h.evaluate_stability({"stability": {"Current": 9.5, "Minimum": 8}}).status == h.OK
    assert h.evaluate_stability({"stability": {"Current": 1.1, "Minimum": 1}}).status == h.CRITICAL
    assert h.evaluate_stability({"stability": None}).status == h.UNKNOWN


def test_app_crashes_grouped_by_program():
    crashes = [event(1000, props=["python.exe"])] * 12 + [event(1002, props=["app.exe"])]
    item = h.evaluate_app_crashes({"app_crashes": crashes})
    assert item.status == h.WARNING
    assert item.details[:2] == ["python.exe: 12 crash(es)", "app.exe: 1 hang(s)"]
    assert h.evaluate_app_crashes({"app_crashes": None}).status == h.OK


def test_uptime_and_pending_restart():
    assert [i.status for i in h.evaluate_uptime(timedelta(days=2), [])] == [h.OK]
    items = h.evaluate_uptime(timedelta(days=45), ["Windows Update is waiting for a restart"])
    assert [i.status for i in items] == [h.WARNING, h.WARNING]


def test_report_survives_missing_collectors():
    items = h.build_report(None, None, [], timedelta(hours=1), [], [])
    assert statuses(items) >= {("Disks", h.UNKNOWN), ("Crashes", h.UNKNOWN), ("Stability", h.UNKNOWN)}

# endregion


def test_local_readers_run():
    """Read-only calls on this machine: they must not raise."""
    assert h.uptime().total_seconds() > 0
    assert any(v["system"] for v in h.fixed_volumes())
    assert isinstance(h.pending_reboot_reasons(), list)
    assert isinstance(h.minidumps(), list)
