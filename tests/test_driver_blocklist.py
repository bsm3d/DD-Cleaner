"""
Vulnerable driver blocklist: PE signature parsing, policy parsing and matching, download validation.
Read-only: real drivers of System32\\drivers are only read; downloads are faked; files go to tmp_path.
"""

import glob
import io
import os
import struct
import zipfile

import pytest

from ddcleaner import driver_blocklist as db
from ddcleaner import pe_signature as ps

DRIVERS = sorted(glob.glob(os.path.join(os.environ["SystemRoot"], "System32", "drivers", "*.sys")))


def signed_digest(data: bytes):
    """(algorithm, digest) the publisher signed (SpcIndirectDataContent of the first signature)."""
    lay = ps.pe_layout(data)
    length = struct.unpack_from("<I", data, lay.cert_offset)[0]
    buf = data[lay.cert_offset + 8:lay.cert_offset + length]
    _, cs, ce = ps.der_read(buf, 0)
    explicit = ps.der_children(buf, cs, ce)[1]
    _, sd_cs, sd_ce = ps.der_read(buf, explicit[2])
    content_info = ps.der_children(buf, sd_cs, sd_ce)[2]
    _, i_cs, i_ce = ps.der_read(buf, ps.der_children(buf, content_info[2], content_info[3])[1][2])
    digest_info = ps.der_children(buf, i_cs, i_ce)[1]
    alg, digest = ps.der_children(buf, digest_info[2], digest_info[3])
    oid = ps.der_children(buf, alg[2], alg[3])[0]
    name = {"1.3.14.3.2.26": "sha1", "2.16.840.1.101.3.4.2.1": "sha256"}[ps.der_oid(buf[oid[2]:oid[3]])]
    return name, buf[digest[2]:digest[3]].hex().upper()


@pytest.fixture(scope="module")
def signed_driver():
    """A third-party-style driver: embedded signature with an issuer and a version resource."""
    for path in DRIVERS:
        info = ps.inspect_file(path)
        if info.signatures and len(info.signatures[0].chain) >= 2 and info.version \
                and info.strings.get("OriginalFilename"):
            return info
    pytest.skip("no embedded-signed driver with version info on this machine")


def policy_xml(file_rules="", signers="", scenario_rules="", denied_signers="", user_rules=""):
    return f"""<?xml version="1.0" encoding="utf-8"?>
<SiPolicy xmlns="urn:schemas-microsoft-com:sipolicy" PolicyType="Base Policy">
  <VersionEx>10.0.1.0</VersionEx>
  <FileRules>
    <Allow ID="ID_ALLOW_ALL_1" FriendlyName="" FileName="*" />
    {file_rules}
  </FileRules>
  <Signers>{signers}</Signers>
  <SigningScenarios>
    <SigningScenario Value="131" ID="ID_SIGNINGSCENARIO_DRIVERS">
      <ProductSigners>
        <DeniedSigners>{denied_signers}</DeniedSigners>
        <FileRulesRef>{scenario_rules}</FileRulesRef>
      </ProductSigners>
    </SigningScenario>
    <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_USER">
      <ProductSigners><FileRulesRef>{user_rules}</FileRulesRef></ProductSigners>
    </SigningScenario>
  </SigningScenarios>
</SiPolicy>""".encode("utf-8")


def version_text(v):
    return ".".join(str(x) for x in v)


# region PE parsing

def test_authenticode_hash_equals_the_signed_digest():
    checked = 0
    for path in DRIVERS:
        with open(path, "rb") as f:
            data = f.read()
        try:
            lay = ps.pe_layout(data)
        except ps.PEFormatError:
            continue
        if not lay.cert_size:
            continue
        algo, digest = signed_digest(data)
        assert ps.authenticode_hashes(data)[algo] == digest, path
        checked += 1
        if checked >= 40:
            break
    assert checked >= 5


def test_signature_chain_goes_from_leaf_to_issuer(signed_driver):
    chain = signed_driver.signatures[0].chain
    assert chain[0].issuer == chain[1].subject
    assert signed_driver.signer == chain[0].common_name != ""
    assert all(len(h) in (40, 64, 96) for h in chain[1].tbs_hashes)


def test_not_a_pe_file_is_reported_not_raised(tmp_path):
    p = tmp_path / "fake.sys"
    p.write_bytes(b"MZ" + b"\0" * 10)
    info = ps.inspect_file(str(p))
    assert info.error and not info.hashes


def test_unsigned_pe_has_hash_but_no_signature(tmp_path, signed_driver):
    data = bytearray(open(signed_driver.path, "rb").read())
    lay = ps.pe_layout(bytes(data))
    struct.pack_into("<II", data, lay.cert_dir_offset, 0, 0)
    unsigned = bytes(data[:lay.cert_offset])
    p = tmp_path / "unsigned.sys"
    p.write_bytes(unsigned)
    info = ps.inspect_file(str(p))
    assert not info.error and not info.signatures
    assert info.hashes["sha256"] == signed_driver.hashes["sha256"]  # the hash ignores the signature

# endregion


# region Policy parsing and matching

def test_hash_rule_matches_and_user_mode_rules_are_ignored(signed_driver):
    sha = signed_driver.hashes["sha256"]
    xml = policy_xml(
        file_rules=f'<Deny ID="ID_DENY_K" FriendlyName="bad.sys Hash Sha256" Hash="{sha}" />'
                   f'<Deny ID="ID_DENY_U" FriendlyName="user" Hash="{signed_driver.hashes["sha1"]}" />',
        scenario_rules='<FileRuleRef RuleID="ID_DENY_K" />', user_rules='<FileRuleRef RuleID="ID_DENY_U" />')
    policy = db.parse_policy(xml)
    assert list(policy.hashes) == [sha]
    assert policy.match(signed_driver) == ["Hash (SHA256): bad.sys Hash Sha256"]


def test_file_rule_uses_original_filename_and_version_range(signed_driver):
    name = signed_driver.strings["OriginalFilename"].upper()  # comparison is case-insensitive
    v = signed_driver.version

    def rule(maximum):
        xml = policy_xml(
            file_rules=f'<Deny ID="ID_DENY_F" FriendlyName="old" FileName="{name}" '
                       f'MinimumFileVersion="0.0.0.0" MaximumFileVersion="{maximum}" />',
            scenario_rules='<FileRuleRef RuleID="ID_DENY_F" />')
        return db.parse_policy(xml)

    assert rule(version_text(v)).match(signed_driver)             # max is inclusive
    older = (v[0], v[1], v[2], v[3] - 1) if v[3] else (v[0] - 1, 65535, 65535, 65535)
    assert not rule(version_text(older)).match(signed_driver)     # file is newer than the vulnerable range


def signer_policy(signed_driver, publisher=None, attrib=None, oem=None, signature=0):
    tbs = sorted(signed_driver.signatures[signature].chain[1].tbs_hashes, key=len)[1]  # SHA256 form
    pub = f'<CertPublisher Value="{publisher}" />' if publisher is not None else ""
    oem_el = f'<CertOemID Value="{oem}" />' if oem is not None else ""
    ref = '<FileAttribRef RuleID="ID_FILEATTRIB_X" />' if attrib else ""
    return db.parse_policy(policy_xml(
        file_rules=attrib or "",
        signers=f'<Signer ID="ID_SIGNER_X" Name="Test CA - Vendor"><CertRoot Type="TBS" Value="{tbs}" />{pub}{oem_el}{ref}</Signer>',
        denied_signers='<DeniedSigner SignerId="ID_SIGNER_X" />'))


def test_signer_rule_needs_issuer_tbs_and_publisher(signed_driver):
    assert signer_policy(signed_driver, publisher=signed_driver.signer).match(signed_driver) == \
        ["Signer: Test CA - Vendor"]
    assert not signer_policy(signed_driver, publisher="Someone Else Ltd").match(signed_driver)


def test_signer_rule_with_file_attribute(signed_driver):
    name = signed_driver.strings["OriginalFilename"]
    v = version_text(signed_driver.version)
    match = f'<FileAttrib ID="ID_FILEATTRIB_X" FileName="{name}" MinimumFileVersion="{v}" MaximumFileVersion="{v}" />'
    other = f'<FileAttrib ID="ID_FILEATTRIB_X" FileName="other.sys" MinimumFileVersion="0.0.0.0" />'
    assert signer_policy(signed_driver, publisher=signed_driver.signer, attrib=match).match(signed_driver)
    assert not signer_policy(signed_driver, publisher=signed_driver.signer, attrib=other).match(signed_driver)


def test_signer_rule_with_oem_id():
    """WHQL-style rule: issuer TBS + OPUS program name, no publisher."""
    for path in DRIVERS:
        info = ps.inspect_file(path)
        index = next((i for i, s in enumerate(info.signatures) if s.opus_program and len(s.chain) >= 2), None)
        if index is not None:
            break
    else:
        pytest.skip("no driver signature with an OPUS program name on this machine")
    opus = info.signatures[index].opus_program
    assert signer_policy(info, oem=opus.upper(), signature=index).match(info)
    assert not signer_policy(info, oem="Another Vendor", signature=index).match(info)


def fake_info(tbs_payload=b"leafless", opus="Vendor Inc.", version=(1, 2, 3, 4), original="drv.sys"):
    issuer = ps.Certificate(der=b"", tbs=tbs_payload, serial=b"\x01", issuer=b"root", subject=b"ca")
    leaf = ps.Certificate(der=b"", tbs=b"leaf", serial=b"\x02", issuer=b"ca", subject=b"leaf")
    return ps.PEInfo(path="x.sys", hashes={"sha1": "0" * 40, "sha256": "0" * 64},
                     signatures=[ps.Signature(chain=[leaf, issuer], opus_program=opus)],
                     version=version, strings={"OriginalFilename": original})


def test_oem_id_rule_without_publisher_does_not_match_every_whql_driver():
    import hashlib
    tbs = hashlib.sha256(b"third party component ca").hexdigest().upper()
    signer = db.DeniedSigner(name="CA 2014 Cheat Engine OPUS", tbs={tbs}, oem_id="Cheat Engine")
    assert signer.matches(fake_info(b"third party component ca", opus="cheat engine"))
    assert not signer.matches(fake_info(b"third party component ca", opus="Realtek Semiconductor"))
    assert not signer.matches(fake_info(b"another ca", opus="Cheat Engine"))


def test_deny_rule_version_semantics():
    """Microsoft App Control docs: in a deny rule, MinimumFileVersion alone means 'this version and older',
    MaximumFileVersion alone 'this version and newer' (the audit found the reverse was implemented)."""
    minimum_only = db.FileAttribute("OriginalFilename", "drv.sys", db.parse_version("1.0.0.1"), None)
    assert minimum_only.matches(fake_info(version=(1, 0, 0, 1)))
    assert minimum_only.matches(fake_info(version=(0, 9, 0, 0)))      # old vulnerable build: blocked
    assert not minimum_only.matches(fake_info(version=(1, 2, 3, 4)))  # fixed build: not blocked
    assert not minimum_only.matches(fake_info(version=None))
    assert not minimum_only.matches(fake_info(original="other.sys"))
    maximum_only = db.FileAttribute("OriginalFilename", "drv.sys", None, db.parse_version("2.0.0.0"))
    assert maximum_only.matches(fake_info(version=(2, 5, 0, 0))) and not maximum_only.matches(fake_info(version=(1, 9, 9, 9)))
    both = db.FileAttribute("OriginalFilename", "drv.sys", db.parse_version("1.0.0.0"), db.parse_version("1.5.0.0"))
    assert both.matches(fake_info(version=(1, 2, 3, 4))) and not both.matches(fake_info(version=(1, 6, 0, 0)))


def test_panio_rule_of_the_real_policy_blocks_old_builds_only():
    """The real blocklist has 'PanIO.sys MinimumFileVersion=1.0.0.1' without maximum."""
    xml = policy_xml(file_rules='<FileAttrib ID="ID_FILEATTRIB_PANIO" FileName="PanIO.sys" MinimumFileVersion="1.0.0.1" />',
                     signers='<Signer ID="ID_SIGNER_P" Name="PassMark"><CertRoot Type="TBS" Value="AA" />'
                             '<FileAttribRef RuleID="ID_FILEATTRIB_PANIO" /></Signer>',
                     denied_signers='<DeniedSigner SignerId="ID_SIGNER_P" />')
    attr = db.parse_policy(xml).signers[0].file_attributes[0]
    assert attr.matches(fake_info(version=(1, 0, 0, 1), original="PanIO.sys"))
    assert not attr.matches(fake_info(version=(2, 0, 0, 0), original="PanIO.sys"))


def test_invalid_policies_are_refused():
    with pytest.raises(ValueError):
        db.parse_policy(b'<?xml version="1.0"?><Other xmlns="urn:x" />')
    with pytest.raises(ValueError):
        db.parse_policy(policy_xml())  # no deny rule at all

# endregion


# region Download and cache

class FakeResponse:
    def __init__(self, url, body):
        self.url, self.body = url, body

    def geturl(self):
        return self.url

    def read(self, n=-1):
        return self.body[:n] if n >= 0 else self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def zipped(xml: bytes, name="VulnerableDriverBlockList/DriverPolicy_Enforced.xml") -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr(name, xml)
    return out.getvalue()


VALID_XML = policy_xml(file_rules=f'<Deny ID="ID_DENY_A" FriendlyName="a" Hash="{"A" * 64}" />',
                       scenario_rules='<FileRuleRef RuleID="ID_DENY_A" />')


def test_download_stores_policy_and_metadata(tmp_path):
    url = "https://download.microsoft.com/download/x/VulnerableDriverBlockList.zip"
    policy = db.download_blocklist(str(tmp_path), opener=lambda *a, **k: FakeResponse(url, zipped(VALID_XML)))
    assert policy.version == "10.0.1.0"
    cached, meta = db.load_policy(str(tmp_path))
    assert cached.hashes == policy.hashes
    assert meta["version"] == "10.0.1.0" and meta["source"] == url


@pytest.mark.parametrize("url", ["https://evil.example/VulnerableDriverBlockList.zip",
                                 "http://download.microsoft.com/x.zip",
                                 "https://microsoft.com.evil.example/x.zip"])
def test_download_refuses_other_locations(tmp_path, url):
    with pytest.raises(ValueError):
        db.download_blocklist(str(tmp_path), opener=lambda *a, **k: FakeResponse(url, zipped(VALID_XML)))
    assert not os.listdir(tmp_path)


def test_download_keeps_previous_list_when_new_one_is_unusable(tmp_path):
    url = "https://download.microsoft.com/x.zip"
    db.download_blocklist(str(tmp_path), opener=lambda *a, **k: FakeResponse(url, zipped(VALID_XML)))
    with pytest.raises(ValueError):
        db.download_blocklist(str(tmp_path), opener=lambda *a, **k: FakeResponse(url, zipped(b"<broken")))
    with pytest.raises(ValueError):
        db.download_blocklist(str(tmp_path), opener=lambda *a, **k: FakeResponse(url, zipped(VALID_XML, "other.xml")))
    assert db.load_policy(str(tmp_path))[0].version == "10.0.1.0"


def test_no_cached_policy(tmp_path):
    assert db.load_policy(str(tmp_path)) == (None, {})

# endregion


# region Inventory and protection state

def test_normalize_driver_paths():
    root = os.environ["SystemRoot"]
    drive = os.path.splitdrive(root)[0]
    assert db.normalize_driver_path(r"\SystemRoot\System32\drivers\x.sys") == os.path.join(root, r"System32\drivers\x.sys")
    assert db.normalize_driver_path(r"System32\drivers\x.sys") == os.path.join(root, r"System32\drivers\x.sys")
    assert db.normalize_driver_path(r"\??\D:\Tools\x.sys") == r"D:\Tools\x.sys"
    assert db.normalize_driver_path(r"\Windows\System32\x.sys") == os.path.normpath(drive + r"\Windows\System32\x.sys")
    assert db.normalize_driver_path(r'"%SystemRoot%\System32\drivers\x.sys"') == os.path.join(root, r"System32\drivers\x.sys")
    volume = next((dev for dev, letter in db.device_map().items() if letter == drive.upper()), None)
    if volume:  # kernel path of a loaded driver -> its drive letter
        assert db.normalize_driver_path(volume + r"\Tools\x.sys") == os.path.join(drive + "\\", "Tools", "x.sys")
    assert db.normalize_driver_path(r"\Device\NoSuchVolume\x.sys") == ""
    assert db.normalize_driver_path(r"SystemRoot\System32\drivers\x.sys") == os.path.join(root, r"System32\drivers\x.sys")
    assert db.normalize_driver_path("x.sys") == ""


def test_inventory_finds_loaded_and_installed_drivers():
    drivers = db.collect_driver_files()
    assert len({d.path.lower() for d in drivers}) == len(drivers)
    assert any(d.loaded for d in drivers)
    assert any(d.service and d.start for d in drivers)
    assert all(os.path.isfile(d.path) for d in drivers)


def test_check_drivers_reports_matches_and_stops(signed_driver):
    policy = db.BlocklistPolicy("t", {signed_driver.hashes["sha256"]: "listed"}, [], [])
    listed = db.DriverFile(path=signed_driver.path, service="svc", start="Manual")
    other = next(p for p in DRIVERS if p != signed_driver.path)
    results = db.check_drivers(policy, [listed, db.DriverFile(path=other)])
    assert [r.flagged for r in results] == [True, False]
    assert results[0].driver.state == "Installed (Manual)"
    assert db.check_drivers(policy, [listed], stop=lambda: True) == []


@pytest.mark.parametrize("setting,hvci,build,enforced", [
    (None, False, 19045, False),   # Windows 10 default
    (1, False, 19045, True),
    (0, True, 22631, False),       # explicitly turned off
    (None, True, 19045, True),     # memory integrity enforces it
    (None, False, 22621, True),    # Windows 11 22H2 default
])
def test_protection_state(setting, hvci, build, enforced):
    state = db.ProtectionState(setting, hvci, build)
    assert state.enforced is enforced
    assert ("Enforced: yes" if enforced else "Enforced: NO") in state.summary

# endregion
