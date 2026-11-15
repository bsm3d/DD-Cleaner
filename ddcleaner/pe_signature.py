"""
PE file facts needed to evaluate a Windows code integrity policy, in pure Python (read-only):
  - Authenticode flat hashes (SHA1/SHA256), the hash WDAC "Hash" rules use;
  - certificates of the embedded signature(s): chain from the leaf upwards, TBS hashes, leaf CN,
    and the SpcSpOpusInfo program name that WDAC calls the OEM ID;
  - version resource (file version, OriginalFilename, InternalName, ProductName, FileDescription).

Catalog-signed files have no embedded signature: only their hash and version can be checked.
"""

import ctypes
import hashlib
import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from ddcleaner.common import system_dll

CERT_TABLE_INDEX = 4
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_NESTED_SIGNATURE = "1.3.6.1.4.1.311.2.4.1"
OID_SPC_SP_OPUS_INFO = "1.3.6.1.4.1.311.2.1.12"
OID_COMMON_NAME = "2.5.4.3"
MAX_SIGNATURE_SIZE = 2 * 1024 * 1024   # real driver signatures are a few dozen KB
MAX_NESTING = 4
MAX_CERTIFICATES = 64
MAX_SIGNERS = 16
MAX_OID_BYTES = 64                      # an OID longer than this is not a real one (and parsing it is quadratic)


class PEFormatError(ValueError):
    pass


# region DER

def der_read(buf: bytes, off: int) -> Tuple[int, int, int]:
    """Read one DER TLV at off. Returns (tag, content_start, content_end)."""
    if off + 2 > len(buf):
        raise PEFormatError("truncated DER")
    tag = buf[off]
    length = buf[off + 1]
    pos = off + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise PEFormatError("unsupported DER length")  # indefinite (BER) or absurd
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(buf):
        raise PEFormatError("DER length past end")
    return tag, pos, end


def der_children(buf: bytes, start: int, end: int) -> List[Tuple[int, int, int, int]]:
    """Children of a constructed value: list of (tag, tlv_start, content_start, content_end)."""
    out = []
    off = start
    while off < end:
        tag, cs, ce = der_read(buf, off)
        out.append((tag, off, cs, ce))
        off = ce
    return out


def der_oid(content: bytes) -> str:
    if not content:
        return ""
    if len(content) > MAX_OID_BYTES:
        raise PEFormatError("OID too long")
    parts = [content[0] // 40, content[0] % 40]
    value = 0
    for b in content[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def der_string(tag: int, content: bytes) -> str:
    if tag == 0x1E:  # BMPString
        return content.decode("utf-16-be", errors="replace")
    if tag == 0x1C:  # UniversalString
        return content.decode("utf-32-be", errors="replace")
    if tag in (0x13, 0x16, 0x14):  # Printable, IA5, Teletex
        return content.decode("latin-1")
    return content.decode("utf-8", errors="replace")

# endregion


# region Certificates

@dataclass
class Certificate:
    der: bytes
    tbs: bytes
    serial: bytes
    issuer: bytes   # raw DER Name, compared byte for byte
    subject: bytes

    @property
    def tbs_hashes(self) -> set:
        """TBS hash with every algorithm WDAC uses (the policy value length tells which applies)."""
        return {hashlib.new(a, self.tbs).hexdigest().upper() for a in ("sha1", "sha256", "sha384")}

    @property
    def common_name(self) -> str:
        return name_attribute(self.subject, OID_COMMON_NAME)


def parse_certificate(der: bytes) -> Certificate:
    _, cs, ce = der_read(der, 0)
    tbs_tag, tbs_start, tbs_cs, tbs_ce = der_children(der, cs, ce)[0]
    fields = der_children(der, tbs_cs, tbs_ce)
    if fields and fields[0][0] == 0xA0:  # [0] version
        fields = fields[1:]
    if len(fields) < 5:
        raise PEFormatError("bad certificate")
    serial = der[fields[0][2]:fields[0][3]]
    issuer = der[fields[2][1]:fields[2][3]]
    subject = der[fields[4][1]:fields[4][3]]
    return Certificate(der=der, tbs=der[tbs_start:tbs_ce], serial=serial, issuer=issuer, subject=subject)


def name_attribute(name_der: bytes, oid: str) -> str:
    """First value of an attribute (e.g. CN) in a DER Name, '' when absent."""
    try:
        _, cs, ce = der_read(name_der, 0)
        for _, _, rdn_cs, rdn_ce in der_children(name_der, cs, ce):
            for _, _, a_cs, a_ce in der_children(name_der, rdn_cs, rdn_ce):
                (_, _, oid_cs, oid_ce), (vtag, _, v_cs, v_ce) = der_children(name_der, a_cs, a_ce)[:2]
                if der_oid(name_der[oid_cs:oid_ce]) == oid:
                    return der_string(vtag, name_der[v_cs:v_ce])
    except (PEFormatError, ValueError):
        pass
    return ""


@dataclass
class Signature:
    """One Authenticode signature: signer chain (leaf first), the OPUS program name and every certificate
    shipped in the same SignedData (a cross-signed chain can take another path than build_chain's)."""
    chain: List[Certificate]
    opus_program: str = ""
    certificates: List[Certificate] = field(default_factory=list)

    @property
    def leaf(self) -> Optional[Certificate]:
        return self.chain[0] if self.chain else None


def build_chain(leaf: Certificate, certs: List[Certificate]) -> List[Certificate]:
    by_subject: Dict[bytes, List[Certificate]] = {}
    for c in certs:
        by_subject.setdefault(c.subject, []).append(c)
    chain = [leaf]
    current = leaf
    while len(chain) < 10 and current.issuer != current.subject:
        parent = next((c for c in by_subject.get(current.issuer, []) if c not in chain), None)
        if parent is None:
            break
        chain.append(parent)
        current = parent
    return chain


def parse_opus_program(buf: bytes, attrs_cs: int, attrs_ce: int) -> str:
    """programName of SpcSpOpusInfo in the authenticated attributes (WDAC "OEM ID")."""
    for _, _, a_cs, a_ce in der_children(buf, attrs_cs, attrs_ce):
        parts = der_children(buf, a_cs, a_ce)
        if len(parts) < 2 or der_oid(buf[parts[0][2]:parts[0][3]]) != OID_SPC_SP_OPUS_INFO:
            continue
        for _, _, v_cs, v_ce in der_children(buf, parts[1][2], parts[1][3]):
            for tag, _, p_cs, p_ce in der_children(buf, v_cs, v_ce):
                if tag != 0xA0:  # programName [0] EXPLICIT SpcString
                    continue
                s_tag, s_cs, s_ce = der_read(buf, p_cs)
                return der_string(0x1E if s_tag == 0x80 else 0x16, buf[s_cs:s_ce])
    return ""


def parse_pkcs7(buf: bytes, depth: int = 0) -> List[Signature]:
    """Signatures in a PKCS#7 ContentInfo, including nested (dual) signatures."""
    if depth > MAX_NESTING:
        return []
    _, cs, ce = der_read(buf, 0)
    content_type, explicit = der_children(buf, cs, ce)[:2]
    if der_oid(buf[content_type[2]:content_type[3]]) != OID_SIGNED_DATA:
        return []
    _, sd_cs, sd_ce = der_read(buf, explicit[2])
    parts = der_children(buf, sd_cs, sd_ce)
    certs: List[Certificate] = []
    signer_infos = None
    for tag, start, p_cs, p_ce in parts[3:]:
        if tag == 0xA0:  # certificates [0] IMPLICIT
            for _, c_start, _, c_ce in der_children(buf, p_cs, p_ce)[:MAX_CERTIFICATES]:
                try:
                    certs.append(parse_certificate(buf[c_start:c_ce]))
                except (PEFormatError, ValueError, IndexError):
                    continue  # attribute certificates etc.
        elif tag == 0x31:
            signer_infos = (p_cs, p_ce)
    if signer_infos is None:
        return []
    by_issuer_serial = {(c.issuer, c.serial): c for c in certs}

    signatures: List[Signature] = []
    nested: List[Signature] = []
    for _, _, si_cs, si_ce in der_children(buf, *signer_infos)[:MAX_SIGNERS]:
        # one broken SignerInfo (or nested signature, which is NOT covered by the signature and can be
        # edited by anyone) must never erase the signatures already parsed
        try:
            fields = der_children(buf, si_cs, si_ce)
            sid_tag, _, sid_cs, sid_ce = fields[1]
            leaf = None
            if sid_tag == 0x30:  # IssuerAndSerialNumber
                (_, i_start, _, i_ce), (_, _, s_cs, s_ce) = der_children(buf, sid_cs, sid_ce)[:2]
                leaf = by_issuer_serial.get((buf[i_start:i_ce], buf[s_cs:s_ce]))
            opus = ""
            unauthenticated = None
            for tag, _, f_cs, f_ce in fields[3:]:
                if tag == 0xA0:
                    opus = parse_opus_program(buf, f_cs, f_ce)
                elif tag == 0xA1:
                    unauthenticated = (f_cs, f_ce)
        except (PEFormatError, ValueError, IndexError):
            continue
        if leaf is not None:
            signatures.append(Signature(chain=build_chain(leaf, certs), opus_program=opus, certificates=certs))
        if unauthenticated is not None:
            nested += _nested_signatures(buf, unauthenticated, depth)
    return signatures + nested


def _nested_signatures(buf: bytes, attrs: Tuple[int, int], depth: int) -> List[Signature]:
    """Dual signatures stored in the unauthenticated attributes; malformed ones are skipped."""
    out: List[Signature] = []
    try:
        for _, _, a_cs, a_ce in der_children(buf, *attrs):
            a_parts = der_children(buf, a_cs, a_ce)
            if len(a_parts) < 2 or der_oid(buf[a_parts[0][2]:a_parts[0][3]]) != OID_NESTED_SIGNATURE:
                continue
            for _, n_start, _, n_ce in der_children(buf, a_parts[1][2], a_parts[1][3]):
                try:
                    out += parse_pkcs7(buf[n_start:n_ce], depth + 1)
                except (PEFormatError, ValueError, IndexError):
                    continue
    except (PEFormatError, ValueError, IndexError):
        pass
    return out

# endregion


# region PE

@dataclass
class PELayout:
    checksum_offset: int
    cert_dir_offset: int
    cert_offset: int
    cert_size: int


def pe_layout(data: bytes) -> PELayout:
    if len(data) < 64 or data[:2] != b"MZ":
        raise PEFormatError("not a PE file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if pe + 24 > len(data) or data[pe:pe + 4] != b"PE\0\0":
        raise PEFormatError("bad PE signature")
    opt = pe + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        dirs = opt + 96
    elif magic == 0x20B:
        dirs = opt + 112
    else:
        raise PEFormatError("unknown optional header")
    cert_dir = dirs + CERT_TABLE_INDEX * 8
    if cert_dir + 8 > len(data):
        raise PEFormatError("truncated optional header")
    cert_offset, cert_size = struct.unpack_from("<II", data, cert_dir)
    if cert_offset == 0 or cert_size == 0 or cert_offset + cert_size > len(data):
        cert_offset, cert_size = len(data), 0
    return PELayout(opt + 64, cert_dir, cert_offset, cert_size)


def authenticode_hashes(data: bytes, layout: Optional[PELayout] = None) -> Dict[str, str]:
    """Authenticode flat hashes: whole file minus checksum, certificate directory entry and table."""
    lay = layout or pe_layout(data)
    ranges = [(0, lay.checksum_offset), (lay.checksum_offset + 4, lay.cert_dir_offset),
              (lay.cert_dir_offset + 8, lay.cert_offset), (lay.cert_offset + lay.cert_size, len(data))]
    out = {}
    for algo in ("sha1", "sha256"):
        h = hashlib.new(algo)
        for a, b in ranges:
            h.update(data[a:b])
        out[algo] = h.hexdigest().upper()
    return out


def embedded_signatures(data: bytes, layout: Optional[PELayout] = None) -> List[Signature]:
    """Parse every WIN_CERTIFICATE (PKCS#7) entry of the certificate table."""
    lay = layout or pe_layout(data)
    signatures: List[Signature] = []
    off, end = lay.cert_offset, lay.cert_offset + min(lay.cert_size, MAX_SIGNATURE_SIZE)
    while off + 8 <= end:
        length, _, cert_type = struct.unpack_from("<IHH", data, off)
        if length < 8 or off + length > end:
            break
        if cert_type == 0x0002:  # WIN_CERT_TYPE_PKCS_SIGNED_DATA
            try:
                signatures.extend(parse_pkcs7(data[off + 8:off + length]))
            except (PEFormatError, ValueError, IndexError):
                pass  # unparsable signature: hash and version rules still apply
        off += (length + 7) & ~7
    return signatures

# endregion


# region Version resource

VERSION_STRINGS = ("OriginalFilename", "InternalName", "ProductName", "FileDescription")


def version_info(path: str) -> Tuple[Optional[Tuple[int, int, int, int]], Dict[str, str]]:
    """(file version as 4-tuple or None, {OriginalFilename, InternalName, ProductName, FileDescription})."""
    strings: Dict[str, str] = {}
    try:
        ver = system_dll("version")
    except (AttributeError, OSError):
        return None, strings
    size = ver.GetFileVersionInfoSizeW(path, None)
    if not size:
        return None, strings
    buf = ctypes.create_string_buffer(size)
    if not ver.GetFileVersionInfoW(path, 0, size, buf):
        return None, strings

    ptr = ctypes.c_void_p()
    length = ctypes.c_uint()
    version = None
    if ver.VerQueryValueW(buf, "\\", ctypes.byref(ptr), ctypes.byref(length)) and length.value >= 52:
        ms, ls = struct.unpack_from("<II", ctypes.string_at(ptr.value, 52), 8)
        version = (ms >> 16, ms & 0xFFFF, ls >> 16, ls & 0xFFFF)

    translations = []
    if ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(length)):
        raw = ctypes.string_at(ptr.value, length.value)
        translations = [struct.unpack_from("<HH", raw, i) for i in range(0, len(raw) - 3, 4)]
    translations += [(0x0409, 0x04B0), (0x0409, 0x04E4), (0x0000, 0x04B0)]
    for name in VERSION_STRINGS:
        for lang, cp in translations:
            key = f"\\StringFileInfo\\{lang:04x}{cp:04x}\\{name}"
            if ver.VerQueryValueW(buf, key, ctypes.byref(ptr), ctypes.byref(length)) and length.value:
                value = ctypes.wstring_at(ptr.value, length.value).rstrip("\0").strip()
                if value:
                    strings[name] = value
                    break
    return version, strings

# endregion


@dataclass
class PEInfo:
    path: str
    hashes: Dict[str, str] = field(default_factory=dict)
    signatures: List[Signature] = field(default_factory=list)
    version: Optional[Tuple[int, int, int, int]] = None
    strings: Dict[str, str] = field(default_factory=dict)
    error: str = ""

    @property
    def signer(self) -> str:
        leaf = self.signatures[0].leaf if self.signatures else None
        return leaf.common_name if leaf else ""


def inspect_file(path: str, max_size: int = 256 * 1024 * 1024) -> PEInfo:
    info = PEInfo(path=path)
    try:
        with open(path, "rb") as f:
            data = f.read(max_size + 1)
        if len(data) > max_size:
            info.error = "file too large"
            return info
        layout = pe_layout(data)
        info.hashes = authenticode_hashes(data, layout)
        info.signatures = embedded_signatures(data, layout)
    except (OSError, PEFormatError, struct.error) as e:
        info.error = str(e)
        return info
    info.version, info.strings = version_info(path)
    return info
