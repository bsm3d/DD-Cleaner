"""Lightweight static heuristics on a file, ported from Little Devil (file_analyzer, entropy_map, security).

Two signals that signature scanning (ClamAV) does not give on its own:
  - the real type of a file from its first bytes, and whether it clashes with the extension: an executable
    or a script hiding behind a document/image/data name is a classic trick (invoice.pdf that is really a PE);
  - Shannon entropy: an executable whose bytes are close to random is probably packed or encrypted (UPX, a
    crypter), a common trait of malware that no known-signature list will match.

Pure Python, no numpy: the entropy is counted with bytes.count (256 C-level scans over a capped sample).
This reads the file, never runs it.
"""

import math
import os
from dataclasses import dataclass
from typing import Tuple

ENTROPY_SAMPLE = 1024 * 1024       # bytes read for type + entropy (enough signal, bounded cost)
PACKED_ENTROPY = 7.2               # an executable above this is very likely packed/encrypted
PRINTABLE = frozenset({9, 10, 13}) | set(range(32, 127))

# (magic, human label, kind). First match wins, so longer/more specific magics come first.
SIGNATURES = [
    (b"\x4c\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (LNK)", "shortcut"),
    (b"MZ", "Windows executable (PE)", "executable"),
    (b"\x7fELF", "ELF executable", "executable"),
    (b"#!", "script (shebang)", "script"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2 (legacy Office or MSI)", "document"),
    (b"PK\x03\x04", "ZIP / Office (OOXML) / JAR", "archive"),
    (b"Rar!", "RAR archive", "archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "archive"),
    (b"\x1f\x8b", "gzip archive", "archive"),
    (b"%PDF", "PDF document", "document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image", "image"),
    (b"\xff\xd8\xff", "JPEG image", "image"),
    (b"GIF8", "GIF image", "image"),
    (b"BM", "BMP image", "image"),
    (b"\x00\x00\x01\x00", "icon (ICO)", "image"),
    (b"II*\x00", "TIFF image", "image"),
    (b"MM\x00*", "TIFF image", "image"),
    (b"OggS", "Ogg media", "media"),
    (b"RIFF", "RIFF media (WAV / AVI)", "media"),
    (b"\x1aE\xdf\xa3", "Matroska / WebM media", "media"),
    (b"ID3", "MP3 audio", "media"),
    (b"fLaC", "FLAC audio", "media"),
]

# declared extension -> the kind its content should have
EXT_KIND = {
    "exe": "executable", "dll": "executable", "sys": "executable", "scr": "executable", "com": "executable",
    "ocx": "executable", "cpl": "executable", "drv": "executable", "efi": "executable", "mui": "executable",
    "lnk": "shortcut",
    "zip": "archive", "jar": "archive", "apk": "archive", "rar": "archive", "7z": "archive", "gz": "archive",
    "tgz": "archive", "docx": "archive", "xlsx": "archive", "pptx": "archive",
    "doc": "document", "xls": "document", "ppt": "document", "msi": "document", "pdf": "document",
    "png": "image", "jpg": "image", "jpeg": "image", "gif": "image", "bmp": "image", "ico": "image",
    "tif": "image", "tiff": "image", "webp": "image",
    "wav": "media", "avi": "media", "mp3": "media", "mp4": "media", "mkv": "media", "webm": "media",
    "flac": "media", "ogg": "media",
}
EXECUTABLE_KINDS = {"executable", "script", "shortcut"}


@dataclass
class FileInspection:
    path: str
    true_type: str = "Unknown"
    kind: str = "data"             # executable | script | shortcut | archive | document | image | media | text | data
    declared_ext: str = ""
    entropy: float = 0.0           # bits per byte, 0..8
    packed: bool = False           # high-entropy executable
    mismatch: str = ""             # message when the content clashes with the extension, else ""
    dangerous: bool = False        # executable/script content wearing a non-executable extension
    error: str = ""

    @property
    def flags(self) -> list:
        out = []
        if self.mismatch:
            out.append(self.mismatch)
        if self.packed:
            out.append(f"High entropy {self.entropy:.1f}/8 (possibly packed or encrypted)")
        return out


def classify(data: bytes) -> Tuple[str, str]:
    """(human label, kind) from the leading bytes."""
    for magic, label, kind in SIGNATURES:
        if data.startswith(magic):
            return label, kind
    sample = data[:1024]
    if sample and sum(1 for b in sample if b in PRINTABLE) >= len(sample) * 0.9:
        return "text", "text"
    return "Unknown binary", "data"


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (0 = uniform, 8 = random). Counted in C via bytes.count."""
    total = len(data)
    if not total:
        return 0.0
    entropy = 0.0
    for value in range(256):
        count = data.count(value)
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _mismatch(kind: str, true_type: str, ext: str) -> Tuple[str, bool]:
    """(message, dangerous). Dangerous = executable/script content under a non-executable extension."""
    if not ext or kind in ("data", "text"):
        return "", False
    expected = EXT_KIND.get(ext)
    if expected is None:
        if kind in EXECUTABLE_KINDS:
            return f"{true_type} with an unexpected .{ext} name", True
        return "", False
    if expected == kind:
        return "", False
    dangerous = kind in EXECUTABLE_KINDS and expected not in EXECUTABLE_KINDS
    return f"Content is {true_type}, not a .{ext} file", dangerous


def inspect(path: str, sample_size: int = ENTROPY_SAMPLE) -> FileInspection:
    result = FileInspection(path=path, declared_ext=os.path.splitext(path)[1].lstrip(".").lower())
    try:
        with open(path, "rb") as f:
            head = f.read(sample_size)
    except OSError as e:
        result.error = str(e)
        return result
    if not head:
        result.error = "empty file"
        return result
    result.true_type, result.kind = classify(head)
    result.entropy = shannon_entropy(head)
    result.packed = result.kind == "executable" and result.entropy >= PACKED_ENTROPY
    result.mismatch, result.dangerous = _mismatch(result.kind, result.true_type, result.declared_ext)
    return result
