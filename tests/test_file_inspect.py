"""Static file heuristics: real-type detection, extension-mismatch (masquerade), and entropy/packing.
Ported from Little Devil (file_analyzer, entropy_map, security)."""

import os

import pytest

from ddcleaner import file_inspect as fi

PE = b"MZ\x90\x00" + b"\x00" * 60
ELF = b"\x7fELF" + b"\x00" * 60
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
ZIP = b"PK\x03\x04" + b"\x00" * 32
PDF = b"%PDF-1.7\n" + b"stuff" * 20
LNK = b"\x4c\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 32
SH = b"#!/bin/sh\necho hi\n"


# region classify

@pytest.mark.parametrize("data, kind, label_part", [
    (PE, "executable", "PE"), (ELF, "executable", "ELF"), (LNK, "shortcut", "LNK"),
    (SH, "script", "shebang"), (ZIP, "archive", "ZIP"), (PDF, "document", "PDF"),
    (PNG, "image", "PNG"), (b"GIF89a....", "image", "GIF"),
    (b"Just some readable text here, mostly letters.", "text", "text"),
    (b"\x01\x02\x7f\x80\xff\xfe\x00\x03random", "data", "Unknown"),
])
def test_classify(data, kind, label_part):
    label, k = fi.classify(data)
    assert k == kind and label_part.lower() in label.lower()


def test_ole2_is_treated_as_a_document():
    assert fi.classify(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 16)[1] == "document"

# endregion


# region entropy

def test_entropy_bounds():
    assert fi.shannon_entropy(b"") == 0.0
    assert fi.shannon_entropy(b"\x00" * 4096) == 0.0            # one symbol -> 0 bits
    full = bytes(range(256)) * 16                                # every byte equally likely -> 8 bits
    assert fi.shannon_entropy(full) == 8.0
    assert 0 < fi.shannon_entropy(b"hello world " * 50) < 5     # text: low/medium


def test_random_bytes_are_high_entropy():
    assert fi.shannon_entropy(os.urandom(65536)) > 7.9

# endregion


# region inspect + mismatch

def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


def test_executable_under_a_document_name_is_dangerous(tmp_path):
    insp = fi.inspect(write(tmp_path, "invoice.pdf", PE))
    assert insp.kind == "executable" and insp.declared_ext == "pdf"
    assert insp.dangerous and "not a .pdf" in insp.mismatch
    assert insp.mismatch in insp.flags


def test_executable_with_an_unknown_extension_is_dangerous(tmp_path):
    insp = fi.inspect(write(tmp_path, "data.xyz", PE))
    assert insp.dangerous and ".xyz" in insp.mismatch


def test_matching_extension_has_no_mismatch(tmp_path):
    assert fi.inspect(write(tmp_path, "tool.exe", PE)).mismatch == ""
    assert fi.inspect(write(tmp_path, "report.pdf", PDF)).mismatch == ""
    assert fi.inspect(write(tmp_path, "photo.png", PNG)).mismatch == ""
    assert fi.inspect(write(tmp_path, "sheet.docx", ZIP)).mismatch == ""   # OOXML is a zip


def test_two_formats_of_the_same_kind_are_not_a_mismatch(tmp_path):
    assert fi.inspect(write(tmp_path, "photo.jpg", PNG)).mismatch == ""   # PNG named .jpg: both images


def test_wrong_but_harmless_type_is_flagged_without_danger(tmp_path):
    insp = fi.inspect(write(tmp_path, "photo.png", ZIP))        # an archive wearing an image name
    assert insp.mismatch and not insp.dangerous                # odd, but not an executable: not dangerous


def test_a_dll_without_extension_is_not_flagged(tmp_path):
    assert fi.inspect(write(tmp_path, "noext", PE)).mismatch == ""


def test_packed_executable_is_flagged(tmp_path):
    packed = PE[:64] + os.urandom(200000)                      # a PE whose body is random -> high entropy
    insp = fi.inspect(write(tmp_path, "packed.exe", packed))
    assert insp.kind == "executable" and insp.entropy >= fi.PACKED_ENTROPY and insp.packed
    assert any("packed" in f for f in insp.flags)


def test_a_normal_executable_is_not_called_packed(tmp_path):
    normal = PE[:64] + (b"The quick brown fox jumps over the lazy dog. " * 4000)
    insp = fi.inspect(write(tmp_path, "normal.exe", normal))
    assert not insp.packed and insp.entropy < fi.PACKED_ENTROPY


def test_high_entropy_archive_is_not_called_packed(tmp_path):
    # a zip is meant to be high entropy; only executables get the packed flag
    insp = fi.inspect(write(tmp_path, "archive.zip", ZIP[:4] + os.urandom(100000)))
    assert insp.kind == "archive" and not insp.packed


def test_missing_and_empty_files(tmp_path):
    assert fi.inspect(str(tmp_path / "nope.exe")).error
    assert fi.inspect(write(tmp_path, "empty.exe", b"")).error == "empty file"

# endregion
