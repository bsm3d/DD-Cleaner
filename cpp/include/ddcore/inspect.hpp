// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares file inspection without running it: real type, entropy, embedded signature, hash and who may write in a folder.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace dd {

// region Real type and entropy
struct FileInspection {
    std::wstring path;
    std::wstring true_type = L"Unknown";
    std::wstring kind = L"data";    // executable | script | shortcut | archive | document | image | media | text | data
    std::wstring declared_ext;
    double entropy = 0;             // bits per byte, 0..8
    bool packed = false;            // high-entropy executable
    std::wstring mismatch;          // message when the content clashes with the extension
    bool dangerous = false;         // executable or script content under a non-executable extension
    std::wstring error;
};

constexpr std::size_t ENTROPY_SAMPLE = 1024 * 1024;
constexpr double PACKED_ENTROPY = 7.2;

void classify(const std::string& data, std::wstring& label, std::wstring& kind);
double shannon_entropy(const std::string& data);
FileInspection inspect(const std::wstring& path, std::size_t sample_size = ENTROPY_SAMPLE);
// endregion

// region Signature, version, hash
struct PEInfo {
    std::wstring path;
    std::wstring signer;    // common name of the embedded signature's certificate, "" when not signed (catalogs not read)
    std::wstring error;
    std::wstring file_version;                         // "1.2.3.4"
    std::map<std::wstring, std::wstring> strings;      // OriginalFilename, InternalName, ProductName, FileDescription
};
PEInfo inspect_pe(const std::wstring& path);
std::wstring sha256_file(const std::wstring& path);    // upper-case hex, "" when unreadable
std::wstring sha256_bytes(const std::string& bytes);
// endregion

// region Folder security
// Who, without administrator rights, can add or replace files in this folder (empty = protected). `ok` is false when the
// permissions cannot be read.
std::vector<std::wstring> unprivileged_writers(const std::wstring& path, bool* ok = nullptr);
std::vector<std::wstring> folder_risk(const std::wstring& folder);
std::wstring current_user_sid();
// endregion

}  // namespace dd
