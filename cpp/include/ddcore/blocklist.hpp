// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the Microsoft vulnerable driver blocklist: policy download and parsing, driver inventory and matching types.

// Liste noire de pilotes vulnérables Microsoft : téléchargement, lecture de la politique (DriverPolicy_Enforced.xml), inventaire et correspondance.
// Évaluée comme l'intégrité du code Windows (scénario 131) : règles Deny Hash, Deny FileName et signataires refusés.
// Une correspondance = Windows refuse de charger le pilote quand la liste est appliquée. Rien ici ne modifie le système.
#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/net.hpp>
#include <ddcore/pe.hpp>

namespace dd {

using Version4 = std::vector<unsigned>;   // four numbers, empty = none
Version4 parse_version(const std::wstring& text);

struct FileAttribute {
    std::wstring attribute;   // version resource string name, e.g. OriginalFilename
    std::wstring value;
    Version4 minimum, maximum;
    std::wstring friendly;
    bool matches(const PeDetails& info) const;
};

struct DeniedSigner {
    std::wstring name;
    std::set<std::wstring> tbs;
    std::wstring publisher, oem_id;
    std::vector<FileAttribute> file_attributes;
    bool matches(const PeDetails& info) const;
};

struct BlocklistPolicy {
    std::wstring version;
    std::map<std::wstring, std::wstring> hashes;   // authenticode hash (upper hex) -> rule friendly name
    std::vector<FileAttribute> file_rules;
    std::vector<DeniedSigner> signers;
    std::size_t rule_count() const { return hashes.size() + file_rules.size() + signers.size(); }
    std::vector<std::wstring> match(const PeDetails& info) const;   // reasons; empty = not listed
};

constexpr const wchar_t* BLOCKLIST_URL = L"https://aka.ms/VulnerableDriverBlockList";
constexpr const wchar_t* POLICY_MEMBER = L"DriverPolicy_Enforced.xml";

// Throws std::runtime_error with a readable message for anything that is not a usable policy.
BlocklistPolicy parse_policy(const std::string& xml_bytes);
std::wstring blocklist_dir();
// The cached policy and its metadata ({} when nothing was downloaded yet). False when nothing is cached.
bool load_policy(BlocklistPolicy& policy, std::map<std::wstring, std::wstring>& meta, const std::wstring& folder = L"");
std::string extract_policy(const std::string& zip_bytes);   // throws
using Fetch = std::function<HttpResponse(const std::wstring& url)>;
// Download, validate and store (atomic replace). Throws std::runtime_error.
BlocklistPolicy download_blocklist(const std::wstring& folder = L"", const Fetch& fetch = nullptr);

// region Driver inventory
struct DriverFile {
    std::wstring path, service, start;
    bool loaded = false;
    std::wstring state() const;   // Loaded | Installed (Boot) | File only
};
std::wstring normalize_driver_path(const std::wstring& path);   // kernel / ImagePath forms to a Win32 path, "" if unknown
std::vector<std::wstring> loaded_driver_paths();                  // kernel modules currently loaded
struct DriverService {
    std::wstring name, image;
    long long start;
};
std::vector<DriverService> driver_services();                     // kernel and file system driver services
std::vector<DriverFile> collect_driver_files();

struct DriverCheck {
    DriverFile driver;
    PeDetails info;
    std::vector<std::wstring> reasons;
    bool flagged() const { return !reasons.empty(); }
};
std::vector<DriverCheck> check_drivers(const BlocklistPolicy& policy, const std::vector<DriverFile>& drivers,
                                       const std::function<void(std::size_t, std::size_t, const std::wstring&)>& progress = nullptr,
                                       const Stop& stop = never);
// endregion

// region Windows protection state
struct ProtectionState {
    int blocklist_setting = -1;   // VulnerableDriverBlocklistEnable, -1 = not set
    bool hvci_enabled = false;
    int build = 0;
    bool enforced() const;        // best estimate of whether Windows currently enforces the blocklist
    std::wstring summary() const;
};
ProtectionState protection_state();
// endregion

}  // namespace dd
