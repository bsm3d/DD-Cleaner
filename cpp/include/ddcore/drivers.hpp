// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares driver package listing, unused driver detection and the complete uninstall of a driver through pnputil.

// Pilotes inutilisés et désinstallation complète (paquet, entrées des appareils débranchés, service et .sys restants).
// Un paquet tiers (oemNN.inf) n'est proposé que si aucun appareil CONNECTÉ ne s'en sert ; sa sauvegarde est faite avant (pnputil /export-driver).
// Suppression SANS /force : Windows refuse lui-même un paquet encore utilisé. Les classes de base ne sont jamais proposées.
#pragma once

#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/proc.hpp>

namespace dd {

struct Package {
    std::wstring published;   // oem12.inf
    std::wstring original;    // wdnetworkstorage.inf
    std::wstring provider, class_name, class_guid, version, date, signer;
    std::vector<long> version_key() const;
};

struct Binding {
    std::wstring name, inf;   // inf in lower case
    bool present = false;
    std::wstring device_class, instance_id;
};

enum class DriverCategory { Old, Gone, None, Used, Protected };
const wchar_t* category_name(DriverCategory c);   // "Older version", "Device not connected", "No device", "In use", "Protected"
const wchar_t* category_risk(DriverCategory c);   // Safe | Check | Danger | Locked

struct Candidate {
    Package package;
    DriverCategory category = DriverCategory::None;
    std::wstring reason;
    std::vector<std::wstring> devices;      // the devices named in the reason (connected or not)
    std::vector<std::wstring> ghost_ids;    // instance ids of the NOT connected devices that use it
    bool in_use() const { return category == DriverCategory::Used; }
    bool removable() const { return category != DriverCategory::Protected; }
};

struct DriverRemoval {
    std::vector<Candidate> removed;
    std::vector<std::pair<Candidate, std::wstring>> failed;
    std::vector<std::wstring> backups;
};

// pnputil, replaceable in tests: returns the exit code and fills the output.
using Pnputil = std::function<int(const std::vector<std::wstring>& args, std::wstring& output)>;
int run_pnputil(const std::vector<std::wstring>& args, std::wstring& output);

bool is_published_name(const std::wstring& name);   // oem + digits + .inf
bool is_critical_class(const std::wstring& class_guid);

std::vector<Package> parse_enum_drivers(const std::wstring& text);   // read by position: Windows translates the labels
std::vector<Package> list_packages(const Pnputil& run = run_pnputil);   // throws std::runtime_error
std::vector<Binding> read_bindings();
std::vector<Binding> parse_bindings(const Json& data);

// Throws std::runtime_error when no connected device could be read: nothing can be judged safely then.
std::vector<Candidate> find_unused(const std::vector<Package>& packages, const std::vector<Binding>& bindings);
std::vector<Candidate> list_all(const std::vector<Package>& packages, const std::vector<Binding>& bindings);
std::vector<Candidate> scan_unused();
std::vector<Candidate> scan_all();

std::wstring store_folder(const std::wstring& original, const std::wstring& store = L"");   // newest folder, "" when none
DriverRemoval remove_packages(const std::vector<Candidate>& candidates, const std::wstring& folder = L"",
                              const Pnputil& run = run_pnputil, const Stop& stop = never);

// region Complete uninstall
struct DriverLeftover {
    std::wstring service, image;   // HKLM\SYSTEM\CurrentControlSet\Services\<name>, its .sys file
    bool file_exists = false;
    std::wstring package;          // the published name that declared the service
};

struct UninstallResult {
    std::vector<Candidate> removed;
    std::vector<std::pair<Candidate, std::wstring>> failed;
    std::vector<std::wstring> backups;
    std::vector<DriverLeftover> leftovers;
    int ghosts_removed = 0;
    bool reboot = false;
};

struct LeftoverRemoval {
    std::vector<DriverLeftover> removed;
    std::vector<std::pair<DriverLeftover, std::wstring>> failed;
    std::vector<std::wstring> backups;
};

std::wstring inf_path(const std::wstring& published);
std::wstring read_inf(const std::wstring& path);
std::vector<std::wstring> inf_services(const std::wstring& path);
std::set<std::wstring> inbox_services(const std::wstring& folder = L"");
std::wstring resolve_driver_file(const std::wstring& image);
// Why a service must not be offered ("" when it is a plain driver service whose file sits in System32\drivers).
std::wstring leftover_problem(const std::wstring& name, bool exists, long long type, long long start, const std::wstring& image_path);
std::vector<DriverLeftover> find_driver_leftovers(const std::vector<std::pair<std::wstring, std::wstring>>& services,
                                                  const std::set<std::wstring>& still_declared);

// Remove packages even when a connected device uses them, then list what they leave behind (never deleted here).
UninstallResult uninstall_completely(const std::vector<Candidate>& candidates, const std::vector<Package>& remaining,
                                     const std::wstring& folder = L"", const Pnputil& run = run_pnputil,
                                     const std::set<std::wstring>* inbox = nullptr, const Stop& stop = never);
// Delete the service key and the .sys file of each leftover, after saving both.
LeftoverRemoval remove_driver_leftovers(const std::vector<DriverLeftover>& leftovers, const std::wstring& folder = L"",
                                        const Stop& stop = never);
// endregion

}  // namespace dd
