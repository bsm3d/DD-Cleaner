// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements driver package handling: pnputil output parsing, candidate ordering and the removal of driver packages.

#include <ddcore/drivers.hpp>

#include <algorithm>
#include <regex>
#include <stdexcept>

#include <windows.h>

#include <ddcore/dead_registry.hpp>
#include <ddcore/registry.hpp>

namespace dd {

namespace {

const std::set<std::wstring>& critical_classes() {
    static const std::set<std::wstring> s = {
        L"{4d36e97d-e325-11ce-bfc1-08002be10318}",   // System devices
        L"{50127dc3-0f36-415e-a6cc-4cb3be910b65}",   // Processors
        L"{4d36e96a-e325-11ce-bfc1-08002be10318}",   // Hard disk controllers
        L"{4d36e97b-e325-11ce-bfc1-08002be10318}",   // SCSI and RAID controllers
        L"{4d36e967-e325-11ce-bfc1-08002be10318}",   // Disk drives
        L"{71a27cdd-812a-4273-a0b6-d3c24b0a2d36}",   // Volumes
        L"{f2e7dd72-6468-4e36-b6f1-6488f42c1b52}",   // Firmware
        L"{d94ee5d8-d189-4994-83d2-f68d7d41b0e6}",   // Security devices
        L"{4d36e966-e325-11ce-bfc1-08002be10318}",   // Computer
        L"{72631e54-78a4-11d0-bcf7-00aa00b7b32a}",   // Batteries
        // these attach to another device's driver, so no device lists them as its own: they would look unused when they are not
        L"{e2f84ce7-8efa-411c-aa69-97454ca4cb57}",   // Extensions
        L"{62f9c741-b25a-46ce-b54c-9bccce08b6f2}",   // Software devices
        L"{5c4c3332-344d-483c-8739-259e934c9cc8}"};  // Software components
    return s;
}

const wchar_t* BINDINGS_PS = LR"J(
$present = @{}
Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | ForEach-Object { $present[([string]$_.InstanceId).ToUpper()] = $true }
$rows = Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.InfName -like 'oem*.inf' } | ForEach-Object {
    [pscustomobject]@{ Name = [string]$_.DeviceName; Inf = [string]$_.InfName; Id = [string]$_.DeviceID;
                       Class = [string]$_.DeviceClass; Present = [bool]$present[([string]$_.DeviceID).ToUpper()] }
}
ConvertTo-Json -InputObject @($rows) -Compress
)J";

const wchar_t* SERVICES_KEY = L"SYSTEM\\CurrentControlSet\\Services";

std::wstring store_path() { return join(join(system32(), L"DriverStore"), L"FileRepository"); }

std::wstring join_names(const std::vector<std::wstring>& names, std::size_t limit) {
    std::wstring out;
    for (std::size_t i = 0; i < names.size() && i < limit; ++i) out += (i ? L", " : L"") + names[i];
    return out;
}

std::vector<std::wstring> unique_sorted(std::vector<std::wstring> v) {
    std::sort(v.begin(), v.end());
    v.erase(std::unique(v.begin(), v.end()), v.end());
    return v;
}

bool version_less(const std::vector<long>& a, const std::vector<long>& b) { return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end()); }

void sort_candidates(std::vector<Candidate>& list) {
    std::stable_sort(list.begin(), list.end(), [](const Candidate& a, const Candidate& b) {
        std::wstring ca = lower(a.package.class_name), cb = lower(b.package.class_name);
        if (ca != cb) return ca < cb;
        std::wstring oa = lower(a.package.original), ob = lower(b.package.original);
        if (oa != ob) return oa < ob;
        return version_less(a.package.version_key(), b.package.version_key());
    });
}

std::wstring backup_name(const Package& pkg) {
    std::wstring name = pkg.published.substr(0, pkg.published.size() - 4);
    std::wstring clean;
    for (wchar_t c : pkg.original) clean.push_back((c < 128 && iswalnum(c)) || c == L'.' || c == L'_' || c == L'-' ? c : L'_');
    return name + L"_" + clean;
}

}  // namespace

std::vector<long> Package::version_key() const {
    std::vector<long> key;
    std::wstring digits;
    for (wchar_t c : version + L" ") {
        if (c >= L'0' && c <= L'9') {
            digits.push_back(c);
        } else if (!digits.empty()) {
            key.push_back(wcstol(digits.c_str(), nullptr, 10));
            digits.clear();
        }
    }
    return key;
}

const wchar_t* category_name(DriverCategory c) {
    switch (c) {
        case DriverCategory::Old: return L"Older version";
        case DriverCategory::Gone: return L"Device not connected";
        case DriverCategory::None: return L"No device";
        case DriverCategory::Used: return L"In use";
        case DriverCategory::Protected: return L"Protected";
    }
    return L"";
}

const wchar_t* category_risk(DriverCategory c) {
    switch (c) {
        case DriverCategory::Old: return L"Safe";
        case DriverCategory::Gone:
        case DriverCategory::None: return L"Check";
        case DriverCategory::Used: return L"Danger";
        case DriverCategory::Protected: return L"Locked";
    }
    return L"";
}

bool is_published_name(const std::wstring& name) {
    static const std::wregex pattern(LR"(oem\d+\.inf)", std::regex::icase);
    return std::regex_match(name, pattern);
}

bool is_critical_class(const std::wstring& guid) { return critical_classes().count(lower(guid)) > 0; }

int run_pnputil(const std::vector<std::wstring>& args, std::wstring& output) {
    std::vector<std::wstring> argv = {sys_exe(L"pnputil.exe")};
    argv.insert(argv.end(), args.begin(), args.end());
    ProcOptions o;
    o.timeout_ms = 120000;
    ProcResult r = run_process(argv, o);
    output = r.output;
    if (!r.started) throw std::runtime_error("pnputil could not be started");
    if (r.timed_out) throw std::runtime_error("pnputil did not answer in time");
    return r.code;
}

// region Reading

std::vector<Package> parse_enum_drivers(const std::wstring& text) {
    std::vector<Package> packages;
    // blocks are separated by blank lines
    std::vector<std::wstring> blocks;
    std::wstring current;
    for (const auto& raw : split(text, L'\n')) {
        std::wstring line = raw;
        if (!line.empty() && line.back() == L'\r') line.pop_back();
        if (trim(line).empty()) {
            if (!current.empty()) blocks.push_back(current);
            current.clear();
        } else {
            current += line + L"\n";
        }
    }
    if (!current.empty()) blocks.push_back(current);
    for (const auto& block : blocks) {
        std::vector<std::wstring> values;
        for (const auto& line : split(block, L'\n')) {
            std::size_t colon = line.find(L':');
            if (colon != std::wstring::npos) values.push_back(trim(line.substr(colon + 1)));
        }
        if (values.size() < 6 || !is_published_name(values[0])) continue;
        std::size_t space = values[5].find(L' ');
        std::wstring date = space == std::wstring::npos ? values[5] : values[5].substr(0, space);
        std::wstring version = space == std::wstring::npos ? L"" : trim(values[5].substr(space + 1));
        packages.push_back({lower(values[0]), values[1], values[2], values[3], lower(values[4]), version, date,
                            values.size() > 6 ? values[6] : L""});
    }
    return packages;
}

std::vector<Package> list_packages(const Pnputil& run) {
    std::wstring out;
    if (run({L"/enum-drivers"}, out) != 0) throw std::runtime_error("The driver store could not be listed");
    return parse_enum_drivers(out);
}

std::vector<Binding> parse_bindings(const Json& data) {
    std::vector<Binding> bindings;
    for (const Json& d : data.as_list()) {
        if (!d.is_object()) continue;
        bindings.push_back({d.get(L"Name").str(), lower(d.get(L"Inf").str()), d.get(L"Present").flag(), d.get(L"Class").str(),
                            d.get(L"Id").str()});
    }
    return bindings;
}

std::vector<Binding> read_bindings() { return parse_bindings(run_powershell_json(BINDINGS_PS, 120000)); }

// endregion

static Candidate unused_candidate(const Package& pkg, const std::vector<Package>& packages, const std::vector<Binding>& bindings) {
    std::vector<std::wstring> names, ids;
    for (const Binding& b : bindings) {
        if (!b.present && b.inf == pkg.published) {
            names.push_back(b.name);
            if (!b.instance_id.empty()) ids.push_back(b.instance_id);
        }
    }
    names = unique_sorted(names);
    const Package* best = nullptr;
    for (const Package& o : packages) {
        if (&o == &pkg || lower(o.original) != lower(pkg.original) || o.provider != pkg.provider) continue;
        if (!version_less(pkg.version_key(), o.version_key())) continue;
        if (!best || version_less(best->version_key(), o.version_key())) best = &o;
    }
    if (best) {
        return {pkg, DriverCategory::Old, L"A newer version (" + best->version + L", " + best->published + L") is installed", names, ids};
    }
    if (!names.empty()) {
        return {pkg, DriverCategory::Gone,
                L"Only used by devices that are not connected: " + join_names(names, 3) + (names.size() > 3 ? L"..." : L""), names, ids};
    }
    return {pkg, DriverCategory::None, L"No device uses this package", {}, {}};
}

static void require_present(const std::vector<Binding>& bindings) {
    for (const Binding& b : bindings) {
        if (b.present) return;
    }
    throw std::runtime_error("The connected devices could not be read: nothing can be judged safely");
}

std::vector<Candidate> find_unused(const std::vector<Package>& packages, const std::vector<Binding>& bindings) {
    require_present(bindings);
    std::set<std::wstring> in_use;
    for (const Binding& b : bindings) {
        if (b.present) in_use.insert(b.inf);
    }
    std::vector<Candidate> candidates;
    for (const Package& pkg : packages) {
        if (in_use.count(pkg.published) || is_critical_class(pkg.class_guid)) continue;
        candidates.push_back(unused_candidate(pkg, packages, bindings));
    }
    sort_candidates(candidates);
    return candidates;
}

std::vector<Candidate> list_all(const std::vector<Package>& packages, const std::vector<Binding>& bindings) {
    require_present(bindings);
    std::vector<Candidate> result;
    for (const Package& pkg : packages) {
        std::vector<std::wstring> present;
        for (const Binding& b : bindings) {
            if (b.present && b.inf == pkg.published) present.push_back(b.name);
        }
        present = unique_sorted(present);
        if (is_critical_class(pkg.class_guid)) {
            result.push_back({pkg, DriverCategory::Protected, L"Core driver: never removed from here", present, {}});
        } else if (!present.empty()) {
            std::vector<std::wstring> ghosts;
            for (const Binding& b : bindings) {
                if (!b.present && b.inf == pkg.published && !b.instance_id.empty()) ghosts.push_back(b.instance_id);
            }
            result.push_back({pkg, DriverCategory::Used, L"In use by: " + join_names(present, 3) + (present.size() > 3 ? L"..." : L""),
                              present, ghosts});
        } else {
            result.push_back(unused_candidate(pkg, packages, bindings));
        }
    }
    sort_candidates(result);
    return result;
}

std::vector<Candidate> scan_unused() { return find_unused(list_packages(), read_bindings()); }
std::vector<Candidate> scan_all() { return list_all(list_packages(), read_bindings()); }

std::wstring store_folder(const std::wstring& original, const std::wstring& store_in) {
    std::wstring store = store_in.empty() ? store_path() : store_in;
    std::wstring prefix = lower(original) + L"_";
    std::vector<Entry> entries;
    if (!list_dir(store, entries)) return L"";
    const Entry* best = nullptr;
    for (const Entry& e : entries) {
        if (starts_with(lower(e.name), prefix) && (!best || e.modified > best->modified)) best = &e;
    }
    return best ? best->path : L"";
}

static bool folder_has_files(const std::wstring& folder) {
    std::vector<Entry> entries;
    return list_dir(folder, entries) && !entries.empty();
}

DriverRemoval remove_packages(const std::vector<Candidate>& candidates, const std::wstring& folder_in, const Pnputil& run,
                              const Stop& stop) {
    DriverRemoval result;
    std::wstring folder = folder_in.empty() ? data_subdir(L"driver_backups") : folder_in;
    std::wstring stamp = timestamp();
    for (const Candidate& candidate : candidates) {
        const Package& pkg = candidate.package;
        if (stop()) {
            result.failed.emplace_back(candidate, L"Stopped");
            continue;
        }
        if (!is_published_name(pkg.published) || is_critical_class(pkg.class_guid)) {
            result.failed.emplace_back(candidate, L"This package cannot be removed from here");
            continue;
        }
        std::wstring target = join(folder, stamp + L"_" + backup_name(pkg));
        int code;
        std::wstring out;
        try {
            make_dirs(target);
            code = run({L"/export-driver", pkg.published, target}, out);
            if (code != 0 || !folder_has_files(target)) {
                result.failed.emplace_back(candidate, L"The backup of the driver files failed: nothing removed");
                continue;
            }
            result.backups.push_back(target);
            code = run({L"/delete-driver", pkg.published}, out);
        } catch (const std::exception& e) {
            result.failed.emplace_back(candidate, wide(e.what()));
            continue;
        }
        if (code == 0 || code == 3010) {
            result.removed.push_back(candidate);
        } else {
            bool in_use = code == 1 || code == 5 || code == 259 || lower(out).find(L"in use") != std::wstring::npos;
            result.failed.emplace_back(candidate, in_use ? L"Windows refused: the driver is in use"
                                                         : L"pnputil failed (code " + std::to_wstring(code) + L"): run as administrator");
        }
    }
    return result;
}

// region Complete uninstall

std::wstring inf_path(const std::wstring& published) { return join(join(system_root(), L"INF"), published); }

std::wstring read_inf(const std::wstring& path) {
    std::string raw;
    if (!read_file(path, raw, 2 * 1024 * 1024)) return L"";
    if (raw.size() >= 2 && ((unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE)) {
        return std::wstring(reinterpret_cast<const wchar_t*>(raw.data() + 2), (raw.size() - 2) / 2);
    }
    if (raw.size() >= 2 && ((unsigned char)raw[0] == 0xFE && (unsigned char)raw[1] == 0xFF)) {
        std::wstring out((raw.size() - 2) / 2, L'\0');
        for (std::size_t i = 0; i < out.size(); ++i) out[i] = (wchar_t)(((unsigned char)raw[2 + 2 * i] << 8) | (unsigned char)raw[3 + 2 * i]);
        return out;
    }
    std::size_t skip = (raw.size() >= 3 && (unsigned char)raw[0] == 0xEF && (unsigned char)raw[1] == 0xBB && (unsigned char)raw[2] == 0xBF) ? 3 : 0;
    UINT page = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, raw.data() + skip, (int)(raw.size() - skip), nullptr, 0) > 0 ? CP_UTF8 : 1252;
    int n = MultiByteToWideChar(page, 0, raw.data() + skip, (int)(raw.size() - skip), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(page, 0, raw.data() + skip, (int)(raw.size() - skip), out.data(), n);
    return out;
}

std::vector<std::wstring> inf_services(const std::wstring& path) {
    static const std::wregex add(LR"(^\s*AddService\s*=\s*"?([A-Za-z0-9_.@\-]+))", std::regex::icase);
    std::vector<std::wstring> names;
    for (const auto& raw : split(read_inf(path), L'\n')) {
        std::wstring line = raw.substr(0, raw.find(L';'));   // what follows a ';' is a comment
        std::wsmatch m;
        if (std::regex_search(line, m, add)) {
            std::wstring name = m[1];
            if (std::find(names.begin(), names.end(), name) == names.end()) names.push_back(name);
        }
    }
    return names;
}

std::set<std::wstring> inbox_services(const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? join(system_root(), L"INF") : folder_in;
    std::set<std::wstring> names;
    std::vector<Entry> files;
    if (!list_dir(folder, files)) return names;
    for (const Entry& f : files) {
        if (!ends_with(lower(f.name), L".inf") || is_published_name(f.name)) continue;
        for (const auto& s : inf_services(f.path)) names.insert(lower(s));
    }
    return names;
}

std::wstring resolve_driver_file(const std::wstring& image_in) {
    std::wstring image = expand_env(strip_quotes(trim(image_in)));
    std::wstring low = lower(image);
    if (starts_with(low, L"\\systemroot\\")) return join(system_root(), image.substr(12));
    if (starts_with(low, L"\\??\\")) return image.substr(4);
    if (is_absolute(image)) return image;
    return image.empty() ? L"" : join(system_root(), image);
}

std::wstring leftover_problem(const std::wstring& name, bool exists, long long type, long long start, const std::wstring& image_path) {
    static const std::wregex valid(LR"([A-Za-z0-9_.@\-]{1,256})");
    if (!std::regex_match(name, valid)) return L"Unusual service name";
    if (!exists) return L"No such service";
    if (type != 1 && type != 2) return L"Not a driver service";
    if (start == 0) return L"A boot-start driver: never touched";
    std::wstring path = resolve_driver_file(image_path);
    if (path.empty() || !starts_with(normcase(path), normcase(join(system32(), L"drivers")) + L"\\")) {
        return L"Its file is not in System32\\drivers";
    }
    return L"";
}

namespace {

struct ServiceValues {
    bool exists = false;
    long long type = -1, start = -1;
    std::wstring image;
};

ServiceValues read_service(const std::wstring& name) {
    ServiceValues s;
    RegKey key = RegKey::open(L"HKLM", std::wstring(SERVICES_KEY) + L"\\" + name);
    if (!key.valid()) return s;
    s.exists = true;
    for (const RegValue& v : key.values()) {
        if (v.name == L"Type" && v.type == REG_DWORD) s.type = v.dword;
        else if (v.name == L"Start" && v.type == REG_DWORD) s.start = v.dword;
        else if (v.name == L"ImagePath" && v.is_text()) s.image = v.text;
    }
    return s;
}

}  // namespace

std::vector<DriverLeftover> find_driver_leftovers(const std::vector<std::pair<std::wstring, std::wstring>>& services,
                                                  const std::set<std::wstring>& still_declared) {
    std::vector<DriverLeftover> found;
    for (const auto& [name, package] : services) {
        if (still_declared.count(lower(name))) continue;
        ServiceValues v = read_service(name);
        if (!leftover_problem(name, v.exists, v.type, v.start, v.image).empty()) continue;
        std::wstring path = resolve_driver_file(v.image);
        found.push_back({name, path, is_file(path), package});
    }
    return found;
}

UninstallResult uninstall_completely(const std::vector<Candidate>& candidates, const std::vector<Package>& remaining,
                                     const std::wstring& folder_in, const Pnputil& run, const std::set<std::wstring>* inbox,
                                     const Stop& stop) {
    UninstallResult result;
    std::wstring folder = folder_in.empty() ? data_subdir(L"driver_backups") : folder_in;
    std::wstring stamp = timestamp();
    std::vector<std::pair<std::wstring, std::wstring>> services;
    for (const Candidate& candidate : candidates) {
        const Package& pkg = candidate.package;
        if (stop()) {
            result.failed.emplace_back(candidate, L"Stopped");
            continue;
        }
        if (!is_published_name(pkg.published) || !candidate.removable() || is_critical_class(pkg.class_guid)) {
            result.failed.emplace_back(candidate, L"This package cannot be removed from here");
            continue;
        }
        std::vector<std::wstring> declared = inf_services(inf_path(pkg.published));
        std::wstring target = join(folder, stamp + L"_" + backup_name(pkg));
        int code;
        std::wstring out;
        try {
            make_dirs(target);
            code = run({L"/export-driver", pkg.published, target}, out);
            if (code != 0 || !folder_has_files(target)) {
                result.failed.emplace_back(candidate, L"The backup of the driver files failed: nothing removed");
                continue;
            }
            result.backups.push_back(target);
            std::vector<std::wstring> args = {L"/delete-driver", pkg.published};
            if (candidate.in_use()) args.insert(args.end(), {L"/uninstall", L"/force"});
            code = run(args, out);
        } catch (const std::exception& e) {
            result.failed.emplace_back(candidate, wide(e.what()));
            continue;
        }
        if (code != 0 && code != 3010) {
            result.failed.emplace_back(candidate, lower(out).find(L"in use") != std::wstring::npos
                                                      ? L"Windows refused: the driver is in use"
                                                      : L"pnputil failed (code " + std::to_wstring(code) + L"): run as administrator");
            continue;
        }
        result.reboot = result.reboot || code == 3010 || candidate.in_use();
        result.removed.push_back(candidate);
        for (const auto& id : candidate.ghost_ids) {
            try {
                std::wstring ignored;
                int rc = run({L"/remove-device", id}, ignored);
                if (rc == 0 || rc == 3010) ++result.ghosts_removed;
            } catch (const std::exception&) {
            }
        }
        for (const auto& s : declared) services.emplace_back(s, pkg.published);
    }
    std::set<std::wstring> gone;
    for (const auto& c : result.removed) gone.insert(c.package.published);
    std::set<std::wstring> still_declared = inbox ? *inbox : inbox_services();
    for (const Package& other : remaining) {
        if (gone.count(other.published)) continue;
        for (const auto& s : inf_services(inf_path(other.published))) still_declared.insert(lower(s));
    }
    result.leftovers = find_driver_leftovers(services, still_declared);
    return result;
}

LeftoverRemoval remove_driver_leftovers(const std::vector<DriverLeftover>& leftovers, const std::wstring& folder_in, const Stop& stop) {
    LeftoverRemoval result;
    std::wstring folder = folder_in.empty() ? data_subdir(L"driver_backups") : folder_in;
    std::wstring stamp = timestamp();
    for (const DriverLeftover& leftover : leftovers) {
        if (stop()) {
            result.failed.emplace_back(leftover, L"Stopped");
            continue;
        }
        ServiceValues v = read_service(leftover.service);
        std::wstring problem = leftover_problem(leftover.service, v.exists, v.type, v.start, v.image);
        if (!problem.empty()) {
            result.failed.emplace_back(leftover, problem);
            continue;
        }
        std::wstring path = resolve_driver_file(v.image);
        std::wstring target = join(folder, stamp + L"_service_" + safe_name(leftover.service, 1000));
        make_dirs(target);
        problem = export_key(L"HKLM", std::wstring(SERVICES_KEY) + L"\\" + leftover.service, join(target, L"service.reg"));
        if (!problem.empty()) {
            result.failed.emplace_back(leftover, L"Backup failed, nothing removed: " + problem);
            continue;
        }
        if (is_file(path)) CopyFileW(path.c_str(), join(target, base_name(path)).c_str(), FALSE);
        result.backups.push_back(target);
        LONG rc = RegKey::delete_tree(L"HKLM", std::wstring(SERVICES_KEY) + L"\\" + leftover.service);
        if (rc == ERROR_ACCESS_DENIED) {
            result.failed.emplace_back(leftover, L"Access denied: run as administrator");
            continue;
        }
        if (rc != ERROR_SUCCESS) {
            result.failed.emplace_back(leftover, L"Windows error " + std::to_wstring(rc));
            continue;
        }
        if (is_file(path) && !delete_file(path)) {
            result.failed.emplace_back(leftover, L"The service entry is removed; the file is still loaded: delete it after a restart");
            continue;
        }
        result.removed.push_back(leftover);
    }
    return result;
}

// endregion

}  // namespace dd
