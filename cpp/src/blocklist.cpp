// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the vulnerable driver blocklist: device path mapping, policy parsing and the matching of installed drivers.

#include <ddcore/blocklist.hpp>

#include <algorithm>
#include <stdexcept>

#include <windows.h>
#include <psapi.h>

#include <ddcore/json.hpp>
#include <ddcore/registry.hpp>

namespace dd {

namespace {

const std::size_t MAX_DOWNLOAD = 20 * 1024 * 1024;

const std::map<std::wstring, std::wstring>& attribute_strings() {
    // FileAttrib / Deny attribute -> version resource string it is compared with
    static const std::map<std::wstring, std::wstring> m = {{L"FileName", L"OriginalFilename"},
                                                           {L"InternalName", L"InternalName"},
                                                           {L"ProductName", L"ProductName"},
                                                           {L"FileDescription", L"FileDescription"}};
    return m;
}

bool attribute_from(const XmlNode& el, FileAttribute& out) {
    for (const wchar_t* key : {L"FileName", L"InternalName", L"ProductName", L"FileDescription"}) {
        std::wstring value = el.attr(key);
        if (value.empty()) continue;
        out = {attribute_strings().at(key), value, parse_version(el.attr(L"MinimumFileVersion")), parse_version(el.attr(L"MaximumFileVersion")),
               el.attr(L"FriendlyName")};
        return true;
    }
    return false;
}

std::wstring casefold(const std::wstring& s) { return lower(s); }

}  // namespace

Version4 parse_version(const std::wstring& text) {
    if (text.empty()) return {};
    Version4 parts;
    for (const auto& p : split(text, L'.')) {
        wchar_t* end = nullptr;
        unsigned long v = wcstoul(p.c_str(), &end, 10);
        if (p.empty() || !end || *end != 0) return {};
        parts.push_back((unsigned)v);
    }
    while (parts.size() < 4) parts.push_back(0);
    parts.resize(4);
    return parts;
}

bool FileAttribute::matches(const PeDetails& info) const {
    auto it = info.strings.find(attribute);
    if (it == info.strings.end() || it->second.empty() || casefold(it->second) != casefold(value)) return false;
    if (minimum.empty() && maximum.empty()) return true;
    if (info.version.empty()) return false;
    // Deny-rule semantics (Microsoft App Control docs, "file rule levels"): both bounds -> inside the range; MinimumFileVersion
    // alone -> that version AND OLDER; MaximumFileVersion alone -> that version and newer. Not the allow-rule meaning: reading
    // Minimum as a lower bound would miss old vulnerable builds and flag the fixed ones.
    if (!minimum.empty() && !maximum.empty()) return minimum <= info.version && info.version <= maximum;
    if (!minimum.empty()) return info.version <= minimum;
    return info.version >= maximum;
}

bool DeniedSigner::matches(const PeDetails& info) const {
    for (const Signature& sig : info.signatures) {
        bool tbs_found = false;
        auto check = [&](const std::vector<Certificate>& certs) {
            for (const auto& c : certs) {
                for (const auto& h : c.tbs_hashes()) tbs_found |= tbs.count(h) > 0;
            }
        };
        check(sig.chain);
        check(sig.certificates);
        if (!tbs_found) continue;
        const Certificate* leaf = sig.leaf();
        if (!publisher.empty() && (!leaf || leaf->common_name() != publisher)) continue;
        if (!oem_id.empty() && casefold(sig.opus_program) != casefold(oem_id)) continue;
        if (!file_attributes.empty()) {
            bool any = false;
            for (const auto& a : file_attributes) any |= a.matches(info);
            if (!any) continue;
        }
        return true;
    }
    return false;
}

std::vector<std::wstring> BlocklistPolicy::match(const PeDetails& info) const {
    std::vector<std::wstring> reasons;
    for (const auto& [algo, digest] : info.hashes) {
        auto it = hashes.find(digest);
        if (it != hashes.end() && !it->second.empty()) {
            std::wstring upper = algo;
            for (auto& c : upper) c = (wchar_t)towupper(c);
            reasons.push_back(L"Hash (" + upper + L"): " + it->second);
            break;
        }
    }
    for (const auto& rule : file_rules) {
        if (rule.matches(info)) reasons.push_back(L"File rule: " + (rule.friendly.empty() ? rule.value : rule.friendly));
    }
    for (const auto& signer : signers) {
        if (signer.matches(info)) reasons.push_back(L"Signer: " + signer.name);
    }
    return reasons;
}

BlocklistPolicy parse_policy(const std::string& xml_bytes) {
    XmlNode root;
    try {
        root = parse_xml(xml_bytes);
    } catch (const std::exception& e) {
        throw std::runtime_error(std::string("invalid policy XML: ") + e.what());
    }
    if (root.name != L"SiPolicy") throw std::runtime_error("not a code integrity policy");

    const XmlNode* scenario = nullptr;
    for (const XmlNode* s : root.descendants(L"SigningScenario")) {
        if (s->attr(L"Value") == L"131") {
            scenario = s;
            break;
        }
    }
    if (!scenario) throw std::runtime_error("no kernel signing scenario in the policy");
    std::set<std::wstring> denied_rule_ids, denied_signer_ids;
    for (const XmlNode* refs : scenario->descendants(L"FileRulesRef")) {
        for (const XmlNode* r : refs->all(L"FileRuleRef")) denied_rule_ids.insert(r->attr(L"RuleID"));
    }
    for (const XmlNode* list : scenario->descendants(L"DeniedSigners")) {
        for (const XmlNode* s : list->all(L"DeniedSigner")) denied_signer_ids.insert(s->attr(L"SignerId"));
    }

    BlocklistPolicy policy;
    std::map<std::wstring, FileAttribute> attributes;
    if (const XmlNode* rules = root.child(L"FileRules")) {
        for (const XmlNode& el : rules->children) {
            if (el.name == L"FileAttrib") {
                FileAttribute attr;
                if (attribute_from(el, attr)) attributes[el.attr(L"ID")] = attr;
            } else if (el.name == L"Deny" && denied_rule_ids.count(el.attr(L"ID"))) {
                if (el.has_attr(L"Hash") && !el.attr(L"Hash").empty()) {
                    std::wstring hash = el.attr(L"Hash");
                    for (auto& c : hash) c = (wchar_t)towupper(c);
                    policy.hashes[hash] = el.attr(L"FriendlyName");
                } else {
                    FileAttribute attr;
                    if (attribute_from(el, attr)) policy.file_rules.push_back(attr);
                }
            }
        }
    }
    if (const XmlNode* signers = root.child(L"Signers")) {
        for (const XmlNode* el : signers->all(L"Signer")) {
            if (!denied_signer_ids.count(el->attr(L"ID"))) continue;
            DeniedSigner signer;
            for (const XmlNode* c : el->all(L"CertRoot")) {
                std::wstring v = c->attr(L"Value");
                if (v.empty()) continue;
                for (auto& ch : v) ch = (wchar_t)towupper(ch);
                signer.tbs.insert(v);
            }
            if (signer.tbs.empty()) continue;
            if (const XmlNode* p = el->child(L"CertPublisher")) signer.publisher = p->attr(L"Value");
            if (const XmlNode* o = el->child(L"CertOemID")) signer.oem_id = o->attr(L"Value");
            for (const XmlNode* ref : el->all(L"FileAttribRef")) {
                auto it = attributes.find(ref->attr(L"RuleID"));
                if (it != attributes.end()) signer.file_attributes.push_back(it->second);
            }
            signer.name = el->attributes.count(L"Name") ? el->attr(L"Name") : el->attr(L"ID");
            policy.signers.push_back(std::move(signer));
        }
    }
    const XmlNode* version = root.child(L"VersionEx");
    policy.version = version && !trim(version->text).empty() ? trim(version->text) : L"?";
    if (policy.rule_count() == 0) throw std::runtime_error("the policy contains no deny rule");
    return policy;
}

std::wstring blocklist_dir() { return join(data_dir(), L"driver_blocklist"); }

bool load_policy(BlocklistPolicy& policy, std::map<std::wstring, std::wstring>& meta, const std::wstring& folder_in) {
    std::wstring folder = folder_in.empty() ? blocklist_dir() : folder_in;
    std::string xml;
    if (!read_file(join(folder, POLICY_MEMBER), xml)) return false;
    meta.clear();
    std::string meta_text;
    Json j;
    if (read_file(join(folder, L"blocklist.json"), meta_text) && try_parse_json(wide(meta_text), j) && j.is_object()) {
        for (const auto& [k, v] : j.members()) meta[k] = v.str();
    }
    policy = parse_policy(xml);
    return true;
}

std::string extract_policy(const std::string& zip_bytes) {
    std::string out;
    std::wstring error;
    if (!zip_extract(zip_bytes, utf8(POLICY_MEMBER), out, error, MAX_DOWNLOAD)) throw std::runtime_error(utf8(error));
    return out;
}

BlocklistPolicy download_blocklist(const std::wstring& folder_in, const Fetch& fetch) {
    std::wstring folder = folder_in.empty() ? blocklist_dir() : folder_in;
    HttpResponse r = fetch ? fetch(BLOCKLIST_URL) : http_get(BLOCKLIST_URL, 60000, MAX_DOWNLOAD);
    if (!r.ok) throw std::runtime_error("download failed: " + utf8(r.error));
    if (r.status != 200) throw std::runtime_error("download failed: HTTP " + std::to_string(r.status));
    if (!url_host_in(r.final_url, {L"microsoft.com"})) throw std::runtime_error("unexpected download location: " + utf8(r.final_url));
    if (r.body.size() > MAX_DOWNLOAD) throw std::runtime_error("download too large");
    std::string xml = extract_policy(r.body);
    BlocklistPolicy policy = parse_policy(xml);   // never store something we cannot use

    make_dirs(folder);
    std::wstring target = join(folder, POLICY_MEMBER);
    if (!write_file(target + L".tmp", xml) || !MoveFileExW((target + L".tmp").c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        throw std::runtime_error("the policy could not be saved");
    }
    Json meta = Json::object();
    meta.set(L"version", Json::string(policy.version));
    meta.set(L"downloaded", Json::string(timestamp()));
    meta.set(L"source", Json::string(r.final_url));
    write_file(join(folder, L"blocklist.json"), utf8(meta.dump(true)));
    return policy;
}

// region Driver inventory

std::wstring DriverFile::state() const {
    if (loaded) return L"Loaded";
    if (!service.empty()) return start.empty() ? L"Installed" : L"Installed (" + start + L")";
    return L"File only";
}

static std::map<std::wstring, std::wstring>& device_map() {
    // '\device\harddiskvolume3' -> 'C:' (QueryDosDevice), to read kernel paths of loaded drivers
    static std::map<std::wstring, std::wstring> map;
    static bool done = false;
    if (!done) {
        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
            std::wstring drive = std::wstring(1, letter) + L":";
            wchar_t buf[1024];
            if (QueryDosDeviceW(drive.c_str(), buf, 1024)) map[lower(buf)] = drive;
        }
        done = true;
    }
    return map;
}

std::wstring normalize_driver_path(const std::wstring& path) {
    if (path.empty()) return L"";
    std::wstring p = expand_env(strip_quotes(trim(path)));
    std::wstring low = lower(p);
    if (starts_with(low, L"\\systemroot\\")) p = join(system_root(), p.substr(12));
    else if (starts_with(low, L"systemroot\\")) p = join(system_root(), p.substr(11));
    else if (starts_with(low, L"\\??\\") || starts_with(low, L"\\\\?\\")) p = p.substr(4);
    else if (starts_with(low, L"\\windows\\")) p = system_root().substr(0, 2) + L"\\" + p.substr(1);
    else if (starts_with(low, L"system32\\") || starts_with(low, L"syswow64\\")) p = join(system_root(), p);
    else if (starts_with(low, L"\\device\\")) {
        // drivers loaded from anywhere (a common "bring your own vulnerable driver" trick) show up like this
        auto parts = split(low, L'\\');   // "", "device", "harddiskvolume3", ...
        if (parts.size() < 3) return L"";
        auto it = device_map().find(L"\\device\\" + parts[2]);
        if (it == device_map().end()) return L"";
        std::size_t third = 0;
        int seen = 0;
        for (; third < p.size(); ++third) {
            if (p[third] == L'\\' && ++seen == 3) break;
        }
        if (seen < 3) return L"";
        p = it->second + p.substr(third);
    }
    if (p.empty() || !is_absolute(p)) return L"";
    std::replace(p.begin(), p.end(), L'/', L'\\');
    return p;
}

std::vector<std::wstring> loaded_driver_paths() {
    std::vector<std::wstring> paths;
    std::vector<LPVOID> bases(1024);
    DWORD needed = 0;
    for (;;) {
        if (!EnumDeviceDrivers(bases.data(), (DWORD)(bases.size() * sizeof(LPVOID)), &needed)) return paths;
        if (needed <= bases.size() * sizeof(LPVOID)) break;
        bases.resize(needed / sizeof(LPVOID) + 16);
    }
    std::size_t count = needed / sizeof(LPVOID);
    wchar_t buf[1024];
    for (std::size_t i = 0; i < count; ++i) {
        if (bases[i] && GetDeviceDriverFileNameW(bases[i], buf, 1024)) paths.push_back(buf);
    }
    return paths;
}

std::vector<DriverService> driver_services() {
    std::vector<DriverService> out;
    const std::wstring root = L"SYSTEM\\CurrentControlSet\\Services";
    RegKey services = RegKey::open(L"HKLM", root);
    for (const auto& name : services.subkeys()) {
        RegKey key = RegKey::open(L"HKLM", root + L"\\" + name);
        if (!key.valid()) continue;
        long long type = -1, start = -1;
        std::wstring image = L"System32\\drivers\\" + name + L".sys";
        for (const RegValue& v : key.values()) {
            if (v.name == L"Type" && v.type == REG_DWORD) type = v.dword;
            else if (v.name == L"Start" && v.type == REG_DWORD) start = v.dword;
            else if (v.name == L"ImagePath" && v.is_text()) image = v.text;
        }
        if (type == 1 || type == 2) out.push_back({name, image, start});
    }
    return out;
}

std::vector<DriverFile> collect_driver_files() {
    std::map<std::wstring, DriverFile> files;
    auto add = [&](const std::wstring& path) -> DriverFile* {
        std::wstring p = normalize_driver_path(path);
        if (p.empty() || !is_file(p)) return nullptr;
        auto it = files.emplace(lower(p), DriverFile{p, L"", L"", false}).first;
        return &it->second;
    };
    static const std::map<long long, const wchar_t*> start_types = {{0, L"Boot"}, {1, L"System"}, {2, L"Automatic"}, {3, L"Manual"}, {4, L"Disabled"}};
    for (const auto& s : driver_services()) {
        DriverFile* entry = add(s.image);
        if (entry && entry->service.empty()) {
            entry->service = s.name;
            auto it = start_types.find(s.start);
            entry->start = it == start_types.end() ? L"" : it->second;
        }
    }
    for (const auto& path : loaded_driver_paths()) {
        if (DriverFile* entry = add(path)) entry->loaded = true;
    }
    std::vector<Entry> sys;
    if (list_dir(join(join(system_root(), L"System32"), L"drivers"), sys)) {
        for (const Entry& e : sys) {
            if (ends_with(lower(e.name), L".sys")) add(e.path);
        }
    }
    std::vector<DriverFile> out;
    for (auto& kv : files) out.push_back(kv.second);
    std::sort(out.begin(), out.end(), [](const DriverFile& a, const DriverFile& b) { return lower(a.path) < lower(b.path); });
    return out;
}

std::vector<DriverCheck> check_drivers(const BlocklistPolicy& policy, const std::vector<DriverFile>& drivers,
                                       const std::function<void(std::size_t, std::size_t, const std::wstring&)>& progress, const Stop& stop) {
    std::vector<DriverCheck> results;
    for (std::size_t n = 0; n < drivers.size(); ++n) {
        if (stop()) break;
        if (progress) progress(n + 1, drivers.size(), drivers[n].path);
        PeDetails info = analyze_pe(drivers[n].path);
        std::vector<std::wstring> reasons;
        if (info.error.empty()) reasons = policy.match(info);
        results.push_back({drivers[n], std::move(info), std::move(reasons)});
    }
    return results;
}

// endregion

// region Windows protection state

bool ProtectionState::enforced() const {
    if (blocklist_setting == 0) return false;
    if (hvci_enabled) return true;
    if (blocklist_setting == 1) return true;
    return build >= 22621;   // on by default from Windows 11 22H2
}

std::wstring ProtectionState::summary() const {
    std::wstring setting = blocklist_setting < 0 ? L"not set (Windows default)" : blocklist_setting == 0 ? L"off" : blocklist_setting == 1 ? L"on" : std::to_wstring(blocklist_setting);
    return L"Windows blocklist setting: " + setting + L"  |  Memory integrity (HVCI): " + (hvci_enabled ? L"on" : L"off") +
           L"  |  Enforced: " + (enforced() ? L"yes" : L"NO");
}

static bool read_dword(const std::wstring& path, const std::wstring& name, DWORD& value) {
    return RegKey::open(L"HKLM", path).get_dword(name, value);
}

ProtectionState protection_state() {
    ProtectionState s;
    DWORD v = 0;
    if (read_dword(L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config", L"VulnerableDriverBlocklistEnable", v)) s.blocklist_setting = (int)v;
    s.hvci_enabled = read_dword(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity", L"Enabled", v) && v == 1;
    std::wstring build;
    if (RegKey::open(L"HKLM", L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion").get_text(L"CurrentBuildNumber", build)) {
        s.build = (int)wcstol(build.c_str(), nullptr, 10);
    }
    return s;
}

// endregion

}  // namespace dd
