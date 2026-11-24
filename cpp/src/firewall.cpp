// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the Windows Firewall reading: profile state, rule fields and the cached read of the firewall settings.

#include <ddcore/firewall.hpp>

#include <algorithm>
#include <cstdarg>
#include <iterator>

#include <windows.h>
#include <shlwapi.h>

#include <ddcore/proc.hpp>
#include <ddcore/registry.hpp>

namespace dd {

const wchar_t* PROFILE_NAMES[3] = {L"Domain", L"Private", L"Public"};

namespace {

const int DYNAMIC_RPC_START = 49152;
const std::size_t MAX_LOG_BYTES = 32u * 1024 * 1024;

std::wstring fmt(const wchar_t* format, ...) {
    va_list args;
    va_start(args, format);
    va_list copy;
    va_copy(copy, args);
    int n = _vscwprintf(format, copy);
    va_end(copy);
    std::wstring out;
    if (n > 0) {
        out.resize((std::size_t)n + 1);
        vswprintf(out.data(), out.size(), format, args);
        out.resize((std::size_t)n);
    }
    va_end(args);
    return out;
}

// path normalisation like os.path.normpath: slashes, duplicate separators, "." and ".." segments
std::wstring norm_path(const std::wstring& path) {
    std::wstring p = path;
    std::replace(p.begin(), p.end(), L'/', L'\\');
    std::wstring prefix;
    if (p.size() >= 2 && p[1] == L':') {
        prefix = p.substr(0, 2);
        p = p.substr(2);
    }
    bool absolute_path = !p.empty() && p[0] == L'\\';
    std::vector<std::wstring> out;
    for (const auto& seg : split(p, L'\\')) {
        if (seg.empty() || seg == L".") continue;
        if (seg == L".." && !out.empty() && out.back() != L"..") out.pop_back();
        else if (seg != L".." || !absolute_path) out.push_back(seg);
    }
    std::wstring result = prefix + (absolute_path ? L"\\" : L"");
    for (std::size_t i = 0; i < out.size(); ++i) result += (i ? L"\\" : L"") + out[i];
    return result.empty() ? L"." : result;
}

struct Fields {
    std::vector<std::pair<std::wstring, std::vector<std::wstring>>> items;   // keys in first-seen order
    void add(const std::wstring& key, const std::wstring& value) {
        for (auto& it : items) {
            if (it.first == key) {
                it.second.push_back(value);
                return;
            }
        }
        items.push_back({key, {value}});
    }
    bool has(const std::wstring& key) const {
        for (auto& it : items) {
            if (it.first == key) return true;
        }
        return false;
    }
    std::wstring first(const std::wstring& key) const {
        for (auto& it : items) {
            if (it.first == key) return it.second[0];
        }
        return L"";
    }
    std::vector<std::wstring> values(const std::wstring& key) const {
        for (auto& it : items) {
            if (it.first == key) return it.second;
        }
        return {};
    }
};

std::wstring upper(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towupper(c);
    return s;
}

}  // namespace

bool FirewallRule::any_remote() const {
    if (remote_addresses.empty()) return true;
    for (const auto& a : remote_addresses) {
        std::wstring l = lower(a);
        if (l == L"*" || l == L"any") return true;
    }
    return false;
}

std::wstring FirewallRule::scope() const {
    if (any_remote()) return L"any address";
    std::vector<std::wstring> unique;
    for (const auto& a : remote_addresses) {
        if (std::find(unique.begin(), unique.end(), a) == unique.end()) unique.push_back(a);
    }
    std::wstring out;
    for (std::size_t i = 0; i < unique.size(); ++i) out += (i ? L", " : L"") + unique[i];
    return out;
}

bool FirewallRule::is_windows_component() const {
    if (app.empty() || app == L"system") return !service.empty() || app == L"system" || starts_with(name, L"@");
    return starts_with(app, lower(system_root()) + L"\\");
}

std::wstring resolve_indirect(const std::wstring& text) {
    if (!starts_with(text, L"@")) return text;
    static std::map<std::wstring, std::wstring> cache;
    auto it = cache.find(text);
    if (it != cache.end()) return it->second;
    std::wstring result = text;
    wchar_t buf[512];
    if (SHLoadIndirectString(expand_env(text).c_str(), buf, 512, nullptr) == S_OK && buf[0]) result = buf;
    cache[text] = result;
    return result;
}

bool parse_rule(const std::wstring& rule_id, const std::wstring& value, FirewallRule& out, const std::wstring& source,
                const IndirectResolver& resolve) {
    Fields fields;
    auto parts = split(value, L'|');
    for (std::size_t i = 1; i < parts.size(); ++i) {
        std::size_t eq = parts[i].find(L'=');
        if (eq != std::wstring::npos) fields.add(parts[i].substr(0, eq), parts[i].substr(eq + 1));
    }
    if (!fields.has(L"Action") || !fields.has(L"Dir")) return false;

    auto all_of = [&](const std::wstring& prefix) {
        std::vector<std::wstring> r;
        for (const auto& [k, vs] : fields.items) {
            if (k == prefix || starts_with(k, prefix + L"2_")) r.insert(r.end(), vs.begin(), vs.end());
        }
        return r;
    };
    auto addresses = [&](const std::wstring& prefix) {
        std::vector<std::wstring> r;
        for (const auto& [k, vs] : fields.items) {
            if (starts_with(k, prefix) && k.size() > 2 && (k[2] == L'4' || k[2] == L'6')) r.insert(r.end(), vs.begin(), vs.end());
        }
        return r;
    };

    FirewallRule r;
    std::wstring app = fields.first(L"App");
    if (!app.empty()) app = lower(app) == L"system" ? L"system" : lower(norm_path(expand_env(app)));
    r.id = rule_id;
    std::wstring name = fields.first(L"Name");
    r.name = resolve(name.empty() ? rule_id : name);
    r.action = fields.first(L"Action");
    r.direction = fields.first(L"Dir");
    r.active = upper(fields.first(L"Active")) == L"TRUE";
    r.protocol = fields.first(L"Protocol");
    for (const auto& p : fields.values(L"Profile")) {
        for (const wchar_t* known : PROFILE_NAMES) {
            if (p == known) r.profiles.insert(p);
        }
    }
    r.local_ports = all_of(L"LPort");
    r.remote_addresses = addresses(L"RA");
    r.local_addresses = addresses(L"LA");
    r.app = app;
    r.service = fields.first(L"Svc");
    r.package = fields.first(L"AppPkgId");
    if (r.package.empty()) r.package = fields.first(L"PFN");
    r.edge = upper(fields.first(L"Edge")) == L"TRUE";
    r.source = source;
    // IF/IFType: specific interfaces; TTK*: trust tuple keywords (Wi-Fi Direct, proximity sharing...)
    for (const auto& [k, vs] : fields.items) {
        if (k == L"IF" || k == L"IFType" || starts_with(k, L"TTK")) r.interface_limited = true;
    }
    out = std::move(r);
    return true;
}

std::vector<FirewallRule> read_rules() {
    const std::pair<const wchar_t*, const wchar_t*> stores[] = {
        {L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\FirewallRules", L"Local"},
        {L"SOFTWARE\\Policies\\Microsoft\\WindowsFirewall\\FirewallRules", L"Group Policy"}};
    std::vector<FirewallRule> rules;
    for (const auto& [path, source] : stores) {
        RegKey key = RegKey::open(L"HKLM", path);
        for (const RegValue& v : key.values()) {
            FirewallRule rule;
            if (v.is_text() && parse_rule(v.name, v.text, rule, source)) rules.push_back(std::move(rule));
        }
    }
    return rules;
}

bool port_matches(const std::vector<std::wstring>& ports, int port) {
    if (ports.empty()) return true;
    for (const auto& p : ports) {
        for (const auto& raw : split(p, L',')) {
            std::wstring item = trim(raw);
            if (item == L"*" || item == L"Any") return true;
            if (item == L"RPC-EPMap" && port == 135) return true;
            if (item == L"RPC" && port >= DYNAMIC_RPC_START) return true;
            std::size_t dash = item.find(L'-');
            auto number = [](const std::wstring& t, long& v) {
                wchar_t* end = nullptr;
                v = wcstol(t.c_str(), &end, 10);
                return !t.empty() && end && *end == 0;
            };
            long lo, hi;
            if (dash != std::wstring::npos) {
                if (number(item.substr(0, dash), lo) && number(item.substr(dash + 1), hi) && lo <= port && port <= hi) return true;
            } else if (number(item, lo) && lo == port) {
                return true;
            }
        }
    }
    return false;
}

// region Profiles

static const wchar_t* PROFILES_PS = LR"J(
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
  [pscustomobject]@{ Name = [string]$_.Name; Enabled = [string]$_.Enabled;
    DefaultInboundAction = [string]$_.DefaultInboundAction; DefaultOutboundAction = [string]$_.DefaultOutboundAction;
    LogBlocked = [string]$_.LogBlocked; LogAllowed = [string]$_.LogAllowed;
    LogFileName = [string]$_.LogFileName; LogMaxSizeKilobytes = [int]$_.LogMaxSizeKilobytes }
})
$networks = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object {
  [pscustomobject]@{ Interface = [string]$_.InterfaceAlias; Name = [string]$_.Name;
    Category = [string]$_.NetworkCategory; IPv4 = [string]$_.IPv4Connectivity }
})
[pscustomobject]@{ profiles = $profiles; networks = $networks } | ConvertTo-Json -Depth 4 -Compress
)J";

static bool truthy(const Json& v) {
    std::wstring t = lower(trim(v.str()));
    return t == L"true" || t == L"1";
}

void parse_profiles(const Json& data, std::map<std::wstring, ProfileState>& profiles, std::vector<Json>& networks) {
    profiles.clear();
    for (const Json& p : data.get(L"profiles").as_list()) {
        std::wstring name = p.get(L"Name").str();
        bool known = false;
        for (const wchar_t* n : PROFILE_NAMES) known |= name == n;
        if (!known) continue;
        std::wstring inbound = p.get(L"DefaultInboundAction").str(), outbound = p.get(L"DefaultOutboundAction").str();
        std::wstring log_file = p.get(L"LogFileName").str();
        profiles[name] = {name, truthy(p.get(L"Enabled")), inbound.empty() || inbound == L"NotConfigured" ? L"Block" : inbound,   // Windows default
                          outbound.empty() || outbound == L"NotConfigured" ? L"Allow" : outbound, truthy(p.get(L"LogBlocked")),
                          expand_env(log_file.empty() ? L"%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall.log" : log_file)};
    }
    networks = data.get(L"networks").as_list();
}

std::set<std::wstring> active_profiles(const std::vector<Json>& networks) {
    std::set<std::wstring> active;
    for (const Json& n : networks) {
        std::wstring c = n.get(L"Category").str();
        active.insert(c == L"Private" ? L"Private" : c == L"DomainAuthenticated" ? L"Domain" : L"Public");
    }
    if (active.empty()) active.insert(L"Public");
    return active;
}

Json collect_profiles() {
    Json data = run_powershell_json(PROFILES_PS, 60000);
    return data.is_object() ? data : Json();
}

std::pair<bool, std::wstring> set_dropped_packet_logging(bool enabled) {
    ProcOptions o;
    o.timeout_ms = 60000;
    ProcResult r = run_powershell(std::wstring(L"Set-NetFirewallProfile -Profile Domain,Private,Public -LogBlocked ") +
                                      (enabled ? L"True" : L"False") + L" -ErrorAction Stop",
                                  o);
    return {r.ok(), trim(r.output)};
}

// endregion

// region Exposure

static bool rule_matches_listener(const FirewallRule& rule, const Listener& l) {
    if (!rule.package.empty() || rule.interface_limited) return false;   // app container rules only apply to that UWP app; TTK/IF to special interfaces
    if (!rule.protocol.empty()) {
        static const std::map<std::wstring, std::wstring> protocols = {{L"6", L"TCP"}, {L"17", L"UDP"}, {L"1", L"ICMPv4"}, {L"58", L"ICMPv6"}};
        auto it = protocols.find(rule.protocol);
        if (it == protocols.end() || it->second != l.protocol) return false;
    }
    if (!rule.app.empty()) {
        if (rule.app == L"system") {
            if (l.pid != 4) return false;
        } else if (!l.path.empty()) {
            if (lower(norm_path(l.path)) != rule.app) return false;
        } else if (base_name(rule.app) != lower(l.process + L".exe")) {
            return false;   // path not readable: fall back to the executable name
        }
    }
    if (!rule.service.empty() && rule.service != L"*") {
        bool found = false;
        for (const auto& s : l.services) found |= lower(s) == lower(rule.service);
        if (!found) return false;
    } else if (rule.service == L"*" && l.services.empty()) {
        return false;
    }
    return port_matches(rule.local_ports, l.port);
}

Exposure evaluate_exposure(const Listener& listener, const std::vector<FirewallRule>& rules,
                           const std::map<std::wstring, ProfileState>& profiles, const std::set<std::wstring>& active) {
    if (listener.loopback()) return {L"local", L"Loopback only (this PC)", L""};
    auto rank = [](const std::wstring& level) { return level == L"open" ? 3 : level == L"limited" ? 2 : 1; };
    bool have_best = false;
    Exposure best;
    for (const auto& profile : active) {   // std::set iterates sorted, like sorted(active)
        Exposure result;
        auto st = profiles.find(profile);
        const ProfileState* state = st == profiles.end() ? nullptr : &st->second;
        if (state && !state->enabled) {
            result = {L"open", L"Open: firewall is off (" + profile + L")", L""};
        } else {
            std::vector<const FirewallRule*> blocks, allows;
            for (const auto& r : rules) {
                if (!r.active || r.direction != L"In" || !r.applies_to_profile(profile) || !rule_matches_listener(r, listener)) continue;
                if (r.action == L"Block") blocks.push_back(&r);
                else if (r.action == L"Allow") allows.push_back(&r);
            }
            if (!blocks.empty()) {
                result = {L"blocked", L"Blocked by rule (" + profile + L")", blocks[0]->name};
            } else if (!allows.empty()) {
                const FirewallRule* chosen = allows[0];
                bool wide = false;
                for (const auto* a : allows) {
                    if (a->any_remote()) {
                        if (!wide) chosen = a;
                        wide = true;
                    }
                }
                if (wide) result = {L"open", L"Open to any address (" + profile + L")", chosen->name};
                else result = {L"limited", L"Open to " + chosen->scope() + L" (" + profile + L")", chosen->name};
            } else if (state && state->inbound == L"Allow") {
                result = {L"open", L"Open: inbound allowed by default (" + profile + L")", L""};
            } else {
                result = {L"blocked", L"Blocked by default (" + profile + L")", L""};
            }
        }
        if (!have_best || rank(result.level) > rank(best.level)) {
            best = result;
            have_best = true;
        }
    }
    return have_best ? best : Exposure{L"blocked", L"Blocked", L""};
}

// endregion

// region Findings

std::map<std::wstring, int> rule_statistics(const std::vector<FirewallRule>& rules) {
    std::map<std::wstring, int> s = {{L"total", (int)rules.size()}, {L"enabled", 0}, {L"inbound_allow", 0},
                                     {L"inbound_block", 0}, {L"outbound_block", 0}, {L"group_policy", 0}};
    for (const auto& r : rules) {
        if (r.active) {
            ++s[L"enabled"];
            if (r.direction == L"In" && r.action == L"Allow") ++s[L"inbound_allow"];
            if (r.direction == L"In" && r.action == L"Block") ++s[L"inbound_block"];
            if (r.direction == L"Out" && r.action == L"Block") ++s[L"outbound_block"];
        }
        if (r.source == L"Group Policy") ++s[L"group_policy"];
    }
    return s;
}

static std::wstring rule_label(const FirewallRule& r) {
    std::wstring what = !r.app.empty() && r.app != L"system" ? r.app : !r.service.empty() ? L"service " + r.service : L"any program";
    std::wstring ports;
    for (std::size_t i = 0; i < r.local_ports.size(); ++i) ports += (i ? L"," : L"") + r.local_ports[i];
    if (ports.empty()) ports = L"all ports";
    static const std::map<std::wstring, std::wstring> protocols = {{L"6", L"TCP"}, {L"17", L"UDP"}, {L"1", L"ICMPv4"}, {L"58", L"ICMPv6"}};
    auto p = protocols.find(r.protocol);
    std::wstring proto = p != protocols.end() ? p->second : r.protocol.empty() ? L"any protocol" : L"protocol " + r.protocol;
    std::wstring profiles;
    for (const auto& n : r.profiles) profiles += (profiles.empty() ? L"" : L"/") + n;
    if (profiles.empty()) profiles = L"all profiles";
    return r.name + L": " + what + L", " + proto + L" " + ports + L", " + profiles + L", from " + r.scope();
}

bool is_protected_path(const std::wstring& path) {
    std::wstring low = lower(norm_path(path));
    for (const wchar_t* var : {L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramW6432"}) {
        std::wstring root = env_var(var);
        if (!root.empty() && starts_with(low, lower(norm_path(root)) + L"\\")) return true;
    }
    return starts_with(low, lower(norm_path(system_root())) + L"\\");
}

std::vector<Finding> evaluate_firewall(const std::vector<FirewallRule>& rules, const std::map<std::wstring, ProfileState>& profiles,
                                       const std::set<std::wstring>& active, const std::function<bool(const std::wstring&)>& path_exists) {
    std::vector<Finding> findings;
    if (profiles.empty()) findings.push_back({Status::Warning, L"Firewall profiles could not be read", {}});
    for (const wchar_t* name : PROFILE_NAMES) {
        auto it = profiles.find(name);
        if (it == profiles.end()) continue;
        const ProfileState& p = it->second;
        std::wstring where = active.count(name) ? L" (in use now)" : L"";
        if (!p.enabled) {
            findings.push_back({Status::Critical, L"Firewall is OFF for the " + std::wstring(name) + L" profile" + where,
                                {L"Every listening port is reachable from that kind of network."}});
        } else if (p.inbound == L"Allow") {
            findings.push_back({Status::Critical, std::wstring(name) + L" profile allows inbound connections by default" + where,
                                {L"Only explicit block rules protect the PC. The Windows default is Block."}});
        }
    }
    bool all_good = !profiles.empty();
    for (const auto& [n, p] : profiles) all_good &= p.enabled && p.inbound != L"Allow";
    if (all_good) findings.push_back({Status::Ok, L"Firewall on for all profiles, inbound blocked by default", {}});

    std::vector<const FirewallRule*> inbound_allow;
    for (const auto& r : rules) {
        if (r.active && r.direction == L"In" && r.action == L"Allow" && r.package.empty()) inbound_allow.push_back(&r);
    }
    std::vector<const FirewallRule*> allow_all;
    for (const auto* r : inbound_allow) {
        if (r->app.empty() && r->service.empty() && r->local_ports.empty() && r->any_remote() && !r->local_scope_limited()) allow_all.push_back(r);
    }
    if (!allow_all.empty()) {
        std::vector<std::wstring> details = {L"No program, service or port restriction: the rule opens the PC completely."};
        for (const auto* r : allow_all) details.push_back(rule_label(*r));
        findings.push_back({Status::Critical, fmt(L"%zu rule(s) allow any inbound traffic", allow_all.size()), details});
    }
    std::vector<const FirewallRule*> public_open;
    for (const auto* r : inbound_allow) {
        if (r->applies_to_profile(L"Public") && r->any_remote() && !r->local_scope_limited() && !r->is_windows_component() &&
            std::find(allow_all.begin(), allow_all.end(), r) == allow_all.end())
            public_open.push_back(r);
    }
    if (!public_open.empty()) {
        std::vector<std::wstring> details = {L"Public profile = hotel, café, airport Wi-Fi. Restrict these rules to the Private "
                                             L"profile unless the program must be reachable there."};
        for (const auto* r : public_open) details.push_back(rule_label(*r));
        findings.push_back({Status::Warning, fmt(L"%zu program rule(s) accept connections on public networks", public_open.size()), details});
    }
    std::vector<const FirewallRule*> edge;
    for (const auto* r : inbound_allow) {
        if (r->edge && !r->is_windows_component()) edge.push_back(r);
    }
    if (!edge.empty()) {
        std::vector<std::wstring> details;
        for (const auto* r : edge) details.push_back(rule_label(*r));
        findings.push_back({Status::Info, fmt(L"%zu rule(s) allow edge traversal (reachable through NAT / Teredo)", edge.size()), details});
    }

    std::vector<const FirewallRule*> orphans;
    std::wstring windows_prefix = lower(system_root()) + L"\\";
    for (const auto& r : rules) {
        if (r.app.empty() || r.app == L"system" || !is_absolute(r.app) || r.app.size() < 2 || r.app[1] != L':') continue;
        if (path_exists(r.app.substr(0, 2) + L"\\") && !path_exists(r.app) && !starts_with(r.app, windows_prefix)) orphans.push_back(&r);
    }
    std::vector<const FirewallRule*> writable, protected_rules;
    for (const auto* r : orphans) (is_protected_path(r->app) ? protected_rules : writable).push_back(r);
    if (!writable.empty()) {
        bool allowing = false;
        std::set<std::wstring> lines;
        for (const auto* r : writable) {
            allowing |= r->action == L"Allow" && r->active;
            lines.insert(r->name + L" (" + r->action + (r->active ? L"" : L", disabled") + L"): " + r->app);
        }
        std::vector<std::wstring> details = {L"A program copied later to that exact path inherits the rule (for example an inbound allow). "
                                             L"Delete these rules in Windows Defender Firewall with Advanced Security (wf.msc)."};
        details.insert(details.end(), lines.begin(), lines.end());
        findings.push_back({allowing ? Status::Warning : Status::Info,
                            fmt(L"%zu rule(s) for missing programs in folders any user can write to", writable.size()), details});
    }
    if (!protected_rules.empty()) {
        std::set<std::wstring> lines;
        for (const auto* r : protected_rules) lines.insert(r->name + L": " + r->app);
        std::vector<std::wstring> details = {L"Leftovers in Program Files: harmless, only administrators can recreate the file. Can be removed in wf.msc."};
        details.insert(details.end(), lines.begin(), lines.end());
        findings.push_back({Status::Info, fmt(L"%zu rule(s) for programs that were uninstalled", protected_rules.size()), details});
    }
    return findings;
}

// endregion

// region Blocked traffic log

std::vector<std::pair<std::wstring, long long>> most_common(const CounterMap& counter, std::size_t limit) {
    std::vector<std::pair<std::wstring, long long>> out(counter.begin(), counter.end());
    std::stable_sort(out.begin(), out.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    if (out.size() > limit) out.resize(limit);
    return out;
}

long long LogStats::dropped() const {
    long long n = 0;
    for (const auto& [k, v] : by_action) {
        if (k.first == L"DROP") n += v;
    }
    return n;
}

void parse_log_lines(const std::vector<std::wstring>& lines, LogStats& stats) {
    std::vector<std::wstring> fields = {L"date", L"time", L"action", L"protocol", L"src-ip", L"dst-ip", L"src-port", L"dst-port", L"size",
                                        L"tcpflags", L"tcpsyn", L"tcpack", L"tcpwin", L"icmptype", L"icmpcode", L"info", L"path"};
    for (const auto& raw : lines) {
        std::wstring line = trim(raw);
        if (line.empty()) continue;
        if (line[0] == L'#') {
            if (starts_with(line, L"#Fields:")) {
                fields.clear();
                for (const auto& f : split(line.substr(8), L' ')) {
                    if (!f.empty()) fields.push_back(f);
                }
            }
            continue;
        }
        std::vector<std::wstring> parts = split(line, L' ');
        if (parts.size() < 8) continue;
        std::map<std::wstring, std::wstring> rec;
        for (std::size_t i = 0; i < fields.size() && i < parts.size(); ++i) rec[fields[i]] = parts[i];
        auto get = [&](const wchar_t* key, const wchar_t* fallback) {
            auto it = rec.find(key);
            return it == rec.end() ? std::wstring(fallback) : it->second;
        };
        ++stats.lines;
        std::wstring stamp = get(L"date", L"") + L" " + get(L"time", L"");
        if (stats.first.empty() || stamp < stats.first) stats.first = stamp;
        if (stamp > stats.last) stats.last = stamp;
        std::wstring action = get(L"action", L"?"), direction = get(L"path", L"?");
        ++stats.by_action[{action, direction}];
        if (action != L"DROP") continue;
        ++stats.per_day[get(L"date", L"?")];
        std::wstring pid = get(L"pid", L"-");
        if (rec.count(L"pid") && pid != L"-" && pid != L"" && pid != L"0") ++stats.processes[pid];
        std::wstring proto = get(L"protocol", L"?");
        if (direction == L"RECEIVE") {
            ++stats.inbound_sources[get(L"src-ip", L"?")];
            std::wstring port = get(L"dst-port", L"-");
            ++stats.inbound_ports[port != L"-" ? proto + L" " + port : proto];
        } else if (direction == L"SEND") {
            ++stats.outbound_targets[get(L"dst-ip", L"?") + L" " + proto + L" " + get(L"dst-port", L"-")];
        }
    }
}

bool read_log(const std::wstring& path, LogStats& stats) {
    bool any = false;
    for (const std::wstring& p : {path + L".old", path}) {
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        LARGE_INTEGER size{};
        GetFileSizeEx(h, &size);
        bool tail = (std::uint64_t)size.QuadPart > MAX_LOG_BYTES;
        if (tail) {
            LARGE_INTEGER to;
            to.QuadPart = size.QuadPart - (long long)MAX_LOG_BYTES;
            SetFilePointerEx(h, to, nullptr, FILE_BEGIN);
        }
        std::string bytes;
        char buf[1 << 16];
        DWORD got;
        while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got) bytes.append(buf, got);
        CloseHandle(h);
        if (tail) {
            std::size_t nl = bytes.find('\n');   // the first line is cut in the middle
            bytes.erase(0, nl == std::string::npos ? bytes.size() : nl + 1);
        }
        parse_log_lines(split(wide(bytes), L'\n'), stats);
        stats.files.push_back(p);
        any = true;
    }
    return any;
}

std::wstring describe_port(const std::wstring& key) {
    static const std::map<std::wstring, std::wstring> hints = {
        {L"TCP 445", L"SMB file sharing"}, {L"TCP 139", L"NetBIOS"}, {L"UDP 137", L"NetBIOS name"}, {L"UDP 138", L"NetBIOS datagram"},
        {L"TCP 3389", L"Remote Desktop"}, {L"TCP 22", L"SSH"}, {L"TCP 23", L"Telnet"}, {L"TCP 135", L"RPC"}, {L"UDP 1900", L"SSDP / UPnP"},
        {L"UDP 5353", L"mDNS"}, {L"UDP 5355", L"LLMNR"}, {L"UDP 3702", L"WS-Discovery"}, {L"UDP 67", L"DHCP"}, {L"UDP 68", L"DHCP"},
        {L"TCP 80", L"HTTP"}, {L"TCP 443", L"HTTPS"}, {L"UDP 443", L"QUIC"}, {L"UDP 123", L"NTP"}, {L"UDP 161", L"SNMP"}};
    auto it = hints.find(key);
    return it == hints.end() ? key : key + L" (" + it->second + L")";
}

// endregion

FirewallReport run_firewall_analysis(const Progress& progress) {
    FirewallReport report;
    if (progress) progress(L"Reading firewall profiles and rules...");
    parse_profiles(collect_profiles(), report.profiles, report.networks);
    report.active = active_profiles(report.networks);
    report.rules = read_rules();
    report.findings = evaluate_firewall(report.rules, report.profiles, report.active);
    for (const auto& [n, p] : report.profiles) report.log_enabled |= p.log_blocked;
    report.log_path = report.profiles.empty() ? join(join(join(join(system_root(), L"system32"), L"LogFiles"), L"Firewall"), L"pfirewall.log")
                                              : report.profiles.begin()->second.log_file;
    if (progress) progress(L"Reading the firewall log...");
    report.has_log = read_log(report.log_path, report.log);
    report.stats = rule_statistics(report.rules);
    return report;
}

}  // namespace dd
