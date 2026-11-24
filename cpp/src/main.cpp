// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Command line front end ddc of the DD Cleaner engine: read-only commands, and delete only with the --yes flag.

#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#include <windows.h>

#include <ddcore/audit.hpp>
#include <ddcore/dead_registry.hpp>
#include <ddcore/garbage.hpp>
#include <ddcore/secrets.hpp>
#include <ddcore/startup.hpp>
#include <ddcore/threat.hpp>

using namespace dd;

namespace {

void out(const std::wstring& text) { std::fputs(utf8(text).c_str(), stdout); }
void line(const std::wstring& text = L"") { out(text + L"\n"); }

const char* USAGE =
    "ddc: DD Cleaner engine (read-only unless --delete --yes is given)\n"
    "\n"
    "  ddc presets                       list the search presets\n"
    "  ddc search <preset|pattern> [options]\n"
    "  ddc leftovers [options]           folders of programs that are no longer installed\n"
    "  ddc usage [folder]                disk usage per drive, or per folder below <folder>\n"
    "  ddc registry                      dead registry entries (looking only)\n"
    "  ddc secrets [--show]              saved Wi-Fi, license, Windows and browser passwords (hidden unless --show)\n"
    "  ddc audit                         security audit (reads only)\n"
    "  ddc startup                       programs that start by themselves\n"
    "\n"
    "options for search and leftovers:\n"
    "  --where profile|appdata|drives    where to look (default profile), or --path <folder>\n"
    "  --age <days>                      only items older than this\n"
    "  --limit <n>                       stop after n items (default 5000)\n"
    "  --delete --yes                    send the listed items to the Recycle Bin\n"
    "  --permanent                       with --delete: remove for good\n";

struct Options {
    std::vector<std::wstring> positional;
    bool show = false;
    Where where = Where::Profile;
    std::wstring path;
    double age = 0;
    std::size_t limit = SEARCH_LIMIT;
    bool del = false, yes = false, permanent = false;
};

bool parse(int argc, wchar_t** argv, int from, Options& o) {
    for (int i = from; i < argc; ++i) {
        std::wstring a = argv[i];
        auto next = [&](std::wstring& v) { return i + 1 < argc ? (v = argv[++i], true) : false; };
        std::wstring v;
        if (a == L"--where") {
            if (!next(v)) return false;
            if (v == L"profile") o.where = Where::Profile;
            else if (v == L"appdata") o.where = Where::AppData;
            else if (v == L"drives") o.where = Where::Drives;
            else return false;
        } else if (a == L"--path") {
            if (!next(o.path)) return false;
            o.where = Where::Custom;
        } else if (a == L"--age") {
            if (!next(v)) return false;
            o.age = std::stod(v);
        } else if (a == L"--limit") {
            if (!next(v)) return false;
            o.limit = (std::size_t)std::stoul(v);
        } else if (a == L"--delete") o.del = true;
        else if (a == L"--yes") o.yes = true;
        else if (a == L"--permanent") o.permanent = true;
        else if (a == L"--show") o.show = true;
        else if (starts_with(a, L"--")) return false;
        else o.positional.push_back(a);
    }
    return true;
}

void print_items(const std::vector<GarbageItem>& items) {
    std::uint64_t likely = 0, all = 0;
    for (const auto& i : items) {
        all += i.size;
        if (is_likely(i)) likely += i.size;
        std::wstring conf = confidence_name(i.confidence);
        line(human_size(i.size) + L"\t" + (i.kind == Kind::Folder ? L"Folder" : L"File") + L"\t" +
             (conf.empty() ? L"-" : conf) + L"\t" + i.path);
    }
    line();
    for (const auto& c : summarize(items)) line(L"  " + c.category + L": " + std::to_wstring(c.count) + L" items, " + human_size(c.bytes));
    line(std::to_wstring(items.size()) + L" items, " + human_size(all) + L" (" + human_size(likely) + L" counted as freeable)");
}

int finish(const FileScan& scan, const Options& o) {
    print_items(scan.items);
    if (scan.truncated) line(L"The list was cut at the limit: narrow the search.");
    if (!o.del) return 0;
    if (!o.yes) {
        line(L"Nothing deleted: add --yes to confirm.");
        return 2;
    }
    DeleteResult r = delete_items(scan.items, o.permanent);
    line(L"Deleted " + std::to_wstring(r.deleted.size()) + L", freed " + human_size(r.freed));
    for (const auto& [item, why] : r.failed) line(L"Not deleted: " + item.path + L": " + why);
    return r.failed.empty() ? 0 : 1;
}

Progress status() {
    return [](const std::wstring& text) { std::fputs(("\r" + utf8(text) + "          \r").c_str(), stderr); };
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    if (argc < 2) {
        std::fputs(USAGE, stdout);
        return 0;
    }
    std::wstring cmd = argv[1];
    Options o;
    try {
        if (!parse(argc, argv, 2, o)) {
            std::fputs(USAGE, stderr);
            return 64;
        }
        if (cmd == L"presets") {
            for (const auto& p : presets()) line(std::wstring(p.name) + L"\t" + p.patterns);
        } else if (cmd == L"search") {
            if (o.positional.empty()) {
                std::fputs(USAGE, stderr);
                return 64;
            }
            std::wstring patterns = o.positional[0];
            for (const auto& p : presets()) {
                if (lower(p.name) == lower(patterns)) patterns = p.patterns;
            }
            FileScan scan = search_files(patterns, search_roots(o.where, o.path), never, status(), o.limit, o.age);
            return finish(scan, o);
        } else if (cmd == L"leftovers") {
            FileScan scan = find_leftovers(installed_markers(), never, status(), nullptr, -1, o.age);
            return finish(scan, o);
        } else if (cmd == L"usage") {
            if (o.positional.empty()) {
                for (const auto& d : drive_usage(fixed_drives())) {
                    line(d.root + L"\t" + human_size(d.used) + L" used of " + human_size(d.total) + L", " + human_size(d.free) + L" free");
                }
            } else {
                FolderUsage u = folder_usage(o.positional[0], never, status());
                for (const auto& [path, size] : u.folders) line(human_size(size) + L"\t" + path);
                line(human_size(u.loose_files) + L"\t(files directly in the folder)");
                line(human_size(u.total()) + L"\ttotal");
            }
        } else if (cmd == L"registry") {
            auto entries = scan_dead(never, status());
            for (const auto& e : entries) {
                line(e.category + L"\t" + e.location() + (e.is_key ? L"" : L"\\" + e.value) + L"\t" + e.reason);
            }
            line(std::to_wstring(entries.size()) + L" dead entries");
        } else if (cmd == L"hunt") {
            auto persistence = collect_persistence(never, status());
            for (const auto& f : persistence) {
                std::wstring flags;
                for (const auto& x : f.flags) flags += (flags.empty() ? L"" : L"; ") + x;
                line(std::to_wstring(f.severity) + L"	" + f.category + L"	" + f.title + L"	" + flags);
            }
            for (const auto& p : scan_processes(never, status())) {
                if (p.severity == SEV_INFO && p.flags.empty()) continue;
                std::wstring flags;
                for (const auto& x : p.flags) flags += (flags.empty() ? L"" : L"; ") + x;
                line(std::to_wstring(p.severity) + L"	Process	" + p.name + L" (" + std::to_wstring(p.pid) + L")	" + flags + L"	" + p.path);
            }
        } else if (cmd == L"audit") {
            SecurityAuditor auditor;
            int score = auditor.run_full_audit();
            for (const auto& [domain, d] : auditor.domain_scores()) {
                line(std::wstring(domain_name(domain)) + L"	" + std::to_wstring(d.current_score) + L"/" + std::to_wstring(d.max_score) + L"	" + d.status());
            }
            for (const auto& i : auditor.issues()) {
                line(std::wstring(risk_name(i.risk)) + L"	-" + std::to_wstring(i.score_impact) + L"	" + i.id + L"	" + i.title + L"	" + i.current_state);
            }
            line(L"Global score " + std::to_wstring(score) + L"/100");
        } else if (cmd == L"secrets") {
            bool show = o.show;   // the values are only printed when asked for
            std::map<std::wstring, std::pair<int, int>> counts;   // kind -> (items, with a readable secret)
            for (const auto& r : collect_secrets()) {
                auto& c = counts[r.kind];
                ++c.first;
                if (!r.value.empty()) ++c.second;
                line(r.kind + L"	" + r.name + L"	" + r.info + L"	" + (show ? r.value : (r.value.empty() ? L"" : L"(hidden)")) + L"	" + r.note);
            }
            for (const auto& [kind, c] : counts) line(kind + L": " + std::to_wstring(c.first) + L" item(s), " + std::to_wstring(c.second) + L" with a secret");
        } else if (cmd == L"startup") {
            for (const auto& e : collect_startup()) {
                line(e.scope + L"\t" + e.kind + L"\t" + e.name + L"\t" + (e.exists ? e.path : L"(file not found) " + e.command));
            }
        } else {
            std::fputs(USAGE, stderr);
            return 64;
        }
    } catch (const std::exception& ex) {
        std::fprintf(stderr, "Error: %s\n", ex.what());
        return 1;
    }
    return 0;
}
