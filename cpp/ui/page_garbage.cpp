// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Garbage page group: files and folders, registry leftovers and the overview of what can be freed.

#include "pages.hpp"

#include <algorithm>
#include <set>

#include <shellapi.h>

#include <ddcore/dead_registry.hpp>
#include <ddcore/garbage.hpp>
#include <ddcore/online.hpp>
#include <ddcore/registry.hpp>


using namespace dd;

namespace {

const double AGES[] = {0, 1, 7, 30};

// What the searches found: the overview reads it
std::vector<GarbageItem> g_items;
std::vector<RegEntry> g_reg;
FolderUsage g_usage;
bool g_have_usage = false;
void refresh_overview();

// region Files and folders

struct FilesPage {
    ui::Page* page = nullptr;
    HWND preset = nullptr, where = nullptr, path = nullptr, age = nullptr, permanent = nullptr, list = nullptr;
    int sort_column = -1;
    bool sort_down = true;
    std::vector<bool> checks;   // by row, kept in step with g_items
} files;

std::wstring files_summary(bool truncated) {
    std::uint64_t all = 0, likely = 0;
    for (const auto& i : g_items) {
        all += i.size;
        if (is_likely(i)) likely += i.size;
    }
    std::wstring text = std::to_wstring(g_items.size()) + L" items, " + human_size(all) + L" (" + human_size(likely) + L" counted as freeable).";
    auto groups = summarize(g_items);
    for (std::size_t i = 0; i < groups.size() && i < 3; ++i) text += (i ? L" | " : L"  Biggest: ") + groups[i].category + L" " + human_size(groups[i].bytes);
    if (truncated) text += L"  The list was cut at the limit: narrow the search.";
    return text;
}

void sync_checks() {
    int n = ui::row_count(files.list);
    files.checks.assign(g_items.size(), false);
    for (int i = 0; i < n && i < (int)g_items.size(); ++i) files.checks[i] = ui::is_checked(files.list, i);
}

void fill_files(bool truncated = false) {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& item : g_items) {
        rows.push_back({human_size(item.size), item.kind == Kind::Folder ? L"Folder" : L"File", confidence_name(item.confidence), item.path, item.reason});
    }
    ui::set_rows(files.list, rows);
    files.checks.resize(g_items.size(), false);
    for (std::size_t i = 0; i < g_items.size(); ++i) ui::set_checked(files.list, (int)i, files.checks[i]);
    files.page->set_summary(g_items.empty() ? L"Nothing found." : files_summary(truncated));
    refresh_overview();
}

void show_scan(const FileScan& scan, bool sort_by_size) {
    g_items = scan.items;
    if (sort_by_size) std::stable_sort(g_items.begin(), g_items.end(), [](const GarbageItem& a, const GarbageItem& b) { return a.size > b.size; });
    files.checks.assign(g_items.size(), false);
    files.sort_column = -1;
    fill_files(scan.truncated);
}

void sort_files(int column) {
    sync_checks();
    std::vector<std::size_t> order(g_items.size());
    for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
    files.sort_down = (column == files.sort_column) ? !files.sort_down : (column == 0);
    files.sort_column = column;
    auto less = [&](std::size_t x, std::size_t y) {
        const GarbageItem &a = g_items[x], &b = g_items[y];
        switch (column) {
            case 0: return a.size < b.size;
            case 1: return a.kind < b.kind;
            case 2: return std::wstring(confidence_name(a.confidence)) < std::wstring(confidence_name(b.confidence));
            case 3: return lower(a.path) < lower(b.path);
            default: return lower(a.reason) < lower(b.reason);
        }
    };
    std::stable_sort(order.begin(), order.end(), [&](std::size_t x, std::size_t y) { return files.sort_down ? less(y, x) : less(x, y); });
    std::vector<GarbageItem> items;
    std::vector<bool> checks;
    for (auto i : order) {
        items.push_back(g_items[i]);
        checks.push_back(files.checks[i]);
    }
    g_items = items;
    files.checks = checks;
    fill_files();
}

void tick_files(const std::function<bool(const GarbageItem&)>& wanted) {
    sync_checks();
    for (std::size_t i = 0; i < g_items.size(); ++i) {
        files.checks[i] = wanted(g_items[i]);
        ui::set_checked(files.list, (int)i, files.checks[i]);
    }
}

double chosen_age() {
    int i = ui::combo_index(files.age);
    return AGES[i < 0 ? 0 : i];
}

std::wstring patterns_of_preset(const std::wstring& typed) {
    std::wstring text = trim(typed);
    for (const auto& p : presets()) {
        if (lower(p.name) == lower(text)) return p.patterns;
    }
    return text;
}

Where chosen_where() {
    int w = ui::combo_index(files.where);
    return w == 1 ? Where::AppData : w == 2 ? Where::Drives : w == 3 ? Where::Custom : Where::Profile;
}

void do_search() {
    std::wstring patterns = patterns_of_preset(ui::get_text(files.preset));
    Where w = chosen_where();
    std::wstring custom = ui::trimmed(files.path);
    if (w == Where::Custom && !is_dir(custom)) {
        ui::warn(L"Choose an existing folder (Browse...).");
        return;
    }
    double age = chosen_age();
    try {
        Matcher check(patterns);   // empty or invalid text is reported before anything starts
    } catch (const std::exception& e) {
        ui::warn(wide(e.what()));
        return;
    }
    ui::run_async(L"Searching...", [=](const Stop& stop, const Progress& progress) {
        auto roots = search_roots(w, custom);
        FileScan scan = search_files(patterns, roots, stop, progress, SEARCH_LIMIT, age);
        return [scan] { show_scan(scan, true); };
    });
}

void do_leftovers() {
    double age = chosen_age();
    ui::run_async(L"Looking for the leftovers of programs that are no longer installed...", [=](const Stop& stop, const Progress& progress) {
        progress(L"Reading the installed programs...");
        auto markers = installed_markers();
        FileScan scan = find_leftovers(markers, stop, progress, nullptr, -1, age);
        return [scan] { show_scan(scan, false); };
    });
}

void show_registry(const std::vector<RegEntry>& entries, bool truncated);

// Every file preset and the leftovers, then every registry preset
void do_scan_all() {
    Where w = chosen_where();
    std::wstring custom = ui::trimmed(files.path);
    if (w == Where::Custom && !is_dir(custom)) {
        ui::warn(L"Choose an existing folder (Browse...).");
        return;
    }
    double age = chosen_age();
    ui::run_async(L"Scan all: files, folders and registry...", [=](const Stop& stop, const Progress& progress) {
        std::wstring patterns;
        for (const auto& p : presets()) patterns += (patterns.empty() ? std::wstring() : std::wstring(L";")) + p.patterns;
        FileScan found = search_files(patterns, search_roots(w, custom), stop, progress, SEARCH_LIMIT, age);
        FileScan merged = found;
        if (!stop()) {
            progress(L"Looking for leftovers of uninstalled programs...");
            merged = merge_scans(found, find_leftovers(installed_markers(), stop, progress, nullptr, -1, age));
        }
        RegScan reg;
        if (!stop()) {
            std::vector<std::wstring> ids;
            for (const auto& p : reg_presets()) ids.push_back(p.id);
            progress(L"Scan all: registry...");
            reg = scan_presets(ids, stop, progress);
        }
        return [merged, reg] {
            show_scan(merged, true);
            show_registry(reg.entries, reg.truncated);
            std::uint64_t likely = 0;
            for (const auto& i : g_items) {
                if (is_likely(i)) likely += i.size;
            }
            ui::set_status(L"Scan all done: " + human_size(likely) + L" of garbage on disk, " + std::to_wstring(g_reg.size()) + L" registry entries.");
        };
    });
}

void do_delete_files() {
    sync_checks();
    std::vector<GarbageItem> chosen;
    std::uint64_t bytes = 0;
    std::size_t low = 0;
    for (std::size_t i = 0; i < g_items.size(); ++i) {
        if (!files.checks[i]) continue;
        chosen.push_back(g_items[i]);
        bytes += g_items[i].size;
        if (g_items[i].confidence == Confidence::Low) ++low;
    }
    if (chosen.empty()) {
        ui::info(L"Tick the items to delete first.");
        return;
    }
    bool permanent = ui::checked(files.permanent);
    std::wstring ask = permanent ? L"Delete " + std::to_wstring(chosen.size()) + L" items (" + human_size(bytes) +
                                       L") PERMANENTLY?\nThey will not go to the Recycle Bin and cannot be recovered."
                                 : L"Send " + std::to_wstring(chosen.size()) + L" items (" + human_size(bytes) + L") to the Recycle Bin?";
    if (low) ask += L"\n\n" + std::to_wstring(low) + L" of them are low-confidence leftovers: they may be portable tools or programs in use. Check them first.";
    if (!ui::confirm(ask, L"Delete the ticked items", permanent)) return;
    ui::run_async(L"Deleting...", [=](const Stop& stop, const Progress&) {
        DeleteResult r = delete_items(chosen, permanent, stop);
        return [r] {
            std::set<std::wstring> gone;
            for (const auto& item : r.deleted) gone.insert(normcase(item.path));
            sync_checks();
            std::vector<GarbageItem> items;
            std::vector<bool> checks;
            for (std::size_t i = 0; i < g_items.size(); ++i) {
                if (gone.count(normcase(g_items[i].path))) continue;
                items.push_back(g_items[i]);
                checks.push_back(files.checks[i]);
            }
            g_items = items;
            files.checks = checks;
            fill_files();
            record_garbage_stat((long long)r.freed, (long long)r.deleted.size(), 0);
            files.page->set_summary(L"Deleted " + std::to_wstring(r.deleted.size()) + L" items, freed " + human_size(r.freed) + L". " + files.page->summary());
            if (!r.failed.empty()) {
                std::wstring text = std::to_wstring(r.failed.size()) + L" items could not be deleted:\n\n";
                for (std::size_t i = 0; i < r.failed.size() && i < 12; ++i) text += r.failed[i].first.path + L"\n    " + r.failed[i].second + L"\n";
                if (r.failed.size() > 12) text += L"...";
                ui::warn(text);
            }
        };
    });
}

void build_files() {
    ui::Page& p = ui::add_page(L"Garbage", L"Files and folders");
    files.page = &p;
    p.label(L"Search:", 50);
    files.preset = p.combo({}, -1, 300, true);
    for (const auto& pr : presets()) SendMessageW(files.preset, CB_ADDSTRING, 0, (LPARAM)pr.name);
    ComboBox_SetCurSel(files.preset, 0);
    p.label(L"In:", 24);
    files.where = p.combo({L"My profile", L"AppData and temp", L"All fixed drives", L"Folder:"}, 0, 160);
    files.path = p.edit(L"", 0);
    p.button(L"Browse...", [] {
        std::wstring dir = ui::choose_folder(L"Folder to search");
        if (dir.empty()) return;
        SetWindowTextW(files.path, dir.c_str());
        ComboBox_SetCurSel(files.where, 3);
    }, 84, false);
    p.newline();
    p.button(L"Search", do_search, 90);
    p.button(L"Find leftovers", do_leftovers, 120);
    p.button(L"Scan all", do_scan_all, 90);
    p.label(L"Older than:", 70);
    files.age = p.combo({L"Any age", L"1 day", L"7 days", L"30 days"}, 0, 120);
    p.button(L"Tick likely", [] { tick_files([](const GarbageItem& i) { return is_likely(i); }); }, 90, false);
    p.button(L"Tick all", [] { tick_files([](const GarbageItem&) { return true; }); }, 80, false);
    p.button(L"Untick all", [] { tick_files([](const GarbageItem&) { return false; }); }, 90, false);
    p.newline();
    files.permanent = p.check(L"Delete permanently (no Recycle Bin)", 260);
    p.button(L"Open location", [] {
        auto rows = ui::selected_rows(files.list);
        if (!rows.empty() && rows[0] < (int)g_items.size()) ui::reveal(g_items[rows[0]].path);
    }, 110, false);
    p.button(L"Export", [] { ui::export_list(files.list, L"garbage_files.csv"); }, 80, false);
    p.button(L"Delete ticked...", do_delete_files, 150, true, true);
    ui::ListEvents ev;
    ev.on_column = sort_files;
    ev.on_activate = [](int row) {
        if (row < (int)g_items.size()) ui::reveal(g_items[row].path);
    };
    files.list = p.list({{L"Size", 80, true}, {L"Kind", 60}, {L"Confidence", 80}, {L"Path", 520}, {L"Reason", 320}}, 3, true, ev);
    p.on_refresh = do_search;
    p.set_summary(L"Pick a preset or type a pattern (*.tmp, a word, \"exact name\"), then Search. Nothing is deleted until you tick items and confirm.");
}

// endregion

// region Registry

struct RegPage {
    ui::Page* page = nullptr;
    HWND pattern = nullptr, names = nullptr, value_names = nullptr, value_data = nullptr, list = nullptr;
    std::vector<bool> checks;
} reg;

void sync_reg_checks() {
    int n = ui::row_count(reg.list);
    reg.checks.assign(g_reg.size(), false);
    for (int i = 0; i < n && i < (int)g_reg.size(); ++i) reg.checks[i] = ui::is_checked(reg.list, i);
}

void fill_reg() {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& e : g_reg) {
        rows.push_back({e.category, e.location(), e.is_key ? L"(key)" : (e.value.empty() ? L"(default)" : e.value), e.reason, e.confidence, e.data});
    }
    ui::set_rows(reg.list, rows);
    reg.checks.resize(g_reg.size(), false);
    for (std::size_t i = 0; i < g_reg.size(); ++i) ui::set_checked(reg.list, (int)i, reg.checks[i]);
    refresh_overview();
}

void show_registry(const std::vector<RegEntry>& entries, bool truncated) {
    g_reg = entries;
    reg.checks.assign(g_reg.size(), false);
    fill_reg();
    reg.page->set_summary(std::to_wstring(entries.size()) + L" entries." + (truncated ? L" The list was cut at the limit: narrow the search." : L"") +
                          L" Nothing was changed: tick what to delete.");
}

void do_reg_search() {
    std::wstring patterns = ui::trimmed(reg.pattern);
    if (patterns.empty()) {
        ui::info(L"Type a word or a wildcard to search the registry for.");
        return;
    }
    bool n = ui::checked(reg.names), vn = ui::checked(reg.value_names), vd = ui::checked(reg.value_data);
    if (!n && !vn && !vd) {
        ui::info(L"Tick at least one of: key names, value names, value data.");
        return;
    }
    try {
        Matcher check(patterns);
    } catch (const std::exception& e) {
        ui::warn(wide(e.what()));
        return;
    }
    ui::run_async(L"Searching the registry...", [=](const Stop& stop, const Progress& progress) {
        RegScan scan = search_registry(patterns, n, vn, vd, stop, progress);
        return [scan] { show_registry(scan.entries, scan.truncated); };
    });
}

void do_reg_presets(bool all) {
    std::vector<std::wstring> ids;
    if (all) {
        for (const auto& p : reg_presets()) ids.push_back(p.id);
    } else {
        ui::DialogSpec spec;
        spec.title = L"Registry presets";
        spec.prompt = L"Tick what to look for. Safe: entries of programs that are gone. Check and Review: guesses, look before ticking.";
        spec.body = ui::DialogSpec::List;
        spec.columns = {{L"Preset", 220}, {L"Risk", 60}, {L"What it finds", 360}};
        spec.checks = true;
        for (const auto& p : reg_presets()) {
            spec.rows.push_back({p.label, p.risk, p.description});
            spec.checked.push_back(p.risk == L"Safe");
        }
        spec.buttons = {{L"Scan", 1}, {L"Cancel", 0}};
        auto r = ui::run_dialog(spec);
        if (r.button != 1) return;
        for (std::size_t i = 0; i < r.checked.size() && i < reg_presets().size(); ++i) {
            if (r.checked[i]) ids.push_back(reg_presets()[i].id);
        }
        if (ids.empty()) return;
    }
    ui::run_async(L"Looking at the registry...", [ids](const Stop& stop, const Progress& progress) {
        RegScan scan = scan_presets(ids, stop, progress);
        return [scan] { show_registry(scan.entries, scan.truncated); };
    });
}

void tick_reg(const std::function<bool(const RegEntry&)>& wanted) {
    sync_reg_checks();
    for (std::size_t i = 0; i < g_reg.size(); ++i) {
        reg.checks[i] = wanted(g_reg[i]);
        ui::set_checked(reg.list, (int)i, reg.checks[i]);
    }
}

std::wstring backups_folder() {
    std::wstring folder = data_subdir(L"garbage_backups");
    make_dirs(folder);
    return folder;
}

void do_reg_delete() {
    sync_reg_checks();
    std::vector<RegEntry> chosen;
    std::vector<std::wstring> refused;
    for (std::size_t i = 0; i < g_reg.size(); ++i) {
        if (!reg.checks[i]) continue;
        std::wstring why = registry_protected_reason(g_reg[i]);
        if (why.empty()) chosen.push_back(g_reg[i]);
        else refused.push_back(g_reg[i].location() + L": " + why);
    }
    if (chosen.empty()) {
        ui::info(refused.empty() ? L"Tick the entries to delete first." : L"None of the ticked entries can be deleted from here:\n\n" + refused[0]);
        return;
    }
    std::wstring ask = L"Delete " + std::to_wstring(chosen.size()) + L" registry entries?\n\nEach key is saved to a .reg file first (double-click it to put the key back). "
                       L"An entry whose backup fails is left alone.";
    if (!refused.empty()) ask += L"\n\n" + std::to_wstring(refused.size()) + L" ticked entries are protected and will be skipped.";
    for (const auto& e : chosen) {
        if (e.confidence == L"Medium" || e.confidence == L"High") {
            ask += L"\n\nSome entries are guesses (see the Confidence column): look at them before you continue.";
            break;
        }
    }
    if (!ui::confirm(ask, L"Delete the ticked registry entries", true)) return;
    ui::run_async(L"Deleting registry entries...", [=](const Stop& stop, const Progress&) {
        RegDeleteResult r = delete_entries(chosen, L"", stop);
        return [r] {
            std::set<std::wstring> gone;
            auto id = [](const RegEntry& e) { return lower(e.location() + L"|" + (e.is_key ? L"" : e.value) + L"|" + (e.is_key ? L"k" : L"v")); };
            for (const auto& e : r.deleted) gone.insert(id(e));
            sync_reg_checks();
            std::vector<RegEntry> keep;
            std::vector<bool> checks;
            for (std::size_t i = 0; i < g_reg.size(); ++i) {
                if (gone.count(id(g_reg[i]))) continue;
                keep.push_back(g_reg[i]);
                checks.push_back(reg.checks[i]);
            }
            g_reg = keep;
            reg.checks = checks;
            fill_reg();
            record_garbage_stat(0, 0, (long long)r.deleted.size());
            reg.page->set_summary(std::to_wstring(r.deleted.size()) + L" deleted, " + std::to_wstring(r.backups.size()) + L" backup file(s). " + std::to_wstring(g_reg.size()) + L" entries left in the list.");
            if (!r.failed.empty()) {
                std::wstring text = std::to_wstring(r.failed.size()) + L" entries could not be deleted:\n\n";
                for (std::size_t i = 0; i < r.failed.size() && i < 12; ++i) text += r.failed[i].first.location() + L": " + r.failed[i].second + L"\n";
                ui::warn(text);
            }
        };
    });
}

// Regedit opens on the last key it showed: point it at the selected entry
void open_in_regedit() {
    auto rows = ui::selected_rows(reg.list);
    if (rows.empty() || rows[0] >= (int)g_reg.size()) {
        ui::info(L"Select an entry first.");
        return;
    }
    const RegEntry& e = g_reg[rows[0]];
    std::wstring last = std::wstring(e.hive == L"HKLM" ? L"Computer\\HKEY_LOCAL_MACHINE\\" : L"Computer\\HKEY_CURRENT_USER\\") + e.key;
    HKEY k = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Applets\\Regedit", 0, nullptr, 0, KEY_SET_VALUE, nullptr, &k, nullptr) == ERROR_SUCCESS) {
        RegSetValueExW(k, L"LastKey", 0, REG_SZ, (const BYTE*)last.c_str(), (DWORD)((last.size() + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
    }
    ShellExecuteW(ui::main_window(), L"open", sys_exe(L"regedit.exe").c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void build_registry() {
    ui::Page& p = ui::add_page(L"Garbage", L"Registry");
    reg.page = &p;
    p.label(L"Search:", 50);
    reg.pattern = p.edit(L"", 0);
    reg.names = p.check(L"Key names", 100, true);
    reg.value_names = p.check(L"Value names", 110, true);
    reg.value_data = p.check(L"Value data", 100, true);
    p.button(L"Search", do_reg_search, 90);
    p.newline();
    p.button(L"Scan presets...", [] { do_reg_presets(false); }, 130);
    p.button(L"Scan all presets", [] { do_reg_presets(true); }, 130);
    p.button(L"Tick high confidence", [] { tick_reg([](const RegEntry& e) { return e.confidence.empty() || e.confidence == L"High"; }); }, 150, false);
    p.button(L"Tick all", [] { tick_reg([](const RegEntry&) { return true; }); }, 80, false);
    p.button(L"Untick all", [] { tick_reg([](const RegEntry&) { return false; }); }, 90, false);
    p.newline();
    p.button(L"Backups", [] { ui::reveal(backups_folder()); }, 80, false);
    p.button(L"Open in Regedit", open_in_regedit, 130, false);
    p.button(L"Export", [] { ui::export_list(reg.list, L"registry_entries.csv"); }, 80, false);
    p.button(L"Delete ticked...", do_reg_delete, 150, true, true);
    ui::ListEvents ev;
    reg.list = p.list({{L"Category", 150}, {L"Location", 360}, {L"Value", 140}, {L"Reason", 300}, {L"Confidence", 80}, {L"Data", 260}}, 3, true, ev);
    p.on_refresh = [] { do_reg_presets(true); };
    p.set_summary(L"Search the registry by word, or scan the presets for entries of programs that are gone. A key is saved to a .reg file before it is deleted.");
}

// endregion

// region Overview

struct OverviewPage {
    ui::Page* page = nullptr;
    HWND drive = nullptr, disks = nullptr, kinds = nullptr, biggest = nullptr, registry = nullptr, freed = nullptr, folders = nullptr;
} ov;

std::wstring bar(double fraction, int width = 24) { return bar_text(fraction, width); }

void refresh_overview() {
    if (!ov.page) return;
    auto usage = drive_usage(fixed_drives());
    std::vector<GarbageItem> likely;
    for (const auto& i : g_items) {
        if (is_likely(i)) likely.push_back(i);
    }
    auto per_drive = size_by_drive(likely);

    std::wstring current = ui::combo_text(ov.drive);
    SendMessageW(ov.drive, CB_RESETCONTENT, 0, 0);
    for (const auto& u : usage) SendMessageW(ov.drive, CB_ADDSTRING, 0, (LPARAM)u.root.c_str());
    int at = (int)SendMessageW(ov.drive, CB_FINDSTRINGEXACT, (WPARAM)-1, (LPARAM)current.c_str());
    ComboBox_SetCurSel(ov.drive, at >= 0 ? at : 0);

    std::vector<std::vector<std::wstring>> rows;
    for (const auto& u : usage) {
        std::wstring letter = u.root.substr(0, 2);
        for (auto& c : letter) c = (wchar_t)towupper(c);
        std::uint64_t junk = std::min<std::uint64_t>(per_drive.count(letter) ? per_drive[letter] : 0, u.used);
        rows.push_back({u.root, bar(u.total ? (double)u.used / u.total : 0), human_size(u.used), human_size(u.free), human_size(u.total), junk ? human_size(junk) : L""});
    }
    ui::set_rows(ov.disks, rows);

    rows.clear();
    std::uint64_t top = 1;
    auto groups = summarize(g_items);
    for (const auto& g : groups) top = std::max<std::uint64_t>(top, g.bytes);
    for (std::size_t i = 0; i < groups.size() && i < 12; ++i) rows.push_back({groups[i].category, bar((double)groups[i].bytes / top), human_size(groups[i].bytes), std::to_wstring(groups[i].count)});
    ui::set_rows(ov.kinds, rows);

    rows.clear();
    std::sort(likely.begin(), likely.end(), [](const GarbageItem& a, const GarbageItem& b) { return a.size > b.size; });
    std::uint64_t big = likely.empty() ? 1 : std::max<std::uint64_t>(1, likely[0].size);
    for (std::size_t i = 0; i < likely.size() && i < 12; ++i) rows.push_back({base_name(likely[i].path), bar((double)likely[i].size / big), human_size(likely[i].size), likely[i].path});
    ui::set_rows(ov.biggest, rows);

    std::map<std::wstring, int> counts;
    for (const auto& e : g_reg) ++counts[e.category];
    std::vector<std::pair<std::wstring, int>> sorted(counts.begin(), counts.end());
    std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    rows.clear();
    for (std::size_t i = 0; i < sorted.size() && i < 12; ++i) rows.push_back({sorted[i].first, bar((double)sorted[i].second / sorted[0].second), std::to_wstring(sorted[i].second)});
    ui::set_rows(ov.registry, rows);

    auto entries = load_garbage_stats();
    auto totals = garbage_totals(entries);
    auto days = garbage_per_day(entries);
    rows.clear();
    long long most = 1, in30 = 0;
    for (const auto& d : days) {
        most = std::max(most, d.second);
        in30 += d.second;
    }
    for (auto it = days.rbegin(); it != days.rend(); ++it) {
        if (it->second > 0) rows.push_back({it->first, bar((double)it->second / most), human_size((std::uint64_t)it->second)});
    }
    ui::set_rows(ov.freed, rows);

    rows.clear();
    if (g_have_usage) {
        std::uint64_t most_folder = g_usage.folders.empty() ? 1 : std::max<std::uint64_t>(1, g_usage.folders[0].second);
        for (std::size_t i = 0; i < g_usage.folders.size() && i < 40; ++i)
            rows.push_back({base_name(g_usage.folders[i].first), bar((double)g_usage.folders[i].second / most_folder), human_size(g_usage.folders[i].second)});
    }
    ui::set_rows(ov.folders, rows);

    std::uint64_t found = 0, unsure = 0;
    for (const auto& i : g_items) (is_likely(i) ? found : unsure) += i.size;
    ov.page->set_summary(L"Garbage found: " + human_size(found) + L" in " + std::to_wstring(likely.size()) + L" item(s)" +
                         (unsure ? L" (+ " + human_size(unsure) + L" of low-confidence folders, not counted)" : L"") + L"   |   Registry: " + std::to_wstring(g_reg.size()) +
                         L" entries   |   Freed so far: " + human_size((std::uint64_t)totals.bytes) + L" (" + std::to_wstring(totals.files) + L" item(s), " + std::to_wstring(totals.registry) +
                         L" registry entries), " + human_size((std::uint64_t)in30) + L" in 30 days.");
}

void measure_folders() {
    std::wstring root = ui::combo_text(ov.drive);
    if (root.empty()) {
        ui::info(L"No drive to measure.");
        return;
    }
    ui::run_async(L"Measuring the folders of " + root + L"...", [=](const Stop& stop, const Progress& progress) {
        FolderUsage usage = folder_usage(root, stop, progress);
        return [usage] {
            g_usage = usage;
            g_have_usage = true;
            refresh_overview();
            ui::set_status(usage.truncated ? L"Measure stopped." : L"Folders measured.");
        };
    });
}

void build_overview() {
    ui::Page& p = ui::add_page(L"Garbage", L"Overview");
    ov.page = &p;
    p.button(L"Refresh", refresh_overview, 80, false);
    p.label(L"Measure the folders of:", 150);
    ov.drive = p.combo({}, -1, 100);
    p.button(L"Measure", measure_folders, 90);
    p.label(L"The charts show what the searches in the other two pages found, and what has been freed since you started using them.", ui::FILL);
    ov.disks = p.list({{L"Drive", 70}, {L"Usage", 220}, {L"Used", 90, true}, {L"Free", 90, true}, {L"Total", 90, true}, {L"Garbage found", 110, true}}, 2);
    ov.kinds = p.list({{L"Garbage found, by kind", 260}, {L"", 220}, {L"Size", 90, true}, {L"Items", 60, true}}, 3);
    ov.biggest = p.list({{L"Biggest items found", 260}, {L"", 220}, {L"Size", 90, true}, {L"Path", 520}}, 3);
    ov.registry = p.list({{L"Registry entries, by kind", 260}, {L"", 220}, {L"Entries", 70, true}}, 2);
    ov.freed = p.list({{L"Space freed, last 30 days", 260}, {L"", 220}, {L"Freed", 90, true}}, 2);
    ov.folders = p.list({{L"Folders at the root of the drive", 260}, {L"", 220}, {L"Size", 90, true}}, 3);
    p.on_refresh = refresh_overview;
    p.on_show = refresh_overview;
}

// endregion

}  // namespace

void build_garbage_pages() {
    build_files();
    build_registry();
    build_overview();
}
