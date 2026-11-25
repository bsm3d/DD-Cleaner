// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Threat hunt page group: running processes, persistence entries with their removal, and the protection settings.

#include "pages.hpp"

#include <algorithm>
#include <memory>
#include <set>

#include <ddcore/antivirus.hpp>
#include <ddcore/threat.hpp>

using namespace dd;

namespace {

std::wstring severity_text(int s) { return s >= SEV_SUSPICIOUS ? L"\U0001F534 Suspicious" : s == SEV_LOOK ? L"\U0001F7E0 Look at it" : L"✅ Ordinary"; }

std::wstring flags_text(const std::vector<std::wstring>& flags) {
    std::wstring out;
    for (const auto& f : flags) out += (out.empty() ? L"" : L"; ") + f;
    return out;
}

// region Processes

struct ProcPage {
    ui::Page* page = nullptr;
    HWND list = nullptr, only_flagged = nullptr;
    std::vector<ProcessFinding> all, shown;
} proc;

void fill_processes() {
    bool only = ui::checked(proc.only_flagged);
    proc.shown.clear();
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& p : proc.all) {
        // a hidden path alone leaves a process "Ordinary": only the two upper verdicts are worth a look
        if (only && p.severity < SEV_LOOK) continue;
        proc.shown.push_back(p);
        rows.push_back({severity_text(p.severity), p.name, std::to_wstring(p.pid), p.connections ? std::to_wstring(p.connections) : L"", p.signer, flags_text(p.flags), p.path});
    }
    ui::set_rows(proc.list, rows);
    int suspicious = 0, look = 0;
    for (const auto& p : proc.all) {
        suspicious += p.severity >= SEV_SUSPICIOUS;
        look += p.severity == SEV_LOOK;
    }
    proc.page->set_summary(std::to_wstring(proc.all.size()) + L" processes, " + std::to_wstring(suspicious) + L" suspicious, " + std::to_wstring(look) + L" to look at. A flag is a reason to look, not a verdict.");
}

void run_processes() {
    ui::run_async(L"Looking at the running processes...", [](const Stop& stop, const Progress& progress) {
        auto found = scan_processes(stop, progress);
        std::stable_sort(found.begin(), found.end(), [](const ProcessFinding& a, const ProcessFinding& b) { return a.severity > b.severity; });
        return [found] {
            proc.all = found;
            fill_processes();
        };
    });
}

std::vector<std::wstring> selected_process_paths() {
    std::vector<std::wstring> out;
    for (int r : ui::selected_rows(proc.list)) {
        if (r < (int)proc.shown.size() && !proc.shown[r].path.empty()) out.push_back(proc.shown[r].path);
    }
    return out;
}

void build_processes() {
    ui::Page& p = ui::add_page(L"Threat hunt", L"Processes");
    proc.page = &p;
    p.button(L"List running processes", run_processes, 190);
    p.button(L"Scan with ClamAV", [] {
        auto paths = selected_process_paths();
        if (paths.empty()) ui::info(L"Select the processes to scan.");
        else scan_with_clamav(paths);
    }, 150);
    p.button(L"Open location", [] {
        auto paths = selected_process_paths();
        if (!paths.empty()) ui::reveal(paths[0]);
    }, 110, false);
    p.button(L"VirusTotal", [] {
        auto paths = selected_process_paths();
        if (paths.empty()) ui::info(L"Select a process first.");
        else virustotal_lookup(paths[0]);
    }, 110);
    p.button(L"Export", [] { ui::export_list(proc.list, L"processes.csv"); }, 80, false);
    proc.only_flagged = p.check(L"Only the ones to look at", 220, true);
    p.on_change(proc.only_flagged, fill_processes);
    ui::ListEvents ev;
    ev.on_activate = [](int row) {
        if (row < (int)proc.shown.size()) ui::reveal(proc.shown[row].path);
    };
    proc.list = p.list({{L"Verdict", 120}, {L"Process", 170}, {L"PID", 60, true}, {L"Internet", 70, true}, {L"Signer", 200}, {L"Why", 330}, {L"Path", 420}}, 4, false, ev);
    p.on_refresh = run_processes;
    p.set_summary(L"Reads the running processes: unsigned programs, odd folders, look-alike names, programs talking to the Internet. Nothing is changed.");
}

// endregion

// region Persistence

struct PersistPage {
    ui::Page* page = nullptr;
    HWND list = nullptr;
    std::vector<HuntFinding> findings;
} persist;

void fill_persistence() {
    std::vector<std::vector<std::wstring>> rows;
    int suspicious = 0, look = 0;
    for (const auto& f : persist.findings) {
        rows.push_back({severity_text(f.severity), f.category, f.title, f.detail, f.location, flags_text(f.flags), f.path});
        suspicious += f.severity >= SEV_SUSPICIOUS;
        look += f.severity == SEV_LOOK;
    }
    ui::set_rows(persist.list, rows);
    for (std::size_t i = 0; i < persist.findings.size(); ++i) ui::set_checked(persist.list, (int)i, false);
    persist.page->set_summary(std::to_wstring(persist.findings.size()) + L" entries, " + std::to_wstring(suspicious) + L" suspicious, " + std::to_wstring(look) + L" to look at.");
}

void run_persistence() {
    ui::run_async(L"Hunting for persistence (services, tasks, hijacked keys, WMI, hosts, proxy, extensions)...", [](const Stop& stop, const Progress& progress) {
        auto found = collect_persistence(stop, progress);
        std::stable_sort(found.begin(), found.end(), [](const HuntFinding& a, const HuntFinding& b) { return a.severity > b.severity; });
        return [found] {
            persist.findings = found;
            fill_persistence();
        };
    });
}

std::vector<std::wstring> selected_persist_paths() {
    std::vector<std::wstring> out;
    for (int r : ui::selected_rows(persist.list)) {
        if (r < (int)persist.findings.size() && !persist.findings[r].path.empty()) out.push_back(persist.findings[r].path);
    }
    return out;
}

void remove_persistence() {
    std::vector<HuntFinding> chosen;
    int not_removable = 0;
    for (std::size_t i = 0; i < persist.findings.size(); ++i) {
        if (!ui::is_checked(persist.list, (int)i)) continue;
        if (removable(persist.findings[i])) chosen.push_back(persist.findings[i]);
        else ++not_removable;
    }
    if (chosen.empty()) {
        ui::info(not_removable ? L"None of the ticked entries can be removed from here (this program only offers to remove tasks, services and Run-type values)." : L"Tick the entries to remove first.");
        return;
    }
    if (!ui::elevated()) {
        ui::warn(L"Removing these entries needs administrator rights.\nRestart the application as administrator.");
        return;
    }
    std::wstring ask = L"Remove " + std::to_wstring(chosen.size()) + L" entries?\n\n";
    for (std::size_t i = 0; i < chosen.size() && i < 10; ++i) ask += L"• " + describe(chosen[i]) + L"\n";
    if (chosen.size() > 10) ask += L"... and " + std::to_wstring(chosen.size() - 10) + L" more\n";
    ask += L"\nA backup is made first (a task as XML, a service key or a value's key as .reg). If the backup fails the entry is left alone.";
    if (not_removable) ask += L"\n\n" + std::to_wstring(not_removable) + L" ticked entries are not removable here and are skipped.";
    if (!ui::confirm(ask, L"Remove the ticked entries", true)) return;
    ui::run_async(L"Removing entries...", [chosen](const Stop& stop, const Progress&) {
        HuntRemovalResult r = remove_findings(chosen, L"", stop);
        return [r] {
            std::set<std::wstring> gone;
            auto id = [](const HuntFinding& f) { return lower(f.category + L"|" + f.title + L"|" + f.location + L"|" + f.path); };
            for (const auto& f : r.removed) gone.insert(id(f));
            std::vector<HuntFinding> keep;
            for (const auto& f : persist.findings) {
                if (!gone.count(id(f))) keep.push_back(f);
            }
            persist.findings = keep;
            fill_persistence();
            std::wstring text = std::to_wstring(r.removed.size()) + L" removed, " + std::to_wstring(r.backups.size()) + L" backup(s).";
            if (r.reboot) text += L" A reboot finishes removing a running service.";
            ui::set_status(text);
            if (!r.failed.empty()) {
                std::wstring lines = std::to_wstring(r.failed.size()) + L" entries could not be removed:\n\n";
                for (const auto& f : r.failed) lines += f.first.title + L": " + f.second + L"\n";
                ui::warn(lines);
            } else {
                ui::info(text);
            }
        };
    });
}

void build_persistence() {
    ui::Page& p = ui::add_page(L"Threat hunt", L"Persistence");
    persist.page = &p;
    p.button(L"Hunt for persistence", run_persistence, 170);
    p.button(L"Scan with ClamAV", [] {
        auto paths = selected_persist_paths();
        if (paths.empty()) ui::info(L"Select the entries to scan.");
        else scan_with_clamav(paths);
    }, 150);
    p.button(L"Open location", [] {
        auto paths = selected_persist_paths();
        if (!paths.empty()) ui::reveal(paths[0]);
    }, 110, false);
    p.button(L"VirusTotal", [] {
        auto paths = selected_persist_paths();
        if (paths.empty()) ui::info(L"Select an entry that has a program file.");
        else virustotal_lookup(paths[0]);
    }, 110);
    p.button(L"Export", [] { ui::export_list(persist.list, L"persistence.csv"); }, 80, false);
    p.button(L"Backups", [] { ui::reveal(data_subdir(L"hunt_backups")); }, 80, false);
    p.button(L"Remove ticked entries...", remove_persistence, 190, true, true);
    ui::ListEvents ev;
    ev.on_activate = [](int row) {
        if (row < (int)persist.findings.size()) ui::reveal(persist.findings[row].path);
    };
    persist.list = p.list({{L"Verdict", 120}, {L"Category", 130}, {L"Entry", 220}, {L"Detail", 300}, {L"Registered at", 280}, {L"Why", 260}, {L"Program", 380}}, 4, true, ev);
    p.on_refresh = run_persistence;
    p.set_summary(L"Where malware keeps itself alive: services, tasks, hijacked keys, WMI subscriptions, hosts file, proxy, browser extensions. Reading changes nothing.");
}

// endregion

// region Protection (watched folders, schedule, YARA rules)

struct ProtectionPage {
    ui::Page* page = nullptr;
    HWND enabled = nullptr, folders = nullptr, schedule = nullptr, rules = nullptr;
    ProtectionSettings settings;
    std::unique_ptr<FolderWatcher> watcher;
    std::vector<std::wstring> waiting;   // new files not scanned yet (a scan was busy)
} prot;

void save_settings() {
    std::wstring error = save_protection_settings(prot.settings);
    if (!error.empty()) ui::warn(L"The settings could not be saved:\n" + error);
}

void restart_watcher() {
    prot.watcher.reset();
    if (prot.settings.watch_enabled && !prot.settings.folders.empty()) {
        prot.watcher = std::make_unique<FolderWatcher>(prot.settings.folders);
        prot.watcher->prime();
    }
}

void fill_protection() {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& f : prot.settings.folders) rows.push_back({f});
    ui::set_rows(prot.folders, rows);
    rows.clear();
    for (const auto& r : list_rule_files()) rows.push_back({r});
    ui::set_rows(prot.rules, rows);
    Button_SetCheck(prot.enabled, prot.settings.watch_enabled ? BST_CHECKED : BST_UNCHECKED);
    static const int hours[] = {0, 1, 4, 8, 12, 24};
    int sel = 0;
    for (int i = 0; i < 6; ++i) {
        if (hours[i] == prot.settings.scan_hours) sel = i;
    }
    ComboBox_SetCurSel(prot.schedule, sel);
}

void watch_tick() {
    if (!prot.watcher) return;
    auto fresh = prot.watcher->poll();
    prot.waiting.insert(prot.waiting.end(), fresh.begin(), fresh.end());
    if (prot.waiting.empty() || ui::busy()) return;
    auto paths = prot.waiting;
    prot.waiting.clear();
    ui::set_status(std::to_wstring(paths.size()) + L" new file(s) in a watched folder: scanning...");
    scan_with_clamav(paths);
}

void schedule_tick() {
    if (!scan_is_due(prot.settings) || ui::busy()) return;
    prot.settings.last_quick_scan = (double)time(nullptr);
    save_settings();
    std::vector<std::wstring> targets;
    for (const wchar_t* var : {L"USERPROFILE"}) {
        std::wstring profile = env_var(var);
        if (!profile.empty()) {
            targets.push_back(join(profile, L"Downloads"));
            targets.push_back(join(profile, L"Desktop"));
        }
    }
    targets.push_back(temp_dir());
    std::vector<std::wstring> existing;
    for (const auto& t : targets) {
        if (is_dir(t)) existing.push_back(t);
    }
    if (!existing.empty()) scan_with_clamav(existing);
}

void build_protection() {
    ui::Page& p = ui::add_page(L"Threat hunt", L"Protection");
    prot.page = &p;
    prot.settings = load_protection_settings();
    prot.enabled = p.check(L"Scan new files automatically in these folders (while the program is open)", 520);
    p.on_change(prot.enabled, [] {
        prot.settings.watch_enabled = ui::checked(prot.enabled);
        save_settings();
        restart_watcher();
    });
    p.button(L"Add folder...", [] {
        std::wstring dir = ui::choose_folder(L"Folder to watch");
        if (dir.empty()) return;
        if (std::find(prot.settings.folders.begin(), prot.settings.folders.end(), dir) == prot.settings.folders.end()) prot.settings.folders.push_back(dir);
        save_settings();
        fill_protection();
        restart_watcher();
    }, 120, false);
    p.button(L"Drop folder", [] {
        auto rows = ui::selected_rows(prot.folders);
        std::sort(rows.rbegin(), rows.rend());
        for (int r : rows) {
            if (r < (int)prot.settings.folders.size()) prot.settings.folders.erase(prot.settings.folders.begin() + r);
        }
        save_settings();
        fill_protection();
        restart_watcher();
    }, 80, false);
    prot.folders = p.list({{L"Watched folders", 700}}, 2);
    p.label(L"Quick scan (Downloads, Desktop, temp) every:", 300);
    prot.schedule = p.combo({L"Never", L"1 hour", L"4 hours", L"8 hours", L"12 hours", L"24 hours"}, 0, 130);
    p.on_change(prot.schedule, [] {
        static const int hours[] = {0, 1, 4, 8, 12, 24};
        int i = ui::combo_index(prot.schedule);
        prot.settings.scan_hours = hours[i < 0 ? 0 : i];
        save_settings();
    });
    p.newline();
    p.label(L"Custom YARA rules (checked by ClamAV before they are added):", 420);
    p.button(L"Add rule file...", [] {
        std::wstring file = ui::open_file(L"YARA rule file", L"YARA rules\0*.yar;*.yara\0All files\0*.*\0");
        if (file.empty()) return;
        ClamInstall install;
        std::wstring reason;
        bool have = find_clam_install(install, reason);
        std::wstring error = add_rule_file(file, L"", have ? &install : nullptr);
        if (!error.empty()) ui::warn(L"The rule file was not added:\n" + error);
        fill_protection();
    }, 130);
    p.button(L"Remove rule", [] {
        auto rows = ui::selected_rows(prot.rules);
        auto files = list_rule_files();
        for (int r : rows) {
            if (r < (int)files.size()) {
                std::wstring error = remove_rule_file(base_name(files[r]));
                if (!error.empty()) ui::warn(error);
            }
        }
        fill_protection();
    }, 110, false);
    prot.rules = p.list({{L"Rule files", 700}}, 2);
    ui::every(10000, watch_tick);
    ui::every(60000, schedule_tick);
    p.on_show = fill_protection;
    restart_watcher();
    p.set_summary(L"Watched folders are polled every 10 seconds: a new file is scanned once it stops changing. Files already there are not scanned.");
}

// endregion

}  // namespace

void build_hunt_pages() {
    build_processes();
    build_persistence();
    build_protection();
}
