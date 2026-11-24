// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : System Health page group: health report, repair tools, startup programs, DPC and ISR load, and the inventory.

#include "pages.hpp"

#include <algorithm>
#include <set>

#include <shellapi.h>

#include <ddcore/proc.hpp>
#include <ddcore/secrets.hpp>
#include <ddcore/startup.hpp>
#include <ddcore/sysinfo.hpp>


using namespace dd;

namespace {

// region Health report

struct HealthPage {
    ui::Page* page = nullptr;
    HWND list = nullptr, details = nullptr;
    std::vector<HealthItem> items;
} health;

std::wstring report_text(const std::vector<HealthItem>& items) {
    std::wstring out = L"DD Cleaner: health report\r\n\r\n";
    for (const auto& i : items) {
        out += std::wstring(L"[") + status_name(i.status) + L"] " + i.category + L": " + i.title + L"\r\n";
        for (const auto& d : i.details) out += L"    " + d + L"\r\n";
    }
    return out;
}

void show_health_item() {
    auto rows = ui::selected_rows(health.list);
    if (rows.empty() || rows[0] >= (int)health.items.size()) {
        ui::set_text(health.details, L"");
        return;
    }
    const HealthItem& i = health.items[rows[0]];
    std::wstring text = i.title + L"\n\n";
    for (const auto& d : i.details) text += d + L"\n";
    ui::set_text(health.details, text);
}

void run_health() {
    ui::run_async(L"Running the health check (30 days of events)...", [](const Stop&, const Progress& progress) {
        auto items = run_health_check(progress);
        return [items] {
            health.items = items;
            std::vector<std::vector<std::wstring>> rows;
            int worst = 0;
            for (const auto& i : items) {
                rows.push_back({status_label(i.status), i.category, i.title});
                worst = std::max(worst, severity(i.status));
            }
            ui::set_rows(health.list, rows);
            if (!rows.empty()) ListView_SetItemState(health.list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            int problems = 0;
            for (const auto& i : items) problems += severity(i.status) >= 3;
            health.page->set_summary(std::to_wstring(items.size()) + L" checks, " + std::to_wstring(problems) + L" needing attention. Select a line for the details.");
        };
    });
}

void build_health() {
    ui::Page& p = ui::add_page(L"System Health", L"Health report");
    health.page = &p;
    p.button(L"Run health check", run_health, 150);
    p.button(L"Save report", [] {
        if (health.items.empty()) {
            ui::info(L"Run the health check first.");
            return;
        }
        std::wstring path = ui::save_file(L"Save the health report", L"health_report.txt", L"Text files\0*.txt\0All files\0*.*\0", L"txt");
        if (!path.empty() && !write_file(path, "\xEF\xBB\xBF" + utf8(report_text(health.items)))) ui::warn(L"The file could not be written.");
    }, 110, false);
    p.button(L"Reliability history", [] {
        ShellExecuteW(ui::main_window(), L"open", sys_exe(L"perfmon.exe").c_str(), L"/rel", nullptr, SW_SHOWNORMAL);
    }, 150, false);
    p.button(L"Mark as reviewed", [] {
        if (!ui::confirm(L"Mark everything found so far as reviewed?\n\nThe counters start again from zero: only events and crash dumps from now on are counted. "
                         L"Nothing is deleted, the logs stay as they are. You can undo this with \"Count everything again\".")) return;
        if (!mark_health_reviewed()) {
            ui::warn(L"The marker could not be saved.");
            return;
        }
        run_health();
    }, 140, false);
    p.button(L"Count everything again", [] {
        if (health_reviewed_at() <= 0) {
            ui::info(L"Nothing is marked as reviewed: all the last 30 days are counted.");
            return;
        }
        forget_health_reviewed();
        run_health();
    }, 170, false);
    p.button(L"Clear event logs", [] {
        if (!ui::confirm(L"Clear the Windows System and Application event logs?\n\nEach log is first saved as a .evtx file in " + data_dir() +
                         L"\\eventlog_backups, then emptied. Other tools (and Windows itself) lose that history. "
                         L"If you only want the counters to restart, use \"Mark as reviewed\" instead, which deletes nothing.",
                         L"Clear event logs")) return;
        if (!ui::elevated()) {
            ui::warn(L"Clearing the logs needs administrator rights. Use \"Run as administrator\" at the bottom right.");
            return;
        }
        ui::run_async(L"Saving and clearing the event logs...", [](const Stop&, const Progress&) {
            std::vector<std::wstring> report;
            std::wstring failed = clear_event_logs({L"System", L"Application"}, report);
            std::wstring text;
            for (const auto& r : report) text += r + L"\n";
            return [text, failed] {
                if (failed.empty()) {
                    mark_health_reviewed();   // the report starts from zero as well
                    ui::info(text);
                    run_health();
                } else {
                    ui::warn(text);
                }
            };
        });
    }, 140, false);
    ui::ListEvents ev;
    ev.on_select = show_health_item;
    health.list = p.list({{L"Status", 110}, {L"Category", 150}, {L"Finding", 700}}, 3, false, ev);
    health.details = p.text(2);
    p.on_refresh = run_health;
    p.set_summary(L"Reads disks, events, crashes, uptime and pending reboots. Nothing is changed.");
}

// endregion

// region Repair tools

struct RepairPage {
    ui::Page* page = nullptr;
    HWND output = nullptr;
} repair;

void run_repair(std::vector<std::wstring> argv, const std::wstring& description, Encoding encoding = Encoding::Oem) {
    if (!ui::elevated() && !ui::confirm(description + L"\n\nRun without administrator rights? Some operations may fail.", L"Administrator recommended")) return;
    std::wstring shown;
    for (const auto& a : argv) shown += (shown.empty() ? L"" : L" ") + a;
    ui::append_text(repair.output, L"\n> " + shown + L"\n");
    ui::run_async(description, [=](const Stop& stop, const Progress&) {
        HWND out = repair.output;
        ProcOptions o;
        o.timeout_ms = 4 * 60 * 60 * 1000;
        o.encoding = encoding;
        o.stop = stop;
        o.on_text = [out](const std::wstring& text) { ui::post_job([out, text] { ui::append_text(out, text); }); };
        ProcResult r = run_process(argv, o);
        return [r, description, out] {
            if (!r.started) {
                ui::append_text(out, L"The tool could not be started.\n");
                ui::warn(L"The tool could not be started.");
            } else if (r.stopped) {
                ui::append_text(out, L"\nStopped.\n");
            } else if (r.timed_out) {
                ui::append_text(out, L"\nTimed out.\n");
            } else if (r.code == 0) {
                ui::set_status(L"Repair operation completed successfully.");
                ui::info(L"Operation completed successfully.\n\nCheck the output for details.");
            } else {
                ui::set_status(L"Repair operation ended with exit code " + std::to_wstring(r.code) + L".");
                ui::warn(L"The command ended with exit code " + std::to_wstring(r.code) + L".\n\nCheck the output for details (SFC also returns a non-zero code when it found problems).");
            }
        };
    });
}

void dism(const wchar_t* arg, const std::wstring& description, const wchar_t* ask) {
    if (ask && !ui::confirm(ask, description)) return;
    run_repair({sys_exe(L"dism.exe"), L"/Online", L"/Cleanup-Image", arg}, description);
}

void network_reset() {
    if (!ui::elevated()) {
        ui::warn(L"Resetting the network stack needs administrator rights.\nRestart the application as administrator.");
        return;
    }
    if (!ui::confirm(L"This will reset:\n• Winsock catalog (netsh winsock reset)\n• TCP/IP stack (netsh int ip reset)\n• DNS cache (ipconfig /flushdns)\n\n"
                     L"You may lose current network connections and need to reboot.\n\nContinue?", L"Network reset", true))
        return;
    ui::append_text(repair.output, L"\n> Network reset sequence starting...\n");
    ui::run_async(L"Resetting the network stack...", [](const Stop& stop, const Progress& progress) {
        std::vector<std::vector<std::wstring>> commands = {{sys_exe(L"netsh.exe"), L"winsock", L"reset"}, {sys_exe(L"netsh.exe"), L"int", L"ip", L"reset"}, {sys_exe(L"ipconfig.exe"), L"/flushdns"}};
        std::wstring all;
        for (const auto& c : commands) {
            if (stop()) break;
            std::wstring shown;
            for (const auto& a : c) shown += (shown.empty() ? L"" : L" ") + a;
            progress(L"Running: " + shown);
            ProcOptions o;
            o.timeout_ms = 120000;
            o.stop = stop;
            ProcResult r = run_process(c, o);
            all += L"\n> " + shown + L"\n" + (r.started ? r.output : L"could not start\n") + L"\n";
        }
        return [all] {
            ui::append_text(repair.output, all);
            ui::info(L"Network reset sequence completed.\n\nA reboot is recommended for changes to take full effect.");
        };
    });
}

void build_repair() {
    ui::Page& p = ui::add_page(L"System Health", L"Repair tools");
    repair.page = &p;
    p.label(L"Order when Windows misbehaves: SFC, then DISM RestoreHealth if SFC cannot repair, then SFC again.", ui::FILL);
    p.newline();
    p.button(L"SFC verify only", [] { run_repair({sys_exe(L"sfc.exe"), L"/verifyonly"}, L"SFC verify only", Encoding::Utf16); }, 150);
    p.button(L"SFC scan and repair...", [] {
        if (ui::confirm(L"SFC /scannow checks every protected system file and replaces damaged ones with the copy from the component store. It takes 10-20 minutes.\n\nContinue?", L"SFC scan and repair"))
            run_repair({sys_exe(L"sfc.exe"), L"/scannow"}, L"SFC scan and repair", Encoding::Utf16);
    }, 170);
    p.button(L"DISM CheckHealth", [] { dism(L"/CheckHealth", L"DISM CheckHealth (quick)", nullptr); }, 150);
    p.button(L"DISM ScanHealth...", [] { dism(L"/ScanHealth", L"DISM ScanHealth (deep scan)", L"DISM ScanHealth will perform a deep scan for corruption.\nThis may take several minutes.\n\nContinue?"); }, 160);
    p.newline();
    p.button(L"DISM RestoreHealth...", [] {
        dism(L"/RestoreHealth", L"DISM RestoreHealth (repair)", L"DISM RestoreHealth will attempt to repair the component store.\nThis may take a very long time (15-30 minutes or more).\n\nContinue?");
    }, 180);
    p.button(L"Component store cleanup...", [] {
        dism(L"/StartComponentCleanup", L"Component store cleanup", L"This will run: DISM /Online /Cleanup-Image /StartComponentCleanup\n\nThis can reduce WinSxS folder size but might make some updates non-removable.\n\nContinue?");
    }, 200);
    p.button(L"Reset network stack...", network_reset, 170);
    repair.output = p.text(1);
    p.set_summary(L"Repair operations can take a long time: the output is shown as the tool writes it. Some require administrator rights. Stop (Esc) ends the tool.");
}

// endregion

// region Startup programs

struct StartupPage {
    ui::Page* page = nullptr;
    HWND list = nullptr;
    std::vector<StartupEntry> entries;
} startup;

std::wstring entry_state(const StartupEntry& e) {
    if (!e.exists) return L"File not found";
    int sev = e.severity();
    return sev >= 2 ? L"Suspicious" : sev == 1 ? L"Look at it" : L"Found";
}

void fill_startup() {
    std::vector<std::vector<std::wstring>> rows;
    int missing = 0, look = 0;
    for (const auto& e : startup.entries) {
        std::wstring flags;
        for (const auto& f : e.flags) flags += (flags.empty() ? L"" : L"; ") + f;
        rows.push_back({e.scope, e.kind, e.name, e.exists ? e.path : e.command, e.signer, flags, entry_state(e)});
        if (!e.exists) ++missing;
        if (e.severity() >= 1) ++look;
    }
    ui::set_rows(startup.list, rows);
    for (std::size_t i = 0; i < startup.entries.size(); ++i) ui::set_checked(startup.list, (int)i, false);
    startup.page->set_summary(std::to_wstring(startup.entries.size()) + L" entries, " + std::to_wstring(missing) + L" with a missing program, " + std::to_wstring(look) + L" to look at.");
}

void run_startup() {
    ui::run_async(L"Reading the startup programs...", [](const Stop& stop, const Progress& progress) {
        auto entries = collect_startup(stop, [progress](std::size_t done, std::size_t total, const std::wstring& name) {
            progress(L"Checking " + std::to_wstring(done) + L"/" + std::to_wstring(total) + L": " + name);
        });
        return [entries] {
            startup.entries = entries;
            fill_startup();
        };
    });
}

std::vector<std::wstring> startup_paths() {
    std::vector<std::wstring> out;
    for (int r : ui::selected_rows(startup.list)) {
        if (r < (int)startup.entries.size() && !startup.entries[r].path.empty()) out.push_back(startup.entries[r].path);
    }
    return out;
}

void remove_startup() {
    std::vector<StartupEntry> chosen;
    for (std::size_t i = 0; i < startup.entries.size(); ++i) {
        if (ui::is_checked(startup.list, (int)i)) chosen.push_back(startup.entries[i]);
    }
    if (chosen.empty()) {
        ui::info(L"Tick the entries to remove first.");
        return;
    }
    std::wstring ask = L"Remove " + std::to_wstring(chosen.size()) + L" startup entries?\n\n";
    bool admin_needed = false;
    for (std::size_t i = 0; i < chosen.size() && i < 10; ++i) ask += L"• " + describe(chosen[i]) + L"\n";
    if (chosen.size() > 10) ask += L"... and " + std::to_wstring(chosen.size() - 10) + L" more\n";
    for (const auto& e : chosen) admin_needed = admin_needed || needs_admin(e);
    if (admin_needed && !ui::elevated()) {
        ui::warn(L"Some of the ticked entries need administrator rights to remove. Restart as administrator, or untick them.");
        return;
    }
    ask += L"\nA backup is made first (.reg, .xml, or a copy of the file). If the backup fails nothing is removed.";
    if (!ui::confirm(ask, L"Remove the ticked startup entries", true)) return;
    ui::run_async(L"Removing startup entries...", [=](const Stop& stop, const Progress&) {
        StartupRemoval r = remove_entries(chosen, L"", stop);
        return [r] {
            std::set<std::wstring> gone;
            for (const auto& e : r.removed) gone.insert(lower(e.kind + L"|" + e.scope + L"|" + e.location + L"|" + e.name));
            std::vector<StartupEntry> keep;
            for (const auto& e : startup.entries) {
                if (!gone.count(lower(e.kind + L"|" + e.scope + L"|" + e.location + L"|" + e.name))) keep.push_back(e);
            }
            startup.entries = keep;
            fill_startup();
            ui::set_status(std::to_wstring(r.removed.size()) + L" entries removed, " + std::to_wstring(r.backups.size()) + L" backup(s).");
            if (!r.failed.empty()) {
                std::wstring text = std::to_wstring(r.failed.size()) + L" entries could not be removed:\n\n";
                for (const auto& f : r.failed) text += f.first.name + L": " + f.second + L"\n";
                ui::warn(text);
            }
        };
    });
}

void build_startup() {
    ui::Page& p = ui::add_page(L"System Health", L"Startup programs");
    startup.page = &p;
    p.button(L"List startup programs", run_startup, 170);
    p.button(L"Scan with ClamAV", [] {
        auto paths = startup_paths();
        if (paths.empty()) ui::info(L"Select the entries to scan.");
        else scan_with_clamav(paths);
    }, 140);
    p.button(L"Open location", [] {
        auto paths = startup_paths();
        if (!paths.empty()) ui::reveal(paths[0]);
    }, 110, false);
    p.button(L"Export", [] { ui::export_list(startup.list, L"startup_programs.csv"); }, 80, false);
    p.button(L"Persistence hunt", [] { ui::select_page(L"Threat hunt", L"Persistence"); }, 140, false);
    p.button(L"Backups", [] { ui::reveal(data_subdir(L"startup_backups")); }, 80, false);
    p.button(L"Remove ticked...", remove_startup, 150, true, true);
    ui::ListEvents ev;
    ev.on_activate = [](int row) {
        if (row < (int)startup.entries.size()) ui::reveal(startup.entries[row].path);
    };
    startup.list = p.list({{L"Scope", 90}, {L"Kind", 70}, {L"Name", 190}, {L"Program", 430}, {L"Signer", 170}, {L"Flags", 200}, {L"State", 100}}, 3, true, ev);
    p.on_refresh = run_startup;
    p.set_summary(L"Lists what starts by itself: Run keys, Startup folders, logon tasks. Tick an entry to remove it (a backup is made first).");
}

// endregion

// region DPC / ISR load

struct LoadPage {
    ui::Page* page = nullptr;
    HWND list = nullptr, text = nullptr;
} load;

void run_load() {
    ui::run_async(L"Measuring the DPC and ISR load (5 s)...", [](const Stop&, const Progress&) {
        LoadResult r = measure_dpc_isr(5);
        return [r] {
            std::vector<std::vector<std::wstring>> rows;
            char buf[32];
            for (std::size_t i = 0; i < r.dpc.size(); ++i) {
                std::wstring dpc, isr;
                snprintf(buf, sizeof(buf), "%.2f %%", r.dpc[i]);
                dpc = wide(buf);
                snprintf(buf, sizeof(buf), "%.2f %%", i < r.isr.size() ? r.isr[i] : 0.0);
                isr = wide(buf);
                rows.push_back({L"Sample " + std::to_wstring(i + 1), dpc, isr});
            }
            ui::set_rows(load.list, rows);
            ui::set_text(load.text, r.verdict());
            load.page->set_summary(r.verdict());
        };
    });
}

void build_load() {
    ui::Page& p = ui::add_page(L"System Health", L"DPC / ISR load");
    load.page = &p;
    p.button(L"Measure (5 s)", run_load, 130);
    p.label(L"High DPC or ISR time causes audio crackles and stutter: a driver is holding a processor.", ui::FILL);
    load.list = p.list({{L"Sample", 140}, {L"DPC time", 120, true}, {L"ISR time", 120, true}}, 2);
    load.text = p.text(2);
    p.on_refresh = run_load;
    p.set_summary(L"Measure while the problem happens (audio crackling, stutter).");
}

// endregion

// region Inventory

struct InventoryPage {
    ui::Page* page = nullptr;
    HWND filter = nullptr, system = nullptr, list = nullptr;
    std::vector<Program> programs, shown;
} inv;

void fill_programs() {
    std::wstring needle = lower(ui::trimmed(inv.filter));
    inv.shown.clear();
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& pr : inv.programs) {
        if (!needle.empty() && lower(pr.name).find(needle) == std::wstring::npos && lower(pr.publisher).find(needle) == std::wstring::npos) continue;
        inv.shown.push_back(pr);
        rows.push_back({pr.name, pr.version, pr.publisher, pr.scope});
    }
    ui::set_rows(inv.list, rows);
}

void read_inventory() {
    ui::run_async(L"Reading inventory...", [](const Stop&, const Progress&) {
        auto programs = installed_programs();
        auto gpus = graphics_cards();
        Activation act = windows_activation();
        return [=] {
            std::wstring text;
            if (act.valid) {
                text += act.edition + L" (build " + act.build + L"): " + act.status + L", " + (act.channel.empty() ? L"unknown channel" : act.channel) +
                        (act.partial_key.empty() ? L"" : L", key ends with " + act.partial_key) + L"\n";
            }
            for (const auto& g : gpus) {
                char vram[32];
                snprintf(vram, sizeof(vram), "%g", g.vram_gb);
                text += L"GPU: " + g.name + L", " + wide(vram) + L" GB, driver " + g.driver_version + L" (" + g.driver_date + L")" + (g.resolution.empty() ? L"" : L", " + g.resolution) + L"\n";
            }
            ui::set_text(inv.system, text.empty() ? L"Nothing could be read." : text);
            inv.programs = programs;
            fill_programs();
            inv.page->set_summary(std::to_wstring(programs.size()) + L" programs.");
        };
    });
}

void export_programs() {
    if (inv.programs.empty()) {
        ui::info(L"Nothing to export. Read the inventory first.");
        return;
    }
    std::wstring path = ui::save_file(L"Export installed programs", L"installed_programs.csv", L"CSV files\0*.csv\0All files\0*.*\0", L"csv");
    if (path.empty()) return;
    auto cell = [](const std::wstring& s) {
        std::wstring out = L"\"";
        for (wchar_t c : s) out += c == L'"' ? std::wstring(L"\"\"") : std::wstring(1, c);
        return out + L"\"";
    };
    std::wstring csv = L"\"Name\",\"Version\",\"Publisher\",\"Installed for\"\r\n";
    for (const auto& p : inv.programs) csv += cell(p.name) + L"," + cell(p.version) + L"," + cell(p.publisher) + L"," + cell(p.scope) + L"\r\n";
    if (!write_file(path, "\xEF\xBB\xBF" + utf8(csv))) ui::warn(L"The file could not be written.");
    else ui::set_status(L"Exported all " + std::to_wstring(inv.programs.size()) + L" programs to " + path);
}

// The saved passwords window: shown on screen only, nothing is written anywhere
void show_secrets(const std::vector<SecretRecord>& records) {
    ui::DialogSpec spec;
    int readable = 0;
    for (const auto& r : records) readable += !r.value.empty();
    spec.title = L"Saved passwords and keys";
    spec.prompt = std::to_wstring(records.size()) + L" item(s), " + std::to_wstring(readable) + L" with a readable secret. Shown on screen only; close this window when you are done.";
    spec.body = ui::DialogSpec::List;
    spec.columns = {{L"Type", 140}, {L"Name", 280}, {L"Detail", 200}, {L"Secret", 240}};
    for (const auto& r : records) spec.rows.push_back({r.kind, r.name, r.info, !r.value.empty() ? L"••••••••" : (!r.note.empty() ? L"(" + r.note + L")" : L"(none)")});
    spec.buttons = {{L"Close", 0}, {L"Show", -2}, {L"Copy selected (clears in 30 s)", -3}};
    spec.width = 980;
    spec.height = 560;
    bool revealed = false;
    spec.action = [&](HWND list, int result, HWND button) {
        if (result == -2) {
            revealed = !revealed;
            for (std::size_t i = 0; i < records.size(); ++i) {
                if (records[i].value.empty()) continue;
                ListView_SetItemText(list, (int)i, 3, const_cast<wchar_t*>(revealed ? records[i].value.c_str() : L"••••••••"));
            }
            SetWindowTextW(button, revealed ? L"Hide" : L"Show");
        } else if (result == -3) {
            int row = ListView_GetNextItem(list, -1, LVNI_SELECTED);
            if (row < 0 || row >= (int)records.size() || records[row].value.empty()) ui::info(L"Select a row that has a password.");
            else ui::copy_secret(records[row].value);
        }
    };
    ui::run_dialog(spec);
}

void saved_secrets() {
    if (!ui::elevated()) {
        ui::warn(L"Windows only gives saved Wi-Fi passwords to an administrator.\nRestart the application as administrator.");
        return;
    }
    if (!ui::confirm(L"PERSONAL USE ONLY\nUse this only on your own PC, to recover your own passwords and keys. Reading the passwords of another person, or of a PC that is not yours, "
                     L"without their permission is forbidden and may be a crime.\n\nThis reads the secrets saved on this PC and shows them on screen:\n"
                     L"  • Wi-Fi passwords and the firmware Windows key\n  • Windows Credential Manager (saved web, app and Remote Desktop logins)\n"
                     L"  • software license keys (Office, Adobe, Autodesk...)\n  • website passwords saved in Chrome, Edge, Brave and Firefox\n\n"
                     L"Nothing is written to a file or to the log, the clipboard is cleared 30 seconds after you copy a secret, and this window empties itself when closed. "
                     L"Make sure nobody can see your screen.\n\nI confirm these are my own passwords. Continue?",
                     L"Show saved passwords (personal use only)", true))
        return;
    ui::run_async(L"Reading saved passwords...", [](const Stop&, const Progress&) {
        auto records = collect_secrets();
        return [records] { show_secrets(records); };
    });
}

void build_inventory() {
    ui::Page& p = ui::add_page(L"System Health", L"Inventory");
    inv.page = &p;
    p.button(L"Read inventory", read_inventory, 130);
    p.button(L"Export programs", export_programs, 130, false);
    p.button(L"Open location", [] {
        auto rows = ui::selected_rows(inv.list);
        if (!rows.empty() && rows[0] < (int)inv.shown.size()) ui::reveal(inv.shown[rows[0]].location);
    }, 110, false);
    p.button(L"Saved Wi-Fi passwords and Windows key...", saved_secrets, 290, true, true);
    p.newline();
    p.label(L"Installed programs, filter:", 170);
    inv.filter = p.edit(L"", 0);
    p.on_change(inv.filter, fill_programs);
    inv.system = p.text(1);
    inv.list = p.list({{L"Name", 360}, {L"Version", 130}, {L"Publisher", 280}, {L"Installed for", 140}}, 4);
    p.on_refresh = read_inventory;
    p.set_summary(L"Windows edition and activation, graphics cards, installed programs.");
}

// endregion

}  // namespace

void build_system_pages() {
    build_health();
    build_repair();
    build_startup();
    build_load();
    build_inventory();
}
