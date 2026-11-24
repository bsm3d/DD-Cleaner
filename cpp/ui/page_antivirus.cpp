// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Antivirus page group: ClamAV scan, quarantine, signature update and the VirusTotal helpers shared with the hunt pages.

#include "pages.hpp"

#include <algorithm>
#include <ctime>
#include <mutex>
#include <regex>
#include <set>

#include <shellapi.h>

#include <ddcore/antivirus.hpp>
#include <ddcore/inspect.hpp>
#include <ddcore/online.hpp>

using namespace dd;

namespace {

// region VirusTotal and preferences

void show_preferences() {
    for (;;) {
        ui::DialogSpec spec;
        spec.title = L"Preferences: API keys";
        spec.prompt = L"VirusTotal API key. Status: " + api_key_status(L"virustotal") +
                      L"\n\nPaste a key to save it, or leave empty and press Save to remove the saved key. The key is only sent to VirusTotal. Looking up sends only a file's hash.";
        spec.body = ui::DialogSpec::Input;
        spec.password = true;
        spec.buttons = {{L"Save", 1}, {L"Test", 2}, {L"Close", 0}};
        spec.width = 640;
        spec.height = 260;
        auto r = ui::run_dialog(spec);
        if (r.button == 0) return;
        std::wstring key = trim(r.text);
        if (r.button == 1) {
            std::wstring error = set_api_key(L"virustotal", key);
            if (!error.empty()) ui::warn(error);
            else ui::set_status(key.empty() ? L"VirusTotal key removed." : L"VirusTotal key saved.");
        } else if (r.button == 2) {
            std::wstring to_test = key.empty() ? get_api_key(L"virustotal") : key;
            if (to_test.empty()) {
                ui::info(L"There is no key to test.");
                continue;
            }
            std::wstring problem = validate_api_key(L"virustotal", to_test);
            if (problem.empty()) problem = check_api_key(L"virustotal", to_test);
            if (problem.empty()) ui::info(L"VirusTotal accepts this key.");
            else ui::warn(problem);
        }
    }
}

void send_for_analysis(const std::wstring& path, const std::wstring& key);

void show_vt_results(const std::vector<VtResult>& results, const std::wstring& key) {
    ui::DialogSpec spec;
    spec.title = L"VirusTotal";
    spec.prompt = L"What VirusTotal says about each file (looked up by its hash: nothing was sent). Select a file for the actions below.";
    spec.body = ui::DialogSpec::List;
    spec.columns = {{L"File", 360}, {L"VirusTotal says", 300}, {L"SHA-256", 280}};
    for (const auto& r : results) {
        std::wstring says = !r.error.empty() ? r.error : (r.has_report ? r.report.verdict() : L"");
        spec.rows.push_back({r.path, says, r.sha256});
    }
    spec.buttons = {{L"Close", 0}, {L"Open report", 2}, {L"Send selected file for analysis...", 3}};
    spec.width = 1000;
    spec.height = 460;
    auto choice = ui::run_dialog(spec);
    if (choice.row < 0 || choice.row >= (int)results.size()) return;
    const VtResult& r = results[choice.row];
    if (choice.button == 2) {
        if (!r.sha256.empty()) ui::open_url(std::wstring(VIRUSTOTAL_GUI) + L"file/" + r.sha256);
    } else if (choice.button == 3) {
        send_for_analysis(r.path, key);
    }
}

void send_for_analysis(const std::wstring& path, const std::wstring& key) {
    std::wstring problem = upload_problem(path);
    if (!problem.empty()) {
        ui::warn(L"This file cannot be sent:\n\n" + problem);
        return;
    }
    std::wstring ask = L"Send this file to VirusTotal?\n\n" + path + L"\n\nSending shares the file with VirusTotal and everyone who uses it. It cannot be undone. "
                       L"Never send a file that holds personal or confidential data.";
    std::wstring warning = upload_warning(path);
    if (!warning.empty()) ask += L"\n\n" + warning;
    if (!ui::confirm(ask, L"Send a file to VirusTotal", true)) return;
    ui::run_async(L"Sending the file to VirusTotal and waiting for the analysis (a few minutes)...", [path, key](const Stop& stop, const Progress& progress) {
        VtResult r = submit_file(path, key, nullptr, progress, stop);
        return [r, key] { show_vt_results({r}, key); };
    });
}

}  // namespace

void virustotal_lookup(const std::wstring& path) {
    if (path.empty() || !is_file(path)) {
        ui::info(L"There is no program file to look up.");
        return;
    }
    std::wstring key = get_api_key(L"virustotal");
    if (key.empty()) {
        ui::info(L"Save your VirusTotal API key first: the Preferences window opens.");
        show_preferences();
        key = get_api_key(L"virustotal");
        if (key.empty()) return;
    }
    ui::run_async(L"Looking the file up on VirusTotal (by hash)...", [path, key](const Stop& stop, const Progress& progress) {
        auto results = check_files({path}, key, nullptr, progress, stop);
        return [results, key] { show_vt_results(results, key); };
    });
}

void virustotal_lookup_hash(const std::wstring& sha256, const std::wstring& label) {
    ui::open_url(std::wstring(VIRUSTOTAL_GUI) + L"file/" + sha256);
    (void)label;
}

namespace {

// endregion

// region Status and targets

struct AvPage {
    ui::Page* scan = nullptr;
    HWND engine = nullptr, database = nullptr;
    HWND targets = nullptr, quarantine_cb = nullptr, archives_cb = nullptr, pua_cb = nullptr, thorough_cb = nullptr, fast_cb = nullptr, cache_cb = nullptr;
    HWND maxsize = nullptr, cache_days = nullptr, threads = nullptr, threats = nullptr, log = nullptr;
    std::vector<std::wstring> target_paths;
    struct Threat {
        std::wstring path, threat, state;
    };
    std::vector<Threat> found;
    int files = 0, errors = 0;
} av;

void refresh_status() {
    ClamInstall install;
    std::wstring reason;
    bool have = find_clam_install(install, reason);
    SetWindowTextW(av.engine, have ? (L"Engine: " + install.folder).c_str() : reason.c_str());
    DatabaseInfo info = read_database_info();
    std::wstring text;
    if (!info.ready) {
        text = L"Signature database: not downloaded yet (see \"Signature update\").";
    } else {
        text = L"Signature database: " + (info.signatures ? std::to_wstring(info.signatures) + L" signatures" : std::wstring(L"custom"));
        if (info.built > 0) {
            time_t t = (time_t)info.built;
            tm lt{};
            localtime_s(&lt, &t);
            wchar_t date[32];
            wcsftime(date, 32, L"%Y-%m-%d", &lt);
            text += std::wstring(L", built ") + date;
            if (info.age_days() > 3) text += L" (" + std::to_wstring(info.age_days()) + L" days old, update recommended)";
        }
    }
    SetWindowTextW(av.database, text.c_str());
}

void fill_targets() {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& t : av.target_paths) rows.push_back({t});
    ui::set_rows(av.targets, rows);
}

void add_target(const std::wstring& path) {
    if (path.empty()) return;
    std::wstring norm = normcase(path);
    for (const auto& t : av.target_paths) {
        if (normcase(t) == norm) return;
    }
    av.target_paths.push_back(path);
    fill_targets();
}

void fill_threats() {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& t : av.found) rows.push_back({t.path, t.threat, t.state});
    ui::set_rows(av.threats, rows);
}

// endregion

// region Scan

std::vector<std::wstring> quick_targets() {
    std::vector<std::wstring> out;
    std::wstring profile = env_var(L"USERPROFILE");
    if (!profile.empty()) {
        for (const wchar_t* sub : {L"Downloads", L"Desktop"}) {
            if (is_dir(join(profile, sub))) out.push_back(join(profile, sub));
        }
    }
    if (is_dir(temp_dir())) out.push_back(temp_dir());
    return out;
}

ScanOptions read_options() {
    ScanOptions o;
    o.quarantine = ui::checked(av.quarantine_cb);
    o.archives = ui::checked(av.archives_cb);
    o.pua = ui::checked(av.pua_cb);
    o.thorough = ui::checked(av.thorough_cb);
    o.fast = ui::checked(av.fast_cb);
    static const int sizes[] = {25, 50, 100, 250, 500};
    int s = ui::combo_index(av.maxsize);
    o.max_filesize_mb = sizes[s < 0 ? 2 : s];
    o.use_cache = ui::checked(av.cache_cb);
    static const int days[] = {1, 3, 7, 14, 30, 60};
    int d = ui::combo_index(av.cache_days);
    o.cache_days = days[d < 0 ? 2 : d];
    o.threads = std::max(0, ui::combo_index(av.threads));   // 0 = Auto, then 1..8
    return o;
}

void start_scan(const std::vector<std::wstring>& paths) {
    std::vector<std::wstring> targets;
    for (const auto& p : paths) {
        if (!p.empty() && lexists(p)) targets.push_back(p);
    }
    if (targets.empty()) {
        ui::info(L"There is nothing to scan: add files or folders first.");
        return;
    }
    ClamInstall install;
    std::wstring reason;
    if (!find_clam_install(install, reason)) {
        ui::warn(reason);
        return;
    }
    if (!read_database_info().ready) {
        ui::warn(L"The signature database is not downloaded yet. Open \"Signature update\" and download it first.");
        ui::select_page(L"Antivirus", L"Signature update");
        return;
    }
    ScanOptions options = read_options();
    av.found.clear();
    av.files = av.errors = 0;
    fill_threats();
    ui::set_text(av.log, L"");
    auto mutex = std::make_shared<std::mutex>();
    ui::run_async(L"Scanning with ClamAV...", [=](const Stop& stop, const Progress& progress) {
        ScanEvents events;
        events.progress = progress;
        events.planned = [](std::size_t to_scan, std::size_t skipped, std::size_t processes) {
            ui::post_job([=] {
                av.scan->set_summary(L"Scanning " + std::to_wstring(to_scan) + L" file(s) with " + std::to_wstring(processes) + L" process(es); " + std::to_wstring(skipped) + L" unchanged file(s) skipped.");
            });
        };
        events.lines = [mutex](const std::vector<std::wstring>& lines) {
            std::vector<ScanLine> parsed;
            for (const auto& l : lines) parsed.push_back(parse_scan_line(l));
            for (const auto& p : parsed) {
                if (p.kind == L"moved") record_quarantine(p.a, p.b, L"");
            }
            std::wstring text;
            for (const auto& l : lines) text += l + L"\n";
            ui::post_job([parsed, text] {
                for (const auto& p : parsed) {
                    if (p.kind == L"found") av.found.push_back({p.a, p.b, L"Found"});
                    else if (p.kind == L"moved") {
                        for (auto& t : av.found) {
                            if (normcase(t.path) == normcase(p.a)) t.state = L"Quarantined";
                        }
                    } else if (p.kind == L"ok") ++av.files;
                    else if (p.kind == L"error") ++av.errors;
                }
                fill_threats();
                if (GetWindowTextLengthW(av.log) > 300000) ui::set_text(av.log, L"(earlier lines dropped)\n");
                ui::append_text(av.log, text);
                av.scan->set_summary(L"Scanned " + std::to_wstring(av.files) + L" files, " + std::to_wstring(av.found.size()) + L" threat(s), " + std::to_wstring(av.errors) + L" error(s)...");
            });
        };
        int code = run_clam_scan(install, targets, options, events, stop);
        return [code] {
            std::wstring text = code == 0 ? L"Scan finished: nothing found." : code == 1 ? L"Scan finished: " + std::to_wstring(av.found.size()) + L" threat(s) found." : code == 2 ? L"Scan stopped." : L"The scan could not start.";
            av.scan->set_summary(text + L"  Scanned " + std::to_wstring(av.files) + L" files, " + std::to_wstring(av.errors) + L" error(s).");
            refresh_status();
            if (code == 1) ui::warn(text + L"\n\nSee the list of threats. With quarantine on they were moved to the Quarantine page.");
        };
    });
}

void build_scan() {
    ui::Page& p = ui::add_page(L"Antivirus", L"Scan");
    av.scan = &p;
    av.engine = p.label(L"", ui::FILL);
    p.newline();
    av.database = p.label(L"", ui::FILL);
    p.newline();
    p.button(L"Add file...", [] { add_target(ui::open_file(L"Choose a file to scan")); }, 100, false);
    p.button(L"Add folder...", [] { add_target(ui::choose_folder(L"Choose a folder to scan")); }, 110, false);
    p.button(L"Drop from list", [] {
        auto rows = ui::selected_rows(av.targets);
        std::sort(rows.rbegin(), rows.rend());
        for (int r : rows) {
            if (r < (int)av.target_paths.size()) av.target_paths.erase(av.target_paths.begin() + r);
        }
        fill_targets();
    }, 80, false);
    p.button(L"Scan these items", [] { start_scan(av.target_paths); }, 150);
    p.button(L"Quick scan", [] { start_scan(quick_targets()); }, 110);
    p.button(L"Full scan", [] {
        if (ui::confirm(L"A full scan reads every fixed disk. It can take hours. Continue?", L"Full scan")) start_scan(fixed_drives());
    }, 100);
    p.newline();
    av.quarantine_cb = p.check(L"Move threats to quarantine", 230, true);
    av.archives_cb = p.check(L"Scan archives", 140, true);
    av.fast_cb = p.check(L"Fast mode", 110);
    av.pua_cb = p.check(L"Detect unwanted apps (PUA)", 230);
    av.thorough_cb = p.check(L"Thorough", 100);
    p.on_change(av.fast_cb, [] {
        bool fast = ui::checked(av.fast_cb);
        EnableWindow(av.archives_cb, !fast);
        EnableWindow(av.thorough_cb, !fast);
    });
    p.newline();
    p.label(L"Skip files larger than (MB):", 190);
    av.maxsize = p.combo({L"25", L"50", L"100", L"250", L"500"}, 2, 80);
    av.cache_cb = p.check(L"Skip files unchanged since a clean scan in the last (days):", 400, true);
    av.cache_days = p.combo({L"1", L"3", L"7", L"14", L"30", L"60"}, 2, 70);
    p.label(L"Parallel scans:", 110);
    av.threads = p.combo({L"Auto", L"1", L"2", L"3", L"4", L"5", L"6", L"7", L"8"}, 0, 80);
    p.button(L"Forget scan memory", [] {
        if (!ui::confirm(L"Forget what earlier scans found clean? The next scan then re-checks every file.", L"Scan memory")) return;
        ScanCache cache(join(clam_dir(), L"scan_cache.dat"));
        cache.clear();
        cache.save();
        ui::set_status(L"Scan memory cleared.");
    }, 150, false);
    av.targets = p.list({{L"Items to scan", 900}}, 1);
    av.threats = p.list({{L"File", 560}, {L"Threat", 260}, {L"State", 140}}, 2);
    av.log = p.text(2);
    p.on_show = refresh_status;
    p.set_summary(L"A scan never deletes anything. With quarantine on, infected files are moved to a folder only administrators can open; restore or delete them from the Quarantine page.");
}

// endregion

// region Quarantine

struct QuarPage {
    ui::Page* page = nullptr;
    HWND list = nullptr;
    std::vector<QuarantineEntry> entries;
} quar;

void refresh_quarantine() {
    quar.entries = list_quarantine();
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& e : quar.entries) rows.push_back({e.date, e.threat, e.original, e.stored});
    ui::set_rows(quar.list, rows);
    quar.page->set_summary(std::to_wstring(quar.entries.size()) + L" file(s) in quarantine.");
}

std::vector<QuarantineEntry> selected_quarantine() {
    std::vector<QuarantineEntry> out;
    for (int r : ui::selected_rows(quar.list)) {
        if (r < (int)quar.entries.size()) out.push_back(quar.entries[r]);
    }
    return out;
}

void quarantine_action(bool restore) {
    auto chosen = selected_quarantine();
    if (chosen.empty()) {
        ui::info(L"Select the files first.");
        return;
    }
    std::wstring what = restore ? L"Restore " : L"Delete permanently ";
    std::wstring ask = what + std::to_wstring(chosen.size()) + L" file(s)?";
    ask += restore ? L"\n\nThey go back to where they were found, and they may still be dangerous." : L"\n\nThis cannot be undone.";
    if (!ui::confirm(ask, restore ? L"Restore" : L"Delete", true)) return;
    std::wstring failed;
    int ok = 0;
    for (const auto& e : chosen) {
        std::wstring error = restore ? restore_quarantined(e) : delete_quarantined(e);
        if (error.empty()) ++ok;
        else failed += e.original + L": " + error + L"\n";
    }
    refresh_quarantine();
    ui::set_status(std::to_wstring(ok) + L" file(s) " + (restore ? L"restored." : L"deleted."));
    if (!failed.empty()) ui::warn(std::to_wstring(chosen.size() - ok) + L" file(s) failed:\n\n" + failed);
}

void build_quarantine() {
    ui::Page& p = ui::add_page(L"Antivirus", L"Quarantine");
    quar.page = &p;
    p.button(L"Refresh", refresh_quarantine, 80, false);
    p.button(L"Restore...", [] { quarantine_action(true); }, 100);
    p.button(L"Delete permanently...", [] { quarantine_action(false); }, 170);
    p.button(L"Open folder", [] {
        make_dirs(quarantine_dir());
        ui::reveal(quarantine_dir());
    }, 110, false);
    p.button(L"VirusTotal", [] {
        auto chosen = selected_quarantine();
        if (chosen.empty()) ui::info(L"Select a file first.");
        else virustotal_lookup(chosen[0].stored);
    }, 110);
    quar.list = p.list({{L"Date", 150}, {L"Threat", 260}, {L"Original place", 520}, {L"Stored as", 300}}, 4);
    p.on_show = refresh_quarantine;
    p.on_refresh = refresh_quarantine;
    p.set_summary(L"Files ClamAV moved here are cut off from the system. Restore only what you are sure is harmless.");
}

// endregion

// region Signature update

struct UpdatePage {
    ui::Page* page = nullptr;
    HWND log = nullptr, label = nullptr;
} upd;

void start_update() {
    ClamInstall install;
    std::wstring reason;
    if (!find_clam_install(install, reason)) {
        ui::warn(reason);
        return;
    }
    bool first = !read_database_info().ready;
    if (!ui::confirm(std::wstring(first ? L"Download the ClamAV signature database now (about 300 MB)?" : L"Check for new ClamAV signatures now?") + L"\n\nfreshclam connects to database.clamav.net.", L"Update signatures")) return;
    std::wstring conf;
    try {
        conf = write_freshclam_conf();
    } catch (const std::exception& e) {
        ui::warn(L"The configuration could not be written:\n" + wide(e.what()));
        return;
    }
    if (conf.empty()) {
        ui::warn(L"The configuration could not be written.");
        return;
    }
    auto command = build_update_command(install, conf, database_dir());
    ui::set_text(upd.log, L"");
    SetWindowTextW(upd.label, L"Updating...");
    ui::run_async(L"Updating the ClamAV signatures...", [command](const Stop& stop, const Progress&) {
        static const std::wregex percent(LR"((\d{1,3})%)");
        int code = run_streaming(command, [](const std::vector<std::wstring>& lines) {
            std::wstring text;
            std::wstring last_progress;
            for (const auto& l : lines) {
                std::wsmatch m;
                if (std::regex_search(l, m, percent)) {
                    int pct = std::min(100, _wtoi(m[1].str().c_str()));
                    last_progress = L"Downloading (" + std::to_wstring(pct) + L" %)";
                    if (pct < 100) continue;   // progress ticks stay out of the log
                }
                text += l + L"\n";
            }
            ui::post_job([text, last_progress] {
                if (!text.empty()) ui::append_text(upd.log, text);
                if (!last_progress.empty()) SetWindowTextW(upd.label, last_progress.c_str());
            });
        }, stop);
        return [code] {
            std::wstring text = ui::stop_requested() ? L"Update stopped." : code == 0 ? L"Signatures are up to date." : L"The update failed (code " + std::to_wstring(code) + L"). See the log below.";
            SetWindowTextW(upd.label, text.c_str());
            ui::set_status(text);
            refresh_status();
        };
    });
}

void build_update() {
    ui::Page& p = ui::add_page(L"Antivirus", L"Signature update");
    upd.page = &p;
    p.button(L"Update signatures...", start_update, 190);
    upd.label = p.label(L"", ui::FILL);
    upd.log = p.text(1);
    p.set_summary(L"Signatures are downloaded by freshclam from database.clamav.net. The first download is about 300 MB; later updates are small. Nothing else is sent.");
}

// endregion

}  // namespace

void scan_with_clamav(const std::vector<std::wstring>& paths) {
    ui::select_page(L"Antivirus", L"Scan");
    start_scan(paths);
}

void build_antivirus_pages() {
    build_scan();
    build_quarantine();
    build_update();
    ui::Page& p = ui::add_page(L"Antivirus", L"VirusTotal");
    p.label(L"VirusTotal: look programs up by hash (from the Threat hunt and Quarantine pages) and, after a confirmation, send one for analysis.", ui::FILL);
    p.newline();
    p.button(L"Preferences: API key...", show_preferences, 200, false);
    p.button(L"Look up a file...", [] {
        std::wstring file = ui::open_file(L"Choose a file to look up");
        if (!file.empty()) virustotal_lookup(file);
    }, 150);
    p.set_summary(L"Looking up sends only a file's SHA-256. Sending a file is always confirmed first.");
}
