// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Security page group: audit and hardening profiles, and the advanced tweaks with their backups and undo.

#include "pages.hpp"

#include <algorithm>
#include <set>

#include <ddcore/audit.hpp>
#include <ddcore/tweaks.hpp>

using namespace dd;

namespace {

// region Audit

struct AuditPage {
    ui::Page* page = nullptr;
    HWND score = nullptr, domains = nullptr, issues_list = nullptr, details = nullptr;
    std::map<Domain, DomainScore> scores;
    std::vector<Issue> issues;
    int global = -1;
    bool done = false;
} audit;

std::wstring risk_label(Risk r) {
    switch (r) {
        case Risk::Critical: return L"\U0001F534 Critical";
        case Risk::High: return L"\U0001F7E0 High";
        case Risk::Medium: return L"\U0001F7E1 Medium";
        case Risk::Low: return L"\U0001F7E2 Low";
    }
    return L"";
}

void show_audit() {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& [domain, s] : audit.scores) rows.push_back({domain_name(domain), std::to_wstring(s.current_score) + L" / " + std::to_wstring(s.max_score), s.status()});
    ui::set_rows(audit.domains, rows);
    std::vector<Issue> sorted = audit.issues;
    std::stable_sort(sorted.begin(), sorted.end(), [](const Issue& a, const Issue& b) {
        if (a.risk != b.risk) return a.risk > b.risk;
        return a.score_impact > b.score_impact;
    });
    audit.issues = sorted;
    rows.clear();
    for (const auto& i : sorted) rows.push_back({risk_label(i.risk), domain_name(i.domain), i.title, i.current_state, L"-" + std::to_wstring(i.score_impact), i.recommended_action});
    ui::set_rows(audit.issues_list, rows);
    const wchar_t* verdict = audit.global >= 85 ? L"Excellent" : audit.global >= 70 ? L"Fair" : audit.global >= 50 ? L"Medium" : L"Critical";
    SetWindowTextW(audit.score, (L"Overall security score: " + std::to_wstring(audit.global) + L" / 100  (" + verdict + L")").c_str());
    audit.page->set_summary(std::to_wstring(sorted.size()) + L" issue(s). Select one for the details.");
}

void run_audit() {
    ui::run_async(L"Running the security audit (read only)...", [](const Stop&, const Progress& progress) {
        SecurityAuditor auditor;
        int score = auditor.run_full_audit(progress);
        auto scores = auditor.domain_scores();
        auto issues = auditor.issues();
        return [=] {
            audit.global = score;
            audit.scores = scores;
            audit.issues = issues;
            audit.done = true;
            show_audit();
        };
    });
}

void show_issue() {
    auto rows = ui::selected_rows(audit.issues_list);
    if (rows.empty() || rows[0] >= (int)audit.issues.size()) return;
    const Issue& i = audit.issues[rows[0]];
    std::wstring text = i.title + L"\n\n" + i.description + L"\n\nCurrent state: " + i.current_state + L"\nRecommended: " + i.recommended_action + L"\nRisk: " + risk_name(i.risk) +
                        L", points lost: " + std::to_wstring(i.score_impact);
    if (!i.fix_command.empty()) text += L"\n\nTo fix by hand (PowerShell):\n" + i.fix_command;
    if (!i.revert_command.empty()) text += L"\nTo undo:\n" + i.revert_command;
    if (i.requires_reboot) text += L"\n\nA reboot is needed after the change.";
    if (!i.learn_more_url.empty()) text += L"\n\nMore: " + i.learn_more_url;
    ui::set_text(audit.details, text);
}

void view_details() {
    if (!audit.done) {
        ui::info(L"Run the audit first.");
        return;
    }
    std::wstring text = L"Overall score: " + std::to_wstring(audit.global) + L" / 100\n\n";
    for (const auto& [domain, s] : audit.scores) {
        text += std::wstring(domain_name(domain)) + L": " + std::to_wstring(s.current_score) + L" / " + std::to_wstring(s.max_score) + L"  " + s.status() + L"\n";
        if (s.issues.empty()) text += L"    nothing to report\n";
        for (const auto& i : s.issues) text += L"    - [" + std::wstring(risk_name(i.risk)) + L"] " + i.title + L" (" + i.current_state + L", -" + std::to_wstring(i.score_impact) + L")\n";
        text += L"\n";
    }
    ui::show_text(L"Security audit details", text, 820, 560);
}

// A saved state: hardening profile or advanced tweaks
struct BackupFile {
    std::wstring path, kind, when;
    int settings = 0;
};

std::vector<BackupFile> all_backups() {
    std::vector<Entry> files;
    std::vector<BackupFile> out;
    if (!list_dir(hardening_backup_dir(), files)) return out;
    std::stable_sort(files.begin(), files.end(), [](const Entry& a, const Entry& b) { return a.modified > b.modified; });
    for (const Entry& f : files) {
        if (f.is_dir() || !ends_with(f.name, L".json")) continue;
        BackupFile b;
        b.path = f.path;
        b.when = f.name;
        if (starts_with(f.name, L"tweaks_backup_")) {
            b.kind = L"Advanced tweaks";
            try {
                b.settings = (int)revert_commands_from_snapshot(f.path).size();
            } catch (const std::exception&) {
                b.kind = L"Unreadable backup";
            }
        } else if (starts_with(f.name, L"hardening_backup_")) {
            Backup data;
            HardeningEngine reader;
            if (reader.load_backup(f.path, data)) {
                b.kind = L"Hardening profile: " + data.profile;
                b.settings = (int)data.entries.size();
            } else {
                b.kind = L"Unreadable backup";
            }
        } else {
            continue;
        }
        out.push_back(b);
    }
    return out;
}

void run_tweak_commands(const std::vector<std::pair<std::wstring, std::wstring>>& commands, const std::wstring& title);

void undo_change() {
    if (!ui::elevated()) {
        ui::warn(L"Undoing changes requires administrator rights.");
        return;
    }
    auto backups = all_backups();
    if (backups.empty()) {
        if (ui::confirm(L"No backup found.\n\nReset the advanced tweaks (services, Windows Script Host, script file associations) to Windows 10 defaults?", L"No backup")) {
            run_tweak_commands(win10_default_restore(), L"Reset to Windows 10 defaults");
        }
        return;
    }
    ui::DialogSpec spec;
    spec.title = L"Undo a change";
    spec.prompt = L"Choose the change to undo: the state saved just before it is restored.";
    spec.body = ui::DialogSpec::List;
    spec.columns = {{L"Change", 280}, {L"Settings", 80, true}, {L"File", 400}};
    for (const auto& b : backups) spec.rows.push_back({b.kind, std::to_wstring(b.settings), base_name(b.path)});
    spec.buttons = {{L"Undo this change...", 1}, {L"Cancel", 0}};
    spec.width = 820;
    spec.height = 420;
    auto choice = ui::run_dialog(spec);
    if (choice.button != 1 || choice.row < 0 || choice.row >= (int)backups.size()) return;
    const BackupFile& b = backups[choice.row];
    if (starts_with(base_name(b.path), L"tweaks_backup_")) {
        std::vector<std::pair<std::wstring, std::wstring>> commands;
        try {
            commands = revert_commands_from_snapshot(b.path);
        } catch (const std::exception& e) {
            ui::warn(L"Invalid backup: " + wide(e.what()));
            return;
        }
        if (ui::confirm(L"Restore " + std::to_wstring(commands.size()) + L" setting(s) to the state saved in:\n" + b.path + L"?", L"Undo advanced tweaks", true)) run_tweak_commands(commands, L"Undo advanced tweaks");
        return;
    }
    if (!ui::confirm(L"Restore the state saved in:\n" + b.path + L"?", L"Undo hardening profile", true)) return;
    std::wstring path = b.path;
    ui::run_async(L"Restoring the saved state...", [path](const Stop&, const Progress&) {
        HardeningEngine engine;
        auto result = engine.revert_backup(path);
        return [result] {
            ui::info(L"✅ " + std::to_wstring(result.first) + L" setting(s) restored\n❌ " + std::to_wstring(result.second) + L" failure(s)");
            run_audit();
        };
    });
}

void apply_profile_flow() {
    if (!ui::elevated()) {
        ui::warn(L"Hardening needs administrator rights.\nRestart the application as administrator.");
        return;
    }
    ui::DialogSpec spec;
    spec.title = L"Apply a hardening profile";
    spec.prompt = L"Choose a profile. Each change is saved first, so it can be undone exactly (Undo a change).";
    spec.body = ui::DialogSpec::List;
    spec.columns = {{L"Profile", 140}, {L"Changes", 70, true}, {L"What it does", 520}};
    const Profile profiles[] = {Profile::Basic, Profile::Recommended, Profile::Strict};
    const wchar_t* about[] = {L"Defender on, firewall on, Guest account off, no automatic logon.",
                              L"Basic + block anonymous SAM access, disable the built-in Administrator, WDigest off, SMBv1 server off.",
                              L"Recommended + RDP off, NTLMv2 only (can break old NAS), maximum UAC, Remote Registry off, NetBIOS off (can break workgroup browsing)."};
    for (int i = 0; i < 3; ++i) spec.rows.push_back({profile_name(profiles[i]), std::to_wstring(profile_action_count(profiles[i])), about[i]});
    spec.buttons = {{L"Choose the changes...", 1}, {L"Cancel", 0}};
    spec.width = 800;
    spec.height = 380;
    auto choice = ui::run_dialog(spec);
    if (choice.button != 1 || choice.row < 0 || choice.row > 2) return;
    Profile profile = profiles[choice.row];

    ui::DialogSpec second;
    second.title = L"Changes of the " + std::wstring(profile_name(profile)) + L" profile";
    second.prompt = L"Untick the changes you do not want.";
    second.body = ui::DialogSpec::List;
    second.columns = {{L"Change", 420}, {L"Kind", 120}};
    second.checks = true;
    auto actions = profile_actions(profile);
    for (const auto& a : actions) {
        second.rows.push_back({a.title, a.kind});
        second.checked.push_back(true);
    }
    second.buttons = {{L"Apply...", 1}, {L"Cancel", 0}};
    second.width = 640;
    second.height = 480;
    auto picked = ui::run_dialog(second);
    if (picked.button != 1) return;
    std::vector<std::wstring> ids;
    for (std::size_t i = 0; i < actions.size() && i < picked.checked.size(); ++i) {
        if (picked.checked[i]) ids.push_back(actions[i].id);
    }
    if (ids.empty()) return;
    if (!ui::confirm(L"Apply " + std::to_wstring(ids.size()) + L" change(s) of the " + std::wstring(profile_name(profile)) +
                         L" profile?\n\nA system restore point is attempted and the previous values are saved to a backup file before anything changes. Some changes need a reboot.",
                     L"Apply the hardening profile", true))
        return;
    ui::run_async(L"Applying the hardening profile...", [profile, ids](const Stop&, const Progress&) {
        HardeningEngine engine;
        ApplyResult r = engine.apply_profile(profile, ids, true, false);
        std::wstring backup = engine.last_backup_path, restore = engine.last_restore_point_message;
        return [r, backup, restore] {
            std::wstring text = L"✅ " + std::to_wstring(r.success) + L" change(s) applied\n❌ " + std::to_wstring(r.failures) + L" failure(s)\n\nRestore point: " + restore + L"\nBackup: " + backup + L"\n";
            for (const auto& e : r.errors) text += L"\n" + e;
            ui::show_text(L"Hardening result", text, 760, 460);
            run_audit();
        };
    });
}

void build_audit() {
    ui::Page& p = ui::add_page(L"Security", L"Audit");
    audit.page = &p;
    p.button(L"Run full audit", run_audit, 130);
    p.button(L"Apply hardening profile...", apply_profile_flow, 200);
    p.button(L"View details", view_details, 110, false);
    p.button(L"Undo a change...", undo_change, 140);
    audit.score = p.label(L"Overall security score: not measured yet", ui::FILL);
    audit.domains = p.list({{L"Domain", 150}, {L"Score", 100, true}, {L"Status", 200}}, 2);
    ui::ListEvents ev;
    ev.on_select = show_issue;
    audit.issues_list = p.list({{L"Risk", 110}, {L"Domain", 90}, {L"Issue", 320}, {L"State", 220}, {L"Points", 60, true}, {L"Recommended", 420}}, 3, false, ev);
    audit.details = p.text(2);
    p.on_refresh = run_audit;
    p.set_summary(L"The audit only reads (registry and Get-* cmdlets). Hardening changes settings: it asks first, and saves the previous values.");
}

// endregion

// region Advanced tweaks

struct TweakPage {
    ui::Page* page = nullptr;
    HWND preset = nullptr, list = nullptr, output = nullptr;
    std::vector<Tweak> tweaks;
} tw;

void load_preset() {
    int sel = ui::combo_index(tw.preset);
    const auto& names = tweak_preset_names();
    if (sel < 0 || sel >= (int)names.size()) return;
    tw.tweaks = tweak_preset(names[sel]);
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& t : tw.tweaks) rows.push_back({t.category, t.name, t.risk, t.description, t.command});
    ui::set_rows(tw.list, rows);
    bool custom = names[sel] == L"Custom";   // "Custom" lists every tweak, unchecked
    for (std::size_t i = 0; i < tw.tweaks.size(); ++i) ui::set_checked(tw.list, (int)i, !custom);
    tw.page->set_summary(L"Tweak set loaded: " + names[sel] + L" (" + std::to_wstring(tw.tweaks.size()) + L" tweaks).");
}

void run_tweak_commands(const std::vector<std::pair<std::wstring, std::wstring>>& commands, const std::wstring& title) {
    if (commands.empty()) {
        ui::info(L"Nothing to apply.");
        return;
    }
    std::wstring snapshot = snapshot_tweaks(commands, hardening_backup_dir());
    if (snapshot.empty()) {
        ui::warn(L"Could not save the current state (hardening backups).\nNothing was changed.");
        return;
    }
    ui::select_page(L"Security", L"Advanced tweaks");
    ui::set_text(tw.output, L"=== " + title + L": " + std::to_wstring(commands.size()) + L" command(s) ===\nState saved to: " + snapshot + L"\n");
    ui::run_async(title + L"...", [commands](const Stop& stop, const Progress&) {
        auto emit = [](const std::wstring& text) { ui::post_job([text] { ui::append_text(tw.output, text); }); };
        emit(L"Creating a system restore point...\n");
        HardeningEngine engine;
        emit(engine.create_restore_point(L"DD Cleaner - Advanced tweaks") ? L"Restore point created\n" : L"Restore point not created (System Protection off or one already created in the last 24 h). The saved state still allows an undo.\n");
        TweakRunResult r = run_tweaks(commands, emit, stop);
        return [r] {
            ui::append_text(tw.output, L"\n=== Completed: " + std::to_wstring(r.ok) + L" ok, " + std::to_wstring(r.failed) + L" failed ===\nA reboot is recommended for all changes to take effect.\n");
            ui::set_status(L"Tweaks done. Reboot recommended.");
        };
    });
}

void apply_tweaks() {
    if (!ui::elevated()) {
        ui::warn(L"Hardening tweaks require administrator privileges.\n\nPlease restart the application as administrator.");
        return;
    }
    std::vector<std::pair<std::wstring, std::wstring>> chosen;
    for (std::size_t i = 0; i < tw.tweaks.size(); ++i) {
        if (ui::is_checked(tw.list, (int)i)) chosen.emplace_back(tw.tweaks[i].name, open_in_editor(tw.tweaks[i].command));
    }
    if (chosen.empty()) {
        ui::info(L"Tick the tweaks to apply first.");
        return;
    }
    std::wstring ask = L"Apply " + std::to_wstring(chosen.size()) + L" tweak(s)?\n\n";
    for (std::size_t i = 0; i < chosen.size() && i < 12; ++i) ask += L"• " + chosen[i].first + L"\n";
    if (chosen.size() > 12) ask += L"... and " + std::to_wstring(chosen.size() - 12) + L" more\n";
    ask += L"\nThe current state is saved first, so Undo a change can put it back. Some tweaks need a reboot.";
    if (!ui::confirm(ask, L"Apply tweaks", true)) return;
    run_tweak_commands(chosen, L"Applying tweaks");
}

void scan_telemetry() {
    if (!ui::confirm(L"Watch network connections for 30 seconds?\n\nRemote IP addresses are matched to host names using the DNS cache, then filtered on Microsoft / Windows / Office / telemetry domains.\n\nNothing is blocked or modified. Continue?", L"Telemetry scan")) return;
    ui::append_text(tw.output, L"\nWatching connections (30 seconds)...\n");
    ui::run_async(L"Telemetry scan (30 s)...", [](const Stop& stop, const Progress&) {
        auto emit = [](const std::wstring& text) { ui::post_job([text] { ui::append_text(tw.output, text); }); };
        TelemetryResult r = telemetry_scan(30000, 3000, stop, nullptr, emit);
        return [r] {
            ui::append_text(tw.output, r.report());
            ui::set_status(L"Telemetry scan completed.");
        };
    });
}

void build_tweaks() {
    ui::Page& p = ui::add_page(L"Security", L"Advanced tweaks");
    tw.page = &p;
    p.label(L"Tweak set:", 90);
    std::vector<std::wstring> names = tweak_preset_names();
    tw.preset = p.combo(names, 0, 200);
    p.button(L"Load", load_preset, 80, false);
    p.button(L"Tick all", [] { ui::set_all_checked(tw.list, true); }, 80, false);
    p.button(L"Untick all", [] { ui::set_all_checked(tw.list, false); }, 90, false);
    p.button(L"Apply ticked tweaks...", apply_tweaks, 180, true, true);
    p.button(L"Scan telemetry (30 s)...", scan_telemetry, 190, true, true);
    tw.list = p.list({{L"Category", 100}, {L"Tweak", 200}, {L"Risk", 70}, {L"What it does", 420}, {L"Command", 380}}, 3, true);
    tw.output = p.text(2);
    p.on_show = [] {
        if (tw.tweaks.empty()) load_preset();
    };
    p.on_refresh = load_preset;
    p.set_summary(L"Services, Windows Script Host and script file associations. The current state is saved before anything is applied.");
}

// endregion

}  // namespace

void build_security_pages() {
    build_audit();
    build_tweaks();
}
