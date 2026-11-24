// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Driver Checker page group: vulnerable drivers from the Microsoft blocklist, driver age, unused drivers and uninstall.

#include "pages.hpp"

#include <algorithm>
#include <ctime>
#include <set>

#include <shellapi.h>

#include <ddcore/blocklist.hpp>
#include <ddcore/drivers.hpp>
#include <ddcore/proc.hpp>
#include <ddcore/sysinfo.hpp>

using namespace dd;

namespace {

// region Vulnerable drivers

struct VulnPage {
    ui::Page* page = nullptr;
    HWND list = nullptr, protection = nullptr, blocklist = nullptr;
    BlocklistPolicy policy;
    bool have_policy = false;
    std::vector<DriverCheck> checks;
} vuln;

void show_blocklist_info() {
    std::map<std::wstring, std::wstring> meta;
    BlocklistPolicy loaded;
    vuln.have_policy = false;
    try {
        vuln.have_policy = load_policy(loaded, meta);
    } catch (const std::exception&) {
    }
    if (!vuln.have_policy) {
        SetWindowTextW(vuln.blocklist, L"Microsoft blocklist: not downloaded yet.");
        return;
    }
    vuln.policy = loaded;
    std::wstring text = L"Microsoft blocklist " + loaded.version + L" (" + std::to_wstring(loaded.rule_count()) + L" rules)";
    auto downloaded = meta.find(L"downloaded");
    if (downloaded != meta.end() && downloaded->second.size() >= 10) {
        text += L", downloaded " + downloaded->second.substr(0, 10);
        double t = parse_time(downloaded->second.substr(0, 19));
        if (t > 0) {
            int age = (int)((double)time(nullptr) - t) / 86400;
            if (age > 90) text += L" (" + std::to_wstring(age) + L" days old, consider updating)";
        }
    }
    SetWindowTextW(vuln.blocklist, text.c_str());
}

void show_protection() {
    try {
        ProtectionState st = protection_state();
        SetWindowTextW(vuln.protection, (st.summary() + (st.enforced() ? L"" : L"   (Memory integrity / the blocklist setting is not enforcing it: see Core isolation)")).c_str());
    } catch (const std::exception&) {
        SetWindowTextW(vuln.protection, L"Windows protection state could not be read.");
    }
}

void download_blocklist_now() {
    ui::run_async(L"Downloading the Microsoft vulnerable driver blocklist...", [](const Stop&, const Progress&) {
        std::wstring error;
        try {
            download_blocklist();
        } catch (const std::exception& e) {
            error = wide(e.what());
        }
        return [error] {
            if (!error.empty()) ui::warn(L"The blocklist could not be downloaded:\n" + error);
            else ui::set_status(L"Blocklist downloaded.");
            show_blocklist_info();
        };
    });
}

void check_vulnerable() {
    if (!vuln.have_policy) {
        if (ui::confirm(L"The Microsoft blocklist has not been downloaded yet. Download it now? (about 1 MB, from aka.ms/VulnerableDriverBlockList)", L"Blocklist needed")) download_blocklist_now();
        return;
    }
    BlocklistPolicy policy = vuln.policy;
    ui::run_async(L"Checking the drivers against the blocklist...", [policy](const Stop& stop, const Progress& progress) {
        auto files = collect_driver_files();
        auto checks = check_drivers(policy, files, [progress](std::size_t done, std::size_t total, const std::wstring& name) {
            progress(L"Checking " + std::to_wstring(done) + L"/" + std::to_wstring(total) + L": " + name);
        }, stop);
        return [checks] {
            vuln.checks = checks;
            std::vector<std::size_t> order(checks.size());
            for (std::size_t i = 0; i < order.size(); ++i) order[i] = i;
            std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return checks[a].flagged() > checks[b].flagged(); });
            std::vector<std::vector<std::wstring>> rows;
            int flagged = 0;
            std::vector<DriverCheck> sorted;
            for (auto i : order) {
                const DriverCheck& c = checks[i];
                sorted.push_back(c);
                std::wstring reason;
                for (const auto& r : c.reasons) reason += (reason.empty() ? L"" : L"; ") + r;
                flagged += c.flagged();
                std::wstring version;
                for (std::size_t k = 0; k < c.info.version.size(); ++k) version += (k ? L"." : L"") + std::to_wstring(c.info.version[k]);
                rows.push_back({c.flagged() ? L"\U0001F534 Listed" : L"✅ OK", base_name(c.driver.path), c.driver.state(), c.driver.service, c.info.signer(), version, reason, c.driver.path});
            }
            vuln.checks = sorted;
            ui::set_rows(vuln.list, rows);
            vuln.page->set_summary(std::to_wstring(checks.size()) + L" drivers checked, " + std::to_wstring(flagged) +
                                   (flagged ? L" listed in the Microsoft blocklist: Windows refuses to load them when the blocklist is enforced." : L" listed. Nothing found."));
        };
    });
}

void build_vulnerable() {
    ui::Page& p = ui::add_page(L"Driver Checker", L"Vulnerable drivers");
    vuln.page = &p;
    p.label(L"Windows protection:", 130);
    vuln.protection = p.label(L"", ui::FILL);
    p.newline();
    vuln.blocklist = p.label(L"", ui::FILL);
    p.newline();
    p.button(L"Check drivers", check_vulnerable, 130);
    p.button(L"Download latest blocklist", download_blocklist_now, 190);
    p.button(L"Open Core isolation settings", [] {
        ShellExecuteW(ui::main_window(), L"open", L"windowsdefender://coreisolation", nullptr, nullptr, SW_SHOWNORMAL);
    }, 210, false);
    p.button(L"Open location", [] {
        auto rows = ui::selected_rows(vuln.list);
        if (!rows.empty() && rows[0] < (int)vuln.checks.size()) ui::reveal(vuln.checks[rows[0]].driver.path);
    }, 110, false);
    p.button(L"Export", [] { ui::export_list(vuln.list, L"vulnerable_drivers.csv"); }, 80, false);
    ui::ListEvents ev;
    ev.on_activate = [](int row) {
        if (row < (int)vuln.checks.size()) ui::reveal(vuln.checks[row].driver.path);
    };
    vuln.list = p.list({{L"Verdict", 90}, {L"Driver", 170}, {L"State", 130}, {L"Service", 130}, {L"Signer", 200}, {L"Version", 110}, {L"Rule", 260}, {L"Path", 420}}, 4, false, ev);
    p.on_show = [] {
        show_protection();
        show_blocklist_info();
    };
    p.on_refresh = check_vulnerable;
    p.set_summary(L"Compares the drivers on this PC with Microsoft's list of known vulnerable drivers. Nothing is changed.");
}

// endregion

// region Driver age

struct AgeDriver {
    std::wstring name, date, version, provider, inf, class_name;
    int age_days = 0;
};

struct AgePage {
    ui::Page* page = nullptr;
    HWND list = nullptr, filter = nullptr;
    std::vector<AgeDriver> drivers, shown;
} age;

void fill_age() {
    static const int days[] = {0, 365, 730, 1095, 1825};
    int sel = ui::combo_index(age.filter);
    int min_days = days[sel < 0 ? 0 : sel];
    age.shown.clear();
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& d : age.drivers) {
        if (d.age_days < min_days) continue;
        age.shown.push_back(d);
        wchar_t years[32];
        swprintf(years, 32, L"%.1f years", d.age_days / 365.25);
        rows.push_back({d.name, d.date, years, d.version, d.provider, d.class_name, d.inf});
    }
    ui::set_rows(age.list, rows);
    age.page->set_summary(std::to_wstring(rows.size()) + L" of " + std::to_wstring(age.drivers.size()) + L" third-party drivers shown.");
}

void scan_age() {
    ui::run_async(L"Listing the third-party drivers...", [](const Stop&, const Progress&) {
        Json raw = run_powershell_json(
            L"Get-CimInstance Win32_PnPSignedDriver | Where-Object { $_.InfName -like 'oem*.inf' } | Select-Object DeviceName, DriverVersion, DriverProviderName, InfName, DeviceClass, "
            L"@{n='Date';e={ if ($_.DriverDate) { $_.DriverDate.ToString('yyyy-MM-dd') } else { '' } }} | ConvertTo-Json -Compress",
            120000);
        std::vector<AgeDriver> drivers;
        std::set<std::wstring> seen;
        double now = (double)time(nullptr);
        for (const Json& d : raw.as_list()) {
            std::wstring inf = d.get(L"InfName").str(), key = inf + L"|" + d.get(L"DriverVersion").str() + L"|" + d.get(L"DeviceName").str();
            if (!seen.insert(key).second) continue;
            double t = parse_time(d.get(L"Date").str() + L"T00:00:00");
            if (t <= 0) continue;
            AgeDriver a;
            a.name = d.get(L"DeviceName").str().empty() ? inf : d.get(L"DeviceName").str();
            a.date = d.get(L"Date").str();
            a.version = d.get(L"DriverVersion").str();
            a.provider = d.get(L"DriverProviderName").str();
            a.inf = inf;
            a.class_name = d.get(L"DeviceClass").str();
            a.age_days = (int)((now - t) / 86400);
            drivers.push_back(a);
        }
        std::sort(drivers.begin(), drivers.end(), [](const AgeDriver& a, const AgeDriver& b) { return a.age_days > b.age_days; });
        bool failed = raw.is_null();
        return [drivers, failed] {
            if (failed) ui::warn(L"The driver list could not be read (PowerShell error or timeout).");
            age.drivers = drivers;
            fill_age();
        };
    });
}

void build_age() {
    ui::Page& p = ui::add_page(L"Driver Checker", L"Driver age");
    age.page = &p;
    p.button(L"Scan drivers", scan_age, 120);
    p.button(L"Export", [] { ui::export_list(age.list, L"driver_age.csv"); }, 80, false);
    p.label(L"Show only drivers older than:", 190);
    age.filter = p.combo({L"All drivers", L"1 year", L"2 years", L"3 years", L"5 years"}, 0, 120);
    p.on_change(age.filter, fill_age);
    age.list = p.list({{L"Device", 300}, {L"Date", 90}, {L"Age", 90, true}, {L"Version", 130}, {L"Provider", 200}, {L"Class", 120}, {L"INF", 90}}, 4);
    p.on_refresh = scan_age;
    p.set_summary(L"Lists the third-party (oem*.inf) drivers and their dates. Read only. An old driver is not a bad driver: update it only when something is wrong.");
}

// endregion

// region Unused drivers and complete uninstall (the two pages share the removal)

struct DriverList {
    HWND list = nullptr;
    ui::Page* page = nullptr;
    std::vector<Candidate> items;
};
DriverList unused, all_drivers;

std::vector<std::vector<std::wstring>> driver_rows(const std::vector<Candidate>& items) {
    std::vector<std::vector<std::wstring>> rows;
    for (const auto& c : items) {
        rows.push_back({c.package.published, c.package.provider, c.package.class_name, c.package.version, c.package.date, category_name(c.category), c.reason});
    }
    return rows;
}

void fill_drivers(DriverList& dl, bool tick_safe) {
    ui::set_rows(dl.list, driver_rows(dl.items));
    for (std::size_t i = 0; i < dl.items.size(); ++i) {
        bool safe = std::wstring(category_risk(dl.items[i].category)) == L"Safe";
        ui::set_checked(dl.list, (int)i, tick_safe && safe);
    }
}

std::vector<Candidate> ticked(DriverList& dl) {
    std::vector<Candidate> out;
    for (std::size_t i = 0; i < dl.items.size(); ++i) {
        if (ui::is_checked(dl.list, (int)i)) out.push_back(dl.items[i]);
    }
    return out;
}

std::wstring package_lines(const std::vector<Candidate>& chosen, std::size_t limit = 12) {
    std::wstring text;
    for (std::size_t i = 0; i < chosen.size() && i < limit; ++i) text += L"• " + chosen[i].package.published + L"  " + chosen[i].package.provider + L"  " + chosen[i].package.class_name + L"\n";
    if (chosen.size() > limit) text += L"... and " + std::to_wstring(chosen.size() - limit) + L" more\n";
    return text;
}

void find_unused_now() {
    ui::run_async(L"Looking for driver packages that nothing uses...", [](const Stop&, const Progress&) {
        std::vector<Candidate> found;
        std::wstring error;
        try {
            found = dd::scan_unused();
        } catch (const std::exception& e) {
            error = wide(e.what());
        }
        return [found, error] {
            if (!error.empty()) {
                ui::warn(L"The scan could not judge the drivers safely:\n" + error);
                return;
            }
            unused.items = found;
            fill_drivers(unused, true);
            unused.page->set_summary(std::to_wstring(found.size()) + L" driver packages that no connected device uses. The safe ones are ticked.");
        };
    });
}

void remove_unused() {
    auto chosen = ticked(unused);
    if (chosen.empty()) {
        ui::info(L"Tick the driver packages to remove first.");
        return;
    }
    if (!ui::elevated()) {
        ui::warn(L"Removing driver packages needs administrator rights.\nRestart the application as administrator.");
        return;
    }
    if (!ui::confirm(L"Remove " + std::to_wstring(chosen.size()) + L" driver packages from the driver store?\n\n" + package_lines(chosen) +
                         L"\nEach package is saved first (pnputil /export-driver) so it can be put back with pnputil /add-driver. Windows itself refuses a package that is still in use.",
                     L"Remove the ticked drivers", true))
        return;
    ui::run_async(L"Removing driver packages...", [chosen](const Stop& stop, const Progress&) {
        DriverRemoval r = remove_packages(chosen, L"", run_pnputil, stop);
        return [r] {
            std::set<std::wstring> gone;
            for (const auto& c : r.removed) gone.insert(lower(c.package.published));
            std::vector<Candidate> keep;
            for (const auto& c : unused.items) {
                if (!gone.count(lower(c.package.published))) keep.push_back(c);
            }
            unused.items = keep;
            fill_drivers(unused, false);
            unused.page->set_summary(std::to_wstring(r.removed.size()) + L" removed, " + std::to_wstring(r.backups.size()) + L" backup(s). " + std::to_wstring(keep.size()) + L" left.");
            if (!r.failed.empty()) {
                std::wstring text = std::to_wstring(r.failed.size()) + L" packages were not removed:\n\n";
                for (const auto& f : r.failed) text += f.first.package.published + L": " + f.second + L"\n";
                ui::warn(text);
            }
        };
    });
}

void list_all_drivers() {
    ui::run_async(L"Listing every driver package...", [](const Stop&, const Progress&) {
        std::vector<Candidate> found;
        std::wstring error;
        try {
            found = dd::scan_all();
        } catch (const std::exception& e) {
            error = wide(e.what());
        }
        return [found, error] {
            if (!error.empty()) {
                ui::warn(L"The drivers could not be listed:\n" + error);
                return;
            }
            all_drivers.items = found;
            fill_drivers(all_drivers, false);
            all_drivers.page->set_summary(std::to_wstring(found.size()) + L" driver packages. Tick the ones to uninstall completely.");
        };
    });
}

void uninstall_completely_now() {
    auto chosen = ticked(all_drivers);
    if (chosen.empty()) {
        ui::info(L"Tick the driver packages to uninstall first.");
        return;
    }
    if (!ui::elevated()) {
        ui::warn(L"Uninstalling driver packages needs administrator rights.\nRestart the application as administrator.");
        return;
    }
    int in_use = 0;
    for (const auto& c : chosen) in_use += c.in_use();
    std::wstring ask = L"Uninstall " + std::to_wstring(chosen.size()) + L" driver packages completely?\n\n" + package_lines(chosen);
    if (in_use) ask += L"\n" + std::to_wstring(in_use) + L" of them are IN USE by a connected device: that device may stop working until you install a driver again.";
    ask += L"\n\nThe package files are saved first. The service and .sys file a package leaves behind are listed afterwards: nothing more is deleted without your confirmation.";
    if (!ui::confirm(ask, L"Uninstall completely", true)) return;
    ui::run_async(L"Uninstalling driver packages...", [chosen](const Stop& stop, const Progress&) {
        std::vector<Package> remaining = list_packages();
        UninstallResult r = uninstall_completely(chosen, remaining, L"", run_pnputil, nullptr, stop);
        return [r] {
            std::set<std::wstring> gone;
            for (const auto& c : r.removed) gone.insert(lower(c.package.published));
            std::vector<Candidate> keep;
            for (const auto& c : all_drivers.items) {
                if (!gone.count(lower(c.package.published))) keep.push_back(c);
            }
            all_drivers.items = keep;
            fill_drivers(all_drivers, false);
            std::wstring text = std::to_wstring(r.removed.size()) + L" packages removed, " + std::to_wstring(r.ghosts_removed) + L" entries of devices that are not connected cleaned.";
            if (!r.failed.empty()) {
                text += L"\n\n" + std::to_wstring(r.failed.size()) + L" not removed:\n";
                for (const auto& f : r.failed) text += f.first.package.published + L": " + f.second + L"\n";
            }
            if (r.reboot) text += L"\n\nA reboot is needed to finish.";
            all_drivers.page->set_summary(text.substr(0, text.find(L'\n')));
            if (r.leftovers.empty()) {
                ui::info(text);
                return;
            }
            // what the packages left behind: shown, and removed only if ticked
            ui::DialogSpec spec;
            spec.title = L"Left behind by the removed drivers";
            spec.prompt = text + L"\n\nThese services and files stayed. Tick the ones to delete (both are saved first).";
            spec.body = ui::DialogSpec::List;
            spec.columns = {{L"Service", 180}, {L"File", 400}, {L"File present", 90}, {L"Package", 100}};
            spec.checks = true;
            for (const auto& l : r.leftovers) spec.rows.push_back({l.service, l.image, l.file_exists ? L"yes" : L"no", l.package});
            spec.checked.assign(r.leftovers.size(), false);
            spec.buttons = {{L"Delete ticked", 1}, {L"Keep them", 0}};
            spec.width = 820;
            spec.height = 520;
            auto choice = ui::run_dialog(spec);
            if (choice.button != 1) return;
            std::vector<DriverLeftover> remove;
            for (std::size_t i = 0; i < choice.checked.size() && i < r.leftovers.size(); ++i) {
                if (choice.checked[i]) remove.push_back(r.leftovers[i]);
            }
            if (remove.empty()) return;
            LeftoverRemoval lr = remove_driver_leftovers(remove);
            std::wstring done = std::to_wstring(lr.removed.size()) + L" removed.";
            for (const auto& f : lr.failed) done += L"\n" + f.first.service + L": " + f.second;
            ui::info(done);
        };
    });
}

void build_unused() {
    ui::Page& p = ui::add_page(L"Driver Checker", L"Unused drivers");
    unused.page = &p;
    p.button(L"Find unused drivers", find_unused_now, 160);
    p.button(L"Tick all", [] { for (std::size_t i = 0; i < unused.items.size(); ++i) ui::set_checked(unused.list, (int)i, true); }, 80, false);
    p.button(L"Untick all", [] { ui::set_all_checked(unused.list, false); }, 90, false);
    p.button(L"Backups", [] { ui::reveal(data_subdir(L"driver_backups")); }, 80, false);
    p.button(L"Remove ticked drivers...", remove_unused, 190, true, true);
    unused.list = p.list({{L"Package", 90}, {L"Provider", 200}, {L"Class", 110}, {L"Version", 120}, {L"Date", 90}, {L"Category", 150}, {L"Why", 480}}, 4, true);
    p.on_refresh = find_unused_now;
    p.set_summary(L"Third-party driver packages that no connected device uses: older versions, devices that are gone. Core classes are never offered.");
}

void build_uninstall() {
    ui::Page& p = ui::add_page(L"Driver Checker", L"Uninstall drivers");
    all_drivers.page = &p;
    p.button(L"List all drivers", list_all_drivers, 140);
    p.button(L"Tick the unused", [] {
        for (std::size_t i = 0; i < all_drivers.items.size(); ++i) {
            auto c = all_drivers.items[i].category;
            ui::set_checked(all_drivers.list, (int)i, c == DriverCategory::Old || c == DriverCategory::Gone || c == DriverCategory::None);
        }
    }, 130, false);
    p.button(L"Untick all", [] { ui::set_all_checked(all_drivers.list, false); }, 90, false);
    p.button(L"Backups", [] { ui::reveal(data_subdir(L"driver_backups")); }, 80, false);
    p.button(L"Uninstall completely...", uninstall_completely_now, 190, true, true);
    all_drivers.list = p.list({{L"Package", 90}, {L"Provider", 200}, {L"Class", 110}, {L"Version", 120}, {L"Date", 90}, {L"Category", 150}, {L"Why", 480}}, 4, true);
    p.on_refresh = list_all_drivers;
    p.set_summary(L"Every third-party driver package, used or not. Uninstalling a package in use can stop a device: Windows asks first, and so do we.");
}

// endregion

}  // namespace

void build_driver_pages() {
    build_vulnerable();
    build_age();
    build_unused();
    build_uninstall();
}
