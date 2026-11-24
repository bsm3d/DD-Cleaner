// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the read-only security audit and the hardening step, which writes a JSON snapshot before any change.

// Audit en lecture seule (registre et cmdlets Get-* en JSON, aucun texte localisé analysé).
// Le durcissement écrit un JSON de sauvegarde (hardening_backup_<timestamp>.json) AVANT tout changement, pour un retour exact.
// Le retour utilise toujours les définitions d'actions intégrées, jamais les chemins relus d'une sauvegarde modifiée.
#pragma once

#include <functional>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>
#include <ddcore/proc.hpp>

namespace dd {

// region Hooks
struct RegistryState {   // one registry value as read: missing, or its type and data
    bool exists = false;
    unsigned long type = 0;
    std::wstring text;           // REG_SZ / REG_EXPAND_SZ
    unsigned long long number = 0;   // REG_DWORD / REG_QWORD
    std::string raw;
    bool numeric() const;        // a DWORD or QWORD, or a string holding a number
    long long as_int() const;
};

// Everything the audit and the hardening engine do to the system goes through these functions: the defaults really query and change
// Windows, tests replace them with a fake system.
struct RegistryAccess {
    std::function<RegistryState(const std::wstring& hive, const std::wstring& path, const std::wstring& name)> read;
    std::function<bool(const std::wstring& hive, const std::wstring& path, const std::wstring& name, unsigned long type, const std::string& bytes)> write;
    std::function<bool(const std::wstring& hive, const std::wstring& path, const std::wstring& name)> remove;
    std::function<std::vector<std::wstring>(const std::wstring& hive, const std::wstring& path)> subkeys;
    std::function<bool(const std::wstring& hive, const std::wstring& path)> key_exists;
};
struct SystemHooks {
    std::function<PsJson(const std::wstring& script, unsigned long timeout_ms)> ps_json;   // PowerShell that prints JSON (rc and data)
    std::function<int(const std::wstring& script)> ps;                                       // PowerShell, exit code only
    std::function<int(const std::vector<std::wstring>& argv)> run_exe;                       // an absolute-path program, exit code
    std::function<bool()> remote_session;
    RegistryAccess registry;
};
SystemHooks& system_hooks();   // starts with the real implementations
// endregion

// region Audit
enum class Risk { Low, Medium, High, Critical };
enum class Domain { System, Accounts, Network, Data };
enum class Profile { Basic, Recommended, Strict };

const wchar_t* risk_name(Risk r);       // Low | Medium | High | Critical
const wchar_t* domain_name(Domain d);   // System | Accounts | Network | Data
const wchar_t* profile_name(Profile p); // Basic | Recommended | Strict
// Names stored by older versions (French) and member names are accepted too. False when unknown.
bool parse_risk(const std::wstring& text, Risk& out);
bool parse_domain(const std::wstring& text, Domain& out);
bool parse_profile(const std::wstring& text, Profile& out);

struct Issue {
    std::wstring id, title, description;
    Domain domain = Domain::System;
    Risk risk = Risk::Low;
    std::wstring current_state, recommended_action;
    int score_impact = 0;   // points lost out of the domain total
    std::wstring fix_command, revert_command;
    bool requires_reboot = false;
    std::wstring learn_more_url;
};

struct DomainScore {
    Domain domain = Domain::System;
    int current_score = 0, max_score = 0;
    std::vector<Issue> issues;
    double percentage() const;
    std::wstring status() const;   // "🟢 Excellent" | "🟡 Fair" | "🟠 Medium" | "🔴 Critical"
};

constexpr int SYSTEM_MAX_SCORE = 25 + 3 + 2 + 4;
constexpr int NETWORK_MAX_SCORE = 30 + 6 + 2;
extern const std::map<Domain, int> DOMAIN_WEIGHTS;   // 25 / 25 / 30 / 20

RegistryState read_registry_state(const std::wstring& hive, const std::wstring& path, const std::wstring& name);

class SecurityAuditor {
public:
    // Runs every check. Returns the global score (0..100); domain results are in domain_scores().
    int run_full_audit(const Progress& progress = nullptr);
    const std::vector<Issue>& issues() const { return issues_; }
    const std::map<Domain, DomainScore>& domain_scores() const { return scores_; }
    // High and critical issues, the riskiest first, then by points lost.
    std::vector<Issue> critical_issues(std::size_t limit = 5) const;
    static int global_score(const std::map<Domain, DomainScore>& scores);

    // The individual checks (null result = nothing to report), exposed so they can be tested one by one.
    bool check_defender(Issue& out);
    bool check_firewall(Issue& out);
    bool check_windows_update(Issue& out);
    bool check_uac(Issue& out);
    std::vector<Issue> check_risky_services();
    bool check_memory_integrity(Issue& out);
    bool check_lsass_protection(Issue& out);
    bool check_wdigest(Issue& out);
    bool check_builtin_admin(const Json& builtin, Issue& out);
    bool check_guest_account(const Json& builtin, Issue& out);
    bool check_autologon(Issue& out);
    bool check_screen_lock(Issue& out);
    bool check_empty_passwords(Issue& out);
    bool check_rdp_exposure(Issue& out);
    bool check_smb_exposure(Issue& out);
    bool check_anonymous_sam(Issue& out);
    bool check_smb1(Issue& out);
    bool check_netbios(Issue& out);
    bool check_ntlmv2(Issue& out);
    bool check_bitlocker(Issue& out, bool& unavailable);
    bool check_restore_points(Issue& out);
    bool check_windows_backup(Issue& out);
    Json builtin_accounts();   // {"admin": {...}, "guest": {...}} from Get-LocalUser, null when it failed

private:
    void record_domain(Domain domain, int max_score, const std::vector<Issue>& issues);
    std::vector<Issue> work_issues_, issues_;
    std::map<Domain, DomainScore> work_scores_, scores_;
    std::mutex lock_;
};
// endregion

// region Hardening
struct ActionValue {
    std::wstring name;
    unsigned long type;       // REG_DWORD or REG_SZ
    std::wstring text;        // REG_SZ data
    unsigned long number;     // REG_DWORD data
};

struct Action {
    std::wstring id, title, kind;   // kind: defender | firewall | account | registry | service | smb1 | netbios
    int rid = 0;                    // account
    std::wstring hive, key;         // registry
    std::vector<ActionValue> values;
    std::wstring service;           // service
    int start = 0;
    bool stop = false;
};

int profile_action_count(Profile profile);
std::vector<Action> profile_actions(Profile profile);   // copies of the built-in definitions
const Action* find_action(const std::wstring& id);

struct BackupEntry {
    std::wstring id, title, kind;
    Json before;
    std::wstring status;    // pending | snapshot_failed | skipped | failed | applied | reverted | revert_failed
    std::wstring message;
};

struct Backup {
    int version = 1;
    std::wstring created, profile;
    bool restore_point_ok = false;
    std::wstring restore_point_message;
    std::vector<BackupEntry> entries;
    std::wstring reverted;
    Json to_json() const;
    static bool from_json(const Json& data, Backup& out);
};

std::wstring hardening_backup_dir();
std::vector<std::wstring> list_hardening_backups();   // newest first


struct ApplyResult {
    int success = 0, failures = 0;
    std::vector<std::wstring> errors;
};

class HardeningEngine {
public:
    std::wstring last_backup_path;
    bool last_restore_point_ok = false;
    std::wstring last_restore_point_message;
    std::vector<std::wstring> last_skipped;

    bool create_restore_point(const std::wstring& description = L"DD Cleaner - Security hardening");
    ApplyResult apply_profile(Profile profile, const std::vector<std::wstring>& custom_actions = {}, bool create_restore = true, bool require_restore = false);
    bool revert_action(const std::wstring& action_id);
    std::pair<int, int> revert_last();                          // (reverted, failed)
    std::pair<int, int> revert_backup(const std::wstring& path);

    // exposed for tests
    std::wstring precheck(const Action& action, const Json& before);
    bool apply_action(const Action& action, const Json& before);
    Json snapshot(const Action& action);   // throws std::runtime_error
    bool revert_entry(const BackupEntry& entry);
    bool load_backup(const std::wstring& path, Backup& out);
    static bool restore_reg_value(const std::wstring& hive, const std::wstring& path, const std::wstring& name, const Json& state, int expected_type = -1);

private:
    std::wstring builtin_admin_safety(const std::wstring& admin_sid);
    std::wstring write_new_backup(const Backup& backup);
    bool save_backup(const std::wstring& path, const Backup& backup);
    std::wstring find_backup_with(const std::wstring& action_id);
    std::recursive_mutex lock_;
};
// endregion

}  // namespace dd
