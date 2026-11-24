// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the read-only malware hunt over persistence points and running processes, and the removal of its findings.

// Read-only malware hunt: persistence points (services, tasks, hijacked keys, WMI, hosts, proxy, extensions) and running processes.
// Removal is separate, with a backup first (task as XML, key as .reg). A finding is a reason to look: severity 2 means very unusual, 1 means worth a look.
#pragma once

#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>

namespace dd {

constexpr int SEV_INFO = 0, SEV_LOOK = 1, SEV_SUSPICIOUS = 2;
constexpr std::uint64_t MAX_SIGNED_SIZE = 64u * 1024 * 1024;   // bigger programs are not read for their signature (cost), only listed

struct HuntRemoval {
    std::wstring kind;   // task | service | regvalue; empty = this program does not offer to remove it
    std::vector<std::wstring> args;   // task: name, task path; service: name; regvalue: hive, key, value name
    bool valid() const { return !kind.empty(); }
};

struct HuntFinding {
    std::wstring category, title, detail;
    int severity = SEV_INFO;
    std::wstring path;       // program file to scan, when there is one
    std::wstring location;   // where it is registered
    std::vector<std::wstring> flags;
    HuntRemoval removal;
    bool dead() const;       // the program it starts no longer exists: removing it is the safest kind of cleanup
};

struct ProcessFinding {
    int pid = 0;
    std::wstring name, path, signer;
    int connections = 0;     // established connections to the Internet
    std::vector<std::wstring> flags;
    int severity = SEV_INFO;
};

// region Shared checks
std::wstring risky_location(const std::wstring& path);   // the reason a program should not live here ("" when ordinary)
std::vector<std::pair<std::wstring, int>> suspicious_command(const std::wstring& command);   // (reason, severity)
bool judge_in_windows(const std::wstring& path);
// Files a standard user could plant to be started instead of an unquoted program path with spaces.
std::vector<std::wstring> hijackable_prefixes(const std::wstring& command);

// Signature, packing and folder rights of program files, each file looked at once.
class FileJudge {
public:
    using SignerOf = std::function<std::wstring(const std::wstring&)>;
    using PackedOf = std::function<bool(const std::wstring&)>;
    using WritableOf = std::function<bool(const std::wstring& folder)>;
    FileJudge(SignerOf signer_of = nullptr, PackedOf packed_of = nullptr, WritableOf writable_of = nullptr);
    bool in_windows(const std::wstring& path) const { return judge_in_windows(path); }
    std::wstring signer(const std::wstring& path);   // "" when unsigned or unreadable (Windows files are signed by catalog: not judged)
    bool unsigned_file(const std::wstring& path);
    bool packed(const std::wstring& path);
    bool writable_folder(const std::wstring& path);

private:
    SignerOf signer_of_;
    PackedOf packed_of_;
    WritableOf writable_of_;
    std::map<std::wstring, std::wstring> signers_;
    std::map<std::wstring, bool> packed_, writable_;
};

// (flags, severity) for a program that runs by itself (service, task). elevated: it runs with high rights.
std::pair<std::vector<std::wstring>, int> program_flags(const std::wstring& path, FileJudge& judge, bool elevated);
// endregion

// region Persistence
struct ServiceEntry {
    std::wstring name, display, image;
    bool has_start = false;
    long long start = -1;
    std::wstring account, dll;
};
std::vector<ServiceEntry> read_services();
std::vector<HuntFinding> check_services(const std::vector<ServiceEntry>& services, FileJudge& judge, const Stop& stop = never);
std::vector<HuntFinding> check_tasks(FileJudge& judge, const Json* tasks = nullptr, const Stop& stop = never);   // tasks: injected PowerShell answer
std::vector<HuntFinding> check_wmi(const Json* consumers = nullptr);
std::vector<HuntFinding> check_hijacks();
std::vector<HuntFinding> check_hosts(const std::wstring& path = L"");
std::vector<HuntFinding> check_proxy();
std::vector<HuntFinding> check_extensions(const std::wstring& local_app_data = L"");
std::vector<HuntFinding> collect_persistence(const Stop& stop = never, const Progress& progress = nullptr, FileJudge* judge = nullptr);
// endregion

// region Running processes
double sequence_ratio(const std::wstring& a, const std::wstring& b);   // difflib.SequenceMatcher(None, a, b).ratio()
std::wstring lookalike(const std::wstring& name);   // the system program this name imitates ("" when not a near copy)
ProcessFinding judge_process(int pid, const std::wstring& name, const std::wstring& path, int internet, FileJudge& judge);
std::vector<ProcessFinding> scan_processes(const Stop& stop = never, const Progress& progress = nullptr, FileJudge* judge = nullptr);
std::vector<std::wstring> program_paths(const std::vector<HuntFinding>& persistence, const std::vector<ProcessFinding>& processes);
// endregion

// region Removal
struct HuntRemovalResult {
    std::vector<HuntFinding> removed;
    std::vector<std::pair<HuntFinding, std::wstring>> failed;
    std::vector<std::wstring> backups;
    bool reboot = false;   // a deleted service that was running disappears at the next restart
};
bool removable(const HuntFinding& finding);
std::wstring describe(const HuntFinding& finding);   // what removing this finding does, for the confirmation window
HuntRemovalResult remove_findings(const std::vector<HuntFinding>& findings, const std::wstring& folder = L"", const Stop& stop = never,
                                  const std::function<int(const std::wstring&)>& delete_service = nullptr);
// endregion

}  // namespace dd
