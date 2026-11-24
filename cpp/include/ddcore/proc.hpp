// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the process launcher: no shell, no window, absolute system binaries, a cleaned environment and captured output.

#pragma once

#include <functional>
#include <string>
#include <vector>

#include <ddcore/common.hpp>
#include <ddcore/json.hpp>

namespace dd {

enum class Encoding { Utf8, Oem, Utf16 };   // Utf16: sfc.exe writes UTF-16LE when its output is redirected

struct ProcOptions {
    unsigned long timeout_ms = 120000;
    Encoding encoding = Encoding::Oem;                      // console tools (pnputil, netsh, sc...) print in the OEM page
    std::function<void(const std::wstring&)> on_line;       // each output line as it arrives (CR and LF both end a line: progress bars redraw with CR)
    std::function<void(const std::wstring&)> on_text;       // the text as it arrives, in chunks
    Stop stop;                                              // polled: the process is killed when it returns true
    std::wstring cwd;                                       // default: System32
    bool merge_stderr = true;
};

struct ProcResult {
    bool started = false;
    int code = -1;
    bool timed_out = false, stopped = false;
    std::wstring output;
    bool ok() const { return started && !timed_out && !stopped && code == 0; }
};

// Absolute path of a Windows system binary (a planted copy next to the exe is never run).
std::wstring sys_exe(const std::wstring& name);

// Environment for elevated children: variables a non-elevated user can set to change what an elevated child loads are dropped.
std::vector<std::wstring> safe_environment();

std::wstring quote_arg(const std::wstring& arg);
ProcResult run_process(const std::vector<std::wstring>& argv, const ProcOptions& options = {});

// PowerShell: -NoProfile -NonInteractive, UTF-8 output. Scripts that print JSON go through run_powershell_json.
ProcResult run_powershell(const std::wstring& script, ProcOptions options = {});

// A script that prints JSON (ConvertTo-Json): null when it fails, prints nothing or prints something else.
Json run_powershell_json(const std::wstring& script, unsigned long timeout_ms = 60000, const Stop& stop = never);

// Like run_powershell_json but keeps the exit code (a script may print its JSON and still exit 1) and tolerates noise before the
// JSON. data is null when nothing usable was printed; rc is -1 when PowerShell could not run or timed out.
struct PsJson {
    int rc = -1;
    Json data;
};
PsJson run_powershell_rc(const std::wstring& script, unsigned long timeout_ms = 60000, const Stop& stop = never);
Json parse_json_loose(const std::wstring& text);   // the JSON found after leading noise, or null

}  // namespace dd
