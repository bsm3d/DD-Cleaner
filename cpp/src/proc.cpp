// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Implements the process launcher: output decoding from code pages, the cleaned environment and the captured output.

#include <ddcore/proc.hpp>

#include <algorithm>
#include <map>

#include <windows.h>

namespace dd {

std::wstring sys_exe(const std::wstring& name) {
    std::wstring low = lower(name);
    if (low == L"powershell.exe") return system32() + L"\\WindowsPowerShell\\v1.0\\powershell.exe";
    if (low == L"explorer.exe" || low == L"regedit.exe") return system_root() + L"\\" + name;
    return system32() + L"\\" + name;
}

std::vector<std::wstring> safe_environment() {
    static const wchar_t* unsafe[] = {L"PSMODULEPATH", L"PSEXECUTIONPOLICYPREFERENCE", L"PSMODULEAUTOLOADINGPREFERENCE",
                                      L"__PSLOCKDOWNPOLICY", L"COMPLUS_", L"COR_", L"DOTNET_", L"PYTHON"};
    std::map<std::wstring, std::wstring> env;   // keyed by upper-case name, sorted as Windows wants
    wchar_t* block = GetEnvironmentStringsW();
    for (const wchar_t* p = block; block && *p; p += wcslen(p) + 1) {
        std::wstring entry = p;
        std::size_t eq = entry.find(L'=', 1);   // entries like "=C:=C:\x" start with '='
        if (eq == std::wstring::npos) continue;
        std::wstring name = entry.substr(0, eq), up = name;
        for (auto& c : up) c = (wchar_t)towupper(c);
        bool drop = false;
        for (const wchar_t* prefix : unsafe) {
            if (starts_with(up, prefix)) drop = true;
        }
        if (!drop) env[up] = entry;
    }
    if (block) FreeEnvironmentStringsW(block);
    std::wstring root = system_root(), s32 = system32();
    env[L"SYSTEMROOT"] = L"SystemRoot=" + root;
    env[L"WINDIR"] = L"windir=" + root;
    env[L"COMSPEC"] = L"ComSpec=" + s32 + L"\\cmd.exe";
    env[L"PATH"] = L"PATH=" + s32 + L";" + root + L";" + s32 + L"\\Wbem;" + s32 + L"\\WindowsPowerShell\\v1.0";
    env[L"PSMODULEPATH"] = L"PSModulePath=" + s32 + L"\\WindowsPowerShell\\v1.0\\Modules";
    std::vector<std::wstring> out;
    for (auto& kv : env) out.push_back(kv.second);
    return out;
}

// Quoting that CommandLineToArgvW and the C runtime read back as the same argument.
std::wstring quote_arg(const std::wstring& arg) {
    if (!arg.empty() && arg.find_first_of(L" \t\n\v\"") == std::wstring::npos) return arg;
    std::wstring out = L"\"";
    for (std::size_t i = 0;; ++i) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == L'\\') {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            out.append(backslashes * 2, L'\\');
            break;
        }
        if (arg[i] == L'"') {
            out.append(backslashes * 2 + 1, L'\\');
            out.push_back(L'"');
        } else {
            out.append(backslashes, L'\\');
            out.push_back(arg[i]);
        }
    }
    out.push_back(L'"');
    return out;
}

static std::wstring decode(const std::string& bytes, Encoding enc) {
    if (bytes.empty()) return L"";
    if (enc == Encoding::Utf16) {
        std::size_t skip = bytes.size() >= 2 && (unsigned char)bytes[0] == 0xFF && (unsigned char)bytes[1] == 0xFE ? 2 : 0;
        return std::wstring(reinterpret_cast<const wchar_t*>(bytes.data() + skip), (bytes.size() - skip) / 2);
    }
    UINT page = enc == Encoding::Utf8 ? CP_UTF8 : CP_OEMCP;
    std::size_t skip = 0;
    if (enc == Encoding::Utf8 && bytes.size() >= 3 && (unsigned char)bytes[0] == 0xEF && (unsigned char)bytes[1] == 0xBB &&
        (unsigned char)bytes[2] == 0xBF)
        skip = 3;
    int n = MultiByteToWideChar(page, 0, bytes.data() + skip, (int)(bytes.size() - skip), nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(page, 0, bytes.data() + skip, (int)(bytes.size() - skip), out.data(), n);
    return out;
}

// How many bytes of `bytes` can be decoded now: a character cut in the middle waits for the next chunk.
static std::size_t complete_prefix(const std::string& bytes, Encoding enc) {
    if (enc == Encoding::Utf16) return bytes.size() & ~(std::size_t)1;
    if (enc == Encoding::Utf8) {
        std::size_t n = bytes.size();
        for (std::size_t back = 1; back <= 3 && back <= n; ++back) {
            unsigned char c = (unsigned char)bytes[n - back];
            if ((c & 0xC0) == 0x80) continue;          // a continuation byte: look further back
            if (c >= 0xF0 && back < 4) return n - back;
            if (c >= 0xE0 && back < 3) return n - back;
            if (c >= 0xC0 && back < 2) return n - back;
            break;
        }
    }
    return bytes.size();
}

ProcResult run_process(const std::vector<std::wstring>& argv, const ProcOptions& o) {
    ProcResult result;
    if (argv.empty()) return result;

    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE read_end = nullptr, write_end = nullptr;
    if (!CreatePipe(&read_end, &write_end, &sa, 0)) return result;
    SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);
    HANDLE null_in = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);

    std::wstring command;
    for (const auto& a : argv) command += (command.empty() ? L"" : L" ") + quote_arg(a);
    std::wstring env_block;
    for (const auto& e : safe_environment()) {
        env_block += e;
        env_block.push_back(L'\0');
    }
    env_block.push_back(L'\0');
    std::wstring cwd = o.cwd.empty() ? system32() : o.cwd;

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = null_in;
    si.hStdOutput = write_end;
    si.hStdError = o.merge_stderr ? write_end : null_in;
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(argv[0].c_str(), command.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT, env_block.data(), cwd.c_str(), &si, &pi);
    CloseHandle(write_end);
    if (null_in != INVALID_HANDLE_VALUE) CloseHandle(null_in);
    if (!ok) {
        CloseHandle(read_end);
        return result;
    }
    result.started = true;
    CloseHandle(pi.hThread);

    DWORD start = GetTickCount();
    std::string raw, unprocessed;
    std::wstring pending_line;
    auto handle_text = [&](const std::wstring& text) {
        if (o.on_text && !text.empty()) o.on_text(text);
        if (!o.on_line) return;
        for (wchar_t c : text) {
            if (c == L'\r' || c == L'\n') {
                if (!pending_line.empty()) o.on_line(pending_line);
                pending_line.clear();
            } else {
                pending_line.push_back(c);
            }
        }
    };
    auto flush_stream = [&](bool final) {
        if (!o.on_line && !o.on_text) return;
        std::size_t take = final ? unprocessed.size() : complete_prefix(unprocessed, o.encoding);
        if (take) {
            std::wstring text = decode(unprocessed.substr(0, take), o.encoding);
            if (o.encoding == Encoding::Utf16 && raw.size() == unprocessed.size() && !text.empty() && text[0] == 0xFEFF) text.erase(0, 1);
            handle_text(text);
            unprocessed.erase(0, take);
        }
        if (final && !pending_line.empty() && o.on_line) {
            o.on_line(pending_line);
            pending_line.clear();
        }
    };
    auto drain = [&] {
        for (;;) {
            DWORD available = 0;
            if (!PeekNamedPipe(read_end, nullptr, 0, nullptr, &available, nullptr) || !available) return;
            char buf[8192];
            DWORD got = 0;
            if (!ReadFile(read_end, buf, std::min<DWORD>(available, sizeof(buf)), &got, nullptr) || !got) return;
            raw.append(buf, got);
            if (o.on_line || o.on_text) unprocessed.append(buf, got);
        }
    };
    for (;;) {
        drain();
        flush_stream(false);
        if (WaitForSingleObject(pi.hProcess, 25) == WAIT_OBJECT_0) break;
        if (o.stop && o.stop()) {
            result.stopped = true;
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 2000);
            break;
        }
        if (o.timeout_ms && GetTickCount() - start > o.timeout_ms) {
            result.timed_out = true;
            TerminateProcess(pi.hProcess, 1);
            WaitForSingleObject(pi.hProcess, 2000);
            break;
        }
    }
    drain();
    flush_stream(true);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    result.code = (int)code;
    CloseHandle(pi.hProcess);
    CloseHandle(read_end);
    result.output = decode(raw, o.encoding);
    return result;
}

ProcResult run_powershell(const std::wstring& script, ProcOptions options) {
    options.encoding = Encoding::Utf8;
    std::wstring full = L"[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + script;
    return run_process({sys_exe(L"powershell.exe"), L"-NoProfile", L"-NonInteractive", L"-Command", full}, options);
}

Json run_powershell_json(const std::wstring& script, unsigned long timeout_ms, const Stop& stop) {
    ProcOptions o;
    o.timeout_ms = timeout_ms;
    o.stop = stop;
    o.merge_stderr = false;   // warnings on stderr must not break the JSON
    ProcResult r = run_powershell(script, o);
    Json data;
    if (!r.started || r.code != 0 || trim(r.output).empty() || !try_parse_json(r.output, data)) return Json();
    return data;
}

Json parse_json_loose(const std::wstring& text_in) {
    std::wstring text = trim(text_in);
    if (text.empty()) return Json();
    Json data;
    if (try_parse_json(text, data)) return data;
    for (wchar_t opener : {L'{', L'['}) {
        std::size_t at = text.find(opener);
        if (at != std::wstring::npos && try_parse_json(text.substr(at), data)) return data;
    }
    return Json();
}

PsJson run_powershell_rc(const std::wstring& script, unsigned long timeout_ms, const Stop& stop) {
    ProcOptions o;
    o.timeout_ms = timeout_ms;
    o.stop = stop;
    o.merge_stderr = false;
    ProcResult r = run_powershell(L"$ProgressPreference='SilentlyContinue'; " + script, o);
    PsJson out;
    if (!r.started || r.timed_out || r.stopped) return out;
    out.rc = r.code;
    out.data = parse_json_loose(r.output);
    return out;
}

}  // namespace dd
