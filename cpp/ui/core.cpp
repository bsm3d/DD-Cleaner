// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Core of the Win32 interface: main window, tabs, layout, the background worker thread and the shared dialogs of all pages.

#include "ui.hpp"

#include <algorithm>
#include <thread>

#include <commdlg.h>
#include <shellapi.h>
#include <shlobj.h>
#include <uxtheme.h>
#include <windowsx.h>

#include <ddcore/proc.hpp>

namespace ui {

// region Core state

struct Core {
    HINSTANCE inst = nullptr;
    HWND hwnd = nullptr, tab = nullptr, sub = nullptr, progress = nullptr, status = nullptr, stop_btn = nullptr, admin_btn = nullptr, summary = nullptr;
    HFONT font = nullptr, mono = nullptr;
    UINT dpi = 96;
    std::vector<std::unique_ptr<Page>> pages;
    struct Group {
        std::wstring name;
        std::vector<int> pages;
        int last = 0;
    };
    std::vector<Group> groups;
    int cur_group = -1, cur_page = -1;
    std::map<int, std::function<void()>> commands;
    std::map<int, ListEvents> list_events;
    std::map<int, std::function<void()>> changes;
    std::map<HWND, int> button_style;   // 1 = blue (main action), 2 = red (danger); drawn by hand
    std::vector<HWND> actions;
    int next_id = 1000;
    std::thread worker, quiet;
    std::atomic<bool> stop{false}, quiet_busy{false};
    bool busy = false, is_elevated = false, filling = false;
    std::wstring shot_path;
    int shot_delay = 0;
    bool shot_refresh = false;
    bool sub_visible = false;

    int new_id() { return next_id++; }
    Page* page() { return cur_page >= 0 ? pages[cur_page].get() : nullptr; }
};

namespace {
Core g;
enum { ID_TAB = 100, ID_SUB, ID_STOP, ID_PROGRESS, ID_STATUS, ID_SUMMARY, ID_ADMIN, ID_ACC_STOP, ID_ACC_COPY, ID_ACC_REFRESH };
constexpr UINT WM_JOB = WM_APP + 1;
constexpr UINT_PTR TIMER_ID = 1;
}  // namespace

Core& core() { return g; }

int scale(int px) { return MulDiv(px, (int)g.dpi, 96); }
HWND main_window() { return g.hwnd; }
HFONT font() { return g.font; }
HFONT mono_font() { return g.mono; }
bool busy() { return g.busy; }
bool stop_requested() { return g.stop.load(); }

static HWND make(Page* page, std::vector<HWND>& all, const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
    (void)page;
    HWND h = CreateWindowExW(ex, cls, text, WS_CHILD | WS_CLIPSIBLINGS | style, 0, 0, 10, 10, g.hwnd, (HMENU)(INT_PTR)id, g.inst, nullptr);
    SendMessageW(h, WM_SETFONT, (WPARAM)g.font, TRUE);
    all.push_back(h);
    return h;
}

// endregion

static void show_group(int gi);

// region Page construction

Page& add_page(const std::wstring& group, const std::wstring& name) {
    auto page = std::make_unique<Page>();
    page->group = group;
    page->name = name;
    page->index_ = (int)g.pages.size();
    int gi = -1;
    for (std::size_t i = 0; i < g.groups.size(); ++i) {
        if (g.groups[i].name == group) gi = (int)i;
    }
    if (gi < 0) {
        g.groups.push_back({group, {}, 0});
        gi = (int)g.groups.size() - 1;
    }
    g.groups[gi].pages.push_back(page->index_);
    g.pages.push_back(std::move(page));
    return *g.pages.back();
}

HWND Page::button(const std::wstring& text, std::function<void()> fn, int width, bool action, bool right) {
    int id = g.new_id();
    HWND h = make(this, all_, L"BUTTON", text.c_str(), WS_TABSTOP | BS_PUSHBUTTON, id);
    g.commands[id] = std::move(fn);
    if (action) g.actions.push_back(h);
    // red for what deletes or changes the system, blue for the first button of the page (its main action)
    static const wchar_t* danger[] = {L"Delete", L"Remove", L"Uninstall", L"Apply", L"Reset network", L"Undo", L"Clear"};
    int style = 0;
    for (const wchar_t* d : danger) {
        if (text.compare(0, wcslen(d), d) == 0) style = 2;
    }
    bool has_main = false;
    for (const auto& it : items_) has_main = has_main || (it.kind == Item::Button && g.button_style.count(it.h) && g.button_style[it.h] == 1);
    if (!style && !has_main && action) style = 1;
    if (style) {
        g.button_style[h] = style;
        SendMessageW(h, BM_SETSTYLE, BS_OWNERDRAW, TRUE);
    }
    items_.push_back({Item::Button, h, width ? width : std::max(60, 14 + 7 * (int)text.size()), right});
    return h;
}

HWND Page::label(const std::wstring& text, int width) {
    HWND h = make(this, all_, L"STATIC", text.c_str(), SS_CENTERIMAGE | SS_ENDELLIPSIS, g.new_id());
    items_.push_back({Item::Label, h, width < 0 ? 0 : (width ? width : 8 + 7 * (int)text.size()), false});
    return h;
}

HWND Page::combo(const std::vector<std::wstring>& options, int selected, int width, bool editable) {
    HWND h = make(this, all_, L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | (editable ? CBS_DROPDOWN : CBS_DROPDOWNLIST) | CBS_AUTOHSCROLL, g.new_id());
    for (const auto& o : options) SendMessageW(h, CB_ADDSTRING, 0, (LPARAM)o.c_str());
    if (selected >= 0) ComboBox_SetCurSel(h, selected);
    items_.push_back({Item::Combo, h, width, false, true});
    return h;
}

HWND Page::edit(const std::wstring& text, int width, bool readonly, bool password) {
    DWORD style = WS_TABSTOP | ES_AUTOHSCROLL | (readonly ? ES_READONLY : 0) | (password ? ES_PASSWORD : 0);
    HWND h = make(this, all_, L"EDIT", text.c_str(), style, g.new_id(), WS_EX_CLIENTEDGE);
    items_.push_back({Item::Edit, h, width, false});
    return h;
}

HWND Page::check(const std::wstring& text, int width, bool checked) {
    HWND h = make(this, all_, L"BUTTON", text.c_str(), WS_TABSTOP | BS_AUTOCHECKBOX, g.new_id());
    Button_SetCheck(h, checked ? BST_CHECKED : BST_UNCHECKED);
    items_.push_back({Item::Check, h, width ? width : 30 + 7 * (int)text.size(), false});
    return h;
}

void Page::newline() { items_.push_back({Item::Newline, nullptr, 0, false}); }

void set_columns(HWND lv, const std::vector<Column>& columns) {
    while (ListView_DeleteColumn(lv, 0)) {}
    int i = 0;
    for (const Column& c : columns) {
        LVCOLUMNW col{};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        col.pszText = const_cast<wchar_t*>(c.title);
        col.cx = scale(c.width);
        col.fmt = c.right ? LVCFMT_RIGHT : LVCFMT_LEFT;
        ListView_InsertColumn(lv, i++, &col);
    }
}

HWND Page::list(std::vector<Column> columns, int weight, bool checks, ListEvents events) {
    int id = g.new_id();
    HWND h = make(this, all_, WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, id, WS_EX_CLIENTEDGE);
    DWORD ex = LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP | (checks ? LVS_EX_CHECKBOXES : 0);
    ListView_SetExtendedListViewStyle(h, ex);
    SetWindowTheme(h, L"Explorer", nullptr);   // the modern selection and hover look
    set_columns(h, columns);
    g.list_events[id] = std::move(events);
    body_.push_back({h, weight});
    return h;
}

HWND Page::text(int weight) {
    HWND h = make(this, all_, L"EDIT", L"", WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_NOHIDESEL, g.new_id(), WS_EX_CLIENTEDGE);
    SendMessageW(h, WM_SETFONT, (WPARAM)g.mono, TRUE);
    SendMessageW(h, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);
    body_.push_back({h, weight});
    return h;
}

HWND Page::custom(const wchar_t* window_class, int weight, DWORD style, DWORD ex_style) {
    HWND h = make(this, all_, window_class, L"", style, g.new_id(), ex_style);
    body_.push_back({h, weight});
    return h;
}

void Page::on_change(HWND h, std::function<void()> fn) { g.changes[GetDlgCtrlID(h)] = std::move(fn); }

void Page::set_summary(const std::wstring& text) {
    summary_ = text;
    if (g.cur_page == index_) SetWindowTextW(g.summary, text.c_str());
}

// endregion

// region Lists and text

void set_rows(HWND lv, const std::vector<std::vector<std::wstring>>& rows) {
    g.filling = true;
    SendMessageW(lv, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(lv);
    for (std::size_t r = 0; r < rows.size(); ++r) {
        for (std::size_t c = 0; c < rows[r].size(); ++c) {
            const std::wstring& text = rows[r][c];
            if (c == 0) {
                LVITEMW item{};
                item.mask = LVIF_TEXT;
                item.iItem = (int)r;
                item.pszText = const_cast<wchar_t*>(text.c_str());
                ListView_InsertItem(lv, &item);
            } else {
                ListView_SetItemText(lv, (int)r, (int)c, const_cast<wchar_t*>(text.c_str()));
            }
        }
    }
    SendMessageW(lv, WM_SETREDRAW, TRUE, 0);
    g.filling = false;
}

bool is_checked(HWND lv, int row) { return ListView_GetCheckState(lv, row) != 0; }

void set_checked(HWND lv, int row, bool checked) {
    g.filling = true;
    ListView_SetCheckState(lv, row, checked);
    g.filling = false;
}

void set_all_checked(HWND lv, bool checked) {
    g.filling = true;
    int n = ListView_GetItemCount(lv);
    for (int i = 0; i < n; ++i) ListView_SetCheckState(lv, i, checked);
    g.filling = false;
}

std::vector<int> selected_rows(HWND lv) {
    std::vector<int> out;
    for (int i = -1; (i = ListView_GetNextItem(lv, i, LVNI_SELECTED)) != -1;) out.push_back(i);
    return out;
}

int row_count(HWND lv) { return ListView_GetItemCount(lv); }

static std::wstring crlf(const std::wstring& text) {
    std::wstring out;
    out.reserve(text.size() + text.size() / 16);
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] == L'\n' && (i == 0 || text[i - 1] != L'\r')) out += L"\r\n";
        else out.push_back(text[i]);
    }
    return out;
}

void set_text(HWND h, const std::wstring& text) { SetWindowTextW(h, crlf(text).c_str()); }

void append_text(HWND h, const std::wstring& text) {
    int end = GetWindowTextLengthW(h);
    SendMessageW(h, EM_SETSEL, end, end);
    SendMessageW(h, EM_REPLACESEL, FALSE, (LPARAM)crlf(text).c_str());
    SendMessageW(h, EM_SCROLLCARET, 0, 0);
}

std::wstring get_text(HWND h) {
    int n = GetWindowTextLengthW(h);
    std::wstring s((std::size_t)n + 1, L'\0');
    GetWindowTextW(h, s.data(), n + 1);
    s.resize((std::size_t)n);
    return s;
}

std::wstring trimmed(HWND h) { return dd::trim(get_text(h)); }
int combo_index(HWND h) { return ComboBox_GetCurSel(h); }
std::wstring combo_text(HWND h) { return trimmed(h); }
bool checked(HWND h) { return Button_GetCheck(h) == BST_CHECKED; }

void export_list(HWND lv, const std::wstring& suggested_name) {
    std::wstring path = save_file(L"Export to CSV", suggested_name, L"CSV files\0*.csv\0All files\0*.*\0", L"csv");
    if (path.empty()) return;
    HWND header = ListView_GetHeader(lv);
    int columns = Header_GetItemCount(header), rows = ListView_GetItemCount(lv);
    auto cell = [](const std::wstring& s) {
        std::wstring out = L"\"";
        for (wchar_t c : s) out += c == L'"' ? std::wstring(L"\"\"") : std::wstring(1, c);
        return out + L"\"";
    };
    std::wstring csv;
    for (int c = 0; c < columns; ++c) {
        wchar_t title[256] = {};
        HDITEMW item{};
        item.mask = HDI_TEXT;
        item.pszText = title;
        item.cchTextMax = 256;
        Header_GetItem(header, c, &item);
        csv += (c ? L"," : L"") + cell(title);
    }
    csv += L"\r\n";
    std::vector<wchar_t> buf(8192);
    for (int r = 0; r < rows; ++r) {
        for (int c = 0; c < columns; ++c) {
            ListView_GetItemText(lv, r, c, buf.data(), (int)buf.size());
            csv += (c ? L"," : L"") + cell(buf.data());
        }
        csv += L"\r\n";
    }
    if (!dd::write_file(path, "\xEF\xBB\xBF" + dd::utf8(csv))) warn(L"The file could not be written:\n" + path);
    else set_status(L"Exported " + std::to_wstring(rows) + L" rows to " + path);
}

// endregion

// region Helpers

bool elevated() { return g.is_elevated; }

void copy_to_clipboard(const std::wstring& text) {
    if (!OpenClipboard(g.hwnd)) return;
    EmptyClipboard();
    HGLOBAL mem = GlobalAlloc(GMEM_MOVEABLE, (text.size() + 1) * sizeof(wchar_t));
    if (mem) {
        memcpy(GlobalLock(mem), text.c_str(), (text.size() + 1) * sizeof(wchar_t));
        GlobalUnlock(mem);
        SetClipboardData(CF_UNICODETEXT, mem);
    }
    CloseClipboard();
}

void copy_secret(const std::wstring& text) {
    copy_to_clipboard(text);
    after(30000, [text] {
        if (!OpenClipboard(g.hwnd)) return;
        HANDLE data = GetClipboardData(CF_UNICODETEXT);
        bool same = false;
        if (data) {
            const wchar_t* now = (const wchar_t*)GlobalLock(data);
            same = now && text == now;
            GlobalUnlock(data);
        }
        if (same) EmptyClipboard();
        CloseClipboard();
    });
}

struct Periodic {
    unsigned ms;
    ULONGLONG last;
    std::function<void()> fn;
};
static std::vector<Periodic>& periodic() {
    static std::vector<Periodic> list;
    return list;
}
void every(unsigned ms, std::function<void()> fn) { periodic().push_back({ms, GetTickCount64(), std::move(fn)}); }

void after(unsigned ms, std::function<void()> fn) {
    std::thread([ms, fn = std::move(fn)] {
        Sleep(ms);
        post_job(fn);
    }).detach();
}

void select_page(const std::wstring& group, const std::wstring& name) {
    for (auto& page : g.pages) {
        if (page->group != group || page->name != name) continue;
        for (std::size_t gi = 0; gi < g.groups.size(); ++gi) {
            if (g.groups[gi].name != group) continue;
            for (std::size_t i = 0; i < g.groups[gi].pages.size(); ++i) {
                if (g.groups[gi].pages[i] == page->index_) g.groups[gi].last = (int)i;
            }
            show_group((int)gi);
            return;
        }
    }
}

static void copy_selected(HWND lv) {
    HWND header = ListView_GetHeader(lv);
    int columns = Header_GetItemCount(header);
    std::wstring out;
    for (int i : selected_rows(lv)) {
        for (int c = 0; c < columns; ++c) {
            wchar_t buf[2048];
            ListView_GetItemText(lv, i, c, buf, 2048);
            out += (c ? L"\t" : L"") + std::wstring(buf);
        }
        out += L"\r\n";
    }
    if (!out.empty()) copy_to_clipboard(out);
}

void reveal(const std::wstring& path) {
    if (path.empty() || !dd::lexists(path)) return;
    std::wstring args = dd::is_dir(path) ? L"\"" + path + L"\"" : L"/select,\"" + path + L"\"";
    ShellExecuteW(g.hwnd, L"open", dd::sys_exe(L"explorer.exe").c_str(), args.c_str(), nullptr, SW_SHOWNORMAL);
}

void open_url(const std::wstring& url) {
    if (url.compare(0, 8, L"https://") != 0 && url.compare(0, 7, L"http://") != 0) return;
    ShellExecuteW(g.hwnd, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
}

void set_status(const std::wstring& text) {
    if (g.status) SetWindowTextW(g.status, text.c_str());
}

void info(const std::wstring& text) { MessageBoxW(g.hwnd, text.c_str(), L"DD Cleaner", MB_OK | MB_ICONINFORMATION); }
void warn(const std::wstring& text) { MessageBoxW(g.hwnd, text.c_str(), L"DD Cleaner", MB_OK | MB_ICONWARNING); }
bool confirm(const std::wstring& text, const std::wstring& title, bool warning) {
    return MessageBoxW(g.hwnd, text.c_str(), title.c_str(), MB_YESNO | MB_DEFBUTTON2 | (warning ? MB_ICONWARNING : MB_ICONQUESTION)) == IDYES;
}

std::wstring choose_folder(const std::wstring& title) {
    BROWSEINFOW bi{};
    bi.hwndOwner = g.hwnd;
    bi.lpszTitle = title.c_str();
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE pidl = SHBrowseForFolderW(&bi);
    if (!pidl) return L"";
    wchar_t path[MAX_PATH] = {};
    std::wstring result = SHGetPathFromIDListW(pidl, path) ? path : L"";
    CoTaskMemFree(pidl);
    return result;
}

std::wstring open_file(const std::wstring& title, const wchar_t* filter) {
    wchar_t file[MAX_PATH] = {};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title.c_str();
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameW(&ofn) ? file : L"";
}

std::wstring save_file(const std::wstring& title, const std::wstring& suggested, const wchar_t* filter, const wchar_t* ext) {
    wchar_t file[MAX_PATH] = {};
    wcsncpy(file, suggested.c_str(), MAX_PATH - 1);
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g.hwnd;
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrTitle = title.c_str();
    ofn.lpstrDefExt = ext;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return GetSaveFileNameW(&ofn) ? file : L"";
}

// endregion

// region Work

void post_job(std::function<void()> job) {
    PostMessageW(g.hwnd, WM_JOB, 0, (LPARAM) new std::function<void()>(std::move(job)));
}

static void set_busy(bool on) {
    g.busy = on;
    for (HWND h : g.actions) EnableWindow(h, !on);
    EnableWindow(g.stop_btn, on);
    ShowWindow(g.progress, on ? SW_SHOW : SW_HIDE);
    SendMessageW(g.progress, PBM_SETMARQUEE, on, 30);
}

bool run_async(const std::wstring& what, Work work) {
    if (g.busy) {
        info(L"Another task is still running. Wait for it, or press Stop.");
        return false;
    }
    if (g.worker.joinable()) g.worker.join();
    g.stop = false;
    set_busy(true);
    set_status(what);
    g.worker = std::thread([work = std::move(work)] {
        Stop stop = [] { return g.stop.load(); };
        Progress progress = [](const std::wstring& text) { post_job([text] { if (g.busy) set_status(text); }); };
        std::function<void()> done;
        try {
            done = work(stop, progress);
        } catch (const std::exception& e) {
            std::wstring text = dd::wide(e.what());
            done = [text] { warn(text); };
        }
        post_job([done = std::move(done)] {
            set_busy(false);
            set_status(g.stop ? L"Stopped." : L"Ready.");
            if (done) done();
        });
    });
    return true;
}

void run_quiet(Work work) {
    if (g.quiet_busy.exchange(true)) return;
    if (g.quiet.joinable()) g.quiet.join();
    g.quiet = std::thread([work = std::move(work)] {
        Stop stop = [] { return g.stop.load(); };
        Progress none = [](const std::wstring&) {};
        std::function<void()> done;
        try {
            done = work(stop, none);
        } catch (const std::exception&) {
        }
        post_job([done = std::move(done)] {
            g.quiet_busy = false;
            if (done) done();
        });
    });
}

// endregion

// region Dialogs

namespace {

struct Dlg {
    DialogSpec spec;
    DialogResult result;
    HWND hwnd = nullptr, label = nullptr, body = nullptr;
    std::vector<HWND> buttons;
    bool done = false;
};

constexpr int ID_DLG_BUTTON = 2000;

void dlg_layout(Dlg* d) {
    RECT rc;
    GetClientRect(d->hwnd, &rc);
    int m = scale(10), bh = scale(28), gap = scale(8);
    int y = m;
    if (d->label) {
        int lh = 0;
        if (!d->spec.prompt.empty()) {   // height of the wrapped text, so that a long prompt is never cut
            HDC dc = GetDC(d->label);
            HGDIOBJ old = SelectObject(dc, g.font);
            RECT t = {0, 0, rc.right - 2 * m, 0};
            DrawTextW(dc, d->spec.prompt.c_str(), -1, &t, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
            SelectObject(dc, old);
            ReleaseDC(d->label, dc);
            lh = std::max(scale(24), (int)t.bottom + scale(6));
        }
        SetWindowPos(d->label, nullptr, m, y, rc.right - 2 * m, lh, SWP_NOZORDER);
        y += lh + (lh ? gap : 0);
    }
    int body_bottom = rc.bottom - m - bh - gap;
    if (d->body) SetWindowPos(d->body, nullptr, m, y, rc.right - 2 * m, std::max(scale(40), body_bottom - y), SWP_NOZORDER);
    int x = rc.right - m;
    for (std::size_t i = d->buttons.size(); i-- > 0;) {
        int w = std::max(scale(80), scale(16) + (int)d->spec.buttons[i].first.size() * scale(7));
        x -= w;
        SetWindowPos(d->buttons[i], nullptr, x, rc.bottom - m - bh, w, bh, SWP_NOZORDER);
        x -= gap;
    }
}

void dlg_finish(Dlg* d, int button) {
    d->result.button = button;
    if (d->body) {
        if (d->spec.body == DialogSpec::List) {
            d->result.row = ListView_GetNextItem(d->body, -1, LVNI_SELECTED);
            if (d->spec.checks) {
                int n = ListView_GetItemCount(d->body);
                for (int i = 0; i < n; ++i) d->result.checked.push_back(ListView_GetCheckState(d->body, i) != 0);
            }
        } else {
            d->result.text = get_text(d->body);
        }
    }
    d->done = true;
}

LRESULT CALLBACK dlg_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    Dlg* d = (Dlg*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
    switch (msg) {
        case WM_SIZE:
            if (d) dlg_layout(d);
            return 0;
        case WM_GETMINMAXINFO:
            ((MINMAXINFO*)lp)->ptMinTrackSize = {scale(380), scale(240)};
            return 0;
        case WM_COMMAND: {
            if (!d) break;
            int id = LOWORD(wp);
            if (id == IDCANCEL) {
                dlg_finish(d, 0);
                return 0;
            }
            if (id >= ID_DLG_BUTTON && id < ID_DLG_BUTTON + (int)d->spec.buttons.size()) {
                int result = d->spec.buttons[id - ID_DLG_BUTTON].second;
                if (result == -1) {   // "Copy": keeps the dialog open
                    copy_to_clipboard(d->body ? get_text(d->body) : L"");
                    return 0;
                }
                if (result <= -2) {
                    if (d->spec.action) d->spec.action(d->body, result, d->buttons[id - ID_DLG_BUTTON]);
                    return 0;
                }
                dlg_finish(d, result);
                return 0;
            }
            break;
        }
        case WM_NOTIFY: {
            auto* h = (NMHDR*)lp;
            if (d && d->body && h->hwndFrom == d->body && h->code == NM_DBLCLK && !d->spec.checks && !d->spec.buttons.empty())
                dlg_finish(d, d->spec.buttons[0].second);
            return 0;
        }
        case WM_CLOSE:
            if (d) dlg_finish(d, 0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

}  // namespace

DialogResult run_dialog(const DialogSpec& spec) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = dlg_proc;
        wc.hInstance = g.inst;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
        wc.lpszClassName = L"DDCleanerDialog";
        RegisterClassExW(&wc);
        registered = true;
    }
    Dlg d;
    d.spec = spec;
    RECT owner;
    GetWindowRect(g.hwnd, &owner);
    int w = scale(spec.width), h = scale(spec.height);
    int x = owner.left + ((owner.right - owner.left) - w) / 2, y = owner.top + ((owner.bottom - owner.top) - h) / 2;
    d.hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME | WS_EX_CONTROLPARENT, L"DDCleanerDialog", spec.title.c_str(), WS_POPUP | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_CLIPCHILDREN,
                             x, y, w, h, g.hwnd, nullptr, g.inst, nullptr);
    SetWindowLongPtrW(d.hwnd, GWLP_USERDATA, (LONG_PTR)&d);
    auto child = [&](const wchar_t* cls, const wchar_t* text, DWORD style, int id, DWORD ex = 0) {
        HWND c = CreateWindowExW(ex, cls, text, WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | style, 0, 0, 10, 10, d.hwnd, (HMENU)(INT_PTR)id, g.inst, nullptr);
        SendMessageW(c, WM_SETFONT, (WPARAM)g.font, TRUE);
        return c;
    };
    if (!spec.prompt.empty()) d.label = child(L"STATIC", spec.prompt.c_str(), SS_LEFT, 1);
    switch (spec.body) {
        case DialogSpec::List: {
            d.body = child(WC_LISTVIEWW, L"", WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, 3, WS_EX_CLIENTEDGE);
            ListView_SetExtendedListViewStyle(d.body, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | (spec.checks ? LVS_EX_CHECKBOXES : 0));
            set_columns(d.body, spec.columns);
            set_rows(d.body, spec.rows);
            for (std::size_t i = 0; i < spec.checked.size() && i < spec.rows.size(); ++i) ListView_SetCheckState(d.body, (int)i, spec.checked[i]);
            if (!spec.rows.empty()) ListView_SetItemState(d.body, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            break;
        }
        case DialogSpec::Text:
            d.body = child(L"EDIT", L"", WS_TABSTOP | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_NOHIDESEL, 3, WS_EX_CLIENTEDGE);
            SendMessageW(d.body, WM_SETFONT, (WPARAM)g.mono, TRUE);
            SendMessageW(d.body, EM_SETLIMITTEXT, 0x7FFFFFFE, 0);
            set_text(d.body, spec.text);
            break;
        case DialogSpec::Input:
            d.body = child(L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL | (spec.password ? ES_PASSWORD : 0) | (spec.read_only ? ES_READONLY : 0), 3, WS_EX_CLIENTEDGE);
            SetWindowTextW(d.body, spec.text.c_str());
            break;
        default: break;
    }
    for (std::size_t i = 0; i < spec.buttons.size(); ++i) {
        d.buttons.push_back(child(L"BUTTON", spec.buttons[i].first.c_str(), WS_TABSTOP | (i == 0 ? BS_DEFPUSHBUTTON : BS_PUSHBUTTON), ID_DLG_BUTTON + (int)i));
    }
    if (!d.buttons.empty()) SendMessageW(d.hwnd, DM_SETDEFID, ID_DLG_BUTTON, 0);
    dlg_layout(&d);
    EnableWindow(g.hwnd, FALSE);
    ShowWindow(d.hwnd, SW_SHOW);
    SetFocus(d.body ? d.body : (d.buttons.empty() ? d.hwnd : d.buttons[0]));
    if (spec.body == DialogSpec::Input) SendMessageW(d.body, EM_SETSEL, 0, -1);
    MSG msg;
    while (!d.done && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(d.hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    EnableWindow(g.hwnd, TRUE);
    DestroyWindow(d.hwnd);
    SetForegroundWindow(g.hwnd);
    return d.result;
}

void show_text(const std::wstring& title, const std::wstring& text, int width, int height) {
    DialogSpec s;
    s.title = title;
    s.body = DialogSpec::Text;
    s.text = text;
    s.buttons = {{L"Close", 0}, {L"Copy", -1}};
    s.width = width;
    s.height = height;
    run_dialog(s);
}

// endregion

// region Layout

namespace {

void place(HWND h, int x, int y, int w, int hgt) { SetWindowPos(h, nullptr, x, y, w, hgt, SWP_NOZORDER | SWP_NOACTIVATE); }

// The width an item needs: what the page asked for, or more when the text (at this DPI and font) does not fit
int item_width(const Page::Item& it) {
    int w = scale(it.width);
    if (it.kind == Page::Item::Combo || it.kind == Page::Item::Edit || !it.h) return w;
    wchar_t text[256];
    GetWindowTextW(it.h, text, 256);
    HDC dc = GetDC(g.hwnd);
    HGDIOBJ old = SelectObject(dc, g.font);
    SIZE size{};
    GetTextExtentPoint32W(dc, text, (int)wcslen(text), &size);
    SelectObject(dc, old);
    ReleaseDC(g.hwnd, dc);
    int pad = it.kind == Page::Item::Button ? scale(24) : it.kind == Page::Item::Check ? scale(28) : scale(6);
    return std::max(w, (int)size.cx + pad);
}

void layout_page(Page& page, const RECT& area) {
    int m = scale(12), gap = scale(8), row = scale(28), sum_h = scale(24);
    int x0 = area.left + m, x1 = area.right - m, y0 = area.top + m, y1 = area.bottom - m;
    int avail = x1 - x0;
    struct Row {
        std::vector<Page::Item*> items;
    };
    std::vector<Row> rows(1);
    int used = 0;
    for (auto& it : page.items_) {
        if (it.kind == Page::Item::Newline) {
            rows.emplace_back();
            used = 0;
            continue;
        }
        int w = it.width > 0 ? item_width(it) : scale(80);
        if (!rows.back().items.empty() && used + w > avail) {
            rows.emplace_back();
            used = 0;
        }
        rows.back().items.push_back(&it);
        used += w + gap;
    }
    int y = y0;
    for (auto& r : rows) {
        if (r.items.empty()) continue;
        int left_fixed = 0, right_fixed = 0;
        bool has_fill = false;
        for (auto* it : r.items) {
            if (it->width <= 0) {
                has_fill = true;
                continue;
            }
            (it->right ? right_fixed : left_fixed) += item_width(*it) + gap;
        }
        int fill_w = std::max(scale(80), avail - left_fixed - right_fixed - (has_fill ? gap : 0));
        int right_x = x1, left_x = x0;
        for (std::size_t i = r.items.size(); i-- > 0;) {   // right-aligned items, from the right edge
            auto* it = r.items[i];
            if (!it->right) continue;
            int w = it->width > 0 ? item_width(*it) : fill_w;
            right_x -= w;
            place(it->h, right_x, y, w, it->dropdown ? scale(240) : row);
            right_x -= gap;
        }
        for (auto* it : r.items) {
            if (it->right) continue;
            int w = it->width > 0 ? item_width(*it) : fill_w;
            place(it->h, left_x, y, w, it->dropdown ? scale(240) : row);
            left_x += w + gap;
        }
        y += row + gap;
    }
    int body_top = y;
    int body_bottom = y1 - sum_h - gap;
    int total_weight = 0;
    for (auto& rg : page.body_) total_weight += rg.weight;
    int space = body_bottom - body_top - gap * std::max(0, (int)page.body_.size() - 1);
    int by = body_top;
    for (auto& rg : page.body_) {
        int h = total_weight ? std::max(scale(50), space * rg.weight / total_weight) : 0;
        place(rg.h, x0, by, x1 - x0, h);
        by += h + gap;
    }
    place(g.summary, x0, y1 - sum_h, x1 - x0, sum_h);
}

}  // namespace

static int nav_height() { return scale(38) + (g.sub_visible ? scale(40) : 0); }

static void layout() {
    if (!g.tab) return;
    RECT rc;
    GetClientRect(g.hwnd, &rc);
    int W = rc.right, H = rc.bottom, bar = scale(34);
    place(g.tab, 0, 0, W, nav_height());
    int right = W - scale(88) - (g.is_elevated ? 0 : scale(170));   // left of Stop and, when shown, of the administrator button
    place(g.progress, right - scale(150), H - bar + scale(9), scale(140), scale(16));
    place(g.status, scale(12), H - bar + scale(6), std::max(scale(100), right - scale(150) - scale(20)), scale(22));
    place(g.admin_btn, W - scale(244), H - bar + scale(4), scale(160), scale(26));
    place(g.stop_btn, W - scale(80), H - bar + scale(4), scale(72), scale(26));
    RECT d = {0, nav_height(), W, H - bar};
    if (Page* p = g.page()) layout_page(*p, d);
}

// endregion

// region Navigation

static void show_page(int index) {
    g.cur_page = index;
    for (auto& page : g.pages) {
        bool on = page->index_ == index;
        for (HWND h : page->all_) ShowWindow(h, on ? SW_SHOW : SW_HIDE);
    }
    Page& p = *g.pages[index];
    for (auto& grp : g.groups) {
        for (std::size_t i = 0; i < grp.pages.size(); ++i) {
            if (grp.pages[i] == index) grp.last = (int)i;
        }
    }
    SetWindowTextW(g.summary, p.summary_.c_str());
    layout();
    p.last_tick_ = GetTickCount64();
    if (!p.shown_once_) {
        p.shown_once_ = true;
        if (p.on_show) p.on_show();
        if (p.auto_refresh && p.on_refresh && !g.busy) p.on_refresh();
    } else if (p.on_show) {
        p.on_show();
    }
}

static void show_group(int gi) {
    g.cur_group = gi;
    auto& grp = g.groups[gi];
    g.sub_visible = grp.pages.size() > 1;
    int last = std::min(grp.last, (int)grp.pages.size() - 1);
    show_page(grp.pages[last]);
    InvalidateRect(g.tab, nullptr, FALSE);
}

static void apply_font() {
    NONCLIENTMETRICSW ncm{};
    ncm.cbSize = sizeof(ncm);
    SystemParametersInfoForDpi(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0, g.dpi);
    if (g.font) DeleteObject(g.font);
    g.font = CreateFontIndirectW(&ncm.lfMessageFont);
    if (g.mono) DeleteObject(g.mono);
    LOGFONTW mono = ncm.lfMessageFont;
    wcscpy(mono.lfFaceName, L"Consolas");
    g.mono = CreateFontIndirectW(&mono);
    EnumChildWindows(g.hwnd, [](HWND h, LPARAM) -> BOOL {
        wchar_t cls[32];
        GetClassNameW(h, cls, 32);
        bool is_text = !wcscmp(cls, L"Edit") && (GetWindowLongW(h, GWL_STYLE) & ES_MULTILINE);
        SendMessageW(h, WM_SETFONT, (WPARAM)(is_text ? g.mono : g.font), TRUE);
        return TRUE;
    }, 0);
}

// endregion

// region Window

// Colour of a cell by what it says: red = dangerous, orange = look at it, green = fine. COLORREF(-1) = leave it alone.
static COLORREF cell_colour(const std::wstring& raw) {
    if (raw.size() > 24) return (COLORREF)-1;   // only short status words, never a sentence
    std::wstring t = dd::lower(raw);
    {   // an age such as "5.6 years": the older, the worse (old drivers are where the known flaws are)
        double years = 0;
        wchar_t unit[16] = {};
        if (swscanf(t.c_str(), L"%lf %15ls", &years, unit) == 2 && std::wstring(unit) == L"years") {
            if (years >= 8) return RGB(200, 30, 30);
            if (years >= 4) return RGB(190, 100, 0);
            if (years < 2) return RGB(25, 130, 55);
            return (COLORREF)-1;
        }
    }
    auto has = [&](const wchar_t* w) { return t.find(w) != std::wstring::npos; };
    if (has(L"critical") || has(L"suspicious") || has(L"listed") || has(L"not found") || has(L"🔴") || has(L"failed") || t == L"off") return RGB(200, 30, 30);
    if (has(L"warning") || has(L"look at it") || has(L"medium") || has(L"high") || has(L"🟠") || has(L"⚠") || has(L"unknown")) return RGB(190, 100, 0);
    if (t.rfind(L"✅", 0) == 0 || t == L"ok" || t == L"found" || has(L"excellent") || has(L"ordinary") || t == L"quarantined" || t == L"low") return RGB(25, 130, 55);
    return (COLORREF)-1;
}

static LRESULT on_notify(NMHDR* h) {
    if (h->code == NM_CUSTOMDRAW && g.list_events.count((int)h->idFrom)) {
        auto* cd = (NMLVCUSTOMDRAW*)h;
        if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
        if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) return CDRF_NOTIFYSUBITEMDRAW;
        if (cd->nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM)) {
            wchar_t text[256] = {};
            ListView_GetItemText(h->hwndFrom, (int)cd->nmcd.dwItemSpec, cd->iSubItem, text, 256);
            COLORREF c = cell_colour(text);
            cd->clrText = c != (COLORREF)-1 ? c : GetSysColor(COLOR_WINDOWTEXT);   // reset, or the colour carries over to the next cell
            return CDRF_DODEFAULT;
        }
        return CDRF_DODEFAULT;
    }
    auto it = g.list_events.find((int)h->idFrom);
    if (it == g.list_events.end() || g.filling) return 0;
    ListEvents& ev = it->second;
    switch (h->code) {
        case NM_DBLCLK:
            if (ev.on_activate && !g.busy) {
                int i = ((NMITEMACTIVATE*)h)->iItem;
                if (i >= 0) ev.on_activate(i);
            }
            break;
        case LVN_KEYDOWN:
            if (((NMLVKEYDOWN*)h)->wVKey == VK_RETURN && ev.on_activate && !g.busy) {
                int i = ListView_GetNextItem(h->hwndFrom, -1, LVNI_FOCUSED);
                if (i >= 0) ev.on_activate(i);
            }
            break;
        case LVN_COLUMNCLICK:
            if (ev.on_column && !g.busy) ev.on_column(((NMLISTVIEW*)h)->iSubItem);
            break;
        case LVN_ITEMCHANGED: {
            auto* nm = (NMLISTVIEW*)h;
            if (!(nm->uChanged & LVIF_STATE)) break;
            if (ev.on_check && ((nm->uNewState ^ nm->uOldState) & LVIS_STATEIMAGEMASK) && nm->iItem >= 0)
                ev.on_check(nm->iItem, ((nm->uNewState & LVIS_STATEIMAGEMASK) >> 12) == 2);
            if (ev.on_select && ((nm->uNewState ^ nm->uOldState) & LVIS_SELECTED)) ev.on_select();
            break;
        }
    }
    return 0;
}

static LRESULT on_command(WPARAM wp) {
    int id = LOWORD(wp);
    switch (id) {
        case ID_STOP:
        case ID_ACC_STOP: g.stop = true; return 0;
        case ID_ACC_REFRESH:
            if (!g.busy && g.page() && g.page()->on_refresh) g.page()->on_refresh();
            return 0;
        case ID_ACC_COPY: {
            HWND focus = GetFocus();
            wchar_t cls[64];
            GetClassNameW(focus, cls, 64);
            if (!wcscmp(cls, WC_LISTVIEWW)) copy_selected(focus);
            else if (!wcscmp(cls, L"Edit")) SendMessageW(focus, WM_COPY, 0, 0);
            return 0;
        }
        case ID_ADMIN: {
            wchar_t exe[MAX_PATH];
            GetModuleFileNameW(nullptr, exe, MAX_PATH);
            if ((INT_PTR)ShellExecuteW(g.hwnd, L"runas", exe, nullptr, nullptr, SW_SHOWNORMAL) > 32) DestroyWindow(g.hwnd);
            return 0;
        }
    }
    if (HIWORD(wp) == EN_CHANGE || HIWORD(wp) == CBN_SELCHANGE) {
        auto it = g.changes.find(id);
        if (it != g.changes.end()) it->second();
        return 0;
    }
    if (HIWORD(wp) == BN_CLICKED || HIWORD(wp) == 0) {
        auto it = g.commands.find(id);
        if (it != g.commands.end()) it->second();
    }
    return 0;
}

static void save_screenshot() {
    RECT rc;
    GetWindowRect(g.hwnd, &rc);
    int w = rc.right - rc.left, h = rc.bottom - rc.top;
    HDC dc = GetDC(nullptr);
    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, w, h);
    SelectObject(mem, bmp);
    PrintWindow(g.hwnd, mem, PW_RENDERFULLCONTENT);
    BITMAPINFOHEADER bi{sizeof(bi), w, -h, 1, 32, BI_RGB};
    std::string pixels((std::size_t)w * h * 4, '\0');
    GetDIBits(mem, bmp, 0, h, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    BITMAPFILEHEADER fh{0x4D42, (DWORD)(sizeof(fh) + sizeof(bi) + pixels.size()), 0, 0, (DWORD)(sizeof(fh) + sizeof(bi))};
    std::string file((const char*)&fh, sizeof(fh));
    file.append((const char*)&bi, sizeof(bi));
    file += pixels;
    dd::write_file(g.shot_path, file);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(nullptr, dc);
}

// region Navigation bar: main tabs (flat, blue underline) and, below, the pages of the group as pills

struct NavItem {
    RECT rc;
    int index;
    bool sub;
};

static std::vector<NavItem> nav_items() {
    std::vector<NavItem> out;
    HDC dc = GetDC(g.tab);
    HGDIOBJ old = SelectObject(dc, g.font);
    int x = scale(10), h1 = scale(38);
    for (std::size_t i = 0; i < g.groups.size(); ++i) {
        SIZE sz{};
        GetTextExtentPoint32W(dc, g.groups[i].name.c_str(), (int)g.groups[i].name.size(), &sz);
        int w = sz.cx + scale(30);
        out.push_back({{x, 0, x + w, h1}, (int)i, false});
        x += w;
    }
    if (g.sub_visible && g.cur_group >= 0) {
        auto& grp = g.groups[g.cur_group];
        int sx = scale(12);
        for (std::size_t i = 0; i < grp.pages.size(); ++i) {
            const std::wstring& name = g.pages[grp.pages[i]]->name;
            SIZE sz{};
            GetTextExtentPoint32W(dc, name.c_str(), (int)name.size(), &sz);
            int w = sz.cx + scale(28);
            out.push_back({{sx, h1 + scale(5), sx + w, h1 + scale(35)}, (int)i, true});
            sx += w + scale(6);
        }
    }
    SelectObject(dc, old);
    ReleaseDC(g.tab, dc);
    return out;
}

static int nav_hover = -1;   // index into nav_items()

static void paint_nav(HDC dc, const RECT& rc) {
    HBRUSH white = CreateSolidBrush(RGB(255, 255, 255)), strip = CreateSolidBrush(RGB(243, 244, 246));
    FillRect(dc, &rc, white);
    RECT top = {0, 0, rc.right, scale(38)};
    FillRect(dc, &top, strip);
    HPEN line = CreatePen(PS_SOLID, 1, RGB(222, 224, 228));
    HGDIOBJ op = SelectObject(dc, line);
    MoveToEx(dc, 0, scale(38) - 1, nullptr);
    LineTo(dc, rc.right, scale(38) - 1);
    SelectObject(dc, op);
    DeleteObject(line);
    DeleteObject(white);
    DeleteObject(strip);
    SetBkMode(dc, TRANSPARENT);
    SelectObject(dc, g.font);
    auto items = nav_items();
    for (std::size_t n = 0; n < items.size(); ++n) {
        const NavItem& it = items[n];
        bool hot = (int)n == nav_hover;
        RECT r = it.rc;
        if (!it.sub) {
            bool active = it.index == g.cur_group;
            if (hot && !active) {
                HBRUSH b = CreateSolidBrush(RGB(228, 233, 241));
                FillRect(dc, &r, b);
                DeleteObject(b);
            }
            if (active) {
                RECT under = {r.left + scale(8), r.bottom - scale(4), r.right - scale(8), r.bottom - 1};
                HBRUSH b = CreateSolidBrush(RGB(0, 103, 192));
                FillRect(dc, &under, b);
                DeleteObject(b);
            }
            SetTextColor(dc, active ? RGB(0, 80, 156) : RGB(60, 60, 60));
            DrawTextW(dc, g.groups[it.index].name.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        } else {
            auto& grp = g.groups[g.cur_group];
            bool active = grp.pages[it.index] == g.cur_page;
            if (active || hot) {
                HBRUSH b = CreateSolidBrush(active ? RGB(0, 103, 192) : RGB(222, 236, 250));
                HPEN pen = CreatePen(PS_SOLID, 1, active ? RGB(0, 103, 192) : RGB(222, 236, 250));
                HGDIOBJ ob = SelectObject(dc, b), opn = SelectObject(dc, pen);
                RoundRect(dc, r.left, r.top, r.right, r.bottom, scale(16), scale(16));
                SelectObject(dc, ob);
                SelectObject(dc, opn);
                DeleteObject(b);
                DeleteObject(pen);
            }
            SetTextColor(dc, active ? RGB(255, 255, 255) : RGB(50, 50, 50));
            DrawTextW(dc, g.pages[grp.pages[it.index]]->name.c_str(), -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        }
    }
}

static LRESULT CALLBACK nav_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC dc = BeginPaint(hwnd, &ps);
            RECT rc;
            GetClientRect(hwnd, &rc);
            HDC mem = CreateCompatibleDC(dc);
            HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
            HGDIOBJ old = SelectObject(mem, bmp);
            paint_nav(mem, rc);
            BitBlt(dc, 0, 0, rc.right, rc.bottom, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteObject(bmp);
            DeleteDC(mem);
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_MOUSEMOVE: {
            POINT p{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            int hot = -1;
            auto items = nav_items();
            for (std::size_t n = 0; n < items.size(); ++n) {
                if (PtInRect(&items[n].rc, p)) hot = (int)n;
            }
            if (hot != nav_hover) {
                nav_hover = hot;
                InvalidateRect(hwnd, nullptr, FALSE);
            }
            TRACKMOUSEEVENT t{sizeof(t), TME_LEAVE, hwnd, 0};
            TrackMouseEvent(&t);
            SetCursor(LoadCursorW(nullptr, hot >= 0 ? IDC_HAND : IDC_ARROW));
            return 0;
        }
        case WM_MOUSELEAVE:
            nav_hover = -1;
            InvalidateRect(hwnd, nullptr, FALSE);
            return 0;
        case WM_LBUTTONDOWN: {
            POINT p{GET_X_LPARAM(lp), GET_Y_LPARAM(lp)};
            for (const auto& it : nav_items()) {
                if (!PtInRect(&it.rc, p)) continue;
                if (!it.sub) {
                    if (it.index != g.cur_group) show_group(it.index);
                } else {
                    show_page(g.groups[g.cur_group].pages[it.index]);
                    InvalidateRect(hwnd, nullptr, FALSE);
                }
                break;
            }
            return 0;
        }
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// endregion

static void draw_button(const DRAWITEMSTRUCT* d) {
    auto it = g.button_style.find(d->hwndItem);
    int style = it == g.button_style.end() ? 1 : it->second;
    bool disabled = d->itemState & ODS_DISABLED, pressed = d->itemState & ODS_SELECTED;
    COLORREF fill = disabled ? RGB(204, 204, 204) : style == 2 ? (pressed ? RGB(150, 28, 18) : RGB(196, 43, 28)) : (pressed ? RGB(0, 80, 156) : RGB(0, 103, 192));
    HBRUSH bg = GetSysColorBrush(COLOR_WINDOW);
    FillRect(d->hDC, &d->rcItem, GetSysColorBrush(COLOR_WINDOW));
    (void)bg;
    HBRUSH brush = CreateSolidBrush(fill);
    HPEN pen = CreatePen(PS_SOLID, 1, fill);
    HGDIOBJ ob = SelectObject(d->hDC, brush), op = SelectObject(d->hDC, pen);
    int r = scale(6);
    RoundRect(d->hDC, d->rcItem.left, d->rcItem.top, d->rcItem.right, d->rcItem.bottom, r, r);
    SelectObject(d->hDC, ob);
    SelectObject(d->hDC, op);
    DeleteObject(brush);
    DeleteObject(pen);
    wchar_t text[256];
    GetWindowTextW(d->hwndItem, text, 256);
    SelectObject(d->hDC, g.font);
    SetBkMode(d->hDC, TRANSPARENT);
    SetTextColor(d->hDC, disabled ? RGB(245, 245, 245) : RGB(255, 255, 255));
    RECT tr = d->rcItem;
    DrawTextW(d->hDC, text, -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    if (d->itemState & ODS_FOCUS) {
        RECT fr = d->rcItem;
        InflateRect(&fr, -scale(3), -scale(3));
        DrawFocusRect(d->hDC, &fr);
    }
}

static LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
        case WM_DRAWITEM:
            draw_button((const DRAWITEMSTRUCT*)lp);
            return TRUE;
        case WM_CREATE: {
            g.hwnd = hwnd;
            g.dpi = GetDpiForWindow(hwnd);
            apply_font();
            {
                WNDCLASSEXW nc{};
                nc.cbSize = sizeof(nc);
                nc.lpfnWndProc = nav_proc;
                nc.hInstance = g.inst;
                nc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
                nc.lpszClassName = L"DDCleanerNav";
                RegisterClassExW(&nc);
            }
            g.tab = CreateWindowExW(0, L"DDCleanerNav", L"", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS, 0, 0, 10, 10, hwnd, (HMENU)(INT_PTR)ID_TAB, g.inst, nullptr);
            std::vector<HWND> none;
            g.progress = make(nullptr, none, PROGRESS_CLASSW, L"", PBS_MARQUEE | PBS_SMOOTH, ID_PROGRESS);
            g.status = make(nullptr, none, L"STATIC", L"Ready.", SS_CENTERIMAGE | SS_ENDELLIPSIS, ID_STATUS);
            g.summary = make(nullptr, none, L"STATIC", L"", SS_CENTERIMAGE | SS_ENDELLIPSIS, ID_SUMMARY);
            g.stop_btn = make(nullptr, none, L"BUTTON", L"Stop (Esc)", WS_TABSTOP | BS_PUSHBUTTON, ID_STOP);
            g.admin_btn = make(nullptr, none, L"BUTTON", L"Run as administrator", WS_TABSTOP | BS_PUSHBUTTON, ID_ADMIN);
            g.button_style[g.admin_btn] = 1;
            SendMessageW(g.admin_btn, BM_SETSTYLE, BS_OWNERDRAW, TRUE);
            g.button_style[g.stop_btn] = 2;
            SendMessageW(g.stop_btn, BM_SETSTYLE, BS_OWNERDRAW, TRUE);
            ShowWindow(g.status, SW_SHOW);
            ShowWindow(g.summary, SW_SHOW);
            ShowWindow(g.stop_btn, SW_SHOW);
            ShowWindow(g.admin_btn, g.is_elevated ? SW_HIDE : SW_SHOW);
            EnableWindow(g.stop_btn, FALSE);
            ShowWindow(g.progress, SW_HIDE);
            // the pages' controls are created after the window exists
            register_all_pages();
            SetTimer(hwnd, TIMER_ID, 500, nullptr);
            return 0;
        }
        case WM_SIZE:
            layout();
            return 0;
        case WM_GETMINMAXINFO:
            ((MINMAXINFO*)lp)->ptMinTrackSize = {scale(900), scale(560)};
            return 0;
        case WM_DPICHANGED: {
            g.dpi = HIWORD(wp);
            apply_font();
            auto* r = (RECT*)lp;
            SetWindowPos(hwnd, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE);
            layout();
            return 0;
        }
        case WM_TIMER:
            if (wp == TIMER_ID) {
                for (auto& job : periodic()) {
                    if (GetTickCount64() - job.last >= job.ms) {
                        job.last = GetTickCount64();
                        job.fn();
                    }
                }
                Page* p = g.page();
                if (p && p->on_tick && p->tick_ms && !IsIconic(hwnd) && GetTickCount64() - p->last_tick_ >= p->tick_ms) {
                    p->last_tick_ = GetTickCount64();
                    p->on_tick();
                }
            } else if (wp == 2) {   // screenshot mode
                KillTimer(hwnd, 2);
                save_screenshot();
                DestroyWindow(hwnd);
            } else if (wp == 3) {
                KillTimer(hwnd, 3);
                if (g.page() && g.page()->on_refresh) g.page()->on_refresh();
            }
            return 0;
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLORBTN:
            // the page area is drawn white by the tab control: labels and check boxes must not paint a grey box on it
            if (true) {
                SetBkMode((HDC)wp, TRANSPARENT);
                if ((HWND)lp == g.summary) SetTextColor((HDC)wp, RGB(90, 90, 90));
                return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
            }
            break;
        case WM_COMMAND: return on_command(wp);
        case WM_NOTIFY: return on_notify((NMHDR*)lp);
        case WM_JOB: {
            std::unique_ptr<std::function<void()>> job((std::function<void()>*)lp);
            (*job)();
            return 0;
        }
        case WM_CLOSE:
            if (g.busy) {
                g.stop = true;
                set_status(L"Stopping...");
            }
            DestroyWindow(hwnd);
            return 0;
        case WM_DESTROY:
            g.stop = true;
            KillTimer(hwnd, TIMER_ID);
            if (g.worker.joinable()) g.worker.join();
            if (g.quiet.joinable()) g.quiet.join();
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static bool is_elevated_process() {
    HANDLE token = nullptr;
    TOKEN_ELEVATION elevation{};
    DWORD size = 0;
    bool result = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) result = elevation.TokenIsElevated;
        CloseHandle(token);
    }
    return result;
}

int run(HINSTANCE inst, int show, int first_group) {
    g.inst = inst;
    g.is_elevated = is_elevated_process();
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_TAB_CLASSES | ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"DDCleaner";
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(10));
    wc.hIconSm = wc.hIcon;
    RegisterClassExW(&wc);

    int sub_page = -1;
    int argc = 0;
    if (LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc)) {
        for (int i = 1; i < argc; ++i) {
            std::wstring a = argv[i];
            if (a == L"--group" && i + 1 < argc) first_group = _wtoi(argv[++i]);
            else if (a == L"--page" && i + 1 < argc) sub_page = _wtoi(argv[++i]);
            else if (a == L"--shot" && i + 1 < argc) g.shot_path = argv[++i];
            else if (a == L"--delay" && i + 1 < argc) g.shot_delay = _wtoi(argv[++i]);
            else if (a == L"--refresh") g.shot_refresh = true;
        }
        LocalFree(argv);
    }

    std::wstring title = std::wstring(L"DD Cleaner 1.0.0") + (g.is_elevated ? L" - Administrator" : L"");
    HWND hwnd = CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName, title.c_str(), WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN, CW_USEDEFAULT, CW_USEDEFAULT,
                                MulDiv(1240, GetDpiForSystem(), 96), MulDiv(760, GetDpiForSystem(), 96), nullptr, nullptr, inst, nullptr);
    if (!hwnd) return 1;
    if (first_group < 0 || first_group >= (int)g.groups.size()) first_group = 0;
    if (sub_page >= 0 && sub_page < (int)g.groups[first_group].pages.size()) g.groups[first_group].last = sub_page;
    show_group(first_group);
    if (!g.shot_path.empty()) {
        // picture mode: fully transparent, click-through, no taskbar button, no focus: nothing shows on the desktop in use
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, GetWindowLongPtrW(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE);
        SetLayeredWindowAttributes(hwnd, 0, 0, LWA_ALPHA);
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
    } else {
        ShowWindow(hwnd, show);
    }
    UpdateWindow(hwnd);
    if (!g.shot_path.empty()) {
        if (g.shot_refresh) SetTimer(hwnd, 3, 800, nullptr);
        SetTimer(hwnd, 2, (UINT)std::max(1500, g.shot_delay), nullptr);
    }

    ACCEL keys[] = {{FVIRTKEY, VK_ESCAPE, ID_ACC_STOP}, {FVIRTKEY | FCONTROL, 'C', ID_ACC_COPY}, {FVIRTKEY, VK_F5, ID_ACC_REFRESH}};
    HACCEL accel = CreateAcceleratorTableW(keys, 3);
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.hwnd == hwnd || IsChild(hwnd, msg.hwnd)) {
            if (TranslateAcceleratorW(hwnd, accel, &msg)) continue;
            if (IsDialogMessageW(hwnd, &msg)) continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    DestroyAcceleratorTable(accel);
    return (int)msg.wParam;
}

// endregion

}  // namespace ui
