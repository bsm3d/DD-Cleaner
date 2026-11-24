// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the small Win32 page framework: toolbars, lists and text panes, with the worker and dialogs every page needs.

// Pages are declared in code: a toolbar (buttons, combos, edits), then a body of lists and text panes sharing the height.
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <windows.h>
#include <commctrl.h>
#include <windowsx.h>

#include <ddcore/common.hpp>
#include <ddcore/proc.hpp>

namespace ui {

using dd::Progress;
using dd::Stop;

struct Column {
    const wchar_t* title;
    int width;          // in 96-dpi pixels
    bool right = false;
};

struct ListEvents {
    std::function<void(int row)> on_activate;       // double click or Enter
    std::function<void(int column)> on_column;      // header click
    std::function<void()> on_select;                // selection changed
    std::function<void(int row, bool checked)> on_check;
};

constexpr int FILL = -1;   // a label that takes the rest of the row

class Page {
public:
    std::wstring group, name;

    // Toolbar (items flow left to right and wrap; width 0 = fills what is left of the row; right = stuck to the right edge)
    HWND button(const std::wstring& text, std::function<void()> fn, int width = 0, bool action = true, bool right = false);
    HWND label(const std::wstring& text, int width = 0);
    HWND combo(const std::vector<std::wstring>& options, int selected, int width = 150, bool editable = false);
    HWND edit(const std::wstring& text, int width = 0, bool readonly = false, bool password = false);
    HWND check(const std::wstring& text, int width = 0, bool checked = false);
    void newline();

    // Body (regions share the height by weight)
    HWND list(std::vector<Column> columns, int weight = 3, bool checks = false, ListEvents events = {});
    HWND text(int weight = 1);                       // read-only multi-line text
    HWND custom(const wchar_t* window_class, int weight, DWORD style = 0, DWORD ex_style = 0);

    void on_change(HWND edit_or_combo, std::function<void()> fn);   // text typed or selection changed
    void set_summary(const std::wstring& text);
    const std::wstring& summary() const { return summary_; }

    std::function<void()> on_refresh;                // F5 and the "refresh" of the page
    std::function<void()> on_show;                   // each time the page is shown
    std::function<void()> on_tick;                   // every tick_ms while the page is shown
    unsigned tick_ms = 0;
    bool auto_refresh = false;                       // run on_refresh the first time the page is shown

// internals, used by core.cpp
    struct Item {
        enum Kind { Button, Label, Combo, Edit, Check, Newline } kind;
        HWND h = nullptr;
        int width = 0;
        bool right = false;
        bool dropdown = false;
    };
    struct Region {
        HWND h;
        int weight;
    };
    std::vector<Item> items_;
    std::vector<Region> body_;
    std::vector<HWND> all_;
    std::wstring summary_;
    int index_ = -1;
    bool shown_once_ = false;
    ULONGLONG last_tick_ = 0;
};

Page& add_page(const std::wstring& group, const std::wstring& name);

// region Lists
void set_rows(HWND lv, const std::vector<std::vector<std::wstring>>& rows);   // replaces everything (redraw off while filling)
void set_columns(HWND lv, const std::vector<Column>& columns);
bool is_checked(HWND lv, int row);
void set_checked(HWND lv, int row, bool checked);
void set_all_checked(HWND lv, bool checked);
std::vector<int> selected_rows(HWND lv);
int row_count(HWND lv);
void export_list(HWND lv, const std::wstring& suggested_name);   // Save dialog, then CSV (UTF-8 with a BOM)
// endregion

// region Text panes
void set_text(HWND h, const std::wstring& text);   // CRLF handled
void append_text(HWND h, const std::wstring& text);
std::wstring get_text(HWND h);
// endregion

// region Messages and dialogs (all modal on the main window)
void info(const std::wstring& text);
void warn(const std::wstring& text);
bool confirm(const std::wstring& text, const std::wstring& title = L"DD Cleaner", bool warning = false);   // Yes/No, No is the default
void show_text(const std::wstring& title, const std::wstring& text, int width = 760, int height = 520);

struct DialogSpec {
    std::wstring title, prompt;
    enum Body { None, List, Text, Input } body = None;
    std::vector<Column> columns;
    std::vector<std::vector<std::wstring>> rows;
    bool checks = false;                             // List: a checkbox per row
    std::vector<bool> checked;                       // List: initial state
    std::wstring text;                               // Text or Input: initial content
    bool password = false, read_only = false;        // Input
    // (label, result), the first is the default. A result of -1 copies the text and stays open; -2 or less calls `action` and stays open
    std::vector<std::pair<std::wstring, int>> buttons = {{L"OK", 1}, {L"Cancel", 0}};
    std::function<void(HWND body, int result, HWND button)> action;
    int width = 680, height = 460;
};
struct DialogResult {
    int button = 0;                                  // the result value of the button pressed (0 when closed)
    int row = -1;                                    // List: the selected row
    std::vector<bool> checked;                       // List with checks
    std::wstring text;                               // Input or Text
};
DialogResult run_dialog(const DialogSpec& spec);

std::wstring choose_folder(const std::wstring& title);
std::wstring open_file(const std::wstring& title, const wchar_t* filter = L"All files\0*.*\0");
std::wstring save_file(const std::wstring& title, const std::wstring& suggested, const wchar_t* filter = L"All files\0*.*\0", const wchar_t* ext = L"");
// endregion

// region Work
using Work = std::function<std::function<void()>(const Stop&, const Progress&)>;
// One task at a time: the buttons marked as actions are disabled, the status bar shows `what`. The returned function runs on the UI thread.
bool run_async(const std::wstring& what, Work work);
// A background refresh that never blocks the buttons (live traffic). Skipped when the previous one has not finished.
void run_quiet(Work work);
void post_job(std::function<void()> job);          // run on the UI thread (any thread may call)
bool busy();
void set_status(const std::wstring& text);
bool stop_requested();
// endregion

// region Helpers
bool elevated();
void copy_to_clipboard(const std::wstring& text);
void copy_secret(const std::wstring& text);        // copies, and empties the clipboard 30 seconds later if it still holds the text
void after(unsigned ms, std::function<void()> fn);   // runs once on the UI thread
void every(unsigned ms, std::function<void()> fn);   // runs on the UI thread for as long as the program lives, whatever page is shown
void select_page(const std::wstring& group, const std::wstring& name);
void reveal(const std::wstring& path);             // Explorer with the file selected
void open_url(const std::wstring& url);            // only https:// and http:// are opened
int scale(int px);
HWND main_window();
HFONT font();
HFONT mono_font();
std::wstring trimmed(HWND h);                      // window text, trimmed
int combo_index(HWND h);
std::wstring combo_text(HWND h);
bool checked(HWND h);
// endregion

void register_all_pages();                         // defined by the page files
int run(HINSTANCE inst, int show, int first_group);

}  // namespace ui
