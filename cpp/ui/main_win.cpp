// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Windows entry point wWinMain that registers the page groups and starts the DD Cleaner window.

// DD Cleaner, Windows version: plain Win32 + common controls, on top of the ddcore engine.
// The window, tabs, worker and dialogs are in core.cpp; each group of pages is in its own page_*.cpp file.
#include "pages.hpp"

void ui::register_all_pages() {
    build_driver_pages();
    build_system_pages();
    build_network_pages();
    build_security_pages();
    build_antivirus_pages();
    build_hunt_pages();
    build_garbage_pages();
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE, PWSTR, int show) {
    int code = ui::run(inst, show, 0);
    ExitProcess((UINT)code);   // the worker threads of the traffic monitor end with the process
}
