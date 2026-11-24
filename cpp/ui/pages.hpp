// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Declares the build function of each page group, the shared header of all the page source files.

#pragma once

#include <string>
#include <vector>

#include <ddcore/common.hpp>

#include "ui.hpp"

void build_garbage_pages();
void build_system_pages();
void build_driver_pages();
void build_network_pages();
void build_hunt_pages();
void build_antivirus_pages();
void build_security_pages();

// Actions that several pages use, defined by the page that owns them
void scan_with_clamav(const std::vector<std::wstring>& paths);   // switches to the Antivirus group and scans
void virustotal_lookup(const std::wstring& path);                // hash lookup, report dialog
void virustotal_lookup_hash(const std::wstring& sha256, const std::wstring& label);

// Helpers for the pages (page_common.cpp)
#include <ddcore/sysinfo.hpp>
std::wstring status_label(dd::Status s);                          // "OK", "Warning"... with a symbol
std::wstring bar_text(double fraction, int width = 24);           // a text bar for the overview lists
