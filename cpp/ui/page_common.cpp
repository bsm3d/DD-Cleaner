// DD Cleaner
// © Benoit Saint-Moulin - 2026
// Version du fichier : 1.0.0
// Fonction du fichier : Helpers shared by the pages: status labels from the engine status values and the drawing of progress bars.

#include "pages.hpp"

#include <algorithm>

std::wstring status_label(dd::Status s) {
    switch (s) {
        case dd::Status::Ok: return L"✅ OK";
        case dd::Status::Info: return L"ℹ️ Info";
        case dd::Status::Warning: return L"⚠️ Warning";
        case dd::Status::Critical: return L"\U0001F534 Critical";
        case dd::Status::Unknown: return L"❔ Unknown";
    }
    return L"";
}

std::wstring bar_text(double fraction, int width) {
    int n = (int)(std::max(0.0, std::min(1.0, fraction)) * width + 0.5);
    return std::wstring((std::size_t)n, L'█') + std::wstring((std::size_t)(width - n), L'░');
}
