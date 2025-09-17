#ifndef REPORT_H
#define REPORT_H

#include "analysis/suspicious_conversation.h"
#include <string>
#include <cstddef>

namespace Report {

    enum class Language {
        EN,
        FR
    };

    struct ReportGenerationOptions {
        size_t totalMessagesInConversation = 0; // Total messages (all, not only suspicious). 0 = unknown.
        size_t maxExamplesPerCategory = 5;
        bool   includePerEntrySection = true;
        bool   includeTopEntries = true;
        size_t topEntriesCount = 10;
        Language language = Language::EN; // Choix de la langue du rapport
    };

    // Génère un rapport analytique textuel (UTF-8) sur une conversation suspecte.
    // Retourne true en cas de succès.
    bool generateReport(const Analysis::SuspiciousConversation& suspicious,
        const std::wstring& outputPath,
        const ReportGenerationOptions& options = {});

} // namespace Report

#endif // REPORT_H