#ifndef REPORT_H
#define REPORT_H

#include "analysis/suspicious_conversation.h"
#include <string>
#include <cstddef>

namespace Report {

    struct ReportGenerationOptions {
        size_t totalMessagesInConversation = 0; // Total messages (all, not only suspicious). 0 = unknown.
        size_t maxExamplesPerCategory = 5;
        bool   includePerEntrySection = true;
        bool   includeTopEntries = true;
        size_t topEntriesCount = 10;
    };

    // Generate a textual analytical report (UTF-8) about a SuspiciousConversation.
    // Returns true on success.
    bool generateReport(const Analysis::SuspiciousConversation& suspicious,
        const std::wstring& outputPath,
        const ReportGenerationOptions& options = {});

} // namespace Report

#endif // REPORT_H