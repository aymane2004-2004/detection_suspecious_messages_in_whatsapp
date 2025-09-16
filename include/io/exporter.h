#ifndef EXPORTER_H
#define EXPORTER_H

#include "core/conversation.h"
#include "analysis/detector.h" // Ajout pour SuspiciousConversation / SuspiciousEntry
#include <string>

namespace Exporter {
    // Export all messages from conversation to CSV file
    bool exportToCSV(const Conversation& conversation, const std::wstring& csvPath);
    
    // Export only specified messages to CSV file
    bool exportToCSV(const std::vector<Message>& messages, const std::wstring& csvPath);
    
    // Export a SuspiciousConversation (détections) vers un CSV
    // Colonnes: Date,Time,Author,MessageType,SuspiciousType,SuspiciousPart,ReasonID,Reason,Score,Content
    bool exportSuspiciousToCSV(const Analysis::SuspiciousConversation& suspicious,
                               const std::wstring& csvPath);

    // Escape special characters in CSV content
    std::wstring escapeCSV(const std::wstring& content);
}

#endif // EXPORTER_H