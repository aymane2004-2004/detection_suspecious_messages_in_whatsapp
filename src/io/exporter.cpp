#include "io/exporter.h"
#include "utils/file_utils.h"
#include "utils/wstring_utils.h"
#include <fstream>
#include <sstream>

namespace Exporter {

    // Helper function to escape special characters in CSV
    std::wstring escapeCSV(const std::wstring& content) {
        std::wstring result = content;
        
        // Replace double quotes with two double quotes (CSV standard)
        size_t pos = 0;
        while ((pos = result.find(L"\"", pos)) != std::wstring::npos) {
            result.replace(pos, 1, L"\"\"");
            pos += 2;
        }
        
        // If content contains comma, newline or quotes, enclose in quotes
        if (WStringUtils::contains(result, L",") || 
            WStringUtils::contains(result, L"\n") || 
            WStringUtils::contains(result, L"\"")) {
            result = L"\"" + result + L"\"";
        }
        
        return result;
    }

    // Convert MessageType enum to string representation
    std::wstring messageTypeToString(MessageType type) {
        switch (type) {
            case MessageType::TEXT:
                return L"TEXT";
            case MessageType::LINK:
                return L"LINK";
            case MessageType::MEDIA_OMITTED:
                return L"MEDIA_OMITTED";
            case MessageType::IMAGE:
                return L"IMAGE";
            case MessageType::VIDEO:
                return L"VIDEO";
            case MessageType::AUDIO:
                return L"AUDIO";
            case MessageType::DOCUMENT:
                return L"DOCUMENT";
            default:
                return L"UNKNOWN";
        }
    }

    // Export all messages from conversation to CSV file
    bool exportToCSV(const Conversation& conversation, const std::wstring& csvPath) {
        return exportToCSV(conversation.getMessages(), csvPath);
    }

    // Export only specified messages to CSV file
    bool exportToCSV(const std::vector<Message>& messages, const std::wstring& csvPath) {
        try {
            std::wofstream csvFile(csvPath);
            csvFile.imbue(std::locale("en_US.UTF-8"));
            
            if (!csvFile.is_open()) {
                return false;
            }
            
            // Write header
            csvFile << L"Date,Time,Author,Type,Content\n";
            
            // Write messages
            for (const auto& message : messages) {
                csvFile << escapeCSV(message.getDate()) << L","
                        << escapeCSV(message.getTime()) << L","
                        << escapeCSV(message.getAuthor()) << L","
                        << escapeCSV(messageTypeToString(message.getType())) << L","
                        << escapeCSV(message.getContent()) << L"\n";
            }
            
            csvFile.close();
            return true;
        }
        catch (const std::exception&) {
            return false;
        }
    }
}