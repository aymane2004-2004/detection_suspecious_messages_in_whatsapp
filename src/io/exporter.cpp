#include "io/exporter.h"
#include "utils/wstring_utils.h"
#include <fstream>
#include <sstream>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#endif

namespace Exporter {

    // Convert wstring -> UTF-8
    static std::string wstringToUtf8(const std::wstring& w) {
#ifdef _WIN32
        if (w.empty()) return {};
        int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
                                             static_cast<int>(w.size()),
                                             nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) return {};
        std::string utf8(sizeNeeded, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
                            static_cast<int>(w.size()),
                            utf8.data(), sizeNeeded, nullptr, nullptr);
        return utf8;
#else
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(w);
#endif
    }

    // Helper function to escape special characters in CSV (works on wide, then converted)
    static std::wstring escapeCSV(const std::wstring& content) {
        std::wstring result = content;

        size_t pos = 0;
        while ((pos = result.find(L"\"", pos)) != std::wstring::npos) {
            result.replace(pos, 1, L"\"\"");
            pos += 2;
        }

        if (WStringUtils::contains(result, L",") ||
            WStringUtils::contains(result, L"\n") ||
            WStringUtils::contains(result, L"\"")) {
            result = L"\"" + result + L"\"";
        }
        return result;
    }

    static std::wstring messageTypeToString(MessageType type) {
        switch (type) {
        case MessageType::TEXT: return L"TEXT";
        case MessageType::LINK: return L"LINK";
        case MessageType::TEXT_LINK: return L"TEXT_LINK";
        case MessageType::MEDIA_OMITTED: return L"MEDIA_OMITTED";
        case MessageType::IMAGE: return L"IMAGE";
        case MessageType::VIDEO: return L"VIDEO";
        case MessageType::AUDIO: return L"AUDIO";
        case MessageType::DOCUMENT: return L"DOCUMENT";
        default: return L"UNKNOWN";
        }
    }

    bool exportToCSV(const Conversation& conversation, const std::wstring& csvPath) {
        return exportToCSV(conversation.getMessages(), csvPath);
    }

    bool exportToCSV(const std::vector<Message>& messages, const std::wstring& csvPath) {
        try {
            // C++17: ofstream accepts std::filesystem::path (wide on Windows)
            std::ofstream csvFile(std::filesystem::path(csvPath), std::ios::binary | std::ios::trunc);
            if (!csvFile.is_open()) {
                return false;
            }

            // Write UTF-8 BOM for Excel compatibility
            const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
            csvFile.write(reinterpret_cast<const char*>(bom), 3);

            // Header
            {
                std::wstring header = L"Date,Time,Author,Type,Content\n";
                csvFile.write(wstringToUtf8(header).c_str(), wstringToUtf8(header).size());
            }

            // Rows
            for (const auto& message : messages) {
                std::wstring row;
                row.reserve(128 + message.getContent().size());

                row.append(escapeCSV(message.getDate())); row.push_back(L',');
                row.append(escapeCSV(message.getTime())); row.push_back(L',');
                row.append(escapeCSV(message.getAuthor())); row.push_back(L',');
                row.append(escapeCSV(messageTypeToString(message.getType()))); row.push_back(L',');
                row.append(escapeCSV(message.getContent())); row.push_back(L'\n');

                std::string utf8 = wstringToUtf8(row);
                csvFile.write(utf8.data(), utf8.size());
            }

            csvFile.close();
            return true;
        }
        catch (...) {
            return false;
        }
    }

} // namespace Exporter