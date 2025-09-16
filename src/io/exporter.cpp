#include "io/exporter.h"
#include "utils/wstring_utils.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <locale>
#include <system_error>
#include <iostream>
#include <algorithm>   // <-- added
#include <tuple>       // <-- added

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
    static std::wstring escapeCSVImpl(const std::wstring& content) {
        std::wstring result = content;

        size_t pos = 0;
        while ((pos = result.find(L"\"", pos)) != std::wstring::npos) {
            result.replace(pos, 1, L"\"\""); // double quotes
            pos += 2;
        }

        if (WStringUtils::contains(result, L",") ||
            WStringUtils::contains(result, L"\n") ||
            WStringUtils::contains(result, L"\"")) {
            result = L"\"" + result + L"\"";
        }
        return result;
    }

    std::wstring escapeCSV(const std::wstring& content) {
        return escapeCSVImpl(content);
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
            std::ofstream csvFile(std::filesystem::path(csvPath), std::ios::binary | std::ios::trunc);
            if (!csvFile.is_open()) {
                return false;
            }

            const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
            csvFile.write(reinterpret_cast<const char*>(bom), 3);

            std::wstring header = L"Date,Time,Author,Type,Content\n";
            auto h8 = wstringToUtf8(header);
            csvFile.write(h8.c_str(), h8.size());

            for (const auto& message : messages) {
                std::wstring row;
                row.reserve(128 + message.getContent().size());

                row.append(escapeCSVImpl(message.getDate())); row.push_back(L',');
                row.append(escapeCSVImpl(message.getTime())); row.push_back(L',');
                row.append(escapeCSVImpl(message.getAuthor())); row.push_back(L',');
                row.append(escapeCSVImpl(messageTypeToString(message.getType()))); row.push_back(L',');
                row.append(escapeCSVImpl(message.getContent())); row.push_back(L'\n');

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

    namespace {
        // Parse date in formats:
        //  - YYYY-MM-DD  (if first token has length 4)
        //  - MM/DD/YY or M/D/YY (ALWAYS interpreted as month/day/year when not YYYY-first)
        // Returns false on failure.
        bool parseDate(const std::wstring& s, int& y, int& m, int& d) {
            y = m = d = 0;
            if (s.empty()) return false;

            wchar_t sep = 0;
            if (s.find(L'-') != std::wstring::npos) sep = L'-';
            else if (s.find(L'/') != std::wstring::npos) sep = L'/';
            if (!sep) return false;

            size_t p1 = s.find(sep);
            size_t p2 = (p1 == std::wstring::npos) ? std::wstring::npos : s.find(sep, p1 + 1);
            if (p1 == std::wstring::npos || p2 == std::wstring::npos) return false;

            std::wstring a = s.substr(0, p1);
            std::wstring b = s.substr(p1 + 1, p2 - (p1 + 1));
            std::wstring c = s.substr(p2 + 1);

            auto toInt = [](const std::wstring& w) -> int {
                if (w.empty()) return -1;
                try { return std::stoi(w); } catch (...) { return -1; }
            };

            if (a.size() == 4) {
                // YYYY-MM-DD
                y = toInt(a);
                m = toInt(b);
                d = toInt(c);
            } else {
                // Interpret strictly as MM/DD/YY
                m = toInt(a);
                d = toInt(b);
                y = toInt(c);
                if (y >= 0 && y < 100) y += 2000; // assume 2000+ for 2-digit years
            }

            if (y < 0 || m < 1 || m > 12 || d < 1 || d > 31) return false;
            return true;
        }

        // Parse time "HH:MM" or "HH:MM:SS"
        bool parseTime(const std::wstring& s, int& H, int& M, int& S) {
            if (s.empty()) return false;
            size_t p1 = s.find(L':');
            if (p1 == std::wstring::npos) return false;
            size_t p2 = s.find(L':', p1 + 1);

            auto toInt = [](const std::wstring& w)->int {
                if (w.empty()) return -1;
                try { return std::stoi(w); } catch (...) { return -1; }
            };

            H = toInt(s.substr(0, p1));
            M = toInt(s.substr(p1 + 1, (p2 == std::wstring::npos ? s.size() : p2) - (p1 + 1)));
            if (p2 != std::wstring::npos) {
                S = toInt(s.substr(p2 + 1));
            } else {
                S = 0;
            }
            if (H < 0 || H > 23 || M < 0 || M > 59 || S < 0 || S > 59) return false;
            return true;
        }

        // Build a sortable 64-bit key from date + time; fallback puts invalids at end.
        uint64_t dateTimeKey(const Message& m) {
            int y=0,mn=0,d=0;
            int H=0,Mi=0,S=0;
            if (!parseDate(m.getDate(), y, mn, d)) {
                // push invalid dates to end
                return (std::numeric_limits<uint64_t>::max)();
            }
            if (!parseTime(m.getTime(), H, Mi, S)) {
                H = Mi = S = 0;
            }
            // Compose key: yyyyyyyy mm dd hh mm ss into numeric (fits safely)
            return (static_cast<uint64_t>(y)   << 32) |
                   (static_cast<uint64_t>(mn)  << 24) |
                   (static_cast<uint64_t>(d)   << 16) |
                   (static_cast<uint64_t>(H)   << 12) |
                   (static_cast<uint64_t>(Mi)  << 6 ) |
                   (static_cast<uint64_t>(S));
        }
    }

    bool exportSuspiciousToCSV(const Analysis::SuspiciousConversation& suspicious,
                               const std::wstring& csvPath)
    {
        try {
            if (csvPath.empty()) {
                std::wcerr << L"[Exporter] Chemin CSV vide.\n";
                return false;
            }

            std::filesystem::path outPath(csvPath);
            if (!outPath.has_parent_path()) {
                std::wcerr << L"[Exporter] Chemin invalide (pas de dossier parent) : " << csvPath << L"\n";
                return false;
            }

            std::error_code ec;
            std::filesystem::create_directories(outPath.parent_path(), ec);
            if (ec) {
                std::wcerr << L"[Exporter] Impossible de créer le dossier: "
                           << outPath.parent_path().wstring()
                           << L" | code=" << ec.value() << L" (" << ec.message().c_str() << L")\n";
                return false;
            }

            std::ofstream csvFile(outPath, std::ios::binary | std::ios::trunc);
            if (!csvFile.is_open()) {
                std::wcerr << L"[Exporter] Échec d'ouverture du fichier: " << csvPath << L"\n";
                return false;
            }

            // UTF-8 BOM
            const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
            csvFile.write(reinterpret_cast<const char*>(bom), 3);

            // Header
            std::wstring header = L"Date,Time,Author,MessageType,SuspiciousType,SuspiciousPart,ReasonID,Reason,Score,Content\n";
            auto headerUtf8 = wstringToUtf8(header);
            csvFile.write(headerUtf8.c_str(), headerUtf8.size());

            // Copy & sort entries by (date,time)
            std::vector<Analysis::SuspiciousEntry> sorted = suspicious.getEntries();
            std::stable_sort(sorted.begin(), sorted.end(),
                [](const Analysis::SuspiciousEntry& a, const Analysis::SuspiciousEntry& b) {
                    return dateTimeKey(a.message) < dateTimeKey(b.message);
                });

            if (sorted.empty()) {
                std::wcerr << L"[Exporter] Avertissement: aucun message suspect. Fichier créé avec seulement l'entête.\n";
            }

            for (const auto& e : sorted) {
                const Message& m = e.message;

                std::wstring row;
                row.reserve(256 + m.getContent().size() + e.suspiciousPart.size());

                std::wstringstream ss;
                ss.imbue(std::locale::classic());
                ss << e.score;
                std::wstring scoreStr = ss.str();

                row.append(escapeCSVImpl(m.getDate())); row.push_back(L',');
                row.append(escapeCSVImpl(m.getTime())); row.push_back(L',');
                row.append(escapeCSVImpl(m.getAuthor())); row.push_back(L',');
                row.append(escapeCSVImpl(messageTypeToString(m.getType()))); row.push_back(L',');
                row.append(escapeCSVImpl(toWString(e.itemType))); row.push_back(L',');
                row.append(escapeCSVImpl(e.suspiciousPart)); row.push_back(L',');
                row.append(escapeCSVImpl(std::to_wstring(e.reasonID))); row.push_back(L',');
                row.append(escapeCSVImpl(e.reason)); row.push_back(L',');
                row.append(escapeCSVImpl(scoreStr)); row.push_back(L',');
                row.append(escapeCSVImpl(m.getContent())); row.push_back(L'\n');

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