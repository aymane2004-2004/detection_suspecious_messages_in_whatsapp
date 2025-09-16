#ifndef PARSER_H
#define PARSER_H

#include "core/conversation.h"
#include "core/message.h"
#include "utils/file_utils.h"
#include "utils/wstring_utils.h"

#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>

namespace Parser {
    /**
     * @brief Classifies a message based on its content
     *
     * Detects:
     * - File attachments
     * - Media omitted markers
     * - URLs with protocol (http/https)
     * - Bare domains like "google.com" (without protocol)
     */
    inline MessageType classify(const std::wstring& content) {
        if (content.empty()) {
            return MessageType::TEXT; // Or introduce MessageType::EMPTY if you have/need it
        }
        // Regular expressions for detection
        std::wregex mediaPattern(L"<(Media|image|video|audio|document) omitted>");
        std::wregex protocolUrlPattern(L"(https?://[^\\s]+)");

        // NOTE: Removed look-behind that caused regex_error(error_syntax).
        // ECMAScript (default std::regex grammar) does NOT support look-behind.
        // New pattern:
        // - Starts at a word boundary
        // - Captures domain with known TLDs
        // - Optional path/query
        // - Positive lookahead to ensure termination boundary (space, end, or punctuation)
        std::wregex bareUrlPattern(
            L"\\b("
                L"(?:[A-Za-z0-9-]+\\.)+"
                L"(?:com|net|org|edu|gov|io|ai|co|us|uk|dev|app|info|biz|me|xyz|online|shop|fr|ma|de|es|it|ca|"
                L"au|jp|cn|br|in|ru|za|ch|nl|se|no|dk|be|pl)"
            L")"
            L"(?:/[\\w\\-._~:/?#[\\]@!$&'()*+,;=%]*)?"
            L"(?=(?:\\s|$|[)\\]?!,.;:]))"
        );

        std::wregex filePattern(L"(.+\\.\\w+)\\s*\\(file attached\\)");
        std::wsmatch matches;

        // File attachments
        if (std::regex_search(content, matches, filePattern)) {
            std::wstring filename = matches[1].str();
            std::wstring extension = filename.substr(filename.find_last_of(L'.') + 1);
            extension = WStringUtils::toLower(extension);

            if (extension == L"jpg" || extension == L"png" || extension == L"gif" ||
                extension == L"jpeg" || extension == L"bmp" || extension == L"webp") return MessageType::IMAGE;
            if (extension == L"mp4" || extension == L"mkv" || extension == L"avi" ||
                extension == L"mov" || extension == L"wmv") return MessageType::VIDEO;
            if (extension == L"mp3" || extension == L"wav" || extension == L"ogg" ||
                extension == L"m4a" || extension == L"flac" ) return MessageType::AUDIO;
            if (extension == L"pdf" || extension == L"doc" || extension == L"docx" ||
                extension == L"txt" || extension == L"xls" || extension == L"xlsx" ||
                extension == L"ppt" || extension == L"pptx") return MessageType::DOCUMENT;
            return MessageType::DOCUMENT;
        }

        // Media omitted markers
        if (std::regex_search(content, matches, mediaPattern)) {
            if (WStringUtils::contains(content, L"image")) return MessageType::IMAGE;
            if (WStringUtils::contains(content, L"video")) return MessageType::VIDEO;
            if (WStringUtils::contains(content, L"audio")) return MessageType::AUDIO;
            if (WStringUtils::contains(content, L"document")) return MessageType::DOCUMENT;
            return MessageType::MEDIA_OMITTED;
        }

        // Collect URLs
        std::vector<std::wstring> urls;

        auto sanitize = [](std::wstring url) {
            while (!url.empty()) {
                wchar_t c = url.back();
                if (c == L'.' || c == L',' || c == L'!' || c == L'?' ||
                    c == L')' || c == L';' || c == L':') {
                    url.pop_back();
                } else break;
            }
            return url;
        };

        // Protocol URLs
        std::wstring::const_iterator searchStart = content.cbegin();
        while (std::regex_search(searchStart, content.cend(), matches, protocolUrlPattern)) {
            std::wstring found = sanitize(matches[0].str());
            if (!found.empty()) urls.push_back(found);
            searchStart = matches.suffix().first;
        }

        // Bare domains
        searchStart = content.cbegin();
        while (std::regex_search(searchStart, content.cend(), matches, bareUrlPattern)) {
            std::wstring found = sanitize(matches[1].str());

            // Skip if part of an email (preceded by '@')
            size_t posInText = static_cast<size_t>(matches.position(1));
            if (posInText > 0 && content[posInText - 1] == L'@') {
                searchStart = matches.suffix().first;
                continue;
            }

            if (!found.empty()) {
                bool exists = false;
                for (const auto& u : urls) if (u == found) { exists = true; break; }
                if (!exists) urls.push_back(found);
            }
            searchStart = matches.suffix().first;
        }

        if (!urls.empty()) {
            std::wstring contentCopy = content;
            for (const auto& url : urls) {
                size_t pos = 0;
                while ((pos = contentCopy.find(url, pos)) != std::wstring::npos) {
                    contentCopy.replace(pos, url.length(), L"");
                }
            }
            contentCopy = WStringUtils::trim(contentCopy);
            return contentCopy.empty() ? MessageType::LINK : MessageType::TEXT_LINK;
        }

        return MessageType::TEXT;
    }

    inline void displayProgressBar(int progress) {
        const int barWidth = 20;
        int filledWidth = barWidth * progress / 100;
        std::cout << "\r[";
        for (int i = 0; i < barWidth; ++i) std::cout << (i < filledWidth ? "#" : "-");
        std::cout << "] " << progress << "%" << std::flush;
    }

    inline bool parseWhatsAppChat(const std::wstring& filePath, Conversation& conversation) {
        try {
            std::vector<std::wstring> lines = FileUtils::readFileLines(filePath);
            if (lines.empty()) {
                std::wcerr << L"The chat file is empty or could not be read." << std::endl;
                return false;
            }
            displayProgressBar(0);

            // Updated pattern:
            // Allow empty content: (.*)
            // Make the space after ':' optional: : ?
            std::wregex messagePattern(
                L"(\\d{1,2}/\\d{1,2}/\\d{2}), (\\d{1,2}:\\d{2})(:\\d{2})? - ([^:]+): ?(.*)"
            );

            std::wstring currentDate, currentTime, currentAuthor, currentContent;
            MessageType currentType = MessageType::UNKNOWN;

            const size_t totalLines = lines.size();
            size_t processedLines = 0;

            for (const auto& line : lines) {
                std::wsmatch matches;
                if (std::regex_search(line, matches, messagePattern)) {
                    // Flush previous message (even if content empty)
                    if (!currentAuthor.empty()) {
                        conversation.addMessage(Message(
                            currentDate,
                            currentTime,
                            currentAuthor,
                            currentContent,
                            currentType
                        ));
                    }

                    currentDate   = matches[1].str();
                    currentTime   = matches[2].str();
                    if (matches[3].matched) currentTime += matches[3].str();
                    currentAuthor = WStringUtils::trim(matches[4].str());
                    currentContent = matches[5].str(); // May be empty
                    currentType = classify(currentContent);
                } else if (!currentAuthor.empty()) {
                    // Continuation line
                    currentContent += L"\n" + line;
                    currentType = classify(currentContent);
                }

                if (++processedLines % 10 == 0 || processedLines == totalLines) {
                    int progress = static_cast<int>(
                        (static_cast<double>(processedLines) / totalLines) * 100
                    );
                    displayProgressBar(progress);
                }
            }

            // Flush last message
            if (!currentAuthor.empty()) {
                conversation.addMessage(Message(
                    currentDate,
                    currentTime,
                    currentAuthor,
                    currentContent,
                    currentType
                ));
            }

            displayProgressBar(100);
            std::cout << std::endl;
            return true;
        } catch (const std::exception& e) {
            std::cerr << "\nError parsing WhatsApp chat: " << e.what() << std::endl;
            return false;
        }
    }

    inline std::wstring standardizeDate(const std::wstring& dateStr) {
        std::wregex datePattern(L"(\\d{1,2})/(\\d{1,2})/(\\d{2})");
        std::wsmatch matches;
        if (std::regex_match(dateStr, matches, datePattern)) {
            int month = std::stoi(matches[1].str());
            int day = std::stoi(matches[2].str());
            int year = std::stoi(matches[3].str());
            if (year < 100) year += 2000;
            std::wstringstream ss;
            ss << year << L"-"
               << (month < 10 ? L"0" : L"") << month << L"-"
               << (day < 10 ? L"0" : L"") << day;
            return ss.str();
        }
        return dateStr;
    }

    inline std::wstring standardizeTime(const std::wstring& timeStr) {
        std::wregex timePattern(L"(\\d{1,2}):(\\d{2}):(\\d{2}) ([AP]M)");
        std::wsmatch matches;
        if (std::regex_match(timeStr, matches, timePattern)) {
            int hour = std::stoi(matches[1].str());
            int minute = std::stoi(matches[2].str());
            int second = std::stoi(matches[3].str());
            std::wstring ampm = matches[4].str();
            if (ampm == L"PM" && hour < 12) hour += 12;
            else if (ampm == L"AM" && hour == 12) hour = 0;
            std::wstringstream ss;
            ss << (hour < 10 ? L"0" : L"") << hour << L":"
               << (minute < 10 ? L"0" : L"") << minute << L":"
               << (second < 10 ? L"0" : L"") << second;
            return ss.str();
        }
        return timeStr;
    }
} // namespace Parser

#endif // PARSER_H