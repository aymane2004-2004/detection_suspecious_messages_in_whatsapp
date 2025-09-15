#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>

#ifdef _WIN32
#include <windows.h>
#else
#include <locale>
#include <codecvt>
#endif

namespace FileUtils {

    // Convert full UTF-8 buffer to std::wstring (UTF-16 on Windows, UTF-32 on Linux)
    inline std::wstring utf8ToWstring(const std::string& utf8) {
#ifdef _WIN32
        if (utf8.empty()) return L"";
        int required = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                           utf8.c_str(), static_cast<int>(utf8.size()),
                                           nullptr, 0);
        if (required <= 0) {
            throw std::runtime_error("UTF-8 to UTF-16 size calculation failed (possibly invalid UTF-8).");
        }
        std::wstring wide(static_cast<size_t>(required), L'\0');
        int converted = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                                            utf8.c_str(), static_cast<int>(utf8.size()),
                                            &wide[0], required);
        if (converted != required) {
            throw std::runtime_error("UTF-8 to UTF-16 conversion failed.");
        }
        return wide;
#else
        // Fallback for non-Windows (codecvt still works in C++17 despite deprecation)
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.from_bytes(utf8);
#endif
    }

    // Reads a UTF-8 (WhatsApp export) file into a vector<wstring>, safely handling emojis
    inline std::vector<std::wstring> readFileLines(const std::wstring& filepath) {
        // Open in binary to avoid newline translation
#ifdef _WIN32
        std::ifstream file(filepath.c_str(), std::ios::binary);
#else
        std::string narrowPath(filepath.begin(), filepath.end());
        std::ifstream file(narrowPath, std::ios::binary);
#endif
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + std::string(filepath.begin(), filepath.end()));
        }

        // Read entire file
        std::string buffer;
        file.seekg(0, std::ios::end);
        std::streampos size = file.tellg();
        file.seekg(0, std::ios::beg);
        buffer.resize(static_cast<size_t>(size));
        if (size > 0) file.read(&buffer[0], size);

        // Normalize line endings to '\n'
        // WhatsApp exports typically use '\r\n' on Windows
        std::string normalized;
        normalized.reserve(buffer.size());
        for (size_t i = 0; i < buffer.size(); ++i) {
            char c = buffer[i];
            if (c == '\r') {
                // Skip '\r'; handle "\r\n" by ignoring '\r'
                continue;
            }
            normalized.push_back(c);
        }

        // Split manually to avoid partial conversion issues
        std::vector<std::wstring> lines;
        size_t start = 0;
        while (start <= normalized.size()) {
            size_t pos = normalized.find('\n', start);
            std::string lineUtf8 = (pos == std::string::npos)
                ? normalized.substr(start)
                : normalized.substr(start, pos - start);
            lines.push_back(utf8ToWstring(lineUtf8));
            if (pos == std::string::npos) break;
            start = pos + 1;
        }

        return lines;
    }

    // Writes lines to a UTF-8 text file
    inline void writeFileLines(const std::wstring& filepath, const std::vector<std::wstring>& lines) {
#ifdef _WIN32
        std::ofstream file(filepath.c_str(), std::ios::binary | std::ios::trunc);
#else
        std::string narrowPath(filepath.begin(), filepath.end());
        std::ofstream file(narrowPath, std::ios::binary | std::ios::trunc);
#endif
        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + std::string(filepath.begin(), filepath.end()));
        }

#ifdef _WIN32
        // Windows: convert each line via WideCharToMultiByte to ensure proper UTF-8 including emojis
        for (const auto& wline : lines) {
            if (!wline.empty()) {
                int required = WideCharToMultiByte(CP_UTF8, 0, wline.c_str(),
                                                   static_cast<int>(wline.size()),
                                                   nullptr, 0, nullptr, nullptr);
                if (required <= 0) continue;
                std::string utf8(required, '\0');
                WideCharToMultiByte(CP_UTF8, 0, wline.c_str(),
                                    static_cast<int>(wline.size()),
                                    &utf8[0], required, nullptr, nullptr);
                file.write(utf8.data(), utf8.size());
            }
            file.put('\n');
        }
#else
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        for (const auto& wline : lines) {
            std::string utf8 = conv.to_bytes(wline);
            file.write(utf8.data(), utf8.size());
            file.put('\n');
        }
#endif
    }

} // namespace FileUtils

#endif // FILE_UTILS_H
