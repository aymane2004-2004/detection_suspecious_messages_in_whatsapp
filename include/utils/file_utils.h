#ifndef FILE_UTILS_H
#define FILE_UTILS_H

#include <string>
#include <vector>
#include <fstream>
#include <locale>

namespace FileUtils {

    // Reads a text file (UTF-8/UTF-16) into a vector of wstrings (one line per element)
    inline std::vector<std::wstring> readFileLines(const std::wstring& filepath) {
        std::vector<std::wstring> lines;
        std::wifstream file(filepath);

        // Use the system's default locale (UTF-8 compatible)
        file.imbue(std::locale("en_US.UTF-8"));

        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + std::string(filepath.begin(), filepath.end()));
        }

        std::wstring line;
        while (std::getline(file, line)) {
            lines.push_back(line);
        }
        return lines;
    }

    // Writes lines to a text file
    inline void writeFileLines(const std::wstring& filepath, const std::vector<std::wstring>& lines) {
        std::wofstream file(filepath);
        file.imbue(std::locale("en_US.UTF-8"));

        if (!file.is_open()) {
            throw std::runtime_error("Cannot open file: " + std::string(filepath.begin(), filepath.end()));
        }

        for (const auto& line : lines) {
            file << line << L"\n";
        }
    }

} // namespace FileUtils

#endif // FILE_UTILS_H
