#include "io/logger.h"
#include <windows.h>
#include <fstream>
#include <sstream>
#include <filesystem>

Logger& Logger::instance() {
    static Logger g;
    return g;
}

void Logger::setOutputFile(const std::wstring& filepath) {
    std::lock_guard<std::mutex> lock(mtx);
    outputFile = filepath;
}

std::wstring Logger::currentTimestamp() {
    SYSTEMTIME st;
    ::GetLocalTime(&st);
    wchar_t buf[64];
    swprintf(buf, 64, L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::wstring(buf);
}

void Logger::log(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(mtx);
    buffer.push_back(LogEntry{ currentTimestamp(), message });
}

void Logger::log(const std::string& message) {
    // Simple narrow->wide (assumes ASCII / UTF-8 basic)
    std::wstring w(message.begin(), message.end());
    log(w);
}

bool Logger::flush() {
    std::lock_guard<std::mutex> lock(mtx);
    if (!outputFile || buffer.empty())
        return static_cast<bool>(outputFile); // false if no file path

    // Ensure parent directory exists (best effort)
    try {
        std::filesystem::path p(*outputFile);
        if (p.has_parent_path())
            std::filesystem::create_directories(p.parent_path());
    } catch (...) {
        // Ignore directory creation failures; attempt file write anyway
    }

    std::wofstream ofs(*outputFile, std::ios::app);
    if (!ofs.is_open())
        return false;

    for (const auto& e : buffer) {
        ofs << e.timestamp << L" | " << e.message << L"\n";
    }
    ofs.flush();
    buffer.clear();
    return true;
}

std::vector<LogEntry> Logger::entries() const {
    std::lock_guard<std::mutex> lock(mtx);
    return buffer;
}

void Logger::clear() {
    std::lock_guard<std::mutex> lock(mtx);
    buffer.clear();
}