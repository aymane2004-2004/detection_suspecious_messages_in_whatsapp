#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <vector>
#include <mutex>
#include <optional>

struct LogEntry {
    std::wstring timestamp; // "YYYY-MM-DD HH:MM:SS.mmm"
    std::wstring message;
};

class Logger {
public:
    // Singleton access (optional usage)
    static Logger& instance();

    // Set (or change) output file path (e.g. L"logs\\session.log")
    void setOutputFile(const std::wstring& filepath);

    // Add a log line (thread-safe)
    void log(const std::wstring& message);
    void log(const std::string& message); // convenience (ASCII / UTF-8 basic)

    // Write all accumulated entries to file now.
    // If no path set returns false.
    bool flush();

    // Retrieve a snapshot of current entries
    std::vector<LogEntry> entries() const;

    // Clear in-memory log (does not delete file)
    void clear();

private:
    Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static std::wstring currentTimestamp(); // Windows local time

    mutable std::mutex mtx;
    std::vector<LogEntry> buffer;
    std::optional<std::wstring> outputFile;
};

#endif // LOGGER_H