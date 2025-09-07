#ifndef META_EXTRACTOR_H
#define META_EXTRACTOR_H

#include <string>
#include <vector>
#include <set>
#include <chrono>
#include <ctime>
#include <iomanip>

// Type du message détecté
enum MessageType {
    TEXT,
    LINK,
    MEDIA_OMITTED,
    IMAGE,
    VIDEO,
    AUDIO,
    DOCUMENT,
    UNKNOWN
};

// Structure contenant les métadonnées d’un message WhatsApp
struct Metadata {
    std::string date;
    std::string time;
    std::string author;
    std::string message;
    MessageType type;
};

class MetaExtractor {
public:
    std::vector<Metadata> extract(const std::string& filepath);
    void printAll(const std::vector<Metadata>& metas);
    void exportToCSV(const std::vector<Metadata>& metas, const std::string& outputPath);
    void logExport(const std::vector<Metadata>& metas, const std::string& outputPath);

    std::set<std::string> loadSuspiciousWords(const std::string& filepath);
    std::vector<Metadata> detectSuspiciousMessages(
        const std::vector<Metadata>& metas,
        const std::set<std::string>& suspiciousWords
        );
    void printSuspiciousMessages(const std::vector<Metadata>& flaggedMessages);

private:
    MessageType classify(const std::string& message);
    std::string messageTypeToString(MessageType type);
};

#endif // META_EXTRACTOR_H
