#ifndef DETECTOR_H
#define DETECTOR_H

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <windows.h>
#include "core/message.h"
#include "core/conversation.h"
#include "core/suspicious_words.h"

namespace Analysis {

    enum class ReasonID : int {
        NONE        = 0,
        SEXUAL      = 1,
        VIOLENCE    = 2,
        HATE_SPEECH = 3,
        DRUGS       = 4,
        SCAM        = 5,
        SELF_HARM   = 6,
        PROFANITY   = 7,
        EXTREMIST   = 8,
        LINK        = 100,
        FILENAME    = 101,
        UNKNOWN     = 999
    };

    enum class SuspiciousItemType {
        LINK,
        WORD,
        FILENAME,
        UNKNOWN
    };

    // Langue de détection
    enum class DetectionLanguage {
        EN,
        FR,
        BOTH
    };

    std::string wideToLowerUtf8(const std::wstring& ws);
    double lookupWordWeight(const std::wstring& token,
                            const Domain* domains,
                            size_t domainCount,
                            int* outReasonID = nullptr);
    double lookupWordWeightBilingual(const std::wstring& token,
                                     int* outReasonID = nullptr);

    struct SuspiciousEntry {
        Message message;
        std::wstring suspiciousPart;
        std::wstring reason;
        SuspiciousItemType itemType;
        double score;
        int reasonID;

        SuspiciousEntry(const Message& msg,
                        std::wstring part,
                        std::wstring why,
                        SuspiciousItemType type,
                        double sc = 0.0,
                        int rid = static_cast<int>(ReasonID::NONE));
    };

    class SuspiciousConversation {
    public:
        SuspiciousConversation();

        void add(const Message& msg,
                 const std::wstring& suspiciousPart,
                 const std::wstring& reason,
                 SuspiciousItemType type = SuspiciousItemType::UNKNOWN);
        void add(const Message& msg,
                 const std::wstring& suspiciousPart,
                 const std::wstring& reason,
                 double score,
                 int reasonID,
                 SuspiciousItemType type = SuspiciousItemType::UNKNOWN);
        void addWordAuto(const Message& msg,
                         const std::wstring& suspiciousWord,
                         const std::wstring& reasonText);

        size_t size() const noexcept;
        bool empty() const noexcept;
        const std::vector<SuspiciousEntry>& getEntries() const noexcept;
        std::vector<Message> getMessages() const;
        std::vector<SuspiciousEntry> filterByType(SuspiciousItemType type) const;
        std::map<SuspiciousItemType, int> countByType() const;
        std::optional<SuspiciousEntry> findBySuspiciousPart(const std::wstring& token) const;

        // NEW: vider les entrées
        void clear() { entries.clear(); }

    private:
        std::vector<SuspiciousEntry> entries;
    };

    std::wstring toWString(SuspiciousItemType t);

    class DetectionEngine {
    public:
        DetectionEngine() = default;
        void detectSuspiciousWords(const Conversation& conversation,
                                   SuspiciousConversation& outSuspicious,
                                   DetectionLanguage language = DetectionLanguage::BOTH);
        void detectSuspiciousWordsInTextFiles(const Conversation& conversation,
                                              SuspiciousConversation& outSuspicious,
                                              const std::wstring& rootDirectory);
        void detectSuspiciousLinks(const Conversation& conversation,
                                   SuspiciousConversation& outSuspicious);
        void detectSuspiciousFilenames(const Conversation& conversation,
                                       SuspiciousConversation& outSuspicious);
        void detectAll(const Conversation& conversation,
                       SuspiciousConversation& outSuspicious,
                       const std::wstring& rootDirectory = L"");

        double getMessageScore(const Message& msg) const;
        const std::unordered_map<const Message*, double>& getAllMessageScores() const noexcept {
            return messageScores;
        }

        // NEW: réinitialiser l'état interne
        void reset() {
            scannedFiles.clear();
            messageScores.clear();
        }

    private:
        static std::vector<std::wstring> tokenize(const std::wstring& text);
        static double scoreToken(const std::wstring& token, int* reasonID);
        void accumulateMessageScore(const Message& msg, double deltaScore);
        static size_t extractLinks(const std::wstring& text,
                                   std::vector<std::wstring>& outLinks);
        static bool isPotentialLink(const std::wstring& token);
        static bool isSuspiciousLink(const std::wstring& link);
        static std::vector<std::wstring> extractCandidateFilenames(const std::wstring& text);
        static bool isSuspiciousFilename(const std::wstring& filename);
        static std::optional<std::wstring> resolveTextFilePath(const Message& msg,
                                                               const std::wstring& rootDirectory);
        void scanTextFileForWords(const std::wstring& filepath,
                                  const Message* originMessage,
                                  SuspiciousConversation& outSuspicious);
        static std::wstring normalize(const std::wstring& s);

        std::unordered_set<std::wstring> scannedFiles;
        std::unordered_map<const Message*, double> messageScores;
    };

} // namespace Analysis

#endif // DETECTOR_H
