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
#include "analysis/suspicious_conversation.h"

namespace Analysis {

    // Language selection for detection
    enum class DetectionLanguage {
        EN,
        FR,
        BOTH
    };

    // Utility / lookup functions
    std::string wideToLowerUtf8(const std::wstring& ws);
    double lookupWordWeight(const std::wstring& token,
                            const Domain* domains,
                            size_t domainCount,
                            int* outReasonID = nullptr);
    double lookupWordWeightBilingual(const std::wstring& token,
                                     int* outReasonID = nullptr);

    class DetectionEngine {
    public:
        DetectionEngine() = default;

        void detectSuspiciousWords(const Conversation& conversation,
                                   SuspiciousConversation& outSuspicious,
                                   DetectionLanguage language = DetectionLanguage::BOTH);

        void detectSuspiciousWordsInTextFiles(const Conversation& conversation,
                                              SuspiciousConversation& outSuspicious,
                                              const std::wstring& rootDirectory,
                                              DetectionLanguage language = DetectionLanguage::BOTH);

        void detectSuspiciousLinks(const Conversation& conversation,
                                   SuspiciousConversation& outSuspicious);

        void detectSuspiciousFilenames(const Conversation& conversation,
                                       SuspiciousConversation& outSuspicious,
                                       DetectionLanguage language = DetectionLanguage::BOTH);

        void detectAll(const Conversation& conversation,
                       SuspiciousConversation& outSuspicious,
                       const std::wstring& rootDirectory = L"");

        double getMessageScore(const Message& msg) const;
        const std::unordered_map<const Message*, double>& getAllMessageScores() const noexcept {
            return messageScores;
        }

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
