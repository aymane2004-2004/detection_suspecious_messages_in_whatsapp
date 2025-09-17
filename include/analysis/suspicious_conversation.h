#ifndef SUSPICIOUS_CONVERSATION_H
#define SUSPICIOUS_CONVERSATION_H

#include <string>
#include <vector>
#include <map>
#include <optional>

#include "core/message.h"

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

        // Count unique messages (uniqueness = combination of date, time, author, content, type)
        size_t uniqueMessageCount() const;

        void clear() { entries.clear(); }

    private:
        std::vector<SuspiciousEntry> entries;
    };

    std::wstring toWString(SuspiciousItemType t);

} // namespace Analysis

#endif // SUSPICIOUS_CONVERSATION_H