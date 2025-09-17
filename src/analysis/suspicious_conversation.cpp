#include "analysis/suspicious_conversation.h"
#include "analysis/detector.h" // for lookupWordWeightBilingual & ReasonID mapping
#include <unordered_set>

namespace Analysis {

    SuspiciousEntry::SuspiciousEntry(const Message& msg,
                                     std::wstring part,
                                     std::wstring why,
                                     SuspiciousItemType type,
                                     double sc,
                                     int rid)
        : message(msg),
          suspiciousPart(std::move(part)),
          reason(std::move(why)),
          itemType(type),
          score(sc),
          reasonID(rid)
    {
    }

    SuspiciousConversation::SuspiciousConversation() = default;

    void SuspiciousConversation::add(const Message& msg,
                                     const std::wstring& suspiciousPart,
                                     const std::wstring& reason,
                                     SuspiciousItemType type)
    {
        entries.emplace_back(msg,
                             suspiciousPart,
                             reason,
                             type,
                             0.0,
                             static_cast<int>(ReasonID::NONE));
    }

    void SuspiciousConversation::add(const Message& msg,
                                     const std::wstring& suspiciousPart,
                                     const std::wstring& reason,
                                     double score,
                                     int reasonID,
                                     SuspiciousItemType type)
    {
        entries.emplace_back(msg,
                             suspiciousPart,
                             reason,
                             type,
                             score,
                             reasonID);
    }

    void SuspiciousConversation::addWordAuto(const Message& msg,
                                             const std::wstring& suspiciousWord,
                                             const std::wstring& reasonText)
    {
        int rid = 0;
        double w = lookupWordWeightBilingual(suspiciousWord, &rid);
        entries.emplace_back(msg,
                             suspiciousWord,
                             reasonText,
                             SuspiciousItemType::WORD,
                             w,
                             (rid == 0 ? static_cast<int>(ReasonID::NONE) : rid));
    }

    size_t SuspiciousConversation::size() const noexcept { return entries.size(); }
    bool   SuspiciousConversation::empty() const noexcept { return entries.empty(); }
    const std::vector<SuspiciousEntry>& SuspiciousConversation::getEntries() const noexcept { return entries; }

    std::vector<Message> SuspiciousConversation::getMessages() const {
        std::vector<Message> out;
        out.reserve(entries.size());
        for (const auto& e : entries)
            out.push_back(e.message);
        return out;
    }

    std::vector<SuspiciousEntry> SuspiciousConversation::filterByType(SuspiciousItemType type) const {
        std::vector<SuspiciousEntry> out;
        for (const auto& e : entries)
            if (e.itemType == type) out.push_back(e);
        return out;
    }

    std::map<SuspiciousItemType, int> SuspiciousConversation::countByType() const {
        std::map<SuspiciousItemType, int> counts;
        for (const auto& e : entries)
            counts[e.itemType]++;
        return counts;
    }

    std::optional<SuspiciousEntry> SuspiciousConversation::findBySuspiciousPart(const std::wstring& token) const {
        for (const auto& e : entries)
            if (e.suspiciousPart == token)
                return e;
        return std::nullopt;
    }

    size_t SuspiciousConversation::uniqueMessageCount() const {
        std::unordered_set<std::wstring> uniq;
        uniq.reserve(entries.size());
        // Use an unlikely separator to build a composite key
        constexpr wchar_t SEP = L'\x1F';
        for (const auto& e : entries) {
            const auto& m = e.message;
            std::wstring key;
            key.reserve(m.getDate().size() + m.getTime().size() + m.getAuthor().size() + m.getContent().size() + 16);
            key.append(m.getDate()).push_back(SEP);
            key.append(m.getTime()).push_back(SEP);
            key.append(m.getAuthor()).push_back(SEP);
            key.append(m.getContent()).push_back(SEP);
            key.append(std::to_wstring(static_cast<int>(m.getType())));
            uniq.insert(std::move(key));
        }
        return uniq.size();
    }

    std::wstring toWString(SuspiciousItemType t) {
        switch (t) {
        case SuspiciousItemType::LINK: return L"LINK";
        case SuspiciousItemType::WORD: return L"WORD";
        case SuspiciousItemType::FILENAME: return L"FILENAME";
        default: return L"UNKNOWN";
        }
    }

} // namespace Analysis