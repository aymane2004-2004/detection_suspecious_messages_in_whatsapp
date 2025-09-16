#include "analysis/detector.h"
#include "utils/file_utils.h"
#include <algorithm>
#include <cctype>
#include <locale>
#include <cwctype>
#include <regex>
#include <sstream>
#include <unordered_set>
#include <filesystem>

namespace Analysis {

    std::string wideToLowerUtf8(const std::wstring& ws) {
        if (ws.empty()) return {};
        int utf8Len = ::WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                                            static_cast<int>(ws.size()),
                                            nullptr, 0, nullptr, nullptr);
        if (utf8Len <= 0) return {};
        std::string utf8(static_cast<size_t>(utf8Len), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, ws.data(),
                              static_cast<int>(ws.size()),
                              utf8.data(), utf8Len,
                              nullptr, nullptr);
        std::transform(utf8.begin(), utf8.end(), utf8.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return utf8;
    }

    double lookupWordWeight(const std::wstring& token,
                            const Domain* domains,
                            size_t domainCount,
                            int* outReasonID)
    {
        if (!domains || domainCount == 0)
            return 0.0;
        std::string needle = wideToLowerUtf8(token);
        for (size_t i = 0; i < domainCount; ++i) {
            if (domains[i].words.find(needle) != domains[i].words.end()) {
                if (outReasonID) *outReasonID = static_cast<int>(i + 1);
                return domains[i].weight;
            }
        }
        return 0.0;
    }

    double lookupWordWeightBilingual(const std::wstring& token,
                                     int* outReasonID)
    {
        int rid = 0;
        double w = lookupWordWeight(token, allEnglishDomains, 8, &rid);
        if (w > 0.0) {
            if (outReasonID) *outReasonID = rid;
            return w;
        }
        w = lookupWordWeight(token, allFrenchDomains, 8, &rid);
        if (w > 0.0) {
            if (outReasonID) *outReasonID = 100 + rid; // Décalage FR
            return w;
        }
        if (outReasonID) *outReasonID = static_cast<int>(ReasonID::NONE);
        return 0.0;
    }

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

    std::wstring toWString(SuspiciousItemType t) {
        switch (t) {
        case SuspiciousItemType::LINK: return L"LINK";
        case SuspiciousItemType::WORD: return L"WORD";
        case SuspiciousItemType::FILENAME: return L"FILENAME";
        default: return L"UNKNOWN";
        }
    }

    // --------------------------------------------------------------------
    // detectSuspiciousWords (messages)
    // --------------------------------------------------------------------
    void DetectionEngine::detectSuspiciousWords(const Conversation& conversation,
                                                SuspiciousConversation& outSuspicious,
                                                DetectionLanguage language)
    {
        const auto& msgs = conversation.getMessages();
        if (msgs.empty()) return;

        auto tokenizeW = [](const std::wstring& text) -> std::vector<std::wstring> {
            std::vector<std::wstring> tokens;
            std::wstring current;
            current.reserve(16);
            for (wchar_t ch : text) {
                if (std::iswalnum(static_cast<wint_t>(ch)) || ch == L'_') {
                    current.push_back(ch);
                } else {
                    if (!current.empty()) {
                        tokens.push_back(current);
                        current.clear();
                    }
                }
            }
            if (!current.empty()) tokens.push_back(current);
            return tokens;
        };

        auto reasonFromRID = [](int rid) -> std::wstring {
            if (rid == static_cast<int>(ReasonID::NONE))
                return L"NONE";
            bool french = (rid >= 100);
            int base = french ? rid - 100 : rid;
            std::wstring suffix = french ? L" (FR)" : L" (EN)";
            switch (base) {
            case 1: return L"SEXUAL content"      + suffix;
            case 2: return L"VIOLENCE content"    + suffix;
            case 3: return L"HATE_SPEECH content" + suffix;
            case 4: return L"DRUGS content"       + suffix;
            case 5: return L"SCAM content"        + suffix;
            case 6: return L"SELF_HARM content"   + suffix;
            case 7: return L"PROFANITY content"   + suffix;
            case 8: return L"EXTREMIST content"   + suffix;
            default: return L"UNKNOWN content";
            }
        };

        auto weightForToken = [language](const std::wstring& tok, int& outRID) -> double {
            outRID = static_cast<int>(ReasonID::NONE);
            if (language == DetectionLanguage::BOTH) {
                return lookupWordWeightBilingual(tok, &outRID);
            } else if (language == DetectionLanguage::EN) {
                double w = lookupWordWeight(tok, allEnglishDomains, 8, &outRID);
                return w;
            } else {
                int ridLocal = 0;
                double w = lookupWordWeight(tok, allFrenchDomains, 8, &ridLocal);
                if (w > 0.0) outRID = 100 + ridLocal;
                return w;
            }
        };

        for (const Message& msg : msgs) {
            MessageType mt = msg.getType();
            if (mt != MessageType::TEXT && mt != MessageType::TEXT_LINK)
                continue;

            const std::wstring& content = msg.getContent();
            if (content.empty()) continue;

            auto tokens = tokenizeW(content);
            if (tokens.empty()) continue;

            double messageAccumulated = 0.0;

            for (const auto& rawToken : tokens) {
                int rid = 0;
                double weight = weightForToken(rawToken, rid);
                if (weight <= 0.0 || rid == static_cast<int>(ReasonID::NONE))
                    continue;

                std::wstring reason = reasonFromRID(rid);
                outSuspicious.add(msg,
                                  rawToken,
                                  reason,
                                  weight,
                                  rid,
                                  SuspiciousItemType::WORD);
                messageAccumulated += weight;
            }

            if (messageAccumulated > 0.0) {
                auto it = messageScores.find(&msg);
                if (it == messageScores.end())
                    messageScores.emplace(&msg, messageAccumulated);
                else
                    it->second += messageAccumulated;
            }
        }
    }

    // --------------------------------------------------------------------
    // FIXED: Proper member definition (previously a free function caused LNK2001)
    // Currently a placeholder (no-op). Implement real file scanning later.
    // --------------------------------------------------------------------
    void DetectionEngine::detectSuspiciousWordsInTextFiles(const Conversation&,
                                                           SuspiciousConversation&,
                                                           const std::wstring&,
                                                           DetectionLanguage)
    {
        // TODO: Implement scanning external text files.
        // Left intentionally empty to satisfy linker & keep behavior consistent.
    }

    // --------------------------------------------------------------------
    // detectSuspiciousLinks
    // --------------------------------------------------------------------
    void DetectionEngine::detectSuspiciousLinks(const Conversation& conversation,
                                                SuspiciousConversation& outSuspicious) {
        const auto& msgs = conversation.getMessages();
        if (msgs.empty()) return;

        struct PatternDef {
            const wchar_t* name;
            const wchar_t* pattern;
            double weight;
            bool fullMatch;
        };

        static const std::vector<PatternDef> kPatterns = {
            { L"EMBEDDED_CREDENTIALS", LR"(^[a-zA-Z][a-zA-Z0-9+\-.]*://[^/\s:@]+:[^/\s:@]+@[^/\s]+)", 7.0, true },
            { L"IP_HOST",              LR"(^[a-zA-Z][a-zA-Z0-9+\-.]*://(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]))", 5.5, true },
            { L"SUSPICIOUS_PORT",      LR"(^[^/\s]+://[^/\s]+:\b(8080|4444|6666|8888|1234|2222|3389|5900|21|23)\b)", 3.5, true },
            { L"TOO_MANY_SUBDOMAINS",  LR"(^(?:[a-z0-9-]+\.){3,}[a-z]{2,}(:\d+)?(/|$))", 4.0, true },
            { L"SUS_KEYWORDS_DOMAIN",  LR"((paypal|apple|google|bank|secure|signin|login|account|verify|update))", 2.5, false },
            { L"SENSITIVE_PATH_KEYS",  LR"([\/\?&](password|token|auth|login|verify|confirm|ssn|credit|card|cvv)[=\/])", 4.5, false },
            { L"ABUSED_TLDS",          LR"(\.(ru|tk|ml|ga|cf|gq|top|work|click|xyz)([:\/?#]|$))", 3.5, false },
            { L"OPEN_REDIRECT",        LR"([?&](url|redirect|redir|next|to)=(https?%3A%2F%2F|https?://))", 5.0, false },
            { L"EXECUTABLE_DOWNLOAD",  LR"(\/[^\/\s]+\.(exe|scr|msi|bat|cmd|jar|zip|rar|7z|iso)(\?|$))", 6.0, false },
            { L"HEAVY_ENCODING",       LR"((%[0-9A-Fa-f]{2}){3,})", 2.5, false },
            { L"UNICODE_CHARS",        LR"([^\x00-\x7F])", 3.0, false },
            { L"PUNYCODE",             LR"(xn--[a-z0-9-]+)", 5.0, false },
            { L"LONG_DOMAIN",          LR"(^(?:https?:\/\/)?([a-z0-9\-]{30,})\.)", 2.5, true },
            { L"RANDOM_ALNUM_DOMAIN",  LR"(^(?:https?:\/\/)?[A-Za-z0-9]{12,}\.)", 3.0, true },
            { L"REPEATED_PATH_SEG",    LR"((\/[A-Za-z0-9\-_]{1,20}){6,})", 2.5, false },
            { L"AT_SYMBOL",            LR"(@)", 2.0, false },
            { L"VERY_LONG_QUERY",      LR"(\?[^#]{200,})", 2.0, false },
            { L"BRAND_DASH_VARIATION", LR"((^|-)(paypal|google|apple|bank)(-|$))", 2.5, false },
            { L"SCRIPT_DATA_URI",      LR"(^[a-zA-Z0-9+\-.]*:(javascript|data):)", 7.5, true }
        };

        static const std::wregex urlExtractor(
            LR"((?:https?://|ftp://)[^\s<>\"']+)", std::regex_constants::icase);

        static const std::wregex bareDomain(
            LR"((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?:/[^\s]*)?)",
            std::regex_constants::icase);

        auto sanitize = [](std::wstring url) {
            while (!url.empty()) {
                wchar_t c = url.back();
                if (c == L'.' || c == L',' || c == L';' || c == L')' ||
                    c == L'!' || c == L'?') {
                    url.pop_back();
                } else break;
            }
            return url;
        };

        auto collectLinks = [&](const std::wstring& text) -> std::vector<std::wstring> {
            std::unordered_set<std::wstring> set;
            {
                std::wsregex_iterator it(text.cbegin(), text.cend(), urlExtractor), end;
                for (; it != end; ++it) set.insert(sanitize(it->str()));
            }
            if (set.empty()) {
                std::wsregex_iterator it(text.cbegin(), text.cend(), bareDomain), end;
                for (; it != end; ++it) {
                    std::wstring v = sanitize(it->str());
                    if (!v.empty()) set.insert(v);
                }
            }
            return { set.begin(), set.end() };
        };

        for (const auto& msg : msgs) {
            MessageType mt = msg.getType();
            if (mt != MessageType::LINK && mt != MessageType::TEXT_LINK)
                continue;
            const std::wstring& content = msg.getContent();
            if (content.empty()) continue;

            auto links = collectLinks(content);
            if (links.empty()) continue;

            for (const auto& link : links) {
                double totalScore = 0.0;
                std::vector<std::wstring> matchedNames;

                for (const auto& p : kPatterns) {
                    std::wregex rgx(p.pattern, std::regex_constants::icase);
                    bool matched = false;
                    try {
                        matched = p.fullMatch ? std::regex_match(link, rgx)
                                              : std::regex_search(link, rgx);
                    } catch (...) { matched = false; }
                    if (matched) {
                        totalScore += p.weight;
                        matchedNames.emplace_back(p.name);
                    }
                }

                if (totalScore > 0.0) {
                    std::wstringstream reason;
                    reason << L"Suspicious link patterns: ";
                    for (size_t i = 0; i < matchedNames.size(); ++i) {
                        if (i) reason << L", ";
                        reason << matchedNames[i];
                    }

                    outSuspicious.add(msg,
                                      link,
                                      reason.str(),
                                      totalScore,
                                      static_cast<int>(ReasonID::LINK),
                                      SuspiciousItemType::LINK);

                    auto it = messageScores.find(&msg);
                    if (it == messageScores.end())
                        messageScores.emplace(&msg, totalScore);
                    else
                        it->second += totalScore;
                }
            }
        }
    }

    void DetectionEngine::detectSuspiciousFilenames(const Conversation& conversation,
                                                    SuspiciousConversation& outSuspicious,
                                                    DetectionLanguage language) {
        const auto& msgs = conversation.getMessages();
        if (msgs.empty()) return;

        auto isTargetType = [](MessageType t) {
            return t == MessageType::IMAGE ||
                   t == MessageType::VIDEO ||
                   t == MessageType::AUDIO ||
                   t == MessageType::DOCUMENT;
        };

        auto hasObfuscatedUnicode = [](const std::wstring& s) -> bool {
            for (wchar_t ch : s) {
                unsigned int c = static_cast<unsigned int>(ch);
                if ((c >= 0x200B && c <= 0x200F) || c == 0xFEFF) return true;
                if (c < 0x20 && c != 0x09 && c != 0x0A && c != 0x0D) return true;
                if (c >= 0x4E00 && c <= 0x9FFF) return true;
                if ((c >= 0x3100 && c <= 0x312F) ||
                    (c >= 0x3130 && c <= 0x318F) ||
                    (c >= 0xAC00 && c <= 0xD7AF)) return true;
            }
            return false;
        };

        auto extractCandidates = [](const std::wstring& content) -> std::vector<std::wstring> {
            std::vector<std::wstring> out;
            static const std::wregex rgx(LR"(([^\s<>:\"/\\|?*]{1,200}\.[A-Za-z0-9]{1,8}))",
                                         std::regex_constants::icase);
            std::wsregex_iterator it(content.begin(), content.end(), rgx), end;
            for (; it != end; ++it) {
                std::wstring cand = it->str();
                while (!cand.empty() && (cand.back() == L'.' || cand.back() == L',' ||
                                         cand.back() == L';' || cand.back() == L')' ||
                                         cand.back() == L'!' || cand.back() == L'?')) {
                    cand.pop_back();
                }
                if (!cand.empty())
                    out.push_back(cand);
            }
            if (out.empty()) {
                if (content.find(L'.') != std::wstring::npos && content.size() <= 260) {
                    std::wstring trimmed = content;
                    while (!trimmed.empty() && iswspace(trimmed.front())) trimmed.erase(trimmed.begin());
                    while (!trimmed.empty() && iswspace(trimmed.back())) trimmed.pop_back();
                    if (!trimmed.empty() && trimmed.find(L' ') == std::wstring::npos)
                        out.push_back(trimmed);
                }
            }
            return out;
        };

        auto reasonFromRID = [](int rid) -> std::wstring {
            if (rid == static_cast<int>(ReasonID::NONE)) return L"NONE";
            bool french = (rid >= 100);
            int base = french ? rid - 100 : rid;
            std::wstring suffix = french ? L"(FR)" : L"(EN)";
            switch (base) {
            case 1: return L"SEXUAL " + suffix;
            case 2: return L"VIOLENCE " + suffix;
            case 3: return L"HATE_SPEECH " + suffix;
            case 4: return L"DRUGS " + suffix;
            case 5: return L"SCAM " + suffix;
            case 6: return L"SELF_HARM " + suffix;
            case 7: return L"PROFANITY " + suffix;
            case 8: return L"EXTREMIST " + suffix;
            default: return L"UNKNOWN";
            }
        };

        auto weightForToken = [language](const std::wstring& tok, int& outRID)->double {
            outRID = static_cast<int>(ReasonID::NONE);
            if (language == DetectionLanguage::BOTH)
                return lookupWordWeightBilingual(tok, &outRID);
            else if (language == DetectionLanguage::EN)
                return lookupWordWeight(tok, allEnglishDomains, 8, &outRID);
            else {
                int local = 0;
                double w = lookupWordWeight(tok, allFrenchDomains, 8, &local);
                if (w > 0.0) outRID = 100 + local;
                return w;
            }
        };

        const double kUnicodeObfuscationWeight = 20.0;

        for (const auto& msg : msgs) {
            if (!isTargetType(msg.getType()))
                continue;
            const std::wstring& content = msg.getContent();
            if (content.empty()) continue;

            auto candidates = extractCandidates(content);
            if (candidates.empty()) continue;

            for (const auto& filename : candidates) {
                std::vector<std::wstring> tokens;
                {
                    std::wstring cur;
                    for (wchar_t ch : filename) {
                        if (std::iswalnum(static_cast<wint_t>(ch))) {
                            cur.push_back(std::towlower(ch));
                        } else {
                            if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
                        }
                    }
                    if (!cur.empty()) tokens.push_back(cur);
                }

                double totalScore = 0.0;
                std::unordered_set<std::wstring> reasonTags;
                bool anyWord = false;

                for (const auto& tok : tokens) {
                    if (tok.size() < 2) continue;
                    int rid = 0;
                    double w = weightForToken(tok, rid);
                    if (w <= 0.0 || rid == static_cast<int>(ReasonID::NONE))
                        continue;
                    anyWord = true;
                    totalScore += (w * 10.0);
                    reasonTags.insert(reasonFromRID(rid));
                }

                bool unicodeSuspicious = hasObfuscatedUnicode(filename);
                if (unicodeSuspicious) {
                    totalScore += kUnicodeObfuscationWeight;
                    reasonTags.insert(L"UNICODE_OBFUSCATION");
                }

                if (totalScore > 0.0) {
                    std::wstringstream reason;
                    reason << L"Filename analysis: ";
                    if (anyWord) reason << L"suspicious words; ";
                    if (unicodeSuspicious) reason << L"unicode/obfuscation; ";
                    reason << L"Tags=[";
                    bool first = true;
                    for (const auto& r : reasonTags) {
                        if (!first) reason << L",";
                        reason << r;
                        first = false;
                    }
                    reason << L"]";

                    outSuspicious.add(msg,
                                      filename,
                                      reason.str(),
                                      totalScore,
                                      static_cast<int>(ReasonID::FILENAME),
                                      SuspiciousItemType::FILENAME);

                    auto it = messageScores.find(&msg);
                    if (it == messageScores.end())
                        messageScores.emplace(&msg, totalScore);
                    else
                        it->second += totalScore;
                }
            }
        }
    }

    void DetectionEngine::detectAll(const Conversation&,
                                    SuspiciousConversation&,
                                    const std::wstring&) {
        // no-op
    }

    double DetectionEngine::getMessageScore(const Message&) const {
        return 0.0;
    }

    std::vector<std::wstring> DetectionEngine::tokenize(const std::wstring&) { return {}; }
    double DetectionEngine::scoreToken(const std::wstring&, int* reasonID) {
        if (reasonID) *reasonID = static_cast<int>(ReasonID::NONE);
        return 0.0;
    }
    void DetectionEngine::accumulateMessageScore(const Message&, double) {}
    size_t DetectionEngine::extractLinks(const std::wstring&, std::vector<std::wstring>&) { return 0; }
    bool DetectionEngine::isPotentialLink(const std::wstring&) { return false; }
    bool DetectionEngine::isSuspiciousLink(const std::wstring&) { return false; }
    std::vector<std::wstring> DetectionEngine::extractCandidateFilenames(const std::wstring&) { return {}; }
    bool DetectionEngine::isSuspiciousFilename(const std::wstring&) { return false; }
    std::optional<std::wstring> DetectionEngine::resolveTextFilePath(const Message&, const std::wstring&) { return std::nullopt; }
    void DetectionEngine::scanTextFileForWords(const std::wstring&, const Message*, SuspiciousConversation&) {}
    std::wstring DetectionEngine::normalize(const std::wstring& s) { return s; }

} // namespace Analysis
