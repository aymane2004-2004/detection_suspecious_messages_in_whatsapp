#include "analysis/detector.h"
#include <algorithm>
#include <cctype>
#include <locale>
#include <cwctype>
#include <regex>
#include <sstream>
#include <unordered_set>

namespace Analysis {

    std::string wideToLowerUtf8(const std::wstring& ws) {
        if (ws.empty()) return {};

        int utf8Len = ::WideCharToMultiByte(CP_UTF8, 0,
                                            ws.data(),
                                            static_cast<int>(ws.size()),
                                            nullptr, 0, nullptr, nullptr);
        if (utf8Len <= 0) return {};

        std::string utf8(static_cast<size_t>(utf8Len), '\0');
        ::WideCharToMultiByte(CP_UTF8, 0,
                              ws.data(),
                              static_cast<int>(ws.size()),
                              utf8.data(),
                              utf8Len,
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

    size_t SuspiciousConversation::size() const noexcept {
        return entries.size();
    }

    bool SuspiciousConversation::empty() const noexcept {
        return entries.empty();
    }

    const std::vector<SuspiciousEntry>& SuspiciousConversation::getEntries() const noexcept {
        return entries;
    }

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
            if (e.itemType == type)
                out.push_back(e);
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
    // DetectionEngine::detectSuspiciousWords (version multilingue)
    // language:
    //   EN   -> utilise uniquement allEnglishDomains (ReasonID 1..8)
    //   FR   -> utilise uniquement allFrenchDomains (ReasonID 101..108 pour cohérence)
    //   BOTH -> anglais puis français (anglais prioritaire), même logique qu'avant
    // DetectionEngine::detectSuspiciousWords (filtered to TEXT, TEXT_LINK)
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

        // Fonction pour obtenir poids + reasonID selon la langue choisie
        auto weightForToken = [language](const std::wstring& tok, int& outRID) -> double {
            outRID = static_cast<int>(ReasonID::NONE);
            if (language == DetectionLanguage::BOTH) {
                return lookupWordWeightBilingual(tok, &outRID);
            } else if (language == DetectionLanguage::EN) {
                double w = lookupWordWeight(tok, allEnglishDomains, 8, &outRID);
                return w;
            } else { // FR
                int ridLocal = 0;
                double w = lookupWordWeight(tok, allFrenchDomains, 8, &ridLocal);
                if (w > 0.0) {
                    outRID = 100 + ridLocal; // conserver offset FR
                }
                return w;
            }
        };

        for (const Message& msg : msgs) {
            // NEW: Skip non-textual messages (performance optimization)
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
    // NO-OP IMPLEMENTATIONS (demandé)
    // --------------------------------------------------------------------

    void DetectionEngine::detectSuspiciousWordsInTextFiles(const Conversation&,
                                                           SuspiciousConversation&,
                                                           const std::wstring&) {
        // no-op
    }

    // --------------------------------------------------------------------
    // detectSuspiciousLinks : Analyse les messages de type LINK ou TEXT_LINK
    // Applique un ensemble de motifs regex attribuant des poids cumulés.
    // ReasonID utilisé : LINK (100)
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

        // Extract URLs with explicit schemes
        static const std::wregex urlExtractor(
            LR"((?:https?://|ftp://)[^\s<>\"']+)", std::regex_constants::icase);

        // Improved bare domain pattern: captures FULL chain of subdomains up to final TLD
        // (e.g., login.bank.secure.example.com) and optional path.
        static const std::wregex bareDomain(
            LR"((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}(?:/[^\s]*)?)",
            std::regex_constants::icase);

        auto sanitize = [](std::wstring url) {
            while (!url.empty()) {
                wchar_t c = url.back();
                if (c == L'.' || c == L',' || c == L';' || c == L')' ||
                    c == L'!' || c == L'?' ) {
                    url.pop_back();
                } else {
                    break;
                }
            }
            return url;
        };

        auto collectLinks = [&](const std::wstring& text) -> std::vector<std::wstring> {
            std::unordered_set<std::wstring> set;

            // URLs with protocol
            {
                std::wsregex_iterator it(text.cbegin(), text.cend(), urlExtractor), end;
                for (; it != end; ++it) {
                    set.insert(sanitize(it->str()));
                }
            }

            // If none found with protocol, attempt bare domains (collect ALL, not just first)
            if (set.empty()) {
                std::wsregex_iterator it(text.cbegin(), text.cend(), bareDomain), end;
                for (; it != end; ++it) {
                    std::wstring v = sanitize(it->str());
                    if (!v.empty())
                        set.insert(v);
                }
            }

            return std::vector<std::wstring>(set.begin(), set.end());
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
                    } catch (...) {
                        matched = false;
                    }
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

    void DetectionEngine::detectSuspiciousFilenames(const Conversation&,
                                                    SuspiciousConversation&) {
        // no-op
    }

    void DetectionEngine::detectAll(const Conversation&,
                                    SuspiciousConversation&,
                                    const std::wstring&) {
        // no-op
    }

    double DetectionEngine::getMessageScore(const Message&) const {
        return 0.0; // no-op
    }

    std::vector<std::wstring> DetectionEngine::tokenize(const std::wstring&) {
        return {}; // no-op
    }

    double DetectionEngine::scoreToken(const std::wstring&, int* reasonID) {
        if (reasonID) *reasonID = static_cast<int>(ReasonID::NONE);
        return 0.0; // no-op
    }

    void DetectionEngine::accumulateMessageScore(const Message&, double) {
        // no-op
    }

    size_t DetectionEngine::extractLinks(const std::wstring&,
                                         std::vector<std::wstring>&) {
        return 0; // no-op
    }

    bool DetectionEngine::isPotentialLink(const std::wstring&) {
        return false; // no-op
    }

    bool DetectionEngine::isSuspiciousLink(const std::wstring&) {
        return false; // no-op
    }

    std::vector<std::wstring> DetectionEngine::extractCandidateFilenames(const std::wstring&) {
        return {}; // no-op
    }

    bool DetectionEngine::isSuspiciousFilename(const std::wstring&) {
        return false; // no-op
    }

    std::optional<std::wstring> DetectionEngine::resolveTextFilePath(const Message&,
                                                                     const std::wstring&) {
        return std::nullopt; // no-op
    }

    void DetectionEngine::scanTextFileForWords(const std::wstring&,
                                               const Message*,
                                               SuspiciousConversation&) {
        // no-op
    }

    std::wstring DetectionEngine::normalize(const std::wstring& s) {
        return s; // no-op
    }

} // namespace Analysis


