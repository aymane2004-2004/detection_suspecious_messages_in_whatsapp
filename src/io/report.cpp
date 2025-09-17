#include "io/report.h"
#include "analysis/suspicious_conversation.h"
#include "core/message.h"
#include "io/logger.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <locale>
#include <iomanip>
#include <cmath>

#ifdef _WIN32
#include <windows.h>
#undef max
#undef min
#endif

namespace Report {

    // ------------------------------------------------------------
    // UTF-8 conversion
    // ------------------------------------------------------------
    static std::string wstringToUtf8(const std::wstring& w) {
#ifdef _WIN32
        if (w.empty()) return {};
        int sizeNeeded = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (sizeNeeded <= 0) return {};
        std::string utf8(sizeNeeded, '\0');
        ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), utf8.data(), sizeNeeded, nullptr, nullptr);
        return utf8;
#else
        std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
        return conv.to_bytes(w);
#endif
    }

    struct CategoryStats {
        size_t count = 0;
        double totalScore = 0.0;
        std::set<std::wstring> examples;
    };

    enum class BaseCategory {
        SEXUAL,
        VIOLENCE,
        HATE_SPEECH,
        DRUGS,
        SCAM,
        SELF_HARM,
        PROFANITY,
        EXTREMIST,
        LINK,
        FILENAME,
        UNKNOWN
    };

    // English category labels kept (content inside entries already EN); could localize later if desired.
    static const std::map<BaseCategory, std::wstring> kCategoryNames = {
        { BaseCategory::SEXUAL,     L"SEXUAL" },
        { BaseCategory::VIOLENCE,   L"VIOLENCE" },
        { BaseCategory::HATE_SPEECH,L"HATE_SPEECH" },
        { BaseCategory::DRUGS,      L"DRUGS" },
        { BaseCategory::SCAM,       L"SCAM / FRAUD" },
        { BaseCategory::SELF_HARM,  L"SELF_HARM" },
        { BaseCategory::PROFANITY,  L"PROFANITY" },
        { BaseCategory::EXTREMIST,  L"EXTREMIST" },
        { BaseCategory::LINK,       L"LINK (pattern)" },
        { BaseCategory::FILENAME,   L"FILENAME (suspicious)" },
        { BaseCategory::UNKNOWN,    L"UNKNOWN" }
    };

    static BaseCategory baseCategoryFrom(const Analysis::SuspiciousEntry& e) {
        if (e.itemType == Analysis::SuspiciousItemType::LINK)
            return BaseCategory::LINK;
        if (e.itemType == Analysis::SuspiciousItemType::FILENAME)
            return BaseCategory::FILENAME;

        int rid = e.reasonID;
        if (e.itemType == Analysis::SuspiciousItemType::WORD) {
            int base = (rid > 100 ? rid - 100 : rid);
            switch (base) {
            case 1: return BaseCategory::SEXUAL;
            case 2: return BaseCategory::VIOLENCE;
            case 3: return BaseCategory::HATE_SPEECH;
            case 4: return BaseCategory::DRUGS;
            case 5: return BaseCategory::SCAM;
            case 6: return BaseCategory::SELF_HARM;
            case 7: return BaseCategory::PROFANITY;
            case 8: return BaseCategory::EXTREMIST;
            default: break;
            }
        }
        if (rid == 100) return BaseCategory::LINK;
        if (rid == 101) return BaseCategory::FILENAME;
        return BaseCategory::UNKNOWN;
    }

    // ------------------------------------------------------------
    // Localization support
    // ------------------------------------------------------------
    struct LocalizedText {
        // Headings
        std::wstring title;
        std::wstring note;
        std::wstring globalSummary;
        std::wstring distinctSuspiciousMessages;
        std::wstring totalMessagesProvided;
        std::wstring totalMessagesFallback;
        std::wstring totalSuspiciousEntries;
        std::wstring totalAccumScore;
        std::wstring avgScorePerEntry;
        std::wstring avgScorePerSuspiciousMsg;
        std::wstring densityPerMsg;
        std::wstring minScore;
        std::wstring maxScore;
        std::wstring riskAssessment;
        std::wstring riskLevel;
        std::wstring riskComment;
        std::wstring itemTypeDistribution;
        std::wstring noSuspicious;
        std::wstring categoryStats;
        std::wstring noData;
        std::wstring topEntries;
        std::wstring detailedEntries;
        std::wstring none;
        std::wstring examples;
        std::wstring disclaimerHeader;
        std::wstring disclaimerBody1;
        std::wstring disclaimerBody2;
        std::wstring reportEnd;

        // Dynamic risk comment suffix
        std::wstring riskCommentSuffix;

        // Risk levels (output)
        std::wstring levelLow;
        std::wstring levelModerate;
        std::wstring levelElevated;
        std::wstring levelHigh;
        std::wstring levelCritical;

        // Other dynamic tokens
        std::wstring wordLabel;
        std::wstring linkLabel;
        std::wstring filenameLabel;
        std::wstring unknownLabel;
        std::wstring distinctSuspiciousMessagesLabel;
    };

    static LocalizedText makeTexts(Language lang) {
        LocalizedText t;
        if (lang == Language::FR) {
            t.title = L"RAPPORT ANALYTIQUE CONVERSATION SUSPECTE";
            t.note = L"NOTE: Rapport académique, peut contenir des faux positifs.";
            t.globalSummary = L"[RÉSUMÉ GLOBAL]";
            t.distinctSuspiciousMessages = L"Messages suspects distincts (uniqueMessageCount) : ";
            t.totalMessagesProvided = L"Total de messages dans la conversation (fourni) : ";
            t.totalMessagesFallback = L"Total de messages dans la conversation (défaut = messages suspects distincts) : ";
            t.totalSuspiciousEntries = L"Total d'entrées suspectes : ";
            t.totalAccumScore = L"Score total accumulé : ";
            t.avgScorePerEntry = L"Score moyen par entrée suspecte : ";
            t.avgScorePerSuspiciousMsg = L"Score moyen par message suspect distinct : ";
            t.densityPerMsg = L"Densité de score (par message total) : ";
            t.minScore = L"Score minimal d'une entrée : ";
            t.maxScore = L"Score maximal d'une entrée : ";
            t.riskAssessment = L"[ÉVALUATION DU RISQUE]";
            t.riskLevel = L"Niveau de risque : ";
            t.riskComment = L"Commentaire : ";
            t.riskCommentSuffix = L". Niveau dérivé d'heuristiques combinant score total et densité.";
            t.itemTypeDistribution = L"[RÉPARTITION DES TYPES D'ÉLÉMENTS SUSPECTS]";
            t.noSuspicious = L"Aucune entrée suspecte détectée.";
            t.categoryStats = L"[STATISTIQUES PAR CATÉGORIE]";
            t.noData = L"Aucune donnée.";
            t.topEntries = L"ENTRÉES AU SCORE LE PLUS ÉLEVÉ";
            t.detailedEntries = L"[ENTRÉES DÉTAILLÉES]";
            t.none = L"(aucune)";
            t.examples = L"Exemples : ";
            t.disclaimerHeader = L"[AVERTISSEMENT]";
            t.disclaimerBody1 = L"Ce rapport est généré par un prototype académique.";
            t.disclaimerBody2 = L"Il peut contenir des faux positifs ou des erreurs. Une revue experte est recommandée.";
            t.reportEnd = L"Fin du rapport.";
            t.levelLow = L"FAIBLE";
            t.levelModerate = L"MODÉRÉ";
            t.levelElevated = L"ÉLEVÉ";
            t.levelHigh = L"HAUT";
            t.levelCritical = L"CRITIQUE";
            t.wordLabel = L"MOT";
            t.linkLabel = L"LIEN";
            t.filenameLabel = L"NOM_FICHIER";
            t.unknownLabel = L"INCONNU";
            t.distinctSuspiciousMessagesLabel = L"Messages suspects distincts";
        }
        else {
            t.title = L"SUSPICIOUS CONVERSATION ANALYTICAL REPORT";
            t.note = L"NOTE: This report is for academic purposes only. It may contain false positives.";
            t.globalSummary = L"[GLOBAL SUMMARY]";
            t.distinctSuspiciousMessages = L"Distinct suspicious messages (uniqueMessageCount): ";
            t.totalMessagesProvided = L"Total messages in conversation (provided): ";
            t.totalMessagesFallback = L"Total messages in conversation (fallback=distinct suspicious messages): ";
            t.totalSuspiciousEntries = L"Total suspicious entries: ";
            t.totalAccumScore = L"Total accumulated score: ";
            t.avgScorePerEntry = L"Average score per suspicious entry: ";
            t.avgScorePerSuspiciousMsg = L"Average score per distinct suspicious message: ";
            t.densityPerMsg = L"Score density (per total message): ";
            t.minScore = L"Min suspicious entry score: ";
            t.maxScore = L"Max suspicious entry score: ";
            t.riskAssessment = L"[RISK ASSESSMENT]";
            t.riskLevel = L"Risk Level: ";
            t.riskComment = L"Comment: ";
            t.riskCommentSuffix = L". Level derived from combined total score and density heuristics.";
            t.itemTypeDistribution = L"[SUSPICIOUS ITEM TYPE DISTRIBUTION]";
            t.noSuspicious = L"No suspicious entries detected.";
            t.categoryStats = L"[CATEGORY STATISTICS]";
            t.noData = L"No data.";
            t.topEntries = L"HIGHEST-SCORING ENTRIES";
            t.detailedEntries = L"[DETAILED ENTRIES]";
            t.none = L"(none)";
            t.examples = L"Examples: ";
            t.disclaimerHeader = L"[DISCLAIMER]";
            t.disclaimerBody1 = L"This analytical report is generated by an academic prototype.";
            t.disclaimerBody2 = L"It may contain false positives or misclassifications. Manual expert review is recommended before any action.";
            t.reportEnd = L"End of report.";
            t.levelLow = L"LOW";
            t.levelModerate = L"MODERATE";
            t.levelElevated = L"ELEVATED";
            t.levelHigh = L"HIGH";
            t.levelCritical = L"CRITICAL";
            t.wordLabel = L"WORD";
            t.linkLabel = L"LINK";
            t.filenameLabel = L"FILENAME";
            t.unknownLabel = L"UNKNOWN";
            t.distinctSuspiciousMessagesLabel = L"Distinct suspicious messages";
        }
        return t;
    }

    struct RiskResult {
        std::wstring level;   // localized
        std::wstring comment; // localized
    };

    static RiskResult assessRisk(double totalScore,
                                 double density,
                                 size_t totalMessages,
                                 size_t suspiciousEntries,
                                 const LocalizedText& lt,
                                 Language lang)
    {
        auto baseLevelCode = [&](double s) -> int {
            if (s < 50)   return 0;
            if (s < 200)  return 1;
            if (s < 600)  return 2;
            if (s < 1500) return 3;
            return 4;
        };

        int levelCode = baseLevelCode(totalScore);

        auto escalate = [&]() { if (levelCode < 4) ++levelCode; };
        auto deescalate = [&]() { if (levelCode > 0) --levelCode; };

        if (totalMessages > 0) {
            if (totalMessages < 50 && totalScore >= 400) escalate();
            if (density > 30.0 && totalScore >= 300) escalate();
            if (density < 5.0 && totalScore >= 500 && suspiciousEntries < (totalMessages / 10 + 5)) {
                deescalate();
            }
        }

        auto codeToLabel = [&](int c)->std::wstring {
            switch (c) {
            case 0: return lt.levelLow;
            case 1: return lt.levelModerate;
            case 2: return lt.levelElevated;
            case 3: return lt.levelHigh;
            default: return lt.levelCritical;
            }
        };

        std::wstringstream comment;
        if (lang == Language::FR) {
            comment << L"ScoreTotal=" << totalScore;
            if (totalMessages > 0) {
                comment << L", Messages=" << totalMessages
                        << L", EntreesSuspectes=" << suspiciousEntries
                        << L", DensiteScoreParMessage=" << std::fixed << std::setprecision(2) << density;
            }
            comment << lt.riskCommentSuffix;
        } else {
            comment << L"TotalScore=" << totalScore;
            if (totalMessages > 0) {
                comment << L", Messages=" << totalMessages
                        << L", SuspiciousEntries=" << suspiciousEntries
                        << L", DensityScorePerMessage=" << std::fixed << std::setprecision(2) << density;
            }
            comment << lt.riskCommentSuffix;
        }

        return { codeToLabel(levelCode), comment.str() };
    }

    static void writeLine(std::wstringstream& ws, const std::wstring& s = L"") {
        ws << s << L"\n";
    }

    static std::wstring formatDouble(double v, int precision = 2) {
        std::wstringstream ss;
        ss << std::fixed << std::setprecision(precision) << v;
        return ss.str();
    }

    bool generateReport(const Analysis::SuspiciousConversation& suspicious,
                        const std::wstring& outputPath,
                        const ReportGenerationOptions& options)
    {
        try {
            if (outputPath.empty()) {
                Logger::instance().log(L"[Report] Output path empty.");
                return false;
            }

            LocalizedText lt = makeTexts(options.language);

            std::filesystem::path out = outputPath;
            if (out.has_parent_path()) {
                std::error_code ec;
                std::filesystem::create_directories(out.parent_path(), ec);
            }

            const auto& entries = suspicious.getEntries();
            size_t totalEntries = entries.size();

            std::map<BaseCategory, CategoryStats> categoryMap;
            std::map<Analysis::SuspiciousItemType, size_t> typeCounts;
            double totalScore = 0.0;
            double minScore = std::numeric_limits<double>::max();
            double maxScore = 0.0;

            for (const auto& e : entries) {
                totalScore += e.score;
                if (e.score < minScore) minScore = e.score;
                if (e.score > maxScore) maxScore = e.score;

                BaseCategory bc = baseCategoryFrom(e);
                auto& cs = categoryMap[bc];
                cs.count++;
                cs.totalScore += e.score;
                if (cs.examples.size() < options.maxExamplesPerCategory)
                    cs.examples.insert(e.suspiciousPart);

                typeCounts[e.itemType]++;
            }
            if (totalEntries == 0) {
                minScore = 0.0;
                maxScore = 0.0;
            }

            size_t distinctMsgCount = suspicious.uniqueMessageCount();

            size_t totalMessages = options.totalMessagesInConversation > 0
                ? options.totalMessagesInConversation
                : distinctMsgCount;

            double densityPerMessage = (totalMessages > 0)
                ? (totalScore / static_cast<double>(totalMessages))
                : 0.0;

            RiskResult risk = assessRisk(totalScore,
                                         densityPerMessage,
                                         totalMessages,
                                         totalEntries,
                                         lt,
                                         options.language);

            std::vector<const Analysis::SuspiciousEntry*> sortedByScore;
            sortedByScore.reserve(entries.size());
            for (const auto& e : entries) sortedByScore.push_back(&e);
            std::sort(sortedByScore.begin(), sortedByScore.end(),
                [](const Analysis::SuspiciousEntry* a, const Analysis::SuspiciousEntry* b) {
                    return a->score > b->score;
                });

            std::wstringstream ws;
            ws << L"============================================================\n";
            ws << lt.title << L"\n";
            ws << L"============================================================\n";
            writeLine(ws, L"Version: 1.0 (Academic Project)");
            writeLine(ws, lt.note);
            writeLine(ws);

            writeLine(ws, lt.globalSummary);
            writeLine(ws, lt.totalSuspiciousEntries + std::to_wstring(totalEntries));
            writeLine(ws, lt.distinctSuspiciousMessages + std::to_wstring(distinctMsgCount));
            if (options.totalMessagesInConversation > 0) {
                writeLine(ws, lt.totalMessagesProvided + std::to_wstring(totalMessages));
            } else {
                writeLine(ws, lt.totalMessagesFallback + std::to_wstring(totalMessages));
            }
            writeLine(ws, lt.totalAccumScore + formatDouble(totalScore, 2));
            writeLine(ws, lt.avgScorePerEntry +
                (totalEntries ? formatDouble(totalScore / totalEntries, 2) : L"0"));
            writeLine(ws, lt.avgScorePerSuspiciousMsg +
                (distinctMsgCount ? formatDouble(totalScore / distinctMsgCount, 2) : L"0"));
            writeLine(ws, lt.densityPerMsg + formatDouble(densityPerMessage, 2));
            writeLine(ws, lt.minScore + formatDouble(minScore, 2));
            writeLine(ws, lt.maxScore + formatDouble(maxScore, 2));
            writeLine(ws);

            writeLine(ws, lt.riskAssessment);
            writeLine(ws, lt.riskLevel + risk.level);
            writeLine(ws, lt.riskComment + risk.comment);
            writeLine(ws);

            writeLine(ws, lt.itemTypeDistribution);
            if (totalEntries == 0) {
                writeLine(ws, lt.noSuspicious);
            } else {
                auto pct = [&](size_t c) -> std::wstring {
                    return formatDouble(100.0 * (static_cast<double>(c) / totalEntries), 2) + L"%";
                };
                writeLine(ws, lt.wordLabel + L": " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::WORD]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::WORD]) + L")");
                writeLine(ws, lt.linkLabel + L": " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::LINK]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::LINK]) + L")");
                writeLine(ws, lt.filenameLabel + L": " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::FILENAME]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::FILENAME]) + L")");
                writeLine(ws, lt.unknownLabel + L": " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::UNKNOWN]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::UNKNOWN]) + L")");
            }
            writeLine(ws);

            writeLine(ws, lt.categoryStats);
            if (totalEntries == 0) {
                writeLine(ws, lt.noData);
            } else {
                for (auto& kv : kCategoryNames) {
                    if (categoryMap.find(kv.first) == categoryMap.end()) {
                        categoryMap[kv.first] = CategoryStats{};
                    }
                }

                std::vector<std::pair<BaseCategory, CategoryStats>> ordered(categoryMap.begin(), categoryMap.end());
                std::sort(ordered.begin(), ordered.end(),
                    [](const auto& a, const auto& b) {
                        return a.second.totalScore > b.second.totalScore;
                    });

                for (const auto& kv : ordered) {
                    const auto& cat = kv.first;
                    const auto& st = kv.second;
                    double pctEntries = totalEntries ? (100.0 * st.count / static_cast<double>(totalEntries)) : 0.0;
                    writeLine(ws, L"- " + kCategoryNames.at(cat));
                    writeLine(ws, L"    Count: " + std::to_wstring(st.count) +
                        L" (" + formatDouble(pctEntries, 2) + L"%)");
                    writeLine(ws, L"    TotalScore: " + formatDouble(st.totalScore, 2) +
                        L" | AvgScore: " +
                        (st.count ? formatDouble(st.totalScore / st.count, 2) : L"0"));
                    if (!st.examples.empty()) {
                        std::wstring exLine = L"    " + lt.examples;
                        bool first = true;
                        size_t shown = 0;
                        for (const auto& ex : st.examples) {
                            if (!first) exLine += L", ";
                            exLine += L"\"" + ex + L"\"";
                            first = false;
                            if (++shown >= st.examples.size()) break;
                        }
                        writeLine(ws, exLine);
                    } else {
                        writeLine(ws, L"    " + lt.examples + lt.none);
                    }
                }
            }
            writeLine(ws);

            if (options.includeTopEntries && !sortedByScore.empty()) {
                size_t topCount = std::min(options.topEntriesCount, sortedByScore.size());
                std::wstring topHeader = L"[TOP " + std::to_wstring(topCount) + L" " + lt.topEntries + L"]";
                writeLine(ws, topHeader);
                for (size_t i = 0; i < topCount; ++i) {
                    const auto* e = sortedByScore[i];
                    std::wstringstream line;
                    line << L"#" << (i + 1)
                        << L" Score=" << formatDouble(e->score, 2)
                        << L" Type=" << Analysis::toWString(e->itemType)
                        << L" Part=\"" << e->suspiciousPart << L"\""
                        << L" Reason=\"" << e->reason << L"\"";
                    writeLine(ws, line.str());
                }
                writeLine(ws);
            }

            if (options.includePerEntrySection) {
                writeLine(ws, lt.detailedEntries);
                if (entries.empty()) {
                    writeLine(ws, options.language == Language::FR ? L"(Aucune entrée suspecte)" : L"(No suspicious entries)");
                } else {
                    std::vector<const Analysis::SuspiciousEntry*> chronological(entries.size());
                    for (size_t i = 0; i < entries.size(); ++i) chronological[i] = &entries[i];
                    std::stable_sort(chronological.begin(), chronological.end(),
                        [](const Analysis::SuspiciousEntry* a, const Analysis::SuspiciousEntry* b) {
                            return (a->message.getDate() + L" " + a->message.getTime()) <
                                   (b->message.getDate() + L" " + b->message.getTime());
                        });

                    size_t idx = 1;
                    for (const auto* e : chronological) {
                        std::wstringstream line;
                        if (options.language == Language::FR) {
                            line << idx++ << L". [" << e->message.getDate() << L" " << e->message.getTime()
                                << L"] Auteur=\"" << e->message.getAuthor()
                                << L"\" Type=" << Analysis::toWString(e->itemType)
                                << L" Score=" << formatDouble(e->score, 2)
                                << L"\n    Élément suspect: \"" << e->suspiciousPart << L"\""
                                << L"\n    Raison: " << e->reason
                                << L"\n    Contenu du message: " << e->message.getContent()
                                << L"\n";
                        } else {
                            line << idx++ << L". [" << e->message.getDate() << L" " << e->message.getTime()
                                << L"] Author=\"" << e->message.getAuthor()
                                << L"\" Type=" << Analysis::toWString(e->itemType)
                                << L" Score=" << formatDouble(e->score, 2)
                                << L"\n    SuspiciousPart: \"" << e->suspiciousPart << L"\""
                                << L"\n    Reason: " << e->reason
                                << L"\n    MessageContent: " << e->message.getContent()
                                << L"\n";
                        }
                        writeLine(ws, line.str());
                    }
                }
            }

            writeLine(ws);
            writeLine(ws, lt.disclaimerHeader);
            writeLine(ws, lt.disclaimerBody1);
            writeLine(ws, lt.disclaimerBody2);
            writeLine(ws, lt.reportEnd);

            std::ofstream ofs(out, std::ios::binary | std::ios::trunc);
            if (!ofs.is_open()) {
                Logger::instance().log(L"[Report] Failed to open output file: " + outputPath);
                return false;
            }
            const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
            ofs.write(reinterpret_cast<const char*>(bom), 3);
            std::wstring report = ws.str();
            std::string utf8 = wstringToUtf8(report);
            ofs.write(utf8.data(), static_cast<std::streamsize>(utf8.size()));
            ofs.close();

            Logger::instance().log(L"[Report] Report generated at: " + outputPath);
            return true;
        }
        catch (const std::exception& ex) {
            std::wstring werr(ex.what(), ex.what() + std::strlen(ex.what()));
            Logger::instance().log(L"[Report] Exception: " + werr);
            return false;
        }
        catch (...) {
            Logger::instance().log(L"[Report] Unknown exception during report generation.");
            return false;
        }
    }

} // namespace Report