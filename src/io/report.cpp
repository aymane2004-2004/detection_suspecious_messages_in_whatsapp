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

    // Convert wstring -> UTF-8 (same style as exporter)
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
        // Disambiguate using item type first (because reasonID collisions with FR offset)
        if (e.itemType == Analysis::SuspiciousItemType::LINK)
            return BaseCategory::LINK;
        if (e.itemType == Analysis::SuspiciousItemType::FILENAME)
            return BaseCategory::FILENAME;

        int rid = e.reasonID;
        if (e.itemType == Analysis::SuspiciousItemType::WORD) {
            // French offsets add +100. Normal words (EN) carry 1..8
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

        // Explicit mapping for raw reason IDs (LINK=100, FILENAME=101)
        if (rid == 100) return BaseCategory::LINK;
        if (rid == 101) return BaseCategory::FILENAME;

        return BaseCategory::UNKNOWN;
    }

    struct RiskResult {
        std::wstring level;
        std::wstring comment;
    };

    static RiskResult assessRisk(double totalScore,
        double density,
        size_t totalMessages,
        size_t suspiciousEntries)
    {
        // Base level by totalScore
        auto baseLevel = [&](double s) -> std::wstring {
            if (s < 50)   return L"LOW";
            if (s < 200)  return L"MODERATE";
            if (s < 600)  return L"ELEVATED";
            if (s < 1500) return L"HIGH";
            return L"CRITICAL";
            };

        std::wstring level = baseLevel(totalScore);

        auto escalate = [&]() {
            if (level == L"LOW") level = L"MODERATE";
            else if (level == L"MODERATE") level = L"ELEVATED";
            else if (level == L"ELEVATED") level = L"HIGH";
            else if (level == L"HIGH") level = L"CRITICAL";
            };
        auto deescalate = [&]() {
            if (level == L"CRITICAL") level = L"HIGH";
            else if (level == L"HIGH") level = L"ELEVATED";
            else if (level == L"ELEVATED") level = L"MODERATE";
            else if (level == L"MODERATE") level = L"LOW";
            };

        // Heuristics: density weight & small conversation amplification
        if (totalMessages > 0) {
            if (totalMessages < 50 && totalScore >= 400) escalate();
            if (density > 30.0 && totalScore >= 300) escalate();
            if (density < 5.0 && totalScore >= 500 && suspiciousEntries < (totalMessages / 10 + 5)) {
                deescalate();
            }
        }

        std::wstringstream comment;
        comment << L"TotalScore=" << totalScore;
        if (totalMessages > 0) {
            comment << L", Messages=" << totalMessages
                << L", SuspiciousEntries=" << suspiciousEntries
                << L", DensityScorePerMessage=" << std::fixed << std::setprecision(2) << density;
        }
        comment << L". Level derived from combined total score and density heuristics.";

        return { level, comment.str() };
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

            // Prepare directory
            std::filesystem::path out = outputPath;
            if (out.has_parent_path()) {
                std::error_code ec;
                std::filesystem::create_directories(out.parent_path(), ec);
            }

            const auto& entries = suspicious.getEntries();
            size_t totalEntries = entries.size();

            // Aggregate
            std::map<BaseCategory, CategoryStats> categoryMap;
            std::map<Analysis::SuspiciousItemType, size_t> typeCounts;
            double totalScore = 0.0;
            double minScore = std::numeric_limits<double>::max();
            double maxScore = 0.0;

            std::set<const Message*> distinctMessages;
            for (const auto& e : entries) {
                totalScore += e.score;
                if (e.score < minScore) minScore = e.score;
                if (e.score > maxScore) maxScore = e.score;
                distinctMessages.insert(&e.message);

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

            size_t distinctMsgCount = distinctMessages.size();
            size_t totalMessages = options.totalMessagesInConversation > 0
                ? options.totalMessagesInConversation
                : distinctMsgCount; // fallback

            double densityPerMessage = (totalMessages > 0)
                ? (totalScore / static_cast<double>(totalMessages))
                : 0.0;

            RiskResult risk = assessRisk(totalScore, densityPerMessage, totalMessages, totalEntries);

            // Prepare sorted top entries by score
            std::vector<const Analysis::SuspiciousEntry*> sortedByScore;
            sortedByScore.reserve(entries.size());
            for (const auto& e : entries) sortedByScore.push_back(&e);
            std::sort(sortedByScore.begin(), sortedByScore.end(),
                [](const Analysis::SuspiciousEntry* a, const Analysis::SuspiciousEntry* b) {
                    return a->score > b->score;
                });

            // Build report in wide buffer
            std::wstringstream ws;
            ws << L"============================================================\n";
            ws << L"SUSPICIOUS CONVERSATION ANALYTICAL REPORT\n";
            ws << L"============================================================\n";
            writeLine(ws, L"Version: 1.0 (Academic Project)");
            writeLine(ws, L"NOTE: This report is for academic purposes only. It may contain false positives.");
            writeLine(ws);

            writeLine(ws, L"[GLOBAL SUMMARY]");
            writeLine(ws, L"Total suspicious entries: " + std::to_wstring(totalEntries));
            writeLine(ws, L"Distinct messages involved: " + std::to_wstring(distinctMsgCount));
            if (options.totalMessagesInConversation > 0) {
                writeLine(ws, L"Total messages in conversation (provided): " + std::to_wstring(totalMessages));
            }
            else {
                writeLine(ws, L"Total messages in conversation (assumed = suspicious message count): " + std::to_wstring(totalMessages));
            }
            writeLine(ws, L"Total accumulated score: " + formatDouble(totalScore, 2));
            writeLine(ws, L"Average score per suspicious entry: " +
                (totalEntries ? formatDouble(totalScore / totalEntries, 2) : L"0"));
            writeLine(ws, L"Average score per suspicious message: " +
                (distinctMsgCount ? formatDouble(totalScore / distinctMsgCount, 2) : L"0"));
            writeLine(ws, L"Score density (per total message): " + formatDouble(densityPerMessage, 2));
            writeLine(ws, L"Min suspicious entry score: " + formatDouble(minScore, 2));
            writeLine(ws, L"Max suspicious entry score: " + formatDouble(maxScore, 2));
            writeLine(ws);

            writeLine(ws, L"[RISK ASSESSMENT]");
            writeLine(ws, L"Risk Level: " + risk.level);
            writeLine(ws, L"Comment: " + risk.comment);
            writeLine(ws);

            // Type distribution
            writeLine(ws, L"[SUSPICIOUS ITEM TYPE DISTRIBUTION]");
            if (totalEntries == 0) {
                writeLine(ws, L"No suspicious entries detected.");
            }
            else {
                auto pct = [&](size_t c) -> std::wstring {
                    return formatDouble(100.0 * (static_cast<double>(c) / totalEntries), 2) + L"%";
                    };
                writeLine(ws, L"WORD: " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::WORD]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::WORD]) + L")");
                writeLine(ws, L"LINK: " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::LINK]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::LINK]) + L")");
                writeLine(ws, L"FILENAME: " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::FILENAME]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::FILENAME]) + L")");
                writeLine(ws, L"UNKNOWN: " + std::to_wstring(typeCounts[Analysis::SuspiciousItemType::UNKNOWN]) +
                    L" (" + pct(typeCounts[Analysis::SuspiciousItemType::UNKNOWN]) + L")");
            }
            writeLine(ws);

            writeLine(ws, L"[CATEGORY STATISTICS]");
            if (totalEntries == 0) {
                writeLine(ws, L"No data.");
            }
            else {
                // Ensure all categories appear even if 0
                for (auto& kv : kCategoryNames) {
                    if (categoryMap.find(kv.first) == categoryMap.end()) {
                        categoryMap[kv.first] = CategoryStats{};
                    }
                }

                // Sort categories by totalScore descending
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
                        std::wstring exLine = L"    Examples: ";
                        bool first = true;
                        size_t shown = 0;
                        for (const auto& ex : st.examples) {
                            if (!first) exLine += L", ";
                            exLine += L"\"" + ex + L"\"";
                            first = false;
                            if (++shown >= st.examples.size()) break;
                        }
                        writeLine(ws, exLine);
                    }
                    else {
                        writeLine(ws, L"    Examples: (none)");
                    }
                }
            }
            writeLine(ws);

            if (options.includeTopEntries && !sortedByScore.empty()) {
                size_t topCount = std::min(options.topEntriesCount, sortedByScore.size());
                writeLine(ws, L"[TOP " + std::to_wstring(topCount) + L" HIGHEST-SCORING ENTRIES]");
                size_t limit = std::min(options.topEntriesCount, sortedByScore.size());
                for (size_t i = 0; i < limit; ++i) {
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
                writeLine(ws, L"[DETAILED ENTRIES]");
                if (entries.empty()) {
                    writeLine(ws, L"(No suspicious entries)");
                }
                else {
                    // Copy & chronological sorting (by message date/time strings; fallback original order)
                    std::vector<const Analysis::SuspiciousEntry*> chronological(entries.size());
                    for (size_t i = 0; i < entries.size(); ++i) chronological[i] = &entries[i];
                    std::stable_sort(chronological.begin(), chronological.end(),
                        [](const Analysis::SuspiciousEntry* a, const Analysis::SuspiciousEntry* b) {
                            // Simple lexical comparison of date+time (assumes ISO or consistent)
                            return (a->message.getDate() + L" " + a->message.getTime()) <
                                (b->message.getDate() + L" " + b->message.getTime());
                        });

                    size_t idx = 1;
                    for (const auto* e : chronological) {
                        std::wstringstream line;
                        line << idx++ << L". [" << e->message.getDate() << L" " << e->message.getTime()
                            << L"] Author=\"" << e->message.getAuthor()
                            << L"\" Type=" << Analysis::toWString(e->itemType)
                            << L" Score=" << formatDouble(e->score, 2)
                            << L"\n    SuspiciousPart: \"" << e->suspiciousPart << L"\""
                            << L"\n    Reason: " << e->reason
                            << L"\n    MessageContent: " << e->message.getContent()
                            << L"\n";
                        writeLine(ws, line.str());
                    }
                }
            }

            writeLine(ws);
            writeLine(ws, L"[DISCLAIMER]");
            writeLine(ws, L"This analytical report is generated by an academic prototype.");
            writeLine(ws, L"It may contain false positives or misclassifications. "
                L"Manual expert review is recommended before any action.");
            writeLine(ws, L"End of report.");

            // Write file in UTF-8 with BOM
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