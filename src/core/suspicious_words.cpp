#include "core/suspicious_words.h"

namespace SuspiciousWords {

    const std::set<std::string> frenchSuspiciousWords = {
        "danger", "arnaque", "spam", "violence"
    };

    const std::set<std::string> englishSuspiciousWords = {
        "danger", "scam", "spam", "violence"
    };

}
