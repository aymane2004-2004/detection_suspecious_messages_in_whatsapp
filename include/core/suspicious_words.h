#ifndef SUSPICIOUS_WORDS_H
#define SUSPICIOUS_WORDS_H

#include <unordered_set>
#include <string>

struct Domain {
    std::unordered_set<std::string> words;
    double weight;
};

// English domains
extern const Domain sexualEnglish;
extern const Domain violenceEnglish;
extern const Domain hateSpeechEnglish;
extern const Domain drugsEnglish;
extern const Domain scamEnglish;
extern const Domain selfHarmEnglish;
extern const Domain profanityEnglish;
extern const Domain extremistEnglish;
extern const Domain allEnglishDomains[];

// French domains
extern const Domain sexualFrench;
extern const Domain violenceFrench;
extern const Domain hateSpeechFrench;
extern const Domain drugsFrench;
extern const Domain scamFrench;
extern const Domain selfHarmFrench;
extern const Domain profanityFrench;
extern const Domain extremistFrench;
extern const Domain allFrenchDomains[];


#endif // SUSPICIOUS_WORDS_H
