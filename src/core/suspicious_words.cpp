#include "core/suspicious_words.h"

// -------------------- English --------------------
const Domain sexualEnglish = {
    {
        "sex", "porn"
    },1.0};
const Domain violenceEnglish = {
    {
        "kill", "bomb"
    },
    3.0
};
const Domain hateSpeechEnglish = {
    {
        "fool", "imbecile"
    },
    2.0
};
const Domain drugsEnglish = {
    {
        "drug", "speed"
    },
    2.0
};
const Domain scamEnglish = {
    {
        "win", "winner", "prize", "gift", "bonus", "reward", "claim", "urgent", "limited"
    },
    1.0
};
const Domain selfHarmEnglish = {
    {
        "jump", "burn"
    },
    3.0
};
const Domain profanityEnglish = {
    {
        "damn", "shit"
    },
    0.5
};
const Domain extremistEnglish = {
    {
        "terrorist"
    },
    3.0
};

const Domain allEnglishDomains[] = {
    sexualEnglish, violenceEnglish, hateSpeechEnglish, drugsEnglish,
    scamEnglish, selfHarmEnglish, profanityEnglish, extremistEnglish
};

// -------------------- French --------------------
const Domain sexualFrench = {
    {
        "sexe"
    },
    1.0
};
const Domain violenceFrench = {
    {
        "tuer"
    },
    3.0
};
const Domain hateSpeechFrench = {
    {
        "raciste"
    },
    2.0
};
const Domain drugsFrench = {
    {
        "cocaïne"
    },
    2.0
};
const Domain scamFrench = {
    {
        "gagner", "gagnant", "prix", "cadeau", "bonus", "récompense"
    },
    1.0
};
const Domain selfHarmFrench = {
    {
        "suicide"
    },
    3.0
};
const Domain profanityFrench = {
    {
        "merde"
    },
    0.5
};
const Domain extremistFrench = {
    {
        "terroriste"
    },
    3.0
};

const Domain allFrenchDomains[] = {
    sexualFrench, violenceFrench, hateSpeechFrench, drugsFrench,
    scamFrench, selfHarmFrench, profanityFrench, extremistFrench
};
