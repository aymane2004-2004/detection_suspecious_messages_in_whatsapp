#include "core/suspicious_words.h"

// -------------------- English --------------------
const Domain sexualEnglish = {
    {
        "sex", "porn", "nude", "xxx", "erotic", "adult", "fetish", "lingerie", "seduce", "intimate",
        "kinky", "bondage", "bdsm", "explicit", "hardcore", "softcore", "milf", "cum", "cock", "dick",
        "pussy", "vagina", "penis", "breasts", "boobs", "ass", "anal", "oral", "masturbate", "orgasm",
        "sexually", "naked", "provocative", "strip", "tempt", "sensual", "lover", "intercourse", "climax", "threesome",
        "pornography", "erotica", "fetishize", "voyeur", "peep", "stripper", "adultfilm", "sexscene", "seduction", "naught",
        "sextoy", "bdsmplay", "bondagesex", "fetishsex", "lingeriesex", "hardcoresex", "softcoresex", "sexualact", "sexed", "sexedup",
        "eroticism", "provocativeness", "libido", "sexualdrive", "sexualfantasy", "sexualdesire", "horny", "lust", "passion", "flirt",
        "seductive", "risque", "pornstar", "eroticvideo", "sexvideo", "adultvideo", "pornmag", "sexmag", "nudemodel", "eroticmodel",
        "stripclub", "sexclub", "sexparty", "hookup", "one-night", "casualsex", "lustful", "sexappeal", "sexualcontent", "sexact",
        "sexualactress", "adultcontent", "porncontent", "nudephoto", "eroticphoto", "sexphoto", "sexualphoto", "kink", "fetishclub", "sexchat"
    },1.0};
const Domain violenceEnglish = {
    {
        "kill", "bomb", "attack", "shoot", "stab", "assault", "murder", "slay", "gun", "knife",
        "explosion", "terror", "fight", "war", "battle", "hit", "punch", "choke", "strangle", "massacre",
        "riot", "arson", "abuse", "lynch", "shooting", "homicide", "blood", "violence", "brutal", "assassin",
        "ambush", "execute", "bombing", "grenade", "bullet", "terrorist", "hostage", "weapon", "knifeattack", "killings",
        "gunfire", "machete", "slaughter", "terrorize", "combat", "attackers", "rioters", "brawl", "fightback", "bludgeon",
        "sword", "murderer", "hitman", "massmurder", "vengeance", "assaulted", "gunman", "assailant", "molotov", "carjacking",
        "sabotage", "massacreplan", "riotcontrol", "civilwar", "bloodshed", "execution", "hijack", "terrorism", "hostility", "killzone",
        "fistfight", "striker", "armed", "combatant", "ambushed", "strikerattack", "shootout", "manslaughter", "slayings", "terrorattack",
        "firefight", "battlefield", "siege", "onslaught", "wound", "injure", "blow", "smash", "destroy", "assaulting",
        "violating", "bloodbath", "killshot", "aggression", "threat", "clash", "storm", "violator", "attackplan", "weaponized"
    },
    3.0
};
const Domain hateSpeechEnglish = {
    {
        "racist", "slut", "idiot", "dumb", "stupid", "loser", "moron", "fool", "imbecile", "jerk",
        "bastard", "asshole", "hate", "scum", "trash", "pig", "bigot", "chauvinist", "xenophobe", "nazi",
        "klansman", "hater", "offender", "villain", "vermin", "fiend", "coward", "pervert", "degenerate", "criminal",
        "intolerant", "prejudiced", "biased", "oppressor", "tyrant", "brute", "harasser", "bully", "chauvinistic", "fanatic",
        "radical", "extremist", "aggressor", "provocateur", "abuser", "exploiter", "menace", "freak", "loserface", "idiotic",
        "ignorant", "malicious", "vile", "obnoxious", "disgusting", "nasty", "despicable", "detestable", "offensive", "repulsive",
        "insult", "mock", "deride", "belittle", "humiliate", "slanderer", "defamer", "taunt", "ridicule", "demean",
        "jeer", "scorn", "contempt", "vilify", "disparage", "denigrate", "degrade", "mockery", "oppress", "demeaning",
        "bigotry", "intolerance", "hatecrime", "racism", "sexism", "misogyny", "homophobia", "transphobia", "discrimination", "prejudice",
        "xenophobia", "hostility", "aggression", "insulting", "abusive", "provocative", "offend", "demeaningword", "vilifying", "derogatory"
    },
    2.0
};
const Domain drugsEnglish = {
    {
        "cocaine", "weed", "heroin", "meth", "morphine", "opioid", "mdma", "ecstasy", "lsd", "marijuana",
        "pot", "hash", "shrooms", "psilocybin", "ketamine", "fentanyl", "oxycodone", "percocet", "vicodin", "amphetamine",
        "methamphetamine", "crystal", "methcrystal", "pcp", "angelDust", "dmt", "tramadol", "cannabis", "joint", "blunt",
        "spliff", "hashish", "hashoil", "dab", "wax", "oil", "thc", "cbd", "ganja", "dope",
        "opium", "molly", "mdxx", "stimulant", "depressant", "hallucinogen", "drug", "addict", "high", "intoxicated",
        "narcotic", "painkiller", "opioids", "cannabinoid", "smoke", "vape", "inject", "needle", "snort", "trip",
        "acid", "shroomtrip", "roll", "rollup", "blaze", "jointsmoke", "weedleaf", "marijuanaleaf", "bud", "kush",
        "hashbrown", "hashoildrop", "crack", "coke", "speed", "uppers", "downers", "barbiturates", "tranquilizer", "xanax",
        "valium", "prozac", "rx", "prescription", "overdose", "rehab", "detox", "substance", "illegal", "controlledsubstance",
        "drugtrade", "drugdealer", "druguse", "drugabuse", "narcotics", "smuggling", "trafficking", "illicit", "streetdrug", "psychedelic"
    },
    2.0
};
const Domain scamEnglish = {
    {
        "win", "winner", "prize", "gift", "bonus", "reward", "claim", "urgent", "limited", "exclusive",
        "offer", "payment", "transfer", "account", "verify", "security", "confirm", "click", "link", "password",
        "login", "bank", "credit", "card", "lottery", "jackpot", "deposit", "withdrawal", "check", "details",
        "personal", "information", "identity", "email", "message", "alert", "notification", "access", "update", "actnow",
        "riskfree", "investment", "bitcoin", "crypto", "funds", "cash", "guaranteed", "easy", "quick", "apply",
        "registration", "sign-up", "accountupdate", "verification", "activation", "limitedtime", "urgentaction", "clickhere", "respond", "confirmnow",
        "secure", "protected", "confidential", "rewardclaim", "banking", "fundtransfer", "transaction", "reminder", "deadline", "important",
        "priority", "service", "offerexpires", "actfast", "exclusiveoffer", "specialoffer", "claimprize", "winbig", "cashreward", "getpaid",
        "giftcard", "voucher", "redeem", "instant", "fastcash", "earnmoney", "onlineoffer", "promotional", "bonusreward", "limitedaccess",
        "opportunity", "applyonline", "register", "notify", "confirmaccount", "securitycheck", "urgentnotice", "rewardprogram", "fundyouraccount", "claimreward"
    },
    1.0
};
const Domain selfHarmEnglish = {
    {
        "suicide", "cutting", "overdose", "selfharm", "bleed", "hang", "jump", "pill", "slice", "burn",
        "starve", "scar", "injure", "poison", "hangmyself", "overdosed", "cutmyself", "selfinjury", "selfdestruct", "slash",
        "selfmutilation", "selfwound", "fatal", "harmmyself", "killmyself", "die", "deathwish", "selfabuse", "selfpunish", "bleeding",
        "selfdestruction", "selfslashing", "selfcut", "suicidal", "selfkill", "selfbleed", "injuring", "selfharming", "hangings", "jumping",
        "overdosing", "poisoning", "selfpoison", "selfharmact", "selfinjured", "selfwounding", "selfscarring", "cuttings", "bleedingmyself", "selfburn",
        "fatalact", "harmact", "selfend", "endmyself", "killact", "dieact", "selfterminate", "selfextinction", "deathact", "pain",
        "suffering", "anguish", "depression", "hopeless", "despair", "sadness", "mentalpain", "emotionalpain", "grief", "cry",
        "suicidalthoughts", "ideation", "selfdestructive", "selfinjuring", "selfcutting", "selfpunishing", "selfharmed", "selfmutilated", "selfwounded", "selfscars",
        "selfinjures", "selfharmingact", "selfkillact", "overdosepill", "overdosemeds", "hangself", "jumpfromheight", "cutwrist", "burnself", "stabself",
        "selfabusive", "selfinflicted", "selfdestructing", "selfdestructed", "suicideplan", "suicideattempt", "suicidalact", "selfhurt", "selftorment", "selfaggression"
    },
    3.0
};
const Domain profanityEnglish = {
    {
        "fuck", "shit", "bitch", "asshole", "dick", "piss", "damn", "crap", "bollocks", "bugger",
        "cock", "prick", "fag", "twat", "slut", "whore", "cunt", "motherfucker", "nigger", "bastard",
        "douche", "jerk", "pussy", "idiot", "moron", "dumbass", "retard", "shithead", "ass", "arse",
        "fucker", "asswipe", "twatface", "dickhead", "cum", "blowjob", "handjob", "tit", "tits", "boobs",
        "faggot", "wanker", "shitbag", "cockhead", "asshat", "dumbfuck", "shitface", "slutty", "cumshot", "prickhead",
        "knobhead", "arsehole", "buggered", "bollocked", "titfuck", "fuckface", "shitfuck", "cockface", "dickface", "bitchass",
        "jackass", "shitstain", "assclown", "dumbshit", "fuckboy", "fuckgirl", "bitchface", "arsewipe", "titty", "twatwaffle",
        "dickwad", "shitdick", "cockwomble", "arseface", "cocksucker", "shitcock", "wank", "prickface", "assburger", "shitheadass",
        "bollock", "dickweasel", "cocknose", "fart", "poop", "arseholeface", "dumbasshole", "shitbrains", "fucktard", "assmunch",
        "bastardface", "twathead", "cuntface", "dickmonger", "shitmonger", "arsefucker", "bollocksface", "wankface", "fucknut", "shitbucket"
    },
    0.5
};
const Domain extremistEnglish = {
    {
        "terrorist", "jihad", "radical", "militant", "extremist", "fundamentalist", "insurgent", "rebel", "fanatic", "separatist",
        "combatant", "activist", "guerrilla", "revolutionary", "ideologue", "zealot", "hardliner", "subversive", "ultranationalist", "paramilitary",
        "terrorism", "attack", "violence", "bombing", "assault", "hostage", "attackplan", "martyr", "militia", "cell",
        "recruitment", "propaganda", "radicalize", "extremism", "covert", "plot", "insurrection", "siege", "terrorattack", "attackers",
        "armedgroup", "hostility", "threat", "radicalgroup", "terrorcell", "ideological", "jihadist", "militantgroup", "extremistcell", "subversion",
        "terrorplan", "attackplot", "guerrillawarfare", "militantattack", "radicalactivity", "fundamentalism", "religiousfanatic", "ultra", "hardcore", "ideologicalattack",
        "revolution", "rebellion", "subversiveact", "armedrebels", "terroroperation", "violentgroup", "militantoperation", "terrororganization", "terrorleader", "terroristattack",
        "hostagecrisis", "bombplot", "suicideattack", "attackgroup", "extremistleader", "violentcell", "terrorcellleader", "radicalleader", "ideologicalcell", "terrorplot",
        "paramilitarygroup", "insurgentcell", "armedinsurgent", "violentorganization", "terroractivity", "armedattack", "violentplan", "extremistplan", "ideologicalattackplan", "subversiveorganization",
        "jihadcell", "militantleader", "terrorcampaign", "radicalcampaign", "violentcampaign", "armedcampaign", "extremistcampaign", "ideologicalcampaign", "covertattack", "terroract"
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
        "sexe", "porno", "nu", "xxx", "erotique", "adulte", "fétiche", "lingerie", "séduire", "intime",
        "coquin", "bondage", "bdsm", "explicite", "hardcore", "softcore", "milf", "jouir", "bite", "zizi",
        "chatte", "vagin", "pénis", "seins", "nichons", "cul", "anal", "oral", "masturber", "orgasme",
        "sexuellement", "nu", "provocant", "strip", "tenter", "sensuel", "amant", "relationssexuelles", "climax", "ménageàtrois",
        "pornographie", "erotisme", "fétichiser", "voyeur", "regarder", "stripteaseuse", "filmadulte", "scènedesex", "séduction", "coquin",
        "jouetsexuel", "bdsmjeu", "bondagesexuel", "fétichismesexuel", "lingeriesexuel", "hardcoresexuel", "softcoresexuel", "actesexuel", "sexé", "sexéup",
        "érotisme", "provocateur", "libido", "désirsexuel", "fantasmesexuel", "envie", "excité", "luxure", "passion", "flirt",
        "séduisant", "osé", "pornstar", "vidéoérotique", "vidéosex", "filmadulte", "revueporno", "revuesexe", "modèle nu", "modèle érotique",
        "clubdestrip", "clubsexuel", "soiréesex", "rencontre", "coup d’un soir", "sexedécontracté", "lubrique", "attraitssexuels", "contenu sexuel", "actesexuels",
        "actriceadultes", "contenu adulte", "contenuporno", "photo nue", "photo érotique", "photosex", "photosexuel", "kink", "clubfétiche", "chatsexuel"
    },
    1.0
};
const Domain violenceFrench = {
    {
        "tuer", "bombe", "attaque", "tirer", "poignarder", "agression", "meurtre", "assassiner", "pistolet", "couteau",
        "explosion", "terrorisme", "combat", "guerre", "bataille", "frapper", "coup", "étrangler", "étranglement", "massacre",
        "émeute", "incendie", "abus", "lyncher", "fusillade", "homicide", "sang", "violence", "brutal", "assassin",
        "embuscade", "exécuter", "attentat", "grenade", "balle", "terroriste", "otage", "arme", "attaqueaucouteau", "meurtres",
        "tir", "machette", "abattage", "terroriser", "combat", "assaillants", "émeutiers", "bagarre", "riposter", "matraquer",
        "épée", "meurtrier", "tueuràgages", "massacremeurtre", "vengeance", "agressé", "pistolero", "assaillant", "cocktailmolotov", "volvoiture",
        "sabotage", "planmassacre", "contrôleémeute", "guerrecivile", "bain de sang", "exécution", "détournement", "terrorisme", "hostilité", "zone de combat",
        "poing", "attaquant", "armé", "combattant", "embusqué", "attaqueattaquant", "fusillade", "homicide involontaire", "meurtres", "attaque terroriste",
        "combat", "champdebataille", "siège", "assaut", "blessure", "blesser", "coup", "fracasser", "détruire", "agresser",
        "viol", "bain de sang", "tirmortel", "agression", "menace", "affrontement", "tempête", "violateur", "planattaque", "armé"
    },
    3.0
};
const Domain hateSpeechFrench = {
    {
        "raciste", "salope", "idiot", "stupide", "imbécile", "loser", "crétin", "fou", "abruti", "connard",
        "bâtard", "trouduc", "haine", "ordure", "déchet", "cochon", "intolérant", "chauviniste", "xénophobe", "nazi",
        "membre du klan", "haineux", "contrevenant", "méchant", "vermine", "démon", "lâche", "pervers", "dégénéré", "criminel",
        "préjugé", "partial", "oppresseur", "tyran", "brute", "harceleur", "brute scolaire", "chauvin", "fanatique",
        "radical", "extrémiste", "agresseur", "provocateur", "abusif", "exploiteur", "menace", "monstre", "perdant", "idiotique",
        "ignorant", "malveillant", "vil", "odieux", "dégoûtant", "méchant", "méprisable", "détestable", "offensant", "répugnant",
        "insulte", "moquer", "ridiculiser", "rabaisser", "humilier", "diffamateur", "calomniateur", "railler", "ridiculiser", "dénigrer",
        "raillerie", "mépris", "contempt", "vilipender", "discréditer", "dénigrer", "dégrader", "moquerie", "opprimer", "humiliation",
        "intolérance", "préjugé", "crime haineux", "racisme", "sexisme", "misogynie", "homophobie", "transphobie", "discrimination", "préjugé",
        "xénophobie", "hostilité", "agression", "insultant", "abusif", "provocateur", "offenser", "terme dégradant", "diffamant", "dénigrant"
    },
    2.0
};
const Domain drugsFrench = {
    {
        "cocaïne", "weed", "héroïne", "meth", "morphine", "opioïde", "mdma", "ecstasy", "lsd", "marijuana",
        "pot", "hasch", "champignons", "psilocybine", "kétamine", "fentanyl", "oxycodone", "percocet", "vicodin", "amphétamine",
        "méthamphétamine", "cristal", "methcristal", "pcp", "angelDust", "dmt", "tramadol", "cannabis", "joint", "blunt",
        "spliff", "haschisch", "huilehasch", "dab", "wax", "huile", "thc", "cbd", "ganja", "dope",
        "opium", "molly", "mdxx", "stimulant", "dépressif", "hallucinogène", "drogue", "toxicomane", "planer", "intoxiqué",
        "narcotique", "antidouleur", "opioïdes", "cannabinoïde", "fumer", "vaper", "injection", "aiguille", "renifler", "trip",
        "acide", "tripchampignon", "rouler", "roulerunjoint", "flamber", "fuméejoint", "feuilleweed", "feuillemarijuana", "bourgeon", "kush",
        "hashbrown", "huilehaschdrop", "crack", "coke", "speed", "uppers", "downers", "barbituriques", "tranquillisants", "xanax",
        "valium", "prozac", "rx", "ordonnance", "overdose", "réhab", "detox", "substance", "illégal", "substancecontrôlée",
        "commerce de drogue", "dealer", "consommationdrogue", "abusdedrogue", "narcotiques", "contrebande", "traite", "illicite", "droguerue", "psychédélique"
    },
    2.0
};
const Domain scamFrench = {
    {
        "gagner", "gagnant", "prix", "cadeau", "bonus", "récompense", "réclamer", "urgent", "limité", "exclusif",
        "offre", "paiement", "transfert", "compte", "vérifier", "sécurité", "confirmer", "cliquer", "lien", "motdepasse",
        "connexion", "banque", "crédit", "carte", "loterie", "jackpot", "dépôt", "retrait", "vérifier", "détails",
        "personnel", "informations", "identité", "email", "message", "alerte", "notification", "accès", "miseàjour", "agirmaintenant",
        "sansrisque", "investissement", "bitcoin", "crypto", "fonds", "argent", "garanti", "facile", "rapide", "postuler",
        "inscription", "enregistrement", "miseàjourcompte", "vérification", "activation", "tempslimité", "actionurgente", "cliquezici", "répondre", "confirmermaintenant",
        "sécurisé", "protégé", "confidentiel", "réclamerécompense", "servicesbancaires", "transfertdefonds", "transaction", "rappel", "échéance", "important",
        "priorité", "service", "offreexpire", "agirvite", "offreexclusive", "offrespeciale", "réclamerprix", "grosgain", "récompenseargent", "être payé",
        "cartecadeau", "bon", "échanger", "instant", "argentrapide", "gagnerargent", "offreenligne", "promotionnel", "récompensebonus", "accèslimité",
        "opportunité", "postulerenligne", "inscrire", "notifier", "confirmercompte", "vérificationdesécurité", "avisurgent", "programme récompense", "fondscompte", "réclamerécompense"
    },
    1.0
};
const Domain selfHarmFrench = {
    {
        "suicide", "scarification", "overdose", "automutilation", "saigner", "pendre", "sauter", "pilule", "trancher", "brûler",
        "se priver", "cicatrice", "blesser", "poison", "pendremoi", "overdosé", "couper", "blessurepersonnelle", "autodestruction", "entaille",
        "automutilation", "blessureauto", "fatal", "meblesser", "mettemoiàmort", "mourir", "désir de mort", "abus de soi", "auto-punition", "saignement",
        "autodestruction", "entaillement", "auto-coupe", "suicidaire", "auto-mort", "auto-saignement", "blessures", "auto-blessure", "pendaisons", "sauts",
        "overdose", "empoisonnement", "auto-poison", "acte d'automutilation", "blessé", "blessureauto", "cicatrisation", "couperies", "auto-saignement", "brûlureauto",
        "actefatal", "acteblessure", "fin de soi", "me terminer", "actemort", "agir pour mourir", "auto-terminaison", "auto-extinction", "actemort", "douleur",
        "souffrance", "angoisse", "dépression", "désespoir", "tristesse", "douleurmentale", "douleurémotionnelle", "chagrin", "pleurer", "pensées suicidaires",
        "idées", "autodestructeur", "auto-blessant", "auto-coupant", "auto-punissant", "auto-blessé", "automutilé", "auto-blessé", "cicatrices", "blessurespersonnelles",
        "acte d'automutilation", "actesuicidaire", "piluleoverdose", "médicamentsoverdose", "pendremoi", "sauter d'une hauteur", "coup poignet", "brûlure personnelle", "se poignarder",
        "abusauto", "auto-infligé", "autodestruction", "autodestructé", "plan suicide", "tentative de suicide", "actesuicidaire", "seblesser", "auto-tourment", "auto-agression"
    },
    3.0
};
const Domain profanityFrench = {
    {
        "merde", "putain", "connard", "trouduc", "bite", "pipi", "bordel", "conneries", "couilles", "enculé",
        "bite", "zizi", "pédé", "conne", "salope", "pute", "chatte", "enculeur", "nègre", "bâtard",
        "goujat", "crétin", "chatte", "idiot", "imbécile", "abruti", "retardé", "tête de con", "cul", "derrière",
        "enfoiré", "essuie-cul", "face de conne", "tête de bite", "sperme", "branlette", "masturbation", "sein", "nichons", "poitrine",
        "pédé", "branleur", "sac de merde", "tête de coq", "chapeau de con", "abrutif", "face de merde", "coquine", "éjaculation", "tête de con",
        "tête de gland", "trouduc", "baisé", "tête de bite", "face de merde", "tête de coq", "pute à cul", "jackass", "tache de merde", "clown de cul",
        "abruti de merde", "mec à baiser", "fille à baiser", "face de pute", "essuie-cul", "tétons", "gaufre de con", "tête de bite", "bite de merde", "cochon",
        "âne", "tête de merde", "museau de coq", "péter", "caca", "face de trouduc", "abruti de cul", "cerveau de merde", "tardif à baiser", "bouffe-cul",
        "face de bâtard", "tête de con", "face de chatte", "mangeur de bite", "mangeur de merde", "enculeur", "tête de couilles", "branleur", "noix de con", "tête de merde",
        "couilles", "tête de weasel", "nez de coq", "prout", "crotte", "face de trouduc", "abruti de trouduc", "cerveau de merde", "con de merde", "mangeur de cul",
        "face de bâtard", "tête de conne", "face de chatte", "mangeur de bite", "mangeur de merde", "enculeur", "face de couilles", "branleur", "tête de con", "seau de merde"
    },
    0.5
};
const Domain extremistFrench = {
    {
        "terroriste", "jihad", "djihad", "radical", "militant", "extrémiste", "fondamentaliste", "insurgé", "rebelle", "fanatique", "séparatiste",
        "combattant", "activiste", "guérilla", "révolutionnaire", "idéologue", "zélote", "intransigeant", "subversif", "ultranationaliste", "paramilitaire",
        "terrorisme", "attaque", "violence", "attentat", "assaut", "otage", "planattaque", "martyr", "milice", "cellule",
        "recrutement", "propagande", "radicaliser", "extrémisme", "caché", "complot", "insurrection", "siège", "attaque terroriste", "assaillants",
        "groupe armé", "hostilité", "menace", "groupe radical", "cellule terroriste", "idéologique", "djihadiste", "groupe militant", "cellule extrémiste", "subversion",
        "plan terroriste", "plan d'attaque", "guerre de guérilla", "attaque militante", "activité radicale", "fondamentalisme", "fanatique religieux", "ultra", "hardcore", "attaque idéologique",
        "révolution", "rébellion", "acte subversif", "rebelles armés", "opération terroriste", "groupe violent", "opération militante", "organisation terroriste", "leader terroriste", "attaque terroriste",
        "crise des otages", "plan de bombe", "attaque suicide", "groupe d'attaque", "leader extrémiste", "cellule violente", "leader cellule terroriste", "leader radical", "cellule idéologique", "plan terroriste",
        "groupe paramilitaire", "cellule insurgée", "insurgé armé", "organisation violente", "activité terroriste", "attaque armée", "plan violent", "plan extrémiste", "plan d'attaque idéologique", "organisation subversive",
        "cellule djihadiste", "leader militant", "campagne terroriste", "campagne radicale", "campagne violente", "campagne armée", "campagne extrémiste", "campagne idéologique", "attaque secrète", "acte terroriste"
    },
    3.0
};

const Domain allFrenchDomains[] = {
    sexualFrench, violenceFrench, hateSpeechFrench, drugsFrench,
    scamFrench, selfHarmFrench, profanityFrench, extremistFrench
};
