#include "metaextractor.hpp"
#include <fstream>
#include <iostream>
#include <regex>
#include <algorithm>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <filesystem>
#include <set>

using namespace std;
namespace fs = std::filesystem;

// Fonction utilitaire pour échapper CSV
static string escapeCSV(const string& s) {
    string result;
    for (char c : s) {
        if (c == '"') result += "\"\"";
        else if (c == '\n' || c == '\r') result += ' ';
        else result += c;
    }
    return result;
}

// Extraction des messages depuis le fichier WhatsApp
vector<Metadata> MetaExtractor::extract(const string& filepath) {
    vector<Metadata> results;
    ifstream file(filepath);
    if (!file.is_open()) {
        cerr << "Erreur : impossible d'ouvrir " << filepath << endl;
        return results;
    }

    string line;
    regex pattern(R"(\[(\d{2}/\d{2}/\d{4}) (\d{2}:\d{2})\] (.*?): (.*))");
    smatch match;

    while (getline(file, line)) {
        if (regex_match(line, match, pattern)) {
            Metadata m;
            m.date = match[1];
            m.time = match[2];
            m.author = match[3];
            m.message = match[4];
            m.type = classify(m.message);
            results.push_back(m);
        }
    }
    return results;
}

// Classification du type de message
MessageType MetaExtractor::classify(const string& message) {
    regex urlRegex(R"(https?:\/\/[^\s]+)");
    if (regex_search(message, urlRegex)) return LINK;
    if (message == "🚫 This message was deleted") return MEDIA_OMITTED;
    regex videoRegex(R"(.*\.(mp4|mkv|avi)$)", regex::icase);
    if (regex_search(message, videoRegex)) return VIDEO;
    regex audioRegex(R"(.*\.(mp3|wav|ogg)$)", regex::icase);
    if (regex_search(message, audioRegex)) return AUDIO;
    regex imageRegex(R"(.*\.(jpg|jpeg|png|gif|webp)$)", regex::icase);
    if (regex_search(message, imageRegex)) return IMAGE;
    regex docRegex(R"(.*\.(pdf|docx|xlsx|pptx|txt)$)", regex::icase);
    if (regex_search(message, docRegex)) return DOCUMENT;
    return TEXT;
}

// Affichage de tous les messages
void MetaExtractor::printAll(const vector<Metadata>& metas) {
    for (const auto& m : metas) {
        cout << "------------------------------------------\n";
        cout << "[+] Date   : " << m.date
             << "\n[+] Heure  : " << m.time
             << "\n[+] Auteur : " << m.author
             << "\n[+] Type   : " << messageTypeToString(m.type)
             << "\n[+] Message: " << m.message << endl;
    }
    cout << "------------------------------------------\n";
}

// Conversion du type de message en string
string MetaExtractor::messageTypeToString(MessageType type) {
    switch (type) {
        case TEXT: return "Texte";
        case LINK: return "Lien";
        case MEDIA_OMITTED: return "Média omis";
        case IMAGE: return "Image";
        case VIDEO: return "Vidéo";
        case AUDIO: return "Audio";
        case DOCUMENT: return "Document";
        default: return "Inconnu";
    }
}

// Export CSV
void MetaExtractor::exportToCSV(const vector<Metadata>& metas, const string& outputPath) {
    if (!fs::exists("outputs")) fs::create_directory("outputs");

    ofstream out(outputPath, ios::out | ios::trunc);
    if (!out.is_open()) {
        cerr << "Erreur : impossible d'ouvrir le fichier CSV " << outputPath << "\n";
        return;
    }

    out << "Date,Heure,Auteur,Type,Message\n";
    for (const auto& m : metas) {
        out << "\"" << m.date << "\","
            << "\"" << m.time << "\","
            << "\"" << m.author << "\","
            << "\"" << messageTypeToString(m.type) << "\","
            << "\"" << escapeCSV(m.message) << "\"\n";
    }

    out.close();
    cout << "[+] Exportation terminée : " << outputPath << endl;
}

// Journalisation
void MetaExtractor::logExport(const vector<Metadata>& metas, const string& outputPath) {
    if (!fs::exists("logs")) fs::create_directory("logs");
    ofstream logFile("logs/log.txt", ios::app);
    if (!logFile.is_open()) {
        cerr << "Erreur : impossible d'ouvrir logs/log.txt\n";
        return;
    }

    auto now = chrono::system_clock::now();
    time_t now_c = chrono::system_clock::to_time_t(now);
    logFile << "[" << put_time(localtime(&now_c), "%Y-%m-%d %H:%M:%S") << "] "
            << "Exportation de " << metas.size() << " messages vers "
            << outputPath << endl;
    logFile.close();
}

// Chargement des mots suspects depuis un fichier
set<string> MetaExtractor::loadSuspiciousWords(const string& filepath) {
    set<string> words;
    ifstream file(filepath);
    if (!file.is_open()) {
        cerr << "Erreur : impossible d'ouvrir " << filepath << endl;
        return words;
    }

    string line;
    while (getline(file, line)) {
        line.erase(remove_if(line.begin(), line.end(), ::isspace), line.end());
        if (!line.empty()) words.insert(line);
    }
    return words;
}

// Détection des messages suspects
vector<Metadata> MetaExtractor::detectSuspiciousMessages(const vector<Metadata>& metas, const set<string>& suspiciousWords) {
    vector<Metadata> flagged;
    for (const auto& m : metas) {
        for (const auto& word : suspiciousWords) {
            if (m.message.find(word) != string::npos) {
                flagged.push_back(m);
                break;
            }
        }
    }
    return flagged;
}

// Affichage des messages suspects
void MetaExtractor::printSuspiciousMessages(const vector<Metadata>& flagged) {
    if (flagged.empty()) {
        cout << "[+] Aucun message suspect détecté.\n";
        return;
    }
    cout << "[!] Messages suspects détectés :\n";
    printAll(flagged);
}
