#include <iostream>
#include "metaextractor.h"
#include <string>
#include <set>
#include <vector>
#include <filesystem>  // C++17
#include <limits>
#define NOMINMAX
#include <windows.h>

void printMenu() {
    std::cout << "===========================================\n";
    std::cout << "      WhatsApp Metadata Analyzer\n";
    std::cout << "===========================================\n";
    std::cout << "1. Extraire et afficher tous les messages\n";
    std::cout << "2. Détecter et afficher les messages suspects\n";
    std::cout << "3. Exporter tous les messages vers CSV\n";
    std::cout << "4. Exporter seulement les messages suspects vers CSV\n";
    std::cout << "0. Quitter\n";
    std::cout << "===========================================\n";
    std::cout << "Votre choix : ";
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

    MetaExtractor extractor;
    std::string whatsappFile;
    std::vector<Metadata> metas;
    std::set<std::string> suspiciousWords;

    std::cout << "Entrez le chemin du fichier WhatsApp exporte : \n";
    std::getline(std::cin, whatsappFile);

    metas = extractor.extract("C:\\Users\\hp7\\Desktop\\detection_suspecious_messages_in_whatsapp\\data\\chat.txt");
    if (metas.empty()) {
        std::cerr << "[!] Aucun message n'a été extrait. Vérifiez le fichier.\n";
        return 1;
    }

    std::string suspiciousFile = "C:\\Users\\hp7\\Desktop\\detection_suspecious_messages_in_whatsapp\\mots suspects\\mots.txt";
    if (!std::filesystem::exists(suspiciousFile)) {
        std::cerr << "[!] Le fichier des mots suspects est introuvable : " << suspiciousFile << std::endl;
        return 1;
    }

    suspiciousWords = extractor.loadSuspiciousWords(suspiciousFile);
    if (suspiciousWords.empty()) {
        std::cerr << "[!] Aucun mot suspect chargé. La détection ne fonctionnera pas.\n";
    }
    else {
        std::cout << "[+] " << suspiciousWords.size() << " mots suspects chargés depuis " << suspiciousFile << "\n";
    }

    if (!std::filesystem::exists("outputs")) std::filesystem::create_directory("outputs");
    if (!std::filesystem::exists("logs")) std::filesystem::create_directory("logs");

    int choice;
    do {
        printMenu();
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
        case 1:
            std::cout << "\n[+] Affichage de tous les messages :\n";
            extractor.printAll(metas);
            break;

        case 2: {
            std::cout << "\n[!] Détection des messages suspects :\n";
            auto flagged = extractor.detectSuspiciousMessages(metas, suspiciousWords);
            extractor.printSuspiciousMessages(flagged);
            break;
        }

        case 3: {
            std::string outputFile = "outputs/all_messages.csv";
            extractor.exportToCSV(metas, outputFile);
            extractor.logExport(metas, outputFile);
            break;
        }

        case 4: {
            std::string outputFile = "outputs/suspicious_messages.csv";
            auto flagged = extractor.detectSuspiciousMessages(metas, suspiciousWords);
            extractor.exportToCSV(flagged, outputFile);
            extractor.logExport(flagged, outputFile);
            break;
        }

        case 0:
            std::cout << "[+] Au revoir !\n";
            break;

        default:
            std::cout << "[!] Choix invalide. Réessayez.\n";
            break;
        }
        std::cout << std::endl;
    } while (choice != 0);

    return 0;
}
