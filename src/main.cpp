#include <iostream>
#include "metaextractor.hpp"
#include <string>
#include <set>
#include <filesystem>  // C++17

using namespace std;
namespace fs = std::filesystem;

void printMenu() {
    cout << "===========================================\n";
    cout << "      WhatsApp Metadata Analyzer\n";
    cout << "===========================================\n";
    cout << "1. Extraire et afficher tous les messages\n";
    cout << "2. Détecter et afficher les messages suspects\n";
    cout << "3. Exporter tous les messages vers CSV\n";
    cout << "4. Exporter seulement les messages suspects vers CSV\n";
    cout << "0. Quitter\n";
    cout << "===========================================\n";
    cout << "Votre choix : ";
}

int main() {
    MetaExtractor extractor;
    string whatsappFile;
    vector<Metadata> metas;
    set<string> suspiciousWords;

    cout << "Entrez le chemin du fichier WhatsApp exporté : ";
    getline(cin, whatsappFile);

    metas = extractor.extract("C:\\Users\\hp7\\Desktop\\detection_suspecious_messages_on_whatsapp\\data\\chat.txt");
    if (metas.empty()) {
        cerr << "[!] Aucun message n'a été extrait. Vérifiez le fichier.\n";
        return 1;
    }

    string suspiciousFile = "C:\\Users\\hp7\\Desktop\\detection_suspecious_messages_on_whatsapp\\mots suspects\\mots.txt";
    if (!fs::exists(suspiciousFile)) {
        cerr << "[!] Le fichier des mots suspects est introuvable : " << suspiciousFile << endl;
        return 1;
    }

    suspiciousWords = extractor.loadSuspiciousWords(suspiciousFile);
    if (suspiciousWords.empty()) {
        cerr << "[!] Aucun mot suspect chargé. La détection ne fonctionnera pas.\n";
    } else {
        cout << "[+] " << suspiciousWords.size() << " mots suspects chargés depuis " << suspiciousFile << "\n";
    }

    if (!fs::exists("outputs")) fs::create_directory("outputs");
    if (!fs::exists("logs")) fs::create_directory("logs");

    int choice;
    do {
        printMenu();
        cin >> choice;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                cout << "\n[+] Affichage de tous les messages :\n";
                extractor.printAll(metas);
                break;

            case 2: {
                cout << "\n[!] Détection des messages suspects :\n";
                auto flagged = extractor.detectSuspiciousMessages(metas, suspiciousWords);
                extractor.printSuspiciousMessages(flagged);
                break;
            }

            case 3: {
                string outputFile = "outputs/all_messages.csv";
                extractor.exportToCSV(metas, outputFile);
                extractor.logExport(metas, outputFile);
                break;
            }

            case 4: {
                string outputFile = "outputs/suspicious_messages.csv";
                auto flagged = extractor.detectSuspiciousMessages(metas, suspiciousWords);
                extractor.exportToCSV(flagged, outputFile);
                extractor.logExport(flagged, outputFile);
                break;
            }

            case 0:
                cout << "[+] Au revoir !\n";
                break;

            default:
                cout << "[!] Choix invalide. Réessayez.\n";
                break;
        }
        cout << endl;
    } while (choice != 0);

    return 0;
}
