#include "analysis/detector.h"
#include "analysis/suspicious_conversation.h"
#include "core/message.h"
#include "core/conversation.h"
#include "core/suspicious_words.h"
#include "io/exporter.h"
#include "io/parser.h"
#include "io/logger.h"
#include "io/report.h"
#include "utils/file_utils.h"
#include "utils/wstring_utils.h"

#include <iostream>
#include <string>
#include <windows.h>
#include <cstdlib>
#include <shobjidl.h>
#include <filesystem>
#include <thread>
#include <chrono>
#include <map>
#include <iomanip>
#include <sstream>
#include <ctime>

inline void LogEvent(const std::wstring& msg) {
    Logger::instance().log(msg);
}

void printMenu(int& step, int& choice) {
    int originalStep = step;
    int maxStep = 5;

    std::system("cls");
    int maxPossibleChoice = 0;
    std::cout << "                         " << step << "/" << maxStep << "\n";
    std::cout << "=======================================================\n";
    std::cout << "        WhatsApp Detection Suspecious Messages\n";
    std::cout << "=======================================================\n";
    if (step > 1) std::cout << "[-1] Revenir en arriere\n";
    std::cout << " [0] Quitter\n";
    switch (step) {
    case 1:
        maxPossibleChoice = 2;
        std::cout << " [1] Choisir le chemin vers le dossier exporte\n";
        std::cout << " [2] Tutoriel pour extraire les messages Whatsapp en anglais\n";
        break;
    case 2:
        maxPossibleChoice = 3;
        std::cout << " [1] Scanner les mots suspets en anglais\n";
        std::cout << " [2] Scanner les mots suspets en français\n";
        std::cout << " [3] Scanner les mots suspets en anglais et en français\n";
        break;
    case 3:
        maxPossibleChoice = 5;
        std::cout << " [1] Scanner que la conversation\n";
        std::cout << " [2] Scanner que les liens\n";
        std::cout << " [3] Scanner que les meta-donnes (medias et documents)\n";
        std::cout << " [4] Scanner que les documents (txt, pdf)\n";
        std::cout << " [5] Faire un scan totale\n";
        break;
    case 4:
        maxPossibleChoice = 4;
        std::cout << " [1] Exporter tous les messages vers CSV\n";
        std::cout << " [2] Exporter seulement les messages suspects vers CSV\n";
        std::cout << " [3] Sauvgarder les logs\n";
        std::cout << " [4] Sauvgarder le rapport de scan\n";
        break;
    case 5:
        maxPossibleChoice = 2;
        std::cout << " Choisir la langue du rapport:\n";
        std::cout << " [1] Anglais\n";
        std::cout << " [2] Français\n";
        break;
    }
    std::cout << "=======================================================\n";
    std::cout << "Votre choix : ";
    std::cin >> choice;
    Logger::instance().log(L"Choix utilisateur au step " + std::to_wstring(originalStep) + L": " + std::to_wstring(choice));

    if (choice == 0) {
        step = 0;
    }
    else if (choice == -1 && step > 1) {
        step--;
    }
    else if (choice < 0 || choice > maxPossibleChoice) {
        std::cout << "Choix invalide. Ressayez." << std::endl;
        Logger::instance().log(L"Choix invalide saisi: " + std::to_wstring(choice) + L" au step " + std::to_wstring(originalStep));
        std::system("pause");
        printMenu(step, choice);
        return;
    }
    else if (choice > 0 && choice <= maxPossibleChoice && step < maxStep) {
        bool shouldAdvance = true;
        if (step == 1 && choice == 2) shouldAdvance = false;      // ne pas avancer pour le tutoriel
        if (step == 4 && choice != 4) shouldAdvance = false;       // avancer à l'étape 5 seulement si [4] Rapport
        if (shouldAdvance) step++;
    }

    if (step != originalStep) {
        Logger::instance().log(L"Changement de step: " + std::to_wstring(originalStep) + L" -> " + std::to_wstring(step));
    }
}

std::wstring SelectFolderDialog() {
    std::wstring folderPath;
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    if (SUCCEEDED(hr)) {
        IFileDialog* pFileDialog = nullptr;
        hr = CoCreateInstance(CLSID_FileOpenDialog, NULL, CLSCTX_ALL, IID_IFileDialog, reinterpret_cast<void**>(&pFileDialog));
        if (SUCCEEDED(hr)) {
            DWORD dwOptions;
            pFileDialog->GetOptions(&dwOptions);
            pFileDialog->SetOptions(dwOptions | FOS_PICKFOLDERS | FOS_PATHMUSTEXIST);
            hr = pFileDialog->Show(NULL);
            if (SUCCEEDED(hr)) {
                IShellItem* pItem = nullptr;
                hr = pFileDialog->GetResult(&pItem);
                if (SUCCEEDED(hr)) {
                    PWSTR pszFilePath = nullptr;
                    hr = pItem->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
                    if (SUCCEEDED(hr)) {
                        folderPath = pszFilePath;
                        CoTaskMemFree(pszFilePath);
                    }
                    pItem->Release();
                }
            }
            pFileDialog->Release();
        }
        CoUninitialize();
    }
    Logger::instance().log(folderPath.empty() ? L"Aucun dossier sélectionné." : L"Dossier sélectionné: " + folderPath);
    return folderPath;
}

std::wstring FindMatchingTextFile(const std::wstring& folderPath) {
    std::filesystem::path path(folderPath);
    std::wstring folderName = path.filename().wstring();
    std::wstring textFilePath = folderPath + L"\\" + folderName + L".txt";
    bool exists = std::filesystem::exists(textFilePath);
    Logger::instance().log(exists ? L"Fichier texte correspondant trouvé: " + textFilePath
        : L"Aucun fichier texte correspondant trouvé pour: " + folderName);
    if (exists) return textFilePath;
    return L"";
}

// NOUVEAU: création dossier Analyse après chaque scan
void CreateAnalysisOutputFolder(const std::wstring& selectedFolderPath,
    std::wstring& outputFolder,
    std::wstring& messagesAllFile,
    std::wstring& messagesSuspFile,
    std::wstring& reportFile,
    std::wstring& logFile,
    std::wstring& timestampPrefix) {
    outputFolder.clear();
    messagesAllFile.clear();
    messagesSuspFile.clear();
    reportFile.clear();
    logFile.clear();
    timestampPrefix.clear();

    std::wstring base = selectedFolderPath + L"\\Analyse";
    std::filesystem::path candidate(base);
    int idx = 2;
    while (std::filesystem::exists(candidate)) {
        candidate = std::filesystem::path(base + L"_" + std::to_wstring(idx++));
    }
    std::error_code ec;
    std::filesystem::create_directories(candidate, ec);
    if (ec) {
        LogEvent(L"Erreur création dossier Analyse: " + candidate.wstring() + L" code=" + std::to_wstring(ec.value()));
    }
    else {
        LogEvent(L"Dossier Analyse créé: " + candidate.wstring());
    }
    outputFolder = candidate.wstring();

    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::wstringstream ts;
    ts << std::put_time(&tm, L"%Y%m%d_%H%M%S") << L"_";
    timestampPrefix = ts.str();

    messagesAllFile = outputFolder + L"\\" + timestampPrefix + L"messages_complets.csv";
    messagesSuspFile = outputFolder + L"\\" + timestampPrefix + L"messages_suspects.csv";
    reportFile = outputFolder + L"\\" + timestampPrefix + L"rapport.txt";
    logFile = outputFolder + L"\\" + timestampPrefix + L"journal.txt";

    std::wcout << L"\nDossier d'analyse créé : " << outputFolder << L"\n";
    std::wcout << L"Préfixe utilisé : " << timestampPrefix << L"\n";
    LogEvent(L"Fichiers cible: " + messagesAllFile + L" | " + messagesSuspFile + L" | " + reportFile + L" | " + logFile);
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    // message de bienvenue
    char welcomeMessage[] = "Ceci est un project academic open-source\nVous pouvez trouver le code source sur ce lien:\nhttps://github.com/aymane2004-2004/detection_suspecious_messages_in_whatsapp\n";
    for (char c : welcomeMessage) {
        if (c == '\n')
            std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    std::system("pause");
    std::system("cls");

    LogEvent(L"Application démarrée.");
    int step = 1;
    int choice = 0;

    std::wstring selectedFolderPath = L"empty";
    std::wstring matchingTextFilePath = L"empty";

    std::wstring outputFolder;
    std::wstring messagesAllFile;
    std::wstring messagesSuspFile;
    std::wstring reportFile;
    std::wstring logFile;
    std::wstring timestampPrefix;

    Conversation conversation;
    enum Langage { ENGLISH = 1, FRENCH = 2, BOTH_LANGAGE = 3 };
    enum Content { CONVERSATION = 1, LINK = 2, METADATA = 3, DOCUMENT = 4, ALL_CONTENT = 5 };
    Langage langageToScan = Langage::ENGLISH;
    Content contentToScan = Content::CONVERSATION;

    Analysis::SuspiciousConversation suspiciousConversation;
    Analysis::DetectionEngine engine;
    Analysis::DetectionLanguage Lang =
        (langageToScan == Langage::ENGLISH) ? Analysis::DetectionLanguage::EN :
        (langageToScan == Langage::FRENCH) ? Analysis::DetectionLanguage::FR :
        Analysis::DetectionLanguage::BOTH;

    std::chrono::steady_clock::time_point startTime;
    std::chrono::steady_clock::time_point endTime;
    long long ms = 0;
    Report::ReportGenerationOptions reportOpts;

    do {
        switch (step) {
        case 0:
            LogEvent(L"Application terminée (demande de sortie).");
            return 0;
        case 1:
            printMenu(step, choice);
            if (choice == 1) {
                LogEvent(L"Réinitialisation des structures pour nouvel import.");
                conversation.clear();
                suspiciousConversation.clear();
                engine.reset();
                outputFolder.clear();
                messagesAllFile.clear();
                messagesSuspFile.clear();
                reportFile.clear();
                logFile.clear();
                timestampPrefix.clear();

                std::wcout << L"Une fenêtre s'est ouverte, sélectionnez le dossier exporté depuis WhatsApp.\n\n";
                LogEvent(L"Ouverture de la boîte de dialogue de sélection de dossier.");
                selectedFolderPath = SelectFolderDialog();
                if (selectedFolderPath.empty()) {
                    std::wcout << L"Aucun dossier sélectionné. Ressayez.\n";
                    LogEvent(L"Echec: aucun dossier sélectionné.");
                    std::system("pause");
                    step--;
                    break;
                }

                std::filesystem::path folderPath(selectedFolderPath);
                std::wstring folderName = folderPath.filename().wstring();
                if (folderName.rfind(L"WhatsApp Chat with", 0) != 0) {
                    std::wcout << L"Erreur : Le dossier sélectionné n'est pas en anglais ou est invalide.\n";
                    std::wcout << L"Le nom du dossier doit commencer par \"WhatsApp Chat with\".\n";
                    LogEvent(L"Echec: nom de dossier invalide -> " + folderName);
                    std::system("pause");
                    step--;
                    break;
                }

                matchingTextFilePath = FindMatchingTextFile(selectedFolderPath);
                if (matchingTextFilePath.empty()) {
                    std::wcout << L"Erreur : Aucun fichier texte portant le même nom que le dossier n'a été trouvé.\n";
                    LogEvent(L"Echec: fichier texte principal introuvable.");
                    std::system("pause");
                    step--;
                    break;
                }

                std::system("cls");
                std::wcout << L"Dossier sélectionné : " << selectedFolderPath << L"\n";
                std::wcout << L"Fichier texte trouvé : " << matchingTextFilePath << L"\n\n";

                LogEvent(L"Parsing du fichier WhatsApp: " + matchingTextFilePath);
                bool parseSuccess = Parser::parseWhatsAppChat(matchingTextFilePath, conversation);
                if (!parseSuccess) {
                    std::wcout << L"Erreur : Impossible de parser le fichier de conversation WhatsApp.\n";
                    LogEvent(L"Echec parsing conversation.");
                    std::system("pause");
                    step--;
                    break;
                }

                LogEvent(L"Conversation chargée. Total messages: " + std::to_wstring(conversation.getMessages().size()));
                std::wcout << L"Conversation chargée avec succès.\n";
                std::map<MessageType, int> messageCounts = conversation.countMessagesByType();
                std::wcout << L"Nombre de messages : " << conversation.getMessages().size() << L"\n";
                std::wcout << L"Répartition des messages par type :\n";
                std::wcout << L"  - Messages texte      : " << std::setw(5) << messageCounts[MessageType::TEXT] << L"\n";
                std::wcout << L"  - Liens               : " << std::setw(5) << messageCounts[MessageType::LINK] << L"\n";
                std::wcout << L"  - Messages avec liens : " << std::setw(5) << messageCounts[MessageType::TEXT_LINK] << L"\n";
                std::wcout << L"  - Médias omis         : " << std::setw(5) << messageCounts[MessageType::MEDIA_OMITTED] << L"\n";
                std::wcout << L"  - Images              : " << std::setw(5) << messageCounts[MessageType::IMAGE] << L"\n";
                std::wcout << L"  - Vidéos              : " << std::setw(5) << messageCounts[MessageType::VIDEO] << L"\n";
                std::wcout << L"  - Audios              : " << std::setw(5) << messageCounts[MessageType::AUDIO] << L"\n";
                std::wcout << L"  - Documents           : " << std::setw(5) << messageCounts[MessageType::DOCUMENT] << L"\n";
                std::wcout << L"  - Types inconnus      : " << std::setw(5) << messageCounts[MessageType::UNKNOWN] << L"\n\n";
                LogEvent(L"Statistiques messages enregistrées.");
                std::this_thread::sleep_for(std::chrono::seconds(1));
                std::system("pause");
            }
            else if (choice == 2) {
                LogEvent(L"Affichage tutoriel export WhatsApp demandé.");
                std::system("cls");
                std::cout << "\nTutoriel pour extraire les messages WhatsApp en anglais :\n";
                std::cout << " 1. Ouvrez WhatsApp sur votre téléphone.\n";
                std::cout << " 2. Allez dans Paramètres > Langue de l'application.\n";
                std::cout << " 3. Choisissez English (Important).\n";
                std::cout << " 4. Revenez à l'accueil.\n";
                std::cout << " 5. Entrez dans une conversation que vous voulez exporter.\n";
                std::cout << " 6. Cliquez sur les trois points en haut à droite > More > Export chat.\n";
                std::cout << " 7. Sélectionnez 'Without media' ou 'Include media'.\n";
                std::cout << " 8. Envoyez le fichier zip sur votre ordinateur.\n";
                std::cout << " 9. Decompresser le fichier zip.\n";
                std::cout << "10. Selectioner le dossier dans cette l'application.\n";
                std::cout << "Pour plus de détails :\n";
                std::cout << "https://github.com/aymane2004-2004/detection_suspecious_messages_in_whatsapp\n";
                LogEvent(L"Fin affichage tutoriel (sortie application).");
                std::system("pause");
                return 0;
            }
            break;
        case 2:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            langageToScan = (Langage)choice;
            Lang =
                (langageToScan == Langage::ENGLISH) ? Analysis::DetectionLanguage::EN :
                (langageToScan == Langage::FRENCH) ? Analysis::DetectionLanguage::FR :
                Analysis::DetectionLanguage::BOTH;
            LogEvent(L"Sélection langue scan: " + std::to_wstring(choice));
            std::wcout << L"\n\n";
            break;
        case 3:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            contentToScan = (Content)choice;
            LogEvent(L"Début détection. Type de contenu: " + std::to_wstring(choice));
            std::system("cls");
            suspiciousConversation.clear();
            engine.reset();
            LogEvent(L"Etat moteur réinitialisé.");
            std::wcout << L"Détection en cours...\n";
            switch (contentToScan) {
            case Content::CONVERSATION:
                startTime = std::chrono::steady_clock::now();
                engine.detectSuspiciousWords(conversation, suspiciousConversation, Lang);
                endTime = std::chrono::steady_clock::now();
                ms = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
                LogEvent(L"detectSuspiciousWords exécuté.");
                break;
            case Content::LINK:
                startTime = std::chrono::steady_clock::now();
                engine.detectSuspiciousLinks(conversation, suspiciousConversation);
                endTime = std::chrono::steady_clock::now();
                ms = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
                LogEvent(L"detectSuspiciousLinks exécuté.");
                break;
            case Content::METADATA:
                startTime = std::chrono::steady_clock::now();
                engine.detectSuspiciousFilenames(conversation, suspiciousConversation, Lang);
                endTime = std::chrono::steady_clock::now();
                ms = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
                LogEvent(L"detectSuspiciousFilenames exécuté.");
                break;
            case Content::DOCUMENT:
                startTime = std::chrono::steady_clock::now();
                engine.detectSuspiciousWordsInTextFiles(conversation, suspiciousConversation, selectedFolderPath, Lang);
                endTime = std::chrono::steady_clock::now();
                ms = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
                LogEvent(L"detectSuspiciousWordsInTextFiles exécuté.");
                break;
            case Content::ALL_CONTENT:
                startTime = std::chrono::steady_clock::now();
                engine.detectAll(conversation, suspiciousConversation, selectedFolderPath, Lang, true);
                endTime = std::chrono::steady_clock::now();
                ms = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
                LogEvent(L"detectAll exécuté.");
                break;
            }
            std::wcout << L"\nDétection terminée.\n";
            LogEvent(L"Détection terminée en " + std::to_wstring(ms) + L" ms. Nombre éléments suspects: " +
                std::to_wstring(suspiciousConversation.size()));

            // Création du dossier Analyse et des fichiers après le scan
            if (selectedFolderPath != L"empty") {
                CreateAnalysisOutputFolder(selectedFolderPath,
                    outputFolder,
                    messagesAllFile,
                    messagesSuspFile,
                    reportFile,
                    logFile,
                    timestampPrefix);
            }
            else {
                LogEvent(L"ATTENTION: selectedFolderPath vide lors de la tentative de création du dossier d'analyse.");
            }

            std::system("pause");
            break;
        case 4:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            if (choice == 1) {
                if (outputFolder.empty()) {
                    std::wcout << L"Erreur: aucun scan récent (dossier d'analyse absent). Relancez un scan (étape 3).\n";
                    LogEvent(L"Export tous messages: outputFolder vide.");
                    std::system("pause");
                    break;
                }
                LogEvent(L"Export CSV (tous les messages) -> " + messagesAllFile);
                {
                    bool exportSuccess = Exporter::exportToCSV(conversation, messagesAllFile);
                    if (exportSuccess) {
                        std::wcout << L"Messages exportés : " << messagesAllFile << L"\n";
                        LogEvent(L"Succès export tous messages.");
                    }
                    else {
                        std::wcout << L"Erreur export messages.\n";
                        LogEvent(L"Echec export tous messages.");
                    }
                }
                std::system("pause");
            }
            else if (choice == 2) {
                if (outputFolder.empty()) {
                    std::wcout << L"Erreur: aucun scan récent (dossier d'analyse absent). Relancez un scan (étape 3).\n";
                    LogEvent(L"Export suspects: outputFolder vide.");
                    std::system("pause");
                    break;
                }
                LogEvent(L"Export CSV (messages suspects) -> " + messagesSuspFile);
                {
                    bool exportSuccess = Exporter::exportSuspiciousToCSV(suspiciousConversation, messagesSuspFile);
                    if (exportSuccess) {
                        std::wcout << L"Messages suspects exportés : " << messagesSuspFile << L"\n";
                        LogEvent(L"Succès export messages suspects.");
                    }
                    else {
                        std::wcout << L"Erreur export messages suspects.\n";
                        LogEvent(L"Echec export messages suspects.");
                    }
                }
                std::system("pause");
            }
            else if (choice == 3) {
                if (outputFolder.empty()) {
                    std::wcout << L"Erreur: aucun scan récent (dossier d'analyse absent). Relancez un scan (étape 3).\n";
                    LogEvent(L"Sauvegarde log impossible: outputFolder vide.");
                    std::system("pause");
                    break;
                }
                std::wstring target = logFile.empty() ? (outputFolder + L"\\journal.txt") : logFile;
                Logger::instance().setOutputFile(target);
                bool ok = Logger::instance().flush();
                if (ok) {
                    std::wcout << L"Journal sauvegardé : " << target << L"\n";
                    LogEvent(L"(Post-flush) Journal écrit.");
                }
                else {
                    std::wcout << L"Erreur: impossible de sauvegarder le journal.\n";
                    LogEvent(L"Echec sauvegarde journal -> " + target);
                }
                std::system("pause");
            }
            else if (choice == 4) {
                // Aller à l'étape 5 pour choisir la langue du rapport (ne génère plus ici)
                if (selectedFolderPath == L"empty" || outputFolder.empty()) {
                    std::wcout << L"Erreur: aucune conversation scannée récemment.\n";
                    LogEvent(L"Rapport: prerequisites manquants.");
                    // S'assurer de rester à l'étape 4 en cas d'erreur
                    step = 4;
                    std::system("pause");
                    break;
                }
                LogEvent(L"Demande de rapport: passage à l'étape 5 pour choix de la langue.");
                // Pas de pause ici, on enchaîne directement vers l'étape 5 au prochain tour
            }
            break;
        case 5:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            if (choice == 1 || choice == 2) {
                if (selectedFolderPath == L"empty" || outputFolder.empty()) {
                    std::wcout << L"Erreur: aucune conversation scannée récemment.\n";
                    LogEvent(L"Rapport: prerequisites manquants (étape 5).");
                    std::system("pause");
                    step = 4;
                    break;
                }
                reportOpts.totalMessagesInConversation = conversation.getMessages().size();
                reportOpts.maxExamplesPerCategory = 5;
                reportOpts.includePerEntrySection = true;
                reportOpts.includeTopEntries = true;
                reportOpts.topEntriesCount = 15;
                reportOpts.language = (choice == 1) ? Report::Language::EN : Report::Language::FR;

                LogEvent(L"Génération rapport (" + std::wstring((choice == 1) ? L"EN" : L"FR") + L") -> " + reportFile);
                bool ok = Report::generateReport(suspiciousConversation, reportFile, reportOpts);
                if (ok) {
                    std::wcout << L"Rapport généré : " << reportFile << L"\n";
                    if (suspiciousConversation.size() == 0) {
                        std::wcout << L"(Aucun élément suspect détecté.)\n";
                    }
                    LogEvent(L"Rapport généré avec succès.");
                }
                else {
                    std::wcout << L"Erreur génération rapport.\n";
                    LogEvent(L"Echec génération rapport.");
                }
                std::system("pause");
                // Retour à l'étape 4 après génération
                step = 4;
            }
            break;
        default:
            std::wcout << "choix du step invalide. Arrêt du programme." << std::endl;
            LogEvent(L"Etat interne invalide: step=" + std::to_wstring(step));
            std::this_thread::sleep_for(std::chrono::seconds(2));
            step = 0;
            break;
        }
    } while (step);

    LogEvent(L"Fin normale du programme.");
    return 0;
}