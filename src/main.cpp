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
#include <shobjidl.h> // For IFileDialog
#include <filesystem>  // Ensure this is included before usage
#include <thread>   // pour std::this_thread::sleep_for
#include <chrono>   // pour std::chrono::seconds, milliseconds, etc.
#include <map>
#include <iomanip>  // For std::setw


void printMenu(int& step, int& choice) {
    std::system("cls");
	int maxPossibleChoice = 0;
	std::cout << "                         " << step << "/4\n";
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
    }
    std::cout << "=======================================================\n";
    std::cout << "Votre choix : ";
    std::cin >> choice;
    if (choice == 0) step = 0;
    else if (choice == -1 && step > 1) { step--;}
    else if (choice < 0 || choice > maxPossibleChoice) {
		std::cout << "Choix invalide. Ressayez." << std::endl;
		std::system("pause");
		printMenu(step, choice);
    }
	else if (choice > 0 && choice <= maxPossibleChoice && step < 4) 
        if (step != 1 || choice !=2) step++;
}

// Function to open a folder selection dialog and return the selected path as std::wstring
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
    return folderPath;
}

// Function to find a text file with the same name as the folder
std::wstring FindMatchingTextFile(const std::wstring& folderPath) {
    std::filesystem::path path(folderPath);
    std::wstring folderName = path.filename().wstring();
    
    // Look for file with the same name as the folder but with .txt extension
    std::wstring textFilePath = folderPath + L"\\" + folderName + L".txt";
    
    if (std::filesystem::exists(textFilePath)) {
        return textFilePath;
    }
    
    return L""; // Return empty string if no matching file found
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
	// message de bienvenue
    /*char welcomeMessage[] = "Ceci est un project academic open-source\nVous pouvez trouver le code source sur ce lien:\ngithub.com\n";
    for (char c : welcomeMessage) {
        if (c == '\n')
            std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << c << std::flush;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
    std::system("pause");
	std::system("cls");*/
    
    // variable pour les etapes
    int step = 1;
    int choice = 0;
    // parametres du scan
    std::wstring selectedFolderPath = L"empty"; // Variable to store the selected folder path
    std::wstring matchingTextFilePath = L"empty"; // Variable to store the path to the text file with the same name
    Conversation conversation;
    enum Langage { ENGLISH = 1, FRENCH = 2, BOTH_LANGAGE = 3 };
    enum Content { CONVERSATION = 1, LINK = 2, METADATA = 3, DOCUMENT = 4, ALL_CONTENT = 5 };
    Langage langageToScan = Langage::ENGLISH;
    Content contentToScan = Content::CONVERSATION;
	// detection results
	Analysis::SuspiciousConversation suspiciousConversation;
    Analysis::DetectionEngine engine;
    Analysis::DetectionLanguage Lang =
        (langageToScan == Langage::ENGLISH) ? Analysis::DetectionLanguage::EN :
        (langageToScan == Langage::FRENCH) ? Analysis::DetectionLanguage::FR :
        Analysis::DetectionLanguage::BOTH;
	

    do {
        switch (step) {
        case 0:
			return 0;
		//step 1
        case 1:
			printMenu(step, choice);
            if (choice == 1) {
                // Réinitialiser avant un nouvel import
                conversation.clear();
                suspiciousConversation.clear();
                engine.reset();

                std::wcout << L"Une fenêtre s'est ouverte, sélectionnez le dossier exporté depuis WhatsApp.\n\n";

                // Open folder selection dialog and store the path
                selectedFolderPath = SelectFolderDialog();
                if (selectedFolderPath.empty()) {
                    std::wcout << L"Aucun dossier sélectionné. Ressayez.\n";
                    std::system("pause");
                    step--;
                    break;
                }

                // Check if the folder name starts with "WhatsApp Chat with"
                std::filesystem::path folderPath(selectedFolderPath);
                std::wstring folderName = folderPath.filename().wstring();
                if (folderName.rfind(L"WhatsApp Chat with", 0) != 0) {
                    std::wcout << L"Erreur : Le dossier sélectionné n'est pas en anglais ou est invalide.\n";
                    std::wcout << L"Le nom du dossier doit commencer par \"WhatsApp Chat with\".\n";
                    std::system("pause");
                    step--;
                    break;
                }

                // Find a text file with the same name as the folder
                matchingTextFilePath = FindMatchingTextFile(selectedFolderPath);
                if (matchingTextFilePath.empty()) {
                    std::wcout << L"Erreur : Aucun fichier texte portant le même nom que le dossier n'a été trouvé.\n";
                    std::system("pause");
                    step--;
                    break;
                }

                std::system("cls");
                std::wcout << L"Dossier sélectionné : " << selectedFolderPath << L"\n";
                std::wcout << L"Fichier texte trouvé : " << matchingTextFilePath << L"\n\n";

                // Parse the WhatsApp chat file into a Conversation object
                bool parseSuccess = Parser::parseWhatsAppChat(matchingTextFilePath, conversation);

                if (!parseSuccess) {
                    std::wcout << L"Erreur : Impossible de parser le fichier de conversation WhatsApp.\n";
                    std::system("pause");
                    step--;
                    break;
                }

                // Display basic conversation stats
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

                std::this_thread::sleep_for(std::chrono::seconds(1));
                std::system("pause");

            }
            else if (choice == 2) {
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
                std::cout << "youtube.com\n";
                std::system("pause");
                return 0;
            }


			break;
        //step 2
        case 2:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            langageToScan = (Langage)choice;
            std::wcout << L"\n\n";
            break;
		//step 3
		case 3:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            contentToScan = (Content)choice;
            std::system("cls");

            
            // Réinitialiser résultats + état moteur
            suspiciousConversation.clear();
            engine.reset();

            std::wcout << L"Détection en cours...\n";
            switch (contentToScan) {
            case Content::CONVERSATION:
                engine.detectSuspiciousWords(conversation, suspiciousConversation, Lang);
                break;
            case Content::LINK:
				engine.detectSuspiciousLinks(conversation, suspiciousConversation);
                break;
            case Content::METADATA:
                engine.detectSuspiciousFilenames(conversation, suspiciousConversation, Lang);
                break;
            case Content::DOCUMENT:
                engine.detectSuspiciousWordsInTextFiles(conversation, suspiciousConversation,
                    selectedFolderPath, Lang);
                break;
            case Content::ALL_CONTENT:
                engine.detectAll(conversation, suspiciousConversation, selectedFolderPath, Lang, true);
                break;
            }

			std::wcout << L"Détection terminée.\n";
			std::system("pause");

            

			break;
        //step 4
        case 4:
            printMenu(step, choice);
            if (choice == -1 && step > 1) { break; }
            if (choice == 1) {
                // Exporter tous les messages vers CSV
                std::wstring csvPath = selectedFolderPath + L"\\exported_messages.csv";
                bool exportSuccess = Exporter::exportToCSV(conversation, csvPath);
                if (exportSuccess) {
                    std::wcout << L"Messages exportés avec succès vers : " << csvPath << L"\n";
                }
                else {
                    std::wcout << L"Erreur lors de l'exportation des messages.\n";
                }
                std::this_thread::sleep_for(std::chrono::seconds(2));
				std::system("pause");
            }
            else if (choice == 2) {
                // Exporter seulement les messages suspects vers CSV
                std::wstring csvPath = selectedFolderPath + L"\\suspicious_messages.csv";
                bool exportSuccess = Exporter::exportSuspiciousToCSV(suspiciousConversation, csvPath);
                if (exportSuccess) {
                    std::wcout << L"Messages suspects exportés avec succès vers : " << csvPath << L"\n";
                }
                else {
                    std::wcout << L"Erreur lors de l'exportation des messages suspects.\n";
                }
                std::this_thread::sleep_for(std::chrono::seconds(2));
                std::system("pause");
            }
            break;
        default:
			std::wcout << "choix du step invalide. Arrêt du programme." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
            step = 0;
			break;
        }
    } while (step);

    return 0;
}
