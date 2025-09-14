#include "analysis/detector.h"
#include "core/message.h"
#include "core/conversation.h"
#include "core/suspicious_words.h"
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


void printMenu(int menuNumber, int& choice, int erase) {
    if (erase) {
        std::system("cls");
	}
	int maxPossibleChoice = 0;
    std::cout << "=======================================================\n";
    std::cout << "        WhatsApp Detection Suspecious Messages\n";
    std::cout << "=======================================================\n";
    switch (menuNumber) {
    case 1:
        maxPossibleChoice = 2;
        std::cout << "[1] Choisir le chemin vers le dossier exporte\n";
        std::cout << "[2] Tutoriel pour extraire les messages Whatsapp en anglais\n";
        break;
    case 2:
        maxPossibleChoice = 3;
        std::cout << "[1] Scanner les mots suspets en anglais\n";
        std::cout << "[2] Scanner les mots suspets en français\n";
        std::cout << "[3] Scanner les mots suspets en anglais et en français\n";
        break;
    case 3:
        maxPossibleChoice = 3;
        std::cout << "[1] Scanner que la conversation\n";
        std::cout << "[2] Scanner que les media (txt,pdf etc)\n";
        std::cout << "[3] Scanner la conversation et les media\n";
        break;
    case 4:
        maxPossibleChoice = 4;
        std::cout << "[1] Exporter tous les messages vers CSV\n";
        std::cout << "[2] Exporter seulement les messages suspects vers CSV\n";
        std::cout << "[3] Sauvgarder les logs\n";
        std::cout << "[4] Sauvgarder le rapport de scan\n";
        break;
    }
    std::cout << "[0] Quitter\n";
    std::cout << "=======================================================\n";
    std::cout << "Votre choix : ";
    std::cin >> choice;
    if (choice < 0 || choice > maxPossibleChoice) {
        std::system("cls");
		std::cout << "Choix invalide. Ressayez." << std::endl;
		printMenu(menuNumber, choice, 0);
    }
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

    int choice;
    int langageToScan = 0; // 1: anglais, 2: français, 3: les deux
    int contentToScan = 0; // 1: conversation, 2: media, 3: les deux
    std::wstring selectedFolderPath; // Variable to store the selected folder path
    std::wstring matchingTextFilePath; // Variable to store the path to the text file with the same name

    printMenu(1, choice, 0);
    if (choice == 1) {
        std::wcout << L"Une fenêtre s'est ouverte, sélectionnez le dossier exporté depuis WhatsApp.\n\n";

        // Open folder selection dialog and store the path
        selectedFolderPath = SelectFolderDialog();
        if (selectedFolderPath.empty()) {
            std::wcout << L"Aucun dossier sélectionné. Arrêt du programme.\n";
            return 0;
        }

        // Check if the folder name starts with "WhatsApp Chat with"
        std::filesystem::path folderPath(selectedFolderPath);
        std::wstring folderName = folderPath.filename().wstring();
        if (folderName.rfind(L"WhatsApp Chat with", 0) != 0) {
            std::wcout << L"Erreur : Le dossier sélectionné n'est pas en anglais ou est invalide.\n";
            std::wcout << L"Le nom du dossier doit commencer par \"WhatsApp Chat with\".\n";
            std::system("pause");
            return 0;
        }

        // Find a text file with the same name as the folder
        matchingTextFilePath = FindMatchingTextFile(selectedFolderPath);
        if (matchingTextFilePath.empty()) {
            std::wcout << L"Erreur : Aucun fichier texte portant le même nom que le dossier n'a été trouvé.\n";
            std::system("pause");
            return 0;
        }

        std::system("cls");
        std::wcout << L"Dossier sélectionné : " << selectedFolderPath << L"\n";
        std::wcout << L"Fichier texte trouvé : " << matchingTextFilePath << L"\n\n";

        // Parse the WhatsApp chat file into a Conversation object
        Conversation conversation;
        bool parseSuccess = Parser::parseWhatsAppChat(matchingTextFilePath, conversation);

        if (!parseSuccess) {
            std::wcout << L"Erreur : Impossible de parser le fichier de conversation WhatsApp.\n";
            std::system("pause");
            return 0;
        }

        // Display basic conversation stats
        std::wcout << L"Conversation chargée avec succès.\n";
        std::wcout << L"Nombre de messages : " << conversation.getMessages().size() << L"\n\n";

        // afficher tout les messages ici

        printMenu(2, choice, 0);
        if (!choice) return 0;
        langageToScan = choice;
        std::wcout << L"\n\n";
        printMenu(3, choice, 1);
        if (!choice) return 0;
        contentToScan = choice;
        std::wcout << L"\n\n";
        printMenu(4, choice, 1);
        if (!choice) return 0;
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
    else {
        return 0;
    }

    return 0;
}
