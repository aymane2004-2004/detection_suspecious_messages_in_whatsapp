#include "../include/analysis/detector.h"
#include "../include/core/suspicious_words.h"

#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <windows.h>
#include <commdlg.h>
#include <cstdlib>
#include <locale>
#include <codecvt>

//#include <mz.h>
//#include <mz_zip.h>
//#include <mz_zip_rw.h>

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
        std::cout << "[1] Choisir le chemin vers le fichier zip\n";
        std::cout << "[2] Regarder tutoriel pour extraire les messages\n";
        std::cout << "    Whatsapp en anglais\n";
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
        std::cout << "[1] Afficher tous les messages\n";
        std::cout << "[2] Afficher les messages suspects détectés\n";
        std::cout << "[3] Exporter tous les messages vers CSV\n";
        std::cout << "[4] Exporter seulement les messages suspects vers CSV\n";
        std::cout << "[5] Sauvgarder les logs\n";
        std::cout << "[6] Sauvgarder les rapports de scan\n";
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

int main() {
    SetConsoleOutputCP(CP_UTF8);

	int choice;
    std::string zipPath;
	int langageToScan = 0; // 1: anglais, 2: français, 3: les deux
	int contentToScan = 0; // 1: conversation, 2: media, 3: les deux


    printMenu(1, choice, 0);
    if (choice == 1) {
		std::cout << "Une fenêtre s'est ouverte, sélectionnez le fichier ZIP exporté depuis WhatsApp.\n\n";
        // Structure OPENFILENAME pour configurer le dialogue
        OPENFILENAME ofn;
        wchar_t szFile[MAX_PATH] = { 0 };
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = L"ZIP Files\0*.zip\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

        if (GetOpenFileName(&ofn) == TRUE) {
            zipPath = std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(ofn.lpstrFile);
            std::wcout << L"Fichier ZIP sélectionné : " << szFile << L"\n\n";
            // Convert wide string (LPWSTR) to UTF-8 std::string
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, nullptr, 0, nullptr, nullptr);
            std::string utf8Path(size_needed - 1, 0); // exclude null terminator
            WideCharToMultiByte(CP_UTF8, 0, ofn.lpstrFile, -1, &utf8Path[0], size_needed, nullptr, nullptr);
            zipPath = utf8Path;
        }
        else {
            std::cout << "Aucun fichier sélectionné." << std::endl;
            return 1;
        }
        std::cout << "\n\n";
		printMenu(2, choice, 1);
		langageToScan = choice;
        std::cout << "\n\n";
		printMenu(3, choice, 1);
        contentToScan = choice;
        std::cout << "\n\n";
        printMenu(4, choice, 1);

        
    }
    else if (choice == 2) {
        std::cout << "\nTutoriel pour extraire les messages WhatsApp en anglais :\n";
        std::cout << "1. Ouvrez WhatsApp sur votre téléphone.\n";
        std::cout << "2. Allez dans Paramètres > Langue de l'application.\n";
        std::cout << "3. Choisissez English (Important).\n";
        std::cout << "4. Revenez à l'accueil.\n";
        std::cout << "5. Entrez dans une conversation que vous voulez exporter.\n";
        std::cout << "6. Cliquez sur les trois points en haut à droite > More > Export chat.\n";
        std::cout << "7. Sélectionnez 'Without media' ou 'Include media'.\n";
        std::cout << "8. Envoyez le fichier ZIP sur votre ordinateur.\n";
        std::cout << "Pour plus de détails :\n";
        std::cout << "youtube.com\n";
		return 0;

    }
    else {
        return 0;
    }




    return 0;
}
