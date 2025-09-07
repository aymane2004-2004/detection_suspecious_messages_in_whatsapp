#include "analysis/detector.h"
#include "core/suspicious_words.h"

#include <iostream>
#include <string>
#include <set>
#include <vector>
#include <windows.h>
#include <commdlg.h>
#include <cstdlib>

void printMenu(int menuNumber, int& choice) {
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
    case 5:
        maxPossibleChoice = 4;
        std::cout << "[1] Extraire et afficher tous les messages\n";
        std::cout << "[2] Détecter et afficher les messages suspects\n";
        std::cout << "[3] Exporter tous les messages vers CSV\n";
        std::cout << "[4] Exporter seulement les messages suspects vers CSV\n";
        break;
    }
    std::cout << "[0] Quitter\n";
    std::cout << "=======================================================\n";
    std::cout << "Votre choix : ";
    std::cin >> choice;
    if (choice < 0 || choice > maxPossibleChoice) {
        std::system("cls");
		std::cout << "Choix invalide. Ressayez." << std::endl;
		printMenu(menuNumber, choice);
    }
}

int main() {
    SetConsoleOutputCP(CP_UTF8);

	int choice;
    std::string zipPath;


    printMenu(1, choice);
    if (choice == 1) {
		std::cout << "Une fenêtre s'est ouverte, sélectionnez le fichier ZIP exporté depuis WhatsApp.\n\n";
        // Structure OPENFILENAME pour configurer le dialogue
        OPENFILENAME ofn;
        char szFile[MAX_PATH] = { 0 };

        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = NULL; // pas de fenêtre parent
        ofn.lpstrFile = szFile;
        ofn.nMaxFile = sizeof(szFile);
        ofn.lpstrFilter = "ZIP Files\0*.zip\0All Files\0*.*\0";
        ofn.nFilterIndex = 1;
        ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

        if (GetOpenFileName(&ofn) == TRUE) {
            zipPath = ofn.lpstrFile;
            std::cout << "Fichier ZIP sélectionné : " << zipPath << std::endl;
        }
        else {
            std::cout << "Aucun fichier sélectionné." << std::endl;
            return 1;
        }
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
