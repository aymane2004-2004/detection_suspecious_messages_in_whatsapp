# WhatsApp Suspicious Messages Detection (C++17, Windows)

Detect suspicious content in exported WhatsApp chats. This Windows console application scans messages, links, filenames, and documents for suspicious patterns in English and/or French, and produces CSV exports, a textual report, and logs.

## Features
- Guided, step-by-step console UI (FR prompts).
- Import WhatsApp chat exports (requires WhatsApp app language set to English).
- Detection modes:
  - Conversation text
  - Links only
  - Media/documents metadata (filenames)
  - Text documents (txt, pdf) in the export folder
  - Full scan (all of the above)
- Detection languages: English, French, or both.
- Exports:
  - All messages to CSV
  - Only suspicious items to CSV
  - Human-readable scan report (EN/FR)
  - Execution logs
- Automatic output folder management:
  - Creates an `Analyse` folder in the selected export directory (auto-suffixed if it already exists)
  - Timestamped filenames (UTC localtime pattern `YYYYMMDD_HHMMSS_`)

## Requirements
- Windows 10/11
- Visual Studio 2022
- C++17 toolset and Windows SDK

No external dependencies beyond the Windows SDK and the C++ standard library are required.

## Build (Visual Studio 2022)
1. Clone the repository.
2. Open the solution/project in Visual Studio 2022.
3. Select configuration and platform (e.g., Release | x64) via __Configuration Manager__.
4. Build via __Build > Build Solution__.
5. Run via __Debug > Start Without Debugging__ or execute the built `.exe`.

Notes:
- The app sets the console output to UTF-8 at startup for better diacritic handling.
- The app uses the Windows folder picker dialog (COM `IFileDialog`).

## How to export a chat from WhatsApp (English UI)
The parser expects the standard WhatsApp export naming in English. On your phone:
1. Open WhatsApp.
2. Go to Settings > App Language and select English.
3. Open the conversation to export.
4. Tap the three dots > More > Export chat.
5. Choose “Without media” or “Include media”.
6. Send the resulting ZIP to your PC and extract it.
7. You will get a folder named like `WhatsApp Chat with <Contact>` and a text file `WhatsApp Chat with <Contact>.txt` inside.

Important:
- The folder name must start with `WhatsApp Chat with`.
- A `.txt` file with the exact same name as the folder must exist in that folder.

## Usage
At startup, follow the on-screen menu:

Step 1: Import
- [1] Choose the exported folder (opens a folder picker).
- [2] Tutorial (exits after showing steps).

Valid selection checks:
- Folder name must start with `WhatsApp Chat with`.
- The folder must contain a `<same name>.txt` chat file.

Step 2: Detection Language
- [1] English
- [2] French
- [3] Both

Step 3: What to scan
- [1] Conversation text only
- [2] Links only
- [3] Metadata (media and documents filenames)
- [4] Documents (txt, pdf) within the export
- [5] Full scan

After scanning, an `Analyse` directory is created inside the selected export folder. Filenames are timestamped.

Step 4: Exports
- [1] Export all messages to CSV
- [2] Export only suspicious messages to CSV
- [3] Save logs to file
- [4] Save scan report (goes to Step 5 for language)

Step 5: Report language
- [1] English
- [2] French

## Output
Outputs are created in `<Selected Export Folder>\Analyse[_N]\` with a timestamp prefix like `20250101_153045_`:

- `YYYYMMDD_HHMMSS_messages_complets.csv` — all parsed messages
- `YYYYMMDD_HHMMSS_messages_suspects.csv` — only suspicious items
- `YYYYMMDD_HHMMSS_rapport.txt` — human-readable report (EN/FR)
- `YYYYMMDD_HHMMSS_journal.txt` — application log

Notes:
- CSV column layout depends on `Exporter` and may include timestamp, author, type, and content.
- The log is buffered in memory until you choose “Save logs”.

## Troubleshooting
- “Folder invalid”: Ensure the folder starts with `WhatsApp Chat with` and contains a text file with the same name.
- “Cannot parse conversation”: Re-export the chat with WhatsApp’s app language set to English.
- No output files: You must run a scan (Step 3) before exporting (Step 4).
- Non-ASCII characters: The app sets UTF-8; use a terminal/font that supports UTF-8.

## Project structure (high level)
- `src/analysis/` — detection engine and suspicious conversation aggregation
- `src/core/` — domain objects (`Message`, `Conversation`, suspicious words)
- `src/io/` — parser, exporter, report generator, logger
- `src/utils/` — helpers for files and wide strings
- `src/main.cpp` — console UI and workflow

## Privacy
All processing happens locally on your machine. No data is transmitted.

## Contributing
Issues and pull requests are welcome. Please:
- Describe the problem clearly and include reproduction details.
- Keep changes focused and documented.
- Follow the existing code style (C++17).

## License
See the repository for licensing information.
