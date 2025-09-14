#ifndef PARSER_H
#define PARSER_H

#include "core/conversation.h"
#include "core/message.h"
#include "utils/file_utils.h"
#include "utils/wstring_utils.h"

#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sstream>

namespace Parser {
    /**
     * @brief Classifies a message based on its content
     * 
     * This function analyzes the message content and determines its type:
     * - If it contains a URL pattern, it's classified as a LINK
     * - If it contains file attachment pattern, it's classified based on file extension
     * - If it contains media omitted patterns, it's classified accordingly
     * - Otherwise, it's classified as TEXT
     * 
     * @param content The message content to classify
     * @return MessageType The detected type of the message
     */
    inline MessageType classify(const std::wstring& content) {
        // Regular expressions for detection
        std::wregex mediaPattern(L"<(Media|image|video|audio|document) omitted>");
        std::wregex urlPattern(L"(https?://[^\\s]+)");
        std::wregex filePattern(L"(.+\\.\\w+)\\s*\\(file attached\\)");
        
        std::wsmatch matches;
        
        // Check for file attachments
        if (std::regex_search(content, matches, filePattern)) {
            std::wstring filename = matches[1].str();
            std::wstring extension = filename.substr(filename.find_last_of(L'.') + 1);
            
            // Convert extension to lowercase
            extension = WStringUtils::toLower(extension);
            
            // Classify based on file extension
            if (extension == L"jpg" || extension == L"png" || extension == L"gif" || 
                extension == L"jpeg" || extension == L"bmp" || extension == L"webp") {
                return MessageType::IMAGE;
            } else if (extension == L"mp4" || extension == L"mkv" || extension == L"avi" || 
                       extension == L"mov" || extension == L"wmv") {
                return MessageType::VIDEO;
            } else if (extension == L"mp3" || extension == L"wav" || extension == L"ogg" || 
                       extension == L"m4a" || extension == L"flac") {
                return MessageType::AUDIO;
            } else if (extension == L"pdf" || extension == L"doc" || extension == L"docx" || 
                       extension == L"txt" || extension == L"xls" || extension == L"xlsx" || 
                       extension == L"ppt" || extension == L"pptx") {
                return MessageType::DOCUMENT;
            } else {
                return MessageType::DOCUMENT; // Default for unknown extensions
            }
        }
        
        // Check for media omitted patterns
        if (std::regex_search(content, matches, mediaPattern)) {
            if (WStringUtils::contains(content, L"image")) {
                return MessageType::IMAGE;
            } else if (WStringUtils::contains(content, L"video")) {
                return MessageType::VIDEO;
            } else if (WStringUtils::contains(content, L"audio")) {
                return MessageType::AUDIO;
            } else if (WStringUtils::contains(content, L"document")) {
                return MessageType::DOCUMENT;
            } else {
                return MessageType::MEDIA_OMITTED;
            }
        }
        
        // Check for URLs
        if (std::regex_search(content, matches, urlPattern)) {
            return MessageType::LINK;
        }
        
        // Default to TEXT for regular messages
        return MessageType::TEXT;
    }

    /**
     * @brief Displays a progress bar animation in the console
     * 
     * @param progress Current progress value (0-100)
     */
    inline void displayProgressBar(int progress) {
        const int barWidth = 20;
        int filledWidth = barWidth * progress / 100;
        
        std::cout << "\r[";
        for (int i = 0; i < barWidth; ++i) {
            if (i < filledWidth) {
                std::cout << "#";
            } else {
                std::cout << "-";
            }
        }
        std::cout << "] " << progress << "%" << std::flush;
    }

    /**
     * @brief Parses a WhatsApp chat text file and extracts messages into a Conversation object
     * 
     * This function reads the content of a WhatsApp chat export file, identifies 
     * messages with their metadata, and creates Message objects that are added to
     * the provided Conversation object.
     * 
     * Expected format of WhatsApp messages in English:
     * [MM/DD/YY, HH:MM:SS AM/PM] Author: Message content
     * 
     * @param filePath The path to the WhatsApp chat text file
     * @param conversation The Conversation object where messages will be stored
     * @return bool True if parsing was successful, false otherwise
     */
    inline bool parseWhatsAppChat(const std::wstring& filePath, Conversation& conversation) {
        try {
            // Read all lines from the file
            std::vector<std::wstring> lines = FileUtils::readFileLines(filePath);
            
            if (lines.empty()) {
                std::wcerr << L"The chat file is empty or could not be read." << std::endl;
                return false;
            }

            // Display initial progress
            displayProgressBar(0);

            // Regular expression to match WhatsApp message format
            std::wregex messagePattern(L"(\\d{1,2}/\\d{1,2}/\\d{2}), (\\d{1,2}:\\d{2})(:\\d{2})? - ([^:]+): (.+)");
            
            std::wstring currentDate;
            std::wstring currentTime;
            std::wstring currentAuthor;
            std::wstring currentContent;
            MessageType currentType;
            
            const size_t totalLines = lines.size();
            size_t processedLines = 0;
            
            for (const auto& line : lines) {
                std::wsmatch matches;
                
                // Check if line starts a new message
                if (std::regex_search(line, matches, messagePattern)) {
                    // If we have collected data for a previous message, add it to the conversation
                    if (!currentAuthor.empty() && !currentContent.empty()) {
                        Message message(currentDate, currentTime, currentAuthor, currentContent, currentType);
                        conversation.addMessage(message);
                    }
                    
                    // Extract components of the new message
                    currentDate = matches[1].str();  // MM/DD/YY
                    currentTime = matches[2].str();  // HH:MM (seconds might be optional)
                    if (matches[3].matched) {
                        currentTime += matches[3].str(); // Add seconds if present
                    }
                    currentAuthor = WStringUtils::trim(matches[4].str());
                    currentContent = matches[5].str();
                    
                    // Use the classify function to determine message type
                    currentType = classify(currentContent);
                } else if (!currentAuthor.empty()) {
                    // This line is a continuation of the previous message
                    currentContent += L"\n" + line;
                    
                    // Re-classify the message with the updated content
                    currentType = classify(currentContent);
                }
                
                // Update progress every few lines to avoid too frequent updates
                if (++processedLines % 10 == 0 || processedLines == totalLines) {
                    int progressPercentage = static_cast<int>((static_cast<double>(processedLines) / totalLines) * 100);
                    displayProgressBar(progressPercentage);
                }
            }
            
            // Add the last message if there is one
            if (!currentAuthor.empty() && !currentContent.empty()) {
                Message message(currentDate, currentTime, currentAuthor, currentContent, currentType);
                conversation.addMessage(message);
            }
            
            // Complete the progress bar and move to next line
            displayProgressBar(100);
            std::cout << std::endl;
            
            return true;
        } catch (const std::exception& e) {
            std::cerr << "\nError parsing WhatsApp chat: " << e.what() << std::endl;
            return false;
        }
    }

    /**
     * @brief Converts date format from MM/DD/YY to YYYY-MM-DD
     * 
     * @param dateStr Date string in format MM/DD/YY
     * @return std::wstring Date in format YYYY-MM-DD
     */
    inline std::wstring standardizeDate(const std::wstring& dateStr) {
        std::wregex datePattern(L"(\\d{1,2})/(\\d{1,2})/(\\d{2})");
        std::wsmatch matches;
        
        if (std::regex_match(dateStr, matches, datePattern)) {
            int month = std::stoi(matches[1].str());
            int day = std::stoi(matches[2].str());
            int year = std::stoi(matches[3].str());
            
            // Assume 20YY for years less than 100
            if (year < 100) {
                year += 2000;
            }
            
            // Format with leading zeros
            std::wstringstream formattedDate;
            formattedDate << year << L"-"
                         << (month < 10 ? L"0" : L"") << month << L"-"
                         << (day < 10 ? L"0" : L"") << day;
                         
            return formattedDate.str();
        }
        
        return dateStr; // Return original if format doesn't match
    }

    /**
     * @brief Converts time format from HH:MM:SS AM/PM to 24-hour format
     * 
     * @param timeStr Time string in format HH:MM:SS AM/PM
     * @return std::wstring Time in 24-hour format HH:MM:SS
     */
    inline std::wstring standardizeTime(const std::wstring& timeStr) {
        std::wregex timePattern(L"(\\d{1,2}):(\\d{2}):(\\d{2}) ([AP]M)");
        std::wsmatch matches;
        
        if (std::regex_match(timeStr, matches, timePattern)) {
            int hour = std::stoi(matches[1].str());
            int minute = std::stoi(matches[2].str());
            int second = std::stoi(matches[3].str());
            std::wstring ampm = matches[4].str();
            
            // Convert to 24-hour format
            if (ampm == L"PM" && hour < 12) {
                hour += 12;
            } else if (ampm == L"AM" && hour == 12) {
                hour = 0;
            }
            
            // Format with leading zeros
            std::wstringstream formattedTime;
            formattedTime << (hour < 10 ? L"0" : L"") << hour << L":"
                         << (minute < 10 ? L"0" : L"") << minute << L":"
                         << (second < 10 ? L"0" : L"") << second;
                         
            return formattedTime.str();
        }
        
        return timeStr; // Return original if format doesn't match
    }
} // namespace Parser

#endif // PARSER_H