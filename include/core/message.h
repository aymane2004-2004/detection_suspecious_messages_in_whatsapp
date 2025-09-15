#ifndef MESSAGE_H
#define MESSAGE_H

#include <string>
#include <vector>

// Type of message
enum class MessageType {
    TEXT,
    LINK,
    TEXT_LINK,  // New type for text mixed with one or multiple links
    MEDIA_OMITTED,
    IMAGE,
    VIDEO,
    AUDIO,
    DOCUMENT,
    UNKNOWN
};

// Class representing a single WhatsApp message
class Message {
public:
    Message() = default;
    Message(const std::wstring& date,
        const std::wstring& time,
        const std::wstring& author,
        const std::wstring& content,
        MessageType type);

    // Getters
    const std::wstring& getDate() const;
    const std::wstring& getTime() const;
    const std::wstring& getAuthor() const;
    const std::wstring& getContent() const;
    MessageType getType() const;

    // Setters
    void setContent(const std::wstring& content);
    void setType(MessageType type);

private:
    std::wstring date;     // Date in format YYYY-MM-DD
    std::wstring time;     // Time in format HH:MM:SS
    std::wstring author;   // Author of the message
    std::wstring content;  // Message text
    MessageType type;      // Type of message
};

#endif // MESSAGE_H
