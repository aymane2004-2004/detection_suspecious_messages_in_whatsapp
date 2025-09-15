#ifndef CONVERSATION_H
#define CONVERSATION_H

#include <vector>
#include <string>
#include <map>
#include "core/message.h"

// Class representing a full conversation
class Conversation {
public:
    Conversation() = default;

    // Add a message to the conversation
    void addMessage(const Message& message);

    // Get all messages
    const std::vector<Message>& getMessages() const;

    // Filter messages by date range (inclusive)
    std::vector<Message> filterByDate(const std::wstring& startDate,
        const std::wstring& endDate) const;

    // Filter messages by type
    std::vector<Message> filterByType(MessageType type) const;

    // Count messages by type
    std::map<MessageType, int> countMessagesByType() const;

private:
    std::vector<Message> messages;
};

#endif // CONVERSATION_H
