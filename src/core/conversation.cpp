#include "core/conversation.h"
#include <algorithm> // for std::copy_if
#include <iterator>   // for std::back_inserter

// -------------------- Add Message --------------------
void Conversation::addMessage(const Message& message) {
    messages.push_back(message);
}

// -------------------- Get All Messages --------------------
const std::vector<Message>& Conversation::getMessages() const {
    return messages;
}

// -------------------- Filter by Date --------------------
std::vector<Message> Conversation::filterByDate(const std::wstring& startDate,
    const std::wstring& endDate) const
{
    std::vector<Message> filtered;

    std::copy_if(messages.begin(), messages.end(), std::back_inserter(filtered),
        [&startDate, &endDate](const Message& msg) {
            const std::wstring& date = msg.getDate();
            return (date >= startDate && date <= endDate);
        });

    return filtered;
}

// -------------------- Filter by Type --------------------
std::vector<Message> Conversation::filterByType(MessageType type) const
{
    std::vector<Message> filtered;

    std::copy_if(messages.begin(), messages.end(), std::back_inserter(filtered),
        [type](const Message& msg) {
            return msg.getType() == type;
        });

    return filtered;
}

// -------------------- Count Messages by Type --------------------
std::map<MessageType, int> Conversation::countMessagesByType() const
{
    std::map<MessageType, int> typeCounts;

    // Initialize all message types with count 0
    typeCounts[MessageType::TEXT] = 0;
    typeCounts[MessageType::LINK] = 0;
    typeCounts[MessageType::TEXT_LINK] = 0;
    typeCounts[MessageType::MEDIA_OMITTED] = 0;
    typeCounts[MessageType::IMAGE] = 0;
    typeCounts[MessageType::VIDEO] = 0;
    typeCounts[MessageType::AUDIO] = 0;
    typeCounts[MessageType::DOCUMENT] = 0;
    typeCounts[MessageType::UNKNOWN] = 0;

    // Count occurrences of each message type
    for (const auto& message : messages) {
        MessageType type = message.getType();
        typeCounts[type]++;
    }

    return typeCounts;
}
