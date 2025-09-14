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
