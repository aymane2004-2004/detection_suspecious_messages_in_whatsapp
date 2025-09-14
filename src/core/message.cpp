#include "core/message.h"

// -------------------- Constructor --------------------
Message::Message(const std::wstring& date,
    const std::wstring& time,
    const std::wstring& author,
    const std::wstring& content,
    MessageType type)
    : date(date), time(time), author(author), content(content), type(type)
{
}

// -------------------- Getters --------------------
const std::wstring& Message::getDate() const {
    return date;
}

const std::wstring& Message::getTime() const {
    return time;
}

const std::wstring& Message::getAuthor() const {
    return author;
}

const std::wstring& Message::getContent() const {
    return content;
}

MessageType Message::getType() const {
    return type;
}

// -------------------- Setters --------------------
void Message::setContent(const std::wstring& newContent) {
    content = newContent;
}

void Message::setType(MessageType newType) {
    type = newType;
}
