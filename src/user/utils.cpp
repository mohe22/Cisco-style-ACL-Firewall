// utils.cpp
#include "utils.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <ranges>
#include <stdexcept>

std::vector<std::string> splitString(std::string_view text) {
    std::vector<std::string> result;

    for (auto part : text | std::views::split(' ')) {
        if (part.empty())
            continue;

        std::string word(part.begin(), part.end());

        std::ranges::transform(word, word.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        result.emplace_back(std::move(word));
    }

    return result;
}

std::tuple<Action, std::vector<std::string>> getAction(std::string_view str) noexcept {
    const auto parts = splitString(str);

    if (parts.empty())
        return {Action::Unknown, {}};

    if (parts[0] == "show") {
        if (parts.size() > 1 && parts[1] == "ace")
            return {Action::ShowAce, std::vector<std::string>(parts.begin() + 2, parts.end())};

        return {Action::Show, {}};
    }

    if (parts[0] == "add")
        return {Action::Add, std::vector<std::string>(parts.begin() + 1, parts.end())};

    if (parts[0] == "update")
        return {Action::Update, std::vector<std::string>(parts.begin() + 1, parts.end())};

    if (parts[0] == "delete")
        return {Action::Delete, std::vector<std::string>(parts.begin() + 1, parts.end())};

    if (parts[0] == "exit" || parts[0] == "quit")
        return {Action::Exit, {}};

    return {Action::Unknown, {}};
}

std::string actionToString(uint8_t action) {
    switch (action) {
        case 0: return "deny";
        case 1: return "permit";
        default: return "unknown";
    }
}

int stringToAction(const std::string& str) {
    if (str == "deny")
        return 0;

    if (str == "permit")
        return 1;

    return -1;
}

std::string protocolToString(uint8_t protocol) {
    switch (protocol) {
        case 0:   return "ip";
        case 1:   return "icmp";
        case 6:   return "tcp";
        case 17:  return "udp";
        case 255: return "ethernet";
        default:  return std::to_string(static_cast<int>(protocol));
    }
}

std::optional<uint8_t> protocolFromString(const std::string& str) {
    if (str == "icmp")     return 1;
    if (str == "tcp")      return 6;
    if (str == "udp")      return 17;
    if (str == "ip")       return 0;
    if (str == "ethernet") return 255;

    try {
        size_t pos = 0;
        int protocol = std::stoi(str, &pos);

        if (pos != str.size())
            return std::nullopt;

        if (protocol < 0 || protocol > 255)
            return std::nullopt;

        return static_cast<uint8_t>(protocol);
    }
    catch (const std::invalid_argument&) {
        return std::nullopt;
    }
    catch (const std::out_of_range&) {
        return std::nullopt;
    }
}

int toInt(const std::string& str) {
    try {
        size_t pos = 0;
        int value = std::stoi(str, &pos);

        if (pos != str.size())
            return -1;

        return value;
    }
    catch (const std::invalid_argument&) {
        return -1;
    }
    catch (const std::out_of_range&) {
        return -1;
    }
}

std::string directionToString(uint8_t direction) {
    switch (direction) {
        case 0: return "inbound";
        case 1: return "outbound";
        default: return "unknown";
    }
}

uint8_t stringToDirection(std::string_view direction) {
    if (direction == "inbound" || direction == "in")
        return 0;

    if (direction == "outbound" || direction == "out")
        return 1;

    return 255;
}

std::string ipToString(uint32_t ip) {
    if (ip == 0)
        return "any";

    char buffer[INET_ADDRSTRLEN]{};

    if (inet_ntop(AF_INET, &ip, buffer, sizeof(buffer)) == nullptr)
        return "invalid";

    return buffer;
}

std::string ipToCiscoString(uint32_t ip) {
    if (ip == 0)
        return "any";

    return "host " + ipToString(ip);
}

std::string portToString(uint16_t port) {
    if (port == 0)
        return "any";

    return std::to_string(ntohs(port));
}

std::string portToCiscoString(uint16_t port) {
    if (port == 0)
        return "";

    return " eq " + std::to_string(ntohs(port));
}
