#include "utils.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <charconv>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <ranges>
#include <sstream>

std::vector<std::string> splitString(std::string_view text) {
    std::vector<std::string> result;

    for (auto part : text | std::views::split(' ')) {
        if (part.empty())
            continue;

        std::string word(part.begin(), part.end());

        std::ranges::transform(word, word.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
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

std::string actionToString(uint8_t action) noexcept {
    switch (action) {
        case 0:  return "deny";
        case 1:  return "permit";
        default: return "unknown";
    }
}

int stringToAction(std::string_view str) noexcept {
    if (str == "deny")
        return 0;

    if (str == "permit")
        return 1;

    return -1;
}

std::string protocolToString(uint8_t protocol) noexcept {
    switch (protocol) {
        case 0: return "ip";
        case 1: return "icmp";
        case 6: return "tcp";
        case 17: return "udp";
        case 255: return "ethernet";
        default: return std::to_string(static_cast<int>(protocol));
    }
}

std::optional<uint8_t> protocolFromString(std::string_view str) noexcept {
    if (str == "icmp")  return 1;
    if (str == "tcp") return 6;
    if (str == "udp") return 17;
    if (str == "ip") return 0;
    if (str == "ethernet") return 255;

    int protocol = 0;
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), protocol);

    if (ec != std::errc{} || ptr != str.data() + str.size())
        return std::nullopt;

    if (protocol < 0 || protocol > 255)
        return std::nullopt;

    return static_cast<uint8_t>(protocol);
}

int toInt(std::string_view str) noexcept {
    int value = 0;
    auto [ptr, ec] = std::from_chars(str.data(), str.data() + str.size(), value);

    if (ec != std::errc{} || ptr != str.data() + str.size())
        return -1;

    return value;
}

std::string directionToString(uint8_t direction) noexcept {
    switch (direction) {
        case 0:  return "inbound";
        case 1:  return "outbound";
        default: return "unknown";
    }
}

uint8_t stringToDirection(std::string_view direction) noexcept {
    if (direction == "inbound" || direction == "in")
        return 0;

    if (direction == "outbound" || direction == "out")
        return 1;

    return 255;
}

std::string ipToString(uint32_t ip) noexcept {
    if (ip == 0)
        return "any";

    char buffer[INET_ADDRSTRLEN]{};

    if (inet_ntop(AF_INET, &ip, buffer, sizeof(buffer)) == nullptr)
        return "invalid";

    return buffer;
}

std::string ipToCiscoString(uint32_t ip) noexcept {
    if (ip == 0)
        return "any";

    return "host " + ipToString(ip);
}

std::string portToString(uint16_t port) noexcept {
    if (port == 0)
        return "any";

    return std::to_string(ntohs(port));
}

std::string portToCiscoString(uint16_t port) noexcept {
    if (port == 0)
        return "";

    return " eq " + std::to_string(ntohs(port));
}

std::string flagsToString(uint8_t flags) noexcept {
    if (flags == 0)
        return "any";

    std::string result;

    if (flags & TCP_FLAG_FIN) result += "fin,";
    if (flags & TCP_FLAG_SYN) result += "syn,";
    if (flags & TCP_FLAG_RST) result += "rst,";
    if (flags & TCP_FLAG_PSH) result += "psh,";
    if (flags & TCP_FLAG_ACK) result += "ack,";
    if (flags & TCP_FLAG_URG) result += "urg,";
    if (flags & TCP_FLAG_ECE) result += "ece,";
    if (flags & TCP_FLAG_CWR) result += "cwr,";

    result.pop_back();

    return result;
}

std::string formatKtime(u64 ktimeNs) noexcept {
    struct timespec boottime{}, realtime{};

    clock_gettime(CLOCK_MONOTONIC, &boottime);
    clock_gettime(CLOCK_REALTIME, &realtime);

    int64_t offsetNs =
        (int64_t)realtime.tv_sec  * 1'000'000'000LL + realtime.tv_nsec -
        ((int64_t)boottime.tv_sec * 1'000'000'000LL + boottime.tv_nsec);

    int64_t wallNs = (int64_t)ktimeNs + offsetNs;

    auto tp = std::chrono::system_clock::time_point(std::chrono::nanoseconds(wallNs));
    auto t  = std::chrono::system_clock::to_time_t(tp);

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()) % 1000;

    std::tm tmv{};
    localtime_r(&t, &tmv);

    std::ostringstream oss;
    oss << std::put_time(&tmv, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setw(3) << std::setfill('0') << ms.count();

    return oss.str();
}
