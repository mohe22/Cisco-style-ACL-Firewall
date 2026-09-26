#include "utils.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cstring>
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

bool parseMac(const std::string& text, u8 (&mac)[6]) noexcept {
    if (text == "any") {
        std::memset(mac, 0, 6);
        return true;
    }

    if (text.size() != 17)
        return false;

    for (size_t i = 0; i < 6; ++i) {
        size_t pos = i * 3;

        if (!std::isxdigit(static_cast<unsigned char>(text[pos])) ||
            !std::isxdigit(static_cast<unsigned char>(text[pos + 1])))
            return false;

        if (i < 5 && text[pos + 2] != ':')
            return false;

        unsigned int byte = 0;
        auto [ptr, ec] = std::from_chars(text.data() + pos, text.data() + pos + 2, byte, 16);

        if (ec != std::errc{})
            return false;

        mac[i] = static_cast<u8>(byte);
    }

    return true;
}

bool parseFlags(const std::string& text, u8& flags) noexcept {
    flags = 0;

    if (text == "any")
        return true;

    size_t start = 0;

    while (start < text.size()) {
        size_t comma = text.find(',', start);
        std::string token = text.substr(start, comma - start);

        std::transform(token.begin(), token.end(), token.begin(),
            [](unsigned char c) { return std::tolower(c); });

        if (token == "fin") flags |= TCP_FLAG_FIN;
        else if (token == "syn") flags |= TCP_FLAG_SYN;
        else if (token == "rst") flags |= TCP_FLAG_RST;
        else if (token == "psh") flags |= TCP_FLAG_PSH;
        else if (token == "ack") flags |= TCP_FLAG_ACK;
        else if (token == "urg") flags |= TCP_FLAG_URG;
        else if (token == "ece") flags |= TCP_FLAG_ECE;
        else if (token == "cwr") flags |= TCP_FLAG_CWR;
        else return false;

        if (comma == std::string::npos)
            break;

        start = comma + 1;
    }

    return true;
}




bool parseIp(const std::string& text, __be32& ip) noexcept {
    if (text == "any") {
        ip = 0;
        return true;
    }

    in_addr addr{};

    if (inet_pton(AF_INET, text.c_str(), &addr) != 1)
        return false;

    if (addr.s_addr == 0)
        return false;

    ip = addr.s_addr;
    return true;
}

bool parsePort(const std::string& text, __be16& port) noexcept {
    if (text == "any") {
        port = 0;
        return true;
    }

    int value = toInt(text);

    if (value < 1 || value > 65535)
        return false;

    port = htons(static_cast<uint16_t>(value));
    return true;
}

bool parseEtherType(const std::string& text, __be16& etherType) noexcept {
    if (text == "any") {
        etherType = 0;
        return true;
    }

    unsigned long value = 0;

    if (text == "ip" || text == "ipv4")
        value = 0x0800;
    else if (text == "arp")
        value = 0x0806;
    else if (text == "ipv6")
        value = 0x86DD;
    else {
        if (text.empty())
            return false;

        int base = 10;
        std::string_view sv = text;

        if (sv.starts_with("0x") || sv.starts_with("0X")) {
            sv.remove_prefix(2);
            base = 16;
        }

        unsigned int parsed = 0;
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), parsed, base);

        if (ec != std::errc{} || ptr != sv.data() + sv.size())
            return false;

        value = parsed;
    }

    if (value == 0 || value > 0xFFFF)
        return false;

    etherType = htons(static_cast<uint16_t>(value));
    return true;
}

std::string macToString(const u8 (&mac)[6]) noexcept {
    static const u8 zero[6] = {};

    if (std::memcmp(mac, zero, 6) == 0)
        return "any";

    char buffer[18];

    std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return buffer;
}
std::string etherTypeToString(__be16 etherType) noexcept {
    if (etherType == 0)
        return "any";

    char buffer[7];
    std::snprintf(buffer, sizeof(buffer), "0x%04x", ntohs(etherType));

    return buffer;
}
std::string formatL3L4(size_t index, const ACEL3L4& rule) noexcept {
    return "[" + std::to_string(index) + "] " +
           actionToString(rule.action) + " " +
           protocolToString(rule.protocol) + " " +
           ipToCiscoString(rule.srcIP) +
           portToCiscoString(rule.srcPort) + " " +
           ipToCiscoString(rule.dstIP) +
           portToCiscoString(rule.dstPort) + " " +
           "flags " + flagsToString(rule.flags) + " " +
           directionToString(rule.direction);
}

std::string formatL2(size_t index, const ACEL2& rule) noexcept{
    return "[" + std::to_string(index) + "] " +
           actionToString(rule.action) + " ethernet " +
           macToString(rule.srcMAC) + " " +
           macToString(rule.dstMAC) + " ethertype " +
           etherTypeToString(rule.etherType) + " " +
           directionToString(rule.direction);
}
