#include "loader.hpp"
#include "utils.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <thread>

static std::atomic<bool> gRunning{true};

static void onSignal(int) {
    gRunning.store(false);
}

using Args = std::vector<std::string>;

static bool parseIndex(const std::string& token, size_t endValue, bool allowEnd, size_t& out) {
    if (allowEnd && token == "end") {
        out = endValue;
        return true;
    }

    int value = toInt(token);

    if (value < 0)
        return false;

    out = static_cast<size_t>(value);
    return true;
}

static bool parseMac(const std::string& text, u8 (&mac)[6]) {
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

        mac[i] = static_cast<u8>(std::strtoul(text.substr(pos, 2).c_str(), nullptr, 16));
    }

    return true;
}

static bool parseIp(const std::string& text, __be32& ip) {
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

static bool parsePort(const std::string& text, __be16& port) {
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

static bool parseEtherType(const std::string& text, __be16& etherType) {
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

        char* end = nullptr;
        value = std::strtoul(text.c_str(), &end, 0);

        if (end == text.c_str() || *end != '\0')
            return false;
    }

    if (value == 0 || value > 0xFFFF)
        return false;

    etherType = htons(static_cast<uint16_t>(value));
    return true;
}

static std::string macToString(const u8 (&mac)[6]) {
    static const u8 zero[6] = {};

    if (std::memcmp(mac, zero, 6) == 0)
        return "any";

    char buffer[18];

    std::snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    return buffer;
}

static std::string etherTypeToString(__be16 etherType) {
    if (etherType == 0)
        return "any";

    char buffer[7];
    std::snprintf(buffer, sizeof(buffer), "0x%04x", ntohs(etherType));

    return buffer;
}

static std::string formatL3L4(size_t index, const ACEL3L4& rule) {
    return "[" + std::to_string(index) + "] " +
           actionToString(rule.action) + " " +
           protocolToString(rule.protocol) + " " +
           ipToCiscoString(rule.srcIP) +
           portToCiscoString(rule.srcPort) + " " +
           ipToCiscoString(rule.dstIP) +
           portToCiscoString(rule.dstPort) + " " +
           directionToString(rule.direction);
}

static std::string formatL2(size_t index, const ACEL2& rule) {
    return "[" + std::to_string(index) + "] " +
           actionToString(rule.action) + " ethernet " +
           macToString(rule.srcMAC) + " " +
           macToString(rule.dstMAC) + " ethertype " +
           etherTypeToString(rule.etherType) + " " +
           directionToString(rule.direction);
}

static bool parseHeader(const Args& a, uint8_t& action, uint8_t& direction, std::string& err) {
    int act = stringToAction(a[2]);

    if (act < 0) {
        err = "invalid action '" + a[2] + "' (permit|deny)";
        return false;
    }

    uint8_t dir = stringToDirection(a[3]);

    if (dir == 255) {
        err = "invalid direction '" + a[3] + "' (in|out)";
        return false;
    }

    action = static_cast<uint8_t>(act);
    direction = dir;
    return true;
}

static bool parseL3Rule(const Args& a, ACEL3L4& rule, std::string& err) {
    if (a.size() < 5) {
        err = "usage: <add|update> l3 <index> <permit|deny> <in|out> <protocol> [src <ip|any>] [sport <port|any>] [dst <ip|any>] [dport <port|any>]";
        return false;
    }

    rule = ACEL3L4{};

    if (!parseHeader(a, rule.action, rule.direction, err))
        return false;

    auto protocol = protocolFromString(a[4]);

    if (!protocol || *protocol == 255) {
        err = "invalid protocol '" + a[4] + "'";
        return false;
    }

    rule.protocol = *protocol;

    for (size_t i = 5; i < a.size(); i += 2) {
        if (i + 1 >= a.size()) {
            err = "missing value for '" + a[i] + "'";
            return false;
        }

        const std::string& key = a[i];
        const std::string& value = a[i + 1];

        if (key == "src") {
            if (!parseIp(value, rule.srcIP)) {
                err = "invalid source ip '" + value + "'";
                return false;
            }
        }
        else if (key == "dst") {
            if (!parseIp(value, rule.dstIP)) {
                err = "invalid destination ip '" + value + "'";
                return false;
            }
        }
        else if (key == "sport") {
            if (!parsePort(value, rule.srcPort)) {
                err = "invalid source port '" + value + "'";
                return false;
            }
        }
        else if (key == "dport") {
            if (!parsePort(value, rule.dstPort)) {
                err = "invalid destination port '" + value + "'";
                return false;
            }
        }
        else {
            err = "unknown option '" + key + "'";
            return false;
        }
    }

    if ((rule.srcPort != 0 || rule.dstPort != 0) &&
        rule.protocol != IP_PROTO_TCP && rule.protocol != IP_PROTO_UDP) {
        err = "sport/dport require protocol tcp or udp";
        return false;
    }

    return true;
}

static bool parseL2Rule(const Args& a, ACEL2& rule, std::string& err) {
    if (a.size() < 4) {
        err = "usage: <add|update> l2 <index> <permit|deny> <in|out> [src <mac>] [dst <mac>] [type <ethertype>]";
        return false;
    }

    rule = ACEL2{};

    if (!parseHeader(a, rule.action, rule.direction, err))
        return false;

    for (size_t i = 4; i < a.size(); i += 2) {
        if (i + 1 >= a.size()) {
            err = "missing value for '" + a[i] + "'";
            return false;
        }

        const std::string& key = a[i];
        const std::string& value = a[i + 1];

        if (key == "src") {
            if (!parseMac(value, rule.srcMAC)) {
                err = "invalid source mac '" + value + "'";
                return false;
            }
        }
        else if (key == "dst") {
            if (!parseMac(value, rule.dstMAC)) {
                err = "invalid destination mac '" + value + "'";
                return false;
            }
        }
        else if (key == "type") {
            if (!parseEtherType(value, rule.etherType)) {
                err = "invalid ethertype '" + value + "'";
                return false;
            }
        }
        else {
            err = "unknown option '" + key + "'";
            return false;
        }
    }


    return true;
}

static void showL3L4(const EbpfLoader& loader) {
    auto rules = loader.getACEL3L4();

    std::cout << "ACL L3/L4 (" << rules.size() << " entries)\n";

    for (size_t i = 0; i < rules.size(); ++i)
        std::cout << "  " << formatL3L4(i, rules[i]) << '\n';
}

static void showL2(const EbpfLoader& loader) {
    auto rules = loader.getACEL2();

    std::cout << "ACL L2 (" << rules.size() << " entries)\n";

    for (size_t i = 0; i < rules.size(); ++i)
        std::cout << "  " << formatL2(i, rules[i]) << '\n';
}

static void printHelp() {
    std::cout <<
        "commands:\n"
        "  show [l2|l3]\n"
        "  show ace <l2|l3> <index>\n"
        "  add l3 <index|end> <permit|deny> <in|out> <protocol> [src <ip|any>] [sport <port|any>] [dst <ip|any>] [dport <port|any>]\n"
        "  add l2 <index|end> <permit|deny> <in|out> [src <mac|any>] [dst <mac|any>] [type <ethertype>]\n"
        "  update l3 <index> <permit|deny> <in|out> <protocol> [src <ip|any>] [sport <port|any>] [dst <ip|any>] [dport <port|any>]\n"
        "  update l2 <index> <permit|deny> <in|out> [src <mac|any>] [dst <mac|any>] [type <ethertype>]\n"
        "  delete <l2|l3> <index>\n"
        "  help\n"
        "  exit\n";
}

static void handleShow(const EbpfLoader& loader, const Args& tokens) {
    if (tokens.size() == 1) {
        showL2(loader);
        showL3L4(loader);
        return;
    }

    if (tokens.size() == 2 && tokens[1] == "l2") {
        showL2(loader);
        return;
    }

    if (tokens.size() == 2 && tokens[1] == "l3") {
        showL3L4(loader);
        return;
    }

    std::cout << "usage: show [l2|l3] | show ace <l2|l3> <index>\n";
}

static void handleShowAce(const EbpfLoader& loader, const Args& a) {
    if (a.size() != 2 || (a[0] != "l2" && a[0] != "l3")) {
        std::cout << "usage: show ace <l2|l3> <index>\n";
        return;
    }

    size_t index = 0;

    if (!parseIndex(a[1], 0, false, index)) {
        std::cout << "invalid index\n";
        return;
    }

    if (a[0] == "l2") {
        auto rule = loader.getACEL2At(index);

        if (rule)
            std::cout << formatL2(index, *rule) << '\n';
        else
            std::cout << "ACE not found\n";

        return;
    }

    auto rule = loader.getACEL3L4At(index);

    if (rule)
        std::cout << formatL3L4(index, *rule) << '\n';
    else
        std::cout << "ACE not found\n";
}

static void handleAddUpdate(EbpfLoader& loader, const Args& a, bool isAdd) {
    const char* verb = isAdd ? "add" : "update";

    if (a.size() < 2 || (a[0] != "l2" && a[0] != "l3")) {
        std::cout << "usage: " << verb << " <l2|l3> <index> ...\n";
        return;
    }

    const bool isL2 = a[0] == "l2";
    const size_t count = isL2 ? loader.countL2() : loader.countL3L4();
    size_t index = 0;

    if (!parseIndex(a[1], count, isAdd, index)) {
        std::cout << "invalid index\n";
        return;
    }

    std::string err;
    bool ok = false;

    if (isL2) {
        ACEL2 rule{};

        if (!parseL2Rule(a, rule, err)) {
            std::cout << err << '\n';
            return;
        }

        ok = isAdd ? loader.addACEL2(rule, index) : loader.updateACEL2(rule, index);
    }
    else {
        ACEL3L4 rule{};

        if (!parseL3Rule(a, rule, err)) {
            std::cout << err << '\n';
            return;
        }

        ok = isAdd ? loader.addACEL3L4(rule, index) : loader.updateACEL3L4(rule, index);
    }

    if (ok)
        std::cout << (isAdd ? "ACE added\n" : "ACE updated\n");
    else
        std::cout << "failed to " << verb << " ACE (index out of range, table full, or invalid rule)\n";
}

static void handleDelete(EbpfLoader& loader, const Args& a) {
    if (a.size() != 2 || (a[0] != "l2" && a[0] != "l3")) {
        std::cout << "usage: delete <l2|l3> <index>\n";
        return;
    }

    size_t index = 0;

    if (!parseIndex(a[1], 0, false, index)) {
        std::cout << "invalid index\n";
        return;
    }

    bool ok = a[0] == "l2" ? loader.removeACEL2(index) : loader.removeACEL3L4(index);

    std::cout << (ok ? "ACE deleted\n" : "failed to delete ACE\n");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " <interface> <bpf_object> [--test]\n";
        return 1;
    }

    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);

    try {
        EbpfLoader loader(argv[1], argv[2]);

        if (argc > 3 && std::string(argv[3]) == "--test")
            loader.addTestACE();

        std::thread poller([&loader]() {
            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGINT);
            sigaddset(&set, SIGTERM);
            pthread_sigmask(SIG_BLOCK, &set, nullptr);

            while (gRunning.load()) {
                try {
                    loader.pollRingBuffer();
                }
                catch (const std::exception& e) {
                    std::cerr << "poll error: " << e.what() << '\n';
                    gRunning.store(false);
                }
            }
        });

        printHelp();

        std::string line;

        while (gRunning.load()) {
            std::cout << "acl> " << std::flush;

            if (!std::getline(std::cin, line))
                break;

            std::replace(line.begin(), line.end(), '\t', ' ');

            const Args tokens = splitString(line);

            if (tokens.empty())
                continue;

            if (tokens[0] == "help" || tokens[0] == "?") {
                printHelp();
                continue;
            }

            auto [action, args] = getAction(line);

            try {
                switch (action) {
                    case Action::Show:
                        handleShow(loader, tokens);
                        break;
                    case Action::ShowAce:
                        handleShowAce(loader, args);
                        break;
                    case Action::Add:
                        handleAddUpdate(loader, args, true);
                        break;
                    case Action::Update:
                        handleAddUpdate(loader, args, false);
                        break;
                    case Action::Delete:
                        handleDelete(loader, args);
                        break;
                    case Action::Exit:
                        gRunning.store(false);
                        break;
                    case Action::Unknown:
                        std::cout << "unknown command, type 'help'\n";
                        break;
                }
            }
            catch (const std::exception& e) {
                std::cerr << "error: " << e.what() << '\n';
            }
        }

        gRunning.store(false);
        poller.join();
    }
    catch (const std::exception& e) {
        std::cerr << "fatal: " << e.what() << '\n';
        return 1;
    }

    return 0;
}
