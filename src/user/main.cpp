#include "loader.hpp"
#include "utils.hpp"
#include <csignal>
#include <iomanip>
#include <iostream>
#include <thread>

static std::atomic<bool> gRunning{true};

static void onSignal(int) {
    gRunning.store(false);
}

using Args = std::vector<std::string>;

namespace Color {
    static bool enabled = isatty(fileno(stdout));

    inline std::string wrap(const char* code, const std::string& s) {
        if (!enabled) return s;
        return std::string(code) + s + "\033[0m";
    }

    constexpr const char* Bold  = "\033[1m";
    constexpr const char* Green = "\033[32m";
    constexpr const char* Red  = "\033[31m";
    constexpr const char* Yellow = "\033[33m";
    constexpr const char* Cyan = "\033[36m";
    constexpr const char* Dim = "\033[2m";
    constexpr const char* Reset  = "\033[0m";
}

static std::string c(const char* code, const std::string& s) {
    return Color::wrap(code, s);
}

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

static std::string colorAction(uint8_t action) {
    return action ? c(Color::Green, "permit") : c(Color::Red, "deny  ");
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
        err = "usage: <add|update> l3 <index> <permit|deny> <in|out> <protocol> "
              "[src <ip|any>] [sport <port|any>] [dst <ip|any>] [dport <port|any>] [flags <list|any>]";
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
        else if (key == "flags") {
            u8 parsedFlags = 0;

            if (!parseFlags(value, parsedFlags)) {
                err = "invalid flags '" + value + "' (comma list of fin,syn,rst,psh,ack,urg,ece,cwr or 'any')";
                return false;
            }

            if (parsedFlags != 0 && rule.protocol != IP_PROTO_TCP) {
                err = "flags require protocol tcp";
                return false;
            }

            rule.flags = parsedFlags;
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

    std::cout << "\n" << c(Color::Bold, "ACL L3/L4") << "  "
               << c(Color::Dim, "(" + std::to_string(rules.size()) + " entries)") << "\n";

    if (rules.empty()) {
        std::cout << c(Color::Dim, "  (no rules)\n");
        return;
    }

    std::cout << c(Color::Dim,
        (std::ostringstream{}
            << std::left
            << std::setw(4)  << "IDX"
            << std::setw(9)  << "ACTION"
            << std::setw(6)  << "PROTO"
            << std::setw(24) << "SOURCE"
            << std::setw(24) << "DESTINATION"
            << std::setw(18) << "FLAGS"
            << std::setw(4)  << "DIR").str())
        << "\n";
    std::cout << c(Color::Dim, std::string(89, '-')) << "\n";

    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& r = rules[i];

        std::string src = ipToCiscoString(r.srcIP) + portToCiscoString(r.srcPort);
        std::string dst = ipToCiscoString(r.dstIP) + portToCiscoString(r.dstPort);

        std::cout << std::left
                   << std::setw(4)  << i
                   << colorAction(r.action) << "  "
                   << std::setw(6)  << protocolToString(r.protocol)
                   << std::setw(24) << src
                   << std::setw(24) << dst
                   << std::setw(18) << flagsToString(r.flags)
                   << (r.direction == 0 ? "in" : "out")
                   << "\n";
    }
    std::cout << "\n";
}

static void showL2(const EbpfLoader& loader) {
    auto rules = loader.getACEL2();

    std::cout << "\n" << c(Color::Bold, "ACL L2") << "  "
               << c(Color::Dim, "(" + std::to_string(rules.size()) + " entries)") << "\n";

    if (rules.empty()) {
        std::cout << c(Color::Dim, "  (no rules)\n");
        return;
    }

    std::cout << c(Color::Dim,
        (std::ostringstream{}
            << std::left
            << std::setw(4)  << "IDX"
            << std::setw(9)  << "ACTION"
            << std::setw(20) << "SRC MAC"
            << std::setw(20) << "DST MAC"
            << std::setw(10) << "ETYPE"
            << std::setw(4)  << "DIR").str())
        << "\n";
    std::cout << c(Color::Dim, std::string(67, '-')) << "\n";

    for (size_t i = 0; i < rules.size(); ++i) {
        const auto& r = rules[i];

        std::cout << std::left
                   << std::setw(4)  << i
                   << colorAction(r.action) << "  "
                   << std::setw(20) << macToString(r.srcMAC)
                   << std::setw(20) << macToString(r.dstMAC)
                   << std::setw(10) << etherTypeToString(r.etherType)
                   << (r.direction == 0 ? "in" : "out")
                   << "\n";
    }
    std::cout << "\n";
}

static void printHelp() {
    std::cout << "\n" << c(Color::Bold, "ACL CLI — commands") << "\n"
        << c(Color::Cyan, "  Show") << "\n"
        << "    show [l2|l3]                        list rules (both if omitted)\n"
        << "    show ace <l2|l3> <index>             show a single rule\n\n"
        << c(Color::Cyan, "  Add / Update (L3)") << "\n"
        << "    add l3 <index|end> <permit|deny> <in|out> <protocol>\n"
        << "        [src <ip|any>] [sport <port|any>]\n"
        << "        [dst <ip|any>] [dport <port|any>] [flags <list|any>]\n"
        << c(Color::Dim, "        e.g. add l3 0 deny in tcp src 192.168.0.162 dport 80 flags syn") << "\n"
        << "    update l3 <index> ...                 same options as add\n\n"
        << c(Color::Cyan, "  Add / Update (L2)") << "\n"
        << "    add l2 <index|end> <permit|deny> <in|out>\n"
        << "        [src <mac|any>] [dst <mac|any>] [type <ethertype>]\n"
        << "    update l2 <index> ...                 same options as add\n\n"
        << c(Color::Cyan, "  Manage") << "\n"
        << "    delete <l2|l3> <index>               remove a rule (asks to confirm)\n"
        << "    help | ?                             show this message\n"
        << "    exit                                  quit\n\n"
        << c(Color::Dim, "  flags: fin,syn,rst,psh,ack,urg,ece,cwr (comma list) or 'any'") << "\n";
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
        std::cout << c(Color::Red, "invalid index") << "\n";
        return;
    }

    if (a[0] == "l2") {
        auto rule = loader.getACEL2At(index);

        if (rule)
            std::cout << formatL2(index, *rule) << '\n';
        else
            std::cout << c(Color::Red, "ACE not found") << "\n";

        return;
    }

    auto rule = loader.getACEL3L4At(index);

    if (rule)
        std::cout << formatL3L4(index, *rule) << '\n';
    else
        std::cout << c(Color::Red, "ACE not found") << "\n";
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
        std::cout << c(Color::Red, "invalid index") << "\n";
        return;
    }

    std::string err;
    bool ok = false;

    if (isL2) {
        ACEL2 rule{};

        if (!parseL2Rule(a, rule, err)) {
            std::cout << c(Color::Red, err) << "\n";
            return;
        }

        ok = isAdd ? loader.addACEL2(rule, index) : loader.updateACEL2(rule, index);
    }
    else {
        ACEL3L4 rule{};

        if (!parseL3Rule(a, rule, err)) {
            std::cout << c(Color::Red, err) << "\n";
            return;
        }

        ok = isAdd ? loader.addACEL3L4(rule, index) : loader.updateACEL3L4(rule, index);
    }

    if (ok)
        std::cout << c(Color::Green, isAdd ? "ACE added" : "ACE updated") << "\n";
    else
        std::cout << c(Color::Red, std::string("failed to ") + verb +
                        " ACE (index out of range, table full, or invalid rule)") << "\n";
}

static void handleDelete(EbpfLoader& loader, const Args& a) {
    if (a.size() != 2 || (a[0] != "l2" && a[0] != "l3")) {
        std::cout << "usage: delete <l2|l3> <index>\n";
        return;
    }

    size_t index = 0;

    if (!parseIndex(a[1], 0, false, index)) {
        std::cout << c(Color::Red, "invalid index") << "\n";
        return;
    }

    if (a[0] == "l2") {
        auto rule = loader.getACEL2At(index);
        if (!rule) {
            std::cout << c(Color::Red, "ACE not found") << "\n";
            return;
        }
        std::cout << "  " << formatL2(index, *rule) << "\n";
    } else {
        auto rule = loader.getACEL3L4At(index);
        if (!rule) {
            std::cout << c(Color::Red, "ACE not found") << "\n";
            return;
        }
        std::cout << "  " << formatL3L4(index, *rule) << "\n";
    }

    std::cout << c(Color::Yellow, "delete this rule? [y/N] ") << std::flush;

    std::string confirm;
    std::getline(std::cin, confirm);

    if (confirm != "y" && confirm != "Y") {
        std::cout << "cancelled\n";
        return;
    }

    bool ok = a[0] == "l2" ? loader.removeACEL2(index) : loader.removeACEL3L4(index);

    std::cout << (ok ? c(Color::Green, "ACE deleted") : c(Color::Red, "failed to delete ACE")) << "\n";
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
            std::cout << c(Color::Bold, "") << c(Color::Cyan, "acl> ") << std::flush;

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
                        std::cout << c(Color::Yellow, "unknown command, type 'help'") << "\n";
                        break;
                }
            }
            catch (const std::exception& e) {
                std::cerr << c(Color::Red, std::string("error: ") + e.what()) << '\n';
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
