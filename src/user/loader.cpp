// loader.cpp
#include "loader.hpp"
#include "utils.hpp"

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <net/if.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>

EbpfLoader::EbpfLoader(const char* ifname, const char* bpfPath)
    : logger_("acl.log") {

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    obj_ = bpf_object__open_file(bpfPath, nullptr);

    if (!obj_)
        throw std::runtime_error("Failed to open BPF object");

    int err = bpf_object__load(obj_);

    if (err)
        fail("Failed to load BPF object: " + std::string(strerror(-err)));

    ACLL2 = bpf_object__find_map_by_name(obj_, "ACLL2");
    ACLL3L4 = bpf_object__find_map_by_name(obj_, "ACLL3L4");

    if (!ACLL2 || !ACLL3L4)
        fail("Failed to find map: ACLL2 or ACLL3L4");

    bpf_map* ringBuf = bpf_object__find_map_by_name(obj_, "RingBuf");

    if (!ringBuf)
        fail("Failed to find map: RingBuf");

    packetFilterIngress = bpf_object__find_program_by_name(obj_, "packetFilterIngress");

    if (!packetFilterIngress)
        fail("Failed to find program: packetFilterIngress");

    packetFilterEgress = bpf_object__find_program_by_name(obj_, "packetFilterEgress");

    if (!packetFilterEgress)
        fail("Failed to find program: packetFilterEgress");

    if (!tableL2_.initialize(bpf_map__fd(ACLL2)))
        fail("Failed to initialize ACLL2 map");

    if (!tableL3L4_.initialize(bpf_map__fd(ACLL3L4)))
        fail("Failed to initialize ACLL3L4 map");

    ifIndex = static_cast<int>(if_nametoindex(ifname));

    if (ifIndex == 0)
        fail("Failed to get interface index: " + std::string(strerror(errno)));

    int ringBufFd = bpf_map__fd(ringBuf);

    if (ringBufFd < 0)
        fail("Failed to get fd for RingBuf");

    rb = ring_buffer__new(ringBufFd, handleReport, this, nullptr);

    if (!rb)
        fail("Failed to create ring buffer");

    int egressFd = getPacketFilterEgressFd();
    int ingressFd = getPacketFilterIngressFd();

    if (egressFd < 0 || ingressFd < 0)
        fail("Failed to get program file descriptors");

    hook = {};
    hook.sz = sizeof(hook);
    hook.ifindex = ifIndex;
    hook.attach_point = BPF_TC_EGRESS;

    err = bpf_tc_hook_create(&hook);

    if (err == 0)
        hookCreated = true;
    else if (err != -EEXIST)
        fail("Failed to create TC hook: " + std::string(strerror(-err)));

    tcOpts = {};
    tcOpts.sz = sizeof(tcOpts);
    tcOpts.prog_fd = egressFd;
    tcOpts.priority = 1;
    tcOpts.handle = 1;

    err = bpf_tc_attach(&hook, &tcOpts);

    if (err)
        fail("Failed to attach TC egress program: " + std::string(strerror(-err)));

    tcAttached = true;

    err = bpf_xdp_attach(ifIndex, ingressFd, attachMode, nullptr);

    if (err)
        fail("Failed to attach XDP program: " + std::string(strerror(-err)));

    attached = true;

    std::cout << "XDP ingress program attached successfully\n";
    std::cout << "TC egress program attached successfully\n";

    logger_.info("ACL engine started on interface " + std::string(ifname));

    {
        ACEL3L4 rule{};
        rule.protocol = 0;
        rule.action = 1;
        rule.direction = 0;

        if (!addACEL3L4(rule, tableL3L4_.size()))
            throw std::runtime_error("Failed to add L3 permit-any inbound");
    }

    {
        ACEL3L4 rule{};
        rule.protocol = 0;
        rule.action = 1;
        rule.direction = 1;

        if (!addACEL3L4(rule, tableL3L4_.size()))
            throw std::runtime_error("Failed to add L3 permit-any outbound");
    }

    {
        ACEL2 rule{};
        rule.action = 1;
        rule.direction = 0;
        rule.etherType=0;
        std::memset(rule.srcMAC, 0, 6);
        std::memset(rule.dstMAC, 0, 6);
        if (!addACEL2(rule, tableL2_.size()))
            throw std::runtime_error("Failed to add L2 permit-any inbound");
    }

    {
        ACEL2 rule{};
        rule.action = 1;
        rule.direction = 1;
        rule.etherType=0;
        std::memset(rule.srcMAC, 0, 6);
        std::memset(rule.dstMAC, 0, 6);

        if (!addACEL2(rule, tableL2_.size()))
            throw std::runtime_error("Failed to add L2 permit-any outbound");
    }
}

EbpfLoader::~EbpfLoader() {
    clean();
}

void EbpfLoader::clean() noexcept {
    if (attached && ifIndex > 0) {
        int ret = bpf_xdp_detach(ifIndex, attachMode, nullptr);

        if (ret == 0)
            std::cout << "XDP program detached successfully\n";
        else
            std::cerr << "XDP detach failed: " << strerror(-ret) << " (" << ret << ")\n";

        attached = false;
    }

    if (tcAttached) {
        bpf_tc_opts detachOpts{};
        detachOpts.sz = sizeof(detachOpts);
        detachOpts.handle = tcOpts.handle;
        detachOpts.priority = tcOpts.priority;
        tcOpts.flags = BPF_TC_F_REPLACE;
        int ret = bpf_tc_detach(&hook, &detachOpts);

        if (ret == 0)
            std::cout << "TC program detached successfully\n";
        else
            std::cerr << "TC detach failed: " << strerror(-ret) << " (" << ret << ")\n";

        tcAttached = false;
    }

    if (hookCreated) {
        hook.attach_point = static_cast<bpf_tc_attach_point>(BPF_TC_INGRESS | BPF_TC_EGRESS);

        int ret = bpf_tc_hook_destroy(&hook);

        if (ret == 0)
            std::cout << "TC hook destroyed successfully\n";
        else if (ret != -ENOENT)
            std::cerr << "TC hook destroy failed: " << strerror(-ret) << " (" << ret << ")\n";

        hookCreated = false;
    }

    if (rb) {
        ring_buffer__free(rb);
        rb = nullptr;
    }

    if (obj_) {
        bpf_object__close(obj_);
        obj_ = nullptr;
    }
}

bool EbpfLoader::pollRingBuffer() {
    if (!rb)
        return false;

    int ret = ring_buffer__poll(rb, 100);

    if (ret == -EINTR)
        return false;

    if (ret < 0)
        throw std::runtime_error("Ring buffer poll failed: " + std::string(strerror(-ret)));

    return true;
}

int EbpfLoader::getPacketFilterIngressFd() const {
    return bpf_program__fd(packetFilterIngress);
}

int EbpfLoader::getPacketFilterEgressFd() const {
    return bpf_program__fd(packetFilterEgress);
}

size_t EbpfLoader::countL3L4() const noexcept {
    return tableL3L4_.size();
}

size_t EbpfLoader::countL2() const noexcept {
    return tableL2_.size();
}

bool EbpfLoader::addACEL3L4(ACEL3L4& rule, size_t insertAt) {
    if (!validate(rule))
        return false;

    rule.enabled = 1;

    return tableL3L4_.insert(rule, insertAt);
}

bool EbpfLoader::removeACEL3L4(size_t index) {
    return tableL3L4_.remove(index);
}

bool EbpfLoader::updateACEL3L4(ACEL3L4& rule, size_t index) {
    if (!validate(rule))
        return false;

    rule.enabled = 1;

    return tableL3L4_.update(rule, index);
}

std::optional<ACEL3L4> EbpfLoader::getACEL3L4At(size_t index) const {
    if (index >= tableL3L4_.size())
        return std::nullopt;

    return tableL3L4_.entries()[index];
}

std::vector<ACEL3L4> EbpfLoader::getACEL3L4() const {
    return tableL3L4_.entries();
}

bool EbpfLoader::addACEL2(ACEL2& rule, size_t insertAt) {
    if (!validate(rule))
        return false;

    rule.enabled = 1;

    return tableL2_.insert(rule, insertAt);
}

bool EbpfLoader::removeACEL2(size_t index) {
    return tableL2_.remove(index);
}

bool EbpfLoader::updateACEL2(ACEL2& rule, size_t index) {
    if (!validate(rule))
        return false;

    rule.enabled = 1;

    return tableL2_.update(rule, index);
}

std::optional<ACEL2> EbpfLoader::getACEL2At(size_t index) const {
    if (index >= tableL2_.size())
        return std::nullopt;

    return tableL2_.entries()[index];
}

std::vector<ACEL2> EbpfLoader::getACEL2() const {
    return tableL2_.entries();
}

void EbpfLoader::addTestACE() {
    {
        ACEL3L4 rule{};
        inet_pton(AF_INET, "192.168.0.1", &rule.srcIP);
        rule.protocol = 1;
        rule.action = 0;
        rule.direction = 0;

        if (!addACEL3L4(rule, tableL3L4_.size()))
            throw std::runtime_error("Failed to add ACE 0");
    }

    {
        ACEL3L4 rule{};
        rule.protocol = 1;
        rule.action = 0;
        rule.direction = 1;

        if (!addACEL3L4(rule, tableL3L4_.size()))
            throw std::runtime_error("Failed to add ACE 1");
    }

    {
        ACEL3L4 rule{};
        rule.dstPort = htons(8080);
        rule.protocol = 6;
        rule.action = 0;
        rule.direction = 0;

        if (!addACEL3L4(rule, tableL3L4_.size()))
            throw std::runtime_error("Failed to add ACE 2");
    }

    {
        ACEL3L4 rule{};
        rule.dstPort = htons(5353);
        rule.protocol = 17;
        rule.action = 0;
        rule.direction = 0;

        if (!addACEL3L4(rule, tableL3L4_.size()))
            throw std::runtime_error("Failed to add ACE 3");
    }

}

void EbpfLoader::fail(const std::string& message) {
    clean();
    throw std::runtime_error(message);
}

bool EbpfLoader::validate(const ACEL3L4& rule) noexcept {
    if (rule.action > 1 || rule.direction > 1)
        return false;

    if ((rule.srcPort != 0 || rule.dstPort != 0) &&
        rule.protocol != IP_PROTO_TCP && rule.protocol != IP_PROTO_UDP)
        return false;

    return true;
}

bool EbpfLoader::validate(const ACEL2& rule) noexcept {
    return rule.action <= 1 && rule.direction <= 1;
}

int EbpfLoader::handleReport(void* ctx, void* data, size_t len) {
    auto* loader = static_cast<EbpfLoader*>(ctx);
    if (len < sizeof(Report)) {
        loader->logger_.error("Invalid report size: " + std::to_string(len));
        return 0;
    }

    auto* report = static_cast<Report*>(data);

    std::string message = "access-list ";
    message += report->type == 0 ? "ACL-L2" : "ACL-L3L4";
    message += " denied ";

    if (report->type == 0) {
        char srcMAC[18];
        char dstMAC[18];

        std::snprintf(srcMAC, sizeof(srcMAC),
            "%02x:%02x:%02x:%02x:%02x:%02x",
            report->l2.srcMAC[0], report->l2.srcMAC[1],
            report->l2.srcMAC[2], report->l2.srcMAC[3],
            report->l2.srcMAC[4], report->l2.srcMAC[5]);

        std::snprintf(dstMAC, sizeof(dstMAC),
            "%02x:%02x:%02x:%02x:%02x:%02x",
            report->l2.dstMAC[0], report->l2.dstMAC[1],
            report->l2.dstMAC[2], report->l2.dstMAC[3],
            report->l2.dstMAC[4], report->l2.dstMAC[5]);

        char etherType[7];

        std::snprintf(etherType, sizeof(etherType),
            "0x%04x", ntohs(report->l2.etherType));

        message += "ethernet " + std::string(srcMAC) + " -> " +
                   std::string(dstMAC) + " ethertype " +
                   std::string(etherType);
    }
    else if (report->type == 1) {
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];

        if (!inet_ntop(AF_INET, &report->l3.srcIP, srcIP, sizeof(srcIP)))
            std::strcpy(srcIP, "invalid");

        if (!inet_ntop(AF_INET, &report->l3.dstIP, dstIP, sizeof(dstIP)))
            std::strcpy(dstIP, "invalid");

        message += protocolToString(report->l3.protocol);
        message += " " + std::string(srcIP);

        if (report->l3.srcPort != 0)
            message += ":" + std::to_string(ntohs(report->l3.srcPort));

        message += " -> " + std::string(dstIP);

        if (report->l3.dstPort != 0)
            message += ":" + std::to_string(ntohs(report->l3.dstPort));
    }
    else {
        loader->logger_.error("Unknown report type: " + std::to_string(report->type));
        return 0;
    }

    message += " (ACE " + std::to_string(report->aceIndex) + ", " +
               directionToString(report->direction) + ")";

    loader->logger_.denied(message);

    return 0;
}
