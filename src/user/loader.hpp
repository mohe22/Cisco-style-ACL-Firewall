// loader.hpp
#pragma once

#include "../../include/common.h"
#include "acl.hpp"
#include "logger.hpp"

#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

class EbpfLoader {
public:
    EbpfLoader(const char* ifname, const char* bpfPath);

    EbpfLoader(const EbpfLoader&) = delete;
    EbpfLoader& operator=(const EbpfLoader&) = delete;

    ~EbpfLoader();

    void clean() noexcept;

    bool pollRingBuffer();

    int getPacketFilterIngressFd() const;
    int getPacketFilterEgressFd() const;

    size_t countL3L4() const noexcept;
    size_t countL2() const noexcept;

    bool addACEL3L4(ACEL3L4& rule, size_t insertAt);
    bool removeACEL3L4(size_t index);
    bool updateACEL3L4(ACEL3L4& rule, size_t index);
    std::optional<ACEL3L4> getACEL3L4At(size_t index) const;
    std::vector<ACEL3L4> getACEL3L4() const;

    bool addACEL2( ACEL2& rule, size_t insertAt);
    bool removeACEL2(size_t index);
    bool updateACEL2(ACEL2& rule, size_t index);
    std::optional<ACEL2> getACEL2At(size_t index) const;
    std::vector<ACEL2> getACEL2() const;

    void addTestACE();

private:
    bpf_object* obj_{nullptr};

    AclTable<ACEL2> tableL2_;
    AclTable<ACEL3L4> tableL3L4_;

    bpf_program* packetFilterIngress{nullptr};
    bpf_program* packetFilterEgress{nullptr};

    bpf_map* ACLL2{nullptr};
    bpf_map* ACLL3L4{nullptr};

    int ifIndex{0};
    int attachMode{XDP_FLAGS_SKB_MODE};

    bool attached{false};
    bool tcAttached{false};
    bool hookCreated{false};

    bpf_tc_hook hook{};
    bpf_tc_opts tcOpts{};

    ring_buffer* rb{nullptr};

    Logger logger_;

    [[noreturn]] void fail(const std::string& message);

    static bool validate(const ACEL3L4& rule) noexcept;
    static bool validate(const ACEL2& rule) noexcept;

    static int handleReport(void* ctx, void* data, size_t len);
};
