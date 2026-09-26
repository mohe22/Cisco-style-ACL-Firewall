#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "../../include/common.h"

#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

struct loopLayer2Ctx {
    struct ethhdr *eth;
    u8 direction;
    int result;
};

struct loopL4L3Ctx {
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    u8 direction;
    int result;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct ACEL2);
} ACLL2 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct ACEL3L4);
} ACLL3L4 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024);
} RingBuf SEC(".maps");

static __always_inline int isMacEqual(const u8 *mac1, const u8 *mac2) {
    return mac1[0] == mac2[0] &&
           mac1[1] == mac2[1] &&
           mac1[2] == mac2[2] &&
           mac1[3] == mac2[3] &&
           mac1[4] == mac2[4] &&
           mac1[5] == mac2[5];
}
static __always_inline u8 getTcpFlags(const struct tcphdr *tcp) {
    u8 flags = 0;

    if (tcp->fin)
        flags |= TCP_FLAG_FIN;

    if (tcp->syn)
        flags |= TCP_FLAG_SYN;

    if (tcp->rst)
        flags |= TCP_FLAG_RST;

    if (tcp->psh)
        flags |= TCP_FLAG_PSH;

    if (tcp->ack)
        flags |= TCP_FLAG_ACK;

    if (tcp->urg)
        flags |= TCP_FLAG_URG;

    if (tcp->ece)
        flags |= TCP_FLAG_ECE;

    if (tcp->cwr)
        flags |= TCP_FLAG_CWR;

    return flags;
}
static int checkLayer2Rules(__u64 index, void *data)
{
    struct loopLayer2Ctx *lctx = (struct loopLayer2Ctx *)data;
    u32 i = (u32)index;
    struct ACEL2 *ace = bpf_map_lookup_elem(&ACLL2, &i);

    if (!ace)
        return 0;
    if (!ace->enabled)
        return 0;
    if (ace->direction != lctx->direction)
        return 0;

    u8 zeroMAC[6] = {0};
    if (!isMacEqual(ace->srcMAC, zeroMAC) && !isMacEqual(lctx->eth->h_source, ace->srcMAC))
        return 0;
    if (!isMacEqual(ace->dstMAC, zeroMAC) && !isMacEqual(lctx->eth->h_dest, ace->dstMAC))
        return 0;
    if (ace->etherType != 0 && lctx->eth->h_proto != ace->etherType)
        return 0;

    /* First matching ACE wins */
    if (ace->action) {
        lctx->result = (lctx->direction == 0) ? XDP_PASS : TC_ACT_OK;
    } else {
        struct Report *report = bpf_ringbuf_reserve(&RingBuf, sizeof(struct Report), 0);
        if (report) {
            report->type = 0;
            report->aceIndex = i;
            report->direction = lctx->direction;
            report->timestamp = bpf_ktime_get_ns();
            __builtin_memcpy(report->l2.dstMAC, lctx->eth->h_dest, 6);
            __builtin_memcpy(report->l2.srcMAC, lctx->eth->h_source, 6);
            report->l2.etherType = lctx->eth->h_proto;
            bpf_ringbuf_submit(report, 0);
        }
        lctx->result = (lctx->direction == 0) ? XDP_DROP : TC_ACT_SHOT;
    }
    return 1; /* stop loop */
}

static int checkLayer3Rules(__u64 index, void *data) {
    struct loopL4L3Ctx *lctx = (struct loopL4L3Ctx *)data;
    u32 i = (u32)index;
    struct ACEL3L4 *ace = bpf_map_lookup_elem(&ACLL3L4, &i);
    if (!ace)
        return 0;
    if (!ace->enabled)
        return 0;
    if (ace->direction != lctx->direction)
        return 0;
    if (ace->protocol != 0 && lctx->ip->protocol != ace->protocol)
        return 0;
    if (ace->srcIP != 0 && lctx->ip->saddr != ace->srcIP)
        return 0;
    if (ace->dstIP != 0 && lctx->ip->daddr != ace->dstIP)
        return 0;

    u8 pktFlags = 0;
    if (ace->dstPort != 0 || ace->srcPort != 0) {
        u16 src_port = 0;
        u16 dst_port = 0;
        if (lctx->ip->protocol == IP_PROTO_TCP && lctx->tcp) {
            src_port = lctx->tcp->source;
            dst_port = lctx->tcp->dest;
            pktFlags = getTcpFlags(lctx->tcp);
        } else if (lctx->ip->protocol == IP_PROTO_UDP && lctx->udp) {
            src_port = lctx->udp->source;
            dst_port = lctx->udp->dest;
        }
        if (ace->dstPort != 0 && dst_port != ace->dstPort)
            return 0;
        if (ace->srcPort != 0 && src_port != ace->srcPort)
            return 0;
    }
    // every bit set in ace->flags must also be set in pktFlags
    if (ace->flags != 0)
        if ((pktFlags & ace->flags) != ace->flags)
            return 0;

    /* First matching ACE wins */
    if (ace->action) {
        lctx->result = (lctx->direction == 0) ? XDP_PASS : TC_ACT_OK;
    } else {
        struct Report *report = bpf_ringbuf_reserve(&RingBuf, sizeof(struct Report), 0);
        if (report) {
            report->type = 1;
            report->aceIndex = i;
            report->direction = lctx->direction;
            report->timestamp = bpf_ktime_get_ns();
            report->l3.srcIP = lctx->ip->saddr;
            report->l3.dstIP = lctx->ip->daddr;
            if (lctx->tcp) {
                report->l3.srcPort = lctx->tcp->source;
                report->l3.dstPort = lctx->tcp->dest;
                report->l3.flags = pktFlags;
            } else if (lctx->udp) {
                report->l3.srcPort = lctx->udp->source;
                report->l3.dstPort = lctx->udp->dest;
                report->l3.flags   = 0;
            } else {
                report->l3.srcPort = 0;
                report->l3.dstPort = 0;
                report->l3.flags   = 0;
            }
            report->l3.protocol = lctx->ip->protocol;
            bpf_ringbuf_submit(report, 0);
        }
        lctx->result = (lctx->direction == 0) ? XDP_DROP : TC_ACT_SHOT;
    }
    return 1;
}

SEC("xdp")
int packetFilterIngress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct loopLayer2Ctx lctx2 = {
        .eth = eth,
        .direction = 0,
        .result = -1,          /* undecided */
    };
    bpf_loop(MAX_ENTRIES, checkLayer2Rules, &lctx2, 0);

    if (lctx2.result == -1) {
        struct Report *report = bpf_ringbuf_reserve(&RingBuf, sizeof(struct Report), 0);
        if (report) {
            report->type = 0;
            report->aceIndex = 0xFF;
            report->direction = 0;
            report->timestamp = bpf_ktime_get_ns();
            __builtin_memcpy(report->l2.dstMAC, eth->h_dest, 6);
            __builtin_memcpy(report->l2.srcMAC, eth->h_source, 6);
            report->l2.etherType = eth->h_proto;
            bpf_ringbuf_submit(report, 0);
        }
        return XDP_DROP;
    }
    if (lctx2.result != XDP_PASS)
        return XDP_DROP;

    if (eth->h_proto != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (struct iphdr *)((u8 *)data + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;
    if (ip->ihl < 5)
        return XDP_DROP;
    __u32 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return XDP_DROP;

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    if (ip->protocol == IP_PROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + ip_header_len);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;
    } else if (ip->protocol == IP_PROTO_UDP) {
        udp = (struct udphdr *)((void *)ip + ip_header_len);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;
    }

    struct loopL4L3Ctx lctx3 = {
        .ip = ip,
        .tcp = tcp,
        .udp = udp,
        .direction = 0,
        .result = -1,
    };
    bpf_loop(MAX_ENTRIES, checkLayer3Rules, &lctx3, 0);

    if (lctx3.result == -1) {
        struct Report *report = bpf_ringbuf_reserve(&RingBuf, sizeof(struct Report), 0);
        if (report) {
            report->type = 1;
            report->aceIndex = 0xFF;
            report->direction = 0;
            report->timestamp = bpf_ktime_get_ns();
            report->l3.srcIP = ip->saddr;
            report->l3.dstIP = ip->daddr;
            if (tcp) {
                report->l3.srcPort = tcp->source;
                report->l3.dstPort = tcp->dest;
                report->l3.flags   = getTcpFlags(tcp);
            } else if (udp) {
                report->l3.srcPort = udp->source;
                report->l3.dstPort = udp->dest;
                report->l3.flags   = 0;
            } else {
                report->l3.srcPort = 0;
                report->l3.dstPort = 0;
                report->l3.flags   = 0;
            }
            report->l3.protocol = ip->protocol;
            bpf_ringbuf_submit(report, 0);
        }
        return XDP_DROP;
    }
    if (lctx3.result != XDP_PASS)
        return XDP_DROP;

    return XDP_PASS;
}

SEC("tc")
int packetFilterEgress(struct __sk_buff *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = (struct ethhdr *)data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    struct loopLayer2Ctx lctx2 = {
        .eth = eth,
        .direction = 1,
        .result = -1,
    };
    bpf_loop(MAX_ENTRIES, checkLayer2Rules, &lctx2, 0);

    if (lctx2.result == -1) {
        struct Report *report = bpf_ringbuf_reserve(&RingBuf, sizeof(struct Report), 0);
        if (report) {
            report->type = 0;
            report->aceIndex = 0xFF;
            report->direction = 1;
            report->timestamp = bpf_ktime_get_ns();
            __builtin_memcpy(report->l2.dstMAC, eth->h_dest, 6);
            __builtin_memcpy(report->l2.srcMAC, eth->h_source, 6);
            report->l2.etherType = eth->h_proto;
            bpf_ringbuf_submit(report, 0);
        }
        return TC_ACT_SHOT;
    }
    if (lctx2.result != TC_ACT_OK)
        return TC_ACT_SHOT;

    if (eth->h_proto != ETH_P_IP)
        return TC_ACT_OK;

    struct iphdr *ip = (struct iphdr *)((u8 *)data + sizeof(struct ethhdr));
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_SHOT;
    if (ip->ihl < 5)
        return TC_ACT_SHOT;
    u32 ip_header_len = ip->ihl * 4;
    if ((void *)ip + ip_header_len > data_end)
        return TC_ACT_SHOT;

    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    if (ip->protocol == IP_PROTO_TCP) {
        tcp = (struct tcphdr *)((void *)ip + ip_header_len);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_SHOT;
    } else if (ip->protocol == IP_PROTO_UDP) {
        udp = (struct udphdr *)((void *)ip + ip_header_len);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_SHOT;
    }

    struct loopL4L3Ctx lctx3 = {
        .ip = ip,
        .tcp = tcp,
        .udp = udp,
        .direction = 1,
        .result = -1,
    };
    bpf_loop(MAX_ENTRIES, checkLayer3Rules, &lctx3, 0);

    if (lctx3.result == -1) {
        struct Report *report = bpf_ringbuf_reserve(&RingBuf, sizeof(struct Report), 0);
        if (report) {
            report->type = 1;
            report->aceIndex = 0xFF;
            report->direction = 1;
            report->timestamp = bpf_ktime_get_ns();
            report->l3.srcIP = ip->saddr;
            report->l3.dstIP = ip->daddr;
            if (tcp) {
                report->l3.srcPort = tcp->source;
                report->l3.dstPort = tcp->dest;
                report->l3.flags = getTcpFlags(tcp);
            } else if (udp) {
                report->l3.srcPort = udp->source;
                report->l3.dstPort = udp->dest;
                report->l3.flags = 0;
            } else {
                report->l3.srcPort = 0;
                report->l3.dstPort = 0;
                report->l3.flags = 0;
            }
            report->l3.protocol = ip->protocol;
            bpf_ringbuf_submit(report, 0);
        }
        return TC_ACT_SHOT;
    }
    if (lctx3.result != TC_ACT_OK)
        return TC_ACT_SHOT;    //explicit deny already reported

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
