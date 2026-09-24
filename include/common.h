#ifndef ACL_COMMON_H
#define ACL_COMMON_H

/*
 * When compiling the eBPF program, vmlinux.h is already included and
 * provides the kernel types such as u8, u16, u32, u64, __be16, and __be32.
 *
 * When compiling userspace code, vmlinux.h is not included, so we include
 * the standard/Linux type headers and define the required integer aliases.
 */
#ifndef __VMLINUX_H__ // if vmlinux.h is not already included
#include <stdint.h>
#include <linux/types.h>
typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

/* Network-byte-order EtherTypes */
#define ETH_P_IP    0x0008  /* IPv4 */
#define ETH_P_IPV6  0xDD86  /* IPv6 */
#define ETH_P_ARP   0x0608  /* ARP  */

#define IP_PROTO_TCP  6
#define IP_PROTO_UDP  17



#define TCP_FLAG_FIN (1u << 0)  // 0b00000001 = 0x01
#define TCP_FLAG_SYN (1u << 1)  // 0b00000010 = 0x02
#define TCP_FLAG_RST (1u << 2)  // 0b00000100 = 0x04
#define TCP_FLAG_PSH (1u << 3)  // 0b00001000 = 0x08
#define TCP_FLAG_ACK (1u << 4)  // 0b00010000 = 0x10
#define TCP_FLAG_URG (1u << 5)  // 0b00100000 = 0x20
#define TCP_FLAG_ECE (1u << 6)  // 0b01000000 = 0x40
#define TCP_FLAG_CWR (1u << 7)  // 0b10000000 = 0x80

#define MAX_ENTRIES 50

/* Layer-3 ACL rule */
struct ACEL3L4 {
    __be32 srcIP;       /* 0 = any */
    __be32 dstIP;       /* 0 = any */
    __be16 dstPort;     /* 0 = any */
    __be16 srcPort;     /* 0 = any */
    u8     protocol;    /* 0 = any */
    u8     flags;
    u8     action;      /* 0 = Drop, 1 = Pass */
    u8     direction;   /* 0 = Inbound, 1 = Outbound */
    u8     enabled;     /* 0 = Disabled, 1 = Enabled */
};

/* Layer-2 ACL rule */
struct ACEL2 {
    u8     srcMAC[6];      /* all-zero = any */
    u8     dstMAC[6];      /* all-zero = any */
    __be16 etherType;      /* 0 = any */
    u8     action;         /* 0 = Drop, 1 = Pass */
    u8     direction;      /* 0 = Inbound, 1 = Outbound */
    u8     enabled;        /* 0 = Disabled, 1 = Enabled */
};

struct Report {
    u8 aceIndex;
    u64 timestamp;
    u8 type; // 0 = L2, 1 = L3
    u8 direction;   /* 0 = Inbound, 1 = Outbound */
    union {
        struct {
            u8 srcMAC[6];
            u8 dstMAC[6];
            __be16 etherType;
        } l2;

        struct {
            __be32 srcIP;
            __be32 dstIP;
            __be16 dstPort;
            u8 flags;
            __be16 srcPort;
            u8 protocol;
        } l3;
    };
};

#endif /* ACL_COMMON_H */
