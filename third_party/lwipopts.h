#pragma once

#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_RAW 1
#define LWIP_DNS 1
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_ICMP 1
#define LWIP_ICMP6 1
#define IP_REASSEMBLY 0
#define IPV6_FRAG_COPYHEADER 1
#define LWIP_IPV6_REASS 0
#define LWIP_IPV6_FRAG 0
#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK 1
#define LWIP_NETIF_HOSTNAME 1

#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_NETIF_API 0
#define LWIP_PPP_API 0

#define MEM_LIBC_MALLOC 1
#define MEMP_MEM_MALLOC 1
#define MEM_ALIGNMENT 8
#define MEM_SIZE (4 * 1024 * 1024)

#undef TCP_MSS
#define TCP_MSS 1360
#define TCP_SND_BUF (32 * TCP_MSS)
#define TCP_WND (48 * TCP_MSS)
#define TCP_SND_QUEUELEN (8 * TCP_SND_BUF / TCP_MSS)
#define LWIP_WND_SCALE 1
#define TCP_RCV_SCALE 2
#define MEMP_NUM_TCP_PCB 512
#define MEMP_NUM_TCP_SEG 4096
#define MEMP_NUM_UDP_PCB 512
#define PBUF_POOL_SIZE 4096
#define PBUF_POOL_BUFSIZE 1536
#define TCP_OOSEQ_MAX_BYTES (4 * TCP_WND)
#define TCP_OOSEQ_MAX_PBUFS 64
#define TCP_TMR_INTERVAL 20
#define TCP_FAST_INTERVAL 20

#define DNS_MAX_SERVERS 4
#define DNS_TABLE_SIZE 64
#define DNS_MAX_NAME_LENGTH 255

#undef LWIP_RAND
#define LWIP_RAND() ((u32_t)rand())

#ifdef __cplusplus
extern "C" unsigned int ovpn2ss_lwip_rand();
#endif
