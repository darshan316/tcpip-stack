/* stack.h - the netif glue that turns raw frames into protocol handling:
 * Ethernet demux -> ARP (resolve/learn) / IPv4 (checksum) -> ICMP echo + TCP.
 * One stack_t is one host with one interface. It owns an ARP cache, a pending
 * queue for packets waiting on ARP, and a tcp_stack_t. */
#ifndef STACK_H
#define STACK_H
#include "eth.h"
#include "ip.h"
#include "arp.h"
#include "tcp.h"

#define STK_PENDING 32
typedef struct { uint8_t ip[ETH_MAX]; size_t len; ipv4_t nh; bool valid; } stk_pend_t;

typedef struct stack {
    const char *name;
    ipv4_t ip, mask, gw;
    mac_t  mac;
    arp_table_t arp;
    tcp_stack_t tcp;
    stk_pend_t pend[STK_PENDING];
    void (*tx)(void *ctx, const uint8_t *frame, size_t len);  /* netif transmit */
    void *ctx;
    unsigned long rx, icmp_replies;
} stack_t;

void stack_init(stack_t *s, const char *name, const char *ip, int plen,
                const char *gw, const char *mac,
                void (*tx)(void*,const uint8_t*,size_t), void *ctx);
/* feed one received Ethernet frame */
void stack_rx(stack_t *s, const uint8_t *frame, size_t len);
/* originate an IPv4 packet (handles ARP + framing) */
void stack_ip_send(stack_t *s, ipv4_t dst, uint8_t proto, const uint8_t *l4, size_t l4len);
void stack_ping(stack_t *s, ipv4_t dst, uint16_t seq);
#endif
