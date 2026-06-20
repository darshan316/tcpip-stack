/* tcp.h - a minimal but real TCP: 3-way handshake, in-order data with ACKs,
 * and the FIN/ACK close sequence, driven entirely by incoming segments.
 *
 * TCP is segment-driven here: tcp_input() runs the state machine for one
 * received segment and tcp_output() builds/sends one segment (with a correct
 * pseudo-header checksum). It is intentionally a teaching-grade core -- no
 * retransmission timers, congestion control, or window scaling -- but the
 * handshake, sequence/ack bookkeeping, and connection teardown are the real
 * thing and are unit-tested. Segments are handed to / from the network through
 * an l3-send callback, so the same TCP works over the simulator and over TAP. */
#ifndef TCP_H
#define TCP_H
#include "ip.h"
#include "eth.h"

typedef enum {
    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RCVD, TCP_ESTABLISHED,
    TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_CLOSE_WAIT, TCP_LAST_ACK,
    TCP_CLOSING, TCP_TIME_WAIT
} tcp_state_t;
const char *tcp_state_name(tcp_state_t s);

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10

#pragma pack(push,1)
typedef struct {
    uint16_t sport, dport;
    uint32_t seq, ack;
    uint8_t  data_off;     /* header length in 32-bit words, high nibble */
    uint8_t  flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg;
} tcp_hdr_t;
#pragma pack(pop)

struct tcp_stack;
typedef struct tcb {
    bool used;
    ipv4_t   local_ip, remote_ip;
    uint16_t local_port, remote_port;
    tcp_state_t state;
    uint32_t iss, irs, snd_una, snd_nxt, rcv_nxt;
    struct tcp_stack *ts;
} tcb_t;

/* callbacks the application installs */
typedef void (*tcp_data_fn)(tcb_t *c, const uint8_t *data, size_t len);
typedef void (*tcp_open_fn)(tcb_t *c);
/* the network send the stack provides: ship a TCP segment to dst */
typedef void (*tcp_l3send_fn)(void *ctx, ipv4_t dst, const uint8_t *seg, size_t len);

typedef struct tcp_stack {
    tcb_t    tcb[8];
    ipv4_t   ip;
    bool     listening; uint16_t listen_port;
    tcp_data_fn on_data;     /* fires when bytes arrive on any connection */
    tcp_open_fn on_open;     /* fires when a connection becomes ESTABLISHED */
    void    *app_ctx;
    tcp_l3send_fn l3send; void *l3ctx;
    uint32_t iss_clock;      /* deterministic ISS source for reproducibility */
} tcp_stack_t;

void  tcp_init(tcp_stack_t *ts, ipv4_t ip, tcp_l3send_fn l3send, void *l3ctx);
void  tcp_listen(tcp_stack_t *ts, uint16_t port);
tcb_t*tcp_connect(tcp_stack_t *ts, uint16_t lport, ipv4_t rip, uint16_t rport);
void  tcp_send(tcb_t *c, const uint8_t *data, size_t len);
void  tcp_close(tcb_t *c);
/* feed one received TCP segment (src = peer IP) into the state machine */
void  tcp_input(tcp_stack_t *ts, ipv4_t src, const uint8_t *seg, size_t len);
void *app_ctx_of(tcb_t *c);   /* convenience for callbacks */
#endif
