#include "sim.h"
#include "stack.h"
#include <stdio.h>
#include <string.h>

/* ---- event-driven wire connecting exactly two stacks ---- */
typedef struct { stack_t *dst; uint8_t f[ETH_MAX]; size_t n; } evt_t;
static evt_t q[256]; static int qh,qt;
static stack_t *g_a,*g_b;
static void wire_tx_a(void*ctx,const uint8_t*f,size_t n){ (void)ctx; q[qt].dst=g_b; memcpy(q[qt].f,f,n); q[qt].n=n; qt=(qt+1)&255; }
static void wire_tx_b(void*ctx,const uint8_t*f,size_t n){ (void)ctx; q[qt].dst=g_a; memcpy(q[qt].f,f,n); q[qt].n=n; qt=(qt+1)&255; }

/* the "application" on each side records what it received */
typedef struct { char buf[256]; size_t len; int closed_seen; } app_t;
static app_t g_srv_app, g_cli_app;
static bool g_verbose;

static void log_state(const char*who){
    if(!g_verbose) return;
    (void)who;
}

/* server: echo every received segment back to the sender */
static void srv_on_data(tcb_t*c,const uint8_t*d,size_t n){
    app_t*a=(app_t*)app_ctx_of(c);
    if(a->len+n<sizeof a->buf){ memcpy(a->buf+a->len,d,n); a->len+=n; }
    if(g_verbose) printf("  server: recv %.*s  -> echoing back\n",(int)n,d);
    tcp_send(c,d,n);
}
/* client: on connect send a greeting; on echo, verify and close */
static void cli_on_open(tcb_t*c){
    if(g_verbose) printf("  client: connection ESTABLISHED -> send \"hello\"\n");
    tcp_send(c,(const uint8_t*)"hello",5);
}
static void cli_on_data(tcb_t*c,const uint8_t*d,size_t n){
    app_t*a=(app_t*)app_ctx_of(c);
    if(a->len+n<sizeof a->buf){ memcpy(a->buf+a->len,d,n); a->len+=n; }
    if(g_verbose) printf("  client: got echo \"%.*s\" -> closing\n",(int)n,d);
    tcp_close(c);
}

/* when a side reaches CLOSE_WAIT, the "app" closes it (sends its FIN) */
static void auto_close(stack_t*s){
    for(int i=0;i<8;i++) if(s->tcp.tcb[i].used && s->tcp.tcb[i].state==TCP_CLOSE_WAIT)
        tcp_close(&s->tcp.tcb[i]);
}
static void pump(stack_t*srv,stack_t*cli){
    int guard=0;
    while(qh!=qt && guard++<2000){
        evt_t e=q[qh]; qh=(qh+1)&255;
        stack_rx(e.dst,e.f,e.n);
        auto_close(srv); auto_close(cli);
    }
}

int demo_echo(bool verbose){
    g_verbose=verbose; qh=qt=0; memset(&g_srv_app,0,sizeof g_srv_app); memset(&g_cli_app,0,sizeof g_cli_app);
    static stack_t srv,cli; g_a=&srv; g_b=&cli;
    stack_init(&srv,"server","10.0.0.1",24,"10.0.0.1","02:00:00:00:00:01",wire_tx_a,&srv);
    stack_init(&cli,"client","10.0.0.2",24,"10.0.0.2","02:00:00:00:00:02",wire_tx_b,&cli);
    /* wire app callbacks into each TCP stack */
    srv.tcp.on_data=srv_on_data; srv.tcp.app_ctx=&g_srv_app;
    cli.tcp.on_open=cli_on_open; cli.tcp.on_data=cli_on_data; cli.tcp.app_ctx=&g_cli_app;

    if(verbose){
        printf("=== TCP echo over the userspace stack ===\n");
        printf("client 10.0.0.2  ->  server 10.0.0.1:7   (ARP, SYN/SYN-ACK/ACK, data, FIN)\n\n");
    }
    tcp_listen(&srv.tcp,7);
    tcp_connect(&cli.tcp,40000,srv.ip,7);   /* active open: sends SYN */
    pump(&srv,&cli);
    log_state("done");

    int ok = (g_srv_app.len==5 && memcmp(g_srv_app.buf,"hello",5)==0
              && g_cli_app.len==5 && memcmp(g_cli_app.buf,"hello",5)==0);
    int closed = (!srv.tcp.tcb[0].used || srv.tcp.tcb[0].state==TCP_CLOSED)
              && (!cli.tcp.tcb[0].used);
    if(verbose){
        printf("\n  server received: \"%.*s\"\n",(int)g_srv_app.len,g_srv_app.buf);
        printf("  client received: \"%.*s\" (the echo)\n",(int)g_cli_app.len,g_cli_app.buf);
        printf("  server final state: %s\n", srv.tcp.tcb[0].used?tcp_state_name(srv.tcp.tcb[0].state):"CLOSED");
        printf("  client final state: %s\n", cli.tcp.tcb[0].used?tcp_state_name(cli.tcp.tcb[0].state):"CLOSED");
        printf("\nResult: handshake + echo + clean close = %s\n", (ok&&closed)?"OK":"FAIL");
    }
    return (ok&&closed)?0:1;
}

int demo_ping(void){
    qh=qt=0;
    static stack_t a,b; g_a=&a; g_b=&b;
    stack_init(&a,"hostA","10.0.0.2",24,"10.0.0.2","02:00:00:00:00:0a",wire_tx_a,&a);
    stack_init(&b,"hostB","10.0.0.1",24,"10.0.0.1","02:00:00:00:00:0b",wire_tx_b,&b);
    printf("=== ICMP ping over the userspace stack ===\n");
    printf("hostA 10.0.0.2 pings hostB 10.0.0.1 (ARP then echo request/reply)\n\n");
    stack_ping(&a,b.ip,1);
    int guard=0; while(qh!=qt && guard++<200){ evt_t e=q[qh]; qh=(qh+1)&255; stack_rx(e.dst,e.f,e.n); }
    printf("  hostA received %lu echo reply(ies)\n",a.icmp_replies);
    printf("Result: %s\n", a.icmp_replies?"ping success":"FAIL");
    return a.icmp_replies?0:1;
}
