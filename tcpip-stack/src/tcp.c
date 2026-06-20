#include "tcp.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

const char *tcp_state_name(tcp_state_t s)
{
    static const char*n[]={"CLOSED","LISTEN","SYN_SENT","SYN_RCVD","ESTABLISHED","FIN_WAIT_1","FIN_WAIT_2","CLOSE_WAIT","LAST_ACK","CLOSING","TIME_WAIT"};
    return n[s];
}
void *app_ctx_of(tcb_t *c){ return c->ts->app_ctx; }

void tcp_init(tcp_stack_t *ts, ipv4_t ip, tcp_l3send_fn l3send, void *l3ctx){
    memset(ts,0,sizeof(*ts));
    ts->ip=ip; ts->l3send=l3send; ts->l3ctx=l3ctx; ts->iss_clock=1000;
}
void tcp_listen(tcp_stack_t *ts, uint16_t port){ ts->listening=true; ts->listen_port=port; }

static tcb_t *tcb_alloc(tcp_stack_t *ts){
    for(int i=0;i<8;i++) if(!ts->tcb[i].used){ memset(&ts->tcb[i],0,sizeof(tcb_t));
        ts->tcb[i].used=true; ts->tcb[i].ts=ts; return &ts->tcb[i]; }
    return NULL;
}
static tcb_t *tcb_find(tcp_stack_t *ts, ipv4_t rip, uint16_t rport, uint16_t lport){
    for(int i=0;i<8;i++){ tcb_t*c=&ts->tcb[i];
        if(c->used && c->remote_ip==rip && c->remote_port==rport && c->local_port==lport) return c; }
    return NULL;
}

/* Build and send one segment. snd_nxt advances by data + SYN/FIN ghost bytes. */
static void tcp_output(tcb_t *c, uint8_t flags, const uint8_t *data, size_t dlen)
{
	
    uint8_t seg[ETH_MAX]; tcp_hdr_t *h=(tcp_hdr_t*)seg;
    memset(h,0,sizeof *h);
    h->sport=htons(c->local_port); h->dport=htons(c->remote_port);
    h->seq=htonl(c->snd_nxt);
    h->ack=htonl(c->rcv_nxt);
    h->data_off=5<<4;                       /* 20-byte header, no options */
    h->flags=flags;
    h->window=htons(65535);
    if(data && dlen) memcpy(seg+sizeof *h,data,dlen);
    size_t seglen=sizeof *h+dlen;
    h->check=0;
    h->check=htons(inet_checksum_pseudo(c->local_ip,c->remote_ip,IPPROTO_TCP_,seg,seglen));
    c->ts->l3send(c->ts->l3ctx,c->remote_ip,seg,seglen);
    c->snd_nxt += dlen + ((flags&TCP_SYN)?1:0) + ((flags&TCP_FIN)?1:0);
}

tcb_t *tcp_connect(tcp_stack_t *ts, uint16_t lport, ipv4_t rip, uint16_t rport)
{
    tcb_t *c=tcb_alloc(ts); if(!c) return NULL;
    c->local_ip=ts->ip; c->local_port=lport; c->remote_ip=rip; c->remote_port=rport;
    c->iss=ts->iss_clock; ts->iss_clock+=64000;
    c->snd_una=c->iss; c->snd_nxt=c->iss;
    c->state=TCP_SYN_SENT;
    tcp_output(c,TCP_SYN,NULL,0);           /* active open */
    return c;
}
void tcp_send(tcb_t *c, const uint8_t *data, size_t len)
{
    if(c->state!=TCP_ESTABLISHED && c->state!=TCP_CLOSE_WAIT) return;
    tcp_output(c,TCP_PSH|TCP_ACK,data,len);
}
void tcp_close(tcb_t *c)
{
    if(c->state==TCP_ESTABLISHED){ tcp_output(c,TCP_FIN|TCP_ACK,NULL,0); c->state=TCP_FIN_WAIT_1; }
    else if(c->state==TCP_CLOSE_WAIT){ tcp_output(c,TCP_FIN|TCP_ACK,NULL,0); c->state=TCP_LAST_ACK; }
}

void tcp_input(tcp_stack_t *ts, ipv4_t src, const uint8_t *seg, size_t len)
{
    if(len<sizeof(tcp_hdr_t)) return;
    const tcp_hdr_t *h=(const tcp_hdr_t*)seg;
    /* verify the segment checksum (covers pseudo-header) */
    uint8_t tmp[ETH_MAX]; memcpy(tmp,seg,len);
    if(inet_checksum_pseudo(src,ts->ip,IPPROTO_TCP_,tmp,len)!=0) return;

    uint16_t sport=ntohs(h->sport), dport=ntohs(h->dport);
    uint32_t seq=ntohl(h->seq), ack=ntohl(h->ack);
    uint8_t  flags=h->flags;
    size_t   hlen=(h->data_off>>4)*4;
    const uint8_t *data=seg+hlen;
    size_t   dlen=len-hlen;

    tcb_t *c=tcb_find(ts,src,sport,dport);

    if(!c){                                 /* no connection: maybe a new one */
        if((flags&TCP_SYN) && !(flags&TCP_ACK) && ts->listening && dport==ts->listen_port){
            c=tcb_alloc(ts); if(!c) return;
            c->local_ip=ts->ip; c->local_port=dport; c->remote_ip=src; c->remote_port=sport;
            c->irs=seq; c->rcv_nxt=seq+1;
            c->iss=ts->iss_clock; ts->iss_clock+=64000;
            c->snd_una=c->iss; c->snd_nxt=c->iss;
            c->state=TCP_SYN_RCVD;
            tcp_output(c,TCP_SYN|TCP_ACK,NULL,0);     /* passive open */
        }
        return;
    }

    switch(c->state){
    case TCP_SYN_SENT:                      /* client awaiting SYN+ACK */
        if((flags&TCP_SYN)&&(flags&TCP_ACK)&&ack==c->snd_nxt){
            c->irs=seq; c->rcv_nxt=seq+1; c->snd_una=ack;
            c->state=TCP_ESTABLISHED;
            tcp_output(c,TCP_ACK,NULL,0);
            if(ts->on_open) ts->on_open(c);
        }
        break;
    case TCP_SYN_RCVD:                      /* server awaiting final ACK */
        if((flags&TCP_ACK)&&ack==c->snd_nxt){ c->snd_una=ack; c->state=TCP_ESTABLISHED;
            if(ts->on_open) ts->on_open(c); }
        break;
    case TCP_ESTABLISHED:
        if(flags&TCP_ACK) c->snd_una=ack;
        if(dlen>0 && seq==c->rcv_nxt){
            c->rcv_nxt += dlen;
            tcp_output(c,TCP_ACK,NULL,0);            /* acknowledge the data */
            if(ts->on_data) ts->on_data(c,data,dlen);
        }
        if((flags&TCP_FIN)&&seq+ (dlen) ==c->rcv_nxt){ /* peer half-closes */
            c->rcv_nxt++; tcp_output(c,TCP_ACK,NULL,0); c->state=TCP_CLOSE_WAIT;
        }
        break;
    case TCP_FIN_WAIT_1:                    /* our FIN sent */
        if((flags&TCP_ACK)&&ack==c->snd_nxt) c->state=TCP_FIN_WAIT_2;
        if((flags&TCP_FIN)&&seq==c->rcv_nxt){ c->rcv_nxt++; tcp_output(c,TCP_ACK,NULL,0);
            c->state=(c->state==TCP_FIN_WAIT_2)?TCP_TIME_WAIT:TCP_CLOSING; }
        break;
    case TCP_FIN_WAIT_2:
        if((flags&TCP_FIN)&&seq==c->rcv_nxt){ c->rcv_nxt++; tcp_output(c,TCP_ACK,NULL,0);
            c->state=TCP_TIME_WAIT; c->used=false; }   /* simplified: close now */
        break;
    case TCP_CLOSING:
        if((flags&TCP_ACK)&&ack==c->snd_nxt){ c->state=TCP_TIME_WAIT; c->used=false; }
        break;
    case TCP_LAST_ACK:                      /* server awaiting ACK of its FIN */
        if((flags&TCP_ACK)&&ack==c->snd_nxt){ c->state=TCP_CLOSED; c->used=false; }
        break;
    default: break;
    }
}
