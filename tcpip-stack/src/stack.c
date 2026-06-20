#include "stack.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

static void send_frame(stack_t *s, mac_t dst, uint16_t et, const uint8_t *p, size_t n)
{
	
    uint8_t fr[ETH_MAX]; 
	size_t fn=eth_build(fr,dst,s->mac,et,p,n); 
	s->tx(s->ctx,fr,fn);
}
static void arp_request(stack_t *s, ipv4_t target)
{
    uint8_t ap[28]; 
	size_t an=arp_build(ap,ARP_OP_REQUEST,s->mac,s->ip,(mac_t){{0}},target);
    send_frame(s,mac_broadcast(),ET_ARP,ap,an);
}
static void l2_send(stack_t *s, ipv4_t nh, const uint8_t *ippkt, size_t iplen)
{
    mac_t dmac;
    if(arp_lookup(&s->arp,nh,&dmac)){ send_frame(s,dmac,ET_IPV4,ippkt,iplen); return; }
	
    for(int i=0;i<STK_PENDING;i++) if(!s->pend[i].valid)
	{
        memcpy(s->pend[i].ip,ippkt,iplen); 
		s->pend[i].len=iplen;
        s->pend[i].nh=nh; s->pend[i].valid=true; 
		break; 
	}
    arp_request(s,nh);
}

static void flush_pending(stack_t *s, ipv4_t ip, mac_t mac)
{
    for(int i=0;i<STK_PENDING;i++) if(s->pend[i].valid && s->pend[i].nh==ip)
	{
        send_frame(s,mac,ET_IPV4,s->pend[i].ip,s->pend[i].len); 
		s->pend[i].valid=false; 
	}
}

void stack_ip_send(stack_t *s, ipv4_t dst, uint8_t proto, const uint8_t *l4, size_t l4len)
{
    uint8_t pkt[ETH_MAX]; 
	ip_hdr_t *h=(ip_hdr_t*)pkt; 
	memset(h,0,sizeof *h);
    h->ver_ihl=0x45; 
	h->tot_len=htons((uint16_t)(sizeof *h+l4len)); 
	h->ttl=64;
    h->proto=proto; 
	h->src=htonl(s->ip); 
	h->dst=htonl(dst);
    h->check=htons(inet_checksum(h,sizeof *h));
    memcpy(pkt+sizeof *h,l4,l4len);
    ipv4_t nh = ip_in_subnet(dst,s->ip,s->mask) ? dst : s->gw;
    l2_send(s,nh,pkt,sizeof(ip_hdr_t)+l4len);
}
/* TCP's l3-send callback: ctx is the stack */
static void tcp_l3(void *ctx, ipv4_t dst, const uint8_t *seg, size_t len)
{
    stack_ip_send((stack_t*)ctx,dst,IPPROTO_TCP_,seg,len);
}

void stack_init(stack_t *s,const char*name,const char*ip,int plen,const char*gw,const char*mac,void (*tx)(void*,const uint8_t*,size_t),void*ctx)
{
    memset(s,0,sizeof *s); 
	s->name=name;
    ip_parse(ip,&s->ip); 
	s->mask=ip_netmask(plen); 
	ip_parse(gw,&s->gw); 
	mac_parse(mac,&s->mac);
    arp_init(&s->arp); 
	s->tx=tx; 
	s->ctx=ctx;
    tcp_init(&s->tcp,s->ip,tcp_l3,s);
}

void stack_ping(stack_t *s, ipv4_t dst, uint16_t seq)
{
    uint8_t m[8]; 
	icmp_echo_t *e=(icmp_echo_t*)m; 
	memset(m,0,8);
    e->type=ICMP_ECHO_REQUEST; 
	e->id=htons(1); 
	e->seq=htons(seq);
    e->check=htons(inet_checksum(m,8));
    stack_ip_send(s,dst,IPPROTO_ICMP_,m,8);
}

void stack_rx(stack_t *s, const uint8_t *frame, size_t len)
{
    if(len<ETH_HLEN) return;
    s->rx++;
    mac_t d=eth_dst(frame);
    if(!mac_is_bcast(d) && !mac_equal(d,s->mac)) return;
    uint16_t et=eth_type(frame);
    if(et==ET_ARP){
        arp_pkt_t a; if(!arp_parse(frame+ETH_HLEN,len-ETH_HLEN,&a)) return;
        mac_t sha; memcpy(sha.addr,a.sha,6); arp_learn(&s->arp,arp_spa(&a),sha);
        flush_pending(s,arp_spa(&a),sha);
        if(a.op==ARP_OP_REQUEST && arp_tpa(&a)==s->ip)
		{
            uint8_t ap[28]; 
			size_t an=arp_build(ap,ARP_OP_REPLY,s->mac,s->ip,sha,arp_spa(&a));
            send_frame(s,sha,ET_ARP,ap,an);
        }
        return;
    }
	
    if(et!=ET_IPV4) return;
    const ip_hdr_t *h=(const ip_hdr_t*)(frame+ETH_HLEN);
    size_t iplen=len-ETH_HLEN;
    if(iplen<sizeof *h || inet_checksum(h,sizeof *h)!=0) return;
    if(ntohl(h->dst)!=s->ip) return;
    ipv4_t src=ntohl(h->src);
    const uint8_t *l4=(const uint8_t*)h+sizeof *h; size_t l4len=iplen-sizeof *h;
    if(h->proto==IPPROTO_ICMP_ && l4len>=sizeof(icmp_echo_t)){
        const icmp_echo_t *q=(const icmp_echo_t*)l4;
        if(q->type==ICMP_ECHO_REQUEST){
            uint8_t r[ETH_MAX]; 
			memcpy(r,l4,l4len); 
			icmp_echo_t*e=(icmp_echo_t*)r;
            e->type=ICMP_ECHO_REPLY; 
			e->check=0; 
			e->check=htons(inet_checksum(r,l4len));
            stack_ip_send(s,src,IPPROTO_ICMP_,r,l4len);
        } else if(q->type==ICMP_ECHO_REPLY)
		{ 
			s->icmp_replies++; 
		}
        return;
    }
    if(h->proto==IPPROTO_TCP_) tcp_input(&s->tcp,src,l4,l4len);
}
