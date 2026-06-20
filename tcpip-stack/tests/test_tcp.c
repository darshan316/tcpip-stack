#include "tcp.h"
#include "sim.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
static int pass=0,fail=0;
#define CHECK(c,m) do{ if(c)pass++; else{fail++; printf("  FAIL: %s (%s:%d)\n",m,__FILE__,__LINE__);} }while(0)

static void test_checksum(void)
{
    printf("[tcp checksum]\n");
    uint8_t seg[20]; tcp_hdr_t*h=(tcp_hdr_t*)seg; 
	memset(seg,0,20);
    h->sport=htons(40000); h->dport=htons(7); 
	h->seq=htonl(12345);
    h->data_off=5<<4; h->flags=TCP_SYN; 
	h->window=htons(65535);
    ipv4_t s,d; 
	ip_parse("10.0.0.2",&s); 
	ip_parse("10.0.0.1",&d);
    h->check=htons(inet_checksum_pseudo(s,d,IPPROTO_TCP_,seg,20));
    CHECK(inet_checksum_pseudo(s,d,IPPROTO_TCP_,seg,20)==0,"valid TCP checksum verifies to 0");
    seg[10]^=0xff; /* corrupt */
    CHECK(inet_checksum_pseudo(s,d,IPPROTO_TCP_,seg,20)!=0,"corruption is detected");
}
static void test_states(void)
{
    printf("[tcp state names]\n");
    CHECK(strcmp(tcp_state_name(TCP_ESTABLISHED),"ESTABLISHED")==0,"state name");
    CHECK(strcmp(tcp_state_name(TCP_SYN_RCVD),"SYN_RCVD")==0,"state name 2");
}
static void test_handshake(void)
{
    printf("[tcp handshake+echo+close]\n");
    CHECK(demo_echo(false)==0,"full connection: SYN/SYN-ACK/ACK, echo, FIN handshake");
}
int main(void)
{
    test_checksum(); test_states(); test_handshake();
    printf("\n%d passed, %d failed\n",pass,fail);
    return fail?1:0;
}
