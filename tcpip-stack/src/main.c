/* main.c - driver for the userspace TCP/IP stack.
 *   stack echo     TCP 3-way handshake + echo + close (verbose)
 *   stack ping     ICMP echo over the stack
 *   stack tap <if> <a.b.c.d/len> <gw> <mac>   live: a host on a TAP iface that
 *   answers ping and runs a TCP echo server on port 7
 */
#include "sim.h"
#include "stack.h"
#include "tap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __linux__
#include <unistd.h>
static int g_fd;
static void tap_netif_tx(void*ctx,const unsigned char*f,size_t n){ (void)ctx; if(g_fd>=0) tap_write(g_fd,f,n); }
static void echo_cb(tcb_t*c,const unsigned char*d,size_t n){ tcp_send(c,d,n); }
static int run_tap(int argc,char**argv){
    if(argc!=6){ fprintf(stderr,"usage: tap <if> <a.b.c.d/len> <gw> <mac>\n"); return 1; }
    char ip[32]; int plen; if(sscanf(argv[3],"%31[^/]/%d",ip,&plen)!=2){ fprintf(stderr,"bad cidr\n"); return 1; }
    char name[32]; strncpy(name,argv[2],31); name[31]=0;
    g_fd=tap_open(name);
    if(g_fd<0){ perror("tap_open"); fprintf(stderr,"(needs root / CAP_NET_ADMIN)\n"); return 1; }
    static stack_t s; stack_init(&s,"host",ip,plen,argv[4],argv[5],tap_netif_tx,&s);
    s.tcp.on_data=echo_cb; s.tcp.app_ctx=&s;
    tcp_listen(&s.tcp,7);
    printf("host %s/%d on %s, TCP echo server on :7, answers ping. Ctrl-C to stop.\n",ip,plen,name);
    for(;;){ unsigned char b[ETH_MAX]; int r=tap_read(g_fd,b,sizeof b); if(r>0) stack_rx(&s,b,(size_t)r); }
    return 0;
}
#endif

int main(int argc,char**argv){
    if(argc<2){ printf("usage: %s {echo|ping|tap ...}\n",argv[0]); return 1; }
    if(!strcmp(argv[1],"echo")) return demo_echo(true);
    if(!strcmp(argv[1],"ping")) return demo_ping();
#ifdef __linux__
    if(!strcmp(argv[1],"tap"))  return run_tap(argc,argv);
#endif
    fprintf(stderr,"unknown command '%s'\n",argv[1]); return 1;
}
