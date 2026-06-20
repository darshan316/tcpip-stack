#include "ip.h"
#include <stdio.h>
#include <arpa/inet.h>   /* htons etc; portable enough for the parse helpers */

bool ip_parse(const char *s, ipv4_t *out){
    unsigned a,b,c,d;
    if(sscanf(s,"%u.%u.%u.%u",&a,&b,&c,&d)!=4) return false;
    if(a>255||b>255||c>255||d>255) return false;
    *out=(a<<24)|(b<<16)|(c<<8)|d;
    return true;
}
char *ip_str(ipv4_t a, char *buf){
    sprintf(buf,"%u.%u.%u.%u",(a>>24)&0xff,(a>>16)&0xff,(a>>8)&0xff,a&0xff);
    return buf;
}
ipv4_t ip_netmask(int p){
    if(p<=0) return 0;
    if(p>=32) return 0xffffffffu;
    return 0xffffffffu << (32-p);
}
uint16_t inet_checksum(const void *buf, size_t len){
    const uint8_t *p=buf; uint32_t sum=0;
    while(len>1){ sum += (uint16_t)((p[0]<<8)|p[1]); p+=2; len-=2; }
    if(len) sum += (uint16_t)(p[0]<<8);
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (uint16_t)~sum;
}

uint16_t inet_checksum_pseudo(ipv4_t src, ipv4_t dst, uint8_t proto,const void *l4, size_t l4len){
    /* sum the 12-byte pseudo-header, then continue over the L4 segment */
    uint8_t ph[12];
    ph[0]=src>>24; ph[1]=src>>16; ph[2]=src>>8; ph[3]=src;
    ph[4]=dst>>24; ph[5]=dst>>16; ph[6]=dst>>8; ph[7]=dst;
    ph[8]=0; ph[9]=proto; ph[10]=l4len>>8; ph[11]=l4len&0xff;
    uint32_t sum=0; const uint8_t *p=ph;
    for(int i=0;i<12;i+=2) sum += (uint16_t)((p[i]<<8)|p[i+1]);
    p=l4; size_t len=l4len;
    while(len>1){ sum += (uint16_t)((p[0]<<8)|p[1]); p+=2; len-=2; }
    if(len) sum += (uint16_t)(p[0]<<8);
    while(sum>>16) sum=(sum&0xffff)+(sum>>16);
    return (uint16_t)~sum;
}
