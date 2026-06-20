/* sim.h - wire two stacks together to demo TCP and ICMP without root. */
#ifndef SIM_H
#define SIM_H
#include <stdbool.h>
int demo_echo(bool verbose);   /* TCP 3-way handshake + echo + close */
int demo_ping(void);           /* ICMP echo across the wire          */
#endif
