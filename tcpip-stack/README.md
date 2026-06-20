# tcpip-stack — a userspace TCP/IP stack (ARP - IPv4 - ICMP  - TCP)

A small but real TCP/IP stack in C that lives entirely in user space. It does
ARP resolution, IPv4 with header checksums, ICMP echo (ping), and a
working TCP: the 3-way handshake, in-order data delivery with ACKs, and the
FIN/ACK connection teardown — enough to run a TCP echo server that a real client
can talk to. It runs as a no-privilege simulator (two stacks wired together) and
as a real host over a Linux TAP interface.

## Why this exists
This is the "how does a packet actually become a connection" project. Switching
and routing move frames, this shows the endpoint side the checksum math over
the pseudo header, sequence/acknowledgement bookkeeping and the TCP state
machine (LISTEN → SYN_RCVD → ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED and
the active open / FIN-WAIT side). Writing a stack from scratch is the standard
way to prove you understand TCP rather than just use it.

## TCP state machine (both sides exercised by stack echo)

 server: LISTEN --recv SYN--------> SYN_RCVD --recv ACK-----> ESTABLISHED
 client: (connect) --send SYN-----> SYN_SENT --recv SYN/ACK-> ESTABLISHED
                         data + ACK + echo flow
 client: ESTABLISHED --send FIN---> FIN_WAIT_1 -> FIN_WAIT_2 -> CLOSED
 server: ESTABLISHED --recv FIN---> CLOSE_WAIT --send FIN----> LAST_ACK -> CLOSED


## Receive path (one Ethernet frame)

 frame ─▶ Ethernet demux
        ├─ ARP  → learn sender, reply to requests for us, release queued packets
        └─ IPv4 → verify header checksum, is it for us?
                 ├─ ICMP echo request → echo reply
                 └─ TCP → verify pseudo-header checksum → tcp_input() state machine


## Layout
| file | what it is |
|------|------------|
| eth.[ch]   | Ethernet II framing + MAC helpers |
| ip.[ch]    | IPv4 headers, RFC 1071 checksum, TCP/UDP pseudo-header checksum |
| arp.[ch]   | ARP cache + request/reply |
| tcp.[ch]   | the TCP segment format and state machine (the core) |
| stack.[ch] | netif glue: Ethernet→ARP/IP→ICMP/TCP, ARP pending queue |
| sim.[ch]   | event wire + server/client apps for the echo & ping demos |
| tap.[ch]   | Linux TAP backend |
| tests/     | unit tests: pseudo-header checksum + full handshake/echo/close |

## Build & test
sh
make          # builds ./stack
make test     # checksum + state machine + end-to-end handshake (5 checks)


## Try it (no root needed)
sh
./stack echo   # watch SYN/SYN-ACK/ACK, "hello" echoed, then FIN -> both CLOSED
./stack ping   # ICMP echo request/reply over the stack


client: connection ESTABLISHED -> send "hello"
server: recv hello  -> echoing back
client: got echo "hello" -> closing
Result: handshake + echo + clean close = OK


## Run it for real (Linux, root) — talk to it with a real client
sh
sudo ./stack tap tap0 10.0.0.5/24 10.0.0.1 02:00:00:00:00:05
# in another shell, give the kernel side an address on the same subnet:
sudo ip addr add 10.0.0.1/24 dev tap0 && sudo ip link set tap0 up
ping 10.0.0.5            # answered by our ICMP
nc 10.0.0.5 7            # type a line, the userspace TCP echoes it back


## Concepts demonstrated
ARP resolution + pending queue, IPv4 header checksum, ICMP echo, TCP
3-way handshake, sequence/ack numbers & SYN/FIN "ghost" bytes, pseudo header
checksum, TCP state machine incl, active/passive close,TAP I/O.

## Deliberately out of scope
Retransmission timers, congestion control, window scaling, out-of-order
reassembly and options/SACK omitted so the state machine stays readable.
The seam (tcp_output / tcp_input) is where a retransmit queue would attach.
