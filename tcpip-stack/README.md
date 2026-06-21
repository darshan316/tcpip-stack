# Userspace TCP/IP Stack

A small TCP/IP stack written in C that runs entirely in user space. It implements
ARP, IPv4, ICMP, and a working subset of TCP, including the connection handshake
and teardown. It can run as a simulator and as a real network endpoint on a Linux
TAP interface.

## Overview

Most programs rely on the operating system's built-in networking. This project
builds that networking from the ground up: resolving addresses with ARP, handling
IP packets and their checksums, answering pings, and running a TCP connection
through its full lifecycle. A TCP echo server built on the stack can talk to
ordinary client tools.

## What it implements

- ARP for address resolution, with a queue for packets waiting on a reply
- IPv4 with header checksum verification
- ICMP echo (ping)
- TCP: the three-way handshake, in-order data with acknowledgements, and the
  connection close
- The TCP connection state machine for both the client and server sides

## How it works

When a frame arrives, the stack identifies whether it is an ARP message or an IP
packet. ARP requests for its address are answered and the sender is recorded. For
IP packets the header checksum is verified, and a ping is answered with an echo
reply. A TCP segment is checked against its checksum and handed to the connection
state machine, which advances through the standard states: listening, accepting a
connection request, established, and the closing sequence. Sequence and
acknowledgement numbers are tracked so data is delivered in order, and the echo
server sends received data back to the sender.

## Project structure

- eth: Ethernet framing and address helpers
- ip: IPv4 headers, the Internet checksum, and the TCP checksum helper
- arp: the ARP cache and message handling
- tcp: the TCP segment format and the connection state machine
- stack: ties Ethernet, ARP, IP, ICMP, and TCP together
- sim: wires two stacks together for the demonstrations
- tap: connects the stack to a Linux TAP interface
- tests: unit tests for the checksum and the full handshake

## Building and running

Build the project and run the tests:

    make
    make test

Run the built-in demonstrations (no special privileges needed):

- ./stack echo : a TCP connection from handshake to data echo to a clean close
- ./stack ping : an ICMP ping handled by the stack

## Running for real (Linux)

Start the stack on a TAP interface, then talk to it from ordinary tools:

    sudo ./stack tap tap0 10.0.0.5/24 10.0.0.1 02:00:00:00:00:05
    sudo ip addr add 10.0.0.1/24 dev tap0
    sudo ip link set tap0 up
    ping 10.0.0.5
    nc 10.0.0.5 7

## Concepts demonstrated

ARP resolution, IPv4 and checksums, ICMP echo, the TCP three-way handshake,
sequence and acknowledgement numbers, the TCP state machine, and connection
teardown.

## Limitations

To keep the state machine readable, the stack does not implement retransmission
timers, congestion control, window scaling, or out-of-order reassembly.
