CC     ?= gcc
CFLAGS ?= -std=c11 -Wall -Wextra -O2 -Iinclude
CORE    = src/ip.c src/eth.c src/arp.c src/tcp.c src/stack.c src/sim.c
OBJ     = $(CORE:.c=.o) src/tap.o

all: stack

stack: $(OBJ) src/main.o
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: $(CORE:.c=.o) tests/test_tcp.o
	$(CC) $(CFLAGS) -o run_tests $(CORE:.c=.o) tests/test_tcp.o
	./run_tests

clean:
	rm -f src/*.o tests/*.o stack run_tests
.PHONY: all test clean
