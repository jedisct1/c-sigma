CFLAGS = -Wall -Wextra -O2 $(shell pkg-config --cflags libsodium)
LDFLAGS = $(shell pkg-config --libs libsodium)

all: test example

test: test.c sigma.c keccak.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

example: example.c sigma.c keccak.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f test example *.o

.PHONY: all clean
