CFLAGS = -Wall -Wextra -O2 -I. $(shell pkg-config --cflags libsodium)
LDFLAGS = $(shell pkg-config --libs libsodium)

# Core library objects
CORE_OBJS = sigma.c keccak.c linear_relation.c pedersen.c serialization.c

# All executables
all: test_sigma example test_framework test_pedersen test_serialization

test_sigma: tests/test_sigma.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

example: example.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_framework: tests/test_framework.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_pedersen: tests/test_pedersen.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test_serialization: tests/test_serialization.c $(CORE_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Run all tests
check: test_sigma example test_framework test_pedersen test_serialization
	@echo "Running Sigma protocol tests..."
	./test_sigma
	@echo "\nRunning example..."
	./example
	@echo "\nRunning framework tests..."
	./test_framework
	@echo "\nRunning Pedersen tests..."
	./test_pedersen
	@echo "\nRunning serialization tests..."
	./test_serialization
	@echo "\n=== All tests passed ==="

clean:
	rm -f test_sigma example test_framework test_pedersen test_serialization *.o
	rm -rf tests/*.o

.PHONY: all clean check
