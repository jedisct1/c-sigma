# Sigma Protocols Implementation in C

A clean, simple C implementation of Sigma protocols with Fiat-Shamir transformation for non-interactive zero-knowledge proofs.

## Features

- Schnorr Protocol: Prove knowledge of discrete logarithm
- Chaum-Pedersen Protocol: Prove discrete logarithm equality (DLEQ)
- Non-interactive proofs: Using Fiat-Shamir transformation with SHAKE128
- Minimal API: Just 6 functions for complete functionality
- No abstractions: Direct use of byte arrays, no wrapper types
- Secure: Built on libsodium's Ristretto255 group operations

## Quick Start

```c
#include "sigma.h"

// Initialize
sigma_init();

// Prove knowledge of private key
uint8_t private_key[32], public_key[32], proof[64];
crypto_core_ristretto255_scalar_random(private_key);
crypto_scalarmult_ristretto255_base(public_key, private_key);

schnorr_prove(proof, private_key, public_key, message, message_len);
bool valid = schnorr_verify(proof, public_key, message, message_len);
```

## Building

Prerequisites:

- C compiler (clang or gcc)
- libsodium development libraries

```bash
# Install libsodium (Ubuntu/Debian)
sudo apt-get install libsodium-dev

# Install libsodium (macOS)
brew install libsodium

# Build
make

# Run tests
./test

# Run examples
./example
```

## API Reference

### Initialization
```c
int sigma_init(void);
```
Initialize the library (wraps sodium_init).

### Schnorr Protocol

Proves knowledge of x where Y = x*G (G is the generator).

```c
// Create proof
int schnorr_prove(
    uint8_t proof[64],                  // Output: 64-byte proof
    const uint8_t witness[32],          // Secret x
    const uint8_t public_key[32],       // Public Y = x*G
    const uint8_t *message,              // Message to bind
    size_t message_len
);

// Verify proof
bool schnorr_verify(
    const uint8_t proof[64],
    const uint8_t public_key[32],
    const uint8_t *message,
    size_t message_len
);
```

### Chaum-Pedersen Protocol

Proves that log_g1(h1) = log_g2(h2) without revealing the exponent.

```c
// Create proof
int chaum_pedersen_prove(
    uint8_t proof[96],                  // Output: 96-byte proof
    const uint8_t witness[32],          // Secret x where h1=g1^x, h2=g2^x
    const uint8_t g1[32], const uint8_t h1[32],
    const uint8_t g2[32], const uint8_t h2[32],
    const uint8_t *message,
    size_t message_len
);

// Verify proof
bool chaum_pedersen_verify(
    const uint8_t proof[96],
    const uint8_t g1[32], const uint8_t h1[32],
    const uint8_t g2[32], const uint8_t h2[32],
    const uint8_t *message,
    size_t message_len
);
```

## Implementation Details

- Elliptic Curve Group: Ristretto255 (via libsodium)
- Hash Function: SHAKE128 for Fiat-Shamir challenges
- Proof Sizes: Fixed - 64 bytes (Schnorr), 96 bytes (Chaum-Pedersen)
- Security: 128-bit security level

## Applications

- Password-authenticated key exchange
- Anonymous credentials
- Verifiable encryption
- Blockchain protocols
- Privacy-preserving authentication
