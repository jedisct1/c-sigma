# Sigma Protocols Implementation in C

A complete implementation of [draft-irtf-cfrg-sigma-protocols-00](https://datatracker.ietf.org/doc/draft-irtf-cfrg-sigma-protocols/) using Ristretto255.

## Features

### Protocol Implementations

- Schnorr Protocol: Prove knowledge of discrete logarithm
- DLEQ Protocol: Prove discrete logarithm equality (also known as Chaum-Pedersen)
- Pedersen Commitments: Prove knowledge of commitment opening
- General Framework: Build arbitrary linear relation proofs with simplified API

### Capabilities

- Non-interactive proofs: Fiat-Shamir transformation with SHAKE128
- Both simple and general framework interfaces
- Serialization: Full encode/decode support with validation
- Secure: Built on libsodium's Ristretto255 group operations
- Spec compliant: Full implementation of IETF draft specification

## Quick Start

```c
#include <sodium.h>
#include "sigma.h"

// Initialize libsodium
sodium_init();

// Prove knowledge of private key
uint8_t private_key[CSIGMA_SCALAR_BYTES];
uint8_t public_key[CSIGMA_POINT_BYTES];
uint8_t proof[CSIGMA_SCHNORR_PROOF_SIZE];

crypto_core_ristretto255_scalar_random(private_key);
crypto_scalarmult_ristretto255_base(public_key, private_key);

uint8_t message[] = "Hello";
csigma_schnorr_prove(proof, private_key, public_key, message, sizeof(message));
bool valid = csigma_schnorr_verify(proof, public_key, message, sizeof(message));
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

# Build all executables
make

# Run all tests
make check
```

## API Reference

### Constants

```c
#define CSIGMA_SCALAR_BYTES        32  // Scalar size
#define CSIGMA_POINT_BYTES         32  // Group element size
#define CSIGMA_SCHNORR_PROOF_SIZE  64  // Schnorr proof size
#define CSIGMA_DLEQ_PROOF_SIZE     96  // DLEQ proof size
#define CSIGMA_PEDERSEN_PROOF_SIZE 96  // Pedersen proof size
```

### Schnorr Protocol

Proves knowledge of x where Y = x*G (G is the generator).

```c
// Create proof
int csigma_schnorr_prove(
    uint8_t proof[CSIGMA_SCHNORR_PROOF_SIZE],   // Output: 64-byte proof
    const uint8_t witness[CSIGMA_SCALAR_BYTES], // Secret x
    const uint8_t public_key[CSIGMA_POINT_BYTES], // Public Y = x*G
    const uint8_t *message,                      // Message to bind
    size_t message_len
);
// Returns: 0 on success, -1 on error

// Verify proof
bool csigma_schnorr_verify(
    const uint8_t proof[CSIGMA_SCHNORR_PROOF_SIZE],
    const uint8_t public_key[CSIGMA_POINT_BYTES],
    const uint8_t *message,
    size_t message_len
);
// Returns: true if valid, false otherwise
```

### DLEQ Protocol

Proves that log_g1(h1) = log_g2(h2) without revealing the exponent.

```c
// Create proof
int csigma_dleq_prove(
    uint8_t proof[CSIGMA_DLEQ_PROOF_SIZE],      // Output: 96-byte proof
    const uint8_t witness[CSIGMA_SCALAR_BYTES], // Secret x where h1=g1^x, h2=g2^x
    const uint8_t g1[CSIGMA_POINT_BYTES], const uint8_t h1[CSIGMA_POINT_BYTES],
    const uint8_t g2[CSIGMA_POINT_BYTES], const uint8_t h2[CSIGMA_POINT_BYTES],
    const uint8_t *message,
    size_t message_len
);
// Returns: 0 on success, -1 on error

// Verify proof
bool csigma_dleq_verify(
    const uint8_t proof[CSIGMA_DLEQ_PROOF_SIZE],
    const uint8_t g1[CSIGMA_POINT_BYTES], const uint8_t h1[CSIGMA_POINT_BYTES],
    const uint8_t g2[CSIGMA_POINT_BYTES], const uint8_t h2[CSIGMA_POINT_BYTES],
    const uint8_t *message,
    size_t message_len
);
// Returns: true if valid, false otherwise
```

### Pedersen Commitments

```c
// Create commitment C = x*G + r*H
int csigma_pedersen_commit(
    uint8_t commitment[CSIGMA_POINT_BYTES],
    const uint8_t value[CSIGMA_SCALAR_BYTES],
    const uint8_t randomness[CSIGMA_SCALAR_BYTES],
    const uint8_t G[CSIGMA_POINT_BYTES],
    const uint8_t H[CSIGMA_POINT_BYTES]
);

// Prove knowledge of opening
int csigma_pedersen_prove(
    uint8_t proof[CSIGMA_PEDERSEN_PROOF_SIZE],
    const uint8_t value[CSIGMA_SCALAR_BYTES],
    const uint8_t randomness[CSIGMA_SCALAR_BYTES],
    const uint8_t G[CSIGMA_POINT_BYTES],
    const uint8_t H[CSIGMA_POINT_BYTES],
    const uint8_t C[CSIGMA_POINT_BYTES],
    const uint8_t *message,
    size_t message_len
);

// Verify proof
bool csigma_pedersen_verify(
    const uint8_t proof[CSIGMA_PEDERSEN_PROOF_SIZE],
    const uint8_t G[CSIGMA_POINT_BYTES],
    const uint8_t H[CSIGMA_POINT_BYTES],
    const uint8_t C[CSIGMA_POINT_BYTES],
    const uint8_t *message,
    size_t message_len
);
```

## When to Use Each Protocol

### Schnorr Protocol

What it proves: Knowledge of a secret value (discrete logarithm) without revealing it.

Mathematical property: Proves "I know x such that Y = x*G" where G is the generator and Y is public.

Use cases:

- Digital signatures: Prove you own the private key corresponding to a public key
- Authentication: Log in to a service without transmitting your password
- Cryptocurrency wallets: Prove ownership of funds without revealing private keys
- Access control: Demonstrate you have credentials without exposing them
- Password-authenticated key exchange (PAKE): Establish secure channels based on passwords

Example scenario: Alice wants to prove she owns a Bitcoin address. She uses Schnorr to prove she knows the private key corresponding to the public address, without revealing the private key itself.

### DLEQ Protocol (Chaum-Pedersen)

What it proves: Two discrete logarithms are equal, without revealing the common exponent.

Mathematical property: Proves "log_g1(h1) = log_g2(h2)" or equivalently "h1 = g1^x AND h2 = g2^x" for some secret x.

Use cases:

- Verifiable encryption: Prove a ciphertext encrypts a specific value without decryption
- Anonymous credentials: Show two credentials belong to the same user without revealing identity
- Mix networks: Prove correct re-encryption in privacy protocols
- Cross-chain atomic swaps: Prove same secret is used in multiple transactions
- Verifiable shuffles: Prove a list was correctly permuted without revealing the permutation
- Blind signatures: Prove consistency between blinded and unblinded values

Example scenario: A voting system needs to prove that an encrypted vote was correctly re-encrypted (same vote, different randomness) during the mixing phase, without revealing the actual vote.

## Protocol Comparison

| Aspect        | Schnorr                     | DLEQ (Chaum-Pedersen)         |
| ------------- | --------------------------- | ----------------------------- |
| Proof size    | 64 bytes                    | 96 bytes                      |
| What's proven | Knowledge of one secret     | Equality of two discrete logs |
| Complexity    | Simpler                     | More complex                  |
| Computation   | 2 exponentiations to verify | 4 exponentiations to verify   |
| Primary use   | Authentication, signatures  | Verifiable encryption, DLEQ   |

## API Levels

### Simple API

Convenient functions for common protocols (recommended for most users):

- `csigma_schnorr_prove()` / `csigma_schnorr_verify()`
- `csigma_dleq_prove()` / `csigma_dleq_verify()`
- `csigma_pedersen_prove()` / `csigma_pedersen_verify()`

### Framework API - Simplified Builder (Recommended)

Build arbitrary linear relation proofs with easy-to-use helpers:

```c
// Add elements and scalars in one step
int G = csigma_relation_add_element(&relation, generator);
int X = csigma_relation_add_element(&relation, public_key);
int x = csigma_relation_add_scalar(&relation);

// Add equation with single term (covers 80% of use cases)
csigma_relation_add_equation_simple(&relation, X, x, G);

// Prove and verify
csigma_prover_commit(&relation, witness, commitment, &state);
csigma_prover_response(&state, challenge, response);
bool valid = csigma_verify(&relation, commitment, challenge, response);
```

### Framework API - General (For Complex Multi-term Equations)

For equations like C = x*G + r*H:

```c
// Allocate multiple scalars/elements at once
int x = csigma_relation_allocate_scalars(&relation, 1);
int r = csigma_relation_allocate_scalars(&relation, 1);

// Add elements
int G = csigma_relation_add_element(&relation, G_value);
int H = csigma_relation_add_element(&relation, H_value);

// Multi-term equation
int scalar_indices[] = {x, r};
int element_indices[] = {G, H};
csigma_relation_add_equation(&relation, C, scalar_indices, element_indices, 2);
```

### Serialization API

```c
// Serialize proof
int csigma_serialize_proof(
    uint8_t *output,
    const uint8_t *commitment,
    size_t num_commitment_elements,
    const uint8_t *response,
    size_t num_response_scalars
);

// Deserialize proof (with validation)
int csigma_deserialize_proof(
    uint8_t *commitment,
    size_t num_commitment_elements,
    uint8_t *response,
    size_t num_response_scalars,
    const uint8_t *data,
    size_t data_len
);

// Calculate expected proof size
size_t csigma_proof_size(size_t num_commitment_elements, size_t num_response_scalars);
```

See `tests/test_framework.c` for complete examples of framework usage with the simplified API.

## Implementation Details

- Elliptic Curve Group: Ristretto255 (via libsodium)
- Hash Function: SHAKE128 for Fiat-Shamir challenges
- Proof Sizes:
  - Schnorr: 64 bytes (1 commitment + 1 response)
  - DLEQ: 96 bytes (2 commitments + 1 response)
  - Pedersen: 96 bytes (1 commitment + 2 responses)
- Security: 128-bit security level
- Namespace: All public functions prefixed with `csigma_`
- Error Handling:
  - Prove/create functions return 0 on success, -1 on error
  - Verify functions return true if valid, false otherwise

## Examples

See the following files for complete working examples:

- `example.c` - Simple API demonstrations
- `tests/test_framework.c` - Simplified framework API usage
- `tests/test_sigma.c` - Schnorr and DLEQ tests
- `tests/test_pedersen.c` - Pedersen commitment tests
