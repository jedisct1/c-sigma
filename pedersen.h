#ifndef PEDERSEN_H
#define PEDERSEN_H

#include "linear_relation.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Pedersen commitment representation proof (spec section 2.2.9)
// REPR(G, H, C) = PoK{(x, r): C = x*G + r*H}
// Proves knowledge of the opening (x, r) of a Pedersen commitment C

#define PEDERSEN_PROOF_SIZE 96 // 1 commitment (32 bytes) + 2 responses (64 bytes)

// Create Pedersen commitment: C = x*G + r*H
// Returns 0 on success, -1 on failure
int pedersen_commit(uint8_t commitment[POINT_BYTES], const uint8_t value[SCALAR_BYTES],
                    const uint8_t randomness[SCALAR_BYTES], const uint8_t G[POINT_BYTES],
                    const uint8_t H[POINT_BYTES]);

// Prove knowledge of Pedersen commitment opening
// proof: output 128-byte proof
// value: secret value x
// randomness: secret randomness r
// G, H: base points
// C: commitment = x*G + r*H
// message: context message to bind
int pedersen_prove(uint8_t proof[PEDERSEN_PROOF_SIZE], const uint8_t value[SCALAR_BYTES],
                   const uint8_t randomness[SCALAR_BYTES], const uint8_t G[POINT_BYTES],
                   const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES],
                   const uint8_t* message, size_t message_len);

// Verify Pedersen commitment opening proof
bool pedersen_verify(const uint8_t proof[PEDERSEN_PROOF_SIZE], const uint8_t G[POINT_BYTES],
                     const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES],
                     const uint8_t* message, size_t message_len);

// Build Pedersen representation proof statement using LinearRelation
// This demonstrates how to construct the proof using the general framework
void pedersen_build_relation(linear_relation_t* relation, const uint8_t G[POINT_BYTES],
                             const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES]);

#endif
