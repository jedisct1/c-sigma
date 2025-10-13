#ifndef PEDERSEN_H
#define PEDERSEN_H

#include "csigma.h"
#include "linear_relation.h"

// Pedersen commitment representation proof (spec section 2.2.9)
// REPR(G, H, C) = PoK{(x, r): C = x*G + r*H}
// Proves knowledge of the opening (x, r) of a Pedersen commitment C

// Create Pedersen commitment: C = x*G + r*H
// Returns 0 on success, -1 on failure
int csigma_pedersen_commit(uint8_t       commitment[CSIGMA_POINT_BYTES],
                           const uint8_t value[CSIGMA_SCALAR_BYTES],
                           const uint8_t randomness[CSIGMA_SCALAR_BYTES],
                           const uint8_t G[CSIGMA_POINT_BYTES],
                           const uint8_t H[CSIGMA_POINT_BYTES]);

// Prove knowledge of Pedersen commitment opening
// proof: output 96-byte proof (commitment + 2 responses)
// value: secret value x
// randomness: secret randomness r
// G, H: base points
// C: commitment = x*G + r*H
// message: context message to bind
// Returns 0 on success, -1 on error
int csigma_pedersen_prove(uint8_t       proof[CSIGMA_PEDERSEN_PROOF_SIZE],
                          const uint8_t value[CSIGMA_SCALAR_BYTES],
                          const uint8_t randomness[CSIGMA_SCALAR_BYTES],
                          const uint8_t G[CSIGMA_POINT_BYTES], const uint8_t H[CSIGMA_POINT_BYTES],
                          const uint8_t C[CSIGMA_POINT_BYTES], const uint8_t* message,
                          size_t message_len);

// Verify Pedersen commitment opening proof
// Returns true if valid, false otherwise
bool csigma_pedersen_verify(const uint8_t proof[CSIGMA_PEDERSEN_PROOF_SIZE],
                            const uint8_t G[CSIGMA_POINT_BYTES],
                            const uint8_t H[CSIGMA_POINT_BYTES],
                            const uint8_t C[CSIGMA_POINT_BYTES], const uint8_t* message,
                            size_t message_len);

#endif
