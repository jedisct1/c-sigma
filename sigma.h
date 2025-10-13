#ifndef SIGMA_H
#define SIGMA_H

#include "csigma.h"

// Simple Sigma protocol API for Schnorr and DLEQ
// For more complex protocols, use the general linear_relation.h framework

// Schnorr protocol - prove knowledge of discrete log
// Proves: I know x such that Y = x*G
// Returns 0 on success, -1 on error
int csigma_schnorr_prove(uint8_t        proof[CSIGMA_SCHNORR_PROOF_SIZE],
                         const uint8_t  witness[CSIGMA_SCALAR_BYTES], // x
                         const uint8_t  public_key[CSIGMA_POINT_BYTES], // Y = x*G
                         const uint8_t* message, size_t message_len);

// Verify Schnorr proof
// Returns true if valid, false otherwise
bool csigma_schnorr_verify(const uint8_t proof[CSIGMA_SCHNORR_PROOF_SIZE],
                           const uint8_t public_key[CSIGMA_POINT_BYTES], const uint8_t* message,
                           size_t message_len);

// DLEQ (Discrete Log Equality) protocol - prove log_g1(h1) = log_g2(h2)
// Also known as Chaum-Pedersen protocol
// Proves: I know x such that h1 = x*g1 AND h2 = x*g2
// Returns 0 on success, -1 on error
int csigma_dleq_prove(uint8_t       proof[CSIGMA_DLEQ_PROOF_SIZE],
                      const uint8_t witness[CSIGMA_SCALAR_BYTES], // x
                      const uint8_t g1[CSIGMA_POINT_BYTES], const uint8_t h1[CSIGMA_POINT_BYTES],
                      const uint8_t g2[CSIGMA_POINT_BYTES], const uint8_t h2[CSIGMA_POINT_BYTES],
                      const uint8_t* message, size_t message_len);

// Verify DLEQ proof
// Returns true if valid, false otherwise
bool csigma_dleq_verify(const uint8_t proof[CSIGMA_DLEQ_PROOF_SIZE],
                        const uint8_t g1[CSIGMA_POINT_BYTES], const uint8_t h1[CSIGMA_POINT_BYTES],
                        const uint8_t g2[CSIGMA_POINT_BYTES], const uint8_t h2[CSIGMA_POINT_BYTES],
                        const uint8_t* message, size_t message_len);

#endif
