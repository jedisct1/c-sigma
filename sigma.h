#ifndef SIGMA_H
#define SIGMA_H

#include "keccak.h"
#include <sodium.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Sigma protocols using Ristretto255 group
// Direct byte array sizes - no wrapper types needed
#define SCALAR_BYTES 32
#define POINT_BYTES  32

// Schnorr proof: commitment (32) + response (32)
#define SCHNORR_PROOF_SIZE 64

// Chaum-Pedersen proof: commitment1 (32) + commitment2 (32) + response (32)
#define CHAUM_PEDERSEN_PROOF_SIZE 96

// Initialize library (just wraps sodium_init)
int sigma_init(void);

// Schnorr protocol - prove knowledge of discrete log
// Proves: I know x such that Y = x*G
int schnorr_prove(uint8_t        proof[SCHNORR_PROOF_SIZE],
                  const uint8_t  witness[SCALAR_BYTES], // x
                  const uint8_t  public_key[POINT_BYTES], // Y = x*G
                  const uint8_t* message, size_t message_len);

bool schnorr_verify(const uint8_t proof[SCHNORR_PROOF_SIZE], const uint8_t public_key[POINT_BYTES],
                    const uint8_t* message, size_t message_len);

// Chaum-Pedersen protocol - prove discrete log equality
// Proves: log_g1(h1) = log_g2(h2)
int chaum_pedersen_prove(uint8_t       proof[CHAUM_PEDERSEN_PROOF_SIZE],
                         const uint8_t witness[SCALAR_BYTES], // x such that h1 = g1^x and h2 = g2^x
                         const uint8_t g1[POINT_BYTES], const uint8_t h1[POINT_BYTES],
                         const uint8_t g2[POINT_BYTES], const uint8_t h2[POINT_BYTES],
                         const uint8_t* message, size_t message_len);

bool chaum_pedersen_verify(const uint8_t proof[CHAUM_PEDERSEN_PROOF_SIZE],
                           const uint8_t g1[POINT_BYTES], const uint8_t h1[POINT_BYTES],
                           const uint8_t g2[POINT_BYTES], const uint8_t h2[POINT_BYTES],
                           const uint8_t* message, size_t message_len);

#endif
