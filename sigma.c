#include "sigma.h"
#include "keccak.h"
#include <string.h>

int
sigma_init(void)
{
    return sodium_init();
}

// Fiat-Shamir challenge generation
static void
generate_challenge(uint8_t challenge[SCALAR_BYTES], const char *protocol_name,
                   const uint8_t *public_inputs, size_t public_inputs_len,
                   const uint8_t *commitment, size_t commitment_len, const uint8_t *message,
                   size_t message_len)
{
    shake128_ctx ctx;
    shake128_init(&ctx);

    // Domain separation
    shake128_absorb(&ctx, (const uint8_t *) protocol_name, strlen(protocol_name));

    // Public inputs
    if (public_inputs && public_inputs_len > 0) {
        shake128_absorb(&ctx, public_inputs, public_inputs_len);
    }

    // Commitment
    shake128_absorb(&ctx, commitment, commitment_len);

    // Message
    if (message && message_len > 0) {
        shake128_absorb(&ctx, message, message_len);
    }

    // Generate challenge and reduce to scalar
    uint8_t challenge_bytes[64];
    shake128_squeeze(&ctx, challenge_bytes, 64);
    crypto_core_ristretto255_scalar_reduce(challenge, challenge_bytes);
}

int
schnorr_prove(uint8_t proof[SCHNORR_PROOF_SIZE], const uint8_t witness[SCALAR_BYTES],
              const uint8_t public_key[POINT_BYTES], const uint8_t *message, size_t message_len)
{
    if (!proof || !witness || !public_key)
        return -1;

    // Generate random nonce
    uint8_t nonce[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(nonce);

    // Commitment: A = nonce * G
    uint8_t commitment[POINT_BYTES];
    crypto_scalarmult_ristretto255_base(commitment, nonce);

    // Generate challenge: c = H(pk || A || message)
    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "schnorr", public_key, POINT_BYTES, commitment, POINT_BYTES,
                       message, message_len);

    // Response: z = nonce + c * witness
    uint8_t response[SCALAR_BYTES];
    uint8_t c_times_x[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_mul(c_times_x, challenge, witness);
    crypto_core_ristretto255_scalar_add(response, nonce, c_times_x);

    // Pack proof: [commitment || response]
    memcpy(proof, commitment, POINT_BYTES);
    memcpy(proof + POINT_BYTES, response, SCALAR_BYTES);

    // Clean up sensitive data
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(c_times_x, sizeof(c_times_x));

    return 0;
}

bool
schnorr_verify(const uint8_t proof[SCHNORR_PROOF_SIZE], const uint8_t public_key[POINT_BYTES],
               const uint8_t *message, size_t message_len)
{
    if (!proof || !public_key)
        return false;

    // Unpack proof
    const uint8_t *commitment = proof;
    const uint8_t *response   = proof + POINT_BYTES;

    // Regenerate challenge
    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "schnorr", public_key, POINT_BYTES, commitment, POINT_BYTES,
                       message, message_len);

    // Check: z*G = A + c*Y
    uint8_t left[POINT_BYTES]; // z*G
    crypto_scalarmult_ristretto255_base(left, response);

    uint8_t c_times_y[POINT_BYTES]; // c*Y
    if (crypto_scalarmult_ristretto255(c_times_y, challenge, public_key) != 0) {
        return false;
    }

    uint8_t right[POINT_BYTES]; // A + c*Y
    if (crypto_core_ristretto255_add(right, commitment, c_times_y) != 0) {
        return false;
    }

    return sodium_memcmp(left, right, POINT_BYTES) == 0;
}

int
chaum_pedersen_prove(uint8_t proof[CHAUM_PEDERSEN_PROOF_SIZE], const uint8_t witness[SCALAR_BYTES],
                     const uint8_t g1[POINT_BYTES], const uint8_t h1[POINT_BYTES],
                     const uint8_t g2[POINT_BYTES], const uint8_t h2[POINT_BYTES],
                     const uint8_t *message, size_t message_len)
{
    if (!proof || !witness || !g1 || !h1 || !g2 || !h2)
        return -1;

    // Generate random nonce
    uint8_t nonce[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(nonce);

    // Commitments: A1 = nonce * g1, A2 = nonce * g2
    uint8_t a1[POINT_BYTES], a2[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(a1, nonce, g1) != 0) {
        sodium_memzero(nonce, sizeof(nonce));
        return -1;
    }
    if (crypto_scalarmult_ristretto255(a2, nonce, g2) != 0) {
        sodium_memzero(nonce, sizeof(nonce));
        return -1;
    }

    // Pack public inputs for challenge
    uint8_t public_inputs[4 * POINT_BYTES];
    memcpy(public_inputs, g1, POINT_BYTES);
    memcpy(public_inputs + POINT_BYTES, h1, POINT_BYTES);
    memcpy(public_inputs + 2 * POINT_BYTES, g2, POINT_BYTES);
    memcpy(public_inputs + 3 * POINT_BYTES, h2, POINT_BYTES);

    // Pack commitments
    uint8_t commitments[2 * POINT_BYTES];
    memcpy(commitments, a1, POINT_BYTES);
    memcpy(commitments + POINT_BYTES, a2, POINT_BYTES);

    // Generate challenge
    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "chaum-pedersen", public_inputs, sizeof(public_inputs),
                       commitments, sizeof(commitments), message, message_len);

    // Response: z = nonce + c * witness
    uint8_t response[SCALAR_BYTES];
    uint8_t c_times_x[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_mul(c_times_x, challenge, witness);
    crypto_core_ristretto255_scalar_add(response, nonce, c_times_x);

    // Pack proof: [A1 || A2 || z]
    memcpy(proof, a1, POINT_BYTES);
    memcpy(proof + POINT_BYTES, a2, POINT_BYTES);
    memcpy(proof + 2 * POINT_BYTES, response, SCALAR_BYTES);

    // Clean up
    sodium_memzero(nonce, sizeof(nonce));
    sodium_memzero(c_times_x, sizeof(c_times_x));

    return 0;
}

bool
chaum_pedersen_verify(const uint8_t proof[CHAUM_PEDERSEN_PROOF_SIZE], const uint8_t g1[POINT_BYTES],
                      const uint8_t h1[POINT_BYTES], const uint8_t g2[POINT_BYTES],
                      const uint8_t h2[POINT_BYTES], const uint8_t *message, size_t message_len)
{
    if (!proof || !g1 || !h1 || !g2 || !h2)
        return false;

    // Unpack proof
    const uint8_t *a1       = proof;
    const uint8_t *a2       = proof + POINT_BYTES;
    const uint8_t *response = proof + 2 * POINT_BYTES;

    // Regenerate challenge
    uint8_t public_inputs[4 * POINT_BYTES];
    memcpy(public_inputs, g1, POINT_BYTES);
    memcpy(public_inputs + POINT_BYTES, h1, POINT_BYTES);
    memcpy(public_inputs + 2 * POINT_BYTES, g2, POINT_BYTES);
    memcpy(public_inputs + 3 * POINT_BYTES, h2, POINT_BYTES);

    uint8_t commitments[2 * POINT_BYTES];
    memcpy(commitments, a1, POINT_BYTES);
    memcpy(commitments + POINT_BYTES, a2, POINT_BYTES);

    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "chaum-pedersen", public_inputs, sizeof(public_inputs),
                       commitments, sizeof(commitments), message, message_len);

    // Check: z*g1 = A1 + c*h1
    uint8_t left1[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(left1, response, g1) != 0) {
        return false;
    }

    uint8_t c_times_h1[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(c_times_h1, challenge, h1) != 0) {
        return false;
    }

    uint8_t right1[POINT_BYTES];
    if (crypto_core_ristretto255_add(right1, a1, c_times_h1) != 0) {
        return false;
    }

    if (sodium_memcmp(left1, right1, POINT_BYTES) != 0) {
        return false;
    }

    // Check: z*g2 = A2 + c*h2
    uint8_t left2[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(left2, response, g2) != 0) {
        return false;
    }

    uint8_t c_times_h2[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(c_times_h2, challenge, h2) != 0) {
        return false;
    }

    uint8_t right2[POINT_BYTES];
    if (crypto_core_ristretto255_add(right2, a2, c_times_h2) != 0) {
        return false;
    }

    return sodium_memcmp(left2, right2, POINT_BYTES) == 0;
}