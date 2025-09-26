#include "pedersen.h"
#include "keccak.h"
#include <string.h>

// Fiat-Shamir challenge generation for Pedersen proofs
static void
generate_challenge(uint8_t challenge[SCALAR_BYTES], const uint8_t G[POINT_BYTES],
                   const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES],
                   const uint8_t* commitment, size_t commitment_len, const uint8_t* message,
                   size_t message_len)
{
    shake128_ctx ctx;
    shake128_init(&ctx);

    // Domain separation
    shake128_absorb(&ctx, (const uint8_t*) "pedersen_repr", 13);

    // Public inputs: G, H, C
    shake128_absorb(&ctx, G, POINT_BYTES);
    shake128_absorb(&ctx, H, POINT_BYTES);
    shake128_absorb(&ctx, C, POINT_BYTES);

    // Commitment
    shake128_absorb(&ctx, commitment, commitment_len);

    // Message
    if (message && message_len > 0) {
        shake128_absorb(&ctx, message, message_len);
    }

    // Generate and reduce challenge
    uint8_t challenge_bytes[64];
    shake128_squeeze(&ctx, challenge_bytes, 64);
    crypto_core_ristretto255_scalar_reduce(challenge, challenge_bytes);
}

int
pedersen_commit(uint8_t commitment[POINT_BYTES], const uint8_t value[SCALAR_BYTES],
                const uint8_t randomness[SCALAR_BYTES], const uint8_t G[POINT_BYTES],
                const uint8_t H[POINT_BYTES])
{
    // C = value*G + randomness*H
    uint8_t value_G[POINT_BYTES], randomness_H[POINT_BYTES];

    if (crypto_scalarmult_ristretto255(value_G, value, G) != 0) {
        return -1;
    }
    if (crypto_scalarmult_ristretto255(randomness_H, randomness, H) != 0) {
        return -1;
    }
    if (crypto_core_ristretto255_add(commitment, value_G, randomness_H) != 0) {
        return -1;
    }

    return 0;
}

void
pedersen_build_relation(linear_relation_t* relation, const uint8_t G[POINT_BYTES],
                        const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES])
{
    linear_relation_init(relation);

    // Allocate scalars: var_x (value), var_r (randomness)
    int var_x = linear_relation_allocate_scalars(relation, 1);
    int var_r = linear_relation_allocate_scalars(relation, 1);

    // Allocate elements: var_G, var_H, var_C
    int var_G = linear_relation_allocate_elements(relation, 1);
    int var_H = linear_relation_allocate_elements(relation, 1);
    int var_C = linear_relation_allocate_elements(relation, 1);

    // Set element values
    linear_relation_set_element(relation, var_G, G);
    linear_relation_set_element(relation, var_H, H);
    linear_relation_set_element(relation, var_C, C);

    // Append equation: C = x*G + r*H
    int scalar_indices[]  = { var_x, var_r };
    int element_indices[] = { var_G, var_H };
    linear_relation_append_equation(relation, var_C, scalar_indices, element_indices, 2);

    // Set the image
    memcpy(relation->image, C, POINT_BYTES);
}

int
pedersen_prove(uint8_t proof[PEDERSEN_PROOF_SIZE], const uint8_t value[SCALAR_BYTES],
               const uint8_t randomness[SCALAR_BYTES], const uint8_t G[POINT_BYTES],
               const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES], const uint8_t* message,
               size_t message_len)
{
    if (!proof || !value || !randomness || !G || !H || !C) {
        return -1;
    }

    // Build the linear relation
    linear_relation_t relation;
    pedersen_build_relation(&relation, G, H, C);

    // Prepare witness: [value, randomness]
    uint8_t witness[2 * SCALAR_BYTES];
    memcpy(&witness[0 * SCALAR_BYTES], value, SCALAR_BYTES);
    memcpy(&witness[1 * SCALAR_BYTES], randomness, SCALAR_BYTES);

    // Prover commit phase
    prover_state_t state;
    uint8_t        commitment[POINT_BYTES]; // One equation = one commitment point
    if (prover_commit(&relation, witness, commitment, &state) != 0) {
        linear_relation_destroy(&relation);
        return -1;
    }

    // Generate Fiat-Shamir challenge
    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, G, H, C, commitment, POINT_BYTES, message, message_len);

    // Prover response phase
    uint8_t response[2 * SCALAR_BYTES]; // Two scalars in witness
    prover_response(&state, challenge, response);

    // Pack proof: [commitment || response]
    memcpy(proof, commitment, POINT_BYTES);
    memcpy(proof + POINT_BYTES, response, 2 * SCALAR_BYTES);

    // Clean up
    prover_state_destroy(&state);
    linear_relation_destroy(&relation);

    return 0;
}

bool
pedersen_verify(const uint8_t proof[PEDERSEN_PROOF_SIZE], const uint8_t G[POINT_BYTES],
                const uint8_t H[POINT_BYTES], const uint8_t C[POINT_BYTES], const uint8_t* message,
                size_t message_len)
{
    if (!proof || !G || !H || !C) {
        return false;
    }

    // Unpack proof
    const uint8_t* commitment = proof;
    const uint8_t* response   = proof + POINT_BYTES;

    // Build the linear relation
    linear_relation_t relation;
    pedersen_build_relation(&relation, G, H, C);

    // Regenerate challenge
    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, G, H, C, commitment, POINT_BYTES, message, message_len);

    // Verify using general verifier
    bool valid = verifier(&relation, commitment, challenge, response);

    // Clean up
    linear_relation_destroy(&relation);

    return valid;
}
