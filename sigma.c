#include "sigma.h"
#include "keccak.h"
#include "linear_relation.h"
#include <string.h>

int
sigma_init(void)
{
    return sodium_init();
}

// Fiat-Shamir challenge generation
static void
generate_challenge(uint8_t challenge[SCALAR_BYTES], const char* protocol_name,
                   const uint8_t* public_inputs, size_t public_inputs_len,
                   const uint8_t* commitment, size_t commitment_len, const uint8_t* message,
                   size_t message_len)
{
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, (const uint8_t*) protocol_name, strlen(protocol_name));

    if (public_inputs && public_inputs_len > 0)
        shake128_absorb(&ctx, public_inputs, public_inputs_len);

    shake128_absorb(&ctx, commitment, commitment_len);

    if (message && message_len > 0)
        shake128_absorb(&ctx, message, message_len);

    uint8_t challenge_bytes[64];
    shake128_squeeze(&ctx, challenge_bytes, 64);
    crypto_core_ristretto255_scalar_reduce(challenge, challenge_bytes);
}

// Build Schnorr relation: Y = x*G
static void
build_schnorr_relation(linear_relation_t* relation, const uint8_t public_key[POINT_BYTES])
{
    linear_relation_init(relation);

    int var_x = linear_relation_allocate_scalars(relation, 1);
    linear_relation_allocate_elements(relation, 2);

    // Set generator (index 0) and public key (index 1)
    uint8_t generator[POINT_BYTES];
    uint8_t one[SCALAR_BYTES] = { 1 };
    crypto_scalarmult_ristretto255_base(generator, one);

    linear_relation_set_element(relation, 0, generator);
    linear_relation_set_element(relation, 1, public_key);

    // Equation: public_key = x * generator
    int indices[] = { var_x, 0 };
    linear_relation_append_equation(relation, 1, &indices[0], &indices[1], 1);

    memcpy(relation->image, public_key, POINT_BYTES);
}

// Build DLEQ relation: h1 = x*g1, h2 = x*g2
static void
build_dleq_relation(linear_relation_t* relation, const uint8_t g1[POINT_BYTES],
                    const uint8_t h1[POINT_BYTES], const uint8_t g2[POINT_BYTES],
                    const uint8_t h2[POINT_BYTES])
{
    linear_relation_init(relation);

    int var_x = linear_relation_allocate_scalars(relation, 1);
    linear_relation_allocate_elements(relation, 4);

    // Set elements: g1, h1, g2, h2 at indices 0-3
    linear_relation_set_element(relation, 0, g1);
    linear_relation_set_element(relation, 1, h1);
    linear_relation_set_element(relation, 2, g2);
    linear_relation_set_element(relation, 3, h2);

    // Equations: h1 = x*g1, h2 = x*g2
    int indices[] = { var_x, 0, 2 };
    linear_relation_append_equation(relation, 1, &indices[0], &indices[1], 1);
    linear_relation_append_equation(relation, 3, &indices[0], &indices[2], 1);

    memcpy(&relation->image[0], h1, POINT_BYTES);
    memcpy(&relation->image[POINT_BYTES], h2, POINT_BYTES);
}

// Pack DLEQ public inputs
static void
pack_dleq_inputs(uint8_t out[4 * POINT_BYTES], const uint8_t g1[POINT_BYTES],
                 const uint8_t h1[POINT_BYTES], const uint8_t g2[POINT_BYTES],
                 const uint8_t h2[POINT_BYTES])
{
    memcpy(&out[0], g1, POINT_BYTES);
    memcpy(&out[POINT_BYTES], h1, POINT_BYTES);
    memcpy(&out[2 * POINT_BYTES], g2, POINT_BYTES);
    memcpy(&out[3 * POINT_BYTES], h2, POINT_BYTES);
}

int
schnorr_prove(uint8_t proof[SCHNORR_PROOF_SIZE], const uint8_t witness[SCALAR_BYTES],
              const uint8_t public_key[POINT_BYTES], const uint8_t* message, size_t message_len)
{
    if (!proof || !witness || !public_key)
        return -1;

    linear_relation_t relation;
    build_schnorr_relation(&relation, public_key);

    prover_state_t state;
    uint8_t        commitment[POINT_BYTES];
    if (prover_commit(&relation, witness, commitment, &state) != 0) {
        linear_relation_destroy(&relation);
        return -1;
    }

    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "schnorr", public_key, POINT_BYTES, commitment, POINT_BYTES,
                       message, message_len);

    prover_response(&state, challenge, &proof[POINT_BYTES]);
    memcpy(proof, commitment, POINT_BYTES);

    prover_state_destroy(&state);
    linear_relation_destroy(&relation);
    return 0;
}

bool
schnorr_verify(const uint8_t proof[SCHNORR_PROOF_SIZE], const uint8_t public_key[POINT_BYTES],
               const uint8_t* message, size_t message_len)
{
    if (!proof || !public_key)
        return false;

    linear_relation_t relation;
    build_schnorr_relation(&relation, public_key);

    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "schnorr", public_key, POINT_BYTES, proof, POINT_BYTES, message,
                       message_len);

    bool valid = verifier(&relation, proof, challenge, &proof[POINT_BYTES]);
    linear_relation_destroy(&relation);
    return valid;
}

int
chaum_pedersen_prove(uint8_t proof[CHAUM_PEDERSEN_PROOF_SIZE], const uint8_t witness[SCALAR_BYTES],
                     const uint8_t g1[POINT_BYTES], const uint8_t h1[POINT_BYTES],
                     const uint8_t g2[POINT_BYTES], const uint8_t h2[POINT_BYTES],
                     const uint8_t* message, size_t message_len)
{
    if (!proof || !witness || !g1 || !h1 || !g2 || !h2)
        return -1;

    linear_relation_t relation;
    build_dleq_relation(&relation, g1, h1, g2, h2);

    prover_state_t state;
    uint8_t        commitment[2 * POINT_BYTES];
    if (prover_commit(&relation, witness, commitment, &state) != 0) {
        linear_relation_destroy(&relation);
        return -1;
    }

    uint8_t public_inputs[4 * POINT_BYTES];
    pack_dleq_inputs(public_inputs, g1, h1, g2, h2);

    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "chaum-pedersen", public_inputs, sizeof(public_inputs),
                       commitment, 2 * POINT_BYTES, message, message_len);

    prover_response(&state, challenge, &proof[2 * POINT_BYTES]);
    memcpy(proof, commitment, 2 * POINT_BYTES);

    prover_state_destroy(&state);
    linear_relation_destroy(&relation);
    return 0;
}

bool
chaum_pedersen_verify(const uint8_t proof[CHAUM_PEDERSEN_PROOF_SIZE], const uint8_t g1[POINT_BYTES],
                      const uint8_t h1[POINT_BYTES], const uint8_t g2[POINT_BYTES],
                      const uint8_t h2[POINT_BYTES], const uint8_t* message, size_t message_len)
{
    if (!proof || !g1 || !h1 || !g2 || !h2)
        return false;

    linear_relation_t relation;
    build_dleq_relation(&relation, g1, h1, g2, h2);

    uint8_t public_inputs[4 * POINT_BYTES];
    pack_dleq_inputs(public_inputs, g1, h1, g2, h2);

    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "chaum-pedersen", public_inputs, sizeof(public_inputs), proof,
                       2 * POINT_BYTES, message, message_len);

    bool valid = verifier(&relation, proof, challenge, &proof[2 * POINT_BYTES]);
    linear_relation_destroy(&relation);
    return valid;
}
