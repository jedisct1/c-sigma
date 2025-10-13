#include "../keccak.h"
#include "../linear_relation.h"
#include <stdio.h>
#include <string.h>

// Generate Fiat-Shamir challenge
void
generate_challenge(uint8_t challenge[CSIGMA_SCALAR_BYTES], const char* protocol_name,
                   const uint8_t* public_inputs, size_t public_inputs_len,
                   const uint8_t* commitment, size_t commitment_len)
{
    shake128_ctx ctx;
    shake128_init(&ctx);

    shake128_absorb(&ctx, (const uint8_t*) protocol_name, strlen(protocol_name));

    if (public_inputs && public_inputs_len > 0) {
        shake128_absorb(&ctx, public_inputs, public_inputs_len);
    }

    shake128_absorb(&ctx, commitment, commitment_len);

    uint8_t challenge_bytes[64];
    shake128_squeeze(&ctx, challenge_bytes, 64);
    crypto_core_ristretto255_scalar_reduce(challenge, challenge_bytes);
}

void
test_schnorr_with_framework()
{
    printf("\n=== Testing Schnorr with LinearRelation Framework (Simplified API) ===\n");

    // Initialize library
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return;
    }

    // Generate witness (private key) and public key
    uint8_t witness[CSIGMA_SCALAR_BYTES];
    uint8_t public_key[CSIGMA_POINT_BYTES];
    crypto_core_ristretto255_scalar_random(witness);
    crypto_scalarmult_ristretto255_base(public_key, witness);

    // Build Schnorr statement: Y = x * G using simplified API
    linear_relation_t relation;
    csigma_relation_init(&relation);

    // Get generator
    uint8_t generator[CSIGMA_POINT_BYTES];
    crypto_scalarmult_ristretto255_base(
        generator, (const uint8_t[]) { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });

    // SIMPLIFIED API: Add elements and scalar in one step
    int G = csigma_relation_add_element(&relation, generator);
    int X = csigma_relation_add_element(&relation, public_key);
    int x = csigma_relation_add_scalar(&relation);

    // SIMPLIFIED API: Add equation with single term
    csigma_relation_add_equation_simple(&relation, X, x, G);

    // Set the image (what we're proving)
    memcpy(relation.image, public_key, CSIGMA_POINT_BYTES);

    // === Prover ===

    // Commit phase
    prover_state_t state;
    uint8_t        commitment[CSIGMA_POINT_BYTES];
    if (csigma_prover_commit(&relation, witness, commitment, &state) != 0) {
        printf("Prover commit failed\n");
        csigma_relation_destroy(&relation);
        return;
    }
    printf("Prover commitment generated\n");

    // Generate challenge (Fiat-Shamir)
    uint8_t challenge[CSIGMA_SCALAR_BYTES];
    generate_challenge(challenge, "schnorr_framework", public_key, CSIGMA_POINT_BYTES, commitment,
                       CSIGMA_POINT_BYTES);

    // Response phase
    uint8_t response[CSIGMA_SCALAR_BYTES];
    csigma_prover_response(&state, challenge, response);
    printf("Prover response generated\n");

    // Clean up prover state
    csigma_prover_state_destroy(&state);

    // === Verifier ===

    bool valid = csigma_verify(&relation, commitment, challenge, response);
    printf("Verification: %s\n", valid ? "VALID" : "INVALID");

    // Test with wrong public key
    uint8_t wrong_pk[CSIGMA_POINT_BYTES];
    uint8_t temp[CSIGMA_SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(wrong_pk, temp);
    memcpy(relation.image, wrong_pk, CSIGMA_POINT_BYTES);

    valid = csigma_verify(&relation, commitment, challenge, response);
    printf("Wrong public key: %s\n", valid ? "INCORRECTLY ACCEPTED" : "CORRECTLY REJECTED");

    csigma_relation_destroy(&relation);
}

void
test_dleq_with_framework()
{
    printf("\n=== Testing DLEQ with LinearRelation Framework ===\n");

    // Generate witness
    uint8_t witness[CSIGMA_SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(witness);

    // Generate two base points
    uint8_t g1[CSIGMA_POINT_BYTES], g2[CSIGMA_POINT_BYTES];
    uint8_t temp[CSIGMA_SCALAR_BYTES];

    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(g1, temp);

    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(g2, temp);

    // Compute h1 = g1^x and h2 = g2^x
    uint8_t h1[CSIGMA_POINT_BYTES], h2[CSIGMA_POINT_BYTES];
    if (crypto_scalarmult_ristretto255(h1, witness, g1) != 0 ||
        crypto_scalarmult_ristretto255(h2, witness, g2) != 0) {
        printf("Failed to compute h1, h2\n");
        return;
    }

    // Build DLEQ statement using simplified API
    linear_relation_t relation;
    csigma_relation_init(&relation);

    // Add elements in one step
    int var_g1 = csigma_relation_add_element(&relation, g1);
    int var_h1 = csigma_relation_add_element(&relation, h1);
    int var_g2 = csigma_relation_add_element(&relation, g2);
    int var_h2 = csigma_relation_add_element(&relation, h2);
    int var_x  = csigma_relation_add_scalar(&relation);

    // Add equations: h1 = x * g1, h2 = x * g2
    csigma_relation_add_equation_simple(&relation, var_h1, var_x, var_g1);
    csigma_relation_add_equation_simple(&relation, var_h2, var_x, var_g2);

    // Set the image
    memcpy(&relation.image[0 * CSIGMA_POINT_BYTES], h1, CSIGMA_POINT_BYTES);
    memcpy(&relation.image[1 * CSIGMA_POINT_BYTES], h2, CSIGMA_POINT_BYTES);

    // === Prover ===

    prover_state_t state;
    uint8_t        commitment[2 * CSIGMA_POINT_BYTES];
    if (csigma_prover_commit(&relation, witness, commitment, &state) != 0) {
        printf("Prover commit failed\n");
        csigma_relation_destroy(&relation);
        return;
    }
    printf("Prover commitment generated\n");

    // Generate challenge
    uint8_t public_inputs[4 * CSIGMA_POINT_BYTES];
    memcpy(&public_inputs[0 * CSIGMA_POINT_BYTES], g1, CSIGMA_POINT_BYTES);
    memcpy(&public_inputs[1 * CSIGMA_POINT_BYTES], h1, CSIGMA_POINT_BYTES);
    memcpy(&public_inputs[2 * CSIGMA_POINT_BYTES], g2, CSIGMA_POINT_BYTES);
    memcpy(&public_inputs[3 * CSIGMA_POINT_BYTES], h2, CSIGMA_POINT_BYTES);

    uint8_t challenge[CSIGMA_SCALAR_BYTES];
    generate_challenge(challenge, "dleq_framework", public_inputs, sizeof(public_inputs),
                       commitment, 2 * CSIGMA_POINT_BYTES);

    // Response phase
    uint8_t response[CSIGMA_SCALAR_BYTES];
    csigma_prover_response(&state, challenge, response);
    printf("Prover response generated\n");

    csigma_prover_state_destroy(&state);

    // === Verifier ===

    bool valid = csigma_verify(&relation, commitment, challenge, response);
    printf("Verification: %s\n", valid ? "VALID" : "INVALID");

    csigma_relation_destroy(&relation);
}

int
main()
{
    test_schnorr_with_framework();
    test_dleq_with_framework();

    printf("\nAll framework tests passed\n");
    return 0;
}
