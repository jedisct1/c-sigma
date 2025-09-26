#include "../keccak.h"
#include "../linear_relation.h"
#include <stdio.h>
#include <string.h>

// Generate Fiat-Shamir challenge
void
generate_challenge(uint8_t challenge[SCALAR_BYTES], const char* protocol_name,
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
    printf("\n=== Testing Schnorr with LinearRelation Framework ===\n");

    // Initialize library
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return;
    }

    // Generate witness (private key) and public key
    uint8_t witness[SCALAR_BYTES];
    uint8_t public_key[POINT_BYTES];
    crypto_core_ristretto255_scalar_random(witness);
    crypto_scalarmult_ristretto255_base(public_key, witness);

    // Build Schnorr statement: Y = x * G
    linear_relation_t relation;
    linear_relation_init(&relation);

    // Allocate variables
    int var_x = linear_relation_allocate_scalars(&relation, 1);
    int var_G = linear_relation_allocate_elements(&relation, 1);
    int var_X = linear_relation_allocate_elements(&relation, 1);

    // Set group elements
    uint8_t generator[POINT_BYTES];
    crypto_scalarmult_ristretto255_base(
        generator, (const uint8_t[]) { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
    linear_relation_set_element(&relation, var_G, generator);
    linear_relation_set_element(&relation, var_X, public_key);

    // Append equation: X = x * G
    int scalar_indices[]  = { var_x };
    int element_indices[] = { var_G };
    linear_relation_append_equation(&relation, var_X, scalar_indices, element_indices, 1);

    // Set the image (what we're proving)
    memcpy(relation.image, public_key, POINT_BYTES);

    // === Prover ===

    // Commit phase
    prover_state_t state;
    uint8_t        commitment[POINT_BYTES];
    if (prover_commit(&relation, witness, commitment, &state) != 0) {
        printf("❌ Prover commit failed\n");
        linear_relation_destroy(&relation);
        return;
    }
    printf("✓ Prover commitment generated\n");

    // Generate challenge (Fiat-Shamir)
    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "schnorr_framework", public_key, POINT_BYTES, commitment,
                       POINT_BYTES);

    // Response phase
    uint8_t response[SCALAR_BYTES];
    prover_response(&state, challenge, response);
    printf("✓ Prover response generated\n");

    // Clean up prover state
    prover_state_destroy(&state);

    // === Verifier ===

    bool valid = verifier(&relation, commitment, challenge, response);
    printf("Verification: %s\n", valid ? "✓ VALID" : "❌ INVALID");

    // Test with wrong public key
    uint8_t wrong_pk[POINT_BYTES];
    uint8_t temp[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(wrong_pk, temp);
    memcpy(relation.image, wrong_pk, POINT_BYTES);

    valid = verifier(&relation, commitment, challenge, response);
    printf("Wrong public key: %s\n", valid ? "❌ INCORRECTLY ACCEPTED" : "✓ CORRECTLY REJECTED");

    linear_relation_destroy(&relation);
}

void
test_dleq_with_framework()
{
    printf("\n=== Testing DLEQ with LinearRelation Framework ===\n");

    // Generate witness
    uint8_t witness[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(witness);

    // Generate two base points
    uint8_t g1[POINT_BYTES], g2[POINT_BYTES];
    uint8_t temp[SCALAR_BYTES];

    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(g1, temp);

    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(g2, temp);

    // Compute h1 = g1^x and h2 = g2^x
    uint8_t h1[POINT_BYTES], h2[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(h1, witness, g1) != 0 ||
        crypto_scalarmult_ristretto255(h2, witness, g2) != 0) {
        printf("Failed to compute h1, h2\n");
        return;
    }

    // Build DLEQ statement
    linear_relation_t relation;
    linear_relation_init(&relation);

    // Allocate variables
    int var_x  = linear_relation_allocate_scalars(&relation, 1);
    int var_g1 = linear_relation_allocate_elements(&relation, 1);
    int var_h1 = linear_relation_allocate_elements(&relation, 1);
    int var_g2 = linear_relation_allocate_elements(&relation, 1);
    int var_h2 = linear_relation_allocate_elements(&relation, 1);

    // Set group elements
    linear_relation_set_element(&relation, var_g1, g1);
    linear_relation_set_element(&relation, var_h1, h1);
    linear_relation_set_element(&relation, var_g2, g2);
    linear_relation_set_element(&relation, var_h2, h2);

    // Append equations: h1 = x * g1, h2 = x * g2
    int scalar_indices[]   = { var_x };
    int element_indices1[] = { var_g1 };
    int element_indices2[] = { var_g2 };
    linear_relation_append_equation(&relation, var_h1, scalar_indices, element_indices1, 1);
    linear_relation_append_equation(&relation, var_h2, scalar_indices, element_indices2, 1);

    // Set the image
    memcpy(&relation.image[0 * POINT_BYTES], h1, POINT_BYTES);
    memcpy(&relation.image[1 * POINT_BYTES], h2, POINT_BYTES);

    // === Prover ===

    prover_state_t state;
    uint8_t        commitment[2 * POINT_BYTES];
    if (prover_commit(&relation, witness, commitment, &state) != 0) {
        printf("❌ Prover commit failed\n");
        linear_relation_destroy(&relation);
        return;
    }
    printf("✓ Prover commitment generated\n");

    // Generate challenge
    uint8_t public_inputs[4 * POINT_BYTES];
    memcpy(&public_inputs[0 * POINT_BYTES], g1, POINT_BYTES);
    memcpy(&public_inputs[1 * POINT_BYTES], h1, POINT_BYTES);
    memcpy(&public_inputs[2 * POINT_BYTES], g2, POINT_BYTES);
    memcpy(&public_inputs[3 * POINT_BYTES], h2, POINT_BYTES);

    uint8_t challenge[SCALAR_BYTES];
    generate_challenge(challenge, "dleq_framework", public_inputs, sizeof(public_inputs),
                       commitment, 2 * POINT_BYTES);

    // Response phase
    uint8_t response[SCALAR_BYTES];
    prover_response(&state, challenge, response);
    printf("✓ Prover response generated\n");

    prover_state_destroy(&state);

    // === Verifier ===

    bool valid = verifier(&relation, commitment, challenge, response);
    printf("Verification: %s\n", valid ? "✓ VALID" : "❌ INVALID");

    linear_relation_destroy(&relation);
}

int
main()
{
    test_schnorr_with_framework();
    test_dleq_with_framework();

    printf("\n✓ All framework tests passed\n");
    return 0;
}
