#include "../serialization.h"
#include <stdio.h>
#include <string.h>

int
main()
{
    printf("\n=== Testing Serialization API ===\n");

    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }

    // Test 1: Complete proof serialization/deserialization
    printf("Test 1: Complete proof round-trip... ");

    // Generate test data: 2 commitment points + 3 response scalars
    uint8_t original_commitment[2 * CSIGMA_POINT_BYTES];
    uint8_t original_response[3 * CSIGMA_SCALAR_BYTES];
    uint8_t temp_scalar[CSIGMA_SCALAR_BYTES];

    // Generate random commitment points
    for (int i = 0; i < 2; i++) {
        crypto_core_ristretto255_scalar_random(temp_scalar);
        crypto_scalarmult_ristretto255_base(&original_commitment[i * CSIGMA_POINT_BYTES],
                                            temp_scalar);
    }

    // Generate random response scalars
    for (int i = 0; i < 3; i++) {
        crypto_core_ristretto255_scalar_random(&original_response[i * CSIGMA_SCALAR_BYTES]);
    }

    // Serialize proof
    size_t  proof_len = csigma_proof_size(2, 3);
    uint8_t proof_buffer[proof_len];

    if (csigma_serialize_proof(proof_buffer, original_commitment, 2, original_response, 3) != 0) {
        printf("Serialization failed\n");
        return 1;
    }

    // Deserialize proof
    uint8_t unpacked_commitment[2 * CSIGMA_POINT_BYTES];
    uint8_t unpacked_response[3 * CSIGMA_SCALAR_BYTES];

    if (csigma_deserialize_proof(unpacked_commitment, 2, unpacked_response, 3, proof_buffer,
                                 proof_len) != 0) {
        printf("Deserialization failed\n");
        return 1;
    }

    // Verify data matches
    if (sodium_memcmp(original_commitment, unpacked_commitment, 2 * CSIGMA_POINT_BYTES) != 0) {
        printf("Commitment mismatch\n");
        return 1;
    }

    if (sodium_memcmp(original_response, unpacked_response, 3 * CSIGMA_SCALAR_BYTES) != 0) {
        printf("Response mismatch\n");
        return 1;
    }
    printf("PASS\n");

    // Test 2: Schnorr proof size
    printf("Test 2: Schnorr proof size... ");
    size_t schnorr_size = csigma_proof_size(1, 1); // 1 commitment, 1 response
    if (schnorr_size != 64) {
        printf("Wrong Schnorr size: %zu (expected 64)\n", schnorr_size);
        return 1;
    }
    printf("PASS\n");

    // Test 3: DLEQ proof size
    printf("Test 3: DLEQ proof size... ");
    size_t dleq_size = csigma_proof_size(2, 1); // 2 commitments, 1 response
    if (dleq_size != 96) {
        printf("Wrong DLEQ size: %zu (expected 96)\n", dleq_size);
        return 1;
    }
    printf("PASS\n");

    // Test 4: Pedersen proof size
    printf("Test 4: Pedersen proof size... ");
    size_t pedersen_size = csigma_proof_size(1, 2); // 1 commitment, 2 responses
    if (pedersen_size != 96) {
        printf("Wrong Pedersen size: %zu (expected 96)\n", pedersen_size);
        return 1;
    }
    printf("PASS\n");

    // Test 5: Error handling - wrong length
    printf("Test 5: Error handling (wrong length)... ");
    uint8_t bad_buffer[10];
    if (csigma_deserialize_proof(unpacked_commitment, 2, unpacked_response, 3, bad_buffer, 10) ==
        0) {
        printf("Should have rejected wrong length\n");
        return 1;
    }
    printf("PASS\n");

    // Test 6: Error handling - NULL input
    printf("Test 6: Error handling (NULL input)... ");
    if (csigma_serialize_proof(NULL, original_commitment, 1, original_response, 1) == 0) {
        printf("Should have rejected NULL output\n");
        return 1;
    }
    printf("PASS\n");

    // Test 7: Round-trip for Schnorr-sized proof
    printf("Test 7: Schnorr-sized proof round-trip... ");
    uint8_t schnorr_commitment[CSIGMA_POINT_BYTES];
    uint8_t schnorr_response[CSIGMA_SCALAR_BYTES];

    crypto_core_ristretto255_scalar_random(temp_scalar);
    crypto_scalarmult_ristretto255_base(schnorr_commitment, temp_scalar);
    crypto_core_ristretto255_scalar_random(schnorr_response);

    uint8_t schnorr_proof[CSIGMA_SCHNORR_PROOF_SIZE];
    if (csigma_serialize_proof(schnorr_proof, schnorr_commitment, 1, schnorr_response, 1) != 0) {
        printf("Serialization failed\n");
        return 1;
    }

    uint8_t schnorr_commitment_out[CSIGMA_POINT_BYTES];
    uint8_t schnorr_response_out[CSIGMA_SCALAR_BYTES];
    if (csigma_deserialize_proof(schnorr_commitment_out, 1, schnorr_response_out, 1, schnorr_proof,
                                 CSIGMA_SCHNORR_PROOF_SIZE) != 0) {
        printf("Deserialization failed\n");
        return 1;
    }

    if (sodium_memcmp(schnorr_commitment, schnorr_commitment_out, CSIGMA_POINT_BYTES) != 0 ||
        sodium_memcmp(schnorr_response, schnorr_response_out, CSIGMA_SCALAR_BYTES) != 0) {
        printf("Data mismatch\n");
        return 1;
    }
    printf("PASS\n");

    printf("\nAll serialization tests passed\n");
    return 0;
}
