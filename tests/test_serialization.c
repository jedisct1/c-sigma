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

    // Test 1: Commitment serialization/deserialization
    printf("Test 1: Commitment round-trip... ");
    uint8_t original_commitment[2 * POINT_BYTES];
    uint8_t temp_scalar[SCALAR_BYTES];

    // Generate two random points
    for (int i = 0; i < 2; i++) {
        crypto_core_ristretto255_scalar_random(temp_scalar);
        crypto_scalarmult_ristretto255_base(&original_commitment[i * POINT_BYTES], temp_scalar);
    }

    uint8_t serialized[2 * POINT_BYTES];
    if (serialize_commitment(serialized, original_commitment, 2) != SERIALIZE_OK) {
        printf("❌ Serialization failed\n");
        return 1;
    }

    uint8_t deserialized[2 * POINT_BYTES];
    if (deserialize_commitment(deserialized, serialized, 2 * POINT_BYTES, 2) != SERIALIZE_OK) {
        printf("❌ Deserialization failed\n");
        return 1;
    }

    if (sodium_memcmp(original_commitment, deserialized, 2 * POINT_BYTES) != 0) {
        printf("❌ Data mismatch\n");
        return 1;
    }
    printf("✓\n");

    // Test 2: Response serialization/deserialization
    printf("Test 2: Response round-trip... ");
    uint8_t original_response[3 * SCALAR_BYTES];
    for (int i = 0; i < 3; i++) {
        crypto_core_ristretto255_scalar_random(&original_response[i * SCALAR_BYTES]);
    }

    uint8_t serialized_resp[3 * SCALAR_BYTES];
    if (serialize_response(serialized_resp, original_response, 3) != SERIALIZE_OK) {
        printf("❌ Serialization failed\n");
        return 1;
    }

    uint8_t deserialized_resp[3 * SCALAR_BYTES];
    if (deserialize_response(deserialized_resp, serialized_resp, 3 * SCALAR_BYTES, 3) !=
        SERIALIZE_OK) {
        printf("❌ Deserialization failed\n");
        return 1;
    }

    if (sodium_memcmp(original_response, deserialized_resp, 3 * SCALAR_BYTES) != 0) {
        printf("❌ Data mismatch\n");
        return 1;
    }
    printf("✓\n");

    // Test 3: Complete proof serialization
    printf("Test 3: Complete proof round-trip... ");
    uint8_t proof_buffer[POINT_BYTES + 2 * SCALAR_BYTES];

    int bytes_written = serialize_proof(proof_buffer, original_commitment, 1, original_response, 2);
    if (bytes_written != (int) (POINT_BYTES + 2 * SCALAR_BYTES)) {
        printf("❌ Wrong proof size: %d\n", bytes_written);
        return 1;
    }

    uint8_t unpacked_commitment[POINT_BYTES];
    uint8_t unpacked_response[2 * SCALAR_BYTES];
    if (deserialize_proof(unpacked_commitment, 1, unpacked_response, 2, proof_buffer,
                          bytes_written) != SERIALIZE_OK) {
        printf("❌ Deserialization failed\n");
        return 1;
    }

    if (sodium_memcmp(unpacked_commitment, original_commitment, POINT_BYTES) != 0) {
        printf("❌ Commitment mismatch\n");
        return 1;
    }

    if (sodium_memcmp(unpacked_response, original_response, 2 * SCALAR_BYTES) != 0) {
        printf("❌ Response mismatch\n");
        return 1;
    }
    printf("✓\n");

    // Test 4: Error handling - wrong length
    printf("Test 4: Error handling (wrong length)... ");
    uint8_t bad_buffer[10];
    if (deserialize_commitment(deserialized, bad_buffer, 10, 2) != SERIALIZE_ERROR_BAD_LENGTH) {
        printf("❌ Should have rejected wrong length\n");
        return 1;
    }
    printf("✓\n");

    // Test 5: Error handling - NULL input
    printf("Test 5: Error handling (NULL input)... ");
    if (serialize_commitment(NULL, original_commitment, 1) != SERIALIZE_ERROR_NULL_INPUT) {
        printf("❌ Should have rejected NULL output\n");
        return 1;
    }
    printf("✓\n");

    // Test 6: Proof size calculation
    printf("Test 6: Proof size calculation... ");
    size_t schnorr_size = proof_size(1, 1); // 1 commitment, 1 response
    if (schnorr_size != 64) {
        printf("❌ Wrong Schnorr size: %zu (expected 64)\n", schnorr_size);
        return 1;
    }

    size_t dleq_size = proof_size(2, 1); // 2 commitments, 1 response
    if (dleq_size != 96) {
        printf("❌ Wrong DLEQ size: %zu (expected 96)\n", dleq_size);
        return 1;
    }

    size_t pedersen_size = proof_size(1, 2); // 1 commitment, 2 responses
    if (pedersen_size != 96) {
        printf("❌ Wrong Pedersen size: %zu (expected 96)\n", pedersen_size);
        return 1;
    }
    printf("✓\n");

    printf("\n✓ All serialization tests passed\n");
    return 0;
}
