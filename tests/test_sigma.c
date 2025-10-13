#include "sigma.h"
#include <stdio.h>
#include <string.h>

void
print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void
test_schnorr()
{
    printf("\n=== Testing Schnorr Protocol ===\n");

    // Generate witness and public key
    uint8_t witness[CSIGMA_SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(witness);

    uint8_t public_key[CSIGMA_POINT_BYTES];
    crypto_scalarmult_ristretto255_base(public_key, witness);

    // Create proof
    uint8_t proof[CSIGMA_SCHNORR_PROOF_SIZE];
    uint8_t message[] = "Test message";

    if (csigma_schnorr_prove(proof, witness, public_key, message, sizeof(message)) != 0) {
        printf("Failed to create proof\n");
        return;
    }

    printf("Created proof (%zu bytes)\n", sizeof(proof));

    // Verify proof
    if (csigma_schnorr_verify(proof, public_key, message, sizeof(message))) {
        printf("Proof verified successfully\n");
    } else {
        printf("Proof verification failed\n");
    }

    // Test with wrong public key
    uint8_t wrong_pk[CSIGMA_POINT_BYTES];
    uint8_t temp_scalar[CSIGMA_SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(temp_scalar);
    crypto_scalarmult_ristretto255_base(wrong_pk, temp_scalar);

    if (!csigma_schnorr_verify(proof, wrong_pk, message, sizeof(message))) {
        printf("Correctly rejected proof with wrong public key\n");
    } else {
        printf("Incorrectly accepted proof with wrong public key\n");
    }
}

void
test_dleq()
{
    printf("\n=== Testing DLEQ Protocol ===\n");

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
    if (crypto_scalarmult_ristretto255(h1, witness, g1) != 0) {
        printf("Failed to compute h1\n");
        return;
    }
    if (crypto_scalarmult_ristretto255(h2, witness, g2) != 0) {
        printf("Failed to compute h2\n");
        return;
    }

    // Create proof
    uint8_t proof[CSIGMA_DLEQ_PROOF_SIZE];
    uint8_t message[] = "DLEQ test";

    if (csigma_dleq_prove(proof, witness, g1, h1, g2, h2, message, sizeof(message)) != 0) {
        printf("Failed to create proof\n");
        return;
    }

    printf("Created proof (%zu bytes)\n", sizeof(proof));

    // Verify proof
    if (csigma_dleq_verify(proof, g1, h1, g2, h2, message, sizeof(message))) {
        printf("Proof verified successfully\n");
    } else {
        printf("Proof verification failed\n");
    }

    // Test with wrong h2 (breaking the discrete log equality)
    uint8_t wrong_h2[CSIGMA_POINT_BYTES];
    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(wrong_h2, temp);

    if (!csigma_dleq_verify(proof, g1, h1, g2, wrong_h2, message, sizeof(message))) {
        printf("Correctly rejected proof with wrong h2\n");
    } else {
        printf("Incorrectly accepted proof with wrong h2\n");
    }
}

int
main()
{
    if (sodium_init() != 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }

    test_schnorr();
    test_dleq();

    printf("\nAll tests passed\n");
    return 0;
}
