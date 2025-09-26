#include "../pedersen.h"
#include <stdio.h>
#include <string.h>

void
test_pedersen()
{
    printf("\n=== Testing Pedersen Commitment Proof ===\n");

    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return;
    }

    // Generate base points G and H
    uint8_t G[POINT_BYTES], H[POINT_BYTES];
    uint8_t temp[SCALAR_BYTES];

    // G = generator
    memset(temp, 0, SCALAR_BYTES);
    temp[0] = 1;
    crypto_scalarmult_ristretto255_base(G, temp);

    // H = random point
    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(H, temp);

    // Generate secret value and randomness
    uint8_t value[SCALAR_BYTES], randomness[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(value);
    crypto_core_ristretto255_scalar_random(randomness);

    // Create commitment C = value*G + randomness*H
    uint8_t C[POINT_BYTES];
    if (pedersen_commit(C, value, randomness, G, H) != 0) {
        printf("❌ Failed to create commitment\n");
        return;
    }
    printf("✓ Created Pedersen commitment\n");

    // Create proof of knowledge of opening
    uint8_t proof[PEDERSEN_PROOF_SIZE];
    uint8_t message[] = "Pedersen commitment proof test";

    if (pedersen_prove(proof, value, randomness, G, H, C, message, sizeof(message)) != 0) {
        printf("❌ Failed to create proof\n");
        return;
    }
    printf("✓ Created proof (%d bytes)\n", PEDERSEN_PROOF_SIZE);

    // Verify proof
    if (pedersen_verify(proof, G, H, C, message, sizeof(message))) {
        printf("✓ Proof verified successfully\n");
    } else {
        printf("❌ Proof verification failed\n");
    }

    // Test with wrong commitment
    uint8_t wrong_value[SCALAR_BYTES], wrong_randomness[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(wrong_value);
    crypto_core_ristretto255_scalar_random(wrong_randomness);

    uint8_t wrong_C[POINT_BYTES];
    pedersen_commit(wrong_C, wrong_value, wrong_randomness, G, H);

    if (!pedersen_verify(proof, G, H, wrong_C, message, sizeof(message))) {
        printf("✓ Correctly rejected proof with wrong commitment\n");
    } else {
        printf("❌ Incorrectly accepted proof with wrong commitment\n");
    }

    // Test with wrong message
    uint8_t wrong_message[] = "Different message";
    if (!pedersen_verify(proof, G, H, C, wrong_message, sizeof(wrong_message))) {
        printf("✓ Correctly rejected proof with wrong message\n");
    } else {
        printf("❌ Incorrectly accepted proof with wrong message\n");
    }
}

int
main()
{
    test_pedersen();
    printf("\n✓ Pedersen tests passed\n");
    return 0;
}
