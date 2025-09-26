#include "sigma.h"
#include <stdio.h>
#include <string.h>

void
print_hex(const char* label, const uint8_t* data, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 16; i++) {
        printf("%02x", data[i]);
    }
    if (len > 16)
        printf("...");
    printf("\n");
}

int
main()
{
    if (sigma_init() != 0) {
        printf("Failed to initialize sodium\n");
        return 1;
    }

    printf("Sigma Protocols - Simplified API Example (Ristretto255)\n");
    printf("=========================================================\n\n");

    // Example 1: Schnorr protocol (proving knowledge of private key)
    printf("1. Schnorr Protocol - Proving knowledge of private key\n");
    printf("-------------------------------------------------------\n");

    // Alice has a private key (witness) and public key
    uint8_t private_key[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(private_key);

    uint8_t public_key[POINT_BYTES];
    crypto_scalarmult_ristretto255_base(public_key, private_key);

    print_hex("Public key", public_key, POINT_BYTES);

    // Alice creates a proof that she knows the private key
    uint8_t schnorr_proof[SCHNORR_PROOF_SIZE];
    uint8_t message[] = "I am Alice";

    schnorr_prove(schnorr_proof, private_key, public_key, message, sizeof(message));
    print_hex("Proof", schnorr_proof, SCHNORR_PROOF_SIZE);

    // Bob verifies the proof
    bool valid = schnorr_verify(schnorr_proof, public_key, message, sizeof(message));
    printf("Verification: %s\n\n", valid ? "✓ VALID" : "✗ INVALID");

    // Example 2: Chaum-Pedersen protocol (proving discrete log equality)
    printf("2. Chaum-Pedersen - Proving discrete log equality\n");
    printf("--------------------------------------------------\n");
    printf("Proves that log_g1(h1) = log_g2(h2) without revealing x\n\n");

    // Setup: Alice knows x such that h1 = g1^x and h2 = g2^x
    uint8_t x[SCALAR_BYTES];
    crypto_core_ristretto255_scalar_random(x);

    // Generate two different base points
    uint8_t g1[POINT_BYTES], g2[POINT_BYTES];
    uint8_t temp[SCALAR_BYTES];

    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(g1, temp);

    crypto_core_ristretto255_scalar_random(temp);
    crypto_scalarmult_ristretto255_base(g2, temp);

    // Compute h1 = g1^x and h2 = g2^x
    uint8_t h1[POINT_BYTES], h2[POINT_BYTES];
    if (crypto_scalarmult_ristretto255(h1, x, g1) != 0) {
        printf("Failed to compute h1\n");
        return 1;
    }
    if (crypto_scalarmult_ristretto255(h2, x, g2) != 0) {
        printf("Failed to compute h2\n");
        return 1;
    }

    print_hex("g1", g1, POINT_BYTES);
    print_hex("h1 = g1^x", h1, POINT_BYTES);
    print_hex("g2", g2, POINT_BYTES);
    print_hex("h2 = g2^x", h2, POINT_BYTES);

    // Alice creates a proof
    uint8_t dleq_proof[CHAUM_PEDERSEN_PROOF_SIZE];
    uint8_t dleq_message[] = "Discrete log equality";

    chaum_pedersen_prove(dleq_proof, x, g1, h1, g2, h2, dleq_message, sizeof(dleq_message));
    print_hex("Proof", dleq_proof, CHAUM_PEDERSEN_PROOF_SIZE);

    // Bob verifies the proof
    valid = chaum_pedersen_verify(dleq_proof, g1, h1, g2, h2, dleq_message, sizeof(dleq_message));
    printf("Verification: %s\n\n", valid ? "✓ VALID" : "✗ INVALID");

    // Clean up
    sodium_memzero(private_key, sizeof(private_key));
    sodium_memzero(x, sizeof(x));

    return 0;
}
