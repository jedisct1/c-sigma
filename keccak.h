#ifndef KECCAK_H
#define KECCAK_H

#include <stddef.h>
#include <stdint.h>

#define KECCAK_ROUNDS 24

void keccak_f1600(uint64_t state[25]);

typedef struct {
    uint64_t state[25]; // 1600 bits
    size_t   rate; // Rate in bytes (136 for SHAKE128)
    size_t   pos; // Current position in buffer
    uint8_t  delim; // Domain separation byte
    int      squeezing; // 0 = absorbing, 1 = squeezing
} shake128_ctx;

void shake128_init(shake128_ctx* ctx);
void shake128_absorb(shake128_ctx* ctx, const uint8_t* data, size_t len);
void shake128_finalize(shake128_ctx* ctx);
void shake128_squeeze(shake128_ctx* ctx, uint8_t* out, size_t len);

void shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen);

#endif
