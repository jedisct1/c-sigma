#include "keccak.h"
#include <string.h>

// Reference Keccak implementation based on the official specification
static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

static const int keccakf_rotc[24] = { 1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
                                      27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44 };

static const int keccakf_piln[24] = { 10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
                                      15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1 };

#define ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

// Fixed Keccak-f[1600] permutation
void
keccak_f1600(uint64_t st[25])
{
    int      i, j, r;
    uint64_t t, bc[5];

    for (r = 0; r < 24; r++) {
        // Theta
        for (i = 0; i < 5; i++) {
            bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
        }

        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                st[j + i] ^= t;
            }
        }

        // Rho Pi
        t = st[1];
        for (i = 0; i < 24; i++) {
            j     = keccakf_piln[i];
            bc[0] = st[j];
            st[j] = ROTL64(t, keccakf_rotc[i]);
            t     = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = st[j + i];
            }
            for (i = 0; i < 5; i++) {
                st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        st[0] ^= keccakf_rndc[r];
    }
}

void
shake128_init(shake128_ctx* ctx)
{
    memset(ctx->state, 0, sizeof(ctx->state));
    ctx->rate      = 168; // SHAKE128 rate = 1344/8 = 168 bytes
    ctx->pos       = 0;
    ctx->delim     = 0x1F; // SHAKE128 domain separator
    ctx->squeezing = 0;
}

void
shake128_absorb(shake128_ctx* ctx, const uint8_t* data, size_t len)
{
    if (ctx->squeezing) {
        return; // Cannot absorb after squeezing starts
    }

    for (size_t i = 0; i < len; i++) {
        ((uint8_t*) ctx->state)[ctx->pos] ^= data[i];
        ctx->pos++;

        if (ctx->pos == ctx->rate) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
    }
}

void
shake128_finalize(shake128_ctx* ctx)
{
    if (ctx->squeezing) {
        return; // Already finalized
    }

    // Apply SHAKE128 padding
    ((uint8_t*) ctx->state)[ctx->pos] ^= ctx->delim;
    ((uint8_t*) ctx->state)[ctx->rate - 1] ^= 0x80;

    keccak_f1600(ctx->state);
    ctx->pos       = 0;
    ctx->squeezing = 1;
}

void
shake128_squeeze(shake128_ctx* ctx, uint8_t* out, size_t len)
{
    if (!ctx->squeezing) {
        shake128_finalize(ctx);
    }

    for (size_t i = 0; i < len; i++) {
        if (ctx->pos == ctx->rate) {
            keccak_f1600(ctx->state);
            ctx->pos = 0;
        }
        out[i] = ((uint8_t*) ctx->state)[ctx->pos];
        ctx->pos++;
    }
}

void
shake128(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen)
{
    shake128_ctx ctx;
    shake128_init(&ctx);
    shake128_absorb(&ctx, in, inlen);
    shake128_finalize(&ctx);
    shake128_squeeze(&ctx, out, outlen);
}