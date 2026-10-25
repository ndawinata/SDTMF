#include "sha256.h"
#include <string.h>

static const uint32_t K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u,
    0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u, 0xe49b69c1u, 0xefbe4786u,
    0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u, 0xa2bfe8a1u, 0xa81a664bu,
    0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au,
    0x5b9cca4fu, 0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

typedef struct {
    uint32_t s[8];
    uint8_t buf[64];
    uint64_t bits;
    size_t nbuf;
} sha256_ctx;

static uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static void transform(uint32_t s[8], const uint8_t block[64]) {
    uint32_t w[64];
    int i;
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
               ((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = s[0], b = s[1], c = s[2], d = s[3];
    uint32_t e = s[4], f = s[5], g = s[6], h = s[7];
    for (i = 0; i < 64; i++) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->s[0] = 0x6a09e667u;
    ctx->s[1] = 0xbb67ae85u;
    ctx->s[2] = 0x3c6ef372u;
    ctx->s[3] = 0xa54ff53au;
    ctx->s[4] = 0x510e527fu;
    ctx->s[5] = 0x9b05688cu;
    ctx->s[6] = 0x1f83d9abu;
    ctx->s[7] = 0x5be0cd19u;
    ctx->bits = 0;
    ctx->nbuf = 0;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    ctx->bits += (uint64_t)len * 8u;
    while (len > 0) {
        size_t take = 64 - ctx->nbuf;
        if (take > len) take = len;
        memcpy(ctx->buf + ctx->nbuf, data, take);
        ctx->nbuf += take;
        data += take;
        len -= take;
        if (ctx->nbuf == 64) {
            transform(ctx->s, ctx->buf);
            ctx->nbuf = 0;
        }
    }
}

static void store_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
    size_t i;
    ctx->buf[ctx->nbuf++] = 0x80;
    if (ctx->nbuf > 56) {
        memset(ctx->buf + ctx->nbuf, 0, 64 - ctx->nbuf);
        transform(ctx->s, ctx->buf);
        ctx->nbuf = 0;
    }
    memset(ctx->buf + ctx->nbuf, 0, 56 - ctx->nbuf);
    for (i = 0; i < 8; i++) {
        ctx->buf[63 - i] = (uint8_t)(ctx->bits >> (8 * i));
    }
    transform(ctx->s, ctx->buf);
    for (i = 0; i < 8; i++) store_be32(out + i * 4, ctx->s[i]);
}

void sdtmf_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

void sdtmf_hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *msg, size_t msg_len, uint8_t out[32]) {
    uint8_t kh[32], ipad[64], opad[64], inner[32];
    const uint8_t *k = key;
    size_t klen = key_len;
    size_t i;
    sha256_ctx ctx;

    if (klen > 64) {
        sdtmf_sha256(k, klen, kh);
        k = kh;
        klen = 32;
    }
    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);
    for (i = 0; i < klen; i++) {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, ipad, 64);
    sha256_update(&ctx, msg, msg_len);
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, opad, 64);
    sha256_update(&ctx, inner, 32);
    sha256_final(&ctx, out);
}

void sdtmf_pbkdf2_hmac_sha256(const uint8_t *pw, size_t pw_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iters, uint8_t *out, size_t out_len) {
    uint32_t block = 1;
    uint8_t u[32], t[32], sbuf[260];
    uint32_t i, j;
    size_t produced = 0;

    if (salt_len > 256) return;
    memcpy(sbuf, salt, salt_len);

    while (produced < out_len) {
        sbuf[salt_len] = (uint8_t)(block >> 24);
        sbuf[salt_len + 1] = (uint8_t)(block >> 16);
        sbuf[salt_len + 2] = (uint8_t)(block >> 8);
        sbuf[salt_len + 3] = (uint8_t)block;
        sdtmf_hmac_sha256(pw, pw_len, sbuf, salt_len + 4, u);
        memcpy(t, u, 32);
        for (i = 1; i < iters; i++) {
            sdtmf_hmac_sha256(pw, pw_len, u, 32, u);
            for (j = 0; j < 32; j++) t[j] ^= u[j];
        }
        {
            size_t take = out_len - produced;
            if (take > 32) take = 32;
            memcpy(out + produced, t, take);
            produced += take;
        }
        block++;
    }
}
