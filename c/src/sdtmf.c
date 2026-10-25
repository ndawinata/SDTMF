#include "sdtmf.h"
#include "sha256.h"

#include <string.h>

static const char ALPH[] = SDTMF_ALPH;
#define B 14

static int idx(char c) {
    unsigned u = (unsigned char)c;
    if (u >= '0' && u <= '9') return (int)(u - '0');
    if (u >= 'A' && u <= 'D') return (int)(u - 'A' + 10);
    return -1;
}

static void be64(uint8_t out[8], uint64_t n) {
    int i;
    for (i = 7; i >= 0; i--) {
        out[i] = (uint8_t)n;
        n >>= 8;
    }
}

static void be16(uint8_t out[2], uint16_t n) {
    out[0] = (uint8_t)(n >> 8);
    out[1] = (uint8_t)n;
}

static uint32_t pow14(int e) {
    uint32_t r = 1;
    while (e-- > 0) r *= 14u;
    return r;
}

static void to_sym(uint32_t n, int w, char *out) {
    int i;
    for (i = w - 1; i >= 0; i--) {
        out[i] = ALPH[n % B];
        n /= B;
    }
}

static uint32_t to_int(const char *s, int w) {
    uint32_t n = 0;
    int i;
    for (i = 0; i < w; i++) n = n * B + (uint32_t)idx(s[i]);
    return n;
}

static int valid_msg(const char *msg, size_t *n_out) {
    size_t n = 0;
    if (!msg || !msg[0]) return 0;
    while (msg[n]) {
        if (idx(msg[n]) < 0) return 0;
        n++;
    }
    if (n > SDTMF_MAX_MSG) return 0;
    *n_out = n;
    return 1;
}

static void keystream(const sdtmf_t *ctx, uint64_t ctr, size_t n, uint8_t *out) {
    size_t have = 0;
    uint16_t blk = 0;
    uint8_t msg[10], d[32];
    int i;

    be64(msg, ctr);
    while (have < n) {
        be16(msg + 8, blk);
        sdtmf_hmac_sha256(ctx->k_enc, 32, msg, 10, d);
        for (i = 0; i < 32 && have < n; i++) {
            if (d[i] < 252) out[have++] = (uint8_t)(d[i] % B);
        }
        blk++;
    }
}

static void make_tag(const sdtmf_t *ctx, uint64_t ctr, const char *ct, size_t n, char *tag) {
    uint8_t buf[8 + SDTMF_MAX_MSG];
    uint8_t d[32];
    uint32_t m = ctx->tag_mod;
    uint32_t r = 0;
    size_t i;

    be64(buf, ctr);
    memcpy(buf + 8, ct, n);
    sdtmf_hmac_sha256(ctx->k_mac, 32, buf, 8 + n, d);
    for (i = 0; i < 32; i++) {
        r = (uint32_t)(((uint64_t)r * 256u + d[i]) % m);
    }
    to_sym(r, ctx->tag_len, tag);
}

static int params_ok(int ctr_tx, int tag_len) {
    return ctr_tx >= 0 && ctr_tx <= 8 && tag_len >= 1 && tag_len <= 8;
}

int sdtmf_set_markers(sdtmf_t *ctx, char start, char end) {
    if (!ctx) return SDTMF_ERR_ARG;
    if (idx(start) >= 0 || idx(end) >= 0) return SDTMF_ERR_ARG;
    if (start != SDTMF_NO_MARKER && start == end) return SDTMF_ERR_ARG;
    ctx->start = start;
    ctx->end = end;
    return SDTMF_OK;
}

int sdtmf_init_keys(sdtmf_t *ctx, const uint8_t k_enc[32], const uint8_t k_mac[32],
                    int ctr_tx, int tag_len) {
    if (!ctx || !k_enc || !k_mac || !params_ok(ctr_tx, tag_len)) return SDTMF_ERR_ARG;
    memmove(ctx->k_enc, k_enc, 32);
    memmove(ctx->k_mac, k_mac, 32);
    ctx->ctr_tx = (uint8_t)ctr_tx;
    ctx->tag_len = (uint8_t)tag_len;
    ctx->start = SDTMF_DEFAULT_START;
    ctx->end = SDTMF_DEFAULT_END;
    ctx->mod = pow14(ctr_tx);
    ctx->tag_mod = pow14(tag_len);
    ctx->tx_ctr = 0;
    ctx->rx_last = -1;
    return SDTMF_OK;
}

int sdtmf_init(sdtmf_t *ctx, const char *password, int ctr_tx, int tag_len) {
    uint8_t master[32], k_enc[32], k_mac[32];
    if (!ctx || !password || !params_ok(ctr_tx, tag_len)) return SDTMF_ERR_ARG;
    sdtmf_pbkdf2_hmac_sha256((const uint8_t *)password, strlen(password),
                             (const uint8_t *)SDTMF_SALT, 8, SDTMF_ITERS, master, 32);
    sdtmf_hmac_sha256(master, 32, (const uint8_t *)"enc", 3, k_enc);
    sdtmf_hmac_sha256(master, 32, (const uint8_t *)"mac", 3, k_mac);
    return sdtmf_init_keys(ctx, k_enc, k_mac, ctr_tx, tag_len);
}

size_t sdtmf_frame_len(const sdtmf_t *ctx, size_t msg_len) {
    if (!ctx) return 0;
    return (ctx->start ? 1u : 0u) + ctx->ctr_tx + msg_len + ctx->tag_len + (ctx->end ? 1u : 0u);
}

int sdtmf_encrypt(sdtmf_t *ctx, const char *msg, char *out, size_t out_sz) {
    size_t n, i, pos;
    uint8_t ks[SDTMF_MAX_MSG];
    char tag[9];
    uint64_t c;
    char *ct;

    if (!ctx || !out) return SDTMF_ERR_ARG;
    if (!valid_msg(msg, &n)) return SDTMF_ERR_MSG;
    if (out_sz < sdtmf_frame_len(ctx, n) + 1) return SDTMF_ERR_BUF;

    ctx->tx_ctr += 1;
    c = ctx->tx_ctr;
    keystream(ctx, c, n, ks);

    pos = 0;
    if (ctx->start) out[pos++] = ctx->start;
    to_sym((uint32_t)(c % ctx->mod), ctx->ctr_tx, out + pos);
    pos += ctx->ctr_tx;
    ct = out + pos;
    for (i = 0; i < n; i++) {
        ct[i] = ALPH[(idx(msg[i]) + ks[i]) % B];
    }
    make_tag(ctx, c, ct, n, tag);
    pos += n;
    memcpy(out + pos, tag, ctx->tag_len);
    pos += ctx->tag_len;
    if (ctx->end) out[pos++] = ctx->end;
    out[pos] = '\0';
    return SDTMF_OK;
}

int sdtmf_decrypt(sdtmf_t *ctx, const char *frame, char *out, size_t out_sz) {
    size_t flen, slen, n, i, ls, le;
    const char *s;
    uint32_t low;
    const char *ct;
    const char *tag;
    char tag2[9];
    uint8_t ks[SDTMF_MAX_MSG];
    int64_t base, rem;
    uint64_t c;
    unsigned diff;

    if (!ctx || !frame || !out) return SDTMF_ERR_ARG;
    flen = strlen(frame);
    ls = ctx->start ? 1u : 0u;
    le = ctx->end ? 1u : 0u;
    if (flen < ls + le) return SDTMF_ERR_REJECT;
    if (ls && frame[0] != ctx->start) return SDTMF_ERR_REJECT;
    if (le && frame[flen - 1] != ctx->end) return SDTMF_ERR_REJECT;
    s = frame + ls;
    slen = flen - ls - le;
    if (slen <= (size_t)ctx->ctr_tx + (size_t)ctx->tag_len) return SDTMF_ERR_REJECT;
    for (i = 0; i < slen; i++) {
        if (idx(s[i]) < 0) return SDTMF_ERR_REJECT;
    }

    n = slen - (size_t)ctx->ctr_tx - (size_t)ctx->tag_len;
    if (n > SDTMF_MAX_MSG || out_sz < n + 1) return SDTMF_ERR_BUF;

    low = to_int(s, ctx->ctr_tx);
    ct = s + ctx->ctr_tx;
    tag = s + ctx->ctr_tx + n;

    base = ctx->rx_last + 1;
    if (base < 1) base = 1;
    rem = ((int64_t)low - base) % (int64_t)ctx->mod;
    if (rem < 0) rem += (int64_t)ctx->mod;
    c = (uint64_t)(base + rem);

    make_tag(ctx, c, ct, n, tag2);
    diff = 0;
    for (i = 0; i < (size_t)ctx->tag_len; i++) {
        diff |= (unsigned)((unsigned char)tag[i] ^ (unsigned char)tag2[i]);
    }
    if (diff != 0) return SDTMF_ERR_REJECT;

    ctx->rx_last = (int64_t)c;
    keystream(ctx, c, n, ks);
    for (i = 0; i < n; i++) {
        int v = idx(ct[i]) - (int)ks[i];
        if (v < 0) v += B;
        out[i] = ALPH[v];
    }
    out[n] = '\0';
    return SDTMF_OK;
}
