#include "sdtmf.h"
#include "sha256.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Mirrors test-vectors.json (SDTMF-v2, password "secret-key"). */

static int failures;

static void fail(const char *label, const char *got, const char *exp) {
    fprintf(stderr, "FAIL %s\n  got  %s\n  exp  %s\n", label, got, exp);
    failures++;
}

static void eq_str(const char *got, const char *exp, const char *label) {
    if (strcmp(got, exp) != 0) fail(label, got, exp);
}

static void eq_int(int64_t got, int64_t exp, const char *label) {
    if (got != exp) {
        char g[32], e[32];
        snprintf(g, sizeof g, "%lld", (long long)got);
        snprintf(e, sizeof e, "%lld", (long long)exp);
        fail(label, g, e);
    }
}

static void hex32(const uint8_t *b, char *out) {
    static const char *H = "0123456789abcdef";
    int i;
    for (i = 0; i < 32; i++) {
        out[i * 2] = H[b[i] >> 4];
        out[i * 2 + 1] = H[b[i] & 0xf];
    }
    out[64] = '\0';
}

typedef struct {
    int ctr_tx, tag_len;
    char start, end;
    const char *msg, *frame, *frame2;
} config_row;

static const config_row CONFIGS[] = {
    {2, 6, '*', '#', "1234", "*015D0857C1CB#", "*0275D6549036#"},
    {2, 3, '*', '#', "1234", "*015D081CB#", "*0275D6036#"},
    {2, 4, '*', '#', "1234", "*015D08C1CB#", "*0275D69036#"},
    {1, 4, '*', '#', "1234", "*15D08C1CB#", "*275D69036#"},
    {0, 4, '*', '#', "1234", "*5D08C1CB#", "*75D69036#"},
    {2, 8, '*', '#', "1234", "*015D085B57C1CB#", "*0275D61D549036#"},
    {3, 6, '*', '#', "1234", "*0015D0857C1CB#", "*00275D6549036#"},
    {2, 6, '#', '*', "1234", "#015D0857C1CB*", "#0275D6549036*"},
    {2, 6, '\0', '\0', "1234", "015D0857C1CB", "0275D6549036"},
    {1, 4, '*', '\0', "1234", "*15D08C1CB", "*275D69036"},
    {2, 6, '<', '>', "1234", "<015D0857C1CB>", "<0275D6549036>"},
};

typedef struct {
    const char *reason;
    int64_t start_rx_last;
    const char *frame;
} reject_row;

static const reject_row REJECTS[] = {
    {"replay", 1, "*01505D531#"},
    {"tampered_tag", -1, "*01505D537#"},
    {"missing_end", -1, "*01505D531"},
    {"missing_start", -1, "01505D531#"},
    {"illegal_char", -1, "*015X5D531#"},
    {"too_short", -1, "*01123456#"},
    {"replay_after_wrap", 196, "*00030C76C#"},
};

int main(void) {
    sdtmf_t tx, rx, wrong;
    char frame[SDTMF_MAX_MSG + 32];
    char msg[SDTMF_MAX_MSG + 1];
    char hex[65], label[160];
    uint8_t d[32], k_enc[32], k_mac[32];
    size_t i;

    sdtmf_sha256((const uint8_t *)"abc", 3, d);
    hex32(d, hex);
    eq_str(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256(abc)");

    sdtmf_hmac_sha256((const uint8_t *)"key", 3,
                      (const uint8_t *)"The quick brown fox jumps over the lazy dog", 43, d);
    hex32(d, hex);
    eq_str(hex, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8", "hmac-sha256");

    if (sdtmf_init(&tx, "secret-key", SDTMF_DEFAULT_CTR_TX, SDTMF_DEFAULT_TAG_LEN) != SDTMF_OK) {
        fail("init", "err", "ok");
        return 1;
    }
    hex32(tx.k_enc, hex);
    eq_str(hex, "3dbd84b492f20d876117a7fb104d882ca4cb0287cf52dec365a0103858309c8e", "k_enc");
    hex32(tx.k_mac, hex);
    eq_str(hex, "7412b7af5f0a104565db40baa142ad586db1654042ebddcfcc487e80d5442189", "k_mac");
    memcpy(k_enc, tx.k_enc, 32);
    memcpy(k_mac, tx.k_mac, 32);
    eq_int(tx.start, '*', "default start");
    eq_int(tx.end, '#', "default end");

    sdtmf_encrypt(&tx, "1", frame, sizeof frame);
    eq_str(frame, "*01505D531#", "encrypt(1)");
    sdtmf_encrypt(&tx, "12AB", frame, sizeof frame);
    eq_str(frame, "*02756DCB16BD#", "encrypt(12AB)");
    sdtmf_encrypt(&tx, "0123456789ABCD", frame, sizeof frame);
    eq_str(frame, "*0347DAB1CC3B814D5113B5#", "encrypt(long)");
    eq_int((int64_t)tx.tx_ctr, 3, "tx_ctr after 3");

    sdtmf_init_keys(&rx, k_enc, k_mac, 2, 6);
    if (sdtmf_decrypt(&rx, "*01505D531#", msg, sizeof msg) != SDTMF_OK) fail("dec1", "err", "ok");
    eq_str(msg, "1", "decrypt 1");
    if (sdtmf_decrypt(&rx, "*02756DCB16BD#", msg, sizeof msg) != SDTMF_OK) fail("dec2", "err", "ok");
    eq_str(msg, "12AB", "decrypt 12AB");
    if (sdtmf_decrypt(&rx, "*0347DAB1CC3B814D5113B5#", msg, sizeof msg) != SDTMF_OK) fail("dec3", "err", "ok");
    eq_str(msg, "0123456789ABCD", "decrypt long");
    eq_int(rx.rx_last, 3, "rx_last after 3");

    for (i = 0; i < sizeof REJECTS / sizeof REJECTS[0]; i++) {
        sdtmf_init_keys(&rx, k_enc, k_mac, 2, 6);
        rx.rx_last = REJECTS[i].start_rx_last;
        snprintf(label, sizeof label, "reject %s", REJECTS[i].reason);
        if (sdtmf_decrypt(&rx, REJECTS[i].frame, msg, sizeof msg) != SDTMF_ERR_REJECT)
            fail(label, "accepted", "reject");
        eq_int(rx.rx_last, REJECTS[i].start_rx_last, label);
    }

    sdtmf_init(&wrong, "wrong-key", 2, 6);
    if (sdtmf_decrypt(&wrong, "*01505D531#", msg, sizeof msg) != SDTMF_ERR_REJECT)
        fail("wrong password", "accepted", "reject");

    sdtmf_init_keys(&tx, k_enc, k_mac, 2, 6);
    tx.tx_ctr = 195;
    sdtmf_encrypt(&tx, "A", frame, sizeof frame);
    eq_str(frame, "*00030C76C#", "wrap encrypt");
    sdtmf_init_keys(&rx, k_enc, k_mac, 2, 6);
    rx.rx_last = 195;
    if (sdtmf_decrypt(&rx, "*00030C76C#", msg, sizeof msg) != SDTMF_OK) fail("wrap dec", "err", "ok");
    eq_str(msg, "A", "wrap decrypt");
    eq_int(rx.rx_last, 196, "wrap rx_last");

    for (i = 0; i < sizeof CONFIGS / sizeof CONFIGS[0]; i++) {
        const config_row *r = &CONFIGS[i];
        snprintf(label, sizeof label, "config ctr_tx=%d tag_len=%d start=%d end=%d",
                 r->ctr_tx, r->tag_len, r->start, r->end);

        sdtmf_init_keys(&tx, k_enc, k_mac, r->ctr_tx, r->tag_len);
        if (sdtmf_set_markers(&tx, r->start, r->end) != SDTMF_OK) fail(label, "set_markers err", "ok");
        sdtmf_encrypt(&tx, r->msg, frame, sizeof frame);
        eq_str(frame, r->frame, label);
        eq_int((int64_t)sdtmf_frame_len(&tx, strlen(r->msg)), (int64_t)strlen(r->frame), label);
        sdtmf_encrypt(&tx, r->msg, frame, sizeof frame);
        eq_str(frame, r->frame2, label);

        sdtmf_init_keys(&rx, k_enc, k_mac, r->ctr_tx, r->tag_len);
        sdtmf_set_markers(&rx, r->start, r->end);
        if (sdtmf_decrypt(&rx, r->frame, msg, sizeof msg) != SDTMF_OK) fail(label, "decrypt err", "ok");
        eq_str(msg, r->msg, label);
        if (sdtmf_decrypt(&rx, r->frame2, msg, sizeof msg) != SDTMF_OK) fail(label, "decrypt2 err", "ok");
        if (sdtmf_decrypt(&rx, r->frame, msg, sizeof msg) != SDTMF_ERR_REJECT) fail(label, "replay accepted", "reject");
    }

    sdtmf_init_keys(&rx, k_enc, k_mac, 2, 6);
    sdtmf_set_markers(&rx, '<', '>');
    if (sdtmf_decrypt(&rx, "*015D0857C1CB#", msg, sizeof msg) != SDTMF_ERR_REJECT)
        fail("default markers under custom", "accepted", "reject");
    sdtmf_init_keys(&rx, k_enc, k_mac, 2, 6);
    if (sdtmf_decrypt(&rx, "#015D0857C1CB*", msg, sizeof msg) != SDTMF_ERR_REJECT)
        fail("swapped markers", "accepted", "reject");

    if (sdtmf_init_keys(&tx, k_enc, k_mac, 9, 6) != SDTMF_ERR_ARG) fail("ctr_tx 9", "ok", "err");
    if (sdtmf_init_keys(&tx, k_enc, k_mac, 2, 0) != SDTMF_ERR_ARG) fail("tag_len 0", "ok", "err");
    if (sdtmf_init_keys(&tx, k_enc, k_mac, 2, 9) != SDTMF_ERR_ARG) fail("tag_len 9", "ok", "err");
    sdtmf_init_keys(&tx, k_enc, k_mac, 2, 6);
    if (sdtmf_set_markers(&tx, '1', '#') != SDTMF_ERR_ARG) fail("start in alphabet", "ok", "err");
    if (sdtmf_set_markers(&tx, '*', 'A') != SDTMF_ERR_ARG) fail("end in alphabet", "ok", "err");
    if (sdtmf_set_markers(&tx, '*', '*') != SDTMF_ERR_ARG) fail("start == end", "ok", "err");

    if (failures) {
        fprintf(stderr, "c: %d failure(s)\n", failures);
        return 1;
    }
    printf("c: all official vectors passed\n");
    return 0;
}
