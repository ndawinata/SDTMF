#ifndef SDTMF_H
#define SDTMF_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SDTMF_OK          0
#define SDTMF_ERR_ARG    -1
#define SDTMF_ERR_MSG    -2
#define SDTMF_ERR_BUF    -3
#define SDTMF_ERR_REJECT -4

#define SDTMF_ALPH     "0123456789ABCD"
#define SDTMF_SALT     "SDTMF-v2"
#define SDTMF_ITERS    100000u
#define SDTMF_MAX_MSG  256

#define SDTMF_DEFAULT_CTR_TX  2
#define SDTMF_DEFAULT_TAG_LEN 6
#define SDTMF_DEFAULT_START   '*'
#define SDTMF_DEFAULT_END     '#'
#define SDTMF_NO_MARKER       '\0'

typedef struct sdtmf {
    uint8_t k_enc[32];
    uint8_t k_mac[32];
    uint8_t ctr_tx;
    uint8_t tag_len;
    char start;          /* SDTMF_NO_MARKER = none */
    char end;            /* SDTMF_NO_MARKER = none */
    uint32_t mod;            /* 14^ctr_tx */
    uint32_t tag_mod;        /* 14^tag_len */
    uint64_t tx_ctr;
    int64_t rx_last;
} sdtmf_t;

/* Both init functions reset markers to '*' / '#'. */
int sdtmf_init(sdtmf_t *ctx, const char *password, int ctr_tx, int tag_len);
int sdtmf_init_keys(sdtmf_t *ctx, const uint8_t k_enc[32], const uint8_t k_mac[32],
                    int ctr_tx, int tag_len);
int sdtmf_set_markers(sdtmf_t *ctx, char start, char end);
size_t sdtmf_frame_len(const sdtmf_t *ctx, size_t msg_len);
int sdtmf_encrypt(sdtmf_t *ctx, const char *msg, char *out, size_t out_sz);
int sdtmf_decrypt(sdtmf_t *ctx, const char *frame, char *out, size_t out_sz);

#ifdef __cplusplus
}
#endif

#endif
