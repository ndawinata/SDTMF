#include <sdtmf.h>

/* Official-vector keys for password "secret-key" (SDTMF-v2).
   Prefer sdtmf_init_keys on AVR — PBKDF2 100000 is too slow there.
   On ESP32 you may instead call
   sdtmf_init(&tx, "secret-key", SDTMF_DEFAULT_CTR_TX, SDTMF_DEFAULT_TAG_LEN). */
static const uint8_t K_ENC[32] = {
    0x3d, 0xbd, 0x84, 0xb4, 0x92, 0xf2, 0x0d, 0x87,
    0x61, 0x17, 0xa7, 0xfb, 0x10, 0x4d, 0x88, 0x2c,
    0xa4, 0xcb, 0x02, 0x87, 0xcf, 0x52, 0xde, 0xc3,
    0x65, 0xa0, 0x10, 0x38, 0x58, 0x30, 0x9c, 0x8e
};
static const uint8_t K_MAC[32] = {
    0x74, 0x12, 0xb7, 0xaf, 0x5f, 0x0a, 0x10, 0x45,
    0x65, 0xdb, 0x40, 0xba, 0xa1, 0x42, 0xad, 0x58,
    0x6d, 0xb1, 0x65, 0x40, 0x42, 0xeb, 0xdd, 0xcf,
    0xcc, 0x48, 0x7e, 0x80, 0xd5, 0x44, 0x21, 0x89
};

static sdtmf_t tx;
static sdtmf_t rx;

void setup() {
    char frame[48];
    char plain[16];

    Serial.begin(115200);
    while (!Serial) { }

    sdtmf_init_keys(&tx, K_ENC, K_MAC, SDTMF_DEFAULT_CTR_TX, SDTMF_DEFAULT_TAG_LEN);
    sdtmf_init_keys(&rx, K_ENC, K_MAC, SDTMF_DEFAULT_CTR_TX, SDTMF_DEFAULT_TAG_LEN);

    /* Optional: change markers on both sides, e.g. '#' to start and '*' to end.
       sdtmf_set_markers(&tx, '#', '*');
       sdtmf_set_markers(&rx, '#', '*'); */

    sdtmf_encrypt(&tx, "1", frame, sizeof(frame));
    Serial.print("frame: ");
    Serial.println(frame); /* *01505D531# */

    if (sdtmf_decrypt(&rx, frame, plain, sizeof(plain)) == SDTMF_OK) {
        Serial.print("plain: ");
        Serial.println(plain);
    } else {
        Serial.println("decrypt rejected");
    }
}

void loop() { }
