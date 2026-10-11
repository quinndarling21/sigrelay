#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZLIB_CONST
#include <zlib.h>

#include "sigrelay/sip.h"
#include "sigrelay/sip_body.h"
#include "test_harness.h"

/* deflateInit2() window bits for each wrapper. */
#define GZIP_BITS (MAX_WBITS + 16)
#define ZLIB_BITS MAX_WBITS
#define RAW_BITS (-MAX_WBITS)

#define BUF_CAP 2048u
#define GUARD_LEN 16u
#define GUARD_BYTE 0xA5u

static const char sdp[] =
    "v=0\r\n"
    "o=alice 2890844526 2890844526 IN IP4 192.0.2.10\r\n"
    "s=-\r\n"
    "c=IN IP4 192.0.2.10\r\n"
    "t=0 0\r\n"
    "m=audio 49170 RTP/AVP 0 8 97\r\n"
    "a=rtpmap:0 PCMU/8000\r\n"
    "a=rtpmap:8 PCMA/8000\r\n"
    "a=rtpmap:97 AMR/8000/1\r\n"
    "a=fmtp:97 mode-set=0,2,5,7; mode-change-period=2\r\n"
    "a=ptime:20\r\n"
    "a=sendrecv\r\n";

#define SDP_LEN (sizeof(sdp) - 1)

typedef struct {
    uint8_t data[BUF_CAP];
    size_t len;
} body_buf;

/* Compresses with zlib's deflate API; window_bits selects the wrapper. */
static void compress_body(int window_bits, const void *in, size_t in_len, gz_header *head,
                          body_buf *b)
{
    z_stream zs;

    memset(&zs, 0, sizeof(zs));
    if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, window_bits, 8, Z_DEFAULT_STRATEGY) !=
            Z_OK ||
        (head != NULL && deflateSetHeader(&zs, head) != Z_OK)) {
        fprintf(stderr, "zlib deflate setup failed\n");
        abort();
    }
    zs.next_in = in;
    zs.avail_in = (uInt)in_len;
    zs.next_out = b->data;
    zs.avail_out = (uInt)sizeof(b->data);
    if (deflate(&zs, Z_FINISH) != Z_STREAM_END) {
        fprintf(stderr, "compressed body does not fit the test buffer\n");
        abort();
    }
    b->len = sizeof(b->data) - zs.avail_out;
    deflateEnd(&zs);
}

/*
 * Decodes a heap copy of exactly in_len bytes, so that reads past the end are
 * detectable, into a buffer guarded past out_cap. Checks the status, that no
 * byte past out_cap changed, that *out_len is written only on success, and on
 * success that the output equals expected_body.
 */
static int check_decode(const char *encoding, const uint8_t *in, size_t in_len, size_t out_cap,
                        sigrelay_sip_body_status expected, const void *expected_body,
                        size_t expected_len)
{
    uint8_t out[BUF_CAP + GUARD_LEN];
    uint8_t *copy = malloc(in_len > 0 ? in_len : 1);
    size_t out_len = SIZE_MAX;
    sigrelay_sip_body_status got;

    if (copy == NULL || out_cap > BUF_CAP) {
        fprintf(stderr, "test setup failed\n");
        abort();
    }
    if (in_len > 0) {
        memcpy(copy, in, in_len);
    }
    memset(out, GUARD_BYTE, sizeof(out));
    got = sigrelay_sip_body_decode(encoding, strlen(encoding), copy, in_len, out, out_cap,
                                   &out_len);
    free(copy);

    if (got != expected) {
        fprintf(stderr, "\"%s\", %zu input bytes, out_cap %zu: expected \"%s\", got \"%s\"\n",
                encoding, in_len, out_cap, sigrelay_sip_body_strerror(expected),
                sigrelay_sip_body_strerror(got));
        return 0;
    }
    for (size_t i = out_cap; i < sizeof(out); i++) {
        if (out[i] != GUARD_BYTE) {
            fprintf(stderr, "\"%s\": byte %zu written past out_cap %zu\n", encoding, i, out_cap);
            return 0;
        }
    }
    if (got != SIGRELAY_SIP_BODY_OK) {
        if (out_len != SIZE_MAX) {
            fprintf(stderr, "\"%s\": out_len written on failure\n", encoding);
            return 0;
        }
        return 1;
    }
    if (out_len != expected_len || (expected_len > 0 && memcmp(out, expected_body, out_len) != 0)) {
        fprintf(stderr, "\"%s\": decoded %zu bytes, expected %zu\n", encoding, out_len,
                expected_len);
        return 0;
    }
    return 1;
}

static int check_fails(const char *encoding, const uint8_t *in, size_t in_len, size_t out_cap,
                       sigrelay_sip_body_status expected)
{
    return check_decode(encoding, in, in_len, out_cap, expected, NULL, 0);
}

static int check_decodes_to_sdp(const char *encoding, const body_buf *b)
{
    return check_decode(encoding, b->data, b->len, BUF_CAP, SIGRELAY_SIP_BODY_OK, sdp, SDP_LEN);
}

/* Every proper prefix of a valid stream is truncated, never corrupt or decoded. */
static int check_prefixes_truncated(const char *encoding, const body_buf *b)
{
    for (size_t len = 0; len < b->len; len++) {
        if (!check_fails(encoding, b->data, len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_TRUNCATED)) {
            fprintf(stderr, "prefix of %zu of %zu bytes\n", len, b->len);
            return 0;
        }
    }
    return 1;
}

/* Every out_cap below the decoded size is too large; the exact size fits. */
static int check_output_caps(const char *encoding, const uint8_t *in, size_t in_len)
{
    for (size_t cap = 0; cap < SDP_LEN; cap++) {
        if (!check_fails(encoding, in, in_len, cap, SIGRELAY_SIP_BODY_ERR_TOO_LARGE)) {
            return 0;
        }
    }
    return check_decode(encoding, in, in_len, SDP_LEN, SIGRELAY_SIP_BODY_OK, sdp, SDP_LEN);
}

/* An INVITE carrying body[0, body_len) after the given extra header lines. */
static size_t build_invite(const char *extra_headers, const uint8_t *body, size_t body_len,
                           char *buf, size_t cap)
{
    int n = snprintf(buf, cap,
                     "INVITE sip:bob@ims.example.net SIP/2.0\r\n"
                     "Via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds\r\n"
                     "Max-Forwards: 70\r\n"
                     "To: <sip:bob@ims.example.net>\r\n"
                     "From: <sip:alice@example.org>;tag=1928301774\r\n"
                     "Call-ID: a84b4c76e66710@pcscf.example.org\r\n"
                     "CSeq: 314159 INVITE\r\n"
                     "Contact: <sip:alice@192.0.2.10>\r\n"
                     "Content-Type: application/sdp\r\n"
                     "%s"
                     "Content-Length: %zu\r\n"
                     "\r\n",
                     extra_headers, body_len);

    if (n < 0 || (size_t)n >= cap || body_len > cap - (size_t)n) {
        fprintf(stderr, "message does not fit the test buffer\n");
        abort();
    }
    memcpy(buf + n, body, body_len);
    return (size_t)n + body_len;
}

/* Parses an INVITE with a gzip body under the given header line and decodes it end to end. */
static int check_gzip_invite(const char *encoding_header)
{
    body_buf gz;
    char buf[BUF_CAP + 512];
    uint8_t out[BUF_CAP];
    sigrelay_sip_message msg;
    sigrelay_sip_status parsed;
    sigrelay_sip_body_status decoded;
    size_t len;
    size_t out_len = 0;

    compress_body(GZIP_BITS, sdp, SDP_LEN, NULL, &gz);
    len = build_invite(encoding_header, gz.data, gz.len, buf, sizeof(buf));
    parsed = sigrelay_sip_parse(buf, len, &msg);
    if (parsed != SIGRELAY_SIP_OK) {
        fprintf(stderr, "parse: %s\n", sigrelay_sip_strerror(parsed));
        return 0;
    }
    if (msg.content_encoding.len != 4 || memcmp(msg.content_encoding.ptr, "gzip", 4) != 0 ||
        msg.body.len != gz.len || msg.message_len != len) {
        fprintf(stderr, "content_encoding \"%.*s\", body %zu bytes\n",
                (int)msg.content_encoding.len, msg.content_encoding.ptr, msg.body.len);
        return 0;
    }
    decoded = sigrelay_sip_body_decode(msg.content_encoding.ptr, msg.content_encoding.len,
                                       (const uint8_t *)msg.body.ptr, msg.body.len, out,
                                       sizeof(out), &out_len);
    if (decoded != SIGRELAY_SIP_BODY_OK || out_len != SDP_LEN ||
        memcmp(out, sdp, SDP_LEN) != 0) {
        fprintf(stderr, "decode: %s, %zu bytes\n", sigrelay_sip_body_strerror(decoded), out_len);
        return 0;
    }
    return 1;
}

void test_sip_body_decodes_gzip(void)
{
    static Bytef name[] = "offer.sdp";
    gz_header head;
    body_buf gz;

    compress_body(GZIP_BITS, sdp, SDP_LEN, NULL, &gz);
    TEST_ASSERT(gz.len > 2);
    TEST_ASSERT_EQ(0x1F, gz.data[0]);
    TEST_ASSERT_EQ(0x8B, gz.data[1]);
    TEST_ASSERT(check_decodes_to_sdp("gzip", &gz));
    TEST_ASSERT(check_decodes_to_sdp("GZip", &gz));

    /* Optional gzip header fields: file name and header CRC. */
    memset(&head, 0, sizeof(head));
    head.name = name;
    head.hcrc = 1;
    compress_body(GZIP_BITS, sdp, SDP_LEN, &head, &gz);
    TEST_ASSERT(check_decodes_to_sdp("gzip", &gz));

    compress_body(GZIP_BITS, "", 0, NULL, &gz);
    TEST_ASSERT(check_decode("gzip", gz.data, gz.len, 0, SIGRELAY_SIP_BODY_OK, NULL, 0));
}

void test_sip_body_decodes_deflate(void)
{
    body_buf z;

    compress_body(ZLIB_BITS, sdp, SDP_LEN, NULL, &z);
    TEST_ASSERT(z.len > 2);
    TEST_ASSERT_EQ(0x78, z.data[0]);
    TEST_ASSERT(check_decodes_to_sdp("deflate", &z));
    TEST_ASSERT(check_decodes_to_sdp("DEFLATE", &z));

    compress_body(ZLIB_BITS, "", 0, NULL, &z);
    TEST_ASSERT(check_decode("deflate", z.data, z.len, 0, SIGRELAY_SIP_BODY_OK, NULL, 0));
}

void test_sip_body_decodes_raw_deflate(void)
{
    body_buf raw;

    compress_body(RAW_BITS, sdp, SDP_LEN, NULL, &raw);
    TEST_ASSERT(check_decodes_to_sdp("deflate", &raw));
    TEST_ASSERT(check_decodes_to_sdp("Deflate", &raw));

    compress_body(RAW_BITS, "", 0, NULL, &raw);
    TEST_ASSERT(check_decode("deflate", raw.data, raw.len, 0, SIGRELAY_SIP_BODY_OK, NULL, 0));
}

void test_sip_body_copies_identity(void)
{
    const uint8_t *body = (const uint8_t *)sdp;
    uint8_t out[8];
    size_t out_len = SIZE_MAX;

    TEST_ASSERT(check_decode("identity", body, SDP_LEN, BUF_CAP, SIGRELAY_SIP_BODY_OK, sdp,
                             SDP_LEN));
    TEST_ASSERT(check_decode("IDENTITY", body, SDP_LEN, SDP_LEN, SIGRELAY_SIP_BODY_OK, sdp,
                             SDP_LEN));
    /* An empty coding is a message without Content-Encoding. */
    TEST_ASSERT(check_decode("", body, SDP_LEN, BUF_CAP, SIGRELAY_SIP_BODY_OK, sdp, SDP_LEN));
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_OK,
                   sigrelay_sip_body_decode(NULL, 0, body, 3, out, sizeof(out), &out_len));
    TEST_ASSERT_EQ(3, out_len);
    TEST_ASSERT(memcmp(out, "v=0", 3) == 0);
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_OK,
                   sigrelay_sip_body_decode("identity", 8, NULL, 0, NULL, 0, &out_len));
    TEST_ASSERT_EQ(0, out_len);
}

void test_sip_body_rejects_unsupported_encoding(void)
{
    static const char *const codings[] = {
        "br", "compress", "x-gzip", "gzip, identity", "gzip,gzip", "gzip ", " gzip",
        "gzip2", "gzi", "deflate;q=1", "identit", "*",
    };
    static const char gzip_with_nul[] = "gz\0ip";
    body_buf gz;
    uint8_t out[BUF_CAP];
    size_t out_len = SIZE_MAX;

    compress_body(GZIP_BITS, sdp, SDP_LEN, NULL, &gz);
    for (size_t i = 0; i < sizeof(codings) / sizeof(codings[0]); i++) {
        TEST_ASSERT(check_fails(codings[i], gz.data, gz.len, BUF_CAP,
                                SIGRELAY_SIP_BODY_ERR_UNSUPPORTED_ENCODING));
    }
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_ERR_UNSUPPORTED_ENCODING,
                   sigrelay_sip_body_decode(gzip_with_nul, sizeof(gzip_with_nul) - 1, gz.data,
                                            gz.len, out, sizeof(out), &out_len));
    TEST_ASSERT(out_len == SIZE_MAX);
}

void test_sip_body_rejects_corrupt_input(void)
{
    /* zlib header with FDICT: the stream needs a preset dictionary nobody agreed on. */
    static const uint8_t needs_dict[] = {0x78, 0x20, 0x00, 0x00, 0x00, 0x01, 0x03, 0x00};
    const uint8_t *text = (const uint8_t *)sdp;
    body_buf gz;
    body_buf z;
    body_buf raw;
    body_buf bad;

    compress_body(GZIP_BITS, sdp, SDP_LEN, NULL, &gz);
    compress_body(ZLIB_BITS, sdp, SDP_LEN, NULL, &z);
    compress_body(RAW_BITS, sdp, SDP_LEN, NULL, &raw);

    /* gzip: bad magic, reserved flag bits, CRC-32 and length trailer mismatches. */
    bad = gz;
    bad.data[0] ^= 0x01u;
    TEST_ASSERT(check_fails("gzip", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    bad = gz;
    bad.data[3] |= 0xE0u;
    TEST_ASSERT(check_fails("gzip", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    bad = gz;
    bad.data[bad.len - 8] ^= 0xFFu;
    TEST_ASSERT(check_fails("gzip", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    bad = gz;
    bad.data[bad.len - 1] ^= 0x01u;
    TEST_ASSERT(check_fails("gzip", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));

    /* zlib wrapper: Adler-32 trailer mismatch and a preset dictionary. */
    bad = z;
    bad.data[bad.len - 1] ^= 0xFFu;
    TEST_ASSERT(
        check_fails("deflate", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    TEST_ASSERT(check_fails("deflate", needs_dict, sizeof(needs_dict), BUF_CAP,
                            SIGRELAY_SIP_BODY_ERR_CORRUPT));

    /* Raw deflate: reserved block type 3. */
    bad = raw;
    bad.data[0] |= 0x06u;
    TEST_ASSERT(
        check_fails("deflate", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));

    /* Data in the wrong format for its label. */
    TEST_ASSERT(check_fails("gzip", text, SDP_LEN, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    TEST_ASSERT(check_fails("deflate", text, SDP_LEN, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    TEST_ASSERT(check_fails("gzip", z.data, z.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    TEST_ASSERT(check_fails("deflate", gz.data, gz.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));

    /* Bytes after the end of the stream, including a second gzip member. */
    bad = gz;
    bad.data[bad.len++] = 0x00;
    TEST_ASSERT(check_fails("gzip", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    bad = gz;
    memcpy(bad.data + bad.len, gz.data, gz.len);
    bad.len += gz.len;
    TEST_ASSERT(check_fails("gzip", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    bad = z;
    bad.data[bad.len++] = 0x00;
    TEST_ASSERT(
        check_fails("deflate", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
    bad = raw;
    bad.data[bad.len++] = 0x00;
    TEST_ASSERT(
        check_fails("deflate", bad.data, bad.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_CORRUPT));
}

void test_sip_body_rejects_truncated_input(void)
{
    body_buf b;

    compress_body(GZIP_BITS, sdp, SDP_LEN, NULL, &b);
    TEST_ASSERT(check_prefixes_truncated("gzip", &b));
    TEST_ASSERT(check_decodes_to_sdp("gzip", &b));

    compress_body(ZLIB_BITS, sdp, SDP_LEN, NULL, &b);
    TEST_ASSERT(check_prefixes_truncated("deflate", &b));
    TEST_ASSERT(check_decodes_to_sdp("deflate", &b));

    compress_body(RAW_BITS, sdp, SDP_LEN, NULL, &b);
    TEST_ASSERT(check_prefixes_truncated("deflate", &b));
    TEST_ASSERT(check_decodes_to_sdp("deflate", &b));
}

void test_sip_body_rejects_oversized_output(void)
{
    static uint8_t zeros[1u << 20];
    body_buf b;
    size_t out_len = SIZE_MAX;

    compress_body(GZIP_BITS, sdp, SDP_LEN, NULL, &b);
    TEST_ASSERT(check_output_caps("gzip", b.data, b.len));
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_ERR_TOO_LARGE,
                   sigrelay_sip_body_decode("gzip", 4, b.data, b.len, NULL, 0, &out_len));
    TEST_ASSERT(out_len == SIZE_MAX);

    compress_body(ZLIB_BITS, sdp, SDP_LEN, NULL, &b);
    TEST_ASSERT(check_output_caps("deflate", b.data, b.len));

    compress_body(RAW_BITS, sdp, SDP_LEN, NULL, &b);
    TEST_ASSERT(check_output_caps("deflate", b.data, b.len));

    TEST_ASSERT(check_output_caps("identity", (const uint8_t *)sdp, SDP_LEN));

    /* 1 MiB of zeros compresses to about 1 KiB; decoding stops at out_cap. */
    compress_body(GZIP_BITS, zeros, sizeof(zeros), NULL, &b);
    TEST_ASSERT(check_fails("gzip", b.data, b.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_TOO_LARGE));
    compress_body(ZLIB_BITS, zeros, sizeof(zeros), NULL, &b);
    TEST_ASSERT(check_fails("deflate", b.data, b.len, BUF_CAP, SIGRELAY_SIP_BODY_ERR_TOO_LARGE));
}

void test_sip_body_rejects_invalid_arguments(void)
{
    const uint8_t *body = (const uint8_t *)sdp;
    uint8_t out[16];
    size_t out_len = SIZE_MAX;

    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_ERR_INVALID_ARG,
                   sigrelay_sip_body_decode("identity", 8, body, 3, out, sizeof(out), NULL));
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_ERR_INVALID_ARG,
                   sigrelay_sip_body_decode(NULL, 4, body, 3, out, sizeof(out), &out_len));
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_ERR_INVALID_ARG,
                   sigrelay_sip_body_decode("gzip", 4, NULL, 3, out, sizeof(out), &out_len));
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_ERR_INVALID_ARG,
                   sigrelay_sip_body_decode("identity", 8, body, 3, NULL, 3, &out_len));
    TEST_ASSERT(out_len == SIZE_MAX);

    /* Every status has its own message. */
    for (int i = SIGRELAY_SIP_BODY_OK; i <= SIGRELAY_SIP_BODY_ERR_INTERNAL; i++) {
        const char *msg = sigrelay_sip_body_strerror((sigrelay_sip_body_status)i);

        TEST_ASSERT(strcmp(msg, "unknown error") != 0);
        for (int j = SIGRELAY_SIP_BODY_OK; j < i; j++) {
            TEST_ASSERT(strcmp(msg, sigrelay_sip_body_strerror((sigrelay_sip_body_status)j)) != 0);
        }
    }
}

void test_sip_parses_content_encoding(void)
{
    char buf[BUF_CAP + 512];
    uint8_t out[BUF_CAP];
    sigrelay_sip_message msg;
    size_t len;
    size_t out_len = 0;

    TEST_ASSERT(check_gzip_invite("Content-Encoding: gzip\r\n"));

    /* Without Content-Encoding the body is identity. */
    len = build_invite("", (const uint8_t *)sdp, SDP_LEN, buf, sizeof(buf));
    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, sigrelay_sip_parse(buf, len, &msg));
    TEST_ASSERT_EQ(0, msg.content_encoding.len);
    TEST_ASSERT_EQ(SIGRELAY_SIP_BODY_OK,
                   sigrelay_sip_body_decode(msg.content_encoding.ptr, msg.content_encoding.len,
                                            (const uint8_t *)msg.body.ptr, msg.body.len, out,
                                            sizeof(out), &out_len));
    TEST_ASSERT_EQ(SDP_LEN, out_len);
    TEST_ASSERT(memcmp(out, sdp, SDP_LEN) == 0);
}

void test_sip_parses_compact_content_encoding(void)
{
    TEST_ASSERT(check_gzip_invite("e: gzip\r\n"));
    TEST_ASSERT(check_gzip_invite("E :  gzip  \r\n"));
}
