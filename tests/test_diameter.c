#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sigrelay/diameter.h"
#include "test_harness.h"

#define CMD_UPDATE_LOCATION 316u
#define APP_S6A 16777251u
#define VENDOR_3GPP 10415u

#define AVP_SESSION_ID 263u
#define AVP_ORIGIN_HOST 264u
#define AVP_ORIGIN_REALM 296u
#define AVP_VENDOR_ID 266u
#define AVP_AUTH_APPLICATION_ID 258u
#define AVP_VENDOR_SPECIFIC_APPLICATION_ID 260u
#define AVP_RAT_TYPE 1032u

#define FLAG_M SIGRELAY_DIAM_AVP_FLAG_MANDATORY
#define FLAG_V SIGRELAY_DIAM_AVP_FLAG_VENDOR

typedef struct {
    uint8_t data[512];
    size_t len;
} diam_buf;

static void put_u24(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 16);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)v;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Appends an AVP with zero padding; b->len stays a multiple of 4. */
static void append_avp(diam_buf *b, uint32_t code, uint8_t flags, uint32_t vendor,
                       const void *data, size_t data_len)
{
    size_t header_len = (flags & FLAG_V) ? SIGRELAY_DIAM_AVP_VENDOR_HEADER_LEN
                                         : SIGRELAY_DIAM_AVP_HEADER_LEN;
    size_t avp_len = header_len + data_len;
    size_t padded_len = (avp_len + 3u) & ~(size_t)3u;
    uint8_t *p;

    if (padded_len > sizeof(b->data) - b->len) {
        fprintf(stderr, "AVP does not fit the test buffer\n");
        abort();
    }
    p = b->data + b->len;
    memset(p, 0, padded_len);
    put_u32(p, code);
    p[4] = flags;
    put_u24(p + 5, (uint32_t)avp_len);
    if (flags & FLAG_V) {
        put_u32(p + 8, vendor);
    }
    memcpy(p + header_len, data, data_len);
    b->len += padded_len;
}

static void append_u32_avp(diam_buf *b, uint32_t code, uint8_t flags, uint32_t vendor,
                           uint32_t value)
{
    uint8_t data[4];

    put_u32(data, value);
    append_avp(b, code, flags, vendor, data, sizeof(data));
}

static void begin_message(diam_buf *b, uint8_t flags, uint32_t command, uint32_t app)
{
    memset(b, 0, sizeof(*b));
    b->data[0] = SIGRELAY_DIAM_VERSION;
    b->data[4] = flags;
    put_u24(b->data + 5, command);
    put_u32(b->data + 8, app);
    put_u32(b->data + 12, 0x11223344u);
    put_u32(b->data + 16, 0x55667788u);
    b->len = SIGRELAY_DIAM_HEADER_LEN;
}

static void end_message(diam_buf *b)
{
    put_u24(b->data + 1, (uint32_t)b->len);
}

/* An S6a Update-Location-Request with plain, padded, vendor and Grouped AVPs. */
static void build_ulr(diam_buf *b)
{
    static const char session_id[] = "dra1.example.net;1;42";
    static const char origin_host[] = "mme1.example.net";
    static const char origin_realm[] = "example.net";
    diam_buf group;

    memset(&group, 0, sizeof(group));
    append_u32_avp(&group, AVP_VENDOR_ID, FLAG_M, 0, VENDOR_3GPP);
    append_u32_avp(&group, AVP_AUTH_APPLICATION_ID, FLAG_M, 0, APP_S6A);

    begin_message(b, SIGRELAY_DIAM_FLAG_REQUEST | SIGRELAY_DIAM_FLAG_PROXIABLE,
                  CMD_UPDATE_LOCATION, APP_S6A);
    append_avp(b, AVP_SESSION_ID, FLAG_M, 0, session_id, sizeof(session_id) - 1);
    append_avp(b, AVP_ORIGIN_HOST, FLAG_M, 0, origin_host, sizeof(origin_host) - 1);
    append_avp(b, AVP_ORIGIN_REALM, FLAG_M, 0, origin_realm, sizeof(origin_realm) - 1);
    append_u32_avp(b, AVP_RAT_TYPE, FLAG_V | FLAG_M, VENDOR_3GPP, 1004u);
    append_avp(b, AVP_VENDOR_SPECIFIC_APPLICATION_ID, FLAG_M, 0, group.data, group.len);
    end_message(b);
}

static void init_message_avps(sigrelay_diam_avp_iter *it, const diam_buf *b)
{
    sigrelay_diam_avp_iter_init(it, b->data + SIGRELAY_DIAM_HEADER_LEN,
                                b->len - SIGRELAY_DIAM_HEADER_LEN);
}

static sigrelay_diam_status parse_header_copy(const uint8_t *data, size_t len)
{
    sigrelay_diam_header hdr;
    sigrelay_diam_status status;
    uint8_t *copy = malloc(len > 0 ? len : 1);

    if (copy == NULL) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    memcpy(copy, data, len);
    status = sigrelay_diam_parse_header(copy, len, &hdr);
    free(copy);
    return status;
}

/* Iterates a heap copy of exactly len bytes; returns the terminal status. */
static sigrelay_diam_status drain_avps_copy(const uint8_t *data, size_t len, size_t *consumed)
{
    sigrelay_diam_avp_iter it;
    sigrelay_diam_avp avp;
    sigrelay_diam_status status;
    uint8_t *copy = malloc(len > 0 ? len : 1);

    if (copy == NULL) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    memcpy(copy, data, len);
    sigrelay_diam_avp_iter_init(&it, copy, len);
    while ((status = sigrelay_diam_avp_next(&it, &avp)) == SIGRELAY_DIAM_OK) {
    }
    *consumed = it.offset;
    free(copy);
    return status;
}

void test_diameter_parses_header(void)
{
    diam_buf b;
    sigrelay_diam_header hdr;

    build_ulr(&b);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_parse_header(b.data, b.len, &hdr));
    TEST_ASSERT_EQ(1, hdr.version);
    TEST_ASSERT_EQ(b.len, hdr.length);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_FLAG_REQUEST | SIGRELAY_DIAM_FLAG_PROXIABLE, hdr.flags);
    TEST_ASSERT_EQ(CMD_UPDATE_LOCATION, hdr.command_code);
    TEST_ASSERT_EQ(APP_S6A, hdr.application_id);
    TEST_ASSERT_EQ(0x11223344u, hdr.hop_by_hop);
    TEST_ASSERT_EQ(0x55667788u, hdr.end_to_end);

    /* A buffer holding more than one message is bounded by the length field. */
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_parse_header(b.data, sizeof(b.data), &hdr));
    TEST_ASSERT_EQ(b.len, hdr.length);

    /* Answers may carry the E bit. */
    begin_message(&b, SIGRELAY_DIAM_FLAG_PROXIABLE | SIGRELAY_DIAM_FLAG_ERROR,
                  CMD_UPDATE_LOCATION, APP_S6A);
    end_message(&b);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_parse_header(b.data, b.len, &hdr));
    TEST_ASSERT_EQ(SIGRELAY_DIAM_HEADER_LEN, hdr.length);
}

void test_diameter_iterates_avps(void)
{
    static const uint32_t expected_codes[] = {AVP_SESSION_ID, AVP_ORIGIN_HOST, AVP_ORIGIN_REALM,
                                              AVP_RAT_TYPE, AVP_VENDOR_SPECIFIC_APPLICATION_ID};
    diam_buf b;
    sigrelay_diam_avp_iter it;
    sigrelay_diam_avp_iter group;
    sigrelay_diam_avp avps[5];
    sigrelay_diam_avp avp;

    build_ulr(&b);
    init_message_avps(&it, &b);
    for (size_t i = 0; i < 5; i++) {
        TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_avp_next(&it, &avps[i]));
        TEST_ASSERT_EQ(expected_codes[i], avps[i].code);
    }
    TEST_ASSERT_EQ(SIGRELAY_DIAM_END, sigrelay_diam_avp_next(&it, &avp));
    TEST_ASSERT_EQ(SIGRELAY_DIAM_END, sigrelay_diam_avp_next(&it, &avp));

    TEST_ASSERT_EQ(29, avps[0].length);
    TEST_ASSERT_EQ(21, avps[0].data_len);
    TEST_ASSERT(memcmp(avps[0].data, "dra1.example.net;1;42", 21) == 0);
    TEST_ASSERT_EQ(19, avps[2].length);
    TEST_ASSERT(memcmp(avps[2].data, "example.net", 11) == 0);
    TEST_ASSERT_EQ(FLAG_V | FLAG_M, avps[3].flags);
    TEST_ASSERT_EQ(VENDOR_3GPP, avps[3].vendor_id);
    TEST_ASSERT_EQ(4, avps[3].data_len);
    TEST_ASSERT_EQ(1004, avps[3].data[3] | (avps[3].data[2] << 8));
    TEST_ASSERT_EQ(0, avps[4].vendor_id);

    sigrelay_diam_avp_iter_init(&group, avps[4].data, avps[4].data_len);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_avp_next(&group, &avp));
    TEST_ASSERT_EQ(AVP_VENDOR_ID, avp.code);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_avp_next(&group, &avp));
    TEST_ASSERT_EQ(AVP_AUTH_APPLICATION_ID, avp.code);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_END, sigrelay_diam_avp_next(&group, &avp));
}

void test_diameter_rejects_malformed_header(void)
{
    diam_buf b;
    sigrelay_diam_header hdr;

    build_ulr(&b);
    b.data[0] = 2;
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_VERSION, sigrelay_diam_parse_header(b.data, b.len, &hdr));

    build_ulr(&b);
    put_u24(b.data + 1, 16);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_LENGTH, sigrelay_diam_parse_header(b.data, b.len, &hdr));
    put_u24(b.data + 1, 0);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_LENGTH, sigrelay_diam_parse_header(b.data, b.len, &hdr));
    put_u24(b.data + 1, 22);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_LENGTH, sigrelay_diam_parse_header(b.data, b.len, &hdr));

    /* The largest 24-bit length must be bounded by the buffer, not trusted. */
    put_u24(b.data + 1, 0xFFFFFCu);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_TRUNCATED, sigrelay_diam_parse_header(b.data, b.len, &hdr));

    build_ulr(&b);
    b.data[4] = SIGRELAY_DIAM_FLAG_REQUEST | SIGRELAY_DIAM_FLAG_ERROR;
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_FLAGS, sigrelay_diam_parse_header(b.data, b.len, &hdr));

    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_INVALID_ARG, sigrelay_diam_parse_header(NULL, 20, &hdr));
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_INVALID_ARG, sigrelay_diam_parse_header(b.data, b.len, NULL));
}

void test_diameter_rejects_malformed_avps(void)
{
    uint8_t region[32];
    sigrelay_diam_avp_iter it;
    sigrelay_diam_avp avp;
    size_t consumed;

    /* AVP length below the 8-byte header. */
    memset(region, 0, sizeof(region));
    put_u32(region, AVP_ORIGIN_HOST);
    put_u24(region + 5, 7);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_LENGTH, drain_avps_copy(region, 16, &consumed));
    TEST_ASSERT_EQ(0, consumed);

    /* V bit set but the length leaves no room for the Vendor-ID. */
    region[4] = FLAG_V;
    put_u24(region + 5, 8);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_LENGTH, drain_avps_copy(region, 16, &consumed));

    /* AVP length runs past the enclosing region, including the 24-bit maximum. */
    region[4] = FLAG_M;
    put_u24(region + 5, 40);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_LENGTH, drain_avps_copy(region, 32, &consumed));
    put_u24(region + 5, 0xFFFFFFu);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_LENGTH, drain_avps_copy(region, 32, &consumed));

    /* Fewer bytes than an AVP header after a valid AVP; the error is sticky. */
    put_u24(region + 5, 12);
    sigrelay_diam_avp_iter_init(&it, region, 16);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, sigrelay_diam_avp_next(&it, &avp));
    TEST_ASSERT_EQ(12, avp.length);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_TRUNCATED, sigrelay_diam_avp_next(&it, &avp));
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_TRUNCATED, sigrelay_diam_avp_next(&it, &avp));

    sigrelay_diam_avp_iter_init(&it, NULL, 8);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_INVALID_ARG, sigrelay_diam_avp_next(&it, &avp));
    sigrelay_diam_avp_iter_init(&it, region, 16);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_INVALID_ARG, sigrelay_diam_avp_next(&it, NULL));
}

void test_diameter_rejects_bad_padding(void)
{
    static const char realm[] = "example.net";
    diam_buf b;
    size_t consumed;

    memset(&b, 0, sizeof(b));
    append_avp(&b, AVP_ORIGIN_REALM, FLAG_M, 0, realm, sizeof(realm) - 1);
    TEST_ASSERT_EQ(20, b.len);
    TEST_ASSERT_EQ(SIGRELAY_DIAM_END, drain_avps_copy(b.data, b.len, &consumed));
    TEST_ASSERT_EQ(20, consumed);

    /* Length 19 needs one padding byte; the region ends before it. */
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_PADDING, drain_avps_copy(b.data, 19, &consumed));
    TEST_ASSERT_EQ(0, consumed);

    b.data[19] = 0xAA;
    TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_AVP_PADDING, drain_avps_copy(b.data, b.len, &consumed));
}

void test_diameter_rejects_truncated_input(void)
{
    diam_buf b;
    sigrelay_diam_avp_iter it;
    sigrelay_diam_avp avp;
    size_t boundaries[8];
    size_t boundary_count = 0;
    const uint8_t *avps;
    size_t avps_len;

    build_ulr(&b);
    for (size_t len = 0; len < b.len; len++) {
        TEST_ASSERT_EQ(SIGRELAY_DIAM_ERR_TRUNCATED, parse_header_copy(b.data, len));
    }
    TEST_ASSERT_EQ(SIGRELAY_DIAM_OK, parse_header_copy(b.data, b.len));

    /* Cutting the AVP area anywhere except an AVP boundary must be an error. */
    avps = b.data + SIGRELAY_DIAM_HEADER_LEN;
    avps_len = b.len - SIGRELAY_DIAM_HEADER_LEN;
    sigrelay_diam_avp_iter_init(&it, avps, avps_len);
    boundaries[boundary_count++] = 0;
    while (sigrelay_diam_avp_next(&it, &avp) == SIGRELAY_DIAM_OK) {
        TEST_ASSERT(boundary_count < sizeof(boundaries) / sizeof(boundaries[0]));
        boundaries[boundary_count++] = it.offset;
    }
    TEST_ASSERT_EQ(6, boundary_count);

    for (size_t len = 0; len <= avps_len; len++) {
        size_t consumed;
        sigrelay_diam_status got = drain_avps_copy(avps, len, &consumed);
        int at_boundary = 0;

        for (size_t i = 0; i < boundary_count; i++) {
            at_boundary |= boundaries[i] == len;
        }
        if ((got == SIGRELAY_DIAM_END) != at_boundary) {
            fprintf(stderr, "AVP area cut at %zu bytes: got \"%s\"\n", len,
                    sigrelay_diam_strerror(got));
        }
        TEST_ASSERT_EQ(at_boundary, got == SIGRELAY_DIAM_END);
        TEST_ASSERT(consumed <= len);
    }
}
