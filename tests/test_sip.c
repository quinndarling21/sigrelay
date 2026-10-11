#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sigrelay/sip.h"
#include "test_harness.h"

static const char invite[] =
    "INVITE sip:bob@ims.example.net SIP/2.0\r\n"
    "Via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds\r\n"
    "Max-Forwards: 70\r\n"
    "To: <sip:bob@ims.example.net>\r\n"
    "From: <sip:alice@example.org>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pcscf.example.org\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Contact: <sip:alice@192.0.2.10>\r\n"
    "Content-Type: application/sdp\r\n"
    "Content-Length: 5\r\n"
    "\r\n"
    "v=0\r\n";

#define INVITE_LEN (sizeof(invite) - 1)
#define INVITE_LINE "INVITE sip:bob@ims.example.net SIP/2.0"

static const char valid_headers[] =
    "Via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds\r\n"
    "To: <sip:bob@ims.example.net>\r\n"
    "From: <sip:alice@example.org>;tag=1928301774\r\n"
    "Call-ID: a84b4c76e66710@pcscf.example.org\r\n"
    "CSeq: 314159 INVITE\r\n"
    "Content-Length: 0\r\n"
    "\r\n";

/* Parses a heap copy of exactly len bytes so that reads past the end are detectable. */
static sigrelay_sip_status parse_copy(const char *text, size_t len)
{
    sigrelay_sip_message msg;
    sigrelay_sip_status status;
    char *copy = malloc(len > 0 ? len : 1);

    if (copy == NULL) {
        fprintf(stderr, "out of memory\n");
        abort();
    }
    memcpy(copy, text, len);
    status = sigrelay_sip_parse(copy, len, &msg);
    free(copy);
    return status;
}

static sigrelay_sip_status parse_parts(const char *start_line, const char *headers)
{
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "%s\r\n%s", start_line, headers);

    if (n < 0 || (size_t)n >= sizeof(buf)) {
        fprintf(stderr, "message does not fit the test buffer\n");
        abort();
    }
    return parse_copy(buf, (size_t)n);
}

typedef struct {
    const char *text;
    sigrelay_sip_status expected;
} sip_case;

static int check_cases(const char *start_line, const sip_case *cases, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        sigrelay_sip_status got = start_line ? parse_parts(start_line, cases[i].text)
                                             : parse_parts(cases[i].text, valid_headers);

        if (got != cases[i].expected) {
            fprintf(stderr, "input:\n%s\nexpected \"%s\", got \"%s\"\n", cases[i].text,
                    sigrelay_sip_strerror(cases[i].expected), sigrelay_sip_strerror(got));
            return 0;
        }
    }
    return 1;
}

void test_sip_parses_invite(void)
{
    char buf[sizeof(invite) + 64];
    sigrelay_sip_message msg;

    /* Trailing bytes stand in for the next message on a stream; nothing is NUL-terminated. */
    memset(buf, 'X', sizeof(buf));
    memcpy(buf, invite, INVITE_LEN);

    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, sigrelay_sip_parse(buf, sizeof(buf), &msg));
    TEST_ASSERT_EQ(SIGRELAY_SIP_REQUEST, msg.kind);
    TEST_ASSERT_STR("INVITE", msg.method);
    TEST_ASSERT_STR("sip:bob@ims.example.net", msg.request_uri);
    TEST_ASSERT_STR("SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds", msg.via);
    TEST_ASSERT_STR("<sip:alice@example.org>;tag=1928301774", msg.from);
    TEST_ASSERT_STR("<sip:bob@ims.example.net>", msg.to);
    TEST_ASSERT_STR("a84b4c76e66710@pcscf.example.org", msg.call_id);
    TEST_ASSERT_EQ(314159, msg.cseq);
    TEST_ASSERT_STR("INVITE", msg.cseq_method);
    TEST_ASSERT(msg.has_content_length);
    TEST_ASSERT_EQ(5, msg.content_length);
    TEST_ASSERT_STR("v=0\r\n", msg.body);
    TEST_ASSERT_EQ(INVITE_LEN - 5, msg.header_len);
    TEST_ASSERT_EQ(INVITE_LEN, msg.message_len);
}

void test_sip_parses_response(void)
{
    static const char ringing[] =
        "SIP/2.0 180 Ringing\r\n"
        "via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds\r\n"
        "TO: <sip:bob@ims.example.net>;tag=a6c85cf\r\n"
        "from: <sip:alice@example.org>;tag=1928301774\r\n"
        "call-id:a84b4c76e66710@pcscf.example.org\r\n"
        "cseq: 314159 INVITE\r\n"
        "CONTENT-LENGTH :  0  \r\n"
        "\r\n";
    static const char no_reason[] =
        "SIP/2.0 200 \r\n"
        "Via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds\r\n"
        "To: <sip:bob@ims.example.net>;tag=a6c85cf\r\n"
        "From: <sip:alice@example.org>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@pcscf.example.org\r\n"
        "CSeq: 314160 BYE\r\n"
        "\r\n"
        "trailing";
    sigrelay_sip_message msg;

    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, sigrelay_sip_parse(ringing, sizeof(ringing) - 1, &msg));
    TEST_ASSERT_EQ(SIGRELAY_SIP_RESPONSE, msg.kind);
    TEST_ASSERT_EQ(180, msg.status_code);
    TEST_ASSERT_STR("Ringing", msg.reason);
    TEST_ASSERT_STR("a84b4c76e66710@pcscf.example.org", msg.call_id);
    TEST_ASSERT_STR("INVITE", msg.cseq_method);
    TEST_ASSERT(msg.has_content_length);
    TEST_ASSERT_EQ(0, msg.body.len);
    TEST_ASSERT_EQ(sizeof(ringing) - 1, msg.message_len);

    /* Without Content-Length the body runs to the end of the buffer. */
    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, sigrelay_sip_parse(no_reason, sizeof(no_reason) - 1, &msg));
    TEST_ASSERT_EQ(200, msg.status_code);
    TEST_ASSERT_EQ(0, msg.reason.len);
    TEST_ASSERT(!msg.has_content_length);
    TEST_ASSERT_STR("trailing", msg.body);
}

void test_sip_parses_compact_headers(void)
{
    static const char options[] =
        "OPTIONS sip:ims.example.net SIP/2.0\r\n"
        "v: SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKnashds8\r\n"
        "v: SIP/2.0/TCP 192.0.2.20:5060;branch=z9hG4bKfwd1\r\n"
        "t: <sip:ims.example.net>\r\n"
        "f: <sip:monitor@example.org>;tag=73\r\n"
        "i: 9f1c2e@192.0.2.10\r\n"
        "CSeq: 7 OPTIONS\r\n"
        "l: 0\r\n"
        "\r\n";
    sigrelay_sip_message msg;

    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, sigrelay_sip_parse(options, sizeof(options) - 1, &msg));
    TEST_ASSERT_STR("OPTIONS", msg.method);
    TEST_ASSERT_STR("SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKnashds8", msg.via);
    TEST_ASSERT_STR("<sip:ims.example.net>", msg.to);
    TEST_ASSERT_STR("<sip:monitor@example.org>;tag=73", msg.from);
    TEST_ASSERT_STR("9f1c2e@192.0.2.10", msg.call_id);
    TEST_ASSERT_EQ(7, msg.cseq);
    TEST_ASSERT(msg.has_content_length);
    TEST_ASSERT_EQ(0, msg.content_length);
}

void test_sip_parses_multi_value_via(void)
{
    static const char response[] =
        "SIP/2.0 200 OK\r\n"
        "Via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds, "
        "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKnashds8\r\n"
        "To: <sip:bob@ims.example.net>;tag=a6c85cf\r\n"
        "From: <sip:alice@example.org>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@pcscf.example.org\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Content-Length: 0\r\n"
        "\r\n";
    sigrelay_sip_message msg;

    /* One Via line may carry several comma-separated values; the first is the topmost. */
    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, sigrelay_sip_parse(response, sizeof(response) - 1, &msg));
    TEST_ASSERT_STR("SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds", msg.via);
}

void test_sip_rejects_malformed_start_line(void)
{
    static const sip_case cases[] = {
        {INVITE_LINE, SIGRELAY_SIP_OK},
        {"", SIGRELAY_SIP_ERR_START_LINE},
        {"INVITE", SIGRELAY_SIP_ERR_START_LINE},
        {"INVITE sip:bob@ims.example.net", SIGRELAY_SIP_ERR_START_LINE},
        {"INVITE  sip:bob@ims.example.net SIP/2.0", SIGRELAY_SIP_ERR_START_LINE},
        {"INV@TE sip:bob@ims.example.net SIP/2.0", SIGRELAY_SIP_ERR_START_LINE},
        {"INVITE sip:bob@ims.example.net SIP/3.0", SIGRELAY_SIP_ERR_VERSION},
        {"INVITE sip:bob@ims.example.net SIP/2.0 extra", SIGRELAY_SIP_ERR_VERSION},
        {"SIP/2.0", SIGRELAY_SIP_ERR_VERSION},
        {"SIP/1.0 200 OK", SIGRELAY_SIP_ERR_VERSION},
        {"SIP/2.0 2000 OK", SIGRELAY_SIP_ERR_STATUS_CODE},
        {"SIP/2.0 099 Too Low", SIGRELAY_SIP_ERR_STATUS_CODE},
        {"SIP/2.0 700 Too High", SIGRELAY_SIP_ERR_STATUS_CODE},
        {"SIP/2.0 2x0 OK", SIGRELAY_SIP_ERR_STATUS_CODE},
        {"SIP/2.0 200", SIGRELAY_SIP_ERR_START_LINE},
    };

    TEST_ASSERT(check_cases(NULL, cases, sizeof(cases) / sizeof(cases[0])));
}

void test_sip_rejects_malformed_headers(void)
{
#define VIA "Via: SIP/2.0/UDP pcscf.example.org:5060;branch=z9hG4bK776asdhds\r\n"
#define TO "To: <sip:bob@ims.example.net>\r\n"
#define FROM "From: <sip:alice@example.org>;tag=1928301774\r\n"
#define CALL_ID "Call-ID: a84b4c76e66710@pcscf.example.org\r\n"
#define CSEQ "CSeq: 314159 INVITE\r\n"
    static const sip_case cases[] = {
        {VIA TO FROM CALL_ID CSEQ "\r\n", SIGRELAY_SIP_OK},
        {VIA TO FROM CSEQ "\r\n", SIGRELAY_SIP_ERR_MISSING_HEADER},
        {TO FROM CALL_ID CSEQ "\r\n", SIGRELAY_SIP_ERR_MISSING_HEADER},
        {VIA TO FROM FROM CALL_ID CSEQ "\r\n", SIGRELAY_SIP_ERR_DUPLICATE_HEADER},
        {VIA TO FROM CALL_ID CSEQ CSEQ "\r\n", SIGRELAY_SIP_ERR_DUPLICATE_HEADER},
        {VIA TO FROM CALL_ID CSEQ "Subject: first\r\n second\r\n\r\n", SIGRELAY_SIP_ERR_HEADER},
        {"Via SIP/2.0/UDP pcscf.example.org\r\n" TO FROM CALL_ID CSEQ "\r\n",
         SIGRELAY_SIP_ERR_HEADER},
        {VIA TO FROM CALL_ID CSEQ ": no-name\r\n\r\n", SIGRELAY_SIP_ERR_HEADER},
        {VIA TO FROM "Call-ID:   \r\n" CSEQ "\r\n", SIGRELAY_SIP_ERR_HEADER},
        {VIA TO FROM CALL_ID "Subject: bell\a\r\n" CSEQ "\r\n", SIGRELAY_SIP_ERR_HEADER},
        {VIA TO FROM CALL_ID "CSeq: abc INVITE\r\n\r\n", SIGRELAY_SIP_ERR_CSEQ},
        {VIA TO FROM CALL_ID "CSeq: 2147483648 INVITE\r\n\r\n", SIGRELAY_SIP_ERR_CSEQ},
        {VIA TO FROM CALL_ID "CSeq: 99999999999999999999 INVITE\r\n\r\n",
         SIGRELAY_SIP_ERR_CSEQ},
        {VIA TO FROM CALL_ID "CSeq: 1\r\n\r\n", SIGRELAY_SIP_ERR_CSEQ},
        {VIA TO FROM CALL_ID "CSeq: 1 BYE\r\n\r\n", SIGRELAY_SIP_ERR_CSEQ},
        {VIA TO FROM CALL_ID CSEQ "Content-Length: -1\r\n\r\n",
         SIGRELAY_SIP_ERR_CONTENT_LENGTH},
        {VIA TO FROM CALL_ID CSEQ "Content-Length: 12a\r\n\r\n",
         SIGRELAY_SIP_ERR_CONTENT_LENGTH},
        {VIA TO FROM CALL_ID CSEQ "Content-Length: 18446744073709551616\r\n\r\n",
         SIGRELAY_SIP_ERR_CONTENT_LENGTH},
        {VIA TO FROM CALL_ID CSEQ "l: 0\r\nContent-Length: 0\r\n\r\n",
         SIGRELAY_SIP_ERR_DUPLICATE_HEADER},
    };
#undef VIA
#undef TO
#undef FROM
#undef CALL_ID
#undef CSEQ
    char with_nul[sizeof(invite)];
    char *call_id;

    TEST_ASSERT(check_cases(INVITE_LINE, cases, sizeof(cases) / sizeof(cases[0])));

    /* An embedded NUL must be rejected, not treated as the end of the value. */
    memcpy(with_nul, invite, sizeof(invite));
    call_id = strstr(with_nul, "a84b4c76");
    TEST_ASSERT(call_id != NULL);
    call_id[3] = '\0';
    TEST_ASSERT_EQ(SIGRELAY_SIP_ERR_HEADER, parse_copy(with_nul, INVITE_LEN));
}

void test_sip_rejects_truncated_input(void)
{
    sigrelay_sip_message msg;

    for (size_t len = 0; len < INVITE_LEN; len++) {
        sigrelay_sip_status got = parse_copy(invite, len);

        if (got != SIGRELAY_SIP_ERR_TRUNCATED) {
            fprintf(stderr, "prefix of %zu bytes: got \"%s\"\n", len, sigrelay_sip_strerror(got));
        }
        TEST_ASSERT_EQ(SIGRELAY_SIP_ERR_TRUNCATED, got);
    }
    TEST_ASSERT_EQ(SIGRELAY_SIP_OK, parse_copy(invite, INVITE_LEN));

    TEST_ASSERT_EQ(SIGRELAY_SIP_ERR_TRUNCATED,
                   parse_parts(INVITE_LINE, "Via: SIP/2.0/UDP pcscf.example.org\r\n"
                                            "To: <sip:bob@ims.example.net>\r\n"
                                            "From: <sip:alice@example.org>;tag=1\r\n"
                                            "Call-ID: 1@pcscf.example.org\r\n"
                                            "CSeq: 1 INVITE\r\n"
                                            "Content-Length: 100\r\n"
                                            "\r\n"
                                            "v=0\r\n"));
    TEST_ASSERT_EQ(SIGRELAY_SIP_ERR_INVALID_ARG, sigrelay_sip_parse(NULL, 10, &msg));
    TEST_ASSERT_EQ(SIGRELAY_SIP_ERR_INVALID_ARG, sigrelay_sip_parse(invite, INVITE_LEN, NULL));
}
