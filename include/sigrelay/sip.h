#ifndef SIGRELAY_SIP_H
#define SIGRELAY_SIP_H

#include <stddef.h>
#include <stdint.h>

#include "sigrelay/sigrelay.h"

#ifdef __cplusplus
extern "C" {
#endif

/* RFC 3261 section 8.1.1.5: the CSeq sequence number MUST be less than 2**31. */
#define SIGRELAY_SIP_CSEQ_MAX 0x7FFFFFFFu

typedef enum {
    SIGRELAY_SIP_OK = 0,
    SIGRELAY_SIP_ERR_INVALID_ARG,
    SIGRELAY_SIP_ERR_TRUNCATED,
    SIGRELAY_SIP_ERR_START_LINE,
    SIGRELAY_SIP_ERR_VERSION,
    SIGRELAY_SIP_ERR_STATUS_CODE,
    SIGRELAY_SIP_ERR_HEADER,
    SIGRELAY_SIP_ERR_DUPLICATE_HEADER,
    SIGRELAY_SIP_ERR_MISSING_HEADER,
    SIGRELAY_SIP_ERR_CSEQ,
    SIGRELAY_SIP_ERR_CONTENT_LENGTH
} sigrelay_sip_status;

typedef enum {
    SIGRELAY_SIP_REQUEST,
    SIGRELAY_SIP_RESPONSE
} sigrelay_sip_kind;

/*
 * Parsed SIP message. Every sigrelay_str points into the buffer passed to
 * sigrelay_sip_parse() and is only valid while that buffer is.
 */
typedef struct {
    sigrelay_sip_kind kind;
    sigrelay_str method;      /* requests only */
    sigrelay_str request_uri; /* requests only */
    unsigned status_code;     /* responses only */
    sigrelay_str reason;      /* responses only, may be empty */
    sigrelay_str via;         /* value of the first (topmost) Via header */
    sigrelay_str from;
    sigrelay_str to;
    sigrelay_str call_id;
    uint32_t cseq;
    sigrelay_str cseq_method;
    int has_content_length;
    size_t content_length;
    sigrelay_str content_encoding; /* empty when absent; see sigrelay/sip_body.h */
    sigrelay_str body;
    size_t header_len;  /* start line and headers, including the empty line */
    size_t message_len; /* header_len plus body length */
} sigrelay_sip_message;

/*
 * Parses one SIP message from buf[0, len). buf does not need to be
 * NUL-terminated and is never read past len. Requires Via, From, To, Call-ID
 * and CSeq; compact header forms (v, f, t, i, l, e) are accepted. When
 * Content-Length is absent the body extends to the end of the buffer.
 * Content-Encoding may appear at most once and is not applied to body.
 * *msg is written only on success.
 */
sigrelay_sip_status sigrelay_sip_parse(const char *buf, size_t len, sigrelay_sip_message *msg);

const char *sigrelay_sip_strerror(sigrelay_sip_status status);

#ifdef __cplusplus
}
#endif

#endif /* SIGRELAY_SIP_H */
