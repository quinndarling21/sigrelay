#ifndef SIGRELAY_SIP_BODY_H
#define SIGRELAY_SIP_BODY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SIGRELAY_SIP_BODY_OK = 0,
    SIGRELAY_SIP_BODY_ERR_INVALID_ARG,
    SIGRELAY_SIP_BODY_ERR_UNSUPPORTED_ENCODING,
    SIGRELAY_SIP_BODY_ERR_CORRUPT,
    SIGRELAY_SIP_BODY_ERR_TRUNCATED,
    SIGRELAY_SIP_BODY_ERR_TOO_LARGE,
    SIGRELAY_SIP_BODY_ERR_NO_MEMORY,
    SIGRELAY_SIP_BODY_ERR_INTERNAL
} sigrelay_sip_body_status;

/*
 * Decodes a SIP message body with the content-coding named by
 * encoding[0, encoding_len) (RFC 3261 section 20.12), typically the
 * content_encoding and body of a parsed sigrelay_sip_message.
 *
 * Codings are matched case-insensitively:
 *   identity  copied unchanged; an empty encoding (no Content-Encoding) is identity
 *   gzip      gzip format (RFC 1952), a single member
 *   deflate   zlib format (RFC 1950); raw deflate data (RFC 1951) without the
 *             zlib header is also accepted
 * Anything else, including a list of codings, is
 * SIGRELAY_SIP_BODY_ERR_UNSUPPORTED_ENCODING.
 *
 * At most out_cap bytes are ever written to out; a body that decodes to more
 * is SIGRELAY_SIP_BODY_ERR_TOO_LARGE. Bytes after the end of a compressed
 * stream are SIGRELAY_SIP_BODY_ERR_CORRUPT. in and out must not overlap.
 * *out_len is written only on success; on failure the contents of out are
 * unspecified.
 */
sigrelay_sip_body_status sigrelay_sip_body_decode(const char *encoding, size_t encoding_len,
                                                  const uint8_t *in, size_t in_len, uint8_t *out,
                                                  size_t out_cap, size_t *out_len);

const char *sigrelay_sip_body_strerror(sigrelay_sip_body_status status);

#ifdef __cplusplus
}
#endif

#endif /* SIGRELAY_SIP_BODY_H */
