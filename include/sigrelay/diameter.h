#ifndef SIGRELAY_DIAMETER_H
#define SIGRELAY_DIAMETER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIGRELAY_DIAM_VERSION 1u
#define SIGRELAY_DIAM_HEADER_LEN 20u
#define SIGRELAY_DIAM_AVP_HEADER_LEN 8u
#define SIGRELAY_DIAM_AVP_VENDOR_HEADER_LEN 12u

/* Command flags (RFC 6733 section 3). */
#define SIGRELAY_DIAM_FLAG_REQUEST 0x80u
#define SIGRELAY_DIAM_FLAG_PROXIABLE 0x40u
#define SIGRELAY_DIAM_FLAG_ERROR 0x20u
#define SIGRELAY_DIAM_FLAG_RETRANSMIT 0x10u

/* AVP flags (RFC 6733 section 4.1). */
#define SIGRELAY_DIAM_AVP_FLAG_VENDOR 0x80u
#define SIGRELAY_DIAM_AVP_FLAG_MANDATORY 0x40u
#define SIGRELAY_DIAM_AVP_FLAG_PROTECTED 0x20u

typedef enum {
    SIGRELAY_DIAM_OK = 0,
    SIGRELAY_DIAM_END, /* AVP iteration finished cleanly */
    SIGRELAY_DIAM_ERR_INVALID_ARG,
    SIGRELAY_DIAM_ERR_TRUNCATED,
    SIGRELAY_DIAM_ERR_VERSION,
    SIGRELAY_DIAM_ERR_LENGTH,
    SIGRELAY_DIAM_ERR_FLAGS,
    SIGRELAY_DIAM_ERR_AVP_TRUNCATED,
    SIGRELAY_DIAM_ERR_AVP_LENGTH,
    SIGRELAY_DIAM_ERR_AVP_PADDING
} sigrelay_diam_status;

typedef struct {
    uint8_t version;
    uint32_t length; /* 24-bit, includes the header and padded AVPs */
    uint8_t flags;
    uint32_t command_code; /* 24-bit */
    uint32_t application_id;
    uint32_t hop_by_hop;
    uint32_t end_to_end;
} sigrelay_diam_header;

typedef struct {
    uint32_t code;
    uint8_t flags;
    uint32_t length;    /* 24-bit, header plus data, excludes padding */
    uint32_t vendor_id; /* 0 unless SIGRELAY_DIAM_AVP_FLAG_VENDOR is set */
    const uint8_t *data;
    size_t data_len;
} sigrelay_diam_avp;

typedef struct {
    const uint8_t *data;
    size_t len;
    size_t offset;
    sigrelay_diam_status status; /* sticky once iteration ends or fails */
} sigrelay_diam_avp_iter;

/*
 * Validates and decodes the 20-byte header at buf[0, len). On success the
 * whole message (hdr->length bytes) is guaranteed to be inside the buffer, so
 * its AVPs are buf + SIGRELAY_DIAM_HEADER_LEN with
 * hdr->length - SIGRELAY_DIAM_HEADER_LEN bytes. *hdr is written only on
 * success.
 */
sigrelay_diam_status sigrelay_diam_parse_header(const uint8_t *buf, size_t len,
                                                sigrelay_diam_header *hdr);

/* Iterates the AVPs in data[0, len): a message body or a Grouped AVP's data. */
void sigrelay_diam_avp_iter_init(sigrelay_diam_avp_iter *it, const uint8_t *data, size_t len);

/*
 * Returns SIGRELAY_DIAM_OK and fills *avp, SIGRELAY_DIAM_END when every byte
 * has been consumed, or an error. After END or an error every further call
 * returns the same status.
 */
sigrelay_diam_status sigrelay_diam_avp_next(sigrelay_diam_avp_iter *it, sigrelay_diam_avp *avp);

const char *sigrelay_diam_strerror(sigrelay_diam_status status);

#ifdef __cplusplus
}
#endif

#endif /* SIGRELAY_DIAMETER_H */
