#include "sigrelay/diameter.h"

#include <stddef.h>
#include <stdint.h>

static uint32_t read_u24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | (uint32_t)p[2];
}

static uint32_t read_u32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

sigrelay_diam_status sigrelay_diam_parse_header(const uint8_t *buf, size_t len,
                                                sigrelay_diam_header *hdr)
{
    uint32_t msg_len;
    uint8_t flags;

    if (buf == NULL || hdr == NULL) {
        return SIGRELAY_DIAM_ERR_INVALID_ARG;
    }
    if (len < SIGRELAY_DIAM_HEADER_LEN) {
        return SIGRELAY_DIAM_ERR_TRUNCATED;
    }
    if (buf[0] != SIGRELAY_DIAM_VERSION) {
        return SIGRELAY_DIAM_ERR_VERSION;
    }
    /* RFC 6733 section 3: the length covers padded AVPs, so it is a multiple of 4. */
    msg_len = read_u24(buf + 1);
    if (msg_len < SIGRELAY_DIAM_HEADER_LEN || (msg_len & 3u) != 0) {
        return SIGRELAY_DIAM_ERR_LENGTH;
    }
    if (msg_len > len) {
        return SIGRELAY_DIAM_ERR_TRUNCATED;
    }
    /* RFC 6733 section 3: the E bit MUST NOT be set in request messages. */
    flags = buf[4];
    if ((flags & SIGRELAY_DIAM_FLAG_REQUEST) && (flags & SIGRELAY_DIAM_FLAG_ERROR)) {
        return SIGRELAY_DIAM_ERR_FLAGS;
    }

    hdr->version = buf[0];
    hdr->length = msg_len;
    hdr->flags = flags;
    hdr->command_code = read_u24(buf + 5);
    hdr->application_id = read_u32(buf + 8);
    hdr->hop_by_hop = read_u32(buf + 12);
    hdr->end_to_end = read_u32(buf + 16);
    return SIGRELAY_DIAM_OK;
}

void sigrelay_diam_avp_iter_init(sigrelay_diam_avp_iter *it, const uint8_t *data, size_t len)
{
    if (it == NULL) {
        return;
    }
    it->data = data;
    it->len = len;
    it->offset = 0;
    it->status = (data == NULL && len > 0) ? SIGRELAY_DIAM_ERR_INVALID_ARG : SIGRELAY_DIAM_OK;
}

static sigrelay_diam_status iter_fail(sigrelay_diam_avp_iter *it, sigrelay_diam_status status)
{
    it->status = status;
    return status;
}

sigrelay_diam_status sigrelay_diam_avp_next(sigrelay_diam_avp_iter *it, sigrelay_diam_avp *avp)
{
    const uint8_t *p;
    size_t remaining;
    size_t header_len;
    size_t padded_len;
    uint32_t avp_len;
    uint8_t flags;

    if (it == NULL || avp == NULL) {
        return SIGRELAY_DIAM_ERR_INVALID_ARG;
    }
    if (it->status != SIGRELAY_DIAM_OK) {
        return it->status;
    }
    if (it->offset >= it->len) {
        return iter_fail(it, SIGRELAY_DIAM_END);
    }

    remaining = it->len - it->offset;
    p = it->data + it->offset;
    if (remaining < SIGRELAY_DIAM_AVP_HEADER_LEN) {
        return iter_fail(it, SIGRELAY_DIAM_ERR_AVP_TRUNCATED);
    }
    flags = p[4];
    avp_len = read_u24(p + 5);
    header_len = (flags & SIGRELAY_DIAM_AVP_FLAG_VENDOR) ? SIGRELAY_DIAM_AVP_VENDOR_HEADER_LEN
                                                         : SIGRELAY_DIAM_AVP_HEADER_LEN;
    if (avp_len < header_len || avp_len > remaining) {
        return iter_fail(it, SIGRELAY_DIAM_ERR_AVP_LENGTH);
    }
    /* The AVP length excludes padding; avp_len < 2^24 so this cannot overflow. */
    padded_len = (size_t)avp_len + ((4u - (avp_len & 3u)) & 3u);
    if (padded_len > remaining) {
        return iter_fail(it, SIGRELAY_DIAM_ERR_AVP_PADDING);
    }
    for (size_t i = avp_len; i < padded_len; i++) {
        if (p[i] != 0) {
            return iter_fail(it, SIGRELAY_DIAM_ERR_AVP_PADDING);
        }
    }

    avp->code = read_u32(p);
    avp->flags = flags;
    avp->length = avp_len;
    avp->vendor_id = (flags & SIGRELAY_DIAM_AVP_FLAG_VENDOR) ? read_u32(p + 8) : 0;
    avp->data = p + header_len;
    avp->data_len = avp_len - header_len;
    it->offset += padded_len;
    return SIGRELAY_DIAM_OK;
}

const char *sigrelay_diam_strerror(sigrelay_diam_status status)
{
    switch (status) {
    case SIGRELAY_DIAM_OK:
        return "ok";
    case SIGRELAY_DIAM_END:
        return "end of AVPs";
    case SIGRELAY_DIAM_ERR_INVALID_ARG:
        return "invalid argument";
    case SIGRELAY_DIAM_ERR_TRUNCATED:
        return "message truncated";
    case SIGRELAY_DIAM_ERR_VERSION:
        return "unsupported Diameter version";
    case SIGRELAY_DIAM_ERR_LENGTH:
        return "invalid message length";
    case SIGRELAY_DIAM_ERR_FLAGS:
        return "invalid command flags";
    case SIGRELAY_DIAM_ERR_AVP_TRUNCATED:
        return "AVP header truncated";
    case SIGRELAY_DIAM_ERR_AVP_LENGTH:
        return "invalid AVP length";
    case SIGRELAY_DIAM_ERR_AVP_PADDING:
        return "invalid AVP padding";
    }
    return "unknown error";
}
