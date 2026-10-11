#include "sigrelay/sip_body.h"

#include <limits.h>
#include <string.h>

/* Declares z_stream.next_in as const so input buffers need no cast. */
#define ZLIB_CONST
#include <zlib.h>

/* inflateInit2() window bits: +16 selects the gzip wrapper, a negative value raw deflate. */
#define ZLIB_WINDOW_BITS MAX_WBITS
#define GZIP_WINDOW_BITS (MAX_WBITS + 16)
#define RAW_WINDOW_BITS (-MAX_WBITS)

static unsigned char ascii_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

/* Content-codings are case-insensitive (RFC 3261 section 20.12). */
static int coding_is(const char *p, size_t n, const char *lit)
{
    size_t lit_len = strlen(lit);

    if (n != lit_len) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (ascii_lower((unsigned char)p[i]) != (unsigned char)lit[i]) {
            return 0;
        }
    }
    return 1;
}

/* RFC 1950 section 2.2: CM is 8 (deflate), CINFO at most 7, CMF * 256 + FLG a multiple of 31. */
static int has_zlib_header(const uint8_t *in, size_t in_len)
{
    if (in_len < 2) {
        return 0;
    }
    return (in[0] & 0x0Fu) == 8u && (in[0] >> 4) <= 7u &&
           ((unsigned)in[0] * 256u + in[1]) % 31u == 0u;
}

/* avail_in and avail_out are uInt, so larger buffers are handed to zlib in pieces. */
static uInt take_chunk(size_t *left)
{
    uInt n = (*left > UINT_MAX) ? UINT_MAX : (uInt)*left;

    *left -= n;
    return n;
}

static sigrelay_sip_body_status inflate_status(int ret)
{
    switch (ret) {
    case Z_BUF_ERROR:
        /* Every call has output space, so no progress means the input ran out. */
        return SIGRELAY_SIP_BODY_ERR_TRUNCATED;
    case Z_DATA_ERROR:
    case Z_NEED_DICT:
        return SIGRELAY_SIP_BODY_ERR_CORRUPT;
    case Z_MEM_ERROR:
        return SIGRELAY_SIP_BODY_ERR_NO_MEMORY;
    default:
        return SIGRELAY_SIP_BODY_ERR_INTERNAL;
    }
}

static sigrelay_sip_body_status inflate_body(int window_bits, const uint8_t *in, size_t in_len,
                                             uint8_t *out, size_t out_cap, size_t *out_len)
{
    z_stream zs;
    sigrelay_sip_body_status status;
    size_t in_left = in_len;
    size_t out_left = out_cap;
    size_t produced;
    unsigned char spare;
    int out_full = 0;
    int ret;

    memset(&zs, 0, sizeof(zs));
    ret = inflateInit2(&zs, window_bits);
    if (ret != Z_OK) {
        return inflate_status(ret);
    }
    zs.next_in = in;
    zs.next_out = out;
    for (;;) {
        if (zs.avail_in == 0) {
            zs.avail_in = take_chunk(&in_left);
        }
        if (zs.avail_out == 0) {
            if (out_left > 0) {
                zs.avail_out = take_chunk(&out_left);
            } else if (out_full) {
                status = SIGRELAY_SIP_BODY_ERR_TOO_LARGE;
                break;
            } else {
                /*
                 * out is full. Inflating into one spare byte tells a stream
                 * that ends exactly here from one with more output, without
                 * writing past out_cap.
                 */
                out_full = 1;
                zs.next_out = &spare;
                zs.avail_out = 1;
            }
        }
        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret == Z_STREAM_END) {
            if (out_full && zs.avail_out == 0) {
                status = SIGRELAY_SIP_BODY_ERR_TOO_LARGE;
            } else if (zs.avail_in != 0 || in_left != 0) {
                status = SIGRELAY_SIP_BODY_ERR_CORRUPT;
            } else {
                status = SIGRELAY_SIP_BODY_OK;
            }
            break;
        }
        if (ret != Z_OK) {
            status = inflate_status(ret);
            break;
        }
    }
    produced = out_full ? out_cap : out_cap - out_left - zs.avail_out;
    inflateEnd(&zs);
    if (status == SIGRELAY_SIP_BODY_OK) {
        *out_len = produced;
    }
    return status;
}

static sigrelay_sip_body_status copy_body(const uint8_t *in, size_t in_len, uint8_t *out,
                                          size_t out_cap, size_t *out_len)
{
    if (in_len > out_cap) {
        return SIGRELAY_SIP_BODY_ERR_TOO_LARGE;
    }
    if (in_len > 0) {
        memcpy(out, in, in_len);
    }
    *out_len = in_len;
    return SIGRELAY_SIP_BODY_OK;
}

sigrelay_sip_body_status sigrelay_sip_body_decode(const char *encoding, size_t encoding_len,
                                                  const uint8_t *in, size_t in_len, uint8_t *out,
                                                  size_t out_cap, size_t *out_len)
{
    if ((encoding == NULL && encoding_len > 0) || (in == NULL && in_len > 0) ||
        (out == NULL && out_cap > 0) || out_len == NULL) {
        return SIGRELAY_SIP_BODY_ERR_INVALID_ARG;
    }
    if (encoding_len == 0 || coding_is(encoding, encoding_len, "identity")) {
        return copy_body(in, in_len, out, out_cap, out_len);
    }
    if (coding_is(encoding, encoding_len, "gzip")) {
        return inflate_body(GZIP_WINDOW_BITS, in, in_len, out, out_cap, out_len);
    }
    if (coding_is(encoding, encoding_len, "deflate")) {
        /* RFC 3261 deflate is zlib-wrapped, but some peers send raw deflate data. */
        return inflate_body(has_zlib_header(in, in_len) ? ZLIB_WINDOW_BITS : RAW_WINDOW_BITS, in,
                            in_len, out, out_cap, out_len);
    }
    return SIGRELAY_SIP_BODY_ERR_UNSUPPORTED_ENCODING;
}

const char *sigrelay_sip_body_strerror(sigrelay_sip_body_status status)
{
    switch (status) {
    case SIGRELAY_SIP_BODY_OK:
        return "ok";
    case SIGRELAY_SIP_BODY_ERR_INVALID_ARG:
        return "invalid argument";
    case SIGRELAY_SIP_BODY_ERR_UNSUPPORTED_ENCODING:
        return "unsupported content coding";
    case SIGRELAY_SIP_BODY_ERR_CORRUPT:
        return "corrupt compressed body";
    case SIGRELAY_SIP_BODY_ERR_TRUNCATED:
        return "compressed body truncated";
    case SIGRELAY_SIP_BODY_ERR_TOO_LARGE:
        return "decoded body larger than the output buffer";
    case SIGRELAY_SIP_BODY_ERR_NO_MEMORY:
        return "out of memory";
    case SIGRELAY_SIP_BODY_ERR_INTERNAL:
        return "internal decompressor error";
    }
    return "unknown error";
}
