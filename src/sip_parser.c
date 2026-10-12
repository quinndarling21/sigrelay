#include "sigrelay/sip.h"

#include <stdint.h>
#include <string.h>

#define SIP_VERSION "SIP/2.0"
#define SIP_VERSION_LEN (sizeof(SIP_VERSION) - 1)

enum {
    SEEN_VIA = 1u << 0,
    SEEN_FROM = 1u << 1,
    SEEN_TO = 1u << 2,
    SEEN_CALL_ID = 1u << 3,
    SEEN_CSEQ = 1u << 4,
    SEEN_CONTENT_LENGTH = 1u << 5,
    SEEN_CONTENT_ENCODING = 1u << 6
};

#define SEEN_REQUIRED (SEEN_VIA | SEEN_FROM | SEEN_TO | SEEN_CALL_ID | SEEN_CSEQ)

static int is_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static int is_alnum(unsigned char c)
{
    return is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

/* RFC 3261 token characters. */
static int is_token_char(unsigned char c)
{
    if (is_alnum(c)) {
        return 1;
    }
    switch (c) {
    case '-':
    case '.':
    case '!':
    case '%':
    case '*':
    case '_':
    case '+':
    case '`':
    case '\'':
    case '~':
        return 1;
    default:
        return 0;
    }
}

static int is_wsp(unsigned char c)
{
    return c == ' ' || c == '\t';
}

/* Header values may hold UTF-8 and HTAB but no other control characters. */
static int is_value_char(unsigned char c)
{
    return c == '\t' || (c >= 0x20 && c != 0x7F);
}

static unsigned char ascii_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

static int str_ieq(const char *p, size_t n, const char *lit)
{
    size_t lit_len = strlen(lit);

    if (n != lit_len) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (ascii_lower((unsigned char)p[i]) != ascii_lower((unsigned char)lit[i])) {
            return 0;
        }
    }
    return 1;
}

static int is_token(const char *p, size_t n)
{
    if (n == 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        if (!is_token_char((unsigned char)p[i])) {
            return 0;
        }
    }
    return 1;
}

/* Offset of the CR of the next CRLF at or after pos, or len if there is none. */
static size_t find_crlf(const char *buf, size_t len, size_t pos)
{
    for (size_t i = pos; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            return i;
        }
    }
    return len;
}

static size_t find_char(const char *p, size_t n, size_t from, char c)
{
    for (size_t i = from; i < n; i++) {
        if (p[i] == c) {
            return i;
        }
    }
    return n;
}

static sigrelay_str make_str(const char *p, size_t n)
{
    sigrelay_str s;

    s.ptr = p;
    s.len = n;
    return s;
}

/* Parses 1*DIGIT, rejecting values above max without overflowing. */
static int parse_decimal(const char *p, size_t n, uint64_t max, uint64_t *out)
{
    uint64_t value = 0;

    if (n == 0) {
        return 0;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        uint64_t digit;

        if (!is_digit(c)) {
            return 0;
        }
        digit = (uint64_t)(c - '0');
        if (value > (max - digit) / 10u) {
            return 0;
        }
        value = value * 10u + digit;
    }
    *out = value;
    return 1;
}

static sigrelay_sip_status parse_request_line(const char *line, size_t n, sigrelay_sip_message *m)
{
    size_t sp1 = find_char(line, n, 0, ' ');
    size_t uri_start;
    size_t sp2;
    size_t version_start;

    if (sp1 == n || !is_token(line, sp1)) {
        return SIGRELAY_SIP_ERR_START_LINE;
    }
    uri_start = sp1 + 1;
    sp2 = find_char(line, n, uri_start, ' ');
    if (sp2 == n || sp2 == uri_start) {
        return SIGRELAY_SIP_ERR_START_LINE;
    }
    for (size_t i = uri_start; i < sp2; i++) {
        unsigned char c = (unsigned char)line[i];

        if (c <= 0x20 || c == 0x7F) {
            return SIGRELAY_SIP_ERR_START_LINE;
        }
    }
    version_start = sp2 + 1;
    if (!str_ieq(line + version_start, n - version_start, SIP_VERSION)) {
        return SIGRELAY_SIP_ERR_VERSION;
    }
    m->kind = SIGRELAY_SIP_REQUEST;
    m->method = make_str(line, sp1);
    m->request_uri = make_str(line + uri_start, sp2 - uri_start);
    return SIGRELAY_SIP_OK;
}

static sigrelay_sip_status parse_status_line(const char *line, size_t n, sigrelay_sip_message *m)
{
    size_t code_start = SIP_VERSION_LEN + 1;
    size_t code_end;
    uint64_t code;

    if (n < code_start || !str_ieq(line, SIP_VERSION_LEN, SIP_VERSION)) {
        return SIGRELAY_SIP_ERR_VERSION;
    }
    if (line[SIP_VERSION_LEN] != ' ') {
        return SIGRELAY_SIP_ERR_VERSION;
    }
    code_end = find_char(line, n, code_start, ' ');
    if (code_end - code_start != 3 || !parse_decimal(line + code_start, 3, 699, &code) ||
        code < 100) {
        return SIGRELAY_SIP_ERR_STATUS_CODE;
    }
    if (code_end == n) {
        return SIGRELAY_SIP_ERR_START_LINE;
    }
    for (size_t i = code_end + 1; i < n; i++) {
        if (!is_value_char((unsigned char)line[i])) {
            return SIGRELAY_SIP_ERR_START_LINE;
        }
    }
    m->kind = SIGRELAY_SIP_RESPONSE;
    m->status_code = (unsigned)code;
    m->reason = make_str(line + code_end + 1, n - code_end - 1);
    return SIGRELAY_SIP_OK;
}

static sigrelay_sip_status parse_start_line(const char *line, size_t n, sigrelay_sip_message *m)
{
    if (n >= 4 && str_ieq(line, 4, "SIP/")) {
        return parse_status_line(line, n, m);
    }
    return parse_request_line(line, n, m);
}

/* CSeq = 1*DIGIT LWS Method */
static sigrelay_sip_status parse_cseq(sigrelay_str value, sigrelay_sip_message *m)
{
    size_t digits = 0;
    size_t method_start;
    uint64_t number;

    while (digits < value.len && is_digit((unsigned char)value.ptr[digits])) {
        digits++;
    }
    if (!parse_decimal(value.ptr, digits, SIGRELAY_SIP_CSEQ_MAX, &number)) {
        return SIGRELAY_SIP_ERR_CSEQ;
    }
    method_start = digits;
    while (method_start < value.len && is_wsp((unsigned char)value.ptr[method_start])) {
        method_start++;
    }
    if (method_start == digits || !is_token(value.ptr + method_start, value.len - method_start)) {
        return SIGRELAY_SIP_ERR_CSEQ;
    }
    m->cseq = (uint32_t)number;
    m->cseq_method = make_str(value.ptr + method_start, value.len - method_start);
    return SIGRELAY_SIP_OK;
}

static sigrelay_sip_status set_once(unsigned *seen, unsigned bit, sigrelay_str value,
                                    sigrelay_str *field)
{
    if (*seen & bit) {
        return SIGRELAY_SIP_ERR_DUPLICATE_HEADER;
    }
    if (value.len == 0) {
        return SIGRELAY_SIP_ERR_HEADER;
    }
    *seen |= bit;
    *field = value;
    return SIGRELAY_SIP_OK;
}

static sigrelay_sip_status split_header(const char *line, size_t n, sigrelay_str *name,
                                        sigrelay_str *value)
{
    size_t name_len = 0;
    size_t pos;
    size_t value_end;

    while (name_len < n && is_token_char((unsigned char)line[name_len])) {
        name_len++;
    }
    /* Also rejects obsolete line folding (a line starting with SP or HTAB). */
    if (name_len == 0) {
        return SIGRELAY_SIP_ERR_HEADER;
    }
    pos = name_len;
    while (pos < n && is_wsp((unsigned char)line[pos])) {
        pos++;
    }
    if (pos == n || line[pos] != ':') {
        return SIGRELAY_SIP_ERR_HEADER;
    }
    pos++;
    for (size_t i = pos; i < n; i++) {
        if (!is_value_char((unsigned char)line[i])) {
            return SIGRELAY_SIP_ERR_HEADER;
        }
    }
    while (pos < n && is_wsp((unsigned char)line[pos])) {
        pos++;
    }
    value_end = n;
    while (value_end > pos && is_wsp((unsigned char)line[value_end - 1])) {
        value_end--;
    }
    *name = make_str(line, name_len);
    *value = make_str(line + pos, value_end - pos);
    return SIGRELAY_SIP_OK;
}

/*
 * A later Via is valid SIP; only the topmost value is stored. An empty value
 * is rejected on every row, including one that follows a valid Via.
 */
static sigrelay_sip_status apply_via(sigrelay_str value, sigrelay_sip_message *m, unsigned *seen)
{
    if (value.len == 0) {
        return SIGRELAY_SIP_ERR_HEADER;
    }
    if (!(*seen & SEEN_VIA)) {
        *seen |= SEEN_VIA;
        m->via = value;
    }
    return SIGRELAY_SIP_OK;
}

static sigrelay_sip_status apply_cseq(sigrelay_str value, sigrelay_sip_message *m, unsigned *seen)
{
    if (*seen & SEEN_CSEQ) {
        return SIGRELAY_SIP_ERR_DUPLICATE_HEADER;
    }
    *seen |= SEEN_CSEQ;
    return parse_cseq(value, m);
}

static sigrelay_sip_status apply_content_length(sigrelay_str value, sigrelay_sip_message *m,
                                                unsigned *seen)
{
    uint64_t length;

    if (*seen & SEEN_CONTENT_LENGTH) {
        return SIGRELAY_SIP_ERR_DUPLICATE_HEADER;
    }
    *seen |= SEEN_CONTENT_LENGTH;
    if (!parse_decimal(value.ptr, value.len, SIZE_MAX, &length)) {
        return SIGRELAY_SIP_ERR_CONTENT_LENGTH;
    }
    m->has_content_length = 1;
    m->content_length = (size_t)length;
    return SIGRELAY_SIP_OK;
}

enum header_id {
    HEADER_VIA,
    HEADER_FROM,
    HEADER_TO,
    HEADER_CALL_ID,
    HEADER_CSEQ,
    HEADER_CONTENT_LENGTH,
    HEADER_CONTENT_ENCODING
};

/* Long and compact names share an id, so "l" and "Content-Length" are one header. */
static const struct {
    const char *name;
    enum header_id id;
} known_headers[] = {
    {"via", HEADER_VIA},
    {"v", HEADER_VIA},
    {"from", HEADER_FROM},
    {"f", HEADER_FROM},
    {"to", HEADER_TO},
    {"t", HEADER_TO},
    {"call-id", HEADER_CALL_ID},
    {"i", HEADER_CALL_ID},
    {"cseq", HEADER_CSEQ},
    {"content-length", HEADER_CONTENT_LENGTH},
    {"l", HEADER_CONTENT_LENGTH},
    {"content-encoding", HEADER_CONTENT_ENCODING},
    {"e", HEADER_CONTENT_ENCODING},
};

static int find_header(sigrelay_str name, enum header_id *id)
{
    for (size_t i = 0; i < sizeof(known_headers) / sizeof(known_headers[0]); i++) {
        if (str_ieq(name.ptr, name.len, known_headers[i].name)) {
            *id = known_headers[i].id;
            return 1;
        }
    }
    return 0;
}

static sigrelay_sip_status dispatch_header(enum header_id id, sigrelay_str value,
                                           sigrelay_sip_message *m, unsigned *seen)
{
    switch (id) {
    case HEADER_VIA:
        return apply_via(value, m, seen);
    case HEADER_FROM:
        return set_once(seen, SEEN_FROM, value, &m->from);
    case HEADER_TO:
        return set_once(seen, SEEN_TO, value, &m->to);
    case HEADER_CALL_ID:
        return set_once(seen, SEEN_CALL_ID, value, &m->call_id);
    case HEADER_CSEQ:
        return apply_cseq(value, m, seen);
    case HEADER_CONTENT_LENGTH:
        return apply_content_length(value, m, seen);
    case HEADER_CONTENT_ENCODING:
        /*
         * A second Content-Encoding row would add a coding to the list; it is
         * rejected rather than kept or dropped so the body is never decoded with
         * only part of its codings.
         */
        return set_once(seen, SEEN_CONTENT_ENCODING, value, &m->content_encoding);
    default:
        /* An id with no case would silently ignore a header the table recognized. */
        return SIGRELAY_SIP_ERR_HEADER;
    }
}

static sigrelay_sip_status parse_header_line(const char *line, size_t n, sigrelay_sip_message *m,
                                             unsigned *seen)
{
    sigrelay_str name;
    sigrelay_str value;
    enum header_id id;
    sigrelay_sip_status status = split_header(line, n, &name, &value);

    if (status != SIGRELAY_SIP_OK) {
        return status;
    }
    if (!find_header(name, &id)) {
        return SIGRELAY_SIP_OK;
    }
    return dispatch_header(id, value, m, seen);
}

sigrelay_sip_status sigrelay_sip_parse(const char *buf, size_t len, sigrelay_sip_message *msg)
{
    sigrelay_sip_message m;
    sigrelay_sip_status status;
    unsigned seen = 0;
    size_t eol;
    size_t pos;
    size_t available;

    if (buf == NULL || msg == NULL) {
        return SIGRELAY_SIP_ERR_INVALID_ARG;
    }
    memset(&m, 0, sizeof(m));

    eol = find_crlf(buf, len, 0);
    if (eol == len) {
        return SIGRELAY_SIP_ERR_TRUNCATED;
    }
    status = parse_start_line(buf, eol, &m);
    if (status != SIGRELAY_SIP_OK) {
        return status;
    }

    pos = eol + 2;
    for (;;) {
        eol = find_crlf(buf, len, pos);
        if (eol == len) {
            return SIGRELAY_SIP_ERR_TRUNCATED;
        }
        if (eol == pos) {
            break;
        }
        status = parse_header_line(buf + pos, eol - pos, &m, &seen);
        if (status != SIGRELAY_SIP_OK) {
            return status;
        }
        pos = eol + 2;
    }
    m.header_len = eol + 2;

    if ((seen & SEEN_REQUIRED) != SEEN_REQUIRED) {
        return SIGRELAY_SIP_ERR_MISSING_HEADER;
    }
    if (m.kind == SIGRELAY_SIP_REQUEST &&
        (m.cseq_method.len != m.method.len ||
         memcmp(m.cseq_method.ptr, m.method.ptr, m.method.len) != 0)) {
        return SIGRELAY_SIP_ERR_CSEQ;
    }

    available = len - m.header_len;
    if (m.has_content_length) {
        if (m.content_length > available) {
            return SIGRELAY_SIP_ERR_TRUNCATED;
        }
        m.body = make_str(buf + m.header_len, m.content_length);
    } else {
        m.body = make_str(buf + m.header_len, available);
    }
    m.message_len = m.header_len + m.body.len;

    *msg = m;
    return SIGRELAY_SIP_OK;
}

const char *sigrelay_sip_strerror(sigrelay_sip_status status)
{
    switch (status) {
    case SIGRELAY_SIP_OK:
        return "ok";
    case SIGRELAY_SIP_ERR_INVALID_ARG:
        return "invalid argument";
    case SIGRELAY_SIP_ERR_TRUNCATED:
        return "message truncated";
    case SIGRELAY_SIP_ERR_START_LINE:
        return "malformed start line";
    case SIGRELAY_SIP_ERR_VERSION:
        return "unsupported SIP version";
    case SIGRELAY_SIP_ERR_STATUS_CODE:
        return "invalid status code";
    case SIGRELAY_SIP_ERR_HEADER:
        return "malformed header";
    case SIGRELAY_SIP_ERR_DUPLICATE_HEADER:
        return "duplicate header";
    case SIGRELAY_SIP_ERR_MISSING_HEADER:
        return "missing mandatory header";
    case SIGRELAY_SIP_ERR_CSEQ:
        return "invalid CSeq";
    case SIGRELAY_SIP_ERR_CONTENT_LENGTH:
        return "invalid Content-Length";
    }
    return "unknown error";
}
