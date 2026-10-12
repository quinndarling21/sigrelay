#ifndef SIGRELAY_RELAY_H
#define SIGRELAY_RELAY_H

#include <stddef.h>

#include "sigrelay/sigrelay.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SIGRELAY_ROUTE_CAPACITY 64u
#define SIGRELAY_ROUTE_NAME_MAX 253u     /* longest DNS name, presentation form */
#define SIGRELAY_ROUTE_LABEL_MAX 63u     /* longest DNS label, RFC 1035 */
#define SIGRELAY_ROUTE_NEXT_HOP_MAX 255u /* host[:port] or aaa:// URI */

typedef enum {
    SIGRELAY_RELAY_OK = 0,
    SIGRELAY_RELAY_ERR_INVALID_ARG,
    SIGRELAY_RELAY_ERR_INVALID_NAME,
    SIGRELAY_RELAY_ERR_INVALID_NEXT_HOP,
    SIGRELAY_RELAY_ERR_DUPLICATE,
    SIGRELAY_RELAY_ERR_TABLE_FULL,
    SIGRELAY_RELAY_ERR_NOT_FOUND
} sigrelay_relay_status;

typedef struct {
    char destination[SIGRELAY_ROUTE_NAME_MAX + 1]; /* lowercase, NUL-terminated */
    size_t destination_len;
    char next_hop[SIGRELAY_ROUTE_NEXT_HOP_MAX + 1]; /* NUL-terminated */
    size_t next_hop_len;
} sigrelay_route;

/* Fixed-capacity table mapping a Diameter realm or SIP domain to a next hop. */
typedef struct {
    sigrelay_route routes[SIGRELAY_ROUTE_CAPACITY];
    size_t count;
} sigrelay_route_table;

void sigrelay_route_table_init(sigrelay_route_table *table);

/*
 * Adds a route. destination is a Diameter realm or SIP domain (RFC 6733
 * section 4.3.1): dot-separated labels of 1 to 63 octets. A label is letters,
 * digits and interior '-', and does not start or end with '-' (RFC 1035
 * section 2.3.1, RFC 1123 section 2.1). One trailing dot is allowed. The name
 * is compared case-insensitively. next_hop is printable ASCII without spaces.
 */
sigrelay_relay_status sigrelay_route_add(sigrelay_route_table *table, const char *destination,
                                         size_t destination_len, const char *next_hop,
                                         size_t next_hop_len);

/*
 * Finds the next hop for a realm or domain taken from a message. An exact
 * match wins; otherwise the longest parent domain on a label boundary is used,
 * so a route for "example.net" serves "ims.example.net" but not
 * "badexample.net". *next_hop points into the table.
 */
sigrelay_relay_status sigrelay_route_lookup(const sigrelay_route_table *table,
                                            const char *destination, size_t destination_len,
                                            sigrelay_str *next_hop);

const char *sigrelay_relay_strerror(sigrelay_relay_status status);

#ifdef __cplusplus
}
#endif

#endif /* SIGRELAY_RELAY_H */
