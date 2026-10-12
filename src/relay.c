#include "sigrelay/relay.h"

#include <string.h>

static unsigned char ascii_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

static int is_name_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '-' || c == '.';
}

/* RFC 1035 section 2.3.1. RFC 1123 section 2.1 allows the label to start with a digit. */
static int valid_label(const char *label, size_t len)
{
    unsigned char first;
    unsigned char last;

    if (len == 0 || len > SIGRELAY_ROUTE_LABEL_MAX) {
        return 0;
    }
    first = (unsigned char)label[0];
    last = (unsigned char)label[len - 1];
    return first != '-' && last != '-';
}

static int valid_name(const char *name, size_t len)
{
    size_t begin = 0;

    if (len == 0 || len > SIGRELAY_ROUTE_NAME_MAX) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (!is_name_char((unsigned char)name[i])) {
            return 0;
        }
    }

    /* One trailing dot is the DNS root in presentation form ("example.net."),
     * not an empty label. Lookup of that spelling stays NOT_FOUND because
     * stored routes have no trailing dot. A bare "." has no label. */
    if ((unsigned char)name[len - 1] == '.') {
        len--;
        if (len == 0) {
            return 0;
        }
    }

    for (size_t i = 0; i < len; i++) {
        if (name[i] == '.') {
            if (!valid_label(name + begin, i - begin)) {
                return 0;
            }
            begin = i + 1;
        }
    }
    return valid_label(name + begin, len - begin);
}

static int valid_next_hop(const char *hop, size_t len)
{
    if (len == 0 || len > SIGRELAY_ROUTE_NEXT_HOP_MAX) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)hop[i];

        if (c <= 0x20 || c >= 0x7F) {
            return 0;
        }
    }
    return 1;
}

static int name_ieq(const sigrelay_route *route, const char *name, size_t len)
{
    if (route->destination_len != len) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)route->destination[i] != ascii_lower((unsigned char)name[i])) {
            return 0;
        }
    }
    return 1;
}

static const sigrelay_route *find_exact(const sigrelay_route_table *table, const char *name,
                                        size_t len)
{
    for (size_t i = 0; i < table->count; i++) {
        if (name_ieq(&table->routes[i], name, len)) {
            return &table->routes[i];
        }
    }
    return NULL;
}

void sigrelay_route_table_init(sigrelay_route_table *table)
{
    if (table != NULL) {
        memset(table, 0, sizeof(*table));
    }
}

sigrelay_relay_status sigrelay_route_add(sigrelay_route_table *table, const char *destination,
                                         size_t destination_len, const char *next_hop,
                                         size_t next_hop_len)
{
    sigrelay_route *route;

    if (table == NULL || destination == NULL || next_hop == NULL) {
        return SIGRELAY_RELAY_ERR_INVALID_ARG;
    }
    if (!valid_name(destination, destination_len)) {
        return SIGRELAY_RELAY_ERR_INVALID_NAME;
    }
    if (!valid_next_hop(next_hop, next_hop_len)) {
        return SIGRELAY_RELAY_ERR_INVALID_NEXT_HOP;
    }
    if (find_exact(table, destination, destination_len) != NULL) {
        return SIGRELAY_RELAY_ERR_DUPLICATE;
    }
    if (table->count >= SIGRELAY_ROUTE_CAPACITY) {
        return SIGRELAY_RELAY_ERR_TABLE_FULL;
    }

    route = &table->routes[table->count];
    memset(route, 0, sizeof(*route));
    for (size_t i = 0; i < destination_len; i++) {
        route->destination[i] = (char)ascii_lower((unsigned char)destination[i]);
    }
    route->destination_len = destination_len;
    memcpy(route->next_hop, next_hop, next_hop_len);
    route->next_hop_len = next_hop_len;
    table->count++;
    return SIGRELAY_RELAY_OK;
}

sigrelay_relay_status sigrelay_route_lookup(const sigrelay_route_table *table,
                                            const char *destination, size_t destination_len,
                                            sigrelay_str *next_hop)
{
    size_t start = 0;

    if (table == NULL || destination == NULL || next_hop == NULL) {
        return SIGRELAY_RELAY_ERR_INVALID_ARG;
    }
    if (!valid_name(destination, destination_len)) {
        return SIGRELAY_RELAY_ERR_INVALID_NAME;
    }

    while (start < destination_len) {
        const sigrelay_route *route =
            find_exact(table, destination + start, destination_len - start);
        const char *dot;

        if (route != NULL) {
            next_hop->ptr = route->next_hop;
            next_hop->len = route->next_hop_len;
            return SIGRELAY_RELAY_OK;
        }
        dot = memchr(destination + start, '.', destination_len - start);
        if (dot == NULL) {
            break;
        }
        start = (size_t)(dot - destination) + 1;
    }
    return SIGRELAY_RELAY_ERR_NOT_FOUND;
}

const char *sigrelay_relay_strerror(sigrelay_relay_status status)
{
    switch (status) {
    case SIGRELAY_RELAY_OK:
        return "ok";
    case SIGRELAY_RELAY_ERR_INVALID_ARG:
        return "invalid argument";
    case SIGRELAY_RELAY_ERR_INVALID_NAME:
        return "invalid realm or domain";
    case SIGRELAY_RELAY_ERR_INVALID_NEXT_HOP:
        return "invalid next hop";
    case SIGRELAY_RELAY_ERR_DUPLICATE:
        return "duplicate route";
    case SIGRELAY_RELAY_ERR_TABLE_FULL:
        return "route table full";
    case SIGRELAY_RELAY_ERR_NOT_FOUND:
        return "no route";
    }
    return "unknown error";
}
