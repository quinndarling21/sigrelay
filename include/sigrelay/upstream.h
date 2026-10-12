#ifndef SIGRELAY_UPSTREAM_H
#define SIGRELAY_UPSTREAM_H

#include <stddef.h>
#include <stdint.h>

#include "sigrelay/sigrelay.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SIGRELAY_UPSTREAM_CAPACITY 16u
#define SIGRELAY_UPSTREAM_NAME_MAX 255u /* host[:port], same limit as a route next hop */
#define SIGRELAY_UPSTREAM_WEIGHT_MIN 1u
#define SIGRELAY_UPSTREAM_WEIGHT_MAX 100u
#define SIGRELAY_UPSTREAM_PROBE_INTERVAL_MAX_MS 600000u /* 10 minutes */
#define SIGRELAY_UPSTREAM_MAX_FAILURES_LIMIT 16u
/* Members that are down are probed this many times less often. */
#define SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR 4u

#define SIGRELAY_UPSTREAM_CACHE_CAPACITY 8u
#define SIGRELAY_UPSTREAM_DOMAIN_MAX 253u /* longest DNS name */
#define SIGRELAY_UPSTREAM_CACHE_TTL_MAX_MS 3600000u /* 1 hour */

typedef enum {
    SIGRELAY_UPSTREAM_OK = 0,
    SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
    SIGRELAY_UPSTREAM_ERR_INVALID_NAME,
    SIGRELAY_UPSTREAM_ERR_INVALID_WEIGHT,
    SIGRELAY_UPSTREAM_ERR_DUPLICATE,
    SIGRELAY_UPSTREAM_ERR_POOL_FULL,
    SIGRELAY_UPSTREAM_ERR_NOT_FOUND,
    SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY,
    SIGRELAY_UPSTREAM_ERR_CACHE_MISS
} sigrelay_upstream_status;

typedef enum {
    SIGRELAY_UPSTREAM_HEALTHY = 0,
    SIGRELAY_UPSTREAM_UNHEALTHY
} sigrelay_upstream_state;

typedef struct {
    char name[SIGRELAY_UPSTREAM_NAME_MAX + 1]; /* NUL-terminated */
    size_t name_len;
    uint8_t weight; /* SIGRELAY_UPSTREAM_WEIGHT_MIN..SIGRELAY_UPSTREAM_WEIGHT_MAX */
    uint8_t credit; /* selections left in the current round */
    sigrelay_upstream_state state;
    uint32_t consecutive_failures;
    uint64_t last_probe_ms; /* caller's clock; 0 until the first probe */
} sigrelay_upstream_member;

/*
 * Fixed-capacity pool of next hops for one destination. Selection is
 * weighted round-robin over healthy members: each round a member is picked
 * up to its weight times, interleaved with the other members.
 */
typedef struct {
    sigrelay_upstream_member members[SIGRELAY_UPSTREAM_CAPACITY];
    size_t count;
    size_t cursor; /* index the next selection scan starts from */
    uint32_t probe_interval_ms;
    uint32_t max_failures;
} sigrelay_upstream_pool;

/*
 * probe_interval_ms is 1..SIGRELAY_UPSTREAM_PROBE_INTERVAL_MAX_MS and
 * max_failures (consecutive failed probes before a member is marked down) is
 * 1..SIGRELAY_UPSTREAM_MAX_FAILURES_LIMIT.
 */
sigrelay_upstream_status sigrelay_upstream_pool_init(sigrelay_upstream_pool *pool,
                                                     uint32_t probe_interval_ms,
                                                     uint32_t max_failures);

/*
 * Adds a healthy member. name is printable ASCII without spaces, compared
 * byte for byte. weight is SIGRELAY_UPSTREAM_WEIGHT_MIN..SIGRELAY_UPSTREAM_WEIGHT_MAX.
 */
sigrelay_upstream_status sigrelay_upstream_member_add(sigrelay_upstream_pool *pool,
                                                      const char *name, size_t name_len,
                                                      uint8_t weight);

/* Removes a member. Views returned by sigrelay_upstream_select may move. */
sigrelay_upstream_status sigrelay_upstream_member_remove(sigrelay_upstream_pool *pool,
                                                         const char *name, size_t name_len);

/*
 * Records a probe result at now_ms. A success resets the failure count and
 * marks the member healthy; max_failures consecutive failures mark it down.
 */
sigrelay_upstream_status sigrelay_upstream_mark_probe(sigrelay_upstream_pool *pool,
                                                      const char *name, size_t name_len,
                                                      int success, uint64_t now_ms);

/*
 * Sets *due to 1 if the member should be probed at now_ms: every
 * probe_interval_ms while healthy, SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR times
 * less often while down, and immediately if the clock went backwards.
 */
sigrelay_upstream_status sigrelay_upstream_probe_due(const sigrelay_upstream_pool *pool,
                                                     const char *name, size_t name_len,
                                                     uint64_t now_ms, int *due);

/*
 * Picks the next healthy member. *next_hop points into the pool. Returns
 * SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY when the pool is empty or every member
 * is down.
 */
sigrelay_upstream_status sigrelay_upstream_select(sigrelay_upstream_pool *pool,
                                                  sigrelay_str *next_hop);

typedef struct {
    char domain[SIGRELAY_UPSTREAM_DOMAIN_MAX + 1]; /* lowercase, NUL-terminated */
    size_t domain_len;
    char next_hop[SIGRELAY_UPSTREAM_NAME_MAX + 1]; /* NUL-terminated */
    size_t next_hop_len;
    uint64_t expires_ms;
    int in_use;
} sigrelay_upstream_cache_entry;

/*
 * Small exact-match cache from a SIP domain to the next hop last selected
 * for it. Entries live for ttl_ms on the caller's clock; when the cache is
 * full the entry closest to expiry is replaced.
 */
typedef struct {
    sigrelay_upstream_cache_entry entries[SIGRELAY_UPSTREAM_CACHE_CAPACITY];
    uint32_t ttl_ms;
} sigrelay_upstream_cache;

/* ttl_ms is 1..SIGRELAY_UPSTREAM_CACHE_TTL_MAX_MS. */
sigrelay_upstream_status sigrelay_upstream_cache_init(sigrelay_upstream_cache *cache,
                                                      uint32_t ttl_ms);

/*
 * Looks up a domain (letters, digits, '-' and '.', case-insensitive). An
 * entry is a hit until now_ms reaches its expiry. *next_hop points into the
 * cache.
 */
sigrelay_upstream_status sigrelay_upstream_cache_lookup(const sigrelay_upstream_cache *cache,
                                                        const char *domain, size_t domain_len,
                                                        uint64_t now_ms, sigrelay_str *next_hop);

/* Stores or refreshes the next hop for a domain, expiring at now_ms + ttl_ms. */
sigrelay_upstream_status sigrelay_upstream_cache_store(sigrelay_upstream_cache *cache,
                                                       const char *domain, size_t domain_len,
                                                       const char *next_hop, size_t next_hop_len,
                                                       uint64_t now_ms);

sigrelay_upstream_status sigrelay_upstream_cache_invalidate(sigrelay_upstream_cache *cache,
                                                            const char *domain,
                                                            size_t domain_len);

const char *sigrelay_upstream_strerror(sigrelay_upstream_status status);

#ifdef __cplusplus
}
#endif

#endif /* SIGRELAY_UPSTREAM_H */
