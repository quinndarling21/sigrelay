#include "sigrelay/upstream.h"

#include <string.h>

#define NO_MEMBER SIZE_MAX

static unsigned char ascii_lower(unsigned char c)
{
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c - 'A' + 'a') : c;
}

static int valid_next_hop(const char *hop, size_t len)
{
    if (len == 0 || len > SIGRELAY_UPSTREAM_NAME_MAX) {
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

static int valid_domain(const char *domain, size_t len)
{
    if (len == 0 || len > SIGRELAY_UPSTREAM_DOMAIN_MAX) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)domain[i];

        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '.')) {
            return 0;
        }
    }
    return 1;
}

/* Index of the member called name, or pool->count if there is none. */
static size_t find_index(const sigrelay_upstream_pool *pool, const char *name, size_t len)
{
    for (size_t i = 0; i < pool->count; i++) {
        const sigrelay_upstream_member *member = &pool->members[i];

        if (member->name_len == len && memcmp(member->name, name, len) == 0) {
            return i;
        }
    }
    return pool->count;
}

static int selectable(const sigrelay_upstream_member *member)
{
    return member->state == SIGRELAY_UPSTREAM_HEALTHY && member->credit > 0;
}

/*
 * First selectable member at or after the cursor, wrapping around to the
 * start of the pool. pool->count must be at least 1.
 */
static size_t next_selectable(const sigrelay_upstream_pool *pool)
{
    for (size_t i = pool->cursor; i < pool->count - 1; i++) {
        if (selectable(&pool->members[i])) {
            return i;
        }
    }
    for (size_t i = 0; i < pool->cursor; i++) {
        if (selectable(&pool->members[i])) {
            return i;
        }
    }
    return NO_MEMBER;
}

/* Starts a new round. Returns 0 if no member is healthy. */
static int refill_credit(sigrelay_upstream_pool *pool)
{
    int any_healthy = 0;

    for (size_t i = 0; i < pool->count; i++) {
        sigrelay_upstream_member *member = &pool->members[i];

        if (member->state == SIGRELAY_UPSTREAM_HEALTHY) {
            member->credit = member->weight;
            any_healthy = 1;
        } else {
            member->credit = 0;
        }
    }
    return any_healthy;
}

sigrelay_upstream_status sigrelay_upstream_pool_init(sigrelay_upstream_pool *pool,
                                                     uint32_t probe_interval_ms,
                                                     uint32_t max_failures)
{
    if (pool == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (probe_interval_ms == 0 || probe_interval_ms > SIGRELAY_UPSTREAM_PROBE_INTERVAL_MAX_MS) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (max_failures == 0 || max_failures > SIGRELAY_UPSTREAM_MAX_FAILURES_LIMIT) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    memset(pool, 0, sizeof(*pool));
    pool->probe_interval_ms = probe_interval_ms;
    pool->max_failures = max_failures;
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_member_add(sigrelay_upstream_pool *pool,
                                                      const char *name, size_t name_len,
                                                      uint8_t weight)
{
    sigrelay_upstream_member *member;

    if (pool == NULL || name == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (!valid_next_hop(name, name_len)) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_NAME;
    }
    if (find_index(pool, name, name_len) != pool->count) {
        return SIGRELAY_UPSTREAM_ERR_DUPLICATE;
    }
    if (pool->count >= SIGRELAY_UPSTREAM_CAPACITY) {
        return SIGRELAY_UPSTREAM_ERR_POOL_FULL;
    }
    if (weight == 0 || weight > SIGRELAY_UPSTREAM_WEIGHT_MAX) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_WEIGHT;
    }

    member = &pool->members[pool->count];
    memset(member, 0, sizeof(*member));
    memcpy(member->name, name, name_len);
    member->name_len = name_len;
    member->weight = weight;
    /*
     * Join the current round with a full share. select() never picks a
     * member without credit, so a new member must not start at zero.
     */
    member->credit = weight > 0 ? weight : 1;
    member->state = SIGRELAY_UPSTREAM_HEALTHY;
    pool->count++;
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_member_remove(sigrelay_upstream_pool *pool,
                                                         const char *name, size_t name_len)
{
    size_t idx;

    if (pool == NULL || name == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    idx = find_index(pool, name, name_len);
    if (idx == pool->count) {
        return SIGRELAY_UPSTREAM_ERR_NOT_FOUND;
    }

    for (size_t i = idx; i + 1 < pool->count; i++) {
        pool->members[i] = pool->members[i + 1];
    }
    pool->count--;
    memset(&pool->members[pool->count], 0, sizeof(pool->members[0]));

    /* Keep the cursor on the member that would have been considered next. */
    if (pool->cursor > idx) {
        pool->cursor--;
    }
    if (pool->cursor >= pool->count) {
        pool->cursor = 0;
    }
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_mark_probe(sigrelay_upstream_pool *pool,
                                                      const char *name, size_t name_len,
                                                      int success, uint64_t now_ms)
{
    sigrelay_upstream_member *member;
    size_t idx;

    if (pool == NULL || name == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    idx = find_index(pool, name, name_len);
    if (idx == pool->count) {
        return SIGRELAY_UPSTREAM_ERR_NOT_FOUND;
    }

    member = &pool->members[idx];
    member->last_probe_ms = now_ms;
    if (success) {
        member->consecutive_failures = 0;
        member->state = SIGRELAY_UPSTREAM_HEALTHY;
        return SIGRELAY_UPSTREAM_OK;
    }
    if (member->consecutive_failures < UINT32_MAX) {
        member->consecutive_failures++;
    }
    if (member->consecutive_failures >= pool->max_failures) {
        member->state = SIGRELAY_UPSTREAM_UNHEALTHY;
        member->credit = 0;
    }
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_probe_due(const sigrelay_upstream_pool *pool,
                                                     const char *name, size_t name_len,
                                                     uint64_t now_ms, int *due)
{
    const sigrelay_upstream_member *member;
    uint32_t factor;
    size_t idx;

    if (pool == NULL || name == NULL || due == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    idx = find_index(pool, name, name_len);
    if (idx == pool->count) {
        return SIGRELAY_UPSTREAM_ERR_NOT_FOUND;
    }

    member = &pool->members[idx];
    factor = member->state == SIGRELAY_UPSTREAM_UNHEALTHY ? SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR : 1u;
    *due = now_ms < member->last_probe_ms ||
           /* False positive (CI triage run 38187716821): sigrelay_upstream_pool_init caps
            * probe_interval_ms at SIGRELAY_UPSTREAM_PROBE_INTERVAL_MAX_MS (600000) and factor is
            * 1 or SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR (4), so the uint32_t product is at most
            * 2400000 and cannot wrap before the widening comparison. */
           // NOLINTNEXTLINE(bugprone-implicit-widening-of-multiplication-result)
           now_ms - member->last_probe_ms >= pool->probe_interval_ms * factor;
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_select(sigrelay_upstream_pool *pool,
                                                  sigrelay_str *next_hop)
{
    sigrelay_upstream_member *member;
    size_t idx;

    if (pool == NULL || next_hop == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (pool->count == 0) {
        return SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY;
    }

    idx = next_selectable(pool);
    if (idx == NO_MEMBER) {
        if (!refill_credit(pool)) {
            return SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY;
        }
        idx = next_selectable(pool);
    }
    if (idx == NO_MEMBER) {
        return SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY;
    }

    member = &pool->members[idx];
    member->credit--;
    pool->cursor = idx + 1 < pool->count ? idx + 1 : 0;
    next_hop->ptr = member->name;
    next_hop->len = member->name_len;
    return SIGRELAY_UPSTREAM_OK;
}

static int domain_ieq(const sigrelay_upstream_cache_entry *entry, const char *domain, size_t len)
{
    if (entry->domain_len != len) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        if ((unsigned char)entry->domain[i] != ascii_lower((unsigned char)domain[i])) {
            return 0;
        }
    }
    return 1;
}

static sigrelay_upstream_cache_entry *find_entry(sigrelay_upstream_cache *cache,
                                                 const char *domain, size_t len)
{
    for (size_t i = 0; i < SIGRELAY_UPSTREAM_CACHE_CAPACITY; i++) {
        sigrelay_upstream_cache_entry *entry = &cache->entries[i];

        if (entry->in_use && domain_ieq(entry, domain, len)) {
            return entry;
        }
    }
    return NULL;
}

/* A free or expired slot if there is one, else the entry closest to expiry. */
static sigrelay_upstream_cache_entry *claim_slot(sigrelay_upstream_cache *cache, uint64_t now_ms)
{
    size_t victim = 0;

    for (size_t i = 0; i < SIGRELAY_UPSTREAM_CACHE_CAPACITY; i++) {
        const sigrelay_upstream_cache_entry *entry = &cache->entries[i];

        if (!entry->in_use || now_ms >= entry->expires_ms) {
            return &cache->entries[i];
        }
        if (entry->expires_ms < cache->entries[victim].expires_ms) {
            victim = i;
        }
    }
    return &cache->entries[victim];
}

sigrelay_upstream_status sigrelay_upstream_cache_init(sigrelay_upstream_cache *cache,
                                                      uint32_t ttl_ms)
{
    if (cache == NULL || ttl_ms == 0 || ttl_ms > SIGRELAY_UPSTREAM_CACHE_TTL_MAX_MS) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    memset(cache, 0, sizeof(*cache));
    cache->ttl_ms = ttl_ms;
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_cache_lookup(const sigrelay_upstream_cache *cache,
                                                        const char *domain, size_t domain_len,
                                                        uint64_t now_ms, sigrelay_str *next_hop)
{
    if (cache == NULL || domain == NULL || next_hop == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (!valid_domain(domain, domain_len)) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_NAME;
    }
    for (size_t i = 0; i < SIGRELAY_UPSTREAM_CACHE_CAPACITY; i++) {
        const sigrelay_upstream_cache_entry *entry = &cache->entries[i];

        if (!entry->in_use || !domain_ieq(entry, domain, domain_len)) {
            continue;
        }
        if (now_ms >= entry->expires_ms) {
            return SIGRELAY_UPSTREAM_ERR_CACHE_MISS;
        }
        next_hop->ptr = entry->next_hop;
        next_hop->len = entry->next_hop_len;
        return SIGRELAY_UPSTREAM_OK;
    }
    return SIGRELAY_UPSTREAM_ERR_CACHE_MISS;
}

sigrelay_upstream_status sigrelay_upstream_cache_store(sigrelay_upstream_cache *cache,
                                                       const char *domain, size_t domain_len,
                                                       const char *next_hop, size_t next_hop_len,
                                                       uint64_t now_ms)
{
    sigrelay_upstream_cache_entry *entry;

    if (cache == NULL || domain == NULL || next_hop == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (!valid_domain(domain, domain_len) || !valid_next_hop(next_hop, next_hop_len)) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_NAME;
    }

    entry = find_entry(cache, domain, domain_len);
    if (entry == NULL) {
        entry = claim_slot(cache, now_ms);
    }
    memset(entry, 0, sizeof(*entry));
    for (size_t i = 0; i < domain_len; i++) {
        entry->domain[i] = (char)ascii_lower((unsigned char)domain[i]);
    }
    entry->domain_len = domain_len;
    memcpy(entry->next_hop, next_hop, next_hop_len);
    entry->next_hop_len = next_hop_len;
    entry->expires_ms =
        now_ms > UINT64_MAX - cache->ttl_ms ? UINT64_MAX : now_ms + cache->ttl_ms;
    entry->in_use = 1;
    return SIGRELAY_UPSTREAM_OK;
}

sigrelay_upstream_status sigrelay_upstream_cache_invalidate(sigrelay_upstream_cache *cache,
                                                            const char *domain,
                                                            size_t domain_len)
{
    sigrelay_upstream_cache_entry *entry;

    if (cache == NULL || domain == NULL) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_ARG;
    }
    if (!valid_domain(domain, domain_len)) {
        return SIGRELAY_UPSTREAM_ERR_INVALID_NAME;
    }
    entry = find_entry(cache, domain, domain_len);
    if (entry == NULL) {
        return SIGRELAY_UPSTREAM_ERR_NOT_FOUND;
    }
    memset(entry, 0, sizeof(*entry));
    return SIGRELAY_UPSTREAM_OK;
}

const char *sigrelay_upstream_strerror(sigrelay_upstream_status status)
{
    switch (status) {
    case SIGRELAY_UPSTREAM_OK:
        return "ok";
    case SIGRELAY_UPSTREAM_ERR_INVALID_ARG:
        return "invalid argument";
    case SIGRELAY_UPSTREAM_ERR_INVALID_NAME:
        return "invalid next hop or domain";
    case SIGRELAY_UPSTREAM_ERR_INVALID_WEIGHT:
        return "invalid weight";
    case SIGRELAY_UPSTREAM_ERR_DUPLICATE:
        return "duplicate member";
    case SIGRELAY_UPSTREAM_ERR_POOL_FULL:
        return "upstream pool full";
    case SIGRELAY_UPSTREAM_ERR_NOT_FOUND:
        return "not found";
    case SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY:
        return "no healthy upstream";
    case SIGRELAY_UPSTREAM_ERR_CACHE_MISS:
        return "no cached next hop";
    }
    return "unknown error";
}
