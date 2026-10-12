#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sigrelay/upstream.h"
#include "test_harness.h"

#define SCSCF1 "scscf1.ims.example.net:5060"
#define SCSCF2 "scscf2.ims.example.net:5060"
#define SCSCF3 "scscf3.ims.example.net:5060"

static sigrelay_upstream_pool pool;
static sigrelay_upstream_cache cache;

static sigrelay_upstream_status add(const char *name, uint8_t weight)
{
    return sigrelay_upstream_member_add(&pool, name, strlen(name), weight);
}

static sigrelay_upstream_status remove_member(const char *name)
{
    return sigrelay_upstream_member_remove(&pool, name, strlen(name));
}

static sigrelay_upstream_status probe(const char *name, int success, uint64_t now_ms)
{
    return sigrelay_upstream_mark_probe(&pool, name, strlen(name), success, now_ms);
}

static sigrelay_upstream_status probe_due(const char *name, uint64_t now_ms, int *due)
{
    return sigrelay_upstream_probe_due(&pool, name, strlen(name), now_ms, due);
}

/* Index of the member select() returned, or SIGRELAY_UPSTREAM_CAPACITY on error. */
static size_t select_index(void)
{
    sigrelay_str hop;

    if (sigrelay_upstream_select(&pool, &hop) != SIGRELAY_UPSTREAM_OK) {
        return SIGRELAY_UPSTREAM_CAPACITY;
    }
    for (size_t i = 0; i < pool.count; i++) {
        if (hop.ptr == pool.members[i].name && hop.len == pool.members[i].name_len) {
            return i;
        }
    }
    return SIGRELAY_UPSTREAM_CAPACITY;
}

static sigrelay_upstream_status store(const char *domain, const char *next_hop, uint64_t now_ms)
{
    return sigrelay_upstream_cache_store(&cache, domain, strlen(domain), next_hop,
                                         strlen(next_hop), now_ms);
}

static sigrelay_upstream_status lookup(const char *domain, uint64_t now_ms, sigrelay_str *next_hop)
{
    return sigrelay_upstream_cache_lookup(&cache, domain, strlen(domain), now_ms, next_hop);
}

static sigrelay_upstream_status invalidate(const char *domain)
{
    return sigrelay_upstream_cache_invalidate(&cache, domain, strlen(domain));
}

void test_upstream_pool_rejects_invalid_config(void)
{
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_pool_init(NULL, 1000, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_pool_init(&pool, 0, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_pool_init(&pool, SIGRELAY_UPSTREAM_PROBE_INTERVAL_MAX_MS + 1, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_pool_init(&pool, 1000, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_pool_init(&pool, 1000, SIGRELAY_UPSTREAM_MAX_FAILURES_LIMIT + 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_pool_init(&pool, SIGRELAY_UPSTREAM_PROBE_INTERVAL_MAX_MS,
                                               SIGRELAY_UPSTREAM_MAX_FAILURES_LIMIT));
    TEST_ASSERT_EQ(0, pool.count);

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_cache_init(NULL, 100));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_cache_init(&cache, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_init(&cache, SIGRELAY_UPSTREAM_CACHE_TTL_MAX_MS + 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_cache_init(&cache, SIGRELAY_UPSTREAM_CACHE_TTL_MAX_MS));

    for (int s = SIGRELAY_UPSTREAM_OK; s <= SIGRELAY_UPSTREAM_ERR_CACHE_MISS; s++) {
        TEST_ASSERT(strcmp(sigrelay_upstream_strerror((sigrelay_upstream_status)s),
                           "unknown error") != 0);
    }
    TEST_ASSERT(strcmp(sigrelay_upstream_strerror((sigrelay_upstream_status)99),
                       "unknown error") == 0);
}

void test_upstream_adds_and_removes_members(void)
{
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF1, 10));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF2, 20));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add("10.0.0.3:5060", SIGRELAY_UPSTREAM_WEIGHT_MAX));
    TEST_ASSERT_EQ(3, pool.count);
    TEST_ASSERT_EQ(20, pool.members[1].weight);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_HEALTHY, pool.members[1].state);
    TEST_ASSERT_EQ(0, pool.members[1].consecutive_failures);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_DUPLICATE, add(SCSCF2, 5));

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, remove_member(SCSCF2));
    TEST_ASSERT_EQ(2, pool.count);
    TEST_ASSERT_EQ(0, strcmp(SCSCF1, pool.members[0].name));
    TEST_ASSERT_EQ(0, strcmp("10.0.0.3:5060", pool.members[1].name));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_NOT_FOUND, remove_member(SCSCF2));

    /* Names take a length and must not depend on NUL termination. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_member_remove(&pool, "10.0.0.3:5060XYZ",
                                                   strlen("10.0.0.3:5060")));
    TEST_ASSERT_EQ(1, pool.count);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF2, 5));
    TEST_ASSERT_EQ(2, pool.count);
}

void test_upstream_rejects_invalid_members(void)
{
    char name[SIGRELAY_UPSTREAM_NAME_MAX + 1];

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, add("", 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, add("scscf1 ims.example.net", 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, add("scscf1\tims.example.net", 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, add("scscf1\x7f", 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_WEIGHT, add(SCSCF1, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_WEIGHT, add(SCSCF1, SIGRELAY_UPSTREAM_WEIGHT_MAX + 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_member_add(NULL, "a", 1, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_member_add(&pool, NULL, 0, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_member_remove(NULL, "a", 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_member_remove(&pool, NULL, 0));
    TEST_ASSERT_EQ(0, pool.count);

    memset(name, 'a', sizeof(name));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_member_add(&pool, name, SIGRELAY_UPSTREAM_NAME_MAX, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_NAME_MAX, strlen(pool.members[0].name));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME,
                   sigrelay_upstream_member_add(&pool, name, SIGRELAY_UPSTREAM_NAME_MAX + 1, 1));

    while (pool.count < SIGRELAY_UPSTREAM_CAPACITY) {
        char hop[32];
        int n = snprintf(hop, sizeof(hop), "10.0.0.%zu:5060", pool.count);

        TEST_ASSERT(n > 0 && (size_t)n < sizeof(hop));
        TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(hop, 1));
    }
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_POOL_FULL, add("10.0.1.1:5060", 1));
}

void test_upstream_marks_member_down_after_failures(void)
{
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF1, 1));

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 1000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 2000));
    TEST_ASSERT_EQ(2, pool.members[0].consecutive_failures);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_HEALTHY, pool.members[0].state);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 3000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_UNHEALTHY, pool.members[0].state);
    TEST_ASSERT_EQ(3000, pool.members[0].last_probe_ms);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 4000));
    TEST_ASSERT_EQ(4, pool.members[0].consecutive_failures);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_UNHEALTHY, pool.members[0].state);

    /* One success brings the member back and clears the failure count. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 1, 5000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_HEALTHY, pool.members[0].state);
    TEST_ASSERT_EQ(0, pool.members[0].consecutive_failures);
    TEST_ASSERT_EQ(5000, pool.members[0].last_probe_ms);

    /* Failures must be consecutive. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 6000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 7000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 1, 8000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 9000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 10000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_HEALTHY, pool.members[0].state);
    TEST_ASSERT_EQ(2, pool.members[0].consecutive_failures);

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_NOT_FOUND, probe(SCSCF2, 1, 11000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_mark_probe(&pool, NULL, 0, 1, 11000));
}

void test_upstream_reports_probe_due(void)
{
    int due = -1;

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 2));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF1, 1));

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe_due(SCSCF1, 1000, &due));
    TEST_ASSERT_EQ(1, due);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 1, 5000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe_due(SCSCF1, 5999, &due));
    TEST_ASSERT_EQ(0, due);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe_due(SCSCF1, 6000, &due));
    TEST_ASSERT_EQ(1, due);

    /* A clock that went backwards must not stall probing. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe_due(SCSCF1, 4000, &due));
    TEST_ASSERT_EQ(1, due);

    /* Members that are down are probed less often. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 6000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 7000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_UNHEALTHY, pool.members[0].state);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe_due(SCSCF1, 8000, &due));
    TEST_ASSERT_EQ(0, due);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   probe_due(SCSCF1, 7000 + 1000 * SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR - 1, &due));
    TEST_ASSERT_EQ(0, due);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   probe_due(SCSCF1, 7000 + 1000 * SIGRELAY_UPSTREAM_DOWN_PROBE_FACTOR, &due));
    TEST_ASSERT_EQ(1, due);

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_NOT_FOUND, probe_due(SCSCF2, 8000, &due));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_probe_due(&pool, SCSCF1, strlen(SCSCF1), 8000, NULL));
}

void test_upstream_selects_all_healthy_members(void)
{
    size_t seen[3] = {0, 0, 0};

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF1, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF2, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF3, 1));

    /* Two full rounds: every healthy member must come up. */
    for (int i = 0; i < 6; i++) {
        size_t idx = select_index();

        TEST_ASSERT(idx < 3);
        seen[idx]++;
    }
    TEST_ASSERT(seen[0] > 0);
    TEST_ASSERT(seen[1] > 0);
    TEST_ASSERT(seen[2] > 0);
}

void test_upstream_select_weights_healthy_members(void)
{
    size_t seen[3] = {0, 0, 0};

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF1, 3));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF2, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF3, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF3, 0, 1000));

    /* With scscf3 down, its share goes to the others in proportion to their weights. */
    for (int i = 0; i < 8; i++) {
        size_t idx = select_index();

        TEST_ASSERT(idx < 3);
        seen[idx]++;
    }
    TEST_ASSERT_EQ(6, seen[0]);
    TEST_ASSERT_EQ(2, seen[1]);
    TEST_ASSERT_EQ(0, seen[2]);
}

void test_upstream_select_reports_none_healthy(void)
{
    sigrelay_str hop;

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_pool_init(&pool, 1000, 1));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY, sigrelay_upstream_select(&pool, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_select(NULL, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG, sigrelay_upstream_select(&pool, NULL));

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF1, 2));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, add(SCSCF2, 2));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 0, 1000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF2, 0, 1000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_NONE_HEALTHY, sigrelay_upstream_select(&pool, &hop));

    /* The first member to recover takes all traffic. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, probe(SCSCF1, 1, 2000));
    for (int i = 0; i < 4; i++) {
        TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_select(&pool, &hop));
        TEST_ASSERT_STR(SCSCF1, hop);
    }
}

void test_upstream_cache_stores_and_expires(void)
{
    sigrelay_str hop;

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_cache_init(&cache, 500));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("ims.example.net", 1000, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, store("ims.example.net", SCSCF1, 1000));

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("ims.example.net", 1000, &hop));
    TEST_ASSERT_STR(SCSCF1, hop);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("IMS.Example.NET", 1499, &hop));
    TEST_ASSERT_STR(SCSCF1, hop);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("ims.example.net", 1500, &hop));

    /* Exact match only: no parent-domain fallback. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("pcscf.ims.example.net", 1000, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("example.net", 1000, &hop));

    /* Storing again replaces the next hop and restarts the TTL. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, store("IMS.example.net", SCSCF2, 1400));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("ims.example.net", 1899, &hop));
    TEST_ASSERT_STR(SCSCF2, hop);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("ims.example.net", 1900, &hop));

    /* Lookups take a length and must not depend on NUL termination. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_cache_lookup(&cache, "ims.example.netXYZ",
                                                  strlen("ims.example.net"), 1500, &hop));
    TEST_ASSERT_STR(SCSCF2, hop);

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, invalidate("Ims.Example.Net"));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("ims.example.net", 1500, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_NOT_FOUND, invalidate("ims.example.net"));
}

void test_upstream_cache_evicts_soonest_expiry(void)
{
    sigrelay_str hop;

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_cache_init(&cache, 1000));
    for (size_t i = 0; i < SIGRELAY_UPSTREAM_CACHE_CAPACITY; i++) {
        char domain[32];
        int n = snprintf(domain, sizeof(domain), "d%zu.example.net", i);

        TEST_ASSERT(n > 0 && (size_t)n < sizeof(domain));
        TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, store(domain, SCSCF1, 1000 + i));
    }

    /* Full: d0 is closest to expiry and gives way. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, store("new.example.net", SCSCF2, 1100));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("d0.example.net", 1100, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("d1.example.net", 1100, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("new.example.net", 1100, &hop));
    TEST_ASSERT_STR(SCSCF2, hop);

    /* An expired entry is reused before any live entry is evicted. */
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, store("other.example.net", SCSCF3, 2001));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_CACHE_MISS, lookup("d1.example.net", 2001, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("d2.example.net", 2001, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("new.example.net", 2001, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("other.example.net", 2001, &hop));
    TEST_ASSERT_STR(SCSCF3, hop);
}

void test_upstream_cache_rejects_invalid_input(void)
{
    char domain[SIGRELAY_UPSTREAM_DOMAIN_MAX + 1];
    sigrelay_str hop;

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_cache_init(&cache, 1000));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, store("", SCSCF1, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, store("ims example.net", SCSCF1, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, store("ims_example.net", SCSCF1, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, store("ims.example.net", "", 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, store("ims.example.net", "scscf1 x", 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, lookup("", 0, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME, invalidate("ims example.net"));

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_store(NULL, "a", 1, "b", 1, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_store(&cache, NULL, 0, "b", 1, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_store(&cache, "a", 1, NULL, 0, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_lookup(NULL, "a", 1, 0, &hop));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_lookup(&cache, "a", 1, 0, NULL));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_ARG,
                   sigrelay_upstream_cache_invalidate(NULL, "a", 1));

    memset(domain, 'a', sizeof(domain));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_cache_store(&cache, domain, SIGRELAY_UPSTREAM_DOMAIN_MAX,
                                                 "hop", 3, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME,
                   sigrelay_upstream_cache_store(&cache, domain, SIGRELAY_UPSTREAM_DOMAIN_MAX + 1,
                                                 "hop", 3, 0));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK,
                   sigrelay_upstream_cache_lookup(&cache, domain, SIGRELAY_UPSTREAM_DOMAIN_MAX, 0,
                                                  &hop));
    TEST_ASSERT_STR("hop", hop);
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_ERR_INVALID_NAME,
                   sigrelay_upstream_cache_lookup(&cache, domain, SIGRELAY_UPSTREAM_DOMAIN_MAX + 1,
                                                  0, &hop));
}

#define SHORT_TTL_MS 20u

void test_upstream_cache_hit_within_ttl(void)
{
    uint64_t now_ms = 1000;
    sigrelay_str hop;

    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, sigrelay_upstream_cache_init(&cache, SHORT_TTL_MS));
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, store("ims.example.net", SCSCF1, now_ms));

    /* Look the entry up just before it expires. */
    now_ms += SHORT_TTL_MS - 1;
    TEST_ASSERT_EQ(SIGRELAY_UPSTREAM_OK, lookup("ims.example.net", now_ms, &hop));
    TEST_ASSERT_STR(SCSCF1, hop);
}
