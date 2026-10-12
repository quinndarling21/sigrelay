#include <stdio.h>
#include <string.h>

#include "sigrelay/relay.h"
#include "test_harness.h"

static sigrelay_route_table table;

static sigrelay_relay_status add(const char *destination, const char *next_hop)
{
    return sigrelay_route_add(&table, destination, strlen(destination), next_hop,
                              strlen(next_hop));
}

static sigrelay_relay_status lookup(const char *destination, sigrelay_str *next_hop)
{
    return sigrelay_route_lookup(&table, destination, strlen(destination), next_hop);
}

void test_relay_routes_exact_match(void)
{
    sigrelay_str hop;

    sigrelay_route_table_init(&table);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add("ims.example.net", "scscf1.ims.example.net:5060"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add("Example.ORG", "aaa://dra1.example.org:3868"));
    TEST_ASSERT_EQ(2, table.count);

    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("ims.example.net", &hop));
    TEST_ASSERT_STR("scscf1.ims.example.net:5060", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("IMS.Example.Net", &hop));
    TEST_ASSERT_STR("scscf1.ims.example.net:5060", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("example.org", &hop));
    TEST_ASSERT_STR("aaa://dra1.example.org:3868", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_NOT_FOUND, lookup("example.com", &hop));

    /* Lookups take a length and must not depend on NUL termination. */
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK,
                   sigrelay_route_lookup(&table, "example.orgXYZ", strlen("example.org"), &hop));
    TEST_ASSERT_STR("aaa://dra1.example.org:3868", hop);
}

void test_relay_routes_parent_domain(void)
{
    sigrelay_str hop;

    sigrelay_route_table_init(&table);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add("example.net", "dra1.example.net:3868"));

    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("pcscf.ims.example.net", &hop));
    TEST_ASSERT_STR("dra1.example.net:3868", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_NOT_FOUND, lookup("badexample.net", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_NOT_FOUND, lookup("net", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_NOT_FOUND, lookup("example.net.", &hop));

    /* The longest matching parent wins regardless of insertion order. */
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add("ims.example.net", "scscf1.ims.example.net:5060"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("pcscf.ims.example.net", &hop));
    TEST_ASSERT_STR("scscf1.ims.example.net:5060", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("hss.example.net", &hop));
    TEST_ASSERT_STR("dra1.example.net:3868", hop);
}

void test_relay_rejects_invalid_routes(void)
{
    char name[SIGRELAY_ROUTE_NAME_MAX + 2];
    sigrelay_str hop;

    sigrelay_route_table_init(&table);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("", "dra1.example.net"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("bad realm.net", "dra1.example.net"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("bad_realm.net", "dra1.example.net"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NEXT_HOP, add("example.net", ""));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NEXT_HOP, add("example.net", "dra1 example.net"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_ARG,
                   sigrelay_route_add(&table, NULL, 0, "dra1.example.net", 16));
    TEST_ASSERT_EQ(0, table.count);

    /* 63 '.' 63 '.' 63 '.' 61 == 253, the longest presentation-form DNS name.
     * A single run of 253 letters is one oversized label, so it is not the
     * length-ceiling fixture. */
    _Static_assert(63 + 1 + 63 + 1 + 63 + 1 + 61 == SIGRELAY_ROUTE_NAME_MAX,
                   "SIGRELAY_ROUTE_NAME_MAX must match four DNS labels");
    memset(name, 'a', sizeof(name));
    name[63] = '.';
    name[127] = '.';
    name[191] = '.';
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK,
                   sigrelay_route_add(&table, name, SIGRELAY_ROUTE_NAME_MAX, "hop", 3));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME,
                   sigrelay_route_add(&table, name, SIGRELAY_ROUTE_NAME_MAX + 1, "hop", 3));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME,
                   sigrelay_route_lookup(&table, name, SIGRELAY_ROUTE_NAME_MAX + 1, &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("", &hop));

    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add("example.net", "dra1.example.net"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_DUPLICATE, add("EXAMPLE.net", "dra2.example.net"));

    while (table.count < SIGRELAY_ROUTE_CAPACITY) {
        char realm[32];
        int n = snprintf(realm, sizeof(realm), "r%zu.example.net", table.count);

        TEST_ASSERT(n > 0 && (size_t)n < sizeof(realm));
        TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add(realm, "dra1.example.net"));
    }
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_TABLE_FULL, add("full.example.org", "dra1.example.net"));
}

void test_relay_rejects_malformed_names(void)
{
    char label[64 + 12];
    char solid[SIGRELAY_ROUTE_NAME_MAX];
    const char suffix[] = ".example.net";
    const size_t suffix_len = sizeof(suffix) - 1;
    sigrelay_str hop;

    sigrelay_route_table_init(&table);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, add("example.net", "dra1.example.net:3868"));

    /* Empty labels, a leading dot, and a label that starts or ends with '-'. */
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("ims..example.net", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("ims..example.net", "hop"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup(".example.net", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add(".example.net", "hop"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("-ims.example.net", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("-ims.example.net", "hop"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("ims-.example.net", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("ims-.example.net", "hop"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("..", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("..", "hop"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup(".", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add(".", "hop"));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("-.-", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("-.-", "hop"));
    /* A second trailing dot is an empty label, not a second root marker. */
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, lookup("example.net..", &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME, add("example.net..", "hop"));

    /* A label longer than 63 octets is not a DNS label (RFC 1035 section 2.3.1). */
    memset(label, 'a', 64);
    memcpy(label + 64, suffix, suffix_len);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME,
                   sigrelay_route_lookup(&table, label, 64 + suffix_len, &hop));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME,
                   sigrelay_route_add(&table, label, 64 + suffix_len, "hop", 3));

    /* 253 letters is within the name limit and over the 63-octet label limit. */
    memset(solid, 'a', sizeof(solid));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME,
                   sigrelay_route_add(&table, solid, sizeof(solid), "hop", 3));
    TEST_ASSERT_EQ(SIGRELAY_RELAY_ERR_INVALID_NAME,
                   sigrelay_route_lookup(&table, solid, sizeof(solid), &hop));

    /* 63 is still a legal label, and a leading digit is legal (RFC 1123 section 2.1). */
    memset(label, 'b', 63);
    memcpy(label + 63, suffix, suffix_len);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, sigrelay_route_lookup(&table, label, 63 + suffix_len, &hop));
    TEST_ASSERT_STR("dra1.example.net:3868", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("1ims.example.net", &hop));
    TEST_ASSERT_STR("dra1.example.net:3868", hop);
    TEST_ASSERT_EQ(SIGRELAY_RELAY_OK, lookup("ims-core.example.net", &hop));
    TEST_ASSERT_STR("dra1.example.net:3868", hop);

    TEST_ASSERT_EQ(1, table.count);
}
