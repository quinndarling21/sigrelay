#ifndef SIGRELAY_TEST_LIST_H
#define SIGRELAY_TEST_LIST_H

/*
 * Every test case. tests/CMakeLists.txt scans this file and registers each
 * entry as its own ctest test of the same name; the runner calls
 * test_<name>(). Do not write the entry pattern anywhere else in this file.
 */
#define SIGRELAY_TEST_CASES(X)              \
    X(sip_parses_invite)                    \
    X(sip_parses_response)                  \
    X(sip_parses_compact_headers)           \
    X(sip_rejects_malformed_start_line)     \
    X(sip_rejects_malformed_headers)        \
    X(sip_rejects_truncated_input)          \
    X(diameter_parses_header)               \
    X(diameter_iterates_avps)               \
    X(diameter_rejects_malformed_header)    \
    X(diameter_rejects_malformed_avps)      \
    X(diameter_rejects_bad_padding)         \
    X(diameter_rejects_truncated_input)     \
    X(relay_routes_exact_match)             \
    X(relay_routes_parent_domain)           \
    X(relay_rejects_invalid_routes)

#endif /* SIGRELAY_TEST_LIST_H */
