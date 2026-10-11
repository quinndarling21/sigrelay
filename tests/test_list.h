#ifndef SIGRELAY_TEST_LIST_H
#define SIGRELAY_TEST_LIST_H

/*
 * Every test case. tests/CMakeLists.txt scans this file and registers each
 * entry as its own ctest test of the same name; the runner calls
 * test_<name>(). Do not write the entry pattern anywhere else in this file.
 */
#define SIGRELAY_TEST_CASES(X)                     \
    X(sip_parses_invite)                           \
    X(sip_parses_response)                         \
    X(sip_parses_compact_headers)                  \
    X(sip_rejects_malformed_start_line)            \
    X(sip_rejects_malformed_headers)               \
    X(sip_rejects_truncated_input)                 \
    X(sip_rejects_malformed_content_encoding)      \
    X(sip_parses_content_encoding)                 \
    X(sip_parses_compact_content_encoding)         \
    X(sip_body_decodes_gzip)                       \
    X(sip_body_decodes_deflate)                    \
    X(sip_body_decodes_raw_deflate)                \
    X(sip_body_copies_identity)                    \
    X(sip_body_rejects_unsupported_encoding)       \
    X(sip_body_rejects_corrupt_input)              \
    X(sip_body_rejects_truncated_input)            \
    X(sip_body_rejects_oversized_output)           \
    X(sip_body_rejects_invalid_arguments)          \
    X(diameter_parses_header)                      \
    X(diameter_iterates_avps)                      \
    X(diameter_rejects_malformed_header)           \
    X(diameter_rejects_malformed_avps)             \
    X(diameter_rejects_bad_padding)                \
    X(diameter_rejects_truncated_input)            \
    X(relay_routes_exact_match)                    \
    X(relay_routes_parent_domain)                  \
    X(relay_rejects_invalid_routes)                \
    X(upstream_pool_rejects_invalid_config)        \
    X(upstream_adds_and_removes_members)           \
    X(upstream_rejects_invalid_members)            \
    X(upstream_marks_member_down_after_failures)   \
    X(upstream_reports_probe_due)                  \
    X(upstream_selects_all_healthy_members)        \
    X(upstream_select_weights_healthy_members)     \
    X(upstream_select_reports_none_healthy)        \
    X(upstream_cache_stores_and_expires)           \
    X(upstream_cache_evicts_soonest_expiry)        \
    X(upstream_cache_rejects_invalid_input)        \
    X(upstream_cache_hit_within_ttl)

#endif /* SIGRELAY_TEST_LIST_H */
