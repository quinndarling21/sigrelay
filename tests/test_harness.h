#ifndef SIGRELAY_TEST_HARNESS_H
#define SIGRELAY_TEST_HARNESS_H

#include <stdio.h>
#include <string.h>

#include "sigrelay/sigrelay.h"
#include "test_list.h"

extern int sigrelay_test_failed;

#define DECLARE_TEST(name) void test_##name(void);
SIGRELAY_TEST_CASES(DECLARE_TEST)
#undef DECLARE_TEST

/* Assertions end the current test case on failure. */
#define TEST_ASSERT(cond)                                                           \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__,   \
                    #cond);                                                         \
            sigrelay_test_failed = 1;                                               \
            return;                                                                 \
        }                                                                           \
    } while (0)

#define TEST_ASSERT_EQ(expected, actual)                                            \
    do {                                                                            \
        long long expected_ = (long long)(expected);                                \
        long long actual_ = (long long)(actual);                                    \
        if (expected_ != actual_) {                                                 \
            fprintf(stderr, "%s:%d: %s: expected %lld, got %lld\n", __FILE__,       \
                    __LINE__, #actual, expected_, actual_);                         \
            sigrelay_test_failed = 1;                                               \
            return;                                                                 \
        }                                                                           \
    } while (0)

#define TEST_ASSERT_STR(expected, actual)                                           \
    do {                                                                            \
        const char *expected_ = (expected);                                         \
        sigrelay_str actual_ = (actual);                                            \
        if (actual_.ptr == NULL || actual_.len != strlen(expected_) ||              \
            memcmp(actual_.ptr, expected_, actual_.len) != 0) {                     \
            fprintf(stderr, "%s:%d: %s: expected \"%s\", got \"%.*s\"\n", __FILE__, \
                    __LINE__, #actual, expected_, (int)actual_.len,                 \
                    actual_.ptr ? actual_.ptr : "");                                \
            sigrelay_test_failed = 1;                                               \
            return;                                                                 \
        }                                                                           \
    } while (0)

#endif /* SIGRELAY_TEST_HARNESS_H */
