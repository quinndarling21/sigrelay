#include <stdio.h>
#include <string.h>

#include "test_harness.h"

int sigrelay_test_failed;

typedef struct {
    const char *name;
    void (*fn)(void);
} test_case;

static const test_case cases[] = {
#define REGISTER_TEST(name) {#name, test_##name},
    SIGRELAY_TEST_CASES(REGISTER_TEST)
#undef REGISTER_TEST
};

#define CASE_COUNT (sizeof(cases) / sizeof(cases[0]))

static int run_case(const test_case *tc)
{
    sigrelay_test_failed = 0;
    tc->fn();
    printf("%s %s\n", sigrelay_test_failed ? "FAIL" : "PASS", tc->name);
    return sigrelay_test_failed;
}

static const test_case *find_case(const char *name)
{
    for (size_t i = 0; i < CASE_COUNT; i++) {
        if (strcmp(cases[i].name, name) == 0) {
            return &cases[i];
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    int failed = 0;

    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        for (size_t i = 0; i < CASE_COUNT; i++) {
            printf("%s\n", cases[i].name);
        }
        return 0;
    }
    if (argc == 1) {
        for (size_t i = 0; i < CASE_COUNT; i++) {
            failed += run_case(&cases[i]);
        }
        printf("%d of %zu test cases failed\n", failed, CASE_COUNT);
        return failed ? 1 : 0;
    }
    for (int i = 1; i < argc; i++) {
        const test_case *tc = find_case(argv[i]);

        if (tc == NULL) {
            fprintf(stderr, "unknown test case: %s\n", argv[i]);
            return 2;
        }
        failed += run_case(tc);
    }
    return failed ? 1 : 0;
}
