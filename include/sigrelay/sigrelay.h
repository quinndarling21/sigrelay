#ifndef SIGRELAY_SIGRELAY_H
#define SIGRELAY_SIGRELAY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A view into a caller-owned buffer. Not NUL-terminated. */
typedef struct {
    const char *ptr;
    size_t len;
} sigrelay_str;

const char *sigrelay_version(void);

#ifdef __cplusplus
}
#endif

#endif /* SIGRELAY_SIGRELAY_H */
