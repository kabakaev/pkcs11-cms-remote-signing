#ifndef SHIM_LOGGING_H
#define SHIM_LOGGING_H

#include <stdio.h>
#include <stdlib.h>

#define SHIM_LOG_ERROR 0
#define SHIM_LOG_INFO  1
#define SHIM_LOG_DEBUG 2

static inline void shim_log(int level, const char *fmt, ...) {
    const char *debug_env = getenv("PKCS11_SHIM_DEBUG");
    if (!debug_env) return;

    /* If PKCS11_SHIM_DEBUG is set, we log everything for now, 
       or we could parse the level from the env var. 
       For simplicity, let's assume any value enables logging. */
    
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "shim: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

#endif /* SHIM_LOGGING_H */
