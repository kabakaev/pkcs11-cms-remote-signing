#ifndef SHIM_HTTP_H
#define SHIM_HTTP_H

#include <stddef.h>
#include "shim.h" /* For CK_RV */

struct string {
    char *ptr;
    size_t len;
};

/* Initialize/Cleanup global HTTP resources (curl global) */
CK_RV shim_http_global_init(void);
CK_RV shim_http_global_cleanup(void);

/* Helper to construct full URL */
char *get_shim_url(const char *endpoint);

/* Perform HTTP GET */
CK_RV shim_http_get(const char *url, struct string *s);

/* Perform HTTP POST */
CK_RV shim_http_post(const char *url, const char *data, struct string *s);

#endif /* SHIM_HTTP_H */
