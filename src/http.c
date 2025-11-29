#include "http.h"
#include "logging.h"
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

/*
 * Provider isolation for curl HTTP operations.
 * 
 * Problem: When the pkcs11 provider is loaded globally in OpenSSL, curl's TLS
 * handshake tries to use it for crypto operations (EC key gen, RSA encrypt),
 * which fails because our shim doesn't support these operations.
 * 
 * Solution: Temporarily override the default properties to force use of the
 * default provider during curl operations, then restore them after.
 */

static void save_and_override_properties(void) {
    /* Override the global default properties to use only the default provider.
     * This affects the NULL (default) library context.
     * Note: There's no API to get the current default properties in OpenSSL 3.0,
     * so we assume they weren't set. For our use case (openssl cms -provider pkcs11),
     * the properties are set per-provider via command line, not globally. */
    if (!EVP_set_default_properties(NULL, "provider=default")) {
        shim_log(SHIM_LOG_ERROR, "Failed to set default properties to provider=default");
    }
}

static void restore_properties(void) {
    /* Restore to no property query (accept any provider) */
    EVP_set_default_properties(NULL, NULL);
}

CK_RV shim_http_global_init(void) {
    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

CK_RV shim_http_global_cleanup(void) {
    curl_global_cleanup();
    return CKR_OK;
}

static int init_string(struct string *s) {
    s->len = 0;
    s->ptr = OPENSSL_malloc(s->len + 1);
    if (s->ptr == NULL) {
        shim_log(SHIM_LOG_ERROR, "OPENSSL_malloc() failed");
        return 1;
    }
    s->ptr[0] = '\0';
    return 0;
}

static size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t new_len = s->len + size * nmemb;
    char *new_ptr = OPENSSL_realloc(s->ptr, new_len + 1);
    if (new_ptr == NULL) {
        shim_log(SHIM_LOG_ERROR, "OPENSSL_realloc() failed");
        return 0;
    }
    s->ptr = new_ptr;
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size * nmemb;
}

static struct curl_slist *get_auth_headers(struct curl_slist *headers) {
    const char *auth = getenv("PKCS11_SHIM_AUTH");
    if (auth) {
        return curl_slist_append(headers, auth);
    }
    return headers;
}

char *get_shim_url(const char *endpoint) {
    const char *base_url = getenv("PKCS11_SHIM_URL");
    const char *default_url = "http://localhost:27180";
    if (!base_url) base_url = default_url;

    size_t len = strlen(base_url) + strlen(endpoint) + 1;
    char *url = OPENSSL_malloc(len);
    if (!url) return NULL;

    snprintf(url, len, "%s%s", base_url, endpoint);
    return url;
}

static long get_timeout(void) {
    const char *timeout_env = getenv("PKCS11_SHIM_TIMEOUT");
    if (timeout_env) {
        return strtol(timeout_env, NULL, 10);
    }
    return 10; /* Default 10 seconds */
}

static void configure_ssl(CURL *curl) {
    const char *verify = getenv("PKCS11_SHIM_SSL_VERIFY");
    const char *capath = getenv("PKCS11_SHIM_CAPATH");
    const char *verbose = getenv("PKCS11_SHIM_CURL_VERBOSE");

    /* Enable verbose output for debugging */
    if (verbose && (strcmp(verbose, "1") == 0 || strcasecmp(verbose, "true") == 0)) {
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    }

    if (verify && (strcmp(verify, "0") == 0 || strcasecmp(verify, "false") == 0)) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    } else {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    }

    if (capath) {
        curl_easy_setopt(curl, CURLOPT_CAINFO, capath);
    }
}

CK_RV shim_http_get(const char *url, struct string *s) {
    CURL *curl = curl_easy_init();
    if (!curl) return CKR_GENERAL_ERROR;

    struct curl_slist *headers = NULL;
    headers = get_auth_headers(headers);

    if (init_string(s) != 0) {
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return CKR_HOST_MEMORY;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, get_timeout());
    configure_ssl(curl);
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    save_and_override_properties();
    CURLcode res = curl_easy_perform(curl);
    restore_properties();

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        shim_log(SHIM_LOG_ERROR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
        OPENSSL_free(s->ptr);
        return CKR_FUNCTION_FAILED;
    }

    shim_log(SHIM_LOG_DEBUG, "GET %s returned %ld", url, response_code);
    if (response_code != 200) {
        shim_log(SHIM_LOG_ERROR, "Response body: %s", s->ptr);
        OPENSSL_free(s->ptr);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV shim_http_post(const char *url, const char *data, struct string *s) {
    CURL *curl = curl_easy_init();
    if (!curl) return CKR_GENERAL_ERROR;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = get_auth_headers(headers);

    if (init_string(s) != 0) {
        if (headers) curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return CKR_HOST_MEMORY;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, get_timeout());
    configure_ssl(curl);

    save_and_override_properties();
    CURLcode res = curl_easy_perform(curl);
    restore_properties();

    long response_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

    if (headers) curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        shim_log(SHIM_LOG_ERROR, "curl_easy_perform() failed: %s", curl_easy_strerror(res));
        OPENSSL_free(s->ptr);
        return CKR_FUNCTION_FAILED;
    }

    shim_log(SHIM_LOG_DEBUG, "POST %s returned %ld", url, response_code);
    /* Accept any 2xx status code as success */
    if (response_code < 200 || response_code >= 300) {
        shim_log(SHIM_LOG_ERROR, "Response body: %s", s->ptr);
        OPENSSL_free(s->ptr);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}
