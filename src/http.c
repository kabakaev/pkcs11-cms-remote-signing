#include "http.h"
#include "logging.h"
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <string.h>
#include <stdlib.h>

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
    const char *default_url = "http://localhost:42180";
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
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);

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

    CURLcode res = curl_easy_perform(curl);

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
    if (response_code != 200) {
        shim_log(SHIM_LOG_ERROR, "Response body: %s", s->ptr);
        OPENSSL_free(s->ptr);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}
