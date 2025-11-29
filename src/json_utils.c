#include "json_utils.h"
#include "jsmn.h"
#include "logging.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <string.h>

/* Base64 decoding helper (duplicated from shim.c, maybe should be shared in utils.c) */
/* For now, let's just duplicate or move it. Moving it to utils.c would be better but let's keep it simple. */
/* Actually, we can use OpenSSL's EVP_DecodeBlock directly or just copy the helper. */
/* Let's copy the helper for now to avoid circular deps or complex refactoring. */

static unsigned char *base64_decode(const char *data, size_t input_length,
                                    size_t *output_length)
{
    EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
    if (!ctx) return NULL;

    size_t max_out_len = (input_length / 4) * 3 + 10;
    unsigned char *decoded_data = OPENSSL_malloc(max_out_len);
    if (decoded_data == NULL) {
        EVP_ENCODE_CTX_free(ctx);
        return NULL;
    }

    int outl = 0;
    int totall = 0;
    EVP_DecodeInit(ctx);
    if (EVP_DecodeUpdate(ctx, decoded_data, &outl, (const unsigned char *)data, input_length) < 0) {
        OPENSSL_free(decoded_data);
        EVP_ENCODE_CTX_free(ctx);
        return NULL;
    }
    totall += outl;

    int final_outl = 0;
    if (EVP_DecodeFinal(ctx, decoded_data + totall, &final_outl) < 0) {
        OPENSSL_free(decoded_data);
        EVP_ENCODE_CTX_free(ctx);
        return NULL;
    }
    totall += final_outl;

    *output_length = totall;
    EVP_ENCODE_CTX_free(ctx);
    return decoded_data;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
        strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return 0;
    }
    return -1;
}

CK_RV parse_certificate_response(const char *json, size_t len, 
                                 unsigned char **cert_der, size_t *cert_der_len) {
    jsmn_parser p;
    jsmn_init(&p);

    int r = jsmn_parse(&p, json, len, NULL, 0);
    if (r < 0) return CKR_FUNCTION_FAILED;

    jsmntok_t *t = OPENSSL_malloc(sizeof(jsmntok_t) * r);
    if (!t) return CKR_HOST_MEMORY;

    jsmn_init(&p);
    r = jsmn_parse(&p, json, len, t, r);
    if (r < 0) {
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    if (r < 1 || t[0].type != JSMN_OBJECT) {
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    char *cert_start = NULL;
    size_t cert_len = 0;

    for (int i = 1; i < r; i++) {
        if (jsoneq(json, &t[i], "certificate") == 0) {
            cert_start = (char *)json + t[i + 1].start;
            cert_len = t[i + 1].end - t[i + 1].start;
            break;
        }
    }

    if (!cert_start) {
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    *cert_der = base64_decode(cert_start, cert_len, cert_der_len);
    OPENSSL_free(t);

    if (!*cert_der) return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

CK_RV parse_signature_response(const char *json, size_t len, 
                               unsigned char **sig, size_t *sig_len) {
    jsmn_parser p;
    jsmn_init(&p);

    int r = jsmn_parse(&p, json, len, NULL, 0);
    if (r < 0) return CKR_FUNCTION_FAILED;

    jsmntok_t *t = OPENSSL_malloc(sizeof(jsmntok_t) * r);
    if (!t) return CKR_HOST_MEMORY;

    jsmn_init(&p);
    r = jsmn_parse(&p, json, len, t, r);
    if (r < 0) {
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    if (r < 1 || t[0].type != JSMN_OBJECT) {
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    char *sig_start = NULL;
    size_t sig_len_b64 = 0;

    for (int i = 1; i < r; i++) {
        if (jsoneq(json, &t[i], "signature") == 0) {
            sig_start = (char *)json + t[i + 1].start;
            sig_len_b64 = t[i + 1].end - t[i + 1].start;
            break;
        }
    }

    if (!sig_start) {
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    *sig = base64_decode(sig_start, sig_len_b64, sig_len);
    OPENSSL_free(t);

    if (!*sig) return CKR_FUNCTION_FAILED;
    return CKR_OK;
}
