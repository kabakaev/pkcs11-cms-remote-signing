#include "json_utils.h"
#include "jsmn.h"
#include "logging.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <stdlib.h>
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

    /* Get certificate field name from environment, default to "certificate" */
    const char *cert_field = getenv("PKCS11_SHIM_API_CERT_JSON_FIELD");
    if (!cert_field) cert_field = "certificate";

    for (int i = 1; i < r; i++) {
        if (jsoneq(json, &t[i], cert_field) == 0) {
            cert_start = (char *)json + t[i + 1].start;
            cert_len = t[i + 1].end - t[i + 1].start;
            break;
        }
    }

    if (!cert_start) {
        shim_log(SHIM_LOG_ERROR, "No '%s' field found in response", cert_field);
        OPENSSL_free(t);
        return CKR_FUNCTION_FAILED;
    }

    /* Check if it's PEM format (starts with -----BEGIN) or base64 DER */
    if (cert_len > 10 && strncmp(cert_start, "-----BEGIN", 10) == 0) {
        /* PEM format - need to decode the PEM to DER */
        /* First, make a null-terminated copy and unescape JSON string escapes */
        char *pem_copy = OPENSSL_malloc(cert_len + 1);
        if (!pem_copy) {
            OPENSSL_free(t);
            return CKR_HOST_MEMORY;
        }
        
        /* Unescape JSON string: convert \n to actual newline, \r to CR, etc. */
        size_t j = 0;
        for (size_t i = 0; i < cert_len; i++) {
            if (cert_start[i] == '\\' && i + 1 < cert_len) {
                switch (cert_start[i + 1]) {
                    case 'n': pem_copy[j++] = '\n'; i++; break;
                    case 'r': pem_copy[j++] = '\r'; i++; break;
                    case 't': pem_copy[j++] = '\t'; i++; break;
                    case '\\': pem_copy[j++] = '\\'; i++; break;
                    case '"': pem_copy[j++] = '"'; i++; break;
                    default: pem_copy[j++] = cert_start[i]; break;
                }
            } else {
                pem_copy[j++] = cert_start[i];
            }
        }
        pem_copy[j] = '\0';
        
        BIO *bio = BIO_new_mem_buf(pem_copy, (int)j);
        if (!bio) {
            OPENSSL_free(pem_copy);
            OPENSSL_free(t);
            return CKR_HOST_MEMORY;
        }
        
        X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        BIO_free(bio);
        OPENSSL_free(pem_copy);
        
        if (!x509) {
            shim_log(SHIM_LOG_ERROR, "Failed to parse PEM certificate");
            OPENSSL_free(t);
            return CKR_FUNCTION_FAILED;
        }
        
        /* Convert to DER */
        int der_len = i2d_X509(x509, NULL);
        if (der_len <= 0) {
            X509_free(x509);
            OPENSSL_free(t);
            return CKR_FUNCTION_FAILED;
        }
        
        *cert_der = OPENSSL_malloc(der_len);
        if (!*cert_der) {
            X509_free(x509);
            OPENSSL_free(t);
            return CKR_HOST_MEMORY;
        }
        
        unsigned char *der_ptr = *cert_der;
        *cert_der_len = i2d_X509(x509, &der_ptr);
        X509_free(x509);
        OPENSSL_free(t);
        return CKR_OK;
    }

    /* Base64 DER format */
    *cert_der = base64_decode(cert_start, cert_len, cert_der_len);
    OPENSSL_free(t);

    if (!*cert_der) return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

CK_RV parse_signature_response(const char *json, size_t len, 
                               unsigned char **sig, size_t *sig_len) {
    /* Check if we should treat response as raw base64 */
    const char *return_type = getenv("PKCS11_SHIM_API_SIGN_RETURN_TYPE");
    if (return_type && strcmp(return_type, "base64") == 0) {
        *sig = base64_decode(json, len, sig_len);
        if (!*sig) return CKR_FUNCTION_FAILED;
        return CKR_OK;
    }
    
    /* Default: parse as JSON with "signature" field */
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
