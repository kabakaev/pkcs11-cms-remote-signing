/* SPDX-License-Identifier: Apache-2.0 */

#include "shim.h"
#include "interface.h"
#include "logging.h"
#include "http.h"
#include "json_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <pthread.h>

/* Dummy object handles */
#define SHIM_SLOT_ID 1
#define SHIM_SESSION_HANDLE 1
#define SHIM_OBJECT_HANDLE 1

/* Key type constants */
#define KEY_TYPE_UNKNOWN 0
#define KEY_TYPE_RSA 1
#define KEY_TYPE_EC 2

static unsigned char *cached_spki = NULL;
static size_t cached_spki_len = 0;
static unsigned char *cached_ec_params = NULL;
static size_t cached_ec_params_len = 0;
static unsigned char *cached_ec_point = NULL;
static size_t cached_ec_point_len = 0;
static unsigned char *cached_rsa_modulus = NULL;
static size_t cached_rsa_modulus_len = 0;
static unsigned char *cached_rsa_exponent = NULL;
static size_t cached_rsa_exponent_len = 0;
static int cached_key_type = KEY_TYPE_UNKNOWN;
static size_t cached_key_bits = 0;

static pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

static CK_RV shim_Initialize(CK_VOID_PTR pInitArgs)
{
    return shim_http_global_init();
}

static CK_RV shim_Finalize(CK_VOID_PTR pReserved)
{
    pthread_mutex_lock(&cache_mutex);
    if (cached_spki) OPENSSL_free(cached_spki);
    if (cached_ec_params) OPENSSL_free(cached_ec_params);
    if (cached_ec_point) OPENSSL_free(cached_ec_point);
    if (cached_rsa_modulus) OPENSSL_free(cached_rsa_modulus);
    if (cached_rsa_exponent) OPENSSL_free(cached_rsa_exponent);
    cached_spki = NULL;
    cached_ec_params = NULL;
    cached_ec_point = NULL;
    cached_rsa_modulus = NULL;
    cached_rsa_exponent = NULL;
    pthread_mutex_unlock(&cache_mutex);

    return shim_http_global_cleanup();
}

static CK_RV shim_GetInfo(CK_INFO_PTR pInfo)
{
    memset(pInfo, 0, sizeof(CK_INFO));
    pInfo->cryptokiVersion.major = 2;
    pInfo->cryptokiVersion.minor = 40;
    OPENSSL_strlcpy((char *)pInfo->manufacturerID, "Shim Provider",
                    sizeof(pInfo->manufacturerID));
    OPENSSL_strlcpy((char *)pInfo->libraryDescription, "Shim Provider",
                    sizeof(pInfo->libraryDescription));
    pInfo->libraryVersion.major = 1;
    pInfo->libraryVersion.minor = 0;
    return CKR_OK;
}

static CK_RV shim_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                              CK_ULONG_PTR pulCount)
{
    if (pSlotList == NULL) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) {
        return CKR_BUFFER_TOO_SMALL;
    }
    pSlotList[0] = SHIM_SLOT_ID;
    *pulCount = 1;
    return CKR_OK;
}

static CK_RV shim_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof(CK_SLOT_INFO));
    OPENSSL_strlcpy((char *)pInfo->slotDescription, "Shim Slot",
                    sizeof(pInfo->slotDescription));
    OPENSSL_strlcpy((char *)pInfo->manufacturerID, "Shim Provider",
                    sizeof(pInfo->manufacturerID));
    pInfo->flags = CKF_TOKEN_PRESENT;
    return CKR_OK;
}

static CK_RV shim_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    memset(pInfo, 0, sizeof(CK_TOKEN_INFO));
    OPENSSL_strlcpy((char *)pInfo->label, "Shim Token", sizeof(pInfo->label));
    OPENSSL_strlcpy((char *)pInfo->manufacturerID, "Shim Provider",
                    sizeof(pInfo->manufacturerID));
    OPENSSL_strlcpy((char *)pInfo->model, "Shim Token", sizeof(pInfo->model));
    OPENSSL_strlcpy((char *)pInfo->serialNumber, "1",
                    sizeof(pInfo->serialNumber));
    pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED
                   | CKF_TOKEN_INITIALIZED;
    return CKR_OK;
}

static CK_RV shim_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags,
                              CK_VOID_PTR pApplication, CK_NOTIFY Notify,
                              CK_SESSION_HANDLE_PTR phSession)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    *phSession = SHIM_SESSION_HANDLE;
    return CKR_OK;
}

static CK_RV shim_CloseSession(CK_SESSION_HANDLE hSession)
{
    return CKR_OK;
}

static CK_RV shim_GetSessionInfo(CK_SESSION_HANDLE hSession,
                                 CK_SESSION_INFO_PTR pInfo)
{
    if (hSession != SHIM_SESSION_HANDLE) return CKR_SESSION_HANDLE_INVALID;
    memset(pInfo, 0, sizeof(CK_SESSION_INFO));
    pInfo->slotID = SHIM_SLOT_ID;
    pInfo->state = CKS_RW_USER_FUNCTIONS;
    pInfo->flags = CKF_RW_SESSION | CKF_SERIAL_SESSION;
    return CKR_OK;
}

static CK_RV shim_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
                        CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    return CKR_OK;
}

/* Number of mechanisms we support */
#define NUM_MECHANISMS 3
static CK_MECHANISM_TYPE supported_mechanisms[NUM_MECHANISMS] = {
    CKM_ECDSA, CKM_RSA_PKCS, CKM_RSA_PKCS_PSS
};

static CK_RV shim_GetMechanismList(CK_SLOT_ID slotID,
                                   CK_MECHANISM_TYPE_PTR pMechanismList,
                                   CK_ULONG_PTR pulCount)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (pMechanismList == NULL) {
        *pulCount = NUM_MECHANISMS;
        return CKR_OK;
    }
    if (*pulCount < NUM_MECHANISMS) {
        *pulCount = NUM_MECHANISMS;
        return CKR_BUFFER_TOO_SMALL;
    }
    for (CK_ULONG i = 0; i < NUM_MECHANISMS; i++) {
        pMechanismList[i] = supported_mechanisms[i];
    }
    *pulCount = NUM_MECHANISMS;
    return CKR_OK;
}

static CK_RV shim_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                                   CK_MECHANISM_INFO_PTR pInfo)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;

    memset(pInfo, 0, sizeof(CK_MECHANISM_INFO));
    pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;

    switch (type) {
    case CKM_ECDSA:
        pInfo->ulMinKeySize = 256;
        pInfo->ulMaxKeySize = 521;
        break;
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
        pInfo->ulMinKeySize = 2048;
        pInfo->ulMaxKeySize = 8192;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

static int find_index = 0;

static CK_RV shim_FindObjectsInit(CK_SESSION_HANDLE hSession,
                                  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    find_index = 0;
    return CKR_OK;
}

static CK_RV shim_FindObjects(CK_SESSION_HANDLE hSession,
                              CK_OBJECT_HANDLE_PTR phObject,
                              CK_ULONG ulMaxObjectCount,
                              CK_ULONG_PTR pulObjectCount)
{
    if (ulMaxObjectCount == 0) {
        *pulObjectCount = 0;
        return CKR_OK;
    }

    if (find_index == 0) {
        phObject[0] = SHIM_OBJECT_HANDLE;
        *pulObjectCount = 1;
        find_index++;
    } else {
        *pulObjectCount = 0;
    }
    return CKR_OK;
}

static CK_RV shim_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
    return CKR_OK;
}

static CK_RV ensure_certificate_info(void)
{
    pthread_mutex_lock(&cache_mutex);
    /* For RSA keys, we need SPKI, modulus and exponent; for EC keys we need params and point */
    if (cached_spki
        && ((cached_key_type == KEY_TYPE_RSA && cached_rsa_modulus
             && cached_rsa_exponent)
            || (cached_key_type == KEY_TYPE_EC && cached_ec_params
                && cached_ec_point))) {
        pthread_mutex_unlock(&cache_mutex);
        return CKR_OK;
    }
    pthread_mutex_unlock(&cache_mutex);

    struct string s;
    const char *cert_path = getenv("PKCS11_SHIM_API_CERT_GET_PATH");
    if (!cert_path) cert_path = "/certificate";
    char *url = get_shim_url(cert_path);
    if (!url) return CKR_HOST_MEMORY;
    CK_RV rv = shim_http_get(url, &s);
    OPENSSL_free(url);
    if (rv != CKR_OK) return rv;

    unsigned char *cert_der = NULL;
    size_t cert_der_len = 0;
    rv = parse_certificate_response(s.ptr, s.len, &cert_der, &cert_der_len);
    OPENSSL_free(s.ptr);
    if (rv != CKR_OK) return rv;

    const unsigned char *ptr = cert_der;
    X509 *x509 = d2i_X509(NULL, &ptr, cert_der_len);
    OPENSSL_free(cert_der);
    if (!x509) return CKR_FUNCTION_FAILED;

    EVP_PKEY *pkey = X509_get_pubkey(x509);
    X509_free(x509);
    if (!pkey) return CKR_FUNCTION_FAILED;

    /* Extract SPKI (SubjectPublicKeyInfo) */
    unsigned char *spki = NULL;
    int spki_len = i2d_PUBKEY(pkey, &spki);
    if (spki_len <= 0) {
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    unsigned char *params = NULL;
    int params_len = 0;
    unsigned char *point_der = NULL;
    int point_der_len = 0;
    unsigned char *rsa_modulus = NULL;
    size_t rsa_modulus_len = 0;
    unsigned char *rsa_exponent = NULL;
    size_t rsa_exponent_len = 0;

    /* Determine key type and extract type-specific parameters */
    int key_type = KEY_TYPE_UNKNOWN;
    size_t key_bits = EVP_PKEY_get_bits(pkey);

    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
        key_type = KEY_TYPE_EC;
        shim_log(SHIM_LOG_DEBUG, "Detected EC key, %zu bits", key_bits);

        char group_name[128];
        if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                           group_name, sizeof(group_name),
                                           NULL)) {
            int nid = OBJ_sn2nid(group_name);
            if (nid == NID_undef) nid = OBJ_ln2nid(group_name);
            if (nid != NID_undef) {
                ASN1_OBJECT *obj = OBJ_nid2obj(nid);
                params_len = i2d_ASN1_OBJECT(obj, &params);
            }
        }

        size_t len = 0;
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, NULL,
                                            0, &len)) {
            unsigned char *point_buf = OPENSSL_malloc(len);
            if (point_buf) {
                if (EVP_PKEY_get_octet_string_param(
                        pkey, OSSL_PKEY_PARAM_PUB_KEY, point_buf, len, &len)) {
                    ASN1_OCTET_STRING *os = ASN1_OCTET_STRING_new();
                    ASN1_OCTET_STRING_set(os, point_buf, len);
                    point_der_len = i2d_ASN1_OCTET_STRING(os, &point_der);
                    ASN1_OCTET_STRING_free(os);
                }
                OPENSSL_free(point_buf);
            }
        }
    } else if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA) {
        key_type = KEY_TYPE_RSA;
        shim_log(SHIM_LOG_DEBUG, "Detected RSA key, %zu bits", key_bits);

        /* Extract RSA modulus (n) and public exponent (e) */
        BIGNUM *n = NULL, *e = NULL;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) && n) {
            rsa_modulus_len = BN_num_bytes(n);
            rsa_modulus = OPENSSL_malloc(rsa_modulus_len);
            if (rsa_modulus) {
                BN_bn2bin(n, rsa_modulus);
            }
            BN_free(n);
        }
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) && e) {
            rsa_exponent_len = BN_num_bytes(e);
            rsa_exponent = OPENSSL_malloc(rsa_exponent_len);
            if (rsa_exponent) {
                BN_bn2bin(e, rsa_exponent);
            }
            BN_free(e);
        }
    } else {
        shim_log(SHIM_LOG_ERROR, "Unsupported key type: %d",
                 EVP_PKEY_base_id(pkey));
        EVP_PKEY_free(pkey);
        OPENSSL_free(spki);
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    EVP_PKEY_free(pkey);

    pthread_mutex_lock(&cache_mutex);
    if (cached_spki) OPENSSL_free(cached_spki);
    cached_spki = spki;
    cached_spki_len = spki_len;
    cached_key_type = key_type;
    cached_key_bits = key_bits;

    if (params) {
        if (cached_ec_params) OPENSSL_free(cached_ec_params);
        cached_ec_params = params;
        cached_ec_params_len = params_len;
    }
    if (point_der) {
        if (cached_ec_point) OPENSSL_free(cached_ec_point);
        cached_ec_point = point_der;
        cached_ec_point_len = point_der_len;
    }
    if (rsa_modulus) {
        if (cached_rsa_modulus) OPENSSL_free(cached_rsa_modulus);
        cached_rsa_modulus = rsa_modulus;
        cached_rsa_modulus_len = rsa_modulus_len;
    }
    if (rsa_exponent) {
        if (cached_rsa_exponent) OPENSSL_free(cached_rsa_exponent);
        cached_rsa_exponent = rsa_exponent;
        cached_rsa_exponent_len = rsa_exponent_len;
    }
    pthread_mutex_unlock(&cache_mutex);

    /* For RSA, we need SPKI, modulus and exponent. For EC, we need params and point too. */
    if (cached_spki
        && (key_type == KEY_TYPE_RSA
                ? (cached_rsa_modulus && cached_rsa_exponent)
                : (cached_ec_params && cached_ec_point))) {
        return CKR_OK;
    }
    shim_log(SHIM_LOG_ERROR, "Failed to cache all required key attributes");
    return CKR_FUNCTION_FAILED;
}

static CK_RV shim_GetAttributeValue(CK_SESSION_HANDLE hSession,
                                    CK_OBJECT_HANDLE hObject,
                                    CK_ATTRIBUTE_PTR pTemplate,
                                    CK_ULONG ulCount)
{
    if (hObject != SHIM_OBJECT_HANDLE) return CKR_OBJECT_HANDLE_INVALID;

    for (CK_ULONG i = 0; i < ulCount; i++) {
        shim_log(SHIM_LOG_DEBUG, "GetAttributeValue type=0x%lx",
                 pTemplate[i].type);
        switch (pTemplate[i].type) {
        case CKA_CLASS:
            if (pTemplate[i].pValue) {
                *(CK_OBJECT_CLASS *)pTemplate[i].pValue = CKO_PRIVATE_KEY;
            }
            pTemplate[i].ulValueLen = sizeof(CK_OBJECT_CLASS);
            break;
        case CKA_KEY_TYPE: {
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            CK_KEY_TYPE kt;
            pthread_mutex_lock(&cache_mutex);
            if (cached_key_type == KEY_TYPE_RSA) {
                kt = CKK_RSA;
            } else {
                kt = CKK_EC;
            }
            pthread_mutex_unlock(&cache_mutex);

            if (pTemplate[i].pValue) {
                *(CK_KEY_TYPE *)pTemplate[i].pValue = kt;
            }
            pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
        } break;
        case CKA_ID:
            if (pTemplate[i].pValue) {
                ((CK_BYTE *)pTemplate[i].pValue)[0] = 0x01;
            }
            pTemplate[i].ulValueLen = 1;
            break;
        case CKA_TOKEN:
        case CKA_COPYABLE:
            if (pTemplate[i].pValue) {
                *(CK_BBOOL *)pTemplate[i].pValue = CK_TRUE;
            }
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            break;
        case 0x61d: /* CKA_PARAMETER_SET */
            pTemplate[i].ulValueLen = 0;
            break;
        case CKA_PUBLIC_KEY_INFO: {
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            pthread_mutex_lock(&cache_mutex);
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= cached_spki_len) {
                    memcpy(pTemplate[i].pValue, cached_spki, cached_spki_len);
                    pTemplate[i].ulValueLen = cached_spki_len;
                } else {
                    pTemplate[i].ulValueLen = cached_spki_len;
                    pthread_mutex_unlock(&cache_mutex);
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = cached_spki_len;
            }
            pthread_mutex_unlock(&cache_mutex);
        } break;
        case CKA_ALLOWED_MECHANISMS: {
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            CK_MECHANISM_TYPE mechanisms[2];
            size_t num_mechs;

            pthread_mutex_lock(&cache_mutex);
            if (cached_key_type == KEY_TYPE_RSA) {
                mechanisms[0] = CKM_RSA_PKCS;
                mechanisms[1] = CKM_RSA_PKCS_PSS;
                num_mechs = 2;
            } else {
                mechanisms[0] = CKM_ECDSA;
                num_mechs = 1;
            }
            pthread_mutex_unlock(&cache_mutex);

            size_t mech_size = num_mechs * sizeof(CK_MECHANISM_TYPE);
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= mech_size) {
                    memcpy(pTemplate[i].pValue, mechanisms, mech_size);
                    pTemplate[i].ulValueLen = mech_size;
                } else {
                    pTemplate[i].ulValueLen = mech_size;
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = mech_size;
            }
        } break;
        case CKA_LABEL:
            if (pTemplate[i].pValue) {
                OPENSSL_strlcpy((char *)pTemplate[i].pValue, "Shim Key",
                                pTemplate[i].ulValueLen);
            }
            pTemplate[i].ulValueLen = 8;
            break;
        case CKA_PRIVATE:
            if (pTemplate[i].pValue) {
                *(CK_BBOOL *)pTemplate[i].pValue = CK_TRUE;
            }
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            break;
        case CKA_SENSITIVE:
            if (pTemplate[i].pValue) {
                *(CK_BBOOL *)pTemplate[i].pValue = CK_TRUE;
            }
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            break;
        case CKA_ALWAYS_AUTHENTICATE:
            if (pTemplate[i].pValue) {
                *(CK_BBOOL *)pTemplate[i].pValue = CK_FALSE;
            }
            pTemplate[i].ulValueLen = sizeof(CK_BBOOL);
            break;
        case CKA_EC_PARAMS: {
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            /* EC params only available for EC keys */
            pthread_mutex_lock(&cache_mutex);
            if (cached_key_type != KEY_TYPE_EC) {
                pthread_mutex_unlock(&cache_mutex);
                pTemplate[i].ulValueLen = (CK_ULONG)-1;
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pthread_mutex_unlock(&cache_mutex);

            pthread_mutex_lock(&cache_mutex);
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= cached_ec_params_len) {
                    memcpy(pTemplate[i].pValue, cached_ec_params,
                           cached_ec_params_len);
                    pTemplate[i].ulValueLen = cached_ec_params_len;
                } else {
                    pTemplate[i].ulValueLen = cached_ec_params_len;
                    pthread_mutex_unlock(&cache_mutex);
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = cached_ec_params_len;
            }
            pthread_mutex_unlock(&cache_mutex);
        } break;
        case CKA_EC_POINT: {
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            /* EC point only available for EC keys */
            pthread_mutex_lock(&cache_mutex);
            if (cached_key_type != KEY_TYPE_EC) {
                pthread_mutex_unlock(&cache_mutex);
                pTemplate[i].ulValueLen = (CK_ULONG)-1;
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }
            pthread_mutex_unlock(&cache_mutex);

            pthread_mutex_lock(&cache_mutex);
            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= cached_ec_point_len) {
                    memcpy(pTemplate[i].pValue, cached_ec_point,
                           cached_ec_point_len);
                    pTemplate[i].ulValueLen = cached_ec_point_len;
                } else {
                    pTemplate[i].ulValueLen = cached_ec_point_len;
                    pthread_mutex_unlock(&cache_mutex);
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = cached_ec_point_len;
            }
            pthread_mutex_unlock(&cache_mutex);
        } break;
        case CKA_MODULUS: { /* 0x120 */
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            /* Modulus only available for RSA keys */
            pthread_mutex_lock(&cache_mutex);
            if (cached_key_type != KEY_TYPE_RSA) {
                pthread_mutex_unlock(&cache_mutex);
                pTemplate[i].ulValueLen = (CK_ULONG)-1;
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }

            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= cached_rsa_modulus_len) {
                    memcpy(pTemplate[i].pValue, cached_rsa_modulus,
                           cached_rsa_modulus_len);
                    pTemplate[i].ulValueLen = cached_rsa_modulus_len;
                } else {
                    pTemplate[i].ulValueLen = cached_rsa_modulus_len;
                    pthread_mutex_unlock(&cache_mutex);
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = cached_rsa_modulus_len;
            }
            pthread_mutex_unlock(&cache_mutex);
        } break;
        case CKA_PUBLIC_EXPONENT: { /* 0x122 */
            CK_RV rv = ensure_certificate_info();
            if (rv != CKR_OK) return rv;

            /* Public exponent only available for RSA keys */
            pthread_mutex_lock(&cache_mutex);
            if (cached_key_type != KEY_TYPE_RSA) {
                pthread_mutex_unlock(&cache_mutex);
                pTemplate[i].ulValueLen = (CK_ULONG)-1;
                return CKR_ATTRIBUTE_TYPE_INVALID;
            }

            if (pTemplate[i].pValue) {
                if (pTemplate[i].ulValueLen >= cached_rsa_exponent_len) {
                    memcpy(pTemplate[i].pValue, cached_rsa_exponent,
                           cached_rsa_exponent_len);
                    pTemplate[i].ulValueLen = cached_rsa_exponent_len;
                } else {
                    pTemplate[i].ulValueLen = cached_rsa_exponent_len;
                    pthread_mutex_unlock(&cache_mutex);
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = cached_rsa_exponent_len;
            }
            pthread_mutex_unlock(&cache_mutex);
        } break;
        default:
            pTemplate[i].ulValueLen = (CK_ULONG)-1;
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
    }
    return CKR_OK;
}

static CK_RV shim_SignInit(CK_SESSION_HANDLE hSession,
                           CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
    return CKR_OK;
}

/* Base64 encoding helper (duplicated from shim.c, maybe should be shared in utils.c) */
/* Actually, let's use EVP_EncodeBlock directly here too, or duplicate helper */
static char *base64_encode(const unsigned char *data, size_t input_length,
                           size_t *output_length)
{
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = OPENSSL_malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    EVP_EncodeBlock((unsigned char *)encoded_data, data, input_length);
    return encoded_data;
}

/* DigestInfo prefixes for various hash algorithms (DER encoded) */
static const unsigned char sha256_digestinfo_prefix[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};
static const unsigned char sha384_digestinfo_prefix[] = {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30
};
static const unsigned char sha512_digestinfo_prefix[] = {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40
};

/* Extract raw hash from DigestInfo structure for RSA PKCS#1 v1.5 signing.
 * Returns pointer to hash within pData (no allocation), or NULL if not DigestInfo.
 * Sets *hash_len to the length of the raw hash. */
static const unsigned char *
extract_hash_from_digestinfo(const unsigned char *pData, size_t ulDataLen,
                             size_t *hash_len)
{
    /* Check for SHA-512 DigestInfo (19 byte prefix + 64 byte hash = 83 bytes) */
    if (ulDataLen == 83 && memcmp(pData, sha512_digestinfo_prefix, 19) == 0) {
        *hash_len = 64;
        return pData + 19;
    }
    /* Check for SHA-384 DigestInfo (19 byte prefix + 48 byte hash = 67 bytes) */
    if (ulDataLen == 67 && memcmp(pData, sha384_digestinfo_prefix, 19) == 0) {
        *hash_len = 48;
        return pData + 19;
    }
    /* Check for SHA-256 DigestInfo (19 byte prefix + 32 byte hash = 51 bytes) */
    if (ulDataLen == 51 && memcmp(pData, sha256_digestinfo_prefix, 19) == 0) {
        *hash_len = 32;
        return pData + 19;
    }
    return NULL;
}

static CK_RV shim_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                       CK_ULONG_PTR pulSignatureLen)
{
    if (pSignature == NULL) {
        /* Return expected signature length based on key type and size */
        CK_RV rv = ensure_certificate_info();
        if (rv != CKR_OK) return rv;

        pthread_mutex_lock(&cache_mutex);
        if (cached_key_type == KEY_TYPE_RSA) {
            /* RSA signature length = key size in bytes */
            *pulSignatureLen = (cached_key_bits + 7) / 8;
        } else {
            /* EC signature length = 2 * (key size in bytes) for r|s format */
            /* For P-256: 64 bytes, P-384: 96 bytes, P-521: ~132 bytes */
            *pulSignatureLen = 2 * ((cached_key_bits + 7) / 8);
        }
        pthread_mutex_unlock(&cache_mutex);
        shim_log(SHIM_LOG_DEBUG, "Sign: returning expected sig length %lu",
                 *pulSignatureLen);
        return CKR_OK;
    }

    /* For RSA keys, OpenSSL CMS passes DigestInfo (prefix + hash).
     * The API expects just the raw hash. Extract it. */
    const unsigned char *data_to_sign = pData;
    size_t data_len = ulDataLen;

    pthread_mutex_lock(&cache_mutex);
    int is_rsa = (cached_key_type == KEY_TYPE_RSA);
    pthread_mutex_unlock(&cache_mutex);

    if (is_rsa) {
        size_t hash_len;
        const unsigned char *raw_hash =
            extract_hash_from_digestinfo(pData, ulDataLen, &hash_len);
        if (raw_hash) {
            shim_log(SHIM_LOG_DEBUG,
                     "Sign: extracted %zu-byte hash from DigestInfo (input was "
                     "%lu bytes)",
                     hash_len, ulDataLen);
            data_to_sign = raw_hash;
            data_len = hash_len;
        } else {
            shim_log(SHIM_LOG_DEBUG,
                     "Sign: RSA key but data (%lu bytes) is not DigestInfo, "
                     "sending as-is",
                     ulDataLen);
        }
    }

    size_t b64len;
    char *b64data = base64_encode(data_to_sign, data_len, &b64len);
    if (!b64data) return CKR_HOST_MEMORY;

    /* Construct JSON body */
    const char *fmt = getenv("PKCS11_SHIM_API_SIGN_REQUEST_FORMAT");
    if (!fmt) fmt = "{\"data\": \"%s\", \"mechanism\": \"ECDSA\"}";

    size_t fmt_len = strlen(fmt);
    char *json_body = OPENSSL_malloc(fmt_len + b64len + 1);
    if (!json_body) {
        OPENSSL_free(b64data);
        return CKR_HOST_MEMORY;
    }
    sprintf(json_body, fmt, b64data);
    OPENSSL_free(b64data);

    const char *sign_path = getenv("PKCS11_SHIM_API_SIGN_PATH");
    if (!sign_path) sign_path = "/sign";
    char *url = get_shim_url(sign_path);
    if (!url) {
        OPENSSL_free(json_body);
        return CKR_HOST_MEMORY;
    }

    struct string s;
    CK_RV rv = shim_http_post(url, json_body, &s);
    OPENSSL_free(url);
    OPENSSL_free(json_body);
    if (rv != CKR_OK) return rv;

    unsigned char *sig_bin = NULL;
    size_t sig_bin_len = 0;
    rv = parse_signature_response(s.ptr, s.len, &sig_bin, &sig_bin_len);
    OPENSSL_free(s.ptr);
    if (rv != CKR_OK) return rv;

    if (*pulSignatureLen < sig_bin_len) {
        OPENSSL_free(sig_bin);
        *pulSignatureLen = sig_bin_len;
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(pSignature, sig_bin, sig_bin_len);
    *pulSignatureLen = sig_bin_len;
    OPENSSL_free(sig_bin);

    return CKR_OK;
}

CK_RV shim_module_init(P11PROV_MODULE *mctx)
{
    P11PROV_INTERFACE *intf = OPENSSL_zalloc(sizeof(P11PROV_INTERFACE));
    if (!intf) return CKR_HOST_MEMORY;

    intf->Initialize = shim_Initialize;
    intf->Finalize = shim_Finalize;
    intf->GetInfo = shim_GetInfo;
    intf->GetSlotList = shim_GetSlotList;
    intf->GetSlotInfo = shim_GetSlotInfo;
    intf->GetTokenInfo = shim_GetTokenInfo;
    intf->OpenSession = shim_OpenSession;
    intf->CloseSession = shim_CloseSession;
    intf->GetSessionInfo = shim_GetSessionInfo;
    intf->Login = shim_Login;
    intf->GetMechanismList = shim_GetMechanismList;
    intf->GetMechanismInfo = shim_GetMechanismInfo;
    intf->FindObjectsInit = shim_FindObjectsInit;
    intf->FindObjects = shim_FindObjects;
    intf->FindObjectsFinal = shim_FindObjectsFinal;
    intf->GetAttributeValue = shim_GetAttributeValue;
    intf->SignInit = shim_SignInit;
    intf->Sign = shim_Sign;

    mctx->interface = intf;
    return CKR_OK;
}
