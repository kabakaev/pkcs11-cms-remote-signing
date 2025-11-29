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

static unsigned char *cached_spki = NULL;
static size_t cached_spki_len = 0;
static unsigned char *cached_ec_params = NULL;
static size_t cached_ec_params_len = 0;
static unsigned char *cached_ec_point = NULL;
static size_t cached_ec_point_len = 0;

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
    cached_spki = NULL;
    cached_ec_params = NULL;
    cached_ec_point = NULL;
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

static CK_RV shim_GetMechanismList(CK_SLOT_ID slotID,
                                   CK_MECHANISM_TYPE_PTR pMechanismList,
                                   CK_ULONG_PTR pulCount)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (pMechanismList == NULL) {
        *pulCount = 1;
        return CKR_OK;
    }
    if (*pulCount < 1) {
        return CKR_BUFFER_TOO_SMALL;
    }
    pMechanismList[0] = CKM_ECDSA;
    *pulCount = 1;
    return CKR_OK;
}

static CK_RV shim_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
                                   CK_MECHANISM_INFO_PTR pInfo)
{
    if (slotID != SHIM_SLOT_ID) return CKR_SLOT_ID_INVALID;
    if (type != CKM_ECDSA) return CKR_MECHANISM_INVALID;
    pInfo->ulMinKeySize = 256;
    pInfo->ulMaxKeySize = 521;
    pInfo->flags = CKF_SIGN | CKF_VERIFY | CKF_HW;
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
    if (cached_spki && cached_ec_params && cached_ec_point) {
        pthread_mutex_unlock(&cache_mutex);
        return CKR_OK;
    }
    pthread_mutex_unlock(&cache_mutex);

    struct string s;
    const char *cert_path = getenv("PKCS11_SHIM_GET_CERT_PATH");
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

    /* Extract EC Params and Point */
    if (EVP_PKEY_base_id(pkey) == EVP_PKEY_EC) {
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
    }
    EVP_PKEY_free(pkey);

    pthread_mutex_lock(&cache_mutex);
    if (cached_spki) OPENSSL_free(cached_spki);
    cached_spki = spki;
    cached_spki_len = spki_len;

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
    pthread_mutex_unlock(&cache_mutex);

    if (cached_spki && cached_ec_params && cached_ec_point) {
        return CKR_OK;
    }
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
        case CKA_KEY_TYPE:
            if (pTemplate[i].pValue) {
                *(CK_KEY_TYPE *)pTemplate[i].pValue = CKK_EC;
            }
            pTemplate[i].ulValueLen = sizeof(CK_KEY_TYPE);
            break;
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
        case CKA_ALLOWED_MECHANISMS:
            if (pTemplate[i].pValue) {
                CK_MECHANISM_TYPE mechanisms[] = { CKM_ECDSA };
                if (pTemplate[i].ulValueLen >= sizeof(mechanisms)) {
                    memcpy(pTemplate[i].pValue, mechanisms, sizeof(mechanisms));
                    pTemplate[i].ulValueLen = sizeof(mechanisms);
                } else {
                    pTemplate[i].ulValueLen = sizeof(mechanisms);
                    return CKR_BUFFER_TOO_SMALL;
                }
            } else {
                pTemplate[i].ulValueLen = sizeof(CK_MECHANISM_TYPE);
            }
            break;
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

static CK_RV shim_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
                       CK_ULONG_PTR pulSignatureLen)
{
    if (pSignature == NULL) {
        /* Return expected signature length. For P-256, it's 64 bytes (r|s). */
        *pulSignatureLen = 64;
        return CKR_OK;
    }

    size_t b64len;
    char *b64data = base64_encode(pData, ulDataLen, &b64len);
    if (!b64data) return CKR_HOST_MEMORY;

    /* Construct JSON body */
    const char *fmt = getenv("PKCS11_SHIM_PAYLOAD_FORMAT");
    if (!fmt) fmt = "{\"data\": \"%s\", \"mechanism\": \"ECDSA\"}";

    size_t fmt_len = strlen(fmt);
    char *json_body = OPENSSL_malloc(fmt_len + b64len + 1);
    if (!json_body) {
        OPENSSL_free(b64data);
        return CKR_HOST_MEMORY;
    }
    sprintf(json_body, fmt, b64data);
    OPENSSL_free(b64data);

    char *url = get_shim_url("/sign");
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
