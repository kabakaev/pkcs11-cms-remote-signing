#ifndef SHIM_JSON_UTILS_H
#define SHIM_JSON_UTILS_H

#include <stddef.h>
#include "shim.h" /* For CK_RV */

/* Parse certificate response: { "certificate": "base64..." } */
CK_RV parse_certificate_response(const char *json, size_t len, 
                                 unsigned char **cert_der, size_t *cert_der_len);

/* Parse signature response: { "signature": "base64..." } */
CK_RV parse_signature_response(const char *json, size_t len, 
                               unsigned char **sig, size_t *sig_len);

#endif /* SHIM_JSON_UTILS_H */
