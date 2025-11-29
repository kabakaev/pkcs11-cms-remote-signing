[![Build](https://github.com/kabakaev/pkcs11-provider/actions/workflows/build.yml/badge.svg)](https://github.com/kabakaev/pkcs11-provider/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# pkcs11-provider repurposed for remote CMS signing

The source code of original pkcs11-provider is changed to support CMS signing with private key on a remote API.

Namely, the modified version replaces the "PKCS#11 Driver" part with a Shim, which instead of talking to a local hardware driver, talks to a Go REST API. This allows openssl to think it's using a local token, while actually performing ECDSA signature operation remotely.

The corresponding remote API is implemented in [api/main.go](api/main.go).

The test script is in [test_cms.sh](test_cms.sh).

The implementation plan is in [plan.md](plan.md).

## Configuration environment variables

The PKCS#11 shim is configured via environment variables:

### Required

| Variable                        | Description                                        | Example                               |
| ------------------------------- | -------------------------------------------------- | ------------------------------------- |
| `PKCS11_SHIM_URL`               | Base URL of the signing API                        | `https://code-signing.example.com/v1` |
| `PKCS11_SHIM_API_CERT_GET_PATH` | Path to GET certificate endpoint (appended to URL) | `/certificate?alias=mykey`            |
| `PKCS11_SHIM_API_SIGN_PATH`     | Path to POST sign endpoint (appended to URL)       | `/sign/digest`                        |

### Optional

| Variable                              | Description                                                                    | Default                                |
| ------------------------------------- | ------------------------------------------------------------------------------ | -------------------------------------- |
| `PKCS11_SHIM_AUTH`                    | Authentication header in `Name:Value` format                                   | _(none)_                               |
| `PKCS11_SHIM_API_CERT_JSON_FIELD`     | JSON field name containing the PEM certificate                                 | `certificate`                          |
| `PKCS11_SHIM_API_SIGN_REQUEST_FORMAT` | JSON payload format for sign request (`%s` = base64 data)                      | `{"data": "%s", "mechanism": "ECDSA"}` |
| `PKCS11_SHIM_API_SIGN_RETURN_TYPE`    | Response type: `json` (expects `{"signature":"..."}`) or `base64` (raw base64) | `json`                                 |
| `PKCS11_SHIM_SSL_VERIFY`              | Enable/disable SSL certificate verification (`true`/`false`)                   | `true`                                 |
| `PKCS11_SHIM_CAPATH`                  | Path to CA certificate bundle for SSL verification                             | _(system default)_                     |
| `PKCS11_SHIM_TIMEOUT`                 | HTTP request timeout in seconds                                                | `30`                                   |
| `PKCS11_SHIM_CURL_VERBOSE`            | Enable curl verbose output for debugging (`1` to enable)                       | _(disabled)_                           |
| `PKCS11_SHIM_DEBUG`                   | Debug output destination (e.g., `file:/dev/stderr`)                            | _(disabled)_                           |

### Example

```bash
export PKCS11_SHIM_URL="https://signing-service.example.com"
export PKCS11_SHIM_AUTH="Authorization:Bearer your-api-key-here"
export PKCS11_SHIM_API_CERT_GET_PATH="/certificate?user=test1"
export PKCS11_SHIM_API_CERT_JSON_FIELD="cert_pem"
export PKCS11_SHIM_API_SIGN_PATH="/sign"
export PKCS11_SHIM_API_SIGN_REQUEST_FORMAT='{"hash": "%s", "alias": "mykey"}'
export PKCS11_SHIM_API_SIGN_RETURN_TYPE="base64"
export PKCS11_SHIM_SSL_VERIFY="true"
```


## The original README.md

The original pkcs11-provider README.md follows.

This is an OpenSSL 3.x provider to access Hardware and Software Tokens using
the PKCS#11 Cryptographic Token Interface. Access to tokens depends
on loading an appropriate PKCS#11 driver that knows how to talk to the specific
token. The PKCS#11 provider is a connector that allows OpenSSL to make proper
use of such drivers. This code targets PKCS#11 version 3.2 but is backwards
compatible to version 3.1, 3.0 and 2.40 as well.

To report Security Vulnerabilities, please use the "Report a Security
Vulnerability" template in the issues reporting page.

### Installation

See [BUILD](BUILD.md) for more details about building and installing the provider.

### Usage

Configuration directives for the provider are documented in [provider-pkcs11(7)](docs/provider-pkcs11.7.md)
man page. Example configurations and basic use cases can be found in [HOWTO](HOWTO.md).

### Notes

 * [PKCS #11 Specification Version 3.2](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html)
