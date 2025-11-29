[![Build](https://github.com/kabakaev/pkcs11-provider/actions/workflows/build.yml/badge.svg)](https://github.com/kabakaev/pkcs11-provider/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# pkcs11-provider repurposed for remote CMS signing

The source code of original pkcs11-provider is changed to support CMS signing with private key on a remote API.

Namely, the modified version replaces the "PKCS#11 Driver" part with a Shim, which instead of talking to a local hardware driver, talks to a Go REST API. This allows openssl to think it's using a local token, while actually performing ECDSA signature operation remotely.

The corresponding remote API is implemented in [api/main.go](api/main.go).

The test script is in [test_cms.sh](test_cms.sh).

The implementation plan is in [plan.md](plan.md).

The original pkcs11-provider README.md:

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
