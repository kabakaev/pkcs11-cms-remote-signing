# Implementation Plan - Remote CMS Signing

The goal is to enable `openssl cms -sign` to sign a large binary file using a remote private key accessed via a REST API. We will modify `pkcs11-provider` to act as a shim that forwards signing requests to a Go-based REST API.

## Decisions

- **Breaking Change**: The `pkcs11-provider` will be modified to bypass standard PKCS#11 module loading and instead use a hardcoded/configured HTTP shim. This effectively repurposes the provider for this specific use case.
- **Assumption**: The remote server expects the raw data to be signed (which, for CMS, is the DER-encoded signed attributes). The server will perform the ECDSA signature. Other signature mechanisms are not supported.
- **Assumption**: We will use a hardcoded slot/token/key for simplicity, or simple logic to expose one virtual token. The key information will be fetched from the remote server over HTTP.

## Implementation

### Go REST API

#### [NEW] [api/main.go](./api/main.go)

- Implement a simple HTTP server listening on `127.0.0.1:27180`.
- Endpoint: `POST /sign`
- Request: JSON `{ "data": "base64...", "mechanism": "ECDSA" }`
- Response: JSON `{ "signature": "base64..." }`
- Logic:
    - Decode base64 data.
    - Use local `openssl` CLI to sign the data.
    - Return the signature.

### PKCS#11 Provider Shim

#### [MODIFY] [src/interface.c](./src/interface.c)

- Modify [p11prov_module_init](./src/interface.c#L291-364) to check for `PKCS11_SHIM_URL` env var (or just always enable if "rewriting").
- If enabled:
    - Skip `dlopen`.
    - Allocate `mctx->interface`.
    - Populate `mctx->interface` with pointers to custom shim functions.

#### [NEW] [src/shim.c](./src/shim.c) (and header)
- Implement the shim functions:
    - `shim_Initialize`, `shim_Finalize`, `shim_GetInfo` (dummy info).
    - `shim_GetSlotList`: Returns 1 slot.
    - `shim_GetSlotInfo`, `shim_GetTokenInfo`: Returns dummy info.
    - `shim_OpenSession`, `shim_CloseSession`: Manage dummy sessions.
    - `shim_FindObjectsInit`, `shim_FindObjects`, `shim_FindObjectsFinal`: Return 1 private key object.
    - `shim_GetAttributeValue`: Return attributes for the private key (CKA_CLASS=CKO_PRIVATE_KEY, CKA_KEY_TYPE=CKK_EC, CKA_ID=...).
    - `shim_SignInit`: Store state.
    - `shim_Sign`:
        - Encode data to base64.
        - Send HTTP POST to the configured URL.
        - Decode response.
        - Return signature.
    - `shim_SignUpdate`, `shim_SignFinal`: Return `CKR_FUNCTION_NOT_SUPPORTED` (assuming single-shot).
    - Helper function to perform HTTP request using `libcurl`.

#### [NEW] [src/shim.h](./src/shim.h)
- Header file for shim module init.

#### [MODIFY] [src/meson.build](./src/meson.build)
- Add `shim.c` to sources.

### Testing
#### [MODIFY] [test_cms.sh](./test_cms.sh)
- Start the Go API server in background.
- Generate a dummy file.
- Run `openssl cms -sign -provider ...`
- Verify the signature.

## Verification Plan
### Automated Tests
- Run `test_cms.sh`.
- This script will:
    1.  Build the provider.
    2.  Build and start the Go API.
    3.  Generate a test key (for the API to use).
    4.  Run `openssl cms -sign` using the provider.
    5.  Verify the output using `openssl cms -verify`.
