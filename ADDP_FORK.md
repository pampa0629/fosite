# ADDP controlled Fosite fork

This fork is the protocol engine dependency governed by the ADDP IAM OAuth/OIDC ADR.

## Provenance

- Upstream: `https://github.com/ory/fosite`
- Upstream baseline: `a5f0b09bf31c17297b25637bb3fec2ff7a55b159`
- License: Apache-2.0, unchanged from upstream
- Controlled release: `v0.50.0-addp.3`

## Patch inventory

1. Upstream PR #883, commit `be6b58a63c8fe8a686641f6a83323eafeca7d84b`: consume the PKCE request session only after successful verification.
2. Upstream PR #887, commits `577e158` and `7d64c9c`: restore JWT audience arrays decoded as `[]interface{}`.
3. ADDP patch: invalidated Device Code replay revokes Access and Refresh Tokens by the persisted original Device Request ID rather than the new Token Request ID.
4. ADDP test-only patch: avoid copying `sync.RWMutex` in the MemoryStore authentication fixture so the controlled release passes `go vet ./...`.
5. ADDP hosted-consent extension: expose side-effect-free PKCE authorization-request validation so a pending request can be rejected before it is persisted, while retaining the same validator used during code issuance.

6. ADDP client lookup error classification: preserve each endpoint's existing rejection for `ErrNotFound` (including wrapped errors), but return `temporarily_unavailable` / HTTP 503 for other Storage failures. Apply the same rule to Basic/Post/Public/JWT client authentication, authorization requests and Basic introspection. Preserve the cause for diagnostics and retain default suppression of storage details in protocol responses. Invalid secrets and disallowed authentication methods remain rejected. No Provider, Strategy or Storage interface changes.

ADDP supplies the persistent RFC 8628 `DeviceRateLimitStrategy` in System. The upstream default no-op strategy is not used by the ADDP Provider.

## Release gate

Before publishing a controlled tag, run:

```bash
make test
```

The same gate runs in the existing Unit tests workflow, including root/client-authentication and selected Handler race tests, vet and module verification.

ADDP must reference an immutable controlled tag or commit. It must not reference this fork's moving branch.
