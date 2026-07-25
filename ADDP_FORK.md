# ADDP controlled Fosite fork

This fork is the protocol engine dependency governed by the ADDP IAM OAuth/OIDC ADR.

## Provenance

- Upstream: `https://github.com/ory/fosite`
- Upstream baseline: `a5f0b09bf31c17297b25637bb3fec2ff7a55b159`
- License: Apache-2.0, unchanged from upstream
- Controlled release: `v0.50.0-addp.1`

## Patch inventory

1. Upstream PR #883, commit `be6b58a63c8fe8a686641f6a83323eafeca7d84b`: consume the PKCE request session only after successful verification.
2. Upstream PR #887, commits `577e158` and `7d64c9c`: restore JWT audience arrays decoded as `[]interface{}`.
3. ADDP patch: invalidated Device Code replay revokes Access and Refresh Tokens by the persisted original Device Request ID rather than the new Token Request ID.
4. ADDP test-only patch: avoid copying `sync.RWMutex` in the MemoryStore authentication fixture so the controlled release passes `go vet ./...`.

ADDP supplies the persistent RFC 8628 `DeviceRateLimitStrategy` in System. The upstream default no-op strategy is not used by the ADDP Provider.

## Release gate

Before publishing a controlled tag, run:

```bash
go test ./...
go test -race ./handler/pkce ./handler/rfc8628 ./token/jwt
go vet ./...
go mod verify
```

ADDP must reference an immutable controlled tag or commit. It must not reference this fork's moving branch.
