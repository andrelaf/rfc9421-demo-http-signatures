# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Restore and build
dotnet restore
dotnet build

# Run the API (starts on http://localhost:5050)
cd src/HttpMessageSignatures.Api && dotnet run

# Run the client (generates keys on first run, sends a signed request)
cd src/HttpMessageSignatures.Client && dotnet run
```

**First-run setup:** Run the client once first to generate `client-private-key.pem` and copy `client-public-key.pem` to the API project directory. The first run will fail to connect (API not running) — that's expected. Then start the API and run the client again.

## Architecture

This is a .NET 10 reference implementation of [RFC 9421 HTTP Message Signatures](https://datatracker.ietf.org/doc/rfc9421/), split into three projects:

### `HttpMessageSignatures.Core` — shared library

- **`Signing/SignatureBaseBuilder`** — builds the canonical "signature base" string from covered components and params (the string that gets signed/verified)
- **`Signing/HttpMessageSigner`** — orchestrates signing: computes Content-Digest, assembles `SignatureParams`, calls `SignatureBaseBuilder`, signs with the provider, and attaches `Signature-Input` / `Signature` headers to the request
- **`Signing/SigningDelegatingHandler`** — wraps `HttpMessageSigner` as an `HttpMessageHandler` for transparent signing via `HttpClient`
- **`Signing/ISignatureProvider`** — contract for sign/verify; implementations: `EcdsaP256SignatureProvider` and `RsaPssSignatureProvider`
- **`Verification/HttpMessageVerifier`** — verifies a signature: extracts headers, parses params, validates timestamp/expiry/algorithm, rebuilds signature base, verifies cryptographically
- **`Verification/SignatureInputParser`** — simplified RFC 8941 Structured Fields parser for the `Signature-Input` header
- **`Digest/ContentDigestCalculator`** — computes and verifies `Content-Digest: sha-256=:...:` (RFC 9530)
- **`Models/SignatureComponent`** — string constants for covered components (`@method`, `@target-uri`, `@authority`, etc.)

### `HttpMessageSignatures.Api` — Minimal API server

- Loads `client-public-key.pem` at startup and registers `EcdsaP256SignatureProvider` + `HttpMessageVerifier` in DI
- `SignatureVerificationMiddleware` intercepts all `/api/*` routes (except `/api/orders/health`): reads body, verifies Content-Digest, builds `HttpMessageContext`, calls `HttpMessageVerifier`, returns 401 on failure
- On success, `SignatureParams` are stored in `HttpContext.Items["rfc9421.signature-params"]` for endpoints to access (keyid, tag, etc.)

### `HttpMessageSignatures.Client` — Console app

- Generates (or loads) an ECDSA P-256 key pair; on first run, copies the public key to the API project directory
- Configures `HttpClient` via DI with `AddHttpMessageSigning()` extension, which attaches `SigningDelegatingHandler`
- Sends a signed `POST /api/orders` with covered components: `@method`, `@target-uri`, `@authority`, `content-type`, `content-digest`

## Key design notes

- The `SignatureBaseBuilder` is the core of RFC 9421 compliance — both signing and verification must produce identical signature base strings from the same inputs.
- `HttpMessageContext` is a neutral DTO that abstracts both `HttpRequestMessage` (client side) and ASP.NET `HttpContext` (server side), allowing `SignatureBaseBuilder` to work in both contexts.
- The `SignatureInputParser` is intentionally simplified — it does not implement full RFC 8941 Structured Fields. For production use, the README recommends the [NSign](https://github.com/Unisys/NSign) library.
- Nonces are generated but not validated (no replay protection) — this is a demo limitation explicitly noted in the README.
- The API uses a single hardcoded public key. Production deployments should do dynamic key lookup by `keyid` from a keystore.
