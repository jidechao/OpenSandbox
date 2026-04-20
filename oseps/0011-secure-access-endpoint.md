---
title: Secure Access on GetEndpoint and Signed Endpoint
authors:
  - "@Pangjiping"
creation-date: 2026-04-19
last-updated: 2026-04-20
status: draft
---

# OSEP-0011: Secure Access on GetEndpoint and Signed Endpoint

## Summary

Optional `secure_access` on sandbox create. **`GetSignedEndpoint(sandboxId, port)`** returns a URL that embeds a **route `signature`** (a **10-character** token). There is **no** `expires`, **no** signing of app path or query, and **no** DNS parent domain in the signed material. The wildcard parent domain is **routing-only**.

The **`signature`** is:

1. **`hex8`** — first **8** characters of the lowercase hex encoding of **`SHA256(inner)`** (i.e. the first **4** bytes of the digest as hex).
2. **`signed_key_id`** — the **last 2** characters of **`signature`**, **`[0-9a-z]`**, equal to the **`key_id`** of the `secret_bytes` row used to mint (typically the server **`active_key`**).

`GetEndpoint` may still return an opaque static **`OPENSANDBOX-SECURE-ACCESS`** header value (annotation / access token) when enabled. That header path is **separate** from the route **`signature`**.

## Signing algorithm (implementation order)

### 1) Inputs and constraints

- **`sandbox_id`**: used verbatim in canonical (may contain `-`).
- **`port`**: decimal integer in **`1..65535`**, **no leading zeros** (e.g. `08080` is invalid).
- **`secret_bytes`**: raw decoded secret bytes for the chosen **`signed_key_id`** (same material ingress uses to verify).

### 2) Build `canonical_bytes` (UTF-8)

Concatenate **exactly** in this order, using a single **LF** (`\n`) between segments:

```text
v1\nshort\n{sandbox_id}\n{port}\n
```

Equivalent explicit concatenation:

```text
"v1" + "\n" + "short" + "\n" + sandbox_id + "\n" + decimal(port) + "\n"
```

### 3) Build `inner` (length-prefixed byte concatenation)

`BE32(x)` is **4** bytes, **big-endian** unsigned 32-bit integer **`x`**.

```text
inner = BE32(len(secret_bytes))
     || secret_bytes
     || BE32(len(canonical_bytes))
     || canonical_bytes
```

### 4) Hash and mint `signature`

```text
digest    = SHA256(inner)              // 32 bytes
hex_all   = lowercase_hex(digest)      // 64 chars
hex8      = hex_all[0:8]
signature = hex8 + signed_key_id       // 10 chars total
```

> The signature binds **`sandbox_id`**, **`port`**, and the signing key only — not the gateway hostname or DNS suffix.

## API

- **CreateSandbox:** `secure_access.enabled` (default `false`).
- **GetSignedEndpoint(sandboxId, port):** returns `signed_endpoint` consistent with `[ingress.gateway].route.mode`, embedding **`signature`**.

## Gateway routing (where the credential lives)

### Host / header token (split on `-` from the **right**)

- **Three or more segments** `<sandbox-id>-<port>-<signature>`:
  - **Last** segment: **`signature`** (must match **`[0-9a-f]{8}[0-9a-z]{2}`**).
  - **Second-to-last**: **`port`** (rules above).
  - **Everything before** (re-joined with `-`): **`sandbox_id`**.
- **Two segments** `<sandbox-id>-<port>`: **unsigned** route; **`signature`** is empty (legacy compatibility).

| Mode | Where |
|------|-------|
| **Wildcard** | Host: `{sandbox_id}-{port}-{signature}.<parent-domain>` (parent domain from gateway DNS only; not signed) |
| **Header** | Header value only: `{sandbox_id}-{port}-{signature}` |
| **URI** | Path: `/{sandbox_id}/{port}/{signature}/` + remainder to upstream |

### URI parsing nuance

- If the path matches **OSEP** shape (valid **`port`** in segment 2 and a valid 10-char **`signature`** in segment 3), treat segments 1–3 as routing prefix and the rest as upstream path.
- Otherwise parse as **legacy** URI: first segment = **`sandbox_id`**, second = **`port`**, remainder (if any) = upstream path — **no** embedded **`signature`**.
- For sandboxes that **do not** require secure access, an OSEP-shaped path may be **reinterpreted** as legacy so a normal path segment is not mistaken for **`signature`**.

After successful authorization, strip the routing token from host / header / path prefix; forward the remaining path and query unchanged.

## Ingress verification

1. Parse **`sandbox_id`**, **`port`**, optional route **`signature`** from host, header, or URI (per mode).
2. **`GetEndpoint(sandbox_id)`** — determine whether the sandbox requires secure access and obtain **`SecureAccessToken`** (annotation) if any.
3. **Unified access decision:**
   - If the sandbox does **not** require secure access → allow.
   - If it **does** require secure access:
     - If **`OPENSANDBOX-SECURE-ACCESS`** is present → it **must** equal the sandbox token (constant-time compare) or **`401`**.
     - Else if route **`signature`** is present → rebuild **`canonical_bytes`**, recompute **`hex8`**, verify against **`secret_bytes`** for **`signed_key_id`** from **`--secure-access-keys`** → **`401`** on mismatch or unknown key.
     - Else **`401`** (signature required).

## Config

**Server (`~/.sandbox.toml`):**

```toml
[ingress.secure_access]
enabled = true
active_key = "k1"                    # 2 chars, must exist in keys

[[ingress.secure_access.keys]]
key_id = "k1"
secret = "base64:..."

[[ingress.secure_access.keys]]
key_id = "k0"
secret = "base64:..."
```

The server mints **`signature`** using **`secret_bytes`** for **`active_key`**.

**Ingress:**

```bash
opensandbox-ingress --secure-access-enabled \
  --secure-access-keys "k1=base64:...,k0=base64:..."
```

## Errors

- **`400`:** malformed route / token shape, invalid **`port`**, invalid **`signature`** charset or length.
- **`401`:** bad **`hex8`**, unknown **`signed_key_id`**, missing credential when required, or secure-access header mismatch.
- **GetSignedEndpoint:** `404` / `403` when sandbox is missing or secure access is disabled.

## Tests

- Unit: `inner` / `hex8`, right-split with hyphens in **`sandbox_id`**, two-segment unsigned host, URI OSEP vs legacy.
- Integration: three route modes + one tampered hex → **`401`**.
