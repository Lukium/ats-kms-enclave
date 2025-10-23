# Domain Architecture

This document clarifies the domain structure for the AllTheServices platform and KMS enclave.

## Domain Overview

### Primary Domains

**Main Platform Domain**: `allthe.services`
- This is where the main Progressive Web App (PWA) is hosted
- Users access the platform at `https://allthe.services`
- Contains all business logic, UI, and application features
- **Note**: During development/testing, `alpha.allthe.services` is used (internal only, not documented in public docs)

**Infrastructure Domain**: `ats.run`
- Helper/shortener domain used for infrastructure components
- Used for services that need to be separate from the main platform
- Examples:
  - KMS enclave: `kms.ats.run`
  - Relay nodes: `{adjective-color-noun}.ats.run` (e.g., `swift-red-falcon.ats.run`, via cloudflared)
  - API services: `api.ats.run` (if needed)

## KMS Enclave Architecture

### Domain Separation for Security

```
┌──────────────────────────────────────────────────┐
│   Main PWA: https://allthe.services              │
│                                                  │
│   ┌─────────────────────────────────────────┐    │
│   │  <iframe                                │    │
│   │    src="https://kms.ats.run/kms.html"   │    │
│   │    sandbox="allow-scripts               │    │
│   │             allow-same-origin">         │    │
│   │                                         │    │
│   │    KMS Enclave                          │    │
│   │    (Different origin = isolated)        │    │
│   └─────────────────────────────────────────┘    │
└──────────────────────────────────────────────────┘
```

### Why This Architecture?

**Cross-Origin Isolation**:
- Main PWA: `allthe.services`
- KMS Enclave: `kms.ats.run`
- Different origins = browser enforces security boundaries
- PWA cannot access enclave's storage, cookies, or functions
- Communication only via postMessage (explicit, auditable)

**Infrastructure Domain Benefits**:
- Clean separation of concerns
- `ats.run` reserved for infrastructure/security-critical services
- `allthe.services` for user-facing application
- Easy to recognize infrastructure vs. application URLs

## Origin Checks

### In KMS Enclave Code

The enclave must validate that messages come from the official PWA:

```typescript
// KMS enclave (running at kms.ats.run)
window.addEventListener('message', (event) => {
  // Verify origin is the main PWA
  if (event.origin !== 'https://allthe.services') {
    console.warn('[KMS] Ignoring message from unexpected origin:', event.origin)
    return
  }
  // Process request...
})
```

### In Main PWA Code

The PWA must validate that responses come from the official KMS:

```typescript
// Main PWA (running at allthe.services)
window.addEventListener('message', (event) => {
  // Verify origin is the KMS enclave
  if (event.origin !== 'https://kms.ats.run') {
    console.warn('[PWA] Ignoring message from unexpected origin:', event.origin)
    return
  }
  // Process response...
})
```

## Content Security Policy (CSP)

### KMS Enclave CSP Headers

The enclave at `kms.ats.run` must restrict which origins can embed it:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self';
  connect-src 'self';
  worker-src 'self';
  frame-ancestors https://allthe.services;
  ...
```

**Critical**: `frame-ancestors https://allthe.services` ensures **only** the official PWA can embed the KMS iframe.

### Main PWA CSP Headers

The PWA at `allthe.services` must allow embedding the KMS:

```
Content-Security-Policy:
  default-src 'none';
  script-src 'self' 'strict-dynamic';
  connect-src 'self' https://api.ats.run https://kms.ats.run;
  frame-src https://kms.ats.run;
  ...
```

## Hosting Setup

### KMS Enclave (`kms.ats.run`)

**Requirements**:
- Static hosting only (no server-side logic)
- Immutable artifacts (content-addressed filenames)
- CDN distribution (Cloudflare or similar)
- HTTPS required (automatic via Cloudflare)

**Suggested setup**:
- Cloudflare Pages or R2 + CDN
- Custom domain: `kms.ats.run`
- Automatic certificate management
- Edge caching for performance

### Main PWA (`allthe.services`)

**Requirements**:
- Progressive Web App hosting
- Service Worker support
- HTTPS required
- Can embed cross-origin iframes

**Integration**:
```typescript
// In main PWA code
const kmsIframe = document.createElement('iframe')
kmsIframe.src = 'https://kms.ats.run/kms.html'
kmsIframe.sandbox.add('allow-scripts')
kmsIframe.sandbox.add('allow-same-origin')
document.body.appendChild(kmsIframe)
```

## Relay Node Subdomains

Relay nodes automatically get subdomains under `ats.run`:
- Format: `{adjective-color-noun}.ats.run` (e.g., `swift-red-falcon.ats.run`, `happy-blue-whale.ats.run`)
- Human-friendly names for easy recognition
- Managed via cloudflared tunnels
- Separate from KMS enclave subdomain

## DNS Configuration

```
# ats.run domain
kms.ats.run                      CNAME → cloudflare-pages-or-cdn
{adjective-color-noun}.ats.run   CNAME → cloudflared-tunnel (per relay)

# allthe.services domain
allthe.services      A/AAAA → main-hosting-provider
www.allthe.services  CNAME → allthe.services
```

## Summary

| Component | Domain | Purpose |
|-----------|--------|---------|
| Main PWA | `allthe.services` | User-facing application |
| KMS Enclave | `kms.ats.run` | Isolated crypto operations |
| Relay Nodes | `{adjective-color-noun}.ats.run` | Distributed relay infrastructure (human-friendly names) |
| API (if needed) | `api.ats.run` | Backend services |

**Key principle**: `ats.run` is for infrastructure, `allthe.services` is for the application.
