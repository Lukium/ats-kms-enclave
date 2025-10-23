# ATS KMS Enclave - Phase 0 Demo

Interactive demonstration of the KMS enclave prototype showing VAPID key generation, JWT signing, and public key retrieval.

## Quick Start

From the repository root:

```bash
# Run the demo (opens in browser)
pnpm demo
```

The demo will open at `http://localhost:5173`

## Features

The demo showcases all Phase 0 capabilities:

1. **Generate VAPID Keypair** - Creates a new P-256 ECDSA keypair for Web Push
2. **Sign JWT Token** - Signs a JWT with the generated key using ES256 algorithm
3. **Retrieve Public Key** - Retrieves the public key by its kid (key ID)
4. **Complete Workflow Test** - Runs all operations in sequence to verify everything works

## What's Happening Under the Hood

- **Worker Isolation**: The cryptographic operations run in a Web Worker, isolated from the main thread
- **In-Memory Storage**: Keys are stored in memory (Map) - Phase 1 will add IndexedDB persistence
- **Non-Extractable Keys**: Private keys cannot be exported from WebCrypto (browser-enforced)
- **RPC Communication**: Client communicates with Worker via postMessage with request/response correlation

## Architecture

```
┌─────────────────┐          postMessage          ┌─────────────────┐
│   Main Thread   │ ◄──────────────────────────► │   Web Worker    │
│                 │                                │                 │
│  KMSClient      │   { id, method, params }      │  handleMessage  │
│  - generateVAPID│  ───────────────────────────► │  - generateVAPID│
│  - signJWT      │                                │  - signJWT      │
│  - getPublicKey │  ◄─────────────────────────── │  - getPublicKey │
│                 │   { id, result/error }        │                 │
└─────────────────┘                                └─────────────────┘
                                                           │
                                                           ▼
                                                    ┌─────────────┐
                                                    │  WebCrypto  │
                                                    │   KeyStore  │
                                                    └─────────────┘
```

## Testing

The demo is backed by **108 tests** with **100% code coverage**:

- 52 baseline WebCrypto tests
- 29 Worker RPC handler tests
- 27 Client RPC bridge tests

Run tests:

```bash
# All tests
pnpm test

# With coverage
pnpm test:coverage

# Watch mode
pnpm test:watch
```

## Building for Production

```bash
# Build optimized demo
pnpm demo:build

# Output will be in example/dist/
```

## Browser Requirements

- **Chrome/Edge**: 120+ (recommended)
- **Firefox**: 120+
- **Safari**: 17+

All browsers must support:
- Web Workers
- WebCrypto API (SubtleCrypto)
- ES2020+ features

## Phase 0 Limitations

This is a prototype demonstration. Phase 0 limitations:

- ❌ Keys are lost on page reload (in-memory only)
- ❌ No persistence (IndexedDB will be added in Phase 1)
- ❌ Single-user only (no multi-key management)
- ❌ No signature format conversion (DER vs P-1363)
- ❌ No reproducible build pipeline yet

## Next Steps

**Phase 1** will add:
- IndexedDB persistence
- Better error handling
- Single-file module build
- Production-ready features

## License

MIT - See LICENSE file for details
