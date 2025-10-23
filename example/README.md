# ATS KMS Enclave - Demos

Interactive demonstrations of the KMS enclave across different implementation phases.

## Available Demos

### Phase 0: Prototype ✅ Complete

[**Phase 0 Demo →**](phase-0/README.md)

In-memory key storage, Worker-based isolation, basic VAPID/JWT operations.

```bash
# Run Phase 0 demo
make demo
# or
pnpm demo
```

**Features:**
- VAPID keypair generation
- ES256 JWT signing
- Public key retrieval
- Complete workflow test

**Status:** ✅ 108 tests passing, 100% coverage

---

### Phase 1: Production Enclave (Planned)

Coming soon:
- IndexedDB key persistence
- Better error handling
- Single-file module build
- Production-ready features

---

### Phase 2: Verifiable Build (Planned)

Coming soon:
- Reproducible builds
- SRI hash generation
- Content-addressed artifacts

---

## Quick Start

```bash
# Run latest demo
make demo

# Run specific phase
cd example/phase-0
../../node_modules/.bin/vite

# Build demo for production
pnpm demo:build
```

## Demo Structure

```
example/
├── README.md          # This file
├── vite.config.ts     # Shared Vite config
├── phase-0/          # Phase 0 demo
│   ├── index.html
│   ├── demo.ts
│   └── README.md
├── phase-1/          # (future)
└── phase-2/          # (future)
```

## Browser Requirements

All demos require:
- **Chrome/Edge**: 120+
- **Firefox**: 120+
- **Safari**: 17+

Features needed:
- Web Workers
- WebCrypto API
- ES2020+ support

## Development

Demos use Vite for fast development and hot module reloading.

Each phase demo is self-contained and can be run independently.
