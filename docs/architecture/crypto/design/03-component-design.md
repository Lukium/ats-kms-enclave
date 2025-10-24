# Component Design

## 1. KMS Client Stub (Main PWA)

**File**: `apps/pwa/src/lib/kms-client.ts`

```typescript
/**
 * KMS Client - Provides interface to isolated KMS enclave
 *
 * This stub runs in the main PWA and communicates with the KMS
 * enclave via postMessage. It never accesses private keys directly.
 */

export class KMSClient {
  private iframe: HTMLIFrameElement | null = null
  private ready: Promise<void>
  private requestId = 0
  private pendingRequests = new Map<string, {
    resolve: (value: any) => void
    reject: (error: Error) => void
  }>()

  constructor() {
    this.ready = this.initialize()
  }

  private async initialize(): Promise<void> {
    // Create sandboxed iframe
    this.iframe = document.createElement('iframe')
    this.iframe.src = 'https://kms.ats.run/kms.html'

    // Sandbox: allow-scripts + allow-same-origin
    // Safe because enclave is cross-origin (kms.ats.run ≠ ats.run)
    this.iframe.sandbox.add('allow-scripts')
    this.iframe.sandbox.add('allow-same-origin')

    // Note: SRI doesn't work on iframes, only on <script> tags
    // SRI verification happens inside kms.html when loading the module
    this.iframe.style.display = 'none'

    // Set up message handler
    window.addEventListener('message', this.handleMessage.bind(this))

    // Append to DOM
    document.body.appendChild(this.iframe)

    // Wait for KMS ready signal
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error('KMS initialization timeout'))
      }, 5000)

      this.pendingRequests.set('init', {
        resolve: () => {
          clearTimeout(timeout)
          resolve()
        },
        reject
      })
    })
  }

  private handleMessage(event: MessageEvent): void {
    // Verify origin
    if (event.origin !== 'https://kms.ats.run') {
      console.warn('[KMS Client] Ignoring message from unexpected origin:', event.origin)
      return
    }

    const { requestId, type, data, error } = event.data

    // Handle ready signal
    if (type === 'ready') {
      const pending = this.pendingRequests.get('init')
      if (pending) {
        pending.resolve(null)
        this.pendingRequests.delete('init')
      }
      return
    }

    // Handle response
    const pending = this.pendingRequests.get(requestId)
    if (!pending) {
      console.warn('[KMS Client] Received response for unknown request:', requestId)
      return
    }

    if (error) {
      pending.reject(new Error(error))
    } else {
      pending.resolve(data)
    }

    this.pendingRequests.delete(requestId)
  }

  private async request<T>(type: string, payload: any): Promise<T> {
    await this.ready

    const requestId = `req-${++this.requestId}`

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(requestId, { resolve, reject })

      this.iframe!.contentWindow!.postMessage(
        { requestId, type, payload },
        'https://kms.ats.run'
      )

      // Timeout after 10 seconds
      setTimeout(() => {
        if (this.pendingRequests.has(requestId)) {
          this.pendingRequests.delete(requestId)
          reject(new Error(`KMS request timeout: ${type}`))
        }
      }, 10000)
    })
  }

  /**
   * Generate VAPID keypair for Web Push
   * Returns public key (private key stays in KMS)
   */
  async generateVAPID(): Promise<{ publicKey: string }> {
    return this.request('generateVAPID', {})
  }

  /**
   * Sign JWT token for relay authorization
   * @param payload JWT payload (aud, exp, relay_id, sub)
   * @returns Signed JWT token
   */
  async signJWT(payload: {
    aud: string
    exp: number
    relay_id: string
    sub: string
  }): Promise<{ jwt: string; expiresAt: number }> {
    return this.request('signJWT', payload)
  }

  /**
   * Reset VAPID key (hard revocation)
   * Generates new keypair, invalidates all existing JWT tokens
   */
  async resetVAPID(): Promise<{ publicKey: string }> {
    return this.request('resetVAPID', {})
  }

  /**
   * Export VAPID public key
   */
  async exportPublicKey(): Promise<{ publicKey: string }> {
    return this.request('exportPublicKey', {})
  }
}

// Singleton instance
export const kmsClient = new KMSClient()
```

## 2. KMS Enclave Main Thread (Iframe)

**File**: `packages/kms-enclave/src/main.ts`

```typescript
/**
 * KMS Enclave Main Thread
 *
 * Runs in sandboxed iframe, forwards requests to dedicated worker.
 * Performs runtime self-check at startup.
 */

import { KMSWorker } from './worker'

// Expected hash (pinned at build time)
const EXPECTED_HASH = 'a3f8b2d1c4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0'

// Runtime self-check
async function verifySelf(): Promise<void> {
  try {
    const response = await fetch(new URL(import.meta.url))
    const blob = await response.blob()
    const buffer = await blob.arrayBuffer()
    const hashBuffer = await crypto.subtle.digest('SHA-384', buffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')

    if (hashHex !== EXPECTED_HASH) {
      throw new Error(`KMS integrity check failed: expected ${EXPECTED_HASH}, got ${hashHex}`)
    }

    console.log('[KMS] ✅ Self-check passed: hash verified')
  } catch (error) {
    console.error('[KMS] ❌ FATAL: Self-check failed', error)
    throw error
  }
}

// Initialize worker
const worker = new Worker(new URL('./worker.ts', import.meta.url))

// Track pending worker requests
const pendingWorkerRequests = new Map<string, {
  resolve: (value: any) => void
  reject: (error: Error) => void
}>()

// Handle worker responses
worker.addEventListener('message', (event) => {
  const { requestId, data, error } = event.data

  const pending = pendingWorkerRequests.get(requestId)
  if (!pending) return

  if (error) {
    pending.reject(new Error(error))
  } else {
    pending.resolve(data)
  }

  pendingWorkerRequests.delete(requestId)
})

// Forward request to worker
async function forwardToWorker<T>(type: string, payload: any): Promise<T> {
  const requestId = `worker-${Date.now()}-${Math.random()}`

  return new Promise((resolve, reject) => {
    pendingWorkerRequests.set(requestId, { resolve, reject })

    worker.postMessage({ requestId, type, payload })

    // Timeout after 5 seconds
    setTimeout(() => {
      if (pendingWorkerRequests.has(requestId)) {
        pendingWorkerRequests.delete(requestId)
        reject(new Error(`Worker request timeout: ${type}`))
      }
    }, 5000)
  })
}

// Handle parent messages
window.addEventListener('message', async (event) => {
  // Verify origin (parent PWA)
  if (event.origin !== 'https://ats.run') {
    console.warn('[KMS] Ignoring message from unexpected origin:', event.origin)
    return
  }

  const { requestId, type, payload } = event.data

  try {
    let data: any

    switch (type) {
      case 'generateVAPID':
        data = await forwardToWorker('generateVAPID', payload)
        break

      case 'signJWT':
        data = await forwardToWorker('signJWT', payload)
        break

      case 'resetVAPID':
        data = await forwardToWorker('resetVAPID', payload)
        break

      case 'exportPublicKey':
        data = await forwardToWorker('exportPublicKey', payload)
        break

      default:
        throw new Error(`Unknown request type: ${type}`)
    }

    // Send success response
    // Use string targetOrigin for broad browser support
    event.source!.postMessage(
      { requestId, type, data },
      event.origin
    )
  } catch (error) {
    // Send error response
    event.source!.postMessage(
      { requestId, type, error: error.message },
      event.origin
    )
  }
})

// Startup sequence
async function startup(): Promise<void> {
  console.log('[KMS] Starting enclave...')

  // Runtime self-check
  await verifySelf()

  // Signal ready to parent
  window.parent.postMessage(
    { type: 'ready' },
    'https://ats.run'
  )

  console.log('[KMS] ✅ Enclave ready')
}

// Start
startup().catch((error) => {
  console.error('[KMS] ❌ FATAL: Startup failed', error)
  // Halt execution
  throw error
})
```

## 3. KMS Worker (Crypto Operations)

**File**: `packages/kms-enclave/src/worker.ts`

```typescript
/**
 * KMS Worker - Dedicated Worker for crypto operations
 *
 * Runs in separate thread, no DOM access, maximum isolation.
 * All keys stored here as non-extractable CryptoKey objects.
 */

import { openDB, DBSchema, IDBPDatabase } from 'idb'

// IndexedDB schema
interface KMSDatabase extends DBSchema {
  keys: {
    key: string
    value: {
      privateKey: CryptoKey  // Non-extractable
      publicKey: string      // Base64 SPKI format
      createdAt: number
    }
  }
}

let db: IDBPDatabase<KMSDatabase>

// Initialize IndexedDB
async function initDB(): Promise<void> {
  db = await openDB<KMSDatabase>('ats-kms', 1, {
    upgrade(db) {
      db.createObjectStore('keys')
    }
  })
}

// Generate VAPID keypair
async function generateVAPID(): Promise<{ publicKey: string }> {
  console.log('[KMS Worker] Generating VAPID keypair...')

  const keypair = await crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256'
    },
    false,  // NOT extractable - private key sealed
    ['sign', 'verify']
  )

  // Export raw public key (65 bytes: 0x04 + 32-byte x + 32-byte y)
  // This format is required by PushManager.subscribe()
  const rawPublicKey = await exportRawP256PublicKey(keypair.publicKey)
  const publicKeyBase64 = btoa(String.fromCharCode(...rawPublicKey))

  // Store keypair with raw public key as source of truth
  await db.put('keys', {
    privateKey: keypair.privateKey,  // CryptoKey (non-extractable)
    rawPublicKey: Array.from(rawPublicKey),  // 65-byte uncompressed point
    publicKeyBase64,  // Base64-encoded for convenience
    createdAt: Date.now()
  }, 'vapid_keypair')

  console.log('[KMS Worker] ✅ VAPID keypair generated (65-byte raw public key)')

  return { publicKey: publicKeyBase64 }
}

// Sign JWT token
async function signJWT(payload: {
  aud: string
  exp: number
  relay_id: string
  sub: string
}): Promise<{ jwt: string; expiresAt: number }> {
  console.log('[KMS Worker] Signing JWT for relay:', payload.relay_id)

  // Retrieve VAPID keypair
  const keypair = await db.get('keys', 'vapid_keypair')
  if (!keypair) {
    throw new Error('VAPID keypair not found - call generateVAPID first')
  }

  // Build JWT header and payload
  const header = {
    typ: 'JWT',
    alg: 'ES256'
  }

  const encodedHeader = base64url(JSON.stringify(header))
  const encodedPayload = base64url(JSON.stringify(payload))
  const message = `${encodedHeader}.${encodedPayload}`

  // Sign with private key (returns P-1363 format - 64 bytes for P-256)
  const messageBuffer = new TextEncoder().encode(message)
  const signature = await crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: 'SHA-256'
    },
    keypair.privateKey,  // Non-extractable CryptoKey
    messageBuffer
  )

  // WebCrypto returns P-1363 format, JWS ES256 requires P-1363 - no conversion needed
  const signatureBase64 = base64url(signature)
  const jwt = `${message}.${signatureBase64}`

  console.log('[KMS Worker] ✅ JWT signed')

  return {
    jwt,
    expiresAt: payload.exp
  }
}

// Reset VAPID keypair (hard revocation)
async function resetVAPID(): Promise<{ publicKey: string }> {
  console.log('[KMS Worker] Resetting VAPID keypair (hard revocation)...')

  // Delete old keypair
  await db.delete('keys', 'vapid_keypair')

  // Generate new keypair
  const result = await generateVAPID()

  console.log('[KMS Worker] ✅ VAPID keypair reset')

  return result
}

// Export public key
async function exportPublicKey(): Promise<{ publicKey: string }> {
  const keypair = await db.get('keys', 'vapid_keypair')
  if (!keypair) {
    throw new Error('VAPID keypair not found')
  }

  return { publicKey: keypair.publicKey }
}

// Base64url encoding
function base64url(data: string | ArrayBuffer): string {
  let base64: string
  if (typeof data === 'string') {
    base64 = btoa(data)
  } else {
    base64 = btoa(String.fromCharCode(...new Uint8Array(data)))
  }
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// Message handler
self.addEventListener('message', async (event) => {
  const { requestId, type, payload } = event.data

  try {
    let data: any

    switch (type) {
      case 'generateVAPID':
        data = await generateVAPID()
        break

      case 'signJWT':
        data = await signJWT(payload)
        break

      case 'resetVAPID':
        data = await resetVAPID()
        break

      case 'exportPublicKey':
        data = await exportPublicKey()
        break

      default:
        throw new Error(`Unknown worker operation: ${type}`)
    }

    self.postMessage({ requestId, data })
  } catch (error) {
    self.postMessage({ requestId, error: error.message })
  }
})

// Initialize database on startup
initDB().then(() => {
  console.log('[KMS Worker] ✅ IndexedDB initialized')
}).catch((error) => {
  console.error('[KMS Worker] ❌ FATAL: IndexedDB initialization failed', error)
})
```
