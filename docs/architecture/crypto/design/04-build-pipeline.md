# Reproducible Build Pipeline

## Build Configuration

**File**: `packages/kms-enclave/esbuild.config.js`

```javascript
const esbuild = require('esbuild')
const crypto = require('crypto')
const fs = require('fs')

// Deterministic build settings
const buildConfig = {
  entryPoints: ['src/main.ts'],
  bundle: true,
  outfile: 'dist/kms.js',
  format: 'esm',
  target: 'es2020',
  minify: true,
  sourcemap: false,  // No sourcemaps for deterministic output
  banner: {
    js: `// AllTheServices KMS Enclave\n// Build: ${process.env.SOURCE_DATE_EPOCH || Date.now()}\n`
  },
  define: {
    'process.env.NODE_ENV': '"production"'
  },
  treeShaking: true,
  legalComments: 'none',
  charset: 'utf8'
}

async function build() {
  // Build bundle
  const result = await esbuild.build(buildConfig)

  // Read built file
  const bundle = fs.readFileSync('dist/kms.js')

  // Compute SHA-384 hash
  const hash = crypto.createHash('sha384').update(bundle).digest('hex')

  // Rename to content-addressed filename
  const hashedFilename = `kms-${hash.slice(0, 8)}.js`
  fs.renameSync('dist/kms.js', `dist/${hashedFilename}`)

  // Generate SRI hash
  const sriHash = `sha384-${crypto.createHash('sha384').update(bundle).digest('base64')}`

  // Write manifest
  fs.writeFileSync('dist/manifest.json', JSON.stringify({
    filename: hashedFilename,
    hash: hash,
    sri: sriHash,
    timestamp: process.env.SOURCE_DATE_EPOCH || Date.now(),
    version: process.env.npm_package_version
  }, null, 2))

  console.log(`✅ Built ${hashedFilename}`)
  console.log(`   Hash: ${hash}`)
  console.log(`   SRI: ${sriHash}`)
}

build().catch(console.error)
```

## Reproducible Build Script

**File**: `packages/kms-enclave/scripts/reproducible-build.sh`

```bash
#!/bin/bash
set -euo pipefail

# Reproducible build script
# Outputs deterministic artifacts that anyone can verify

echo "🔨 AllTheServices KMS Enclave - Reproducible Build"
echo ""

# Check clean working directory
if [ -n "$(git status --porcelain)" ]; then
  echo "❌ Error: Working directory not clean"
  echo "   Commit or stash changes before building"
  exit 1
fi

# Get current commit
COMMIT=$(git rev-parse HEAD)
echo "📌 Commit: $COMMIT"

# Set deterministic timestamp (commit time)
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
echo "🕐 Timestamp: $SOURCE_DATE_EPOCH ($(date -d @$SOURCE_DATE_EPOCH))"

# Clean previous build
rm -rf dist/
mkdir -p dist/

# Install dependencies (from lockfile)
echo ""
echo "📦 Installing dependencies..."
pnpm install --frozen-lockfile

# Build
echo ""
echo "🔨 Building KMS enclave..."
node esbuild.config.js

# Build worker separately
echo ""
echo "🔨 Building KMS worker..."
node esbuild.config.worker.js

# Generate combined manifest
echo ""
echo "📝 Generating manifest..."
node scripts/generate-manifest.js

echo ""
echo "✅ Reproducible build complete!"
echo ""
echo "Output files:"
ls -lh dist/
echo ""
echo "🔍 Verify build:"
echo "   1. Other developers can run this script and get identical output"
echo "   2. Check dist/manifest.json for SRI hashes"
echo "   3. Sign with: cosign sign-blob dist/kms-*.js"
```

## Transparency Log Integration

**File**: `packages/kms-enclave/scripts/publish-release.sh`

```bash
#!/bin/bash
set -euo pipefail

# Publish KMS release to transparency log (Sigstore)

VERSION=$1
if [ -z "$VERSION" ]; then
  echo "Usage: $0 <version>"
  exit 1
fi

echo "📦 Publishing KMS Enclave v$VERSION to transparency log"
echo ""

# Build reproducibly
./scripts/reproducible-build.sh

# Sign with Sigstore (requires cosign)
echo ""
echo "🔐 Signing with Sigstore..."

for file in dist/kms-*.js; do
  echo "   Signing $file..."
  cosign sign-blob \
    --bundle "$file.bundle" \
    "$file"
done

echo ""
echo "✅ Release signed and published to Rekor transparency log"
echo ""
echo "🔍 Verify with:"
echo "   cosign verify-blob --bundle dist/kms-*.js.bundle dist/kms-*.js"
echo ""
echo "📤 Next steps:"
echo "   1. Upload dist/* to kms.ats.run"
echo "   2. Update main PWA with new SRI hash"
echo "   3. Tag release: git tag kms-v$VERSION"
echo "   4. Push tag: git push origin kms-v$VERSION"
```
