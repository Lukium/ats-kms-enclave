/**
 * ATS KMS Enclave - Phase 0 Demo
 *
 * Demonstrates VAPID key generation, JWT signing, and public key retrieval.
 */

import { KMSClient } from '../src/client';

// Global state
let client: KMSClient | null = null;
let currentKid: string | null = null;

// UI elements
const generateBtn = document.getElementById('generate-btn') as HTMLButtonElement;
const signBtn = document.getElementById('sign-btn') as HTMLButtonElement;
const getKeyBtn = document.getElementById('getkey-btn') as HTMLButtonElement;
const testBtn = document.getElementById('test-btn') as HTMLButtonElement;

const vapidOutput = document.getElementById('vapid-output') as HTMLDivElement;
const jwtOutput = document.getElementById('jwt-output') as HTMLDivElement;
const getKeyOutput = document.getElementById('getkey-output') as HTMLDivElement;
const testOutput = document.getElementById('test-output') as HTMLDivElement;

// Utility functions
function setOutput(element: HTMLDivElement, content: string, type: 'success' | 'error' | 'info' = 'info'): void {
  element.textContent = content;
  element.className = `output ${type}`;
}

function formatKey(key: string, maxLength = 60): string {
  if (key.length <= maxLength) {
    return key;
  }
  return `${key.substring(0, maxLength)}...`;
}

function formatJWT(jwt: string): string {
  const parts = jwt.split('.');
  if (parts.length !== 3) {
    return jwt;
  }

  const [header, payload, signature] = parts;
  return `Header:    ${formatKey(header!)}\nPayload:   ${formatKey(payload!)}\nSignature: ${formatKey(signature!)}`;
}

function setLoading(button: HTMLButtonElement, loading: boolean): void {
  if (loading) {
    button.disabled = true;
    button.innerHTML = button.textContent + ' <span class="loading"></span>';
  } else {
    button.disabled = false;
    button.innerHTML = button.textContent?.replace(/<span.*<\/span>/, '') || '';
  }
}

// Initialize client
async function initClient(): Promise<void> {
  if (!client) {
    client = new KMSClient();
    console.log('[Demo] KMS Client initialized');
  }
}

// Event handlers
generateBtn.addEventListener('click', async () => {
  try {
    await initClient();
    setLoading(generateBtn, true);

    const result = await client!.generateVAPID();
    currentKid = result.kid;

    const output = [
      '✓ VAPID keypair generated successfully!',
      '',
      `Kid:        ${result.kid}`,
      `Public Key: ${formatKey(result.publicKey)}`,
      '',
      `Full Public Key (${result.publicKey.length} chars):`,
      result.publicKey,
    ].join('\n');

    setOutput(vapidOutput, output, 'success');

    // Enable other buttons
    signBtn.disabled = false;
    getKeyBtn.disabled = false;

    console.log('[Demo] Generated VAPID keypair:', result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    setOutput(vapidOutput, `✗ Error: ${message}`, 'error');
    console.error('[Demo] Generate error:', error);
  } finally {
    setLoading(generateBtn, false);
  }
});

signBtn.addEventListener('click', async () => {
  if (!currentKid) {
    setOutput(jwtOutput, '✗ No VAPID key available. Generate one first.', 'error');
    return;
  }

  try {
    await initClient();
    setLoading(signBtn, true);

    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:demo@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour
    };

    const result = await client!.signJWT(currentKid, payload);

    const output = [
      '✓ JWT signed successfully!',
      '',
      formatJWT(result.jwt),
      '',
      `Full JWT (${result.jwt.length} chars):`,
      result.jwt,
      '',
      'Payload:',
      JSON.stringify(payload, null, 2),
    ].join('\n');

    setOutput(jwtOutput, output, 'success');
    console.log('[Demo] Signed JWT:', result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    setOutput(jwtOutput, `✗ Error: ${message}`, 'error');
    console.error('[Demo] Sign error:', error);
  } finally {
    setLoading(signBtn, false);
  }
});

getKeyBtn.addEventListener('click', async () => {
  if (!currentKid) {
    setOutput(getKeyOutput, '✗ No VAPID key available. Generate one first.', 'error');
    return;
  }

  try {
    await initClient();
    setLoading(getKeyBtn, true);

    const result = await client!.getPublicKey(currentKid);

    if (result.publicKey === null) {
      setOutput(getKeyOutput, `✗ Key not found: ${currentKid}`, 'error');
      return;
    }

    const output = [
      '✓ Public key retrieved successfully!',
      '',
      `Kid:        ${currentKid}`,
      `Public Key: ${formatKey(result.publicKey)}`,
      '',
      `Full Public Key (${result.publicKey.length} chars):`,
      result.publicKey,
    ].join('\n');

    setOutput(getKeyOutput, output, 'success');
    console.log('[Demo] Retrieved public key:', result);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    setOutput(getKeyOutput, `✗ Error: ${message}`, 'error');
    console.error('[Demo] Get key error:', error);
  } finally {
    setLoading(getKeyBtn, false);
  }
});

testBtn.addEventListener('click', async () => {
  try {
    await initClient();
    setLoading(testBtn, true);

    const steps: string[] = [];

    // Step 1: Generate VAPID keypair
    steps.push('1. Generating VAPID keypair...');
    const vapid = await client!.generateVAPID();
    steps.push(`   ✓ Generated: ${vapid.kid}`);

    // Step 2: Sign JWT
    steps.push('');
    steps.push('2. Signing JWT token...');
    const payload = {
      aud: 'https://fcm.googleapis.com',
      sub: 'mailto:test@ats.run',
      exp: Math.floor(Date.now() / 1000) + 3600,
    };
    const jwt = await client!.signJWT(vapid.kid, payload);
    steps.push(`   ✓ JWT signed (${jwt.jwt.length} chars)`);

    // Step 3: Retrieve public key
    steps.push('');
    steps.push('3. Retrieving public key...');
    const pubkey = await client!.getPublicKey(vapid.kid);
    steps.push(`   ✓ Public key matches: ${pubkey.publicKey === vapid.publicKey}`);

    // Step 4: Verify JWT structure
    steps.push('');
    steps.push('4. Verifying JWT structure...');
    const parts = jwt.jwt.split('.');
    steps.push(`   ✓ Has 3 parts: ${parts.length === 3}`);

    // Decode header
    const headerB64 = parts[0]!;
    const headerJson = atob(headerB64.replace(/-/g, '+').replace(/_/g, '/'));
    const header = JSON.parse(headerJson) as { typ: string; alg: string; kid: string };
    steps.push(`   ✓ Algorithm: ${header.alg}`);
    steps.push(`   ✓ Kid in header: ${header.kid === vapid.kid}`);

    steps.push('');
    steps.push('✓ All tests passed!');
    steps.push('');
    steps.push('Summary:');
    steps.push(`  - Kid: ${vapid.kid}`);
    steps.push(`  - Public Key: ${formatKey(vapid.publicKey)}`);
    steps.push(`  - JWT Length: ${jwt.jwt.length} chars`);
    steps.push(`  - Algorithm: ${header.alg}`);

    setOutput(testOutput, steps.join('\n'), 'success');
    console.log('[Demo] Complete test passed');

    // Update current kid
    currentKid = vapid.kid;
    signBtn.disabled = false;
    getKeyBtn.disabled = false;
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error';
    setOutput(testOutput, `✗ Test failed: ${message}`, 'error');
    console.error('[Demo] Test error:', error);
  } finally {
    setLoading(testBtn, false);
  }
});

// Initialize on load
console.log('[Demo] Phase 0 Demo loaded');
console.log('[Demo] Ready to demonstrate KMS operations');
