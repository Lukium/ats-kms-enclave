# Security Policy

## Reporting Security Vulnerabilities

**Please DO NOT report security vulnerabilities through public GitHub issues.**

### Private Reporting

Email security concerns to: **security@ats.run**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will respond within **48 hours** and work with you to:
1. Confirm the vulnerability
2. Develop a fix
3. Test the fix
4. Coordinate disclosure

### Security Advisories

For confirmed vulnerabilities, we will:
- Create a private GitHub Security Advisory
- Collaborate with you on the fix
- Credit you in the advisory (unless you prefer to remain anonymous)
- Coordinate public disclosure after fix is deployed

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| < 1.0   | :x: (not yet released) |

Once releases begin, we will maintain security support for:
- Latest major version
- Previous major version (for 6 months)

## Security Model

### What We Protect Against

✅ **Threats we defend against**:
- Malicious PWA updates
- CDN compromise
- Supply chain attacks
- MITM attacks
- Service Worker tampering
- Key exfiltration attempts

See [Security Model](docs/architecture/crypto/design/05-security-model.md) for details.

### What We Cannot Protect Against

❌ **Threats outside our control**:
- Malicious browser extensions
- Compromised operating system
- Physical device access
- Browser implementation bugs (0-days)
- Hardware backdoors

Users must:
- Keep browsers updated
- Secure their devices
- Only install trusted extensions
- Protect physical access to devices

## Security Features

### Verifiable Integrity

Users can verify the KMS enclave integrity:

1. **Hash Display**: Enclave hash displayed in PWA
2. **Manifest Verification**: Compare against published manifest
3. **Reproducible Builds**: Anyone can rebuild and verify
4. **Transparency Logs**: All releases in Sigstore/Rekor

### Isolation Boundaries

Multiple independent security layers:

1. **Cross-origin isolation** - `kms.ats.run` ≠ `allthe.services`
2. **Sandboxed iframe** - Restricted capabilities
3. **Dedicated Worker** - No DOM access
4. **Non-extractable keys** - Browser-enforced
5. **SRI verification** - Hash validation
6. **Runtime self-check** - Integrity verification

### Security Headers

Strict CSP and security headers:
- `frame-ancestors` - Only official PWA can embed
- `connect-src 'self'` - No external network access
- All device permissions denied

## Security Best Practices

### For Users

1. **Verify enclave hash** - Use the "Verify" button in PWA
2. **Keep browser updated** - Latest Chrome/Firefox/Safari
3. **Secure your device** - Strong passwords, encryption
4. **Review extensions** - Only install trusted extensions
5. **Report issues** - Email security@ats.run if suspicious

### For Developers

1. **Follow TDD** - 100% test coverage catches bugs
2. **Review security model** - Understand isolation boundaries
3. **Test error paths** - Ensure fail-secure behavior
4. **Verify origin checks** - All postMessage communication
5. **Check reproducibility** - Builds must be deterministic

## Vulnerability Disclosure Process

### Timeline

1. **T+0**: Report received
2. **T+48h**: Initial response
3. **T+7d**: Vulnerability confirmed/rejected
4. **T+30d**: Fix developed and tested
5. **T+45d**: Fix deployed
6. **T+60d**: Public disclosure

We aim to fix critical vulnerabilities within 30 days of confirmation.

### Credit

Security researchers who responsibly disclose vulnerabilities will be:
- Credited in security advisory
- Listed in SECURITY_HALL_OF_FAME.md
- Thanked in release notes

## Security Audits

### Planned Audits

- [ ] Independent security audit (post-implementation)
- [ ] Community security review (ongoing)
- [ ] Reproducible build verification (automated)

### Past Audits

None yet (project in design phase).

## Security Contact

**Email**: security@ats.run

**PGP Key**: (To be added when project is public)

**Response Time**: Within 48 hours

## Resources

- [Security Model](docs/architecture/crypto/design/05-security-model.md)
- [Architecture Overview](docs/architecture/crypto/README.md)
- [Verification Guide](docs/architecture/crypto/design/06-implementation-guide.md)
- [Threat Model](docs/architecture/crypto/design/05-security-model.md#threat-model)

## Updates

This security policy will be updated as the project evolves. Check back regularly for updates.

---

**Last Updated**: 2025-01-23
