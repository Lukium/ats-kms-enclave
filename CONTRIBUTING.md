# Contributing to ATS KMS Enclave

Thank you for your interest in contributing to the AllTheServices KMS Enclave! This is a security-critical project, and we welcome contributions that help improve its security, verifiability, and maintainability.

## Code of Conduct

Be respectful, professional, and constructive. This project serves real users whose security depends on the quality of this code.

## Before You Contribute

### Read the Documentation

1. **[CLAUDE.md](CLAUDE.md)** - Development guidance
2. **[docs/architecture/crypto/README.md](docs/architecture/crypto/README.md)** - Architecture overview
3. **[docs/architecture/crypto/design/](docs/architecture/crypto/design/)** - Detailed design
4. **[docs/architecture/crypto/plan.md](docs/architecture/crypto/plan.md)** - Implementation plan

### Understand the Security Model

This project implements defense-in-depth security with multiple independent layers. Any changes must maintain or improve security guarantees.

Read: [Security Model](docs/architecture/crypto/design/05-security-model.md)

## Development Methodology: Test-Driven Development (TDD)

**CRITICAL**: This project requires strict TDD with 100% code coverage.

### TDD Workflow

1. **Write failing test first** (RED)
   ```bash
   # Write test that defines expected behavior
   pnpm test
   # Test should fail
   ```

2. **Write minimal code to pass** (GREEN)
   ```bash
   # Implement just enough to pass the test
   pnpm test
   # Test should pass
   ```

3. **Refactor while keeping tests green** (REFACTOR)
   ```bash
   # Improve code quality
   pnpm test
   # All tests still pass
   ```

4. **Verify coverage**
   ```bash
   pnpm test:coverage
   # Must be 100%
   ```

### Coverage Requirements

- **100% line coverage** - Every line executed
- **100% branch coverage** - Every conditional path tested
- **100% function coverage** - Every function called
- **100% statement coverage** - Every statement executed

**No exceptions.** Code without tests cannot be merged.

## Contributing Workflow

### 1. Create an Issue

Before starting work:
- Search existing issues to avoid duplicates
- Create a new issue describing the change
- Wait for maintainer feedback before starting implementation

### 2. Fork and Clone

```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/ats-kms-enclave
cd ats-kms-enclave
git remote add upstream https://github.com/Lukium/ats-kms-enclave
```

### 3. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

Branch naming:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `test/` - Test improvements
- `refactor/` - Code refactoring

### 4. Write Tests First

```bash
# Create test file
touch tests/unit/your-feature.test.ts

# Write tests that define expected behavior
# Tests should fail initially
pnpm test
```

### 5. Implement Feature

Write minimal code to make tests pass:

```bash
# Implement feature
pnpm test
# Verify all tests pass
```

### 6. Verify Coverage

```bash
# Run coverage report
pnpm test:coverage

# Must show 100% coverage
# CI will block merge if coverage < 100%
```

### 7. Run Linting and Type Checks

```bash
# Lint code
pnpm lint

# Type check
pnpm typecheck

# Fix auto-fixable issues
pnpm lint:fix
```

### 8. Commit Changes

Use conventional commit format:

```bash
git commit -m "feat: add VAPID key generation"
git commit -m "fix: correct DER to P-1363 conversion"
git commit -m "docs: update security model"
git commit -m "test: add edge cases for JWT signing"
```

Commit types:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation
- `test:` - Test changes
- `refactor:` - Code refactoring
- `perf:` - Performance improvement
- `chore:` - Build/tooling changes

### 9. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Pull Request Guidelines

### PR Title

Use conventional commit format:
```
feat: add VAPID key generation
fix: correct signature format conversion
docs: update implementation guide
```

### PR Description

Include:
1. **What** - What does this PR do?
2. **Why** - Why is this change needed?
3. **How** - How does it work?
4. **Tests** - What tests were added?
5. **Coverage** - Screenshot of 100% coverage

Template:
```markdown
## Summary
Brief description of changes

## Motivation
Why is this change needed?

## Implementation
How does it work?

## Tests
- [ ] Unit tests added
- [ ] Integration tests added
- [ ] 100% coverage maintained

## Checklist
- [ ] Tests written first (TDD)
- [ ] All tests pass
- [ ] Coverage is 100%
- [ ] Linting passes
- [ ] Type checks pass
- [ ] Documentation updated
- [ ] Architecture docs updated (if needed)
```

### Code Review Process

1. **Automated checks** - CI must pass (tests, coverage, linting)
2. **Test review** - Tests reviewed before implementation
3. **Security review** - Security implications assessed
4. **Code review** - Implementation reviewed for quality
5. **Approval** - At least one maintainer approval required

## Types of Contributions

### 🐛 Bug Fixes

1. Create issue with bug report
2. Write test that reproduces bug (fails)
3. Fix bug (test passes)
4. Submit PR with test + fix

### ✨ New Features

1. Discuss in issue first
2. Update architecture docs if needed
3. Write comprehensive test suite
4. Implement feature
5. Update documentation

### 📚 Documentation

1. Architecture changes → Update `docs/architecture/crypto/`
2. API changes → Update relevant design docs
3. User-facing changes → Update README.md

### 🧪 Tests

Adding tests without changing implementation:
1. Identify untested code path (shouldn't exist!)
2. Add test coverage
3. Ensure existing behavior maintained

### 🔒 Security Improvements

1. **Discuss privately first** - Email security@ats.run
2. Create private security advisory on GitHub
3. Collaborate on fix
4. Public disclosure after fix

## Architecture Changes

Changes affecting architecture must:

1. **Propose change** in architecture docs first
2. **Validate against security principles**:
   - Verifiability - Can users audit?
   - Isolation - Are boundaries maintained?
   - Fail-secure - Do errors halt execution?
3. **Update affected design documents**
4. **Get security review** if changing isolation boundaries
5. **Update CLAUDE.md** if workflow changes

## What Gets Reviewed

### Test Quality
- Tests written before implementation?
- Tests clear and descriptive?
- Success and failure cases covered?
- Edge cases tested?
- 100% coverage achieved?

### Code Quality
- Simple and auditable?
- Follows existing patterns?
- Type-safe (TypeScript strict mode)?
- Well-commented for security-critical sections?
- No unnecessary dependencies?

### Security
- Maintains isolation boundaries?
- Fail-secure on errors?
- No key exfiltration paths?
- Origin checks correct?
- Timing-safe operations?

### Documentation
- Architecture docs updated?
- API documentation clear?
- Security implications documented?
- User-facing changes explained?

## Common Pitfalls

### ❌ Don't

- ❌ Write code before tests
- ❌ Skip coverage checks
- ❌ Add dependencies without discussion
- ❌ Change security boundaries without review
- ❌ Merge with failing tests
- ❌ Use `/* istanbul ignore */` to skip coverage
- ❌ Make architecture changes without updating docs

### ✅ Do

- ✅ Write tests first (TDD)
- ✅ Maintain 100% coverage
- ✅ Keep codebase simple
- ✅ Document security decisions
- ✅ Ask questions early
- ✅ Update architecture docs
- ✅ Verify reproducible builds

## Getting Help

- **Questions**: Open a discussion on GitHub
- **Bugs**: Create an issue with reproduction steps
- **Security**: Email security@ats.run (private)
- **Architecture**: Reference design docs, ask in issue

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in security advisories (if applicable)

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make the ATS KMS Enclave more secure and verifiable! 🔐
