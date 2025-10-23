## Summary

Brief description of what this PR does.

## Related Issue

Closes #(issue number)

## Motivation

Why is this change needed? What problem does it solve?

## Implementation

How does this work? Explain key implementation details.

## Test-Driven Development

- [ ] Tests written FIRST before implementation
- [ ] All tests pass
- [ ] 100% code coverage maintained

## Test Coverage

```
Coverage summary (paste from `pnpm test:coverage`):
Lines   : 100%
Branches: 100%
Functions: 100%
Statements: 100%
```

## Security Impact

- [ ] This PR maintains all existing security guarantees
- [ ] This PR enhances security
- [ ] This PR has no security implications
- [ ] This PR affects security boundaries (requires security review)

## Architecture Changes

- [ ] No architecture changes
- [ ] Architecture docs updated in: `docs/architecture/crypto/...`
- [ ] CLAUDE.md updated (if workflow changes)

## Breaking Changes

- [ ] No breaking changes
- [ ] Breaking changes (describe below)

**Breaking changes description**: N/A

## Checklist

### Code Quality
- [ ] Tests written first (TDD methodology)
- [ ] All tests pass locally
- [ ] Coverage is 100% (no exceptions)
- [ ] Code follows existing patterns
- [ ] TypeScript strict mode passes
- [ ] Linting passes (`pnpm lint`)

### Documentation
- [ ] Code is well-commented
- [ ] Architecture docs updated (if needed)
- [ ] README updated (if needed)
- [ ] API changes documented

### Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated (if applicable)
- [ ] Edge cases tested
- [ ] Error paths tested
- [ ] Browser compatibility tested (if applicable)

### Security
- [ ] Origin checks maintained
- [ ] Isolation boundaries preserved
- [ ] Non-extractable keys protected
- [ ] Fail-secure on errors
- [ ] No key exfiltration paths

### Build
- [ ] Reproducible build succeeds
- [ ] No new dependencies (or justified if added)
- [ ] Build artifacts are deterministic

## Screenshots / Recordings

If applicable, add screenshots or recordings.

## Additional Notes

Any other information that reviewers should know.

---

**Reviewer Notes**:
- Review tests before reviewing implementation
- Verify 100% coverage maintained
- Check security implications
- Validate architecture docs updated
