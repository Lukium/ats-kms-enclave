.PHONY: help install test test-coverage test-coverage-lines typecheck lint pre-commit clean demo demo-phase-0 demo-phase-1

# Default target - show help
help:
	@echo "ATS KMS Enclave - Development Commands"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  help           Show this help message"
	@echo "  install        Install dependencies"
	@echo "  test                   Run all tests"
	@echo "  test-coverage          Run tests with 80% coverage enforcement (V2 only)"
	@echo "  test-coverage-lines    Run tests with coverage + line counts"
	@echo "  typecheck              Run TypeScript type checking"
	@echo "  lint           Run ESLint"
	@echo "  pre-commit     Run all pre-commit checks (test-coverage + typecheck + lint)"
	@echo "  demo           Run latest demo (currently Phase 1)"
	@echo "  demo-phase-0   Run Phase 0 demo in browser"
	@echo "  demo-phase-1   Run Phase 1 demo in browser"
	@echo "  clean          Remove generated files"
	@echo ""
	@echo "Pre-commit workflow:"
	@echo "  1. make pre-commit"
	@echo "  2. Fix any errors"
	@echo "  3. git commit"

# Install dependencies
install:
	@echo "📦 Installing dependencies..."
	pnpm install

# Run tests (V2 only - configured in vitest.config.ts)
test:
	@echo "🧪 Running tests (V2 only)..."
	@echo "   Tests: tests/v2/**/*.test.ts"
	@echo "   Coverage: src/v2/**/*.ts"
	pnpm test

# Run tests with coverage (V2 only)
test-coverage:
	@echo "🎯 Running tests with coverage (V2 only)..."
	@echo "   Tests: tests/v2/**/*.test.ts"
	@echo "   Coverage: src/v2/**/*.ts"
	@echo "   Threshold: 80% (lines, functions, branches, statements)"
	pnpm test:coverage

# Run tests with coverage + line counts (V2 only)
test-coverage-lines:
	@echo "📊 Running tests with coverage and line counts (V2 only)..."
	@echo "   Tests: tests/v2/**/*.test.ts"
	@echo "   Coverage: src/v2/**/*.ts"
	@echo "   Threshold: 80% (lines, functions, branches, statements)"
	pnpm test:coverage:lines

# Run TypeScript type checking
typecheck:
	@echo "🔍 Type checking..."
	pnpm typecheck

# Run linter
lint:
	@echo "✨ Linting..."
	pnpm lint

# Run all pre-commit checks
pre-commit: test-coverage-lines typecheck lint
	@echo ""
	@echo "📝 Updating README.md with test stats..."
	@pnpm update:readme
	@echo ""
	@echo "✅ All pre-commit checks passed!"
	@echo "✅ 80% test coverage verified (V2 only)!"
	@echo "✅ README.md updated!"
	@echo "Ready to commit 🚀"

# Run latest demo (alias to current phase)
demo: demo-phase-1

# Run Phase 0 demo in browser
demo-phase-0:
	@echo "🚀 Starting Phase 0 demo..."
	@echo "Opening http://localhost:5173"
	pnpm demo:phase-0

# Run Phase 1 demo in browser
demo-phase-1:
	@echo "🚀 Phase 1 Demo requires two terminals:"
	@echo ""
	@echo "Terminal 1 (KMS enclave):"
	@echo "  pnpm demo:phase-1:kms"
	@echo "  → http://localhost:5174"
	@echo ""
	@echo "Terminal 2 (Parent PWA):"
	@echo "  pnpm demo:phase-1:parent"
	@echo "  → http://localhost:5173"
	@echo ""
	@echo "Then open http://localhost:5173 in your browser"
	@echo ""
	@echo "See example/phase-1/README.md for full details"

# Clean generated files
clean:
	@echo "🧹 Cleaning..."
	rm -rf node_modules
	rm -rf dist
	rm -rf coverage
	rm -rf .vitest
	@echo "✨ Clean complete"
