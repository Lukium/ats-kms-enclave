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
	@echo "  test-coverage          Run tests with 100% coverage enforcement"
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

# Run tests
test:
	@echo "🧪 Running tests..."
	pnpm test

# Run tests with coverage
test-coverage:
	@echo "🎯 Running tests with coverage..."
	pnpm test:coverage

# Run tests with coverage + line counts
test-coverage-lines:
	@echo "📊 Running tests with coverage and line counts..."
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
	@echo "✅ 100% test coverage verified!"
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
	@echo "🚀 Starting Phase 1 demo..."
	@echo "Opening http://localhost:5174"
	pnpm demo:phase-1

# Clean generated files
clean:
	@echo "🧹 Cleaning..."
	rm -rf node_modules
	rm -rf dist
	rm -rf coverage
	rm -rf .vitest
	@echo "✨ Clean complete"
