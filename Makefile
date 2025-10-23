.PHONY: help install test typecheck lint pre-commit clean

# Default target - show help
help:
	@echo "ATS KMS Enclave - Development Commands"
	@echo ""
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  help        Show this help message"
	@echo "  install     Install dependencies"
	@echo "  test        Run all tests"
	@echo "  typecheck   Run TypeScript type checking"
	@echo "  lint        Run ESLint"
	@echo "  pre-commit  Run all pre-commit checks (test + typecheck + lint)"
	@echo "  clean       Remove generated files"
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

# Run TypeScript type checking
typecheck:
	@echo "🔍 Type checking..."
	pnpm typecheck

# Run linter
lint:
	@echo "✨ Linting..."
	pnpm lint

# Run all pre-commit checks
pre-commit: test typecheck lint
	@echo ""
	@echo "✅ All pre-commit checks passed!"
	@echo "Ready to commit 🚀"

# Clean generated files
clean:
	@echo "🧹 Cleaning..."
	rm -rf node_modules
	rm -rf dist
	rm -rf coverage
	rm -rf .vitest
	@echo "✨ Clean complete"
