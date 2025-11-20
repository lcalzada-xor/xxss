# Contributing to xxss

Thank you for your interest in contributing to xxss! This document provides guidelines and instructions for contributing.

## 🚀 Quick Start

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/xxss.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `go test -v ./tests/...`
6. Commit: `git commit -m "feat: your feature description"`
7. Push: `git push origin feature/your-feature-name`
8. Create a Pull Request

## 📋 Development Setup

### Prerequisites
- Go 1.21 or higher
- Git

### Building
```bash
go build -o xxss .
```

### Running Tests
```bash
# All tests
go test -v ./tests/...

# With race detection
go test -race ./tests/...

# Benchmarks
go test -bench=. -benchmem ./tests/benchmark_test.go
```

## 🎯 Code Style

- Follow standard Go conventions
- Use `gofmt` for formatting
- Add comments for exported functions
- Keep functions focused and small
- Write tests for new features

## 🧪 Testing Guidelines

### Writing Tests
- Place tests in `tests/` directory
- Use descriptive test names: `TestFeature_Scenario`
- Include both positive and negative test cases
- Use `httptest` for HTTP mocking

### Test Coverage
- Aim for >80% coverage on new code
- Test edge cases and error conditions
- Include integration tests for new features

## 📝 Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions/changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Maintenance tasks

Examples:
```
feat: add SVG context detection
fix: goroutine leak in blind XSS
docs: update README with new flags
test: add CSP bypass detection tests
```

## 🐛 Reporting Bugs

### Before Reporting
- Check existing issues
- Verify it's reproducible
- Test with latest version

### Bug Report Template
```markdown
**Description**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Run command: `xxss ...`
2. Expected: ...
3. Actual: ...

**Environment**
- xxss version: 
- Go version: 
- OS: 

**Additional Context**
Any other relevant information
```

## ✨ Feature Requests

### Feature Request Template
```markdown
**Problem**
What problem does this solve?

**Proposed Solution**
How should it work?

**Alternatives**
Other approaches considered

**Additional Context**
Examples, mockups, etc.
```

## 🔍 Code Review Process

1. **Automated Checks**: All tests must pass
2. **Code Review**: Maintainer review required
3. **Documentation**: Update docs if needed
4. **Changelog**: Add entry to CHANGELOG.md

## 📚 Project Structure

```
xxss/
├── main.go           # CLI entry point
├── models/           # Data models
├── network/          # HTTP client & rate limiting
├── scanner/          # Core scanning logic
│   ├── scanner.go    # GET scanning
│   ├── scanner_post.go # POST/PUT/PATCH scanning
│   ├── blind.go      # Blind XSS
│   ├── context.go    # Context detection
│   ├── analyzer.go   # Response analysis
│   ├── security.go   # Security headers
│   └── polyglots.go  # XSS payloads
└── tests/            # Test suite
```

## 🎨 Adding New Features

### New Context Type
1. Add constant to `models/result.go`
2. Implement detection in `scanner/context.go`
3. Add payloads to `scanner/polyglots.go`
4. Add tests to `tests/new_contexts_test.go`

### New Scanning Method
1. Add function to appropriate scanner file
2. Update `Scanner` struct if needed
3. Add CLI flag in `main.go`
4. Write comprehensive tests
5. Update README.md

## 🔒 Security

### Reporting Security Issues
**DO NOT** open public issues for security vulnerabilities.

Contact: [Create a private security advisory on GitHub]

### Security Considerations
- Validate all user inputs
- Avoid arbitrary code execution
- Sanitize outputs
- Use secure defaults

## 📄 License

By contributing, you agree that your contributions will be licensed under the MIT License.

## 💬 Questions?

- Open a [Discussion](https://github.com/lcalzada-xor/xxss/discussions)
- Check existing [Issues](https://github.com/lcalzada-xor/xxss/issues)

## 🙏 Thank You!

Every contribution helps make xxss better for everyone!
