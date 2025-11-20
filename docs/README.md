# Documentation

This directory contains all documentation for xxss.

## 📚 Documentation Structure

### Release Documentation
- **[RELEASE_NOTES.md](RELEASE_NOTES.md)** - Current release notes (v1.4.0)
- **[RELEASE_NOTES_v1.3.0.md](RELEASE_NOTES_v1.3.0.md)** - Previous release notes

### Project Documentation
See root directory:
- **[README.md](../README.md)** - Main project documentation
- **[CHANGELOG.md](../CHANGELOG.md)** - Version history
- **[CONTRIBUTING.md](../CONTRIBUTING.md)** - Contribution guidelines

## 🔍 Quick Links

### For Users
- [Installation](../README.md#installation)
- [Usage Examples](../README.md#usage)
- [Detected Contexts](../README.md#detected-contexts)
- [Latest Release Notes](RELEASE_NOTES.md)

### For Contributors
- [Contributing Guide](../CONTRIBUTING.md)
- [Development Setup](../CONTRIBUTING.md#development-setup)
- [Testing Guidelines](../CONTRIBUTING.md#testing-guidelines)
- [Code Style](../CONTRIBUTING.md#code-style)

### For Maintainers
- [Changelog](../CHANGELOG.md)
- [Release Process](../CONTRIBUTING.md#code-review-process)

## 📖 Additional Resources

### Technical Details
- **Context Detection**: See `scanner/context.go` for implementation
- **Blind XSS**: See `scanner/blind.go` for implementation
- **CSP Analysis**: See `scanner/security.go` for implementation
- **Rate Limiting**: See `network/ratelimiter.go` for implementation

### Testing
- **Test Suite**: See `tests/` directory
- **Benchmarks**: See `tests/benchmark_test.go`
- **CSP Tests**: See `tests/csp_test.go`
- **Context Tests**: See `tests/new_contexts_test.go`
