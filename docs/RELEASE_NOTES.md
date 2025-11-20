# Release Notes - xxss v1.4.0

## 🎉 Major Release: Enhanced Detection & Performance

This release brings significant improvements to XSS detection capabilities, performance optimizations, and critical bug fixes.

---

## ✨ New Features

### 🔍 Advanced Context Detection
Expanded from 6 to **10 context types** (+67% coverage):
- **Template Literals** (`` `${injection}` ``) - Critical for React/Vue/Angular apps
- **SVG Context** - Common in dashboards and visualizations  
- **Meta Refresh** - Important for legacy applications
- **Data URIs** - Content injection detection

### 🎯 Complete Blind XSS Support
- **POST Body Parameters**: Form-urlencoded and JSON support
- **GET Parameters**: Already supported
- **HTTP Headers**: Already supported
- Fire-and-forget with proper resource cleanup

### 🛡️ Advanced CSP Analysis
Detects bypassable CSP policies:
- `unsafe-inline` and `unsafe-eval`
- Wildcard sources (`*`)
- JSONP endpoints (googleapis.com, etc.)
- Bypassable CDNs (jsdelivr, unpkg, cdnjs)
- Missing `base-uri` directive

### ⚡ Performance Optimizations
- **+12% faster** in parallel scans
- **Dynamic connection pooling** that scales with concurrency
- **~20,000 requests/second** throughput
- **66KB/op** stable memory usage

### 🚦 Rate Limiting
- Token bucket algorithm
- Configurable requests/second
- Prevents server blocking/banning

---

## 🐛 Critical Bug Fixes

### Resource Leaks (Critical)
- Fixed goroutine leaks in all blind XSS functions
- Proper response body cleanup (3 locations)
- Added 10-second timeout to prevent hanging requests

### Data Integrity (Critical)
- Fixed incorrect JSON escaping in blind XSS payloads
- Now using proper `json.Marshal()` for safety
- Prevents malformed payloads and injection vulnerabilities

### API Updates (High Priority)
- Replaced deprecated `ioutil.ReadAll` with `io.ReadAll` (7 locations)
- Added input validation for blind URLs
- Improved error handling in JSON output

### Concurrency (Medium Priority)
- Fixed data races in blind XSS tests
- Added context cancellation (10s timeout)
- Thread-safe with `atomic.Bool`

---

## 📊 Performance Metrics

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| Throughput | ~17,500 ops/s | ~20,000 ops/s | +12% |
| Latency (parallel) | 183µs | 161µs | -12% |
| Memory | 66KB/op | 66KB/op | Stable |
| Context Coverage | 6 types | 10 types | +67% |

---

## 🧪 Testing

- **36/36 tests** passing ✅
- **0 data races** detected ✅
- **4 benchmarks** implemented ✅
- **100% critical bugs** fixed ✅

---

## 📝 Breaking Changes

### API Change
`network.NewClient` now returns two values:
```go
// Before (v1.3.2)
client := network.NewClient(timeout, proxy)

// After (v1.4.0)
client, rateLimiter := network.NewClient(timeout, proxy, concurrency, rateLimit)
```

**Migration**: Add `concurrency` and `rateLimit` parameters. Use `0` for rateLimit to disable.

---

## 🚀 Upgrade Guide

### Installation
```bash
go install github.com/lcalzada-xor/xxss@v1.4.0
```

### New Flags
```bash
-b, --blind string    Blind XSS callback URL
```

### Usage Example
```bash
# Blind XSS scanning
echo "https://example.com/?param=test" | xxss -b https://your-callback.com

# High concurrency with rate limiting
cat urls.txt | xxss -c 100 --rate-limit 50
```

---

## 📚 Documentation

- **CHANGELOG.md**: Full changelog
- **README.md**: Updated with new features
- **Bug Reports**: Comprehensive bug analysis available

---

## 🙏 Acknowledgments

This release includes contributions focusing on:
- Performance optimization
- Security improvements
- Code quality enhancements
- Comprehensive testing

---

## 📦 Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete details.

## 🔗 Links

- **GitHub**: https://github.com/lcalzada-xor/xxss
- **Issues**: https://github.com/lcalzada-xor/xxss/issues
- **Releases**: https://github.com/lcalzada-xor/xxss/releases/tag/v1.4.0
