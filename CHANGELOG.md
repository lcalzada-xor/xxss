# Changelog

All notable changes to this project will be documented in this file.

## [v2.4.0] - 2025-11-29

### Added
- **Library Detection Engine**: New `-dt` / `--detect-libraries` flag to identify JavaScript libraries (React, Vue, Angular, jQuery, etc.) without performing XSS scans.
- **Refactoring**: Major codebase restructuring for better modularity and maintainability.
  - Split `Scanner` into specialized components (`ReflectedScanner`, `BlindScanner`, `DOMScanner`).
  - Extracted entry point logic into `pkg/runner`.

### Changed
- **Performance**: Optimized technology detection using a new signature-based engine.

## [v2.3.0] - 2025-11-27

### Added
- **DOM Clobbering False Positive Reduction**: The scanner now cross-references HTML `id`/`name` attributes with JavaScript global variable usage. Findings are only reported if the specific ID/Name is actually accessed in the script, significantly reducing noise.
- **Prototype Pollution Accuracy**: Improved detection logic to ignore `location.*` properties when used as keys in dynamic assignments (fixing GTM false positives) and to stop flagging static assignments to `.prototype` and `.constructor` as low-confidence issues.
- **Connection Error Reporting**: Connection errors (e.g., TLS failures, timeouts) are now displayed by default, ensuring visibility into failed scans without needing verbose mode.

### Fixed
- Fixed an issue where failed HTTP requests (due to connection errors) were not counted in the final "HTTP requests" statistic.
- Fixed false positives in Google Tag Manager (GTM) scripts related to `location.href` usage.
- Fixed false positives in Bootstrap and other libraries related to static prototype assignments.

## [v2.2.1] - 2025-11-20
...
