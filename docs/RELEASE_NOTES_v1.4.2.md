# Release Notes - xxss v1.4.2

**Date:** November 20, 2025
**Type:** Hotfix Release

## Overview

This hotfix release addresses a critical bug in the parameter reflection detection logic and introduces a new feature to track HTTP requests.

## Key Changes

### 🐛 Fixed: Parameter Reflection Detection
- **Issue**: Previously, the scanner replaced **all** parameters with unique probes simultaneously during the baseline check. This caused false negatives when a parameter's reflection depended on another parameter having a specific value (e.g., `?error=msg&errorMsg=test`).
- **Fix**: The scanner now tests each parameter **individually**, keeping other parameters at their original values. This ensures accurate detection of conditionally reflected parameters.

### ✨ Added: HTTP Request Counter
- **Feature**: Added a counter to track the number of HTTP requests made during scanning.
- **Visibility**:
  - **Verbose Mode (`-v`)**: Shows the number of requests made for each scanned URL.
  - **Final Statistics**: Displays the total number of HTTP requests made across the entire scan.
- **Benefit**: Provides better visibility into scanner performance and helps users monitor request volume for rate limiting purposes.

## Installation

You can install the latest version using `go install`:

```bash
go install github.com/lcalzada-xor/xxss@v1.4.2
```

## Usage Example

```bash
# Scan a single URL with verbose output to see request counts
echo "http://example.com/?p=val" | xxss -v

# Output:
# [*] http://example.com/?p=val: 4 HTTP requests
# [*] Scan complete: 1 URLs processed, 0 vulnerabilities found, 4 HTTP requests
```
