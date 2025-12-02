# Phase 2 Design: Advanced JavaScript Library Detection

This document details the design for Phase 2 of the technology detection improvements, focusing on **Hash-based Detection** and **Source Map Analysis**. These methods aim to solve the limitations of regex-based detection (false positives, minification) and provide 100% accurate version identification.

## 1. Hash-based Detection (`HashDetector`)

### Objective
Identify standard library files (e.g., from CDNs) by comparing their cryptographic hash against a database of known hashes.

### Architecture

1.  **Hash Database (`hashes.json`)**:
    A JSON file storing known hashes for popular libraries and versions.
    ```json
    {
      "jquery": {
        "3.6.0": ["e1d...hash1", "a4f...hash2"],
        "3.5.1": ["..."]
      },
      "react": { ... }
    }
    ```
    *   *Optimization*: Use a flat map `Hash -> {Name, Version}` for O(1) lookup.

2.  **Detector Implementation**:
    *   Implement the `Detector` interface.
    *   **Input**: The content of the downloaded script.
    *   **Process**:
        1.  Calculate SHA-256 (or MD5) of the script content.
        2.  Look up the hash in the loaded database.
        3.  If found, return `Technology` with `Confidence: "Certain"`.

3.  **Database Generation**:
    *   We need a script/tool to generate `hashes.json` by fetching common versions from cdnjs/unpkg.
    *   *Initial Scope*: Include top 10-20 libraries (React, Vue, jQuery, Bootstrap, Axios, etc.).

### Integration
*   The `Scanner` already fetches external scripts.
*   The `HashDetector` will be added to the `Manager`.
*   It runs in parallel with `SignatureDetector`.

## 2. Source Map Analysis (`SourceMapDetector`)

### Objective
Identify libraries included in bundled/minified files (Webpack, Vite, etc.) by analyzing their Source Maps.

### Architecture

1.  **Detection**:
    *   Scan script content for `//# sourceMappingURL=<url>` or `//@ sourceMappingURL=<url>`.
    *   Resolve relative URLs against the script's URL.

2.  **Fetching & Parsing**:
    *   Fetch the `.map` file.
    *   Parse the JSON structure (Standard Source Map v3).

3.  **Analysis**:
    *   Iterate through the `sources` array in the map.
    *   Look for patterns indicating library usage, typically in `node_modules`.
    *   *Example Patterns*:
        *   `webpack:///node_modules/react/index.js` -> Detects **React**
        *   `../node_modules/vue/dist/vue.runtime.esm.js` -> Detects **Vue**
    *   *Version Extraction*: Sometimes difficult from paths alone, but presence is certain.

### Integration
*   This requires fetching an *additional* file (the `.map`).
*   **Constraint**: Only fetch source maps if `Verbose` mode is on or if explicitly enabled, to save bandwidth/time.
*   **Fallback**: If the map contains `sourcesContent`, we can potentially run signature detection on the original source code (advanced).

## 3. Implementation Plan

### Step 1: Hash Database & Detector
1.  Create `pkg/scanner/technologies/hashes.json`.
2.  Create `pkg/scanner/technologies/hash_detector.go`.
3.  Implement `NewHashDetector` and `DetectAll`.
4.  Update `Manager` to include `HashDetector`.

### Step 2: Source Map Detector
1.  Create `pkg/scanner/technologies/sourcemap_detector.go`.
2.  Implement logic to find and fetch `sourceMappingURL`.
3.  Implement logic to parse `sources` and match against library patterns.

### Step 3: Integration & Testing
1.  Update `Scanner` to pass downloaded scripts to the new detectors.
2.  Add unit tests with mock script content and map files.

## 4. Future Considerations
*   **Database Updates**: Automate the update of `hashes.json` via a GitHub Action or separate script.
*   **Fuzzy Hashing**: For slightly modified files (e.g., different comments), standard hashing fails. SimHash or similar could be explored later.
