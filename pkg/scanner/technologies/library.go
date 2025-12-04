package technologies

import (
	_ "embed"
	"encoding/json"
	"log"
)

//go:embed signatures.json
var signaturesJSON []byte

//go:embed hashes.json
var hashesJSON []byte

//go:embed dependencies.json
var dependenciesJSON []byte

// DefaultSignatures returns the built-in list of signatures
func DefaultSignatures() []Signature {
	var signatures []Signature
	err := json.Unmarshal(signaturesJSON, &signatures)
	if err != nil {
		log.Printf("Error loading signatures: %v", err)
		return []Signature{}
	}
	return signatures
}

// DefaultHashes returns the built-in map of hashes
func DefaultHashes() map[string]HashEntry {
	var hashes map[string]HashEntry
	err := json.Unmarshal(hashesJSON, &hashes)
	if err != nil {
		log.Printf("Error loading hashes: %v", err)
		return make(map[string]HashEntry)
	}
	return hashes
}

// DefaultDependencies returns the built-in list of dependency rules
func DefaultDependencies() []DependencyRule {
	var rules []DependencyRule
	err := json.Unmarshal(dependenciesJSON, &rules)
	if err != nil {
		log.Printf("Error loading dependencies: %v", err)
		return []DependencyRule{}
	}
	return rules
}
