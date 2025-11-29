package technologies

import (
	_ "embed"
	"encoding/json"
	"log"
)

//go:embed signatures.json
var signaturesJSON []byte

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
