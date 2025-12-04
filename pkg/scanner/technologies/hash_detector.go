package technologies

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/hex"
	"strings"
)

// HashEntry represents a known technology version associated with a hash
type HashEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HashDetector detects technologies based on file hashes
type HashDetector struct {
	Hashes map[string]HashEntry
}

// NewHashDetector creates a new HashDetector with the given hash database
func NewHashDetector(hashes map[string]HashEntry) *HashDetector {
	return &HashDetector{
		Hashes: hashes,
	}
}

// DetectAll calculates the hash of the body and checks if it matches any known technology
func (d *HashDetector) DetectAll(body string) []*Technology {
	normalizedBody := strings.TrimSpace(body)

	// Calculate MD5
	hashMD5 := md5.Sum([]byte(normalizedBody))
	hashStringMD5 := hex.EncodeToString(hashMD5[:])

	// Calculate SHA-1
	hashSHA1 := sha1.Sum([]byte(normalizedBody))
	hashStringSHA1 := hex.EncodeToString(hashSHA1[:])

	// Calculate SHA-512
	hashSHA512 := sha512.Sum512([]byte(normalizedBody))
	hashStringSHA512 := hex.EncodeToString(hashSHA512[:])

	// Check MD5
	if entry, exists := d.Hashes[hashStringMD5]; exists {
		return []*Technology{
			{
				Name:       entry.Name,
				Version:    entry.Version,
				Confidence: "Critical",
			},
		}
	}

	// Check SHA-1
	if entry, exists := d.Hashes[hashStringSHA1]; exists {
		return []*Technology{
			{
				Name:       entry.Name,
				Version:    entry.Version,
				Confidence: "Critical",
			},
		}
	}

	// Check SHA-512
	if entry, exists := d.Hashes[hashStringSHA512]; exists {
		return []*Technology{
			{
				Name:       entry.Name,
				Version:    entry.Version,
				Confidence: "Critical",
			},
		}
	}

	return nil
}
