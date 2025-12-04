package technologies

import (
	"testing"
)

func TestHashDetector_DetectAll(t *testing.T) {
	// Mock database
	hashes := map[string]HashEntry{
		"d2fe9198a799442b835865e9b835a845":         {Name: "TestLibMD5", Version: "1.0.0"},
		"da39a3ee5e6b4b0d3255bfef95601890afd80709": {Name: "TestLibSHA1", Version: "2.0.0"}, // SHA1 of empty string
		// SHA512 of `console.log("sha512");`
		"e4ab63943d29b935cf9c3ab02738b874d386a616e17dc7ff082d7febcd1aacf5837ae899d83f16f05a5ccd8c7b52b06ed2b4a006e2395df572e2000252278b30": {Name: "TestLibSHA512", Version: "3.0.0"},
	}

	detector := NewHashDetector(hashes)

	tests := []struct {
		name         string
		body         string
		expectedName string
		shouldFind   bool
	}{
		{
			name:         "Exact Match MD5",
			body:         `console.log("test_hash_detection");`,
			expectedName: "TestLibMD5",
			shouldFind:   true,
		},
		{
			name:         "Exact Match SHA1",
			body:         ``, // Empty string SHA1 is da39...
			expectedName: "TestLibSHA1",
			shouldFind:   true,
		},
		{
			name:         "Exact Match SHA512",
			body:         `console.log("sha512");`,
			expectedName: "TestLibSHA512",
			shouldFind:   true,
		},
		{
			name:       "No Match",
			body:       `console.log("something else");`,
			shouldFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			techs := detector.DetectAll(tt.body)
			found := len(techs) > 0

			if found != tt.shouldFind {
				t.Errorf("DetectAll() found = %v, want %v", found, tt.shouldFind)
			}

			if found {
				if techs[0].Name != tt.expectedName {
					t.Errorf("DetectAll() Name = %v, want %v", techs[0].Name, tt.expectedName)
				}
			}
		})
	}
}

func TestManager_HashIntegration(t *testing.T) {
	// This tests that the Manager correctly uses the HashDetector with the embedded hashes.json
	// We added "TestLib" to hashes.json for this purpose.
	manager := NewManager()

	body := `console.log("test_hash_detection");`
	techs := manager.DetectAll(body)

	found := false
	for _, tech := range techs {
		if tech.Name == "TestLib" && tech.Version == "1.0.0" {
			found = true
			break
		}
	}

	if !found {
		t.Error("Manager did not detect TestLib via hash")
	}
}
