package payloads

import (
	"fmt"
	"strings"
)

// ObfuscationType defines the type of obfuscation to apply
type ObfuscationType int

const (
	ObfuscateNone ObfuscationType = iota
	ObfuscateJSUnicode
	ObfuscateJSConcat
	ObfuscateHTMLEntities
)

// Obfuscate applies the specified obfuscation technique to the payload
func Obfuscate(payload string, method ObfuscationType) string {
	switch method {
	case ObfuscateJSUnicode:
		return obfuscateJSUnicode(payload)
	case ObfuscateJSConcat:
		return obfuscateJSConcat(payload)
	case ObfuscateHTMLEntities:
		return obfuscateHTMLEntities(payload)
	default:
		return payload
	}
}

// obfuscateJSUnicode escapes characters to \uXXXX format
// It primarily targets parenthesis and quotes which are often filtered
func obfuscateJSUnicode(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		// Obfuscate critical chars: ( ) ' " < >
		if strings.ContainsRune("()'\"><", r) {
			sb.WriteString(fmt.Sprintf("\\u%04x", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// obfuscateJSConcat splits strings and concatenates them
// e.g. alert(1) -> 'al'+'ert'(1) - simplistic implementation
// A better approach for "alert(1)" is to split the function name
func obfuscateJSConcat(payload string) string {
	// This is highly context dependent.
	// Simple heuristic: if payload contains "alert", split it.
	if strings.Contains(payload, "alert") {
		return strings.Replace(payload, "alert", "'al'+'ert'", 1)
	}
	if strings.Contains(payload, "confirm") {
		return strings.Replace(payload, "confirm", "'con'+'firm'", 1)
	}
	if strings.Contains(payload, "prompt") {
		return strings.Replace(payload, "prompt", "'pro'+'mpt'", 1)
	}
	return payload
}

// obfuscateHTMLEntities encodes special characters to HTML entities
// Useful for reflection inside HTML attributes or elements
func obfuscateHTMLEntities(payload string) string {
	var sb strings.Builder
	for _, r := range payload {
		// Obfuscate critical chars: < > " ' ( ) :
		if strings.ContainsRune("<>\"'():", r) {
			sb.WriteString(fmt.Sprintf("&#%d;", r))
		} else {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
