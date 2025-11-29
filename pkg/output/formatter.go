package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner/technologies"
)

// Format returns the formatted result string based on the selected format
func Format(res models.Result, format string) string {
	switch format {
	case "url":
		// URL-only format for dalfox pipeline
		return res.URL

	case "human":
		// Human-readable format (Purple Gothic Theme)
		cPurple := "\x1b[38;5;129m"
		cLightPurple := "\x1b[38;5;141m"
		cDarkPurple := "\x1b[38;5;93m"
		cRed := "\x1b[38;5;196m"
		cOrange := "\x1b[38;5;214m"
		cBlue := "\x1b[38;5;45m"
		cReset := "\x1b[0m"

		var sb strings.Builder

		// Special handling for DOM XSS
		if res.Parameter == "DOM" {
			sb.WriteString(fmt.Sprintf("\n%s[+] DOM XSS Vulnerability Found%s\n", cPurple, cReset))
			sb.WriteString(fmt.Sprintf("    %sURL:%s        %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.URL, cReset))
			sb.WriteString(fmt.Sprintf("    %sMethod:%s     %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.Method, cReset))

			// Add HTTP Status with color coding
			statusColor := cLightPurple
			if res.HTTPStatus >= 400 {
				statusColor = cRed
			} else if res.HTTPStatus >= 300 {
				statusColor = cOrange
			}
			sb.WriteString(fmt.Sprintf("    %sHTTP Status:%s %s%d%s\n", cDarkPurple, cReset, statusColor, res.HTTPStatus, cReset))
			sb.WriteString(fmt.Sprintf("    %sExploitable:%s %s%v%s\n", cDarkPurple, cReset, cLightPurple, res.Exploitable, cReset))

			if len(res.DOMFindings) > 0 {
				sb.WriteString(fmt.Sprintf("\n    %sFindings:%s\n", cDarkPurple, cReset))
				for _, finding := range res.DOMFindings {
					// Severity Color
					sevColor := cBlue
					if strings.Contains(strings.ToUpper(finding.Confidence), "HIGH") {
						sevColor = cRed
					} else if strings.Contains(strings.ToUpper(finding.Confidence), "MEDIUM") {
						sevColor = cOrange
					}

					// Clean description: remove redundant "Dangerous ... usage in ..." if it's too long or repetitive
					// For now, keep it but maybe we can shorten it in the future.
					// Let's just print the description.

					sb.WriteString(fmt.Sprintf("      %s[%s] %s%s\n", sevColor, finding.Confidence, finding.Description, cReset))
					sb.WriteString(fmt.Sprintf("             %sFlow:%s %s --> %s%s\n", cDarkPurple, cReset, finding.Source, finding.Sink, cReset))
					if finding.Line != "" {
						sb.WriteString(fmt.Sprintf("             %sType:%s %s%s\n", cDarkPurple, cReset, strings.TrimSpace(finding.Line), cReset))
					}
					if finding.Evidence != "" {
						sb.WriteString(fmt.Sprintf("             %sEvidence:%s %s%s\n", cDarkPurple, cReset, strings.TrimSpace(finding.Evidence), cReset))
					}
					sb.WriteString("\n") // Add spacing between findings
				}
			}
			return sb.String()
		}

		// Standard Reflected/Stored XSS Output
		sb.WriteString(fmt.Sprintf("\n%s[+] XSS Vulnerability Found%s\n", cPurple, cReset))
		sb.WriteString(fmt.Sprintf("    %sURL:%s        %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.URL, cReset))
		sb.WriteString(fmt.Sprintf("    %sMethod:%s     %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.Method, cReset))

		// Add HTTP Status with color coding
		statusColor := cLightPurple
		if res.HTTPStatus >= 400 {
			statusColor = "\x1b[38;5;196m" // Red for errors
		} else if res.HTTPStatus >= 300 {
			statusColor = "\x1b[38;5;214m" // Orange for redirects
		}
		sb.WriteString(fmt.Sprintf("    %sHTTP Status:%s %s%d%s\n", cDarkPurple, cReset, statusColor, res.HTTPStatus, cReset))

		sb.WriteString(fmt.Sprintf("    %sParameter:%s  %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.Parameter, cReset))
		sb.WriteString(fmt.Sprintf("    %sInjection:%s  %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.InjectionType, cReset))
		sb.WriteString(fmt.Sprintf("    %sContext:%s    %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.Context, cReset))
		sb.WriteString(fmt.Sprintf("    %sExploitable:%s %s%v%s\n", cDarkPurple, cReset, cLightPurple, res.Exploitable, cReset))
		if res.SecurityHeaders.WAF != "" {
			sb.WriteString(fmt.Sprintf("    %sWAF:%s        %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.SecurityHeaders.WAF, cReset))
		}
		sb.WriteString(fmt.Sprintf("    %sUnfiltered:%s %s%v%s\n", cDarkPurple, cReset, cLightPurple, res.Unfiltered, cReset))
		if res.SuggestedPayload != "" {
			sb.WriteString(fmt.Sprintf("    %sPayload:%s    %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.SuggestedPayload, cReset))
		}
		if res.SecurityHeaders.CSP != "" {
			sb.WriteString(fmt.Sprintf("    %sCSP:%s        %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.SecurityHeaders.CSP, cReset))
		}
		// Fallback for DOM findings in non-DOM parameter mode (shouldn't happen often but good to have)
		if len(res.DOMFindings) > 0 {
			sb.WriteString(fmt.Sprintf("    %sDOM Findings:%s\n", cDarkPurple, cReset))
			for _, finding := range res.DOMFindings {
				sb.WriteString(fmt.Sprintf("      %s- [%s] %s%s\n", cLightPurple, finding.Confidence, finding.Description, cReset))
			}
		}
		return sb.String()

	case "json":
		// JSON format
		output, err := json.Marshal(res)
		if err != nil {
			// Return error as JSON instead of empty string
			return fmt.Sprintf("{\"error\":\"failed to marshal result: %v\"}", err)
		}
		return string(output)

	default:
		// Default to URL format
		return res.URL
	}
}

// TechResult holds the detection results for a single URL
type TechResult struct {
	URL          string
	Technologies []*technologies.Technology
}

// FormatAllTechnologies formats the technology detection results for multiple URLs into a single table
func FormatAllTechnologies(results []TechResult, format string) string {
	if len(results) == 0 {
		return ""
	}

	switch format {
	case "json":
		// For JSON, we just marshal the whole list
		output, err := json.Marshal(results)
		if err != nil {
			return fmt.Sprintf("{\"error\":\"failed to marshal result: %v\"}", err)
		}
		return string(output)

	case "human":
		cPurple := "\x1b[38;5;129m"
		cLightPurple := "\x1b[38;5;141m"
		cDarkPurple := "\x1b[38;5;93m"
		cReset := "\x1b[0m"
		cRed := "\x1b[31m"
		cYellow := "\x1b[33m"

		var sb strings.Builder

		// Check for WAFs across all results
		var wafDetected bool
		var wafName string
		for _, res := range results {
			for _, tech := range res.Technologies {
				if strings.Contains(strings.ToLower(tech.Name), "waf") {
					wafDetected = true
					wafName = tech.Name
					break
				}
			}
			if wafDetected {
				break
			}
		}

		if wafDetected {
			sb.WriteString(fmt.Sprintf("\n%s[!] WARNING: WAF Detected (%s)%s\n", cRed, wafName, cReset))
			sb.WriteString(fmt.Sprintf("%s    The results might be incomplete or inaccurate due to WAF blocking.%s\n", cYellow, cReset))
		}

		sb.WriteString(fmt.Sprintf("\n%s[+] Technologies Detected%s\n", cPurple, cReset))

		// Determine column widths
		maxURL := 3
		maxTech := 10
		maxVer := 7

		for _, res := range results {
			if len(res.URL) > maxURL {
				maxURL = len(res.URL)
			}
			for _, tech := range res.Technologies {
				if len(tech.Name) > maxTech {
					maxTech = len(tech.Name)
				}
				ver := tech.Version
				if ver == "" {
					ver = "Unknown"
				}
				if len(ver) > maxVer {
					maxVer = len(ver)
				}
			}
		}

		// Cap URL width to avoid overly wide tables, maybe 50 chars?
		if maxURL > 50 {
			maxURL = 50
		}

		// Header
		// Format string: "    %-(maxURL)s %-(maxTech)s %-(maxVer)s %-10s"
		headerFmt := fmt.Sprintf("    %s%%-%ds %%-%ds %%-%ds %%-10s%s\n", cDarkPurple, maxURL, maxTech, maxVer, cReset)
		sb.WriteString(fmt.Sprintf(headerFmt, "URL", "TECHNOLOGY", "VERSION", "CONFIDENCE"))

		separatorFmt := fmt.Sprintf("    %s%%-%ds %%-%ds %%-%ds %%-10s%s\n", cDarkPurple, maxURL, maxTech, maxVer, cReset)
		sb.WriteString(fmt.Sprintf(separatorFmt, strings.Repeat("-", maxURL), strings.Repeat("-", maxTech), strings.Repeat("-", maxVer), strings.Repeat("-", 10)))

		// Track seen WAFs to deduplicate
		seenWAFs := make(map[string]bool)

		for _, res := range results {
			urlStr := res.URL
			if len(urlStr) > 50 {
				urlStr = urlStr[:47] + "..."
			}

			for _, tech := range res.Technologies {
				// Deduplicate WAFs
				if strings.Contains(strings.ToLower(tech.Name), "waf") {
					if seenWAFs[tech.Name] {
						continue
					}
					seenWAFs[tech.Name] = true
				}

				version := tech.Version
				if version == "" {
					version = "Unknown"
				}

				rowFmt := fmt.Sprintf("    %s%%-%ds %s%%-%ds %s%%-%ds %s%%-10s%s\n", cLightPurple, maxURL, cReset, maxTech, cLightPurple, maxVer, cLightPurple, cReset)
				sb.WriteString(fmt.Sprintf(rowFmt, urlStr, tech.Name, version, tech.Confidence))
			}
		}
		sb.WriteString("\n")
		return sb.String()

	default:
		return ""
	}
}
