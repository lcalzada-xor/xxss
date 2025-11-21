package output

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lcalzada-xor/xxss/pkg/models"
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
		cReset := "\x1b[0m"

		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("\n%s[+] XSS Vulnerability Found%s\n", cPurple, cReset))
		sb.WriteString(fmt.Sprintf("    %sURL:%s        %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.URL, cReset))
		sb.WriteString(fmt.Sprintf("    %sMethod:%s     %s%s%s\n", cDarkPurple, cReset, cLightPurple, res.Method, cReset))
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
