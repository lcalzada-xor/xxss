package technologies

import (
	"strings"
)

// DependencyRule defines a rule for inferring missing technologies
type DependencyRule struct {
	TriggerTech             string   `json:"trigger_tech"`
	TriggerVersionNotPrefix string   `json:"trigger_version_not_prefix"`
	MissingTechs            []string `json:"missing_techs"`
	InferTech               string   `json:"infer_tech"`
}

// DependencyAnalyzer analyzes detected technologies to infer missing dependencies
type DependencyAnalyzer struct {
	Rules []DependencyRule
}

// NewDependencyAnalyzer creates a new DependencyAnalyzer with the given rules
func NewDependencyAnalyzer(rules []DependencyRule) *DependencyAnalyzer {
	return &DependencyAnalyzer{
		Rules: rules,
	}
}

// Analyze checks the list of detected technologies and adds inferred dependencies
func (a *DependencyAnalyzer) Analyze(detected []*Technology) []*Technology {
	var inferred []*Technology

	// Map for O(1) lookups
	techMap := make(map[string]*Technology)
	for _, t := range detected {
		techMap[t.Name] = t
	}

	for _, rule := range a.Rules {
		// Check if trigger technology is present
		trigger, ok := techMap[rule.TriggerTech]
		if !ok {
			continue
		}

		// Check version condition (if specified)
		if rule.TriggerVersionNotPrefix != "" {
			// If version is known and starts with the excluded prefix, skip this rule
			if trigger.Version != "" && strings.HasPrefix(trigger.Version, rule.TriggerVersionNotPrefix) {
				continue
			}
			// If version is unknown, we proceed (conservative approach: assume it might be the version that triggers dependency)
			// OR we could skip. The previous hardcoded logic skipped if version was unknown for Bootstrap?
			// Actually, the previous logic was: if bootstrap.Version != "" { if !prefix "5." { add } } else { // do nothing }
			// So if version is unknown, we DO NOT infer. Let's replicate that safety.
			if trigger.Version == "" {
				continue
			}
		}

		// Check if ANY of the "missing" techs are present.
		// The rule is: we infer ONLY if NONE of the 'MissingTechs' are found.
		// e.g. Backbone needs Underscore OR Lodash. If either is present, we are good.
		foundAnyMissing := false
		for _, missing := range rule.MissingTechs {
			if _, has := techMap[missing]; has {
				foundAnyMissing = true
				break
			}
		}

		if !foundAnyMissing {
			// None of the required alternatives were found, so we infer the default one
			inferred = append(inferred, &Technology{
				Name:       rule.InferTech,
				Version:    "",
				Confidence: "Low", // Inferred
			})
		}
	}

	return append(detected, inferred...)
}
