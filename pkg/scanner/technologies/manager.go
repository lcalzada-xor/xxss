package technologies

import "sync"

// Manager coordinates multiple detectors to find technologies
type Manager struct {
	Detectors []Detector
}

// NewManager creates a new Manager with default detectors
func NewManager() *Manager {
	return &Manager{
		Detectors: []Detector{
			NewSignatureDetector(DefaultSignatures()),
			NewHashDetector(DefaultHashes()),
		},
	}
}

// DetectAll runs all detectors against the body and returns all found technologies
func (m *Manager) DetectAll(body string) []*Technology {
	var allTechnologies []*Technology
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, detector := range m.Detectors {
		wg.Add(1)
		go func(d Detector) {
			defer wg.Done()
			results := d.DetectAll(body)
			if len(results) > 0 {
				mu.Lock()
				allTechnologies = append(allTechnologies, results...)
				mu.Unlock()
			}
		}(detector)
	}

	wg.Wait()

	// Post-processing: Analyze dependencies
	analyzer := NewDependencyAnalyzer(DefaultDependencies())
	allTechnologies = analyzer.Analyze(allTechnologies)

	return allTechnologies
}
