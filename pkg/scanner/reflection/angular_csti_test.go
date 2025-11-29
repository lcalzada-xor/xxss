package reflection

import (
	"testing"

	"github.com/lcalzada-xor/xxss/v2/pkg/models"
)

func TestAngularCSTIDetection(t *testing.T) {
	// Simulating Lab 3 response
	// Angular is present (ng-app)
	// Reflection is in HTML text context
	body := `
		<html>
		<script src="angular.js"></script>
		<body ng-app>
			<h1>2 search results for 'zXyWvUtSrQpOnMlKjIhGfEdCbA'</h1>
		</body>
		</html>
	`
	probe := "zXyWvUtSrQpOnMlKjIhGfEdCbA"

	ctx := DetectContext(body, probe)

	if ctx != models.ContextAngular {
		t.Errorf("Expected ContextAngular, got %s", ctx)
	}
}
