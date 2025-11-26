package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/lcalzada-xor/xxss/v2/pkg/network"
	"github.com/lcalzada-xor/xxss/v2/pkg/scanner"
)

func verifyManualMain() {
	if err := runTests(); err != nil {
		fmt.Println("FAIL: " + err.Error())
		os.Exit(1)
	}
	fmt.Println("SUCCESS")
}

func runTests() error {
	// Test Proxy
	proxyHit := false
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit = true
		w.WriteHeader(200)
	}))
	defer proxyServer.Close()

	client := network.NewClient(2*time.Second, proxyServer.URL, 10, 0)
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	client.Do(req)

	if !proxyHit {
		return fmt.Errorf("Proxy was not hit")
	}

	// Test Headers
	headerReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") == "MyHeader" {
			headerReceived = true
		}
	}))
	defer server.Close()

	client2 := network.NewClient(2*time.Second, "", 10, 0)
	headers := map[string]string{
		"X-Custom": "MyHeader",
	}
	sc := scanner.NewScanner(client2, headers)
	sc.Scan(context.Background(), server.URL + "/?p=test")

	if !headerReceived {
		return fmt.Errorf("Custom header was not received")
	}

	return nil
}
