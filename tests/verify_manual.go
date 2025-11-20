package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/lcalzada-xor/xxss/network"
	"github.com/lcalzada-xor/xxss/scanner"
)

func main() {
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

	client := network.NewClient(2*time.Second, proxyServer.URL)
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

	client2 := network.NewClient(2*time.Second, "")
	headers := map[string]string{
		"X-Custom": "MyHeader",
	}
	sc := scanner.NewScanner(client2, headers)
	sc.Scan(server.URL + "/?p=test")

	if !headerReceived {
		return fmt.Errorf("Custom header was not received")
	}

	return nil
}
