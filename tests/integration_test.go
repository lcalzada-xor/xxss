package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lcalzada-xor/xxss/v3/pkg/network"
	"github.com/lcalzada-xor/xxss/v3/pkg/scanner"
)

func TestProxySupport(t *testing.T) {
	// 1. Create a "Proxy" server that records requests
	proxyHit := false
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHit = true
		w.WriteHeader(200)
	}))
	defer proxyServer.Close()

	// 2. Create a Client with this proxy
	client := network.NewClient(2*time.Second, proxyServer.URL, 10, 0)

	// 3. Make a request to anywhere (should go through proxy)
	// We need a target that resolves, but the proxy will intercept it effectively if configured right.
	// Actually, for an HTTP proxy, the client connects to the proxy.
	// Let's just try to get "http://example.com".
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	client.Do(req)

	if !proxyHit {
		t.Errorf("Expected request to go through proxy %s, but it didn't", proxyServer.URL)
	}
}

func TestCustomHeaders(t *testing.T) {
	// 1. Create a Target server that checks headers
	headerReceived := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") == "MyHeader" {
			headerReceived = true
		}
	}))
	defer server.Close()

	// 2. Create Scanner with custom headers
	client := network.NewClient(2*time.Second, "", 10, 0)
	headers := map[string]string{
		"X-Custom": "MyHeader",
	}
	sc := scanner.NewScanner(client, headers)

	// 3. Scan the target
	sc.Scan(context.Background(), server.URL + "/?p=test")

	if !headerReceived {
		t.Error("Expected X-Custom header to be sent, but it wasn't")
	}
}
