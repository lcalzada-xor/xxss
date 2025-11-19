package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"strings"
)

func main() {
	http.HandleFunc("/vuln", func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		// Vulnerable: reflects input directly
		fmt.Fprintf(w, "<html><body>Reflected: %s</body></html>", param)
	})

	http.HandleFunc("/safe", func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		// Safe: HTML encodes input
		fmt.Fprintf(w, "<html><body>Safe: %s</body></html>", html.EscapeString(param))
	})

	http.HandleFunc("/mixed", func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		// Mixed: allows quotes but encodes brackets
		safe := html.EscapeString(param)
		safe = strings.ReplaceAll(safe, "&#34;", "\"")
		safe = strings.ReplaceAll(safe, "&#39;", "'")
		fmt.Fprintf(w, "<html><body>Mixed: %s</body></html>", safe)
	})

	log.Println("Listening on :8081")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
