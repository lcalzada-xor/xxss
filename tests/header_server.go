package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received request: %s %s\n", r.Method, r.URL.String())
		fmt.Println("Headers:")
		for k, v := range r.Header {
			fmt.Printf("  %s: %s\n", k, v)
		}
		// Reflect parameters to trigger xxss detection logic if needed,
		// but here we just want to see headers on stdout.
		w.Write([]byte("<html><body>"))
		for k, v := range r.URL.Query() {
			for _, val := range v {
				w.Write([]byte(val))
			}
		}
		w.Write([]byte("</body></html>"))
	})

	fmt.Println("Listening on :8081...")
	http.ListenAndServe(":8081", nil)
}
