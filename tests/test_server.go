package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("p")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body><div>%s</div></body></html>`, param)
	})

	fmt.Println("Test server running on http://localhost:8888")
	log.Fatal(http.ListenAndServe(":8888", nil))
}
