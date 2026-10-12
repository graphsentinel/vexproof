// P0: does -coverpkg instrument stdlib and golang.org/x code?
package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"golang.org/x/net/html"
)

func main() {
	http.HandleFunc("/parse", func(w http.ResponseWriter, r *http.Request) {
		doc, err := html.Parse(strings.NewReader(r.URL.Query().Get("q")))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		fmt.Fprintf(w, "%v\n", doc.Type)
	})
	http.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) { os.Exit(0) })
	_ = http.ListenAndServe(":8099", nil)
}
