package main

import (
	"fmt"
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello, World!")
}

func main() {
	http.HandleFunc("/", handler)

	log.Println("Server running at http://localhost:4170/")
	log.Fatal(http.ListenAndServe("localhost:4170", nil))
}
