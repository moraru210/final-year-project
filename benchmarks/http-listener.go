package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello, World!")
}

func main() {
	//input parsing
	if len(os.Args) != 2 {
		fmt.Println("Usage: test <integer> <integer>")
		os.Exit(1)
	}

	http.HandleFunc("/", handler)

	address := "localhost:" + os.Args[1]
	log.Printf("Server running at http://%s/\n", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
