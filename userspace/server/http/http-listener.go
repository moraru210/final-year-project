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
	if len(os.Args) != 3 {
		fmt.Println("Usage: http-listener IPv4 Port")
		os.Exit(1)
	}

	http.HandleFunc("/", handler)

	address := os.Args[1] + ":" + os.Args[2]
	log.Printf("Server running at http://%s/\n", address)
	log.Fatal(http.ListenAndServe(address, nil))
}
