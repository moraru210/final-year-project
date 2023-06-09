package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	url := "http://ec2-13-42-41-168.eu-west-2.compute.amazonaws.com:3001" // Replace with the server's IP address and port number

	response, err := http.Get(url)
	if err != nil {
		log.Fatal("Request failed:", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		log.Fatal("Request failed with status code:", response.StatusCode)
	}

	fmt.Println("Response:", response.Status)
}
