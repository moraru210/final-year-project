package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <port>")
		os.Exit(1)
	}

	// Set the address
	address := "localhost:" + os.Args[1]
	fmt.Println("Address is: ", address)
	// Connect to the netcat listener
	conn, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Set the socket options
	tcpConn := conn.(*net.TCPConn)
	tcpConn.SetLinger(0)

	// Create a channel to receive OS signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for user input or termination signal
	go func() {
		for {
			fmt.Println("Press Enter to send the text from 'input' (text file), or Ctrl+C to terminate")
			var input string
			fmt.Scanln(&input)
			sendTextFromFile(conn)
		}
	}()

	// Wait for the signal
	<-sigCh
	fmt.Println("\nReceived an interrupt, stopping services...")

	conn.Close()
	os.Exit(0)
}

func sendTextFromFile(conn net.Conn) {
	filePath := "input"
	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Failed to read file '%s': %v\n", filePath, err)
		return
	}

	// Send the file contents through the connection
	_, err = conn.Write(data)
	if err != nil {
		fmt.Printf("Failed to send data: %v\n", err)
		return
	}

	fmt.Println("Text sent successfully!")
}
