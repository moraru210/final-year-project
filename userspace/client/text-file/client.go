package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run client.go <ipv4> <port>")
		os.Exit(1)
	}

	// Set the address
	address := os.Args[1] + ":" + os.Args[2]
	fmt.Println("Address is: ", address)
	// Connect to the netcat listener

	// localAddr := &net.TCPAddr{
	// 	IP:   net.ParseIP("0.0.0.0"),
	// 	Port: 5000,
	// }
	// dialer := &net.Dialer{
	// 	LocalAddr: localAddr,
	// }
	conn, err := net.Dial("tcp", address)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Set the socket options
	tcpConn := conn.(*net.TCPConn)
	tcpConn.SetLinger(0)
	tcpConn.SetKeepAlive(false)
	tcpConn.SetKeepAlivePeriod(0)
	tcpConn.SetNoDelay(true)
	//tcpConn.SetReadBuffer(0)

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
	filePath := "input.txt"
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

	// Receive and print the response from the server
	response := receiveResponse(conn)
	fmt.Println("Response received:")
	fmt.Println(response)
}

func receiveResponse(conn net.Conn) string {
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("Failed to receive response: %v\n", err)
		return ""
	}

	return response
}
