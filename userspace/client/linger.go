package main

import (
	"net"
	"syscall"
	"time"
)

func main() {
	// Connect to the netcat listener
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	// Configure the socket options
	linger := syscall.Linger{
		Onoff: 1,
		Linger: 0,
	}
	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		panic(err)
	}
	err = rawConn.Control(func(fd uintptr) {
		err = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
		if err != nil {
			panic(err)
		}
	})
	if err != nil {
		panic(err)
	}

	time.Sleep(100 * time.Millisecond) // wait for connection to set

	// Send a message
	_, err = conn.Write([]byte("hello alex"))
	if err != nil {
		panic(err)
	}
	time.Sleep(100 * time.Millisecond) // wait for message to be sent

	// Send a message
	_, err = conn.Write([]byte("hello alex2"))
	if err != nil {
		panic(err)
	}
	time.Sleep(100 * time.Millisecond) // wait for message to be sent

	// Close the connection
	conn.Close()
}