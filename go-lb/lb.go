package main

// #cgo CFLAGS: -g -Wall
// #include "common.h"
import "C"
import (
    "fmt"
    "net"
)

func main() {
    //set up connection with worker nodes
    setUpWorkerConnections()

    // Listen for incoming connections
    ln, err := net.Listen("tcp", ":8080")
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        return
    }
    defer ln.Close()

    fmt.Println("Server listening on port 8080")

    const num_workers = 2;
    rr := 0
    for {
        // Accept new connection
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println("Error accepting:", err.Error())
            continue
        }

        // Handle new connection in a goroutine
        go handleConnection(conn)
    }
}

func setUpWorkerConnections() (net.Conn, net.Conn) {
    // Connect to netcat server at localhost:4170
    conn1, err := net.Dial("tcp", "localhost:4170")
    if err != nil {
        fmt.Println("Error connecting to localhost:4170:", err)
        return nil, nil
    }

    fmt.Println("Connected to localhost:4170")

    // Connect to netcat server at localhost:4171
    conn2, err := net.Dial("tcp", "localhost:4171")
    if err != nil {
        fmt.Println("Error connecting to localhost:4171:", err)
        return nil, nil
    }

    fmt.Println("Connected to localhost:4171")

    // Send messages to the netcat servers
    message1 := "Hello from connection 1\n"
    message2 := "Hello from connection 2\n"

    _, err = conn1.Write([]byte(message1))
    if err != nil {
        fmt.Println("Error sending message to localhost:4170:", err)
        return nil, nil
    }

    fmt.Println("Sent message to localhost:4170")

    _, err = conn2.Write([]byte(message2))
    if err != nil {
        fmt.Println("Error sending message to localhost:4171:", err)
        return nil, nil
    }

    fmt.Println("Sent message to localhost:4171")
    return conn1, conn2
}

func handleConnection(conn net.Conn) {
    defer conn.Close()

    // Get the client's IP address and port number
    remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
    ip := remoteAddr.IP.String()
    port := C.uint(remoteAddr.Port)

    fmt.Printf("Client connected from %s:%d\n", ip, port)

    c := C.struct_connection{
        src_port: port,
        dst_port: 8080,
    }

    fmt.Printf("Access connection struct src_port %d\n", c.src_port);

    // Receive messages from the client
    buffer := make([]byte, 1024)
    for {
        n, err := conn.Read(buffer)
        if err != nil {
            fmt.Println("Error reading:", err.Error())
            return
        }

        fmt.Printf("Received message: %s\n", buffer[:n])
        buffer = make([]byte, 1024)
    }
}