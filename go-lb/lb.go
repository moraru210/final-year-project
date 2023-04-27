package main

// #cgo CFLAGS: -g -Wall
// #include "common.h"
import "C"
import (
    "fmt"
    "net"
)

func main() {
    // Listen for incoming connections
    ln, err := net.Listen("tcp", ":8080")
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        return
    }
    defer ln.Close()

    fmt.Println("Server listening on port 8080")

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