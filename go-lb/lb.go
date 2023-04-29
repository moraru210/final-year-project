package main

// #cgo CFLAGS: -g -Wall
// #include "common.h"
import "C"
import (
    "fmt"
    "net"
    "github.com/cilium/cilium/pkg/bpf"
    "unsafe"
)

func main() {
    const connection_map_path = "/sys/fs/bpf/test/ports_map"
    conn_map_fd, err := bpf.ObjGet(connection_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding map")

    //set up connection with worker nodes
    conn1, conn2, err := setUpWorkerConnections()
    if (err != nil) {
        fmt.Println("Error setting up worker connections:", err.Error())
        return
    }
    defer conn1.Close()
    defer conn2.Close()

    // Listen for incoming connections
    ln, err := net.Listen("tcp", ":8080")
    if err != nil {
        fmt.Println("Error listening:", err.Error())
        return
    }
    defer ln.Close()

    fmt.Println("Server listening on port 8080")

    const num_workers = 2;
    rr := 1
    for {
        // Accept new connection
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println("Error accepting:", err.Error())
            continue
        }

        // Handle new connection in a goroutine
        if (rr % num_workers == 1) {
            go handleConnection(conn, conn1, conn_map_fd)
        } else {
            go handleConnection(conn, conn2, conn_map_fd)
        }
    }
}

func setUpWorkerConnections() (net.Conn, net.Conn, error) {
    // Connect to netcat server at localhost:4170
    conn1, err := net.Dial("tcp", "localhost:4170")
    if err != nil {
        fmt.Println("Error connecting to localhost:4170:", err)
        return nil, nil, err
    }
    fmt.Println("Connected to localhost:4170")

    // Connect to netcat server at localhost:4171
    conn2, err := net.Dial("tcp", "localhost:4171")
    if err != nil {
        fmt.Println("Error connecting to localhost:4171:", err)
        return nil, nil, err
    }
    fmt.Println("Connected to localhost:4171")
    
    return conn1, conn2, nil
}

func handleConnection(conn net.Conn, conn_w net.Conn, conn_map_fd int) {
    defer conn.Close()

    // Get the client's IP address and port number
    remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
    c_ip := remoteAddr.IP.String()
    c_port := C.uint(remoteAddr.Port)

    fmt.Printf("Client connected from %s:%d\n", c_ip, c_port)

    client_c := C.struct_connection{
        src_port: c_port,
        dst_port: 8080,
    }

    fmt.Printf("Access client connection struct src_port %d\n", client_c.src_port);

    // Get the worker's IP address and port number
    remoteAddr = conn_w.RemoteAddr().(*net.TCPAddr)
    w_ip := remoteAddr.IP.String()
    w_port := C.uint(remoteAddr.Port)

    fmt.Printf("Client connected from %s:%d\n", w_ip, w_port)

    worker_c := C.struct_connection{
        src_port: 8080,
        dst_port: w_port,
    }

    fmt.Printf("Access worker connection struct dst_port %d\n", worker_c.dst_port);

    // Update Ports Map with conn->conn_w and rev(conn_w)->rev(conn)
    err := bpf.UpdateElement(conn_map_fd, "ports_map", unsafe.Pointer(&client_c), unsafe.Pointer(&worker_c), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating map: ", err.Error())
        return
    } 
    fmt.Println("complete updating map")

    r_client := reverse(client_c)
    r_worker := reverse(worker_c)

    err = bpf.UpdateElement(conn_map_fd, "ports_map", unsafe.Pointer(&r_worker), unsafe.Pointer(&r_client), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating map: ", err.Error())
        return
    } 
    fmt.Println("complete updating map")

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

func reverse(conn C.struct_connection) C.struct_connection {
    var tmp = conn.src_port
    conn.src_port = conn.dst_port
    conn.dst_port = tmp
    return conn
}