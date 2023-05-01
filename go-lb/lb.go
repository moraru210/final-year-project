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

type maps_fd struct {
    ports_map int
    seq_offsets int
    ack_offsets int
    seq_map int
    ack_map int
}

func main() {
    const connection_map_path = "/sys/fs/bpf/lo/ports_map"
    ports_map_fd, err := bpf.ObjGet(connection_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding ports_map")

    const seq_offsets_path = "/sys/fs/bpf/lo/seq_offsets"
    seq_offsets_fd, err := bpf.ObjGet(seq_offsets_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding seq_offsets map")

    const ack_offsets_path = "/sys/fs/bpf/lo/ack_offsets"
    ack_offsets_fd, err := bpf.ObjGet(ack_offsets_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding ack_offsets map")

    const seq_map_path = "/sys/fs/bpf/lo/seq_map"
    seq_map_fd, err := bpf.ObjGet(seq_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding seq_map")

    const ack_map_path = "/sys/fs/bpf/lo/ack_map"
    ack_map_fd, err := bpf.ObjGet(ack_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding ack_map")

    maps := maps_fd{
        ports_map: ports_map_fd,
        seq_offsets: seq_offsets_fd,
        ack_offsets: ack_offsets_fd,
        seq_map: seq_map_fd,
        ack_map: ack_map_fd,
    }

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
            go handleConnection(conn, conn1, maps)
        } else {
            go handleConnection(conn, conn2, maps)
        }
        rr += 1
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

func handleConnection(conn net.Conn, conn_w net.Conn, maps maps_fd) {
    //defer conn.Close()

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
    w_rem_port := C.uint(remoteAddr.Port)

    localAddr := conn_w.LocalAddr().(*net.TCPAddr)
    w_loc_port := C.uint(localAddr.Port)

    fmt.Printf("Client connected from %s:%d\n", w_ip, w_rem_port)

    worker_c := C.struct_connection{
        src_port: w_rem_port,
        dst_port: w_loc_port,
    }

    fmt.Printf("Access worker connection struct dst_port %d\n", worker_c.dst_port);

    //Handle the initial seq and ack offsets for the lb c<->w connections
    // *** client->LB ***
    var c_seq = C.uint(0)
    err := bpf.LookupElement(maps.seq_map, unsafe.Pointer(&client_c), unsafe.Pointer(&c_seq))
    if (err != nil) {
        fmt.Println("Error, could not find the seq number: ", err.Error())
        return
    }
    fmt.Println("completed seq_map lookup")

    var c_ack = C.uint(0)
    err = bpf.LookupElement(maps.ack_map, unsafe.Pointer(&client_c), unsafe.Pointer(&c_ack))
    if (err != nil) {
        fmt.Println("Error, could not find the ack number: ", err.Error())
        return
    }
    fmt.Println("completed ack_map lookup")
    // ******
    // *** LB<-worker ***
    var w_seq = C.uint(0)
    err = bpf.LookupElement(maps.seq_map, unsafe.Pointer(&worker_c), unsafe.Pointer(&w_seq))
    if (err != nil) {
        fmt.Println("Error, could not find the seq number: ", err.Error())
        return
    }
    fmt.Println("completed seq_map lookup")

    var w_ack = C.uint(0)
    err = bpf.LookupElement(maps.ack_map, unsafe.Pointer(&worker_c), unsafe.Pointer(&w_ack))
    if (err != nil) {
        fmt.Println("Error, could not find the ack number: ", err.Error())
        return
    }
    fmt.Println("completed ack_map lookup")
    // ******
    // *** calculate offsets for each connection direction and add to maps
    fmt.Println("c_seq is %d and c_ack is %d\n", c_seq, c_ack)
    fmt.Println("w_seq is %d and w_ack is %d\n", w_seq, w_ack)
    var seq_off = C.int(c_seq - w_ack) //w is inv direction
    var ack_off = C.int(c_ack - w_seq) //w is inv direction
    fmt.Println("seq_off is %d and ack_off is %d\n", seq_off, ack_off)

    err = bpf.UpdateElement(maps.seq_offsets, "seq_offsets", unsafe.Pointer(&client_c), unsafe.Pointer(&seq_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating seq_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating seq_offsets map")

    err = bpf.UpdateElement(maps.ack_offsets, "ack_offsets", unsafe.Pointer(&client_c), unsafe.Pointer(&ack_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ack_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating ack_offsets map")
    
    var inv_seq_off = C.int(-1 * seq_off)
    var inv_ack_off = C.int(-1 * ack_off)
    err = bpf.UpdateElement(maps.seq_offsets, "seq_offsets", unsafe.Pointer(&worker_c), unsafe.Pointer(&inv_seq_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating seq_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating seq_offsets map")

    err = bpf.UpdateElement(maps.ack_offsets, "ack_offsets", unsafe.Pointer(&worker_c), unsafe.Pointer(&inv_ack_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ack_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating ack_offsets map")
    // ******

    // Update Ports Map with conn->conn_w and set conn offsets to 0.
    r_worker := reverse(worker_c)
    err = bpf.UpdateElement(maps.ports_map, "ports_map", unsafe.Pointer(&client_c), unsafe.Pointer(&r_worker), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ports_mapmap: ", err.Error())
        return
    } 
    fmt.Println("complete updating ports_map")

    // Update Ports Map with conn_w->rev(conn) 
    r_client := reverse(client_c)
    err = bpf.UpdateElement(maps.ports_map, "ports_map", unsafe.Pointer(&worker_c), unsafe.Pointer(&r_client), bpf.BPF_ANY)
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