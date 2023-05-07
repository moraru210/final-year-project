package main

/*
#cgo CFLAGS: -g -Wall
#include "../../kernel/common.h"
#include <arpa/inet.h>
#include <stdint.h>
*/
import "C"
import (
    "fmt"
    "net"
    "github.com/cilium/cilium/pkg/bpf"
    "unsafe"
    "github.com/moraru210/final-year-project/userspace/common"
)

func main() {
    const connection_map_path = "/sys/fs/bpf/lo/conn_map"
    Conn_map_fd, err := bpf.ObjGet(connection_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding Conn_map")

    const Numbers_map_path = "/sys/fs/bpf/lo/numbers_map"
    Numbers_map_fd, err := bpf.ObjGet(Numbers_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding Numbers_map")

    maps := common.Maps_fd{
        Conn_map: Conn_map_fd,
        Numbers_map: Numbers_map_fd,
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

func handleConnection(conn net.Conn, conn_w net.Conn, maps common.Maps_fd) {
    defer conn.Close()

    // Get the client's IP address and port number
    remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
    c_ip := remoteAddr.IP.String()
    c_port := C.uint(remoteAddr.Port)

    fmt.Printf("Client connected from %s:%d\n", c_ip, c_port)

    lo_ip := C.inet_addr(C.CString("0x7f000001"))
    fmt.Println("lo_ip is: ", lo_ip)

    client_c := C.struct_connection{
        src_port: c_port,
        dst_port: 8080,
        src_ip: lo_ip,
        dst_ip: lo_ip,
    }

    fmt.Printf("Access client connection struct src_port %d\n", client_c.src_port);

    // Get the worker's IP address and port number
    remoteAddr = conn_w.RemoteAddr().(*net.TCPAddr)
    w_ip := remoteAddr.IP.String()
    w_rem_port := C.uint(remoteAddr.Port)

    localAddr := conn_w.LocalAddr().(*net.TCPAddr)
    w_loc_port := C.uint(localAddr.Port)

    fmt.Printf("Connected to worker from %s:%d\n", w_ip, w_rem_port)

    worker_c := C.struct_connection{
        src_port: w_rem_port,
        dst_port: w_loc_port,
        src_ip: lo_ip,
        dst_ip: lo_ip,
    }

    fmt.Printf("Access worker connection struct dst_port %d\n", worker_c.dst_port);

    //Handle the initial seq and ack offsets for the lb c<->w connections
    // *** client->LB ***
    var c_numbers = C.struct_numbers{
        seq_no: C.uint(0),
        ack_no: C.uint(0),
        seq_offset: C.int(0),
        ack_offset: C.int(0),
    }
    err := bpf.LookupElement(maps.Numbers_map, unsafe.Pointer(&client_c), unsafe.Pointer(&c_numbers))
    if (err != nil) {
        fmt.Println("Error, could not find client's numbers elem: ", err.Error())
        return
    }
    fmt.Println("completed client's Numbers_map lookup")
    // ******
    // *** LB<-worker ***
    var w_numbers = C.struct_numbers{
        seq_no: C.uint(0),
        ack_no: C.uint(0),
        seq_offset: C.int(0),
        ack_offset: C.int(0),
    }
    err = bpf.LookupElement(maps.Numbers_map, unsafe.Pointer(&worker_c), unsafe.Pointer(&w_numbers))
    if (err != nil) {
        fmt.Println("Error, could not find worker's numbers elem: ", err.Error())
        return
    }
    fmt.Println("completed worker's Numbers_map lookup")
    // ******
    // *** calculate offsets for each connection direction and add to maps
    fmt.Println("c_seq is %d and c_ack is %d\n", c_numbers.seq_no, c_numbers.ack_no)
    fmt.Println("w_seq is %d and w_ack is %d\n", w_numbers.seq_no, w_numbers.ack_no)
    var seq_off = C.int(c_numbers.seq_no - w_numbers.ack_no) //w is inv direction
    var ack_off = C.int(c_numbers.ack_no - w_numbers.seq_no) //w is inv direction
    fmt.Println("Client: seq_off is %d and ack_off is %d\n", seq_off, ack_off)

    c_numbers.seq_offset = seq_off
    c_numbers.ack_offset = ack_off

    err = bpf.UpdateElement(maps.Numbers_map, "Numbers_map", unsafe.Pointer(&client_c), unsafe.Pointer(&c_numbers), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating numbers_elem in Numbers_map: ", err.Error())
        return
    } 
    fmt.Println("complete updating Numbers_map")
    
    var inv_seq_off = C.int(w_numbers.seq_no - c_numbers.ack_no)
    var inv_ack_off = C.int(w_numbers.ack_no - c_numbers.seq_no)
    fmt.Println("Worker: seq_off is %d and ack_off is %d\n", inv_seq_off, inv_ack_off)

    w_numbers.seq_offset = seq_off
    w_numbers.ack_offset = ack_off

    err = bpf.UpdateElement(maps.Numbers_map, "Numbers_map", unsafe.Pointer(&worker_c), unsafe.Pointer(&w_numbers), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating numbers_elem in Numbers_map: ", err.Error())
        return
    } 
    fmt.Println("complete updating Numbers_map")
    // ******

    // Update Ports Map with conn->conn_w and set conn offsets to 0.
    r_worker := reverse(worker_c)
    err = bpf.UpdateElement(maps.Conn_map, "Conn_map", unsafe.Pointer(&client_c), unsafe.Pointer(&r_worker), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating Conn_map: ", err.Error())
        return
    } 
    fmt.Println("complete updating Conn_map")

    // Update Ports Map with conn_w->rev(conn) 
    r_client := reverse(client_c)
    err = bpf.UpdateElement(maps.Conn_map, "Conn_map", unsafe.Pointer(&worker_c), unsafe.Pointer(&r_client), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating Conn_map: ", err.Error())
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
    var tmp_p = conn.src_port
    var tmp_i = conn.src_ip
    conn.src_port = conn.dst_port
    conn.dst_port = tmp_p
    conn.src_ip = conn.dst_ip
    conn.dst_ip = tmp_i
    return conn
}