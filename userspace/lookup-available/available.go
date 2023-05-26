package main

/*
#cgo CFLAGS: -g -Wall
#include <arpa/inet.h>
#include <stdint.h>
*/
import "C"
import (
	"fmt"
	"os"
	"strconv"

	ebpf "github.com/cilium/ebpf"
)

const (
	connection_map_path = "/sys/fs/bpf/lo/conn_map"
	numbers_map_path    = "/sys/fs/bpf/lo/numbers_map"
	available_map_path  = "/sys/fs/bpf/lo/available_map"
	state_map_path      = "/sys/fs/bpf/lo/state_map"
	rematch_map_path    = "/sys/fs/bpf/lo/rematch_map"
	first_server_no     = 4171
)

var (
	round_robin = 0
)

type Connection struct {
	Src_port uint32
	Dst_port uint32
	Src_ip   uint32
	Dst_ip   uint32
}

type Reroute struct {
	Original_conn  Connection
	New_conn       Connection
	Rematch_flag   uint32
	Original_index uint32
	New_index      uint32
}

type Numbers struct {
	Seq_no     uint32
	Ack_no     uint32
	Seq_offset int32
	Ack_offset int32
	Init_seq   uint32
	Init_ack   uint32
}

type Server struct {
	Port uint32
	Ip   uint32
}

type Availability struct {
	Conns [2]Connection
	Valid [2]uint32 //signifies that conn is in use if 1
}

func main() {
	//map handling
	conn_map, err := ebpf.LoadPinnedMap(connection_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", connection_map_path)
	}
	defer conn_map.Close()

	// numbers_map, err := ebpf.LoadPinnedMap(numbers_map_path, nil)
	// if err != nil {
	// 	fmt.Printf("Could not open %s\n", numbers_map_path)
	// }

	available_map, err := ebpf.LoadPinnedMap(available_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", available_map_path)
	}
	defer available_map.Close()

	// state_map, err := ebpf.LoadPinnedMap(state_map_path, nil)
	// if err != nil {
	// 	fmt.Printf("Could not open %s\n", state_map_path)
	// }

	rematch_map, err := ebpf.LoadPinnedMap(rematch_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", rematch_map_path)
	}
	defer rematch_map.Close()

	//input parsing
	if len(os.Args) != 3 {
		fmt.Println("Usage: available <integer> ")
		os.Exit(1)
	}

	client_src, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Invalid first integer argument")
		os.Exit(1)
	}

	worker_port, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("Invalid second integer argument")
		os.Exit(1)
	}

	var reroute Reroute
	conn := Connection{
		Src_port: uint32(client_src),
		Dst_port: uint32(8080),
		Src_ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
		Dst_ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
	}
	fmt.Printf("Query conn has ip_Src: %d and ip_Dst: %d\n", conn.Src_ip, conn.Dst_ip)

	if err := conn_map.Lookup(conn, &reroute); err != nil {
		fmt.Printf("unable to lookup conn in conn_map: %v\n", err)
	} else {
		fmt.Printf("Original conn src %d dst %d\n", reroute.Original_conn.Src_port, reroute.Original_conn.Dst_port)
		fmt.Printf("Original index: %d\n", reroute.Original_index)
		fmt.Printf("Rematch flag: %d\n", reroute.Rematch_flag)
		fmt.Printf("New conn src %d dst %d\n", reroute.New_conn.Src_port, reroute.New_conn.Dst_port)
		fmt.Printf("New index: %d\n", reroute.New_index)
	}

	rematch_key := uint32(client_src)
	var rematch_flag uint32
	if err := rematch_map.Lookup(rematch_key, &rematch_flag); err != nil {
		fmt.Printf("Unable to lookup state for client src port: %v\n", err)
	} else {
		fmt.Printf("Rematch flag for client port %d is %d\n", rematch_key, rematch_flag)
	}

	server := Server{
		Port: uint32(worker_port),
		Ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
	}
	var availability Availability
	if err := available_map.Lookup(server, &availability); err != nil {
		fmt.Printf("Unable to lookup availability for Server with port %d: %v\n", server.Port, err)
	} else {
		fmt.Printf("Availability found\n")
		for i, conn := range availability.Conns {
			fmt.Printf("index: %d\n", i)
			fmt.Printf("Conn.src = %d, Conn.dst = %d\n", conn.Src_port, conn.Dst_port)
			fmt.Printf("Valid[%d]: %d\n", i, availability.Valid[i])
		}
		fmt.Printf("End of avaialability\n")
	}
}
