package main

/*
#cgo CFLAGS: -g -Wall
#include <arpa/inet.h>
#include <stdint.h>
*/
import "C"
import (
	"fmt"
	"net"
	ebpf "github.com/cilium/ebpf"
	"os"
	"strconv"
	// "github.com/moraru210/final-year-project/userspace/common"
)

const (
	connection_map_path = "/sys/fs/bpf/lo/conn_map"
	numbers_map_path = "/sys/fs/bpf/lo/numbers_map"
	available_map_path = "/sys/fs/bpf/lo/available_map"
)

type Connection struct {
	Src_port uint32
	Dst_port uint32
	Src_ip uint32
	Dst_ip uint32
}

type Reroute struct {
	Original_conn Connection
	Rematch_flag uint32
	New_conn Connection
	State uint32
}

type Server struct {
	Port uint32
	Ip uint32
}

func main() {
	//input parsing
	if len(os.Args) != 3 {
        fmt.Println("Usage: test <integer> <integer>")
        os.Exit(1)
    }

    no_clients, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Println("Invalid first integer argument")
        os.Exit(1)
    }

	no_workers, err := strconv.Atoi(os.Args[2])
	if err != nil {
        fmt.Println("Invalid second integer argument")
        os.Exit(1)
    }

	//map handling
	conn_map, err := ebpf.LoadPinnedMap(connection_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", connection_map_path)
	}

	numbers_map, err := ebpf.LoadPinnedMap(numbers_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", numbers_map_path)
	}

	available_map, err := ebpf.LoadPinnedMap(available_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", available_map_path)
	}

    // c1 := Connection{
    //     Src_port: 0,
    //     Dst_port: 0,
    //     Src_ip: lo_ip,
    //     Dst_ip: lo_ip,
    // }
	// if err := m.Put(c1, c1); err != nil {
	// 	fmt.Println("could not add to map")
	// } else {
	// 	var v Connection
	// 	if err := m.Lookup(c1, &v); err != nil {
	// 		fmt.Println("could not lookup map")
	// 	}
	// 	fmt.Printf("value retried is %d \n", v.Src_ip)
	// }	

	defer conn_map.Close()
	defer numbers_map.Close()
	defer available_map.Close()

	//Setting up servers
	setUpServerConnections(no_workers, no_clients, available_map)
}

func setUpServerConnections(no_workers int, no_clients int, available_map *ebpf.Map) {
	for i := 1; i <= no_workers; i++ {
		for j:= 0 ; j < no_clients; j++ {
			
			conn_dest := fmt.Sprintf("locahost:417%d", i)
			conn, err := net.Dial("tcp", conn_dest)
			if err != nil {
				// Handle the error appropriately
				fmt.Printf("<i: %d, j: %d> Failed to connect to localhost:417%d: %v\n", i, j, i, err)	
			}

			// Insert this new connection to available map
			// Conn in this instance is localP: X, remoteP: 417Y
			insertToAvailableMap(conn, available_map)
		} 
	}
}

func insertToAvailableMap(conn net.Conn, available_map *ebpf.Map) {
	// Create key
	remAddr := conn.RemoteAddr().(*net.TCPAddr)
	lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
	server := Server{
		Port: uint32(remAddr.Port),
		Ip: lo_ip,
	}

	// Create value
	connStruct := convertToConnStruct(conn)
	dummy_conn := generateDummyConn()
	reroute := Reroute{
		Original_conn: connStruct,
		Rematch_flag: 0,
		New_conn: dummy_conn,
		State: 0,
	}

	// Put into bpf map
	if err := available_map.Put(server, reroute); err != nil{
		fmt.Printf("Could not insert Conn.src %d Conn.dst %d into Available_map\n", connStruct.Src_port, connStruct.Dst_port)
	}
}

func convertToConnStruct(conn net.Conn) Connection {
	c_remoteAddr := conn.RemoteAddr().(*net.TCPAddr)
    //c_rem_ip := c_remoteAddr.IP.String()
    c_rem_port := uint32(c_remoteAddr.Port)

	c_localAddr := conn.LocalAddr().(*net.TCPAddr)
    c_loc_port := uint32(c_localAddr.Port)

    lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
    fmt.Println("lo_ip is: ", lo_ip)

	c := Connection{
		Src_port: c_loc_port,
		Dst_port: c_rem_port,
		Src_ip: lo_ip,
		Dst_ip: lo_ip,
	}

	fmt.Println("conn src: %d and dst %d", c.Src_port, c.Dst_port)
	return c
}

func generateDummyConn() Connection {
	lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
	dummy := Connection{
		Src_port: 0,
		Dst_port: 0,
		Src_ip: lo_ip,
		Dst_ip: lo_ip,
	}
	return dummy
}