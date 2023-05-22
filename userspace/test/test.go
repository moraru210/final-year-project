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
	"os"
	"strconv"

	ebpf "github.com/cilium/ebpf"
)

const (
	connection_map_path = "/sys/fs/bpf/lo/conn_map"
	numbers_map_path    = "/sys/fs/bpf/lo/numbers_map"
	available_map_path  = "/sys/fs/bpf/lo/available_map"
	state_map_path      = "/sys/fs/bpf/lo/state_map"
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
	Rematch_flag   uint32
	Original_index uint32
	New_conn       Connection
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
	Conns []Connection
	Valid []uint32
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

	state_map, err := ebpf.LoadPinnedMap(state_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", state_map_path)
	}

	defer conn_map.Close()
	defer numbers_map.Close()
	defer available_map.Close()
	defer state_map.Close()

	// Set up servers
	setUpServerConnections(no_workers, no_clients, available_map)

	// Set up listener for clients
	go startLB(no_workers, available_map, conn_map, state_map, numbers_map)
}

func startLB(no_workers int, available_map *ebpf.Map, conn_map *ebpf.Map, state_map *ebpf.Map, numbers_map *ebpf.Map) {
	ln := startListener()
	if ln == nil {
		return
	}
	defer ln.Close()

	for {
		conn := acceptConnection(ln)
		if conn == nil {
			continue
		}
		defer conn.Close()

		server_conn, index := chooseServerConn(no_workers, available_map)
		if server_conn == nil {
			fmt.Printf("not able to choose a server conn\n")
			continue
		}

		connStruct := reverseConn(convertToConnStruct(conn))
		fmt.Printf("Client conn.src %d conn.dst %d\n", connStruct.Src_port, connStruct.Dst_port)
		insertToConnMap(connStruct, *server_conn, conn_map, index)
		insertToStateMap(connStruct.Src_port, 0, state_map)

		setInitialOffsets(connStruct, *server_conn, numbers_map)
	}
}

func setInitialOffsets(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map) {
	var (
		client_n *Numbers
		server_n *Numbers
	)
	grabNumbersForConns(client_conn, server_conn, numbers_map, client_n, server_n)
	if client_n == nil || server_n == nil {
		fmt.Printf("client_n or server_n returned as nil, hence exit setInitialOffests\n")
	}

	calculateAndUpdateOffsets(client_conn, server_conn, numbers_map, *client_n, *server_n)
}

func calculateAndUpdateOffsets(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map, client_n Numbers, server_n Numbers) {
	client_n.Seq_offset = int32(client_n.Seq_no - server_n.Ack_no)
	client_n.Ack_offset = int32(client_n.Ack_no - server_n.Seq_no)

	server_n.Seq_offset = int32(server_n.Seq_no - client_n.Ack_no)
	server_n.Ack_offset = int32(server_n.Ack_no - client_n.Seq_no)

	if err := numbers_map.Put(client_conn, client_n); err != nil {

	}

	if err := numbers_map.Put(server_conn, server_n); err != nil {

	}
}

func grabNumbersForConns(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map, client_n *Numbers, server_n *Numbers) {
	if err := numbers_map.Lookup(client_conn, client_n); err != nil {
		fmt.Printf("Initial Offsets: unable to retrieve numbers for client_conn\n")
		return
	}

	rev_server := reverseConn(server_conn)
	if err := numbers_map.Lookup(rev_server, server_n); err != nil {
		fmt.Printf("Initial Offsets: unable to retrieve numbers for client_conn\n")
	}
}

func insertToStateMap(client_port uint32, state uint32, state_map *ebpf.Map) {
	if err := state_map.Put(client_port, state); err != nil {
		fmt.Printf("Unable to insert an init state for conn: %v\n", err)
	}
}

func insertToConnMap(client_conn Connection, server_conn Connection, conn_map *ebpf.Map, index int) {
	reroute := Reroute{
		Original_conn:  server_conn,
		Original_index: uint32(index),
		New_conn:       server_conn,
		New_index:      uint32(index),
	}
	if err := conn_map.Put(client_conn, reroute); err != nil {
		fmt.Printf("Unable to insert server reroute for client_conn in conn_map: %v\n", err)
		return
	}

	rev_client := reverseConn(client_conn)
	rev_server := reverseConn(server_conn)

	rev_reroute := Reroute{
		Original_conn:  rev_client,
		Original_index: uint32(0),
		New_conn:       rev_client,
		New_index:      uint32(0),
	}
	if err := conn_map.Put(rev_server, rev_reroute); err != nil {
		fmt.Printf("Unable to insert client reroute for rev(server_conn) in conn_map: %v\n", err)
	}
}

func startListener() net.Listener {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("Error listening:", err.Error())
		return nil
	}
	return ln
}

func acceptConnection(ln net.Listener) net.Conn {
	conn, err := ln.Accept()
	if err != nil {
		fmt.Printf("Failed to accept incoming connection: %v\n", err)
		return nil
	}
	fmt.Println("Accepted connection")
	return conn
}

func chooseServerConn(no_workers int, available_map *ebpf.Map) (*Connection, int) {
	chosen_server := first_server_no + (round_robin % no_workers)
	var availability Availability
	if err := available_map.Lookup(chosen_server, &availability); err != nil {
		fmt.Printf("Failed to lookup availability from map for client conn: %v\n", err)
		return nil, -1
	}

	conn_ptr, index := findAvailableConn(availability)
	if conn_ptr == nil {
		fmt.Printf("Unable to find a valid connection in availability struct\n")
	}
	return conn_ptr, index
}

func findAvailableConn(availability Availability) (*Connection, int) {
	for i, conn := range availability.Conns {
		if availability.Valid[i] == 1 {
			availability.Valid[i] = 0
			return &conn, i
		}
	}
	return nil, -1
}

func setUpServerConnections(no_workers int, no_clients int, available_map *ebpf.Map) {
	for i := 1; i <= no_workers; i++ {
		for j := 0; j < no_clients; j++ {

			conn_dest := fmt.Sprintf("locahost:417%d", i)
			conn, err := net.Dial("tcp", conn_dest)
			if err != nil {
				// Handle the error appropriately
				fmt.Printf("<i: %d, j: %d> Failed to connect to localhost:417%d: %v\n", i, j, i, err)
			}

			// Insert this new connection to available map
			// Conn in this instance is localP: X, remoteP: 417Y
			insertToAvailableMap(conn, available_map, j, no_workers)
		}
	}
}

func insertToAvailableMap(conn net.Conn, available_map *ebpf.Map, index int, no_workers int) {
	// Create key
	remAddr := conn.RemoteAddr().(*net.TCPAddr)
	lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
	server := Server{
		Port: uint32(remAddr.Port),
		Ip:   lo_ip,
	}

	// If first index, then create new availability - else grab and update
	connStruct := convertToConnStruct(conn)
	var availability Availability
	if index == 0 {
		availability = Availability{
			Conns: make([]Connection, no_workers),
			Valid: make([]uint32, no_workers),
		}
	} else {
		if err := available_map.Lookup(connStruct, &availability); err != nil {
			fmt.Printf("not able to find avaialability for connStruct with src_p %d and dst_p %d\n", connStruct.Src_port, connStruct.Dst_port)
		}
	}
	availability.Conns[index] = connStruct
	availability.Valid[index] = 0

	// Put into bpf map
	if err := available_map.Put(server, availability); err != nil {
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
		Src_ip:   lo_ip,
		Dst_ip:   lo_ip,
	}

	fmt.Printf("conn src: %d and dst %d\n", c.Src_port, c.Dst_port)
	return c
}

func generateDummyConn() Connection {
	lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
	dummy := Connection{
		Src_port: 0,
		Dst_port: 0,
		Src_ip:   lo_ip,
		Dst_ip:   lo_ip,
	}
	return dummy
}

func reverseConn(conn Connection) Connection {
	var new_conn Connection
	new_conn.Src_port = conn.Dst_port
	new_conn.Dst_port = conn.Src_port
	new_conn.Src_ip = conn.Dst_ip
	new_conn.Dst_ip = conn.Src_ip
	return new_conn
}
