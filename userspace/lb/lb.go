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
	"os/signal"
	"strconv"
	"syscall"

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
	Original_index uint32
	Seq_offset     int32
	Ack_offset     int32
	Rematch_flag   uint32
	New_conn       Connection
	New_index      uint32
}

type Numbers struct {
	Seq_no   uint32
	Ack_no   uint32
	Init_seq uint32
	Init_ack uint32
}

type Server struct {
	Port uint32
	Ip   uint32
}

type Availability struct {
	Conns []Connection
	Valid []uint32 //signifies that conn is in use if 1
}

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	//input parsing
	if len(os.Args) != 3 {
		fmt.Println("Usage: .\\lb <integer> <integer>")
		os.Exit(1)
	}

	no_clients, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("No first argument (no_clients) detected - default: 2")
		no_clients = 2
	}

	no_workers, err := strconv.Atoi(os.Args[2])
	if err != nil {
		fmt.Println("No second argument (no_workers) detected - default: 2")
		no_workers = 2
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

	defer conn_map.Close()
	defer numbers_map.Close()
	defer available_map.Close()

	// Set up servers
	fmt.Printf("Servers - setting up connection to servers\n")
	setUpServerConnections(no_workers, no_clients, available_map)
	fmt.Printf("Servers - completed servers setup\n")

	// Set up listener for clients
	fmt.Printf("LB - start")
	go startLB(no_workers, available_map, conn_map, numbers_map)

	// // Set up rematcher
	fmt.Printf("Rematcher - start")
	go rematchControl(available_map, conn_map)

	// Wait for interrupt signal
	<-interrupt
	fmt.Println("\nInterrupt signal received. Cleaning up...")
}

func rematchControl(available_map *ebpf.Map, conn_map *ebpf.Map) {
	var c_no, s_no uint32

	for {
		fmt.Print("Rematcher - Enter two integers separated by a space: \n")
		_, err := fmt.Scanf("%d %d", &c_no, &s_no)
		if err != nil {
			fmt.Println("Invalid input. Please enter two integers separated by a space.")
			continue
		}

		fmt.Printf("Rematcher - rematch: client_no %d and server_no %d\n", c_no, s_no)
		rematch(c_no, s_no, available_map, conn_map)
	}
}

func rematch(client_src_port, server_no uint32, available_map *ebpf.Map, conn_map *ebpf.Map) {
	server := Server{
		Port: server_no,
		Ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
	}
	server_conn, index := grabServerConn(server, available_map)
	if server_conn == nil {
		fmt.Printf("Rematcher - Error: Not able to grab a server\n")
		return
	}

	client_conn := Connection{
		Src_port: uint32(client_src_port),
		Dst_port: uint32(8080),
		Src_ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
		Dst_ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
	}
	var reroute Reroute
	if err := conn_map.Lookup(client_conn, &reroute); err != nil {
		fmt.Printf("Rematcher - Error: Not able to lookup reroute for given client_conn: %v\n", err)
		return
	}
	//fmt.Printf("Rematcher - check: original_conn.src %d, original_conn.dst %d\n", reroute.Original_conn.Src_port, reroute.Original_conn.Dst_port)

	reroute.New_conn = *server_conn
	reroute.New_index = uint32(index)
	reroute.Rematch_flag = uint32(1)

	if err := conn_map.Put(client_conn, reroute); err != nil {
		fmt.Printf("Rematcher - Error: not able to put rematch in conn_map: %v\n", err)
	}
}

func startLB(no_workers int, available_map *ebpf.Map, conn_map *ebpf.Map, numbers_map *ebpf.Map) {
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
			fmt.Printf("LB - Error: not able to choose a server conn\n")
			continue
		}

		servStruct := *server_conn
		connStruct := reverseConn(convertToConnStruct(conn))
		fmt.Printf("LB - Client conn.src %d conn.dst %d\n", connStruct.Src_port, connStruct.Dst_port)
		fmt.Printf("LB - Server conn.src %d conn.dst %d\n", servStruct.Src_port, servStruct.Dst_port)

		var nums Numbers
		if err := numbers_map.Lookup(connStruct, &nums); err != nil {
			fmt.Printf("LB - Error: unable to retrieve numbers for (conn.src %d, conn.dst %d): %v\n", connStruct.Src_port, connStruct.Dst_port, err)
			os.Exit(1)
		}

		client_reroute, server_reroute, err := getReroutes(connStruct, servStruct, numbers_map, index)
		if err != nil {
			fmt.Printf("LB - Error: unable to retrieve reroutes for connections: %v\n", err)
			os.Exit(1)
		}

		revServer := reverseConn(servStruct)
		insertToConnMap(connStruct, client_reroute, conn_map)
		insertToConnMap(revServer, server_reroute, conn_map)
	}
}

func getReroutes(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map, index int) (Reroute, Reroute, error) {
	client_n, server_n, err := grabNumbersForConns(client_conn, server_conn, numbers_map)
	if err != nil {
		fmt.Printf("LB - Error: client_n or server_n returned as nil, hence exit setInitialOffests: %v\n", err)
		return Reroute{}, Reroute{}, err
	}

	c_seq_off, c_ack_off := calculateOffsets(client_n, server_n)
	client_reroute := Reroute{
		Original_conn:  server_conn,
		Original_index: uint32(index),
		Seq_offset:     c_seq_off,
		Ack_offset:     c_ack_off,
		Rematch_flag:   uint32(0),
		New_conn:       server_conn,
		New_index:      uint32(index),
	}

	s_ack_off, s_seq_off := calculateOffsets(server_n, client_n)
	rev_client_conn := reverseConn(client_conn)
	server_reroute := Reroute{
		Original_conn:  rev_client_conn,
		Original_index: uint32(index),
		Seq_offset:     s_seq_off,
		Ack_offset:     s_ack_off,
		Rematch_flag:   uint32(0),
		New_conn:       rev_client_conn,
		New_index:      uint32(index),
	}

	return client_reroute, server_reroute, nil
}

func calculateOffsets(conn_n Numbers, other_n Numbers) (int32, int32) {
	seq_offset := int32(conn_n.Seq_no - other_n.Seq_no)
	ack_offset := int32(conn_n.Ack_no - other_n.Ack_no)
	return seq_offset, ack_offset
}

func grabNumbersForConns(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map) (Numbers, Numbers, error) {
	var client_n Numbers
	var server_n Numbers

	err := numbers_map.Lookup(client_conn, &client_n)
	if err != nil {
		fmt.Printf("LB - Initial Offsets: unable to retrieve numbers for client_conn: %v\n", err)
	} else {
		//fmt.Printf("server.SrcPort is  %d server.DstPort is %d\n", server_conn.Src_port, server_conn.Dst_port)
		err = numbers_map.Lookup(server_conn, &server_n)
		if err != nil {
			fmt.Printf("LB - Initial Offsets: unable to retrieve numbers for server_conn: %v\n", err)
		}
	}

	return client_n, server_n, err
}

func insertToStateMap(client_port uint32, state uint32, state_map *ebpf.Map) {
	if err := state_map.Put(client_port, state); err != nil {
		fmt.Printf("LB - Unable to insert an init state for conn: %v\n", err)
	}
}

func insertToConnMap(conn Connection, reroute Reroute, conn_map *ebpf.Map) {
	if err := conn_map.Put(conn, reroute); err != nil {
		fmt.Printf("Unable to insert server reroute for (conn.src: %d, conn.dst: %d) in conn_map: %v\n", conn.Src_port, conn.Dst_port, err)
		os.Exit(1)
	}
}

func startListener() net.Listener {
	ln, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println("LB - Error listening:", err.Error())
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

	// Set the socket options
	tcpConn := conn.(*net.TCPConn)
	tcpConn.SetLinger(0)
	// Disable TCP keep-alive on the accepted connection
	tcpConn.SetKeepAlive(false)
	tcpConn.SetKeepAlivePeriod(0)
	//tcpConn.SetReadBuffer(0)

	err = tcpConn.SetNoDelay(true) // Disable Nagle's algorithm
	if err != nil {
		fmt.Println("LB - Error setting TCP_NODELAY option:", err.Error())
		// Handle the error gracefully, e.g., log it and continue accepting connections
		return nil
	}

	//fmt.Println("Accepted connection")
	return conn
}

func chooseServerConn(no_workers int, available_map *ebpf.Map) (*Connection, int) {
	chosen_server_port := first_server_no + (round_robin % no_workers)
	round_robin += 1
	chosen_server := Server{
		Port: uint32(chosen_server_port),
		Ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
	}

	return grabServerConn(chosen_server, available_map)
}

func grabServerConn(server Server, available_map *ebpf.Map) (*Connection, int) {
	var availability Availability
	if err := available_map.Lookup(server, &availability); err != nil {
		fmt.Printf("Failed to lookup availability from map for client conn: %v\n", err)
		return nil, -1
	}

	conn_ptr, index := findAvailableConn(availability)
	if conn_ptr == nil {
		fmt.Printf("Unable to find a valid connection in availability struct\n")
		return nil, -1
	}

	if index >= 0 && index < len(availability.Valid) {
		availability.Valid[index] = 1
	} else {
		fmt.Printf("Unable to update avaialability.Valid[index] since index %d out of range\n", index)
		return nil, -1
	}

	if err := available_map.Put(server, availability); err != nil {
		fmt.Printf("Failed to put updated avaialability in map: %v\n", err)
		return nil, -1
	}

	return conn_ptr, index
}

func findAvailableConn(availability Availability) (*Connection, int) {
	for i, conn := range availability.Conns {
		if availability.Valid[i] == 0 {
			return &conn, i
		}
	}
	return nil, -1
}

func setUpServerConnections(no_workers int, no_clients int, available_map *ebpf.Map) {
	for i := 1; i <= no_workers; i++ {
		for j := 0; j < no_clients; j++ {

			conn_dest := fmt.Sprintf("localhost:417%d", i)
			//fmt.Println(conn_dest)
			conn, err := net.Dial("tcp", conn_dest)
			if err != nil {
				// Handle the error appropriately
				fmt.Printf("<i: %d, j: %d> Failed to connect to localhost:417%d: %v\n", i, j, i, err)
				os.Exit(1)
			}

			// Set the socket options
			tcpConn := conn.(*net.TCPConn)
			tcpConn.SetLinger(0)
			// Disable TCP keep-alive on the accepted connection
			tcpConn.SetKeepAlive(false)
			tcpConn.SetKeepAlivePeriod(0)

			err = tcpConn.SetNoDelay(true) // Disable Nagle's algorithm
			if err != nil {
				fmt.Println("Error setting TCP_NODELAY option:", err.Error())
				// Handle the error gracefully, e.g., log it and continue accepting connections
				os.Exit(1)
			}

			// Insert this new connection to available map
			// Conn in this instance is localP: X, remoteP: 417Y
			insertToAvailableMap(conn, available_map, j, no_clients)
		}
	}
}

func insertToAvailableMap(conn net.Conn, available_map *ebpf.Map, index int, no_clients int) {
	// Create key
	remAddr := conn.RemoteAddr().(*net.TCPAddr)
	lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
	server := Server{
		Port: uint32(remAddr.Port),
		Ip:   lo_ip,
	}
	//fmt.Printf("Server key for available_map is .port %d and .ip %d\n", server.Port, server.Ip)

	// If first index, then create new availability - else grab and update
	connStruct := convertToConnStruct(conn)
	var availability Availability
	if index == 0 {
		availability = Availability{
			Conns: make([]Connection, no_clients),
			Valid: make([]uint32, no_clients),
		}
	} else {
		if err := available_map.Lookup(server, &availability); err != nil {
			fmt.Printf("not able to find avaialability for connStruct with src_p %d and dst_p %d\n", connStruct.Src_port, connStruct.Dst_port)
		}
	}
	//fmt.Printf("len of availability arrays: %d\n", len(availability.Conns))
	availability.Conns[index] = connStruct
	availability.Valid[index] = uint32(0)

	// Put into bpf map
	if err := available_map.Put(server, availability); err != nil {
		fmt.Printf("Could not insert Conn.src %d Conn.dst %d into Available_map: %v\n", connStruct.Src_port, connStruct.Dst_port, err)
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
