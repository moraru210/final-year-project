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
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

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

	rematch_map, err := ebpf.LoadPinnedMap(rematch_map_path, nil)
	if err != nil {
		fmt.Printf("Could not open %s\n", rematch_map_path)
	}

	defer conn_map.Close()
	defer numbers_map.Close()
	defer available_map.Close()
	defer state_map.Close()

	// Set up servers
	fmt.Printf("reached this section\n")
	setUpServerConnections(no_workers, no_clients, available_map)

	// Set up listener for clients
	go startLB(no_workers, available_map, conn_map, state_map, numbers_map, rematch_map)

	// Set up rematcher
	go rematchControl(available_map, conn_map, rematch_map)

	// Wait for interrupt signal
	<-interrupt
	fmt.Println("\nInterrupt signal received. Cleaning up...")
}

func rematchControl(available_map *ebpf.Map, conn_map *ebpf.Map, rematch_map *ebpf.Map) {
	fmt.Printf("Stated rematcher\n")

	var c_no, s_no uint32

	for {
		fmt.Print("Enter two integers separated by a space: \n")
		_, err := fmt.Scanf("%d %d", &c_no, &s_no)
		if err != nil {
			fmt.Println("Invalid input. Please enter two integers separated by a space.")
			continue
		}

		fmt.Printf("Rematch: client_no %d and server_no %d\n", c_no, s_no)
		rematch(c_no, s_no, available_map, conn_map, rematch_map)
	}
}

func rematch(client_src_port, server_no uint32, available_map *ebpf.Map, conn_map *ebpf.Map, rematch_map *ebpf.Map) {
	server := Server{
		Port: server_no,
		Ip:   uint32(C.inet_addr(C.CString("0x7f000001"))),
	}
	server_conn, index := grabServerConn(server, available_map)
	if server_conn == nil {
		fmt.Printf("Rematcher: Not able to grab a server\n")
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
		fmt.Printf("Rematcher: Not able to lookup reroute for given client_conn: %v\n", err)
		return
	}
	fmt.Printf("Rematcher - check: original_conn.src %d, original_conn.dst %d\n", reroute.Original_conn.Src_port, reroute.Original_conn.Dst_port)

	reroute.New_conn = *server_conn
	reroute.New_index = uint32(index)
	reroute.Rematch_flag = 1

	if err := conn_map.Put(client_conn, reroute); err != nil {
		fmt.Printf("Rematcher: Not able to put rematch in conn_map: %v\n", err)
	}

	if err := rematch_map.Put(uint32(client_src_port), uint32(1)); err != nil {
		fmt.Printf("Rematcher: unable to set rematch to 1 for %d\n", uint32(client_src_port))
	}
}

func startLB(no_workers int, available_map *ebpf.Map, conn_map *ebpf.Map, state_map *ebpf.Map, numbers_map *ebpf.Map, rematch_map *ebpf.Map) {
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
		insertToRematchMap(connStruct.Src_port, 0, rematch_map)

		setInitialOffsets(connStruct, *server_conn, numbers_map)
	}
}

func setInitialOffsets(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map) {
	client_n, server_n, err := grabNumbersForConns(client_conn, server_conn, numbers_map)
	if err != nil {
		fmt.Printf("client_n or server_n returned as nil, hence exit setInitialOffests\n")
		return
	}

	calculateAndUpdateOffsets(client_conn, server_conn, numbers_map, client_n, server_n)
}

func calculateAndUpdateOffsets(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map, client_n Numbers, server_n Numbers) {
	client_n.Seq_offset = int32(client_n.Seq_no - server_n.Ack_no)
	client_n.Ack_offset = int32(client_n.Ack_no - server_n.Seq_no)

	server_n.Seq_offset = int32(server_n.Seq_no - client_n.Ack_no)
	server_n.Ack_offset = int32(server_n.Ack_no - client_n.Seq_no)

	if err := numbers_map.Put(client_conn, client_n); err != nil {
		fmt.Printf("Not able to include offsets in client_numbers to numbers_map: %v\n", err)
	}

	rev_server := reverseConn(server_conn)
	if err := numbers_map.Put(rev_server, server_n); err != nil {
		fmt.Printf("Not able to include offsets in server_numbers to numbers_map: %v\n", err)
	}
}

func grabNumbersForConns(client_conn Connection, server_conn Connection, numbers_map *ebpf.Map) (Numbers, Numbers, error) {
	var client_n Numbers
	var server_n Numbers

	err := numbers_map.Lookup(client_conn, &client_n)
	if err != nil {
		fmt.Printf("Initial Offsets: unable to retrieve numbers for client_conn\n")
	} else {
		fmt.Printf("server.SrcPort is  %d server.DstPort is %d\n", server_conn.Src_port, server_conn.Dst_port)
		rev_server := reverseConn(server_conn)
		fmt.Printf("rev_server.SrcPort is  %d rev_server.DstPort is %d\n", rev_server.Src_port, rev_server.Dst_port)
		err = numbers_map.Lookup(rev_server, &server_n)
		if err != nil {
			fmt.Printf("Initial Offsets: unable to retrieve numbers for server_conn: %v\n", err)
		}
	}

	return client_n, server_n, err
}

func insertToStateMap(client_port uint32, state uint32, state_map *ebpf.Map) {
	if err := state_map.Put(client_port, state); err != nil {
		fmt.Printf("Unable to insert an init state for conn: %v\n", err)
	}
}

func insertToRematchMap(client_port uint32, rematch_flag uint32, rematch_map *ebpf.Map) {
	if err := rematch_map.Put(client_port, rematch_flag); err != nil {
		fmt.Printf("Unable to insert an init rematch_flag for conn: %v\n", err)
	}
}

func insertToConnMap(client_conn Connection, server_conn Connection, conn_map *ebpf.Map, index int) {
	reroute := Reroute{
		Original_conn:  server_conn,
		Rematch_flag:   uint32(0),
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
		Rematch_flag:   uint32(0),
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

	// Set the socket options
	tcpConn := conn.(*net.TCPConn)
	tcpConn.SetLinger(0)
	// Disable TCP keep-alive on the accepted connection
	tcpConn.SetKeepAlive(false)
	tcpConn.SetKeepAlivePeriod(0)

	fmt.Println("Accepted connection")
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
			fmt.Println(conn_dest)
			conn, err := net.Dial("tcp", conn_dest)
			if err != nil {
				// Handle the error appropriately
				fmt.Printf("<i: %d, j: %d> Failed to connect to localhost:417%d: %v\n", i, j, i, err)
			}

			// Disable TCP keep-alive
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetKeepAlive(false)
			}

			// Insert this new connection to available map
			// Conn in this instance is localP: X, remoteP: 417Y
			insertToAvailableMap(conn, available_map, j, no_workers)
		}
	}
	fmt.Println("Completed setting up server connections")
}

func insertToAvailableMap(conn net.Conn, available_map *ebpf.Map, index int, no_workers int) {
	// Create key
	remAddr := conn.RemoteAddr().(*net.TCPAddr)
	lo_ip := uint32(C.inet_addr(C.CString("0x7f000001")))
	server := Server{
		Port: uint32(remAddr.Port),
		Ip:   lo_ip,
	}
	fmt.Printf("Server key for available_map is .port %d and .ip %d\n", server.Port, server.Ip)

	// If first index, then create new availability - else grab and update
	connStruct := convertToConnStruct(conn)
	var availability Availability
	if index == 0 {
		availability = Availability{
			Conns: [2]Connection{},
			Valid: [2]uint32{},
		}
	} else {
		if err := available_map.Lookup(server, &availability); err != nil {
			fmt.Printf("not able to find avaialability for connStruct with src_p %d and dst_p %d\n", connStruct.Src_port, connStruct.Dst_port)
		}
	}
	fmt.Printf("len of availability arrays: %d\n", len(availability.Conns))
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
