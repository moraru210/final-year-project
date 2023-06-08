package main

/*
#cgo CFLAGS: -g -Wall
#include <arpa/inet.h>
#include <stdint.h>
*/
import "C"
import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	ebpf "github.com/cilium/ebpf"
)

const (
	connection_map_path = "/sys/fs/bpf/lo/conn_map"
	numbers_map_path    = "/sys/fs/bpf/lo/numbers_map"
	available_map_path  = "/sys/fs/bpf/lo/available_map"
	rematch_map_path    = "/sys/fs/bpf/lo/rematch_map"
	first_server_no     = 4171
)

var (
	round_robin     = 0
	last_server_no  = first_server_no
	current_targets []net.Conn
	lb_ip           = net.ParseIP("127.0.0.1")
)

func main() {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

	fmt.Println("MAX_CLIENTS: ", MAX_CLIENTS)
	fmt.Println("MAX_SERVERS: ", MAX_SERVERS)

	//initial number of servers
	no_workers, err := strconv.Atoi(os.Args[1])
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
	lb_ip = lb_ip.To4() // Ensure it's an IPv4 address
	if lb_ip == nil {
		fmt.Printf("Invalid IPv4 address: %s\n", lb_ip)
		return
	}

	u32_ip := binary.BigEndian.Uint32(lb_ip)
	fmt.Printf("Servers - setting up connection to servers on %s: %d\n", lb_ip, u32_ip)
	setUpServerConnections(no_workers, available_map, lb_ip)
	fmt.Printf("Servers - completed servers setup\n")

	// Set up listener for clients
	fmt.Printf("LB - start\n")
	go startLB(no_workers, available_map, conn_map, numbers_map, lb_ip)

	// // Set up rematcher
	fmt.Printf("Rematcher - start\n")
	go controlPanel(available_map, conn_map, numbers_map)

	// Wait for interrupt signal
	<-interrupt
	fmt.Println("\nInterrupt signal received. Cleaning up...")
}

func controlPanel(available_map *ebpf.Map, conn_map *ebpf.Map, numbers_map *ebpf.Map) {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("*** CONTROL PANEL ***\n")
		fmt.Println("Enter your choice:")
		fmt.Println("Options: 1. rematch <client_addr> <server_addr>")
		fmt.Println("         2. add <quantity>")
		fmt.Println("         3. remove <quantity>")

		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		// Split input by space to separate the command and arguments
		parts := strings.Split(input, " ")

		if len(parts) == 0 {
			continue
		}

		// Extract the command
		command := parts[0]

		// Handle the different commands
		switch command {
		case "rematch":
			if len(parts) != 3 {
				fmt.Println("Invalid number of arguments for rematch.")
				continue
			}
			clientAddr := parts[1]
			serverAddr := parts[2]
			fmt.Printf("Rematch: client_addr=%s, server_addr=%s\n", clientAddr, serverAddr)
			client_ip, client_port, err := handleAddr(clientAddr)
			if err != nil {
				fmt.Printf("Parsing error: %v\n", err)
				continue
			}
			server_ip, server_port, err := handleAddr(serverAddr)
			if err != nil {
				fmt.Printf("Parsing error: %v\n", err)
				continue
			}

			rematch(client_port, client_ip, server_port, server_ip, available_map, conn_map)

		case "add":
			if len(parts) != 2 {
				fmt.Println("Invalid number of arguments for add.")
				continue
			}
			quantity, err := strconv.Atoi(parts[1])
			if err != nil {
				fmt.Println("Invalid quantity for add.")
				continue
			}
			fmt.Println("Add:", quantity)
			addServers(quantity, available_map, lb_ip)

		case "remove":
			if len(parts) != 2 {
				fmt.Println("Invalid number of arguments for rematch.")
				continue
			}
			serverAddr := parts[1]
			fmt.Printf("Remove: server_addr=%s\n", serverAddr)
			server_ip, server_port, err := handleAddr(serverAddr)
			if err != nil {
				fmt.Printf("Parsing error: %v\n", err)
				continue
			}
			removeTarget(server_port, numbers_map, available_map, server_ip)

		default:
			fmt.Println("Invalid command.")
		}

		fmt.Print("*********\n")
	}
}

func removeTarget(target_port uint32, numbers_map *ebpf.Map, available_map *ebpf.Map, ipAddr net.IP) {
	// Assumption: there is no session left utilising this server
	to_delete := delete_from_current(target_port, ipAddr)

	delete_from_numbers_map(to_delete, numbers_map, ipAddr)
	delete_from_available_map(target_port, available_map, ipAddr)

	for _, conn := range to_delete {
		conn.Close()
	}
}

func delete_from_available_map(target_port uint32, available_map *ebpf.Map, ipAddr net.IP) {
	server := Server{
		Port: target_port,
		Ip:   binary.BigEndian.Uint32(ipAddr),
	}

	available_map.Delete(server)
}

func delete_from_numbers_map(to_delete []net.Conn, numbers_map *ebpf.Map, ipAddr net.IP) {
	for _, conn := range to_delete {
		remote_addr := conn.RemoteAddr().(*net.TCPAddr)
		local_addr := conn.LocalAddr().(*net.TCPAddr)

		key := Connection{
			Src_port: uint32(local_addr.Port),
			Dst_port: uint32(remote_addr.Port),
			Src_ip:   binary.BigEndian.Uint32(net.IP(lb_ip)),
			Dst_ip:   binary.BigEndian.Uint32(ipAddr),
		}

		numbers_map.Delete(key)
	}
}

func delete_from_current(target_port uint32, ipAddr net.IP) []net.Conn {
	var to_delete []net.Conn
	for i := 0; i < len(current_targets); i++ {
		current_conn := current_targets[i]
		remote_addr := current_conn.RemoteAddr().(*net.TCPAddr)
		if uint32(remote_addr.Port) == target_port && remote_addr.IP.String() == ipAddr.String() {
			to_delete = append(to_delete, current_conn)
			current_targets = append(current_targets[:i], current_targets[i+1:]...)
			i--
		}
	}
	return to_delete
}

func handleAddr(address string) (net.IP, uint32, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		fmt.Println("Invalid address:", err)
		return nil, 0, err
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, errors.New("Invalid IP address")
	}

	ip = ip.To4()
	if ip == nil {
		return nil, 0, errors.New("Not a valid IPv4 address")
	}

	port, err := strconv.ParseUint(portString, 10, 32)
	if err != nil {
		fmt.Println("Invalid port number:", err)
		return nil, 0, err
	}

	fmt.Println("IP:", ip.String())
	fmt.Println("Port:", uint32(port))
	return ip, uint32(port), nil
}

func rematch(client_src_port uint32, client_ip net.IP, server_no uint32, server_ip net.IP, available_map *ebpf.Map, conn_map *ebpf.Map) {
	server := Server{
		Port: server_no,
		Ip:   binary.BigEndian.Uint32(server_ip),
	}
	server_conn, index := grabServerConn(server, available_map)
	if server_conn == nil {
		fmt.Printf("Rematcher - Error: Not able to grab a server\n")
		return
	}

	client_conn := Connection{
		Src_port: uint32(client_src_port),
		Dst_port: uint32(8080),
		Src_ip:   binary.BigEndian.Uint32(client_ip),
		Dst_ip:   binary.BigEndian.Uint32(server_ip),
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

func startLB(no_workers int, available_map *ebpf.Map, conn_map *ebpf.Map, numbers_map *ebpf.Map, ipAddr net.IP) {
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

		server_conn, index := chooseServerConn(no_workers, available_map, ipAddr)
		if server_conn == nil {
			fmt.Printf("LB - Error: not able to choose a server conn\n")
			continue
		}

		servStruct := *server_conn
		connStruct := reverseConn(convertToConnStruct(conn))
		fmt.Printf("LB - Client conn.srcPort %d conn.dstPort %d, conn.SrcIP %d, conn.DstIP %d\n", connStruct.Src_port, connStruct.Dst_port, connStruct.Src_ip, connStruct.Dst_ip)
		fmt.Printf("LB - Server conn.src %d conn.dst %d\n", servStruct.Src_port, servStruct.Dst_port)

		var nums Numbers
		if err := numbers_map.Lookup(connStruct, &nums); err != nil {
			fmt.Printf("LB - Error: unable to retrieve numbers for (conn.src %d, conn.dst %d, conn.SrcIP %d, conn.DstIP %d): %v\n", connStruct.Src_port, connStruct.Dst_port, connStruct.Src_ip, connStruct.Dst_ip, err)
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

func chooseServerConn(no_workers int, available_map *ebpf.Map, ipAddr net.IP) (*Connection, int) {
	chosen_server_port := first_server_no + (round_robin % no_workers)
	round_robin += 1
	chosen_server := Server{
		Port: uint32(chosen_server_port),
		Ip:   binary.BigEndian.Uint32(ipAddr),
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
	fmt.Printf("Found at index: %d\n", index)
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
	for i := 0; i < len(availability.Valid); i++ {
		fmt.Printf("Index: %d, valid: %d, conn.src: %d\n", i, availability.Valid[i], availability.Conns[i].Src_port)
		if availability.Valid[i] == 0 {
			return &availability.Conns[i], i
		}
	}
	return nil, -1
}

func setUpServerConnections(no_workers int, available_map *ebpf.Map, ipAddr net.IP) {
	for i := 0; i < no_workers; i++ {
		for j := 0; j < MAX_CLIENTS; j++ {
			server := first_server_no + i
			newServer(server, j, available_map, ipAddr)
		}
	}
	last_server_no = 4170 + no_workers
}

func addServers(quanity int, available_map *ebpf.Map, ipAddr net.IP) {
	start := (last_server_no - 4170) + 1
	end := start + quanity
	if end-1 > MAX_SERVERS {
		fmt.Printf("Unable to add %d, since it will become above limit\n", quanity)
	}
	for i := start; i < end; i++ {
		for j := 0; j < MAX_CLIENTS; j++ {
			newServer(i, j, available_map, ipAddr)
		}
	}
	last_server_no = end - 1
}

func newServer(target_index int, conn_index int, available_map *ebpf.Map, ipAddr net.IP) {
	conn_dest := fmt.Sprintf("%s:%d", ipAddr.String(), target_index)
	conn, err := net.Dial("tcp", conn_dest)
	if err != nil {
		// Handle the error appropriately
		fmt.Printf("<i: %s, j: %d> Failed to connect to %s: %v\n", ipAddr.String(), conn_index, ipAddr.String(), err)
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
	insertToAvailableMap(conn, available_map, conn_index, ipAddr)

	current_targets = append(current_targets, conn)
}

func insertToAvailableMap(conn net.Conn, available_map *ebpf.Map, index int, ipAddr net.IP) {
	// Create key
	remAddr := conn.RemoteAddr().(*net.TCPAddr)
	server := Server{
		Port: uint32(remAddr.Port),
		Ip:   binary.BigEndian.Uint32(ipAddr),
	}
	//fmt.Printf("Server key for available_map is .port %d and .ip %d\n", server.Port, server.Ip)

	// If first index, then create new availability - else grab and update
	connStruct := convertToConnStruct(conn)
	var availability Availability
	if index == 0 {
		availability = Availability{
			Conns: [MAX_CLIENTS]Connection{},
			Valid: [MAX_CLIENTS]uint32{},
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
	c_rem_ip := c_remoteAddr.IP.String()
	c_rem_port := uint32(c_remoteAddr.Port)

	c_localAddr := conn.LocalAddr().(*net.TCPAddr)
	c_loc_ip := c_localAddr.IP.String()
	c_loc_port := uint32(c_localAddr.Port)

	fmt.Println("local ip is: ", c_loc_ip)

	c := Connection{
		Src_port: c_loc_port,
		Dst_port: c_rem_port,
		Src_ip:   binary.BigEndian.Uint32(net.ParseIP(c_rem_ip).To4()),
		Dst_ip:   binary.BigEndian.Uint32(net.ParseIP(c_loc_ip).To4()),
	}

	fmt.Printf("conn srcPort: %d, dstPort %d, srcIP: %d, dstIP: %d\n", c.Src_port, c.Dst_port, c.Src_ip, c.Dst_ip)
	return c
}

func reverseConn(conn Connection) Connection {
	var new_conn Connection
	new_conn.Src_port = conn.Dst_port
	new_conn.Dst_port = conn.Src_port
	new_conn.Src_ip = conn.Dst_ip
	new_conn.Dst_ip = conn.Src_ip
	return new_conn
}
