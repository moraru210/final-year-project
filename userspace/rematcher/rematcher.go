package rematcher

import (
	"encoding/binary"
	"fmt"
	"net"

	ebpf "github.com/cilium/ebpf"
)

func Rematch(conn_map, numbers_map, available_map *ebpf.Map, client_src_port, server_no uint32, client_ip, server_ip net.IP) {
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

	var nums Numbers
	if err := conn_map.Lookup(client_conn, &nums); err != nil {
		fmt.Printf("Rematcher - Error: Not able to lookup numbers for given client_conn: %v\n", err)
		return
	}
	//fmt.Printf("Rematcher - check: original_conn.src %d, original_conn.dst %d\n", reroute.Original_conn.Src_port, reroute.Original_conn.Dst_port)

	reroute.New_conn = *server_conn
	reroute.New_index = uint32(index)
	reroute.New_eth = nums.Cur_Eth
	reroute.Rematch_flag = uint32(1)

	if err := conn_map.Put(client_conn, reroute); err != nil {
		fmt.Printf("Rematcher - Error: not able to put rematch in conn_map: %v\n", err)
	}
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
