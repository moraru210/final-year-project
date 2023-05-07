package main

// #cgo CFLAGS: -g -Wall
// #include "../../kernel/common.h"
import "C"
import (
	"fmt"
	"os"
    "strconv"
	"github.com/cilium/cilium/pkg/bpf"
    "unsafe"
    "net"
    "encoding/binary"
    "github.com/moraru210/final-year-project/userspace/common"
)

type seq_ack_struct struct {
    c_seq C.uint
    c_ack C.uint
    w_seq C.uint
    w_ack C.uint
}

func main() {
	if len(os.Args) != 3 {
        fmt.Println("Usage: rematch <integer> <integer>")
        os.Exit(1)
    }

    client_one, err := strconv.Atoi(os.Args[1])
    if err != nil {
        fmt.Println("Invalid first integer argument")
        os.Exit(1)
    }

	client_two, err := strconv.Atoi(os.Args[2])
	if err != nil {
        fmt.Println("Invalid second integer argument")
        os.Exit(1)
    }

    fmt.Println("first arg: %d and second arg: %d", client_one, client_two)

	const connection_map_path = "/sys/fs/bpf/lo/conn_map"
    conn_map_fd, err := bpf.ObjGet(connection_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding conn_map")

    const numbers_map_path = "/sys/fs/bpf/lo/numbers_map"
    numbers_map_fd, err := bpf.ObjGet(numbers_map_path)
    if (err != nil) {
        fmt.Println("Error finding map object: ", err.Error())
        return
    }
    fmt.Println("complete finding numbers_map")

    maps := common.Maps_fd{
        Conn_map: conn_map_fd,
        Numbers_map: numbers_map_fd,
    }
    
    ip := net.ParseIP("127.0.0.1")
    if ip == nil {
        fmt.Println("invalid ip address provided")
        return
    }
    lo_ip := C.uint(binary.BigEndian.Uint64(ip.To16()))

	c_conn_one := C.struct_connection{
		src_port: C.uint(client_one),
		dst_port: 8080,
        src_ip: lo_ip,
        dst_ip: lo_ip,
	}

	c_conn_two := C.struct_connection{
		src_port: C.uint(client_two),
		dst_port: 8080,
        src_ip: lo_ip,
        dst_ip: lo_ip,
	}

	swap_conn_workers(maps, c_conn_one, c_conn_two)
}

func swap_conn_workers(maps common.Maps_fd, c_conn_one C.struct_connection, c_conn_two C.struct_connection) {
	w_conn_one := reverse(find_worker_conn(maps.Conn_map, c_conn_one))
    if (w_conn_one.src_port == 0 && w_conn_one.dst_port == 0) {
        fmt.Println("could not find w_conn for first conn")
        return
    }
	w_conn_two := reverse(find_worker_conn(maps.Conn_map, c_conn_two))
    if (w_conn_two.src_port == 0 && w_conn_two.dst_port == 0) {
        fmt.Println("could not find w_conn for second conn")
        return
    }

    /******************************/
    cco := C.struct_numbers{
        seq_no: C.uint(0),
        ack_no: C.uint(0),
        seq_offset: C.int(0),
        ack_offset: C.int(0),
    }
    err := bpf.LookupElement(maps.Numbers_map, unsafe.Pointer(&c_conn_one), unsafe.Pointer(&cco))
    if (err != nil) {
        fmt.Println("Error, could not find the ack from map: ", err.Error())
        return
    }
    fmt.Println("completed numbers_map lookup")

    wco := C.struct_numbers{
        seq_no: C.uint(0),
        ack_no: C.uint(0),
        seq_offset: C.int(0),
        ack_offset: C.int(0),
    }
    err = bpf.LookupElement(maps.Numbers_map, unsafe.Pointer(&w_conn_one), unsafe.Pointer(&wco))
    if (err != nil) {
        fmt.Println("Error, could not find the ack from map: ", err.Error())
        return
    }
    fmt.Println("completed numbers_map lookup")
    /******************************/
    /******************************/
    cct := C.struct_numbers{
        seq_no: C.uint(0),
        ack_no: C.uint(0),
        seq_offset: C.int(0),
        ack_offset: C.int(0),
    }
    err = bpf.LookupElement(maps.Numbers_map, unsafe.Pointer(&c_conn_one), unsafe.Pointer(&cct))
    if (err != nil) {
        fmt.Println("Error, could not find the numbers elem from map: ", err.Error())
        return
    }
    fmt.Println("completed numbers_map lookup")

    wct := C.struct_numbers{
        seq_no: C.uint(0),
        ack_no: C.uint(0),
        seq_offset: C.int(0),
        ack_offset: C.int(0),
    }
    err = bpf.LookupElement(maps.Numbers_map, unsafe.Pointer(&w_conn_one), unsafe.Pointer(&wct))
    if (err != nil) {
        fmt.Println("Error, could not find the numbers elem from map: ", err.Error())
        return
    }
    fmt.Println("completed numbers_map lookup")
    /*****************************/
    first_seq_ack := seq_ack_struct{
        c_seq: cco.seq_no,
        c_ack: cco.ack_no,
        w_seq: wct.seq_no,
        w_ack: wct.ack_no,
    }
    set_offsets(maps, c_conn_one, w_conn_two, first_seq_ack)

    second_seq_ack := seq_ack_struct{
        c_seq: cct.seq_no,
        c_ack: cct.ack_no,
        w_seq: wco.seq_no,
        w_ack: wco.ack_no,
    }
    set_offsets(maps, c_conn_two, w_conn_one, second_seq_ack)

    r_worker_one := reverse(w_conn_one)
    err = bpf.UpdateElement(maps.Conn_map, "conn_map", unsafe.Pointer(&c_conn_two), unsafe.Pointer(&r_worker_one), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating conn_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating conn_map map")

    // Update Conn Map with conn_w->rev(conn) 
    r_client_two := reverse(c_conn_two)
    err = bpf.UpdateElement(maps.Conn_map, "conn_map", unsafe.Pointer(&w_conn_one), unsafe.Pointer(&r_client_two), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating map: ", err.Error())
        return
    } 
    fmt.Println("complete updating conn_map map")

    r_worker_two := reverse(w_conn_two)
    err = bpf.UpdateElement(maps.Conn_map, "conn_map", unsafe.Pointer(&c_conn_one), unsafe.Pointer(&r_worker_two), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating conn_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating conn_map map")

    // Update Ports Map with conn_w->rev(conn) 
    r_client_one := reverse(c_conn_one)
    err = bpf.UpdateElement(maps.Conn_map, "conn_map", unsafe.Pointer(&w_conn_two), unsafe.Pointer(&r_client_one), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating conn_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating conn_map map")
}

func set_offsets(maps common.Maps_fd, c_conn C.struct_connection, w_conn C.struct_connection, sas seq_ack_struct) {
    fmt.Println("c_seq is %d and c_ack is %d\n", sas.c_seq, sas.c_ack)
    fmt.Println("w_seq is %d and w_ack is %d\n", sas.w_seq, sas.w_ack)
    var seq_off = C.int(sas.c_seq - sas.w_ack) //w is inv direction
    var ack_off = C.int(sas.c_ack - sas.w_seq) //w is inv direction
    fmt.Println("seq_off is %d and ack_off is %d\n", seq_off, ack_off)

    new_c_num := C.struct_numbers{
        seq_no: sas.c_seq,
        ack_no: sas.c_ack,
        seq_offset: seq_off,
        ack_offset: ack_off,
    }
    err := bpf.UpdateElement(maps.Numbers_map, "numbers_map", unsafe.Pointer(&c_conn), unsafe.Pointer(&new_c_num), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating numbers_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating numbers_map map")

    var inv_seq_off = C.int(sas.w_seq - sas.c_ack)
    var inv_ack_off = C.int(sas.w_ack - sas.c_seq)

    new_w_num := C.struct_numbers{
        seq_no: sas.w_seq,
        ack_no: sas.w_ack,
        seq_offset: inv_seq_off,
        ack_offset: inv_ack_off,
    }
    err = bpf.UpdateElement(maps.Numbers_map, "numbers_map", unsafe.Pointer(&w_conn), unsafe.Pointer(&new_w_num), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating numbers_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating numbers_map map")
}

func find_worker_conn(map_fd int, c_conn C.struct_connection) C.struct_connection {
	var w_conn = C.struct_connection{
		src_port:0, 
		dst_port:0,
        src_ip:0,
        dst_ip:0,
	}
    err := bpf.LookupElement(map_fd, unsafe.Pointer(&c_conn), unsafe.Pointer(&w_conn))
    if (err != nil) {
        fmt.Println("Error, could not find the worker connection: ", err.Error())
        return w_conn
    }
    fmt.Println("completed conn_map lookup")
	return w_conn
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