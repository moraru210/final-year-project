package main

// #cgo CFLAGS: -g -Wall
// #include "common.h"
import "C"
import (
	"fmt"
	"os"
    "strconv"
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

	c_conn_one := C.struct_connection{
		src_port: C.uint(client_one),
		dst_port: 8080,
	}

	c_conn_two := C.struct_connection{
		src_port: C.uint(client_two),
		dst_port: 8080,
	}

	swap_conn_workers(maps, c_conn_one, c_conn_two)
}

func swap_conn_workers(maps maps_fd, c_conn_one C.struct_connection, c_conn_two C.struct_connection) {
	w_conn_one := reverse(find_worker_conn(maps.ports_map, c_conn_one))
    if (w_conn_one.src_port == 0 && w_conn_one.dst_port == 0) {
        fmt.Println("could not find w_conn for first conn")
        return
    }
	w_conn_two := reverse(find_worker_conn(maps.ports_map, c_conn_two))
    if (w_conn_two.src_port == 0 && w_conn_two.dst_port == 0) {
        fmt.Println("could not find w_conn for second conn")
        return
    }

	cco_seq, cco_ack, check_one := get_seq_and_ack(maps, c_conn_one)
    wco_seq, wco_ack, check_two := get_seq_and_ack(maps, w_conn_one)
    if (check_one == 0) {
        fmt.Println("something went wrong when retrieving seq/ack")
        return
    }
    fmt.Println("first worked")
    if (check_two == 0) {
        fmt.Println("something went wrong when retrieving seq/ack")
        return
    }
    fmt.Println("second worked")

    cct_seq, cct_ack, check_three := get_seq_and_ack(maps, c_conn_two)
    wct_seq, wct_ack, check_four := get_seq_and_ack(maps, w_conn_two)
    if(check_three == 0 || check_four == 0) {
        fmt.Println("something went wrong when retrieving seq/ack")
        return
    }

    first_seq_ack := seq_ack_struct{
        c_seq: cco_seq,
        c_ack: cco_ack,
        w_seq: wct_seq,
        w_ack: wct_ack,
    }
    set_offsets(maps, c_conn_one, w_conn_two, first_seq_ack)

    second_seq_ack := seq_ack_struct{
        c_seq: cct_seq,
        c_ack: cct_ack,
        w_seq: wco_seq,
        w_ack: wco_ack,
    }
    set_offsets(maps, c_conn_two, w_conn_one, second_seq_ack)

    r_worker_one := reverse(w_conn_one)
    err := bpf.UpdateElement(maps.ports_map, "ports_map", unsafe.Pointer(&c_conn_two), unsafe.Pointer(&r_worker_one), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ports_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating ports_map")

    // Update Ports Map with conn_w->rev(conn) 
    r_client_two := reverse(c_conn_two)
    err = bpf.UpdateElement(maps.ports_map, "ports_map", unsafe.Pointer(&w_conn_one), unsafe.Pointer(&r_client_two), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating map: ", err.Error())
        return
    } 
    fmt.Println("complete updating map")

    r_worker_two := reverse(w_conn_two)
    err = bpf.UpdateElement(maps.ports_map, "ports_map", unsafe.Pointer(&c_conn_one), unsafe.Pointer(&r_worker_two), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ports_map map: ", err.Error())
        return
    } 
    fmt.Println("complete updating ports_map")

    // Update Ports Map with conn_w->rev(conn) 
    r_client_one := reverse(c_conn_one)
    err = bpf.UpdateElement(maps.ports_map, "ports_map", unsafe.Pointer(&w_conn_two), unsafe.Pointer(&r_client_one), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating map: ", err.Error())
        return
    } 
    fmt.Println("complete updating map")
}

func set_offsets(maps maps_fd, c_conn C.struct_connection, w_conn C.struct_connection, sas seq_ack_struct) {
    fmt.Println("c_seq is %d and c_ack is %d\n", sas.c_seq, sas.c_ack)
    fmt.Println("w_seq is %d and w_ack is %d\n", sas.w_seq, sas.w_ack)
    var seq_off = C.int(sas.c_seq - sas.w_ack) //w is inv direction
    var ack_off = C.int(sas.c_ack - sas.w_seq) //w is inv direction
    fmt.Println("seq_off is %d and ack_off is %d\n", seq_off, ack_off)

    err := bpf.UpdateElement(maps.seq_offsets, "seq_offsets", unsafe.Pointer(&c_conn), unsafe.Pointer(&seq_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating seq_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating seq_offsets map")

    err = bpf.UpdateElement(maps.ack_offsets, "ack_offsets", unsafe.Pointer(&c_conn), unsafe.Pointer(&ack_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ack_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating ack_offsets map")

    var inv_seq_off = C.int(sas.w_seq - sas.c_ack)
    var inv_ack_off = C.int(sas.w_ack - sas.c_seq)
    err = bpf.UpdateElement(maps.seq_offsets, "seq_offsets", unsafe.Pointer(&w_conn), unsafe.Pointer(&inv_seq_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating seq_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating seq_offsets map")

    err = bpf.UpdateElement(maps.ack_offsets, "ack_offsets", unsafe.Pointer(&w_conn), unsafe.Pointer(&inv_ack_off), bpf.BPF_ANY)
    if (err != nil) {
        fmt.Println("Error in updating ack_offsets map: ", err.Error())
        return
    } 
    fmt.Println("complete updating ack_offsets map")
}

func get_seq_and_ack(maps maps_fd, conn C.struct_connection) (C.uint, C.uint, int) {
    seq_no := C.uint(0)
    err := bpf.LookupElement(maps.seq_map, unsafe.Pointer(&conn), unsafe.Pointer(&seq_no))
    if (err != nil) {
        fmt.Println("Error, could not find the seq from map: ", err.Error())
        return 0, 0, 0
    }
    fmt.Println("completed seq_map lookup")

    ack_no := C.uint(0)
    err = bpf.LookupElement(maps.ack_map, unsafe.Pointer(&conn), unsafe.Pointer(&ack_no))
    if (err != nil) {
        fmt.Println("Error, could not find the ack from map: ", err.Error())
        return 0, 0, 0
    }
    fmt.Println("completed ack_map lookup")
	return seq_no, ack_no, 1
}

func find_worker_conn(map_fd int, c_conn C.struct_connection) C.struct_connection {
	var w_conn = C.struct_connection{
		src_port:0, 
		dst_port:0,
	}
    err := bpf.LookupElement(map_fd, unsafe.Pointer(&c_conn), unsafe.Pointer(&w_conn))
    if (err != nil) {
        fmt.Println("Error, could not find the worker connection: ", err.Error())
        return w_conn
    }
    fmt.Println("completed ports_map lookup")
	return w_conn
}

func reverse(conn C.struct_connection) C.struct_connection {
    var tmp = conn.src_port
    conn.src_port = conn.dst_port
    conn.dst_port = tmp
    return conn
}