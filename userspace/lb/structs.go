package main

const MAX_CLIENTS = 10
const MAX_SERVERS = 10
const ETH_ALEN = 6

type Connection struct {
	Src_port uint32
	Dst_port uint32
	Src_ip   uint32
	Dst_ip   uint32
}

type Reroute struct {
	Original_conn  Connection // 16
	Original_eth   Eth_conn   // 12
	Original_index uint32     // 4
	Seq_offset     int32      // 4
	Ack_offset     int32      // 4
	Rematch_flag   uint32     // 4
	New_conn       Connection // 16
	New_eth        Eth_conn   // 12
	New_index      uint32     // 4
}

type Numbers struct {
	Seq_no   uint32
	Ack_no   uint32
	Init_seq uint32
	Init_ack uint32
	Cur_Eth  Eth_conn
}

type Server struct {
	Port uint32
	Ip   uint32
}

type Availability struct {
	Conns [MAX_CLIENTS]Connection
	Valid [MAX_CLIENTS]uint32
}

type Eth_conn struct {
	Src_addr Eth_addr
	Dst_addr Eth_addr
}

type Eth_addr struct {
	Addr [ETH_ALEN]byte
}
