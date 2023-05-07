struct connection {
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int src_ip;
	unsigned int dst_ip;
};

struct numbers {
	unsigned int seq_no;
	unsigned int ack_no;
	signed int seq_offset;
	signed int ack_offset;
};