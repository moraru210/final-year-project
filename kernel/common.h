#define MAX_CLIENTS 2
#define LB_LISTENER_PORT 8080

struct connection {
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int src_ip;
	unsigned int dst_ip;
};

struct reroute {
	struct connection original_conn;
	unsigned int original_index;
	unsigned int rematch_flag;
	struct connection new_conn;
	unsigned int new_index;
};

struct numbers {
	unsigned int seq_no;
	unsigned int ack_no;
	signed int seq_offset;
	signed int ack_offset;
	unsigned int init_seq;
	unsigned int init_ack;
};

struct server {
	unsigned int port;
	unsigned int ip;
};

struct availability {
	struct connection conns[MAX_CLIENTS];
	unsigned int valid[MAX_CLIENTS];
	//spin_lock maybe?
};