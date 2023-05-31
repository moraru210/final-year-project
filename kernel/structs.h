#include <linux/in.h>

#define MAX_CLIENTS 2
#define LB_LISTENER_PORT 8080
#define MIN_SERVER_PORT 4171
#define MAX_SERVER_PORT (4170+MAX_CLIENTS) 

struct connection {
	__u32 src_port;
	__u32 dst_port;
	__u32 src_ip;
	__u32 dst_ip;
};

struct reroute {
	struct connection original_conn;
	__u32 original_index;
    __s32 seq_offset;
	__s32 ack_offset;
     __u32 rematch_flag;
    struct connection new_conn;
	__u32 new_index;
};

struct numbers {
	__u32 seq_no;
	__u32 ack_no;
	__u32 init_seq;
	__u32 init_ack;
};

struct server {
	__u32 port;
	__u32 ip;
};

struct availability {
	struct connection conns[MAX_CLIENTS];
	__u32 valid[MAX_CLIENTS];
	//spin_lock maybe?
};