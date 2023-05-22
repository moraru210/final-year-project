#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "./common.h"

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

#define MIN_SERVER_PORT 4171
#define MAX_SERVER_PORT (4170+MAX_CLIENTS) 

struct bpf_map_def SEC("maps") conn_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(struct reroute),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") numbers_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(struct numbers),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") available_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct server),
	.value_size  = sizeof(struct availability),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") state_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 20,
};


static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	return csum;
}

static inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) 
{
    for (int i = 0; i < max; i += 2) {
	if ((void *)(buf + 1) > data_end)
	    break;
        sum += *buf;
        buf++;
    }
    if((void *)buf +1 <= data_end) {
		sum +=  bpf_htons((*((unsigned char *)buf)) << 8);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

static inline __u16 l4_checksum(struct iphdr *iph, void *l4, void *data_end)
{
    __u32 csum = 0;
    csum += *(((__u16 *) &(iph->saddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->saddr))+1); // 2nd 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+0); // 1st 2 bytes
    csum += *(((__u16 *) &(iph->daddr))+1); // 2nd 2 bytes
    csum += bpf_htons((__u16)iph->protocol); // protocol is a u8
    csum += bpf_htons((__u16)(data_end - (void *)l4)); 
    return generic_checksum((unsigned short *) l4, data_end, csum, 1480);
}

static inline void perform_checksums(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
{
	iph->check = 0;
	iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));
	tcph->check = 0;
	tcph->check = l4_checksum(iph, tcph, data_end);
}

static inline int from_server(struct connection *conn)
{
	if (conn->src_port >= MIN_SERVER_PORT 
		&& conn->src_port <= MAX_SERVER_PORT) {
			return 1;
		}
	return 0;
}

static inline int from_client(struct connection *conn)
{
	if (conn->dst_port == LB_LISTENER_PORT) {
			return 1;
	}
	return 0;
}

static inline int to_server(struct connection *conn)
{
	if (conn->dst_port >= MIN_SERVER_PORT 
		&& conn->dst_port <= MAX_SERVER_PORT) {
			return 1;
		}
	return 0;
}

// static inline int to_client(struct connection *conn)
// {
// 	if (conn->src_port == LB_LISTENER_PORT) {
// 			return 1;
// 	}
// 	return 0;
// }

static inline struct connection create_reverse_conn(struct connection *conn) 
{
	struct connection rev_conn;
	rev_conn.src_ip = conn->dst_ip;
	rev_conn.dst_ip = conn->src_ip;
	rev_conn.src_port = conn->dst_port;
	rev_conn.dst_port = conn->src_port;
	return rev_conn;
}

static inline struct connection create_conn_struct(struct tcphdr **tcph, struct iphdr **iph)
{
	struct connection conn;
	conn.src_port = bpf_ntohs((*tcph)->source);
	conn.dst_port = bpf_ntohs((*tcph)->dest);
	bpf_printk("tcp src port is %u and dst port is %u", conn.src_port, conn.dst_port);
	conn.src_ip = (*iph)->saddr;
	conn.dst_ip = (*iph)->daddr;
	bpf_printk("ip before endian conversion src %u and dst %u", (*iph)->saddr, (*iph)->daddr);
	bpf_printk("ip header saddr %u and daddr %u", conn.src_ip, conn.dst_ip);
	return conn;
}

static inline struct server create_server_struct(struct connection *conn)
{
	// This function assumes the server is at the destination of the input connection
	struct server server;
	server.port = conn->dst_port;
	server.ip = conn->dst_ip;
	return server;
}

static inline void modify_seq_ack(struct tcphdr **tcph_ptr, signed int seq_off, signed int ack_off) {
	struct tcphdr *tcph = *(tcph_ptr);
	unsigned int cur_seq = bpf_ntohl(tcph->seq);
	unsigned int cur_ack = bpf_ntohl(tcph->ack_seq);

	unsigned int new_seq = cur_seq - seq_off;
	tcph->seq = bpf_htonl(new_seq);
	unsigned int new_ack_seq = cur_ack - ack_off; 
	tcph->ack_seq = bpf_htonl(new_ack_seq);
}

SEC("xdp_tcp")
int  xdp_prog_tcp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 action = XDP_PASS; /* Default action */
	struct hdr_cursor nh;
	int eth_type, ip_type;

	nh.pos = data;

	bpf_printk("*** start of a new packet ***");
	// Begin initial checks
	eth_type = parse_ethhdr(&nh, data_end, &ethh);
	if (eth_type < 0) {
		goto OUT;
	}
	bpf_printk("parsed ethhdr");

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iph);
	} else {
		goto OUT;
	}
	bpf_printk("parsed iphdr");
	
	if (ip_type != IPPROTO_TCP) {
		goto OUT;
	}
	bpf_printk("checked if TCP");

	if (parse_tcphdr(&nh, data_end, &tcph) < 0) {
		goto OUT;
	}
	bpf_printk("parsed tcphdr");
	// Complete initial checks

	// Numbers map will store keys: C1->LB, W1->LB
	// This is due to ease of quickly grabbing and applying offset on majority of packet cases
	//	
	//	for every packet (from/to servers/clients)
	//		retrieve numbers kv pair
	//		retrieve seq and ack_seq from current packet
	//		update the numbers kv.value to have update seq and ack_seq values
	//		place updated kv back to the numbers_map
	//
	//  if needs to reroute
	//  	if rst and from client (done - needs recheck)
	//			grab client_numbers from numbers_map (key is client_conn) (done)
	//			grab server_numbers from numbers_map (key is reroute.original) (not needed?)
	//			set packet.seq/ack to client_numbers.init_seq/ack
	//			delete client_numbers from numbers_map
	//			delete client_conn from conn_map
	//			delete original_conn from conn_map
	//			grab the availability struct for reroute.original_conn.dst_port/ip key
	//			set availability.valid[pos(reroute.original_conn)] = true
	//
	//  	if from_client and reroute.rematch_flag is true and reroute.state is true (done - needs recheck)
	//			grab the availability struct for reroute.original_conn.dst_port/ip key
	//			set availability.valid[pos(reroute.original_conn)] = true
	//			set reroute.original = reroute.new
	// 			set reroute.rematch = 0
	//			set reroute.state = 0
	//			update conn_map to have update reroute	
	//			grab reroute_numbers for rev(reroute.new) conn
	//			grab client_numbers for client_conn
	//			client_numbers.seq_offset = client_numbers.seq_no - reroute_numbers.ack_no
	//			client_numbers.ack_offset = client_numbers.ack_no - reroute_numbers.seq_no
	//			reroute_numbers.seq_offset = reroute_numbers.seq_no - client_numbers.ack_no
	//			reroute_numbers.ack_offset = reroute_numbers.ack_no - client_numbers.seq_no
	//			update numbers_map to contain the updated client_numbers for client_conn
	//			update numbers_map to contain the updated reroute_numbers for rev(reroute.new)
	//			use client_numbers to alter seq and ack correspondingly
	//			
	//		if from_server and reroute.state is false 
	//			set reroute.state to true
	//			update conn_map to have updated reroute
	//			continue with offsets like normal
	//
	//		if from_client and reroute.state is true and reroute.rematch_flag is false
	//			set reroute.state to false
	//			update conn_map to have updated reroute
	//			continue with offsets like normal
	//		
	//		change seq and ack_seq accordingly
	//		change src and dst port accordingly	
	//		perform tcp checksum
	//		perform ipv4 checksum
	//		action = XDP_TX
	//		

	// create connection struct using header information
	struct connection conn = create_conn_struct(&tcph, &iph);

	if (from_client(&conn) || from_server(&conn) || to_server(&conn)) {
		struct connection query_conn;
		unsigned int seq_no = bpf_ntohl(tcph->seq);
		unsigned int ack_no = bpf_ntohl(tcph->ack_seq);	

		if (to_server(&conn)) {
			query_conn = create_reverse_conn(&conn);
			unsigned int temp = seq_no;
			seq_no = ack_no;
			ack_no = temp;
		} else {
			query_conn = conn;
		}	
		struct numbers *numbers_elem_ptr = bpf_map_lookup_elem(&numbers_map, &query_conn);
		struct numbers numbers_elem;
		if (!numbers_elem_ptr) {
			bpf_printk("could not find numbers elem in numbers map");
			numbers_elem.seq_offset = 0;
			numbers_elem.ack_offset = 0;
			numbers_elem.init_seq = 0;
			numbers_elem.init_ack = 0;
		} else {
			bpf_printk("successfully found numbers elem in numbers map");
			numbers_elem = *(numbers_elem_ptr);
			seq_no = max(seq_no, numbers_elem.seq_no);
			ack_no = max(ack_no, numbers_elem.ack_no);
		}

		numbers_elem.seq_no = seq_no;
		numbers_elem.ack_no = ack_no;
		bpf_printk("before updating numbers map");
		if (bpf_map_update_elem(&numbers_map, &query_conn, &numbers_elem, 0) < 0) {
			bpf_printk("failed updating numbers map");
			action = XDP_ABORTED;
			goto OUT;
		}
		bpf_printk("successfully updated numbers map");
	}

	struct reroute *reroute_ptr = bpf_map_lookup_elem(&conn_map, &conn);
	if (!reroute_ptr) {
		bpf_printk("could not query conn_map for rerouting");
		goto OUT;
	} else {
		bpf_printk("Found a reroute");
		struct reroute reroute = *(reroute_ptr);

		if (tcph->rst && from_client(&conn)) {
			bpf_printk("Reroute packet received is a RST from a client");
			struct numbers *numbers_elem_ptr = bpf_map_lookup_elem(&numbers_map, &conn);
			struct numbers numbers_elem;
			if (!numbers_elem_ptr) {
				bpf_printk("could not find numbers elem in numbers map");
				bpf_printk("ABORT PACKET");
				action = XDP_ABORTED;
				goto OUT;
			} else {
				bpf_printk("successfully found numbers elem in numbers map");
				numbers_elem = *(numbers_elem_ptr);
				if (bpf_map_delete_elem(&numbers_map, &conn)) {
					bpf_printk("unable to delete numbers from numbers map for conn");
				}
				tcph->seq = bpf_htonl(numbers_elem.init_seq);
				tcph->ack_seq = bpf_htonl(numbers_elem.init_ack);

				perform_checksums(tcph, iph, data_end);
			}

			struct connection original_conn = reroute.original_conn;

			//create the worker struct
			//grab avaialability from available map
			//set valid[reroute.index] = 0
			struct server server = create_server_struct(&original_conn);
			struct availability *availability_ptr = bpf_map_lookup_elem(&available_map, &server);
			if (!availability_ptr) {
				bpf_printk("could not find avaialability in order to invalidate reroute.original");
			} else {
				struct availability availability = *(availability_ptr);
				unsigned int index = reroute.original_index;
				unsigned int max_size = sizeof(availability.conns) / sizeof(availability.conns[0]);
				if (index >= max_size) {
					bpf_printk("index: %u", index);
					bpf_printk("ABORT PACKET");
					action = XDP_ABORTED;
					goto OUT;
				} else {
					availability.valid[index] = 0;
				}
			}


			bpf_printk("successfully found value for conn in conn_map");
			if (bpf_map_delete_elem(&conn_map, &conn)) {
				bpf_printk("unable to delete client_conn from conn map");
			}

			struct connection rev_original_conn = create_reverse_conn(&original_conn);
			if (bpf_map_delete_elem(&conn_map, &rev_original_conn)) {
				bpf_printk("unable to delete rev(original_conn) from conn map");
			}			
		
			goto OUT;
		}
		
		unsigned int *state_ptr;
		if (from_client(&conn)) {
			state_ptr = bpf_map_lookup_elem(&state_map, &conn.src_port);
			if (!state_ptr) {
				bpf_printk("Unable to find state from client_conn");
				action = XDP_ABORTED;
				goto OUT;
			}
		} else if (from_server(&conn)) {
			state_ptr = bpf_map_lookup_elem(&state_map, &reroute.original_conn.dst_port);
			if (!state_ptr) {
				bpf_printk("Unable to find state from client_conn");
				action = XDP_ABORTED;
				goto OUT;
			}
		} else {
			bpf_printk("Reroute is not from server nor client, which should be impossible");
			action = XDP_ABORTED;
			goto OUT;
		}
		unsigned int state = *(state_ptr);

		struct numbers *numbers_ptr = bpf_map_lookup_elem(&numbers_map, &conn);
		if (!numbers_ptr) {
			bpf_printk("Could not find conn's numbers elem in numbers map");
			action = XDP_ABORTED;
			goto OUT;
		}
		
		if (from_client(&conn) && reroute.rematch_flag && state) {
			struct connection original_conn = reroute.original_conn;
			struct server server = create_server_struct(&original_conn);
			struct availability *availability_ptr = bpf_map_lookup_elem(&available_map, &server);
			if (!availability_ptr) {
				bpf_printk("could not find avaialability in order to invalidate reroute.original");
			} else {
				struct availability availability = *(availability_ptr);
				unsigned int index = reroute.original_index;
				unsigned int max_size = sizeof(availability.conns) / sizeof(availability.conns[0]);
				if (index >= max_size) {
					bpf_printk("index: %u", index);
					bpf_printk("ABORT PACKET");
					action = XDP_ABORTED;
					goto OUT;
				} else {
					availability.valid[index] = 1;
				}
			}

			reroute.original_conn = reroute.new_conn;
			reroute.rematch_flag = 0;
			reroute.original_index = reroute.new_index;
			
			unsigned int zero = 0;
			if (bpf_map_update_elem(&state_map, &conn.src_port, &zero, 0) < 0) {
				bpf_printk("Unable to change state back to 0");
			}

			if (bpf_map_update_elem(&conn_map, &conn, &reroute, 0) < 0) {
				bpf_printk("Unable to change reroute when rematching");
			}

			//ASSUMPTION: WHEN USERSPACE REMATCHES, IT ALREADY ADDS THIS
			struct connection rev_server = create_reverse_conn(&reroute.original_conn);
			// struct connection rev_client = create_reverse_conn(&conn);
			// if (bpf_map_update_elem(&conn_map, &rev_server, &rev_client, 0) < 0) {
			// 	bpf_printk("Unable to change reroute when rematching");
			// }

			struct numbers *server_numbers_ptr = bpf_map_lookup_elem(&numbers_map, &rev_server);
			if (!server_numbers_ptr) {
				bpf_printk("Could not find server's numbers elem in numbers map");
				action = XDP_ABORTED;
				goto OUT;
			}
			struct numbers server_numbers = *server_numbers_ptr;

			numbers_ptr->seq_offset = numbers_ptr->seq_no - server_numbers.ack_no;
			numbers_ptr->ack_offset = numbers_ptr->ack_no - server_numbers.seq_no;
			server_numbers.seq_offset = server_numbers.seq_no - numbers_ptr->ack_no;
			server_numbers.ack_offset = server_numbers.ack_no - numbers_ptr->seq_no; 

			if (bpf_map_update_elem(&numbers_map, &rev_server, &server_numbers, 0) < 0) {
				bpf_printk("Could not update map with updated server_numbers offsets");
			}

			if (bpf_map_update_elem(&numbers_map, &conn, numbers_ptr, 0) < 0) {
				bpf_printk("Could not update map with updated client_numbers offsets");
			}

		} else if (from_server(&conn) && !state) {
			unsigned int one = 1;
			if (bpf_map_update_elem(&state_map, &conn.src_port, &one, 0) < 0) {
				bpf_printk("Unable to change state back to 0");
			}

			if (bpf_map_update_elem(&conn_map, &conn, &reroute, 0) < 0) {
				bpf_printk("Failed to update conn_map with updated reroute.state (0->1)");
			}

		} else if (from_client(&conn) && state && !reroute.rematch_flag) {
			unsigned int zero = 0;
			if (bpf_map_update_elem(&state_map, &conn.src_port, &zero, 0) < 0) {
				bpf_printk("Unable to change state back to 0");
			}

			if (bpf_map_update_elem(&conn_map, &conn, &reroute, 0) < 0) {
				bpf_printk("Failed to update conn_map with updated reroute.state (1->0)");
			}
		}

		modify_seq_ack(&tcph, numbers_ptr->seq_offset, numbers_ptr->ack_offset);
		tcph->source = bpf_htons(reroute.original_conn.src_port);
		tcph->dest = bpf_htons(reroute.original_conn.dst_port);
		iph->saddr = reroute.original_conn.src_ip;
		iph->daddr = reroute.original_conn.dst_ip;
		bpf_printk("modified ip addresses");
		bpf_printk("modified ip header saddr %u and daddr %u", reroute.original_conn.src_ip, reroute.original_conn.dst_ip);
		swap_src_dst_mac(ethh);
		bpf_printk("Swapped eth addresses");
		bpf_printk("destination TCP port after is %u", bpf_ntohs(tcph->dest));
		perform_checksums(tcph, iph, data_end);
		action = XDP_TX;
	}
OUT:
	bpf_printk("*** end of a packet ***");
	return action;
}

SEC("xdp_pass")
int xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";