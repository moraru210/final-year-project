#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "./structs.h"

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

/* Allow users of header file to redefine VLAN max depth */
#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 4
#endif

// /* Define maps */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 30);
	__type(key, struct connection);
	__type(value, struct reroute);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} conn_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 30);
	__type(key, struct connection);
	__type(value, struct numbers);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} numbers_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 30);
	__type(key, struct server);
	__type(value, struct availability);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} available_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 30);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} state_map SEC(".maps");

struct hdr_cursor {
	void *pos;
};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};


static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* Notice, parse_ethhdr() will skip VLAN tags, by advancing nh->pos and returns
 * next header EtherType, BUT the ethhdr pointer supplied still points to the
 * Ethernet header. Thus, caller can look at eth->h_proto to see if this was a
 * VLAN tagged packet.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh, void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	struct vlan_hdr *vlh;
	__u16 h_proto;
	int i;

	if (eth + 1 > data_end)
		return -1;

	nh->pos = eth + 1;
	*ethhdr = eth;
	vlh = nh->pos;
	h_proto = eth->h_proto;

	/* Use loop unrolling to avoid the verifier restriction on loops;
	 * support up to VLAN_MAX_DEPTH layers of VLAN encapsulation.
	 */
	#pragma unroll
	for (i = 0; i < VLAN_MAX_DEPTH; i++) {
		if (!proto_is_vlan(h_proto))
			break;

		if (vlh + 1 > data_end)
			break;

		h_proto = vlh->h_vlan_encapsulated_proto;
		vlh++;
	}

	nh->pos = vlh;
	return h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
				       void *data_end,
				       struct iphdr **iphdr)
{
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;

	/* Variable-length IPv4 header, need to use byte-based arithmetic */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}

/*
 * parse_tcphdr: parse and return the length of the tcp header
 */
static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
					void *data_end,
					struct tcphdr **tcphdr)
{
	int len;
	struct tcphdr *h = nh->pos;

	if (h + 1 > data_end)
		return -1;

	len = h->doff * 4;
	if ((void *) h + len > data_end)
		return -1;

	nh->pos  = h + 1;
	*tcphdr = h;

	return len;
}

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	return csum;
}

static inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) 
{
	int flag = 0;
    for (int i = 0; i < max; i += 2) {
		if ((void *)(buf + 1) > data_end)
			flag = 1;
	    	break;
        sum += *buf;
        buf++;
    }
	if (!flag) {
		if((void *)buf +1 <= data_end) {
			sum +=  bpf_htons((*((unsigned char *)buf)) << 8);
    	}
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
	// return (csum >> 16);
    return generic_checksum((unsigned short *) l4, data_end, csum, 1480);
}

static inline void perform_checksums(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
{
	iph->check = 0;
	iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));
	tcph->check = 0;
	tcph->check = l4_checksum(iph, tcph, data_end);
}

static inline struct connection create_conn_struct(struct tcphdr **tcph, struct iphdr **iph)
{
	struct connection conn;
	conn.src_port = bpf_ntohs((*tcph)->source);
	conn.dst_port = bpf_ntohs((*tcph)->dest);
	bpf_printk("CONN - src port: %u, dst port: %u", conn.src_port, conn.dst_port);
	conn.src_ip = (*iph)->saddr;
	conn.dst_ip = (*iph)->daddr;
	bpf_printk("ip header saddr: %u, daddr: %u", conn.src_ip, conn.dst_ip);
	return conn;
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

// static inline int to_server(struct connection *conn)
// {
// 	if (conn->dst_port >= MIN_SERVER_PORT 
// 		&& conn->dst_port <= MAX_SERVER_PORT) {
// 			return 1;
// 		}
// 	return 0;
// }

static inline int to_client(struct connection *conn)
{
	if (conn->src_port == LB_LISTENER_PORT) {
			return 1;
	}
	return 0;
}

static inline int generate_and_insert_numbers(struct connection conn, __u32 *seq_no, __u32 *ack_no) {
	struct numbers nums;
	nums.seq_no = *ack_no;
	nums.ack_no = *seq_no + 1;

	nums.init_seq = nums.seq_no;
	nums.init_ack = nums.ack_no;

	bpf_printk("Number struct generated\n");
	bpf_printk("Nums.seq: %u\n", nums.seq_no);
	bpf_printk("Nums.ack: %u\n", nums.ack_no);

	if (bpf_map_update_elem(&numbers_map, &conn, &nums, 0) < 0) {
		bpf_printk("Unable to introduce (conn.src: %u, conn.dst: %u) to numbers_map\n", conn.src_port, conn.dst_port);
		return 0;
	}
	return 1;
}

static inline void modify_seq_ack(struct tcphdr **tcph_ptr, signed int seq_off, signed int ack_off) {
	struct tcphdr *tcph = *(tcph_ptr);
	__u32 cur_seq = bpf_ntohl(tcph->seq);
	__u32 cur_ack = bpf_ntohl(tcph->ack_seq);

	__u32 new_seq = cur_seq - seq_off;
	tcph->seq = bpf_htonl(new_seq);
	__u32 new_ack_seq = cur_ack - ack_off; 
	tcph->ack_seq = bpf_htonl(new_ack_seq);
}

static inline struct connection create_reverse_conn(struct connection *conn) 
{
	struct connection rev_conn;
	rev_conn.src_ip = conn->dst_ip;
	rev_conn.dst_ip = conn->src_ip;
	rev_conn.src_port = conn->dst_port;
	rev_conn.dst_port = conn->src_port;
	return rev_conn;
}

static inline struct server create_server_struct(struct connection *conn)
{
	// This function assumes the server is at the destination of the input connection
	struct server server;
	server.port = conn->dst_port;
	server.ip = conn->dst_ip;
	return server;
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

	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iph);
	} else {
		goto OUT;
	}
	
	if (ip_type != IPPROTO_TCP) {
		goto OUT;
	}

    int tcph_len = parse_tcphdr(&nh, data_end, &tcph);
	if (tcph_len < 0) {
		goto OUT;
	}

	__u32 seq_no = bpf_htonl(tcph->seq);
	__u32 ack_seq = bpf_ntohl(tcph->ack_seq);
    
	int payload_len = bpf_ntohs(iph->tot_len) - (sizeof(struct iphdr) + tcph_len);

	struct connection conn = create_conn_struct(&tcph, &iph);

	// Query map for possible routing
	struct reroute *reroute_ptr = bpf_map_lookup_elem(&conn_map, &conn);
	if (!reroute_ptr) {
		
		//bpf_printk("REROUTE - could not query conn_map for routing\n");
		// Introduce the seq and ack into NUMBERS_STRUCT for respective CONN
		if (tcph->syn && tcph->ack && (to_client(&conn) || from_server(&conn))) {
			struct connection rev_conn = create_reverse_conn(&conn);
			//bpf_printk("REROUTE - rev_conn.src: %u, rev_conn.dst: %u\n", rev_conn.src_port, rev_conn.dst_port);
			if (generate_and_insert_numbers(rev_conn, &seq_no, &ack_seq) == 0) {
				bpf_printk("ABORT - Unable to insert numbers for conn\n");
				action = XDP_ABORTED;
				goto OUT;
			}
		}
		goto OUT;

	} else {

		//bpf_printk("REROUTE - reroute found\n");
		// Update NUMBERS When receiving PSH - (need to include payload in ack/seq)
		if (tcph->psh && from_server(&conn)) {
			struct connection rev_conn = create_reverse_conn(&conn);
			struct numbers *nums_ptr = bpf_map_lookup_elem(&numbers_map, &rev_conn);
			if (!nums_ptr) {
				bpf_printk("NUMBERS - Unable to retrieve numbers for (conn.src %u, conn.dst %u)\n", conn.src_port, conn.dst_port);
				action = XDP_ABORTED;
				goto OUT;
			} else {
				nums_ptr->seq_no = ack_seq;
				nums_ptr->ack_no = seq_no + payload_len;
				if (bpf_map_update_elem(&numbers_map, &conn, nums_ptr, 0) < 0) {
					bpf_printk("NUMBERS - Unable to update numbers for (conn.src %u, conn.dst %u)\n", conn.src_port, conn.dst_port);
				}
			}

			struct connection rev_client_conn = create_reverse_conn(&reroute_ptr->original_conn);
			struct numbers *client_nums_ptr = bpf_map_lookup_elem(&numbers_map, &rev_client_conn);
			if (!client_nums_ptr) {
				bpf_printk("NUMBERS - Unable to retrieve numbers for (conn.src %u, conn.dst %u)\n", rev_client_conn.src_port, rev_client_conn.dst_port);
				action = XDP_ABORTED;
				goto OUT;
			} else {
				client_nums_ptr->seq_no = nums_ptr->seq_no - reroute_ptr->seq_offset;
				client_nums_ptr->ack_no = nums_ptr->ack_no - reroute_ptr->ack_offset;
				if (bpf_map_update_elem(&numbers_map, &reroute_ptr->original_conn, client_nums_ptr, 0) < 0) {
					bpf_printk("NUMBERS - Unable to update numbers for (conn.src %u, conn.dst %u)\n", rev_client_conn.src_port, rev_client_conn.dst_port);
				}
			}
		}

		//Check if rematch is needed
		if (reroute_ptr->rematch_flag == 1) {
			//bpf_printk("REMATCH - rematch flag set\n");
			__u32 *state_ptr = bpf_map_lookup_elem(&state_map, &conn.src_port);
			if (!state_ptr) {
				bpf_printk("REMATCH - unable to retrieve state from map with conn.src %u\n", conn.src_port);
				action = XDP_ABORTED;
				goto OUT;
			}
			__u32 state = *state_ptr;
			bpf_printk("REMATCH - state: %u\n", state);

			if (state) {
				// Safe to initiate rematching process
				struct server server = create_server_struct(&reroute_ptr->original_conn);
				struct availability *availability_ptr = bpf_map_lookup_elem(&available_map, &server);
				if (!availability_ptr) {
					bpf_printk("could not find avaialability in order to invalidate reroute.original");
					bpf_printk("ABORT PACKET");
					action = XDP_ABORTED;
					goto OUT;
				} else {
					struct availability availability = *(availability_ptr);
					__u32 index = reroute_ptr->original_index;
					__u32 max_size = sizeof(availability.conns) / sizeof(availability.conns[0]);
					if (index >= max_size) {
						bpf_printk("index: %u", index);
						bpf_printk("ABORT PACKET");
						action = XDP_ABORTED;
						goto OUT;
					} else {
						bpf_printk("index: %u", index);
						availability.valid[index] = 0;
					}

					//need to update available_map with new availability information
					if (bpf_map_update_elem(&available_map, &server, &availability, 0) < 0) {
						bpf_printk("unable to update available_map to invalidate old map");
						bpf_printk("ABORT PACKET");
						action = XDP_ABORTED;
						goto OUT;
					}
				}

				struct numbers *nums_ptr = bpf_map_lookup_elem(&numbers_map, &conn);
				if (!nums_ptr) {
					bpf_printk("NUMBERS - Unable to retrieve numbers for (conn.src %u, conn.dst %u)\n", conn.src_port, conn.dst_port);
					action = XDP_ABORTED;
					goto OUT;
				}

				struct numbers *server_nums_ptr = bpf_map_lookup_elem(&numbers_map, &reroute_ptr->new_conn);
				if (!server_nums_ptr) {
					bpf_printk("NUMBERS - Unable to retrieve numbers for (conn.src %u, conn.dst %u)\n", reroute_ptr->new_conn.src_port, reroute_ptr->new_conn.dst_port);
					action = XDP_ABORTED;
					goto OUT;
				}

				struct connection rev_server = create_reverse_conn(&reroute_ptr->original_conn);
				if (bpf_map_delete_elem(&conn_map, &rev_server) < 0) {
					bpf_printk("REMATCH - Unable to delete reroute object for (conn.src %u, conn.dst %u)\n", rev_server.src_port, rev_server.dst_port);
					action = XDP_ABORTED;
					goto OUT;
				}

				nums_ptr->seq_no = seq_no;
				nums_ptr->ack_no = ack_seq;

				if (bpf_map_update_elem(&numbers_map, &conn, nums_ptr, 0) < 0) {
					bpf_printk("REMATCH - Unable to upate numbers object for (conn.src %u, conn.dst %u)\n", conn.src_port, conn.dst_port);
					action = XDP_ABORTED;
					goto OUT;
				}

				__s32 c_seq_offset = nums_ptr->seq_no - server_nums_ptr->seq_no;
				__s32 c_ack_offset = nums_ptr->ack_no - server_nums_ptr->ack_no;

				__s32 s_seq_offset = server_nums_ptr->ack_no - nums_ptr->ack_no;
				__s32 s_ack_offset = server_nums_ptr->seq_no - nums_ptr->seq_no;

				// bpf_printk("Server conn.seq: %u, conn.ack: %u\n", server_nums_ptr->seq_no, server_nums_ptr->ack_no);
				// bpf_printk("Client conn.seq: %u, conn.ack: %u\n", nums_ptr->seq_no, nums_ptr->ack_no);
				// bpf_printk("c_seq_offset: %d, c_ack_offset: %d", c_seq_offset, c_ack_offset);
				// bpf_printk("Client.seq after: %u, Client.ack after: %u", nums_ptr->seq_no - c_seq_offset, nums_ptr->ack_no - c_ack_offset);

				// First correct client->LB reroute
				reroute_ptr->original_conn = reroute_ptr->new_conn;
				reroute_ptr->original_index = reroute_ptr->new_index;
				reroute_ptr->seq_offset = c_seq_offset;
				reroute_ptr->ack_offset = c_ack_offset;
				reroute_ptr->rematch_flag = 0;

				if (bpf_map_update_elem(&conn_map, &conn, reroute_ptr, 0) < 0) {
					bpf_printk("REMATCH - Unable to upate reroute object for (conn.src %u, conn.dst %u)\n", conn.src_port, conn.dst_port);
					action = XDP_ABORTED;
					goto OUT;
				}

				// Next correct server->LB reroute
				struct reroute rev_reroute;
				rev_reroute.original_conn = create_reverse_conn(&conn);
				rev_reroute.seq_offset = s_seq_offset;
				rev_reroute.ack_offset = s_ack_offset;
				rev_reroute.original_index = 0;
				rev_reroute.new_index = 0;
				rev_reroute.new_conn = rev_reroute.original_conn;
				struct connection rev_new_server = create_reverse_conn(&reroute_ptr->new_conn);

				if (bpf_map_update_elem(&conn_map, &rev_new_server, &rev_reroute, 0) < 0) {
					bpf_printk("REMATCH - Unable to upate reroute object for (conn.src %u, conn.dst %u)\n", rev_new_server.src_port, rev_new_server.dst_port);
					action = XDP_ABORTED;
					goto OUT;
				}			
			}
		}

		// Update state to be zero
		if (payload_len > 0 && from_client(&conn)) {
			__u32 zero = 0;
			if (bpf_map_update_elem(&state_map, &conn.src_port, &zero, 0) < 0) {
				bpf_printk("STATE - unable to change state to 0 for conn.src: %u\n", conn.src_port);
				action = XDP_ABORTED;
				goto OUT;
			}
		} else if (payload_len > 0 && from_server(&conn)) {
			__u32 one = 1;
			if (bpf_map_update_elem(&state_map, &reroute_ptr->original_conn.dst_port, &one, 0) < 0) {
				bpf_printk("STATE - unable to change state to 1 for original_conn.dst: %u\n", reroute_ptr->original_conn.dst_port);
			}
		}
		

		modify_seq_ack(&tcph, reroute_ptr->seq_offset, reroute_ptr->ack_offset);
		tcph->source = bpf_htons(reroute_ptr->original_conn.src_port);
		tcph->dest = bpf_htons(reroute_ptr->original_conn.dst_port);
		iph->saddr = reroute_ptr->original_conn.src_ip;
		iph->daddr = reroute_ptr->original_conn.dst_ip;
			
		// bpf_printk("AFTER MODIFICATION - tcp.src: %u, tcp.dst %u\n", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
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