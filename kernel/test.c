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

/* Define maps */
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

// static __always_inline __u16 csum_reduce_helper(__u32 csum)
// {
// 	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
// 	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
// 	return csum;
// }

// static inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) 
// {
//     for (int i = 0; i < max; i += 2) {
// 	if ((void *)(buf + 1) > data_end)
// 	    break;
//         sum += *buf;
//         buf++;
//     }
//     if((void *)buf +1 <= data_end) {
// 		sum +=  bpf_htons((*((unsigned char *)buf)) << 8);
//     }
//     sum = (sum & 0xffff) + (sum >> 16);
//     sum = (sum & 0xffff) + (sum >> 16);
//     return ~sum;
// }

// static inline __u16 l4_checksum(struct iphdr *iph, void *l4, void *data_end)
// {
//     __u32 csum = 0;
//     csum += *(((__u16 *) &(iph->saddr))+0); // 1st 2 bytes
//     csum += *(((__u16 *) &(iph->saddr))+1); // 2nd 2 bytes
//     csum += *(((__u16 *) &(iph->daddr))+0); // 1st 2 bytes
//     csum += *(((__u16 *) &(iph->daddr))+1); // 2nd 2 bytes
//     csum += bpf_htons((__u16)iph->protocol); // protocol is a u8
//     csum += bpf_htons((__u16)(data_end - (void *)l4)); 
//     return generic_checksum((unsigned short *) l4, data_end, csum, 1480);
// }

// static inline void perform_checksums(struct tcphdr *tcph, struct iphdr *iph, void *data_end)
// {
// 	iph->check = 0;
// 	iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));
// 	tcph->check = 0;
// 	tcph->check = l4_checksum(iph, tcph, data_end);
// }

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

// static inline int from_client(struct connection *conn)
// {
// 	if (conn->dst_port == LB_LISTENER_PORT) {
// 			return 1;
// 	}
// 	return 0;
// }

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

static inline int generate_and_insert_numbers(struct connection *conn, __u32 *seq_no, __u32 *ack_no) {
	struct numbers nums;
	nums.seq_no = *ack_no;
	nums.ack_no = *seq_no + 1;

	nums.init_seq = nums.seq_no;
	nums.init_ack = nums.ack_no;

	bpf_printk("Number struct generated\n");
	bpf_printk("Nums.seq: %u\n", nums.seq_no);
	bpf_printk("Nums.ack: %u\n", nums.ack_no);

	if (bpf_map_update_elem(&numbers_map, conn, &nums, 0) < 0) {
		bpf_printk("Unable to introduce (conn.src: %u, conn.dst: %u) to numbers_map\n", conn->src_port, conn->dst_port);
		return 0;
	}
	return 1;
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

    if (tcph->ack) {
		bpf_printk("ACK Packet - Sequence Number: %u\n", seq_no);
        bpf_printk("ACK Packet - Acknowledge Number: %u\n", ack_seq);
    }
    
	int payload_len = bpf_ntohs(iph->tot_len) - (sizeof(struct iphdr) + tcph_len);
    if (payload_len > 0) {
        // Payload present
        // Calculate acknowledgment number
        __u32 seq_num = bpf_ntohl(tcph->seq);
        __u32 ack_num = seq_num + payload_len;

        // Print the payload size and predicted acknowledgment number
        bpf_printk("Payload Size: %d bytes, Predicted Acknowledgment Number: %u\n", payload_len, ack_num);
    }

	struct connection conn = create_conn_struct(&tcph, &iph);
	if (tcph->syn && tcph->ack && (to_client(&conn) || from_server(&conn))) {
		
		if (!generate_and_insert_numbers(&conn, &seq_no, &ack_seq)) {
			action = XDP_ABORTED;
			goto OUT;
		}
		
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