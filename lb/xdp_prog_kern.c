#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "./common.h"

#define NO_TARGETS 2

struct bpf_map_def SEC("maps") ports_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(struct connection),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") seq_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(unsigned int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") ack_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(unsigned int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") seq_offsets = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(signed int),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") ack_offsets = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(signed int),
	.max_entries = 18,
};

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

static inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) {
    
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

SEC("xdp_tcp")
int  xdp_prog_tcp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 action = XDP_DROP; /* Default action */
	struct hdr_cursor nh;
	int eth_type, ip_type;

	struct connection conn;

	nh.pos = data;

	bpf_printk("*** start of a new packet ***");

	eth_type = parse_ethhdr(&nh, data_end, &ethh);
	if (eth_type < 0) {
		action = XDP_ABORTED;
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
		action = XDP_ABORTED;
		goto OUT;
	}
	bpf_printk("parsed TCP header");

	conn.src_port = bpf_ntohs(tcph->source);
	conn.dst_port = bpf_ntohs(tcph->dest);

	if (conn.dst_port == 4170) {
		//packet is intended for the laod balancer
		bpf_printk("packet for dst %d, src %d", conn.dst_port, conn.src_port);

		unsigned int seq_no = bpf_ntohl(tcph->seq);
		bpf_printk("seq_no: %u, after endian conversion is: %u", tcph->seq, seq_no);
		unsigned int ack_no = bpf_ntohl(tcph->ack_seq);
		bpf_printk("ack_seq_no: %u, after endian conversion is: %u", tcph->ack_seq, ack_no);

		if (tcph->syn) {
			//initialising connection in maps
			bpf_printk("handling syn packet");
			bpf_printk("before updating ports map");
			// choosing target:
			unsigned int target = 4171 + (conn.src_port % NO_TARGETS);
			bpf_printk("target chosen is %u", target);

			struct connection new_conn;
			new_conn.src_port = conn.dst_port;
			new_conn.dst_port = target;

			signed int zero = 0;

			if (bpf_map_update_elem(&ports_map, &new_conn, &conn, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("init ports map");

			if (bpf_map_update_elem(&seq_offsets, &conn, &zero, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("init seq offsets map");

			if (bpf_map_update_elem(&ack_offsets, &conn, &zero, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("init ack offsets map");			

		}  else if (tcph->psh) {
			//packet is sent from client, containing data for listeners
			//check offset maps and apply offsets
			struct connection client_conn;
			client_conn = conn;

			signed int *seq_off_ptr = bpf_map_lookup_elem(&seq_offsets, &client_conn);
			if (!seq_off_ptr) {
				bpf_printk("could not query seq_offsets for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			signed int seq_off = *seq_off_ptr;
			bpf_printk("seq off retrieved is %u", seq_off);

			signed int *ack_off_ptr = bpf_map_lookup_elem(&ack_offsets, &client_conn);
			if (!ack_off_ptr) {
				bpf_printk("could not query ack_offsets for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			signed int ack_off = *ack_off_ptr;
			bpf_printk("ack off retrieved is %u", ack_off);

			unsigned int seq_new = seq_no - seq_off;
			unsigned int ack_seq_new = ack_no - ack_off;

			tcph->source = bpf_htons(client_conn.dst_port);
			tcph->dest = bpf_htons(client_conn.src_port);
			tcph->seq = bpf_htonl(seq_new);
			tcph->ack_seq = bpf_htonl(ack_seq_new);
			bpf_printk("completed rewrite of packet from client to send to target");

		}  else if (conn.src_port >= 4171 && conn.src_port <= 4172) {
			//packet is received from one of target listeners
			//check for offsets and apply offsets
			bpf_printk("handling packet from target with port %u", conn.src_port);
			struct connection query_conn;
			query_conn.src_port = conn.dst_port;
			query_conn.dst_port = conn.src_port;

			struct connection client_conn;
			struct connection *client_conn_ptr = bpf_map_lookup_elem(&ports_map, &query_conn);
			if (!client_conn_ptr) {
				bpf_printk("could not query ports_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			client_conn = *client_conn_ptr;
			bpf_printk("retrieved client connection from map successfully");

			unsigned int *seq_off = bpf_map_lookup_elem(&seq_offsets, &client_conn);
			if (!seq_off) {
				bpf_printk("could not query ports_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("seq off retrieved is %u", *seq_off);

			unsigned int *ack_off = bpf_map_lookup_elem(&ack_offsets, &client_conn);
			if (!ack_off) {
				bpf_printk("could not query ports_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("ack_seq off retrieved is %u", *ack_off);

			unsigned int new_seq_no = seq_no + *ack_off;
			bpf_printk("new seq no is %u", new_seq_no);
			unsigned int new_ack_no = ack_no + *seq_off;
			bpf_printk("new ack_seq no is %u", new_ack_no);

			tcph->source = bpf_htons(4170);
			tcph->dest = bpf_htons(client_conn.src_port);
			tcph->seq = bpf_htonl(new_seq_no);
			tcph->ack_seq = bpf_htonl(new_ack_no);
			bpf_printk("completed rewrite of packet from target to send to client");
		}
		
		if (tcph->ack) {
			bpf_printk("ack packet");
			bpf_printk("before updating seq map");
			if (bpf_map_update_elem(&seq_map, &conn, &seq_no, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated seq map");

			bpf_printk("before updating ack map");
			if (bpf_map_update_elem(&ack_map, &conn, &ack_no, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated ack map");
			bpf_printk("completed updating seq and ack maps");
		}

		swap_src_dst_ipv4(iph);
		bpf_printk("Swapped ip addresses");

		swap_src_dst_mac(ethh);
		bpf_printk("Swapped eth addresses");

		bpf_printk("destination TCP port after is %u", bpf_ntohs(tcph->dest));

		iph->check = 0;
		iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, sizeof(struct iphdr), 0));

		tcph->check = 0;
		tcph->check = l4_checksum(iph, tcph, data_end);

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