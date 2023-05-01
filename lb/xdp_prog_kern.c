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
	__u32 action = XDP_PASS; /* Default action */
	struct hdr_cursor nh;
	int eth_type, ip_type;

	nh.pos = data;

	bpf_printk("*** start of a new packet ***");

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
	bpf_printk("parsed TCP header");

	struct connection conn;
	conn.src_port = bpf_ntohs(tcph->source);
	conn.dst_port = bpf_ntohs(tcph->dest);

	if (conn.dst_port == 8080 || (conn.src_port == 4170 || conn.src_port == 4171)) {
		bpf_printk("before updating seq map");
		if (bpf_map_update_elem(&seq_map, &conn, &tcph->seq, 0) < 0) {
			bpf_printk("failed updating seq map");
			action = XDP_ABORTED;
			goto OUT;
		}
		bpf_printk("successfully updated seq map");

		bpf_printk("before updating ack map");
		if (bpf_map_update_elem(&ack_map, &conn, &tcph->ack_seq, 0) < 0) {
			bpf_printk("failed updating ack map");
			action = XDP_ABORTED;
			goto OUT;
		}
		bpf_printk("successfully updated ack map");
	}

	struct connection *outgoing_conn_ptr = bpf_map_lookup_elem(&ports_map, &conn);
	if (!outgoing_conn_ptr) {
		bpf_printk("could not query ports_map for rerouting");
		goto OUT;
	} else {
		bpf_printk("found connection to rerouter to");
		struct connection outgoing_conn = *(outgoing_conn_ptr);

		signed int *seq_off_ptr = bpf_map_lookup_elem(&seq_offsets, &conn);
		if (!seq_off_ptr) {
			bpf_printk("could not find offset for seq no");
			action = XDP_ABORTED;
			goto OUT;
		}
		signed int seq_off = *seq_off_ptr;

		signed int *ack_off_ptr = bpf_map_lookup_elem(&ack_offsets, &conn);
		if (!ack_off_ptr) {
			bpf_printk("could not find offset for seq no");
			action = XDP_ABORTED;
			goto OUT;
		}
		signed int ack_off = *ack_off_ptr;

		unsigned int cur_seq = tcph->seq;
		unsigned int cur_ack = tcph->ack_seq;

		tcph->source = bpf_htons(outgoing_conn.src_port);
		tcph->dest = bpf_htons(outgoing_conn.dst_port);
		tcph->seq = cur_seq - seq_off;
		tcph->ack_seq = cur_ack - ack_off; 

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