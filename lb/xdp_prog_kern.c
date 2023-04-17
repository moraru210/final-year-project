#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "./common.h"

struct bpf_map_def SEC("maps") ports_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 18,
};

struct bpf_map_def SEC("maps") ports_offsets = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 18,
};

struct bpf_map_def SEC("maps") seq_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(unsigned int),
	.max_entries = 18,
};

struct bpf_map_def SEC("maps") ack_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(unsigned int),
	.max_entries = 18,
};

struct bpf_map_def SEC("maps") seq_offsets = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct offset_key),
	.value_size  = sizeof(signed int),
	.max_entries = 18,
};

struct bpf_map_def SEC("maps") ack_offsets = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct offset_key),
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

	if (conn.dst_port == 4172 || conn.dst_port == 4173 || conn.src_port == 4172 || conn.src_port == 4173) {
		bpf_printk("packet for dst %d, src %d", conn.dst_port, conn.src_port);

		if (tcph->syn) {
			bpf_printk("handling syn packet");
			bpf_printk("before updating ports map");
			unsigned int zero = 0;
			if (bpf_map_update_elem(&ports_map, &conn.src_port, &zero, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated ports map");
		}
			
		unsigned int seq_no = bpf_ntohl(tcph->seq);
		bpf_printk("seq_no: %u, after endian conversion is: %u", tcph->seq, seq_no);
		unsigned int ack_no = bpf_ntohl(tcph->ack_seq);
		bpf_printk("ack_seq_no: %u, after endian conversion is: %u", tcph->ack_seq, ack_no);
		
		if (tcph->ack) {
			struct connection query_conn;
			query_conn.src_port = conn.src_port;
			query_conn.dst_port = conn.dst_port;
			
			bpf_printk("before updating seq map");
			if (bpf_map_update_elem(&seq_map, &query_conn, &seq_no, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated seq map");

			bpf_printk("before updating ack map");
			if (bpf_map_update_elem(&ack_map, &query_conn, &ack_no, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated ack map");
		}

		if (tcph->psh && conn.dst_port == 4173) {
			bpf_printk("re-routing the message from 4173 to 4172");

			struct connection query_conn;
			query_conn.src_port = 4172;
			query_conn.dst_port = 47160; //hard-coded

			unsigned int *prev_port = bpf_map_lookup_elem(&seq_map, &query_conn.src_port);
			if (!prev_port) {
				bpf_printk("could not query ports_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			query_conn.dst_port = *prev_port;
			
			unsigned int *ack_seq_new = bpf_map_lookup_elem(&seq_map, &query_conn);
			if (!ack_seq_new) {
				bpf_printk("could not query seq_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}

			unsigned int *seq_new = bpf_map_lookup_elem(&ack_map, &query_conn);
			if (!ack_seq_new) {
				bpf_printk("could not query ack_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}

			signed int seq_off = seq_no - *seq_new;
			signed int ack_off = ack_no - *ack_seq_new;

			struct offset_key query_offset;
			query_offset.new_port = 4172;
			query_offset.original_port = 4173;

			bpf_printk("before updating seq offsets");
			if (bpf_map_update_elem(&seq_offsets, &query_conn, &seq_off, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated seq offsets");

			bpf_printk("before updating ack offsets");
			if (bpf_map_update_elem(&ack_offsets, &query_conn, &ack_off, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}
			bpf_printk("updated ack offsets");

			tcph->source = bpf_htons(query_conn.dst_port);
			tcph->dest = bpf_htons(4172);
			tcph->seq = bpf_htonl(*seq_new);
			tcph->ack_seq = bpf_htonl(*ack_seq_new);

		} else if (!(tcph->syn) && conn.src_port == 4172) {
			bpf_printk("re-routing ack from 4172 to correct client");

			struct connection query_conn;
			query_conn.src_port = 4173;
			query_conn.dst_port = 47160; //hard-coded

			unsigned int *change_port = bpf_map_lookup_elem(&seq_map, &query_conn.src_port);
			if (!change_port) {
				bpf_printk("could not query ports_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}
			query_conn.dst_port = *change_port;

			struct offset_key query_offset;
			query_offset.new_port = 4172;
			query_offset.original_port = 4173;

			signed int *ack_off = bpf_map_lookup_elem(&ack_offsets, &query_offset);
			if (!ack_off) {
				bpf_printk("could not query ack_offset for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}

			signed int *seq_off = bpf_map_lookup_elem(&seq_offsets, &query_offset);
			if (!ack_off) {
				bpf_printk("could not query seq_offset for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}

			unsigned int new_seq = bpf_ntohl(tcph->seq) + *seq_off;
			unsigned int new_ack_seq = bpf_ntohl(tcph->ack_seq) + *ack_off;
			tcph->source = bpf_htons(4173);
			tcph->dest = bpf_htons(query_conn.dst_port);
			tcph->seq = new_seq;
			tcph->ack_seq = new_ack_seq;
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

SEC("xdp_drop")
int xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";