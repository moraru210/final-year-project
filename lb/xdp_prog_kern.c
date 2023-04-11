#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

struct bpf_map_def SEC("maps") ports_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 6,
};

struct bpf_map_def SEC("maps") seq_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 6,
};

struct bpf_map_def SEC("maps") ack_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 6,
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

// static inline int get_offset(unsigned int *current_seq, int *new_port) {
// 	void *new_seq_no;
// 	new_seq_no = bpf_map_lookup_elem(&ports_map, new_port);
// 	if (!new_seq_no) {
// 		return -1;
// 	}

// 	return *current_seq - *((int *)new_seq_no);
// }

SEC("xdp_tcp")
int  xdp_prog_tcp(struct xdp_md *ctx)
{
	// int offset = 0;

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	__u32 action = XDP_DROP; /* Default action */
	struct hdr_cursor nh;
	int eth_type, ip_type;

	nh.pos = data;

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

	if (bpf_ntohs(tcph->dest) == 4172 || bpf_ntohs(tcph->dest) == 4173 || bpf_ntohs(tcph->source) == 4173 || bpf_ntohs(tcph->source) == 4174) {
		if (bpf_ntohs(tcph->dest) == 4172) {

			unsigned int new_dest = 4173;
			unsigned int *res = bpf_map_lookup_elem(&ports_map, &new_dest);
			if (!res) {
				action = XDP_ABORTED;
				goto OUT;
			}

			unsigned int next_dest = 4174;
			unsigned int *next_port_seq = bpf_map_lookup_elem(&seq_map, &next_dest);
			if (!next_port_seq) {
				action = XDP_ABORTED;
				goto OUT;
			}

			unsigned int *next_port_ack = bpf_map_lookup_elem(&ack_map, &next_dest);
			if (!next_port_ack) {
				action = XDP_ABORTED;
				goto OUT;
			}		

			unsigned int seq_no = tcph->seq;
			unsigned int ack_seq_no = tcph->ack_seq;
			if (*res == 2) {
				new_dest = next_dest;
				seq_no = *next_port_seq;
				ack_seq_no = *next_port_ack;
			}
			__sync_fetch_and_add(res, 1);

			// if (new_dest != current) {
			// 	offset = get_offset(&seq_no, &new_dest);
			// 	current = new_dest;
			// }
			
			tcph->dest = bpf_htons(new_dest);
			tcph->seq = seq_no;
			tcph->ack = ack_seq_no;

		} else if (bpf_ntohs(tcph->dest) == 4173) {
			unsigned int new_dest = 4174;
			tcph->dest = bpf_htons(4174);

			unsigned int seq_no = tcph->seq;
			unsigned int ack_seq_no = tcph->ack_seq;

			if (bpf_map_update_elem(&seq_map, &new_dest, &seq_no, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}

			if (bpf_map_update_elem(&ack_map, &new_dest, &ack_seq_no, 0) < 0) {
				action = XDP_ABORTED;
				goto OUT;
			}

		} else if (bpf_ntohs(tcph->source) == 4173) {
			
			// int target_port = bpf_ntohs(tcph->source);
			unsigned int ack_seq = tcph->ack_seq;
			// if (target_port != current) {
			// 	action = XDP_ABORTED;
			// 	goto OUT;
			// }

			tcph->source = bpf_htons(4172);
			tcph->ack_seq = ack_seq;

		} else if (bpf_ntohs(tcph->source) == 4174) {
			// int target_port = bpf_ntohs(tcph->source);
			unsigned int ack_seq = tcph->ack_seq;
			// if (target_port != current) {
			// 	action = XDP_ABORTED;
			// 	goto OUT;
			// }

			tcph->source = bpf_htons(4173);
			tcph->ack_seq = ack_seq;
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