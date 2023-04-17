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
			if (bpf_map_update_elem(&ports_map, &conn.src_port, &conn.dst_port, 0) < 0) {
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

		struct offset_key query_offset;
		query_offset.original_port = 4173;
		query_offset.new_port = 4172;	

		if (tcph->psh && conn.dst_port == 4173) {
			bpf_printk("re-routing the message from 4173 to 4172");

			unsigned int *prev_port = bpf_map_lookup_elem(&ports_map, &query_offset.new_port);
			if (!prev_port) {
				bpf_printk("could not query ports_map for rerouting");
				action = XDP_ABORTED;
				goto OUT;
			}

			struct connection query_conn;
			query_conn.dst_port = 4172;
			query_conn.src_port = *prev_port;
			bpf_printk("client port extracted is %u", query_conn.dst_port);

			signed int seq_off;
			signed int ack_off;
			unsigned int ack_seq_new;
			unsigned int seq_new;

			unsigned int *check_off = bpf_map_lookup_elem(&seq_offsets, &query_offset);	
			if (!check_off) {
				bpf_printk("no offset detected when sending data");

				unsigned int *ack_seq_new_ptr = bpf_map_lookup_elem(&ack_map, &query_conn);
				if (!ack_seq_new_ptr) {
					bpf_printk("could not query seq_map for rerouting");
					action = XDP_ABORTED;
					goto OUT;
				}
				ack_seq_new = *ack_seq_new_ptr;
				bpf_printk("new ack seq no is %u", ack_seq_new);

				
				unsigned int *seq_new_ptr = bpf_map_lookup_elem(&seq_map, &query_conn);
				if (!seq_new_ptr) {
					bpf_printk("could not query seq_map for rerouting");
					action = XDP_ABORTED;
					goto OUT;
				}
				seq_new = *seq_new_ptr;
				bpf_printk("new seq no is %u", seq_new);

				seq_off = seq_no - seq_new;
				bpf_printk("seq no offset is %d", seq_off);
				ack_off = ack_no - ack_seq_new;
				bpf_printk("ack_seq no offset is %d", ack_off);

				bpf_printk("before updating seq offsets");
				if (bpf_map_update_elem(&seq_offsets, &query_offset, &seq_off, 0) < 0) {
					action = XDP_ABORTED;
					goto OUT;
				}
				bpf_printk("updated seq offsets");

				bpf_printk("before updating ack offsets");
				if (bpf_map_update_elem(&ack_offsets, &query_offset, &ack_off, 0) < 0) {
					action = XDP_ABORTED;
					goto OUT;
				}
				bpf_printk("updated ack offsets");
			} else {
				signed int *seq_off_ptr = bpf_map_lookup_elem(&seq_offsets, &query_offset);
				if (!seq_off_ptr) {
					bpf_printk("could not query ports_map for rerouting");
					action = XDP_ABORTED;
					goto OUT;
				}
				seq_off = *seq_off_ptr;
				bpf_printk("seq off retrieved is %u", seq_off);

				unsigned int *ack_off_ptr = bpf_map_lookup_elem(&ack_offsets, &query_offset);
				if (!ack_off_ptr) {
					bpf_printk("could not query ports_map for rerouting");
					action = XDP_ABORTED;
					goto OUT;
				}
				ack_off = *ack_off_ptr;
				bpf_printk("ack_seq off retrieved is %u", ack_off);

				seq_new = seq_no - seq_off;
				ack_seq_new = ack_no - ack_off;
			}

			tcph->source = bpf_htons(query_conn.src_port);
			tcph->dest = bpf_htons(4172);
			tcph->seq = bpf_htonl(seq_new);
			tcph->ack_seq = bpf_htonl(ack_seq_new);

		} else if (conn.src_port == 4172) {

			unsigned int *check_off = bpf_map_lookup_elem(&seq_offsets, &query_offset);	
			if (!check_off) {
				bpf_printk("no offset detected");
			} else {
				bpf_printk("re-routing the message from 4172's client to 4173's");
				unsigned int *return_port = bpf_map_lookup_elem(&ports_map, &query_offset.original_port);
				if (!return_port) {
					bpf_printk("could not query ports_map for rerouting");
					action = XDP_ABORTED;
					goto OUT;
				}

				unsigned int *seq_off = bpf_map_lookup_elem(&seq_offsets, &query_offset);
				if (!seq_off) {
					bpf_printk("could not query ports_map for rerouting");
					action = XDP_ABORTED;
					goto OUT;
				}
				bpf_printk("seq off retrieved is %u", *seq_off);

				unsigned int *ack_off = bpf_map_lookup_elem(&ack_offsets, &query_offset);
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

				tcph->source = bpf_htons(4173);
				tcph->dest = bpf_htons(*return_port);
				tcph->seq = bpf_htonl(new_seq_no);
				tcph->ack_seq = bpf_htonl(new_ack_no);
			}
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