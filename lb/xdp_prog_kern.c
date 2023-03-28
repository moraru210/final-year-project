#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

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

	if (bpf_ntohs(tcph->dest) == 4172 || bpf_ntohs(tcph->source) == 4173) {
		if (bpf_ntohs(tcph->dest) == 4172) {
			__u32 idx = bpf_get_prandom_u32();
			unsigned short mod = (idx % 2); 
			
			tcph->dest = bpf_htons(4173 + mod);
		} else if (bpf_ntohs(tcph->source) == 4173 || bpf_ntohs(tcph->source) == 4174) {
			tcph->source = bpf_htons(4172);
		}

		swap_src_dst_ipv4(iph);
		bpf_printk("Swapped ip addresses");

		swap_src_dst_mac(ethh);
		bpf_printk("Swapped eth addresses");

		bpf_printk("destionation TCP port after is %u", bpf_ntohs(tcph->dest));

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