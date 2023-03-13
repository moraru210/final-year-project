#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

#define MAX_OPT_WORDS 10 // 40 bytes for options
#define MAX_TARGET_COUNT 64 // max number of target servers for LB
#define REDIR_OPT_TYPE 42
#define MAX_UDP_SIZE 1480

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

	return csum;
}

SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	__u32 size = sizeof(struct iphdr);
	struct udphdr *udph;
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
	
	if (ip_type != IPPROTO_UDP) {
		goto OUT;
	}
	bpf_printk("checked if UDP");

	if (parse_udphdr(&nh, data_end, &udph) < 0) {
		goto OUT;
	}
	bpf_printk("parsed UDP header");

	if (bpf_ntohs(udph->dest) == 4172) {
		bpf_printk("DST is 4172");
		udph->dest = bpf_htons(bpf_ntohs(udph->dest)+1);

		swap_src_dst_ipv4(iph);
		bpf_printk("Swapped ip addresses");

		swap_src_dst_mac(ethh);
		bpf_printk("Swapped eth addresses");

		bpf_printk("destionation udp port after is %u", bpf_ntohs(udph->dest));

		iph->check = 0;
		iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, size, 0));

		//TODO:
		udph->check = 0;

		action = XDP_TX;
	}
OUT:
	return action;
}

SEC("xdp_tcp")
int  xdp_prog_tcp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	__u32 size_ip = sizeof(struct iphdr);
	__u32 size_tcp = sizeof(struct tcphdr);
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

	if (bpf_ntohs(tcph->dest) == 4172) {
		bpf_printk("DST will be 4173");
		tcph->dest = bpf_htons(bpf_ntohs(tcph->dest)+1);

		swap_src_dst_ipv4(iph);
		bpf_printk("Swapped ip addresses");

		swap_src_dst_mac(ethh);
		bpf_printk("Swapped eth addresses");

		bpf_printk("destionation udp port after is %u", bpf_ntohs(tcph->dest));

		iph->check = 0;
		iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, size_ip, 0));

		//TODO: fix tcp checksum
		tcph->check = 0;
		tcph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)tcph, size_tcp, 0));

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