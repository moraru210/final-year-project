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

struct bpf_map_def SEC("maps") tx_port = {
	.type = BPF_MAP_TYPE_DEVMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 256,
};

struct bpf_map_def SEC("maps") redirect_params = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = ETH_ALEN,
	.value_size = ETH_ALEN,
	.max_entries = 1,
};

static __always_inline __u16 udp_checksum(struct iphdr *ip, struct udphdr * udp, void * data_end)
{
    __u16 csum = 0;
    __u16 *buf = (__u16*)udp;

    // Compute pseudo-header checksum
    csum += ip->saddr;
    csum += ip->saddr >> 16;
    csum += ip->daddr;
    csum += ip->daddr >> 16;
    csum += (__u16)ip->protocol << 8;
    csum += udp->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) {
        if ((void *)(buf + 1) > data_end) {
            break;
        }
        csum += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) {
       // In case payload is not 2 bytes aligned
        csum += *(__u8 *)buf;
    }

   //csum = ~csum;
   return csum;
}

static __always_inline __u16 ip_checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1) {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    return ~sum;
}

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
	// struct ipv6hdr *ipv6hdr;
	struct udphdr *udph;
	__u32 action = XDP_DROP; /* Default action */
	struct hdr_cursor nh;
	// int nh_type;
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

		// Fix IP checksum
		iph->check = 0;
		iph->check = ~csum_reduce_helper(bpf_csum_diff(0, 0, (__be32 *)iph, size, 0));

		//Fix UDP checksum
		udph->check = 0;
		// __u32 csum = udp_checksum(iph, udph, data_end);
		// udph->check = ~csum_reduce_helper(csum);

		action = XDP_TX;
	}
OUT:
	return action;
}

/* Solution to packet03/assignment-2 */
SEC("xdp_redirect")
int xdp_redirect_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS; //aa:11:1e:a8:f8:42
	unsigned char dst[ETH_ALEN + 1] = { 0xaa,0x11,0x1e,0xa8,0xf8,0x42, '\0' };
	unsigned ifindex =  9; /* TODO: put your values here */

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect(ifindex, 0);

out:
	return action;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
	__u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

/*
 * The icmp_checksum_diff function takes pointers to old and new structures and
 * the old checksum and returns the new checksum.  It uses the bpf_csum_diff
 * helper to compute the checksum difference. Note that the sizes passed to the
 * bpf_csum_diff helper should be multiples of 4, as it operates on 32-bit
 * words.
 */
static __always_inline __u16 icmp_checksum_diff(
		__u16 seed,
		struct icmphdr_common *icmphdr_new,
		struct icmphdr_common *icmphdr_old)
{
	__u32 csum, size = sizeof(struct icmphdr_common);

	csum = bpf_csum_diff((__be32 *)icmphdr_old, size, (__be32 *)icmphdr_new, size, seed);
	return csum_fold_helper(csum);
}

SEC("xdp_icmp_echo")
int xdp_icmp_echo_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	int icmp_type;
	struct iphdr *iphdr;
	struct ipv6hdr *ipv6hdr;
	__u16 echo_reply, old_csum;
	struct icmphdr_common *icmphdr;
	struct icmphdr_common icmphdr_old;
	__u32 action = XDP_PASS;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type != IPPROTO_ICMP)
			goto out;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)) {
		ip_type = parse_ip6hdr(&nh, data_end, &ipv6hdr);
		if (ip_type != IPPROTO_ICMPV6)
			goto out;
	} else {
		goto out;
	}

	/*
	 * We are using a special parser here which returns a stucture
	 * containing the "protocol-independent" part of an ICMP or ICMPv6
	 * header.  For purposes of this Assignment we are not interested in
	 * the rest of the structure.
	 */
	icmp_type = parse_icmphdr_common(&nh, data_end, &icmphdr);
	if (eth_type == bpf_htons(ETH_P_IP) && icmp_type == ICMP_ECHO) {
		/* Swap IP source and destination */
		swap_src_dst_ipv4(iphdr);
		echo_reply = ICMP_ECHOREPLY;
	} else if (eth_type == bpf_htons(ETH_P_IPV6)
		   && icmp_type == ICMPV6_ECHO_REQUEST) {
		/* Swap IPv6 source and destination */
		swap_src_dst_ipv6(ipv6hdr);
		echo_reply = ICMPV6_ECHO_REPLY;
	} else {
		goto out;
	}

	/* Swap Ethernet source and destination */
	swap_src_dst_mac(eth);


	/* Patch the packet and update the checksum.*/
	old_csum = icmphdr->cksum;
	icmphdr->cksum = 0;
	icmphdr_old = *icmphdr;
	icmphdr->type = echo_reply;
	icmphdr->cksum = icmp_checksum_diff(~old_csum, icmphdr, &icmphdr_old);

	action = XDP_TX;

out:
	return action;
}

/* Solution to packet03/assignment-3 */
SEC("xdp_redirect_map")
int xdp_redirect_map_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct hdr_cursor nh;
	struct ethhdr *eth;
	int eth_type;
	int action = XDP_PASS;
	unsigned char *dst;

	/* These keep track of the next header type and iterator pointer */
	nh.pos = data;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == -1)
		goto out;

	/* Do we know where to redirect this packet? */
	dst = bpf_map_lookup_elem(&redirect_params, eth->h_source);
	if (!dst)
		goto out;

	/* Set a proper destination address */
	memcpy(eth->h_dest, dst, ETH_ALEN);
	action = bpf_redirect_map(&tx_port, 0, 0);

out:
	return action;
}

/* Solution to packet03/assignment-3 */
SEC("xdp_rm_udp")
int xdp_rm_udp_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh;
	struct iphdr *iph;
	// struct ipv6hdr *ipv6hdr;
	struct udphdr *udph;
	__u32 action = XDP_DROP; /* Default action */
	struct hdr_cursor nh;
	// int nh_type;
	int eth_type, ip_type;
	unsigned char *dst;

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
		//action = XDP_DROP;
		goto OUT;
	}
	bpf_printk("parsed UDP header");

	if (bpf_ntohs(udph->dest) == 4172) {
		bpf_printk("DST is 4172");
		udph->dest = bpf_htons(bpf_ntohs(udph->dest)+1);

		/* Do we know where to redirect this packet? */
		dst = bpf_map_lookup_elem(&redirect_params, ethh->h_source);
		if (!dst)
			goto OUT;

		/* Set a proper destination address */
		memcpy(ethh->h_dest, dst, ETH_ALEN);
		action = bpf_redirect_map(&tx_port, 0, 0);

		bpf_printk("destionation udp pot after is %u", bpf_ntohs(udph->dest));
		iph->check = ip_checksum((__u16 *)iph, sizeof(struct iphdr));
		udph->check = udp_checksum(iph, udph, data_end);
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