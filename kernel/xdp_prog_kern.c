#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>

#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"
#include "./common.h"

#define max(a,b)             \
({                           \
    __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b;       \
})

struct bpf_map_def SEC("maps") conn_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(struct connection),
	.max_entries = 20,
};

struct bpf_map_def SEC("maps") numbers_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct connection),
	.value_size  = sizeof(struct numbers),
	.max_entries = 20,
};

static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
	return csum;
}

static inline unsigned short generic_checksum(unsigned short *buf, void *data_end, unsigned long sum, int max) 
{
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
	bpf_printk("tcp src port is %u and dst port is %u", conn.src_port, conn.dst_port);
	conn.src_ip = iph->saddr;
	conn.dst_ip = iph->daddr;
	bpf_printk("ip before endian conversion s %u and d %u", iph->saddr, iph->daddr);
	bpf_printk("ip header saddr %u and daddr %u", conn.src_ip, conn.dst_ip);

	if (tcph->syn && (conn.dst_port != 8080 && conn.dst_port != 4170 && conn.dst_port != 4171 && conn.src_port != 8080 && conn.src_port != 4170 && conn.src_port != 4171)) {
		bpf_printk("reset packet detected");
		action = XDP_DROP;
		goto OUT;
	} else if (tcph->fin) {
		bpf_printk("before deleting numbers from numbers map");
		if (bpf_map_delete_elem(&numbers_map, &conn) < 0) {
			bpf_printk("failed deleting numbers from numbers map");
		}
		bpf_printk("after attempting to delete numbers from numbers map");

		struct connection *other_conn_ptr = bpf_map_lookup_elem(&conn_map, &conn);
		if (!other_conn_ptr) {
			bpf_printk("could not find other conn to delete from map");
		} else {
			struct connection other_conn = *other_conn_ptr;
			bpf_printk("before deleting other conn from  ports map");
			if (bpf_map_delete_elem(&conn_map, &other_conn) < 0) {
				bpf_printk("failed deleting from ports map");
			}
			bpf_printk("after attempting to delete other conn from ports map");
		}		

		bpf_printk("before deleting conn from  ports map");
		if (bpf_map_delete_elem(&conn_map, &conn) < 0) {
			bpf_printk("failed deleting from ports map");
		}
		bpf_printk("after attempting to delete from ports map");

		goto OUT;
	} else if (conn.dst_port == 8080 || (conn.src_port == 4170 || conn.src_port == 4171)) {
		unsigned int seq_no = bpf_ntohl(tcph->seq);
		unsigned int ack_no = bpf_ntohl(tcph->ack_seq);
		
		struct numbers *numbers_elem_ptr = bpf_map_lookup_elem(&numbers_map, &conn);
		struct numbers numbers_elem;
		if (!numbers_elem_ptr) {
			bpf_printk("could not find numbers elem in numbers map");
			numbers_elem.seq_offset = 0;
			numbers_elem.ack_offset = 0;
		} else {
			bpf_printk("successfully found numbers elem in numbers map");
			numbers_elem = *(numbers_elem_ptr);
			seq_no = max(seq_no, numbers_elem.seq_no);
			ack_no = max(ack_no, numbers_elem.ack_no);
		}

		numbers_elem.seq_no = seq_no;
		numbers_elem.ack_no = ack_no;

		bpf_printk("before updating numbers map");
		if (bpf_map_update_elem(&numbers_map, &conn, &numbers_elem, 0) < 0) {
			bpf_printk("failed updating numbers map");
			action = XDP_ABORTED;
			goto OUT;
		}
		bpf_printk("successfully updated numbers map");
	}

	struct connection *outgoing_conn_ptr = bpf_map_lookup_elem(&conn_map, &conn);
	if (!outgoing_conn_ptr) {
		bpf_printk("could not query conn_map for rerouting");
		goto OUT;
	} else {
		bpf_printk("found connection to rerouter to");
		struct connection outgoing_conn = *(outgoing_conn_ptr);

		struct numbers *numbers_elem_ptr = bpf_map_lookup_elem(&numbers_map, &conn);
		if (!numbers_elem_ptr) {
			bpf_printk("could not find numbers elem in numers map");
			action = XDP_ABORTED;
			goto OUT;
		}
		struct numbers numbers_elem = *numbers_elem_ptr;

		signed int seq_off = numbers_elem.seq_offset;
		signed int ack_off = numbers_elem.ack_offset;

		unsigned int cur_seq = bpf_ntohl(tcph->seq);
		unsigned int cur_ack = bpf_ntohl(tcph->ack_seq);

		tcph->source = bpf_htons(outgoing_conn.src_port);
		tcph->dest = bpf_htons(outgoing_conn.dst_port);
		unsigned int new_seq = cur_seq - seq_off;
		tcph->seq = bpf_htonl(new_seq);
		unsigned int new_ack_seq = cur_ack - ack_off; 
		tcph->ack_seq = bpf_htonl(new_ack_seq);

		//swap_src_dst_ipv4(iph);
		iph->saddr = outgoing_conn.src_ip;
		iph->daddr = outgoing_conn.dst_ip;
		bpf_printk("modified ip addresses");
		bpf_printk("ip header saddr %u and daddr %u", outgoing_conn.src_ip, outgoing_conn.dst_ip);

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