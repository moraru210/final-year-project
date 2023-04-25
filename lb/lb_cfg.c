/* SPDX-License-Identifier: GPL-2.0 */

static const char *__doc__ = "XDP redirect helper\n"
	" - Allows to populate/query tx_port and redirect_params maps\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf_endian.h>

#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"

#include "../common/xdp_stats_kern_user.h"

#include "./common.h"

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"redirect-dev",         required_argument,	NULL, 'r' },
	 "Redirect to device <ifname>", "<ifname>", true},

	{{"src-mac", required_argument, NULL, 'L' },
	 "Source MAC address of <dev>", "<mac>", true },

	{{"dest-mac", required_argument, NULL, 'R' },
	 "Destination MAC address of <redirect-dev>", "<mac>", true },

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{0, 0, NULL,  0 }, NULL, false}
};

static int parse_u8(char *str, unsigned char *x)
{
	unsigned long z;

	z = strtoul(str, 0, 16);
	if (z > 0xff)
		return -1;

	if (x)
		*x = z;

	return 0;
}

static int parse_mac(char *str, unsigned char mac[ETH_ALEN])
{
	if (parse_u8(str, &mac[0]) < 0)
		return -1;
	if (parse_u8(str + 3, &mac[1]) < 0)
		return -1;
	if (parse_u8(str + 6, &mac[2]) < 0)
		return -1;
	if (parse_u8(str + 9, &mac[3]) < 0)
		return -1;
	if (parse_u8(str + 12, &mac[4]) < 0)
		return -1;
	if (parse_u8(str + 15, &mac[5]) < 0)
		return -1;

	return 0;
}

static int write_iface_params(int map_fd, unsigned char *src, unsigned char *dest)
{
	if (bpf_map_update_elem(map_fd, src, dest, 0) < 0) {
		fprintf(stderr,
			"WARN: Failed to update bpf map file: err(%d):%s\n",
			errno, strerror(errno));
		return -1;
	}

	printf("forward: %02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x\n",
			src[0], src[1], src[2], src[3], src[4], src[5],
			dest[0], dest[1], dest[2], dest[3], dest[4], dest[5]
	      );

	return 0;
}

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";

int main(int argc, char **argv)
{
	int i;
	int len;
	int ports_map_fd;
	int seq_map_fd;
	int ack_map_fd;
	bool redirect_map;
	char pin_dir[PATH_MAX];
	unsigned char src[ETH_ALEN];
	unsigned char dest[ETH_ALEN];

	struct config cfg = {
		.ifindex   = -1,
		.redirect_ifindex   = -1,
	};

	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	redirect_map = (cfg.ifindex > 0) && (cfg.redirect_ifindex > 0);

	if (cfg.redirect_ifindex > 0 && cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	printf("map dir: %s\n", pin_dir);

	/****************************************************/
	ports_map_fd = open_bpf_map_file(pin_dir, "ports_map", NULL);
	if (ports_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	struct connection query_conn1;
	query_conn1.src_port = 4170; 
	query_conn1.dst_port = 4172; //TODO: make this configurable

	struct connection query_conn2;
	query_conn2.src_port = 4169;
	query_conn2.dst_port = 4171; //TODO: make this configurable

	struct connection client_conn1;
	struct connection client_conn2;

	int err = bpf_map_lookup_elem(ports_map_fd, &query_conn1, &client_conn1);
	if (err < 0) {
		printf("failed finding client connection1\n");
		return EXIT_FAIL_BPF;
	} else {
		printf("client connection found with src port %u\n", client_conn1.src_port);
	}

	err = bpf_map_lookup_elem(ports_map_fd, &query_conn2, &client_conn2);
	if (err < 0) {
		printf("failed finding client connection2\n");
		return EXIT_FAIL_BPF;
	} else {
		printf("client connection found with src port %u\n", client_conn2.src_port);
	}
	/****************************************************/

	seq_map_fd = open_bpf_map_file(pin_dir, "seq_map", NULL);
	if (seq_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	ack_map_fd = open_bpf_map_file(pin_dir, "ack_map", NULL);
	if (ack_map_fd < 0) {
		return EXIT_FAIL_BPF;
	}

	unsigned int c1_seq;
	err = bpf_map_lookup_elem(seq_map_fd, &client_conn1, &c1_seq);
	if (err < 0) {
		printf("failed finding client connection1 seq no\n");
		return EXIT_FAIL_BPF;
	} else {
		printf("client connection1 found seq no %u\n", c1_seq);
	}

	unsigned int c1_ack;
	err = bpf_map_lookup_elem(ack_map_fd, &client_conn1, &c1_ack);
	if (err < 0) {
		printf("failed finding client connection1 ack no\n");
		return EXIT_FAIL_BPF;
	} else {
		printf("client connection1 found ack no %u\n", c1_ack);
	}

	unsigned int c2_seq;
	err = bpf_map_lookup_elem(seq_map_fd, &client_conn2, &c2_seq);
	if (err < 0) {
		printf("failed finding client connection2 seq no\n");
		return EXIT_FAIL_BPF;
	} else {
		printf("client connection2 found seq no %u\n", c2_seq);
	}

	unsigned int c2_ack;
	err = bpf_map_lookup_elem(ack_map_fd, &client_conn2, &c2_ack);
	if (err < 0) {
		printf("failed finding client connection2 ack no\n");
		return EXIT_FAIL_BPF;
	} else {
		printf("client connection2 found ack no %u\n", c2_ack);
	}

	signed int c1_seq_off = c1_seq - c2_seq;
	printf("conn1 seq no offset is %d\n", c1_seq_off);
	signed int c1_ack_off = c1_ack - c2_ack;
	printf("conn1 ack no offset is %d\n", c1_ack_off);

	signed int c2_seq_off = c2_seq - c1_seq;
	printf("conn2 seq no offset is %d\n", c2_seq_off);
	signed int c2_ack_off = c2_ack - c1_ack;
	printf("conn2 ack no offset is %d\n", c2_ack_off);

	/****************************************************/
	// int seq_off_map_fd = open_bpf_map_file(pin_dir, "seq_offsets", NULL);
	// if (seq_off_map_fd < 0) {
	// 	return EXIT_FAIL_BPF;
	// }

	// int ack_off_map_fd = open_bpf_map_file(pin_dir, "ack_offsets", NULL);
	// if (ack_off_map_fd < 0) {
	// 	return EXIT_FAIL_BPF;
	// }

	// err = bpf_map_update_elem(ports_map_fd, &query_conn1, &client_conn2, 0);
	// if (err < 0) {
	// 	printf("failed to update ports maps for client1 to target2\n");
	// } else {
	// 	printf("updated ports maps for client1 to target2\n");
	// }

	// err = bpf_map_update_elem(ports_map_fd, &query_conn2, &client_conn1, 0);
	// if (err < 0) {
	// 	printf("failed to update ports maps for client2 to target1\n");
	// } else {
	// 	printf("updated ports maps for client2 to target1\n");
	// }

	// err = bpf_map_update_elem(seq_off_map_fd, &client_conn1, &c1_seq_off, 0);
	// if (err < 0) {
	// 	printf("failed to update seq offset maps for client conn1\n");
	// } else {
	// 	printf("updated seq offset maps for client conn1\n");
	// }

	// err = bpf_map_update_elem(ack_off_map_fd, &client_conn1, &c1_ack_off, 0);
	// if (err < 0) {
	// 	printf("failed to update ack offset maps for client conn1\n");
	// } else {
	// 	printf("updated ack offset maps for client conn1\n");
	// }

	// err = bpf_map_update_elem(seq_off_map_fd, &client_conn2, &c2_seq_off, 0);
	// if (err < 0) {
	// 	printf("failed to update seq offset maps for client conn2\n");
	// } else {
	// 	printf("updated seq offset maps for client conn2\n");
	// }

	// err = bpf_map_update_elem(ack_off_map_fd, &client_conn2, &c2_ack_off, 0);
	// if (err < 0) {
	// 	printf("failed to update ack offset maps for client conn2\n");
	// } else {
	// 	printf("updated ack offset maps for client conn2\n");
	// }

	return EXIT_OK;
}
