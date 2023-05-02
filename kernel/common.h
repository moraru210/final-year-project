struct __attribute__((packed)) connection {
	unsigned int src_port;
	unsigned int dst_port;
};

struct __attribute__((packed)) offset_key {
	unsigned int original_port;
	unsigned int new_port;
};