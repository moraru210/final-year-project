# Final Year Project
Repository dedicated for my final year project at Imperial College London. 

The project aims to bridge the gap between layer 4 and 7 load balancer categories (however still working at the 4th layer) by creating a load balancer that can remix the connection table initial matching without having to terminate connections already set up.

Requirements from project:
- The design should work in the presence of packet loss and retransmissions.
- The design should work in the presence of out of order packets.

Assumptions made:
- There is a single outstanding request for every connection.
- To get a reply the request must have been fully received.
- To get the next request the previous response must have been fully received.

## Implementation
The project comprises of two main components. The first is the kernel code, located in the `kernel` folder in the repository and it is attached to a network device. The other component is code that runs in userspace, which is located in the `userspace` folder in the repository.

### Kernel Space
The eBPF code that is to be attached to a network device is found in `kernel/xdp_prog_kern.c`. For developmental processes, after compiling and generating the ELF file you may run `sudo bash local_script.sh` with or without the `-r or --reuse` flag - this attaches the aforementioned eBPF code to the `lo` device and runs each packet it detects through the `xdp_tcp` program.

The eBPF program initialises two main maps that it utilises to modify a packet's information - the `conn_map` and `numbers_map`. The `conn_map` uses `struct connection` for both its keys and values, and the struct is defined in `kernel/common.h`. The struct stores the 4-tuple information (source port, destination port, source ip adress, destination ip address) that is required to redirect a packet to the correct interface. The purpose of this map is to identify if the packet needs to be rerouted (by checking if it's 4-tuple exists in the map) and modifying the specific header values with the value struct retured by the map if a result is found.
