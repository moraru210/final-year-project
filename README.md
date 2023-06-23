# Final Year Project - REMATCHER
Repository dedicated for my final year project at Imperial College London. 

## How To Run
```
sudo make TARGET=<interface> MAX_SERVERS=<integer> MAX_CLIENTS=<integer> MAX_PER_SERVER=<integer> IPv4=<address>
```
- `TARGET` the network interface to attach the XDP code onto
- `IPv4` the IP address assigned to the load-balancer
- `MAX_CLIENTS` maximum number of clients the load-balancer will endure
- `MAX_SERVERS` maximum number of servers the load-balancer will endure
- `MAX_PER_SERVER` number of open connections between the middlebox and each server


## Project's Motivation
Is there a middle-ground in terms of benefits when considering the layer-4 versus layer-7 and software versus hardware categories?

Ideally every system wants to capture both the higher throughput of a layer-4 load-balancer, in addition to the uniformity of load brought by a layer-7 since it leads to a decrease in tail-latency. If the possibility of modifying a layer-4 load-balancer’s approach to packet-forwarding was improved 5 to spread network load better, we would be able to reciprocate benefits that layer-7 load-balancers showcase. At the same time, it is vital that we maintain a similar standard in benefits that layer-4 load-balancers provide - otherwise we would circle back to the same dilemma of being on polar ends in terms of benefits.

In regards to the medium, every system would also want to strike the balance between performance and flexibility. In recent times there has been rapid development on technology that avoids the inefficiencies of context switching between userspace and kernel level - meanwhile, it is able to provide similar levels of programmability to match the flexibility standard of software-based loadbalancers. The benefit of improving performance is an important matter when considering the typical usage of load-balancers within microservices architectures, which is dominating in terms of popularity and showcases microsecond scale communication. However, it is also important to provide flexibility as it was a foundational motivation to strive away from monolithic architectures.

## Project's Approach
In regards to the gap between layer-4 and layer-7, this project aims to find the balance by moving away from the strict use of ’sticky’ sessions that typical layer-4 load-balancers adopt. Specifically, we want to provide a layer-4 load-balancer the freedom to switch target servers if it is deemed to bring wanted benefits such as uniformity of load in the system - in the hopes that it leads to reduction in tail-latency within the system or increase the overall utilisation of resources.

We want to provide this freedom of choice while respectably maintaining the qualities that a layer-4 flavour provides. In this regard, the main quality we will continuously inspect and aim to improve is throughput, since it is the principle factor that influences the decision of choosing layer-4 over layer-7.

Furthermore, the debate of picking which medium to use for this project will also have an influence on throughput. For this project we decide to pursue an eBPF solution, as we want to explore the advantages in terms of throughput and overhead latency it can showcase when compared to software-based solutions. eBPF is technology that provides a good balance in terms of performance as it overcomes the inefficiencies of context switching, but also provides the needed flexibility and programmability

## Assumptions
- There is a single outstanding request for every connection.
- To get a reply the request must have been fully received.
- To get the next request the previous response must have been fully received.

## Implementation
The project comprises of two main components. The first is the kernel code, located in the `kernel` folder in the repository and it is attached to a network device. The other component is code that runs in userspace, which is located in the `userspace` folder in the repository.

### Kernel Space
The eBPF code that is to be attached to a network device is found in `kernel/xdp_prog_kern.c`. For developmental processes, after compiling and generating the ELF file you may run `sudo bash local_script.sh` with or without the `-r or --reuse` flag - this attaches the aforementioned eBPF code to the `lo` device and runs each packet it detects through the `xdp_tcp` program.

The eBPF program initialises two main maps that it utilises to modify a packet's information - the `conn_map` and `numbers_map`. The `conn_map` uses `struct connection` for both its keys and values, and the struct is defined in `kernel/common.h`. The struct stores the 4-tuple information (source port, destination port, source ip adress, destination ip address) that is required to redirect a packet to the correct interface. The purpose of this map is to identify if the packet needs to be rerouted (by checking if it's 4-tuple exists in the map) and modifying the specific header values with the value struct retured by the map if a result is found. The `numbers_map` uses `struct connection` as the key and `struct numbers` (which can also be found in `kernel/common.h`) as the value. The latter struct contains `seq_no` and `ack_no` which represent the connection's sequence and acknowledgement numbers as unsigned integers. It also contains `seq_offset` and `ack_offset` which are signed integer values used to subtract from a current packet's sequence and acknowledgement values in order to match the subsequent connection's values that it is being rerouted through.

### User Space
The main load balancer code can be found in `userspace/lb/lb.go`. It creates and handles the connection with its worker nodes/servers, before listening for new client connections. When a client connects to the load balancer via port 8080, the load balancer will assign a worker node to the connected client. It does so by grabbing the `struct numbers` for each respective connection (client to load balancer, worker to load balancer), and calulcating the offset required to subtract from a travelling packet so that it respect the next connection's sequence and acknowledgement values. In addition, it also updates the `conn_map` (mentioned in the kernel section) to contain the connection pairing of (client->lb, lb->worker) and (worker->lb, lb->client).
