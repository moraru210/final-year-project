# Final Year Project - REMATCHER
Rematcher - A repository dedicated for my final year project at Imperial College London. 

## How To Start
```
sudo make TARGET=<interface> MAX_SERVERS=<integer> MAX_CLIENTS=<integer> MAX_PER_SERVER=<integer> IPv4=<address>
```
- `TARGET` the network interface to attach the XDP code onto
- `IPv4` the IP address assigned to the load-balancer
- `MAX_CLIENTS` maximum number of clients the load-balancer will endure
- `MAX_SERVERS` maximum number of servers the load-balancer will endure
- `MAX_PER_SERVER` number of open connections between the middlebox and each server

## How To Add Server(s)
Once Rematcher is running, you will prompted with the 'control panel' where you are able to run commands. To add servers you run:
```
add (IPv4 address):(port number)
```

Example servers in this repo include:
- `userspace/server/http`
- `userspace/server/text-file`

## How To Rematcher Server(s)
When Rematcher is running, to remove servers you run:
```
remove (IPv4 address):(port number)
```

## How To Run A Rematch
When Rematcher is running, to rematch a client session's target server you run:
```
rematch (IPv4 address):(port number) (IPv4 address):(port number)
```
Where the first argument is the client's address, and the second argument is the new target server you wish to switch the client session to. 

## Project's Motivation
Is there a middle-ground in terms of benefits when considering the layer-4 versus layer-7 and software versus hardware categories?

Ideally every system wants to capture both the higher throughput of a layer-4 load-balancer, in addition to the uniformity of load brought by a layer-7 since it leads to a decrease in tail-latency. If the possibility of modifying a layer-4 load-balancer’s approach to packet-forwarding was improved 5 to spread network load better, we would be able to reciprocate benefits that layer-7 load-balancers showcase. At the same time, it is vital that we maintain a similar standard in benefits that layer-4 load-balancers provide - otherwise we would circle back to the same dilemma of being on polar ends in terms of benefits.

In regards to the medium, every system would also want to strike the balance between performance and flexibility. In recent times there has been rapid development on technology that avoids the inefficiencies of context switching between userspace and kernel level - meanwhile, it is able to provide similar levels of programmability to match the flexibility standard of software-based loadbalancers. The benefit of improving performance is an important matter when considering the typical usage of load-balancers within microservices architectures, which is dominating in terms of popularity and showcases microsecond scale communication. However, it is also important to provide flexibility as it was a foundational motivation to strive away from monolithic architectures.

## Project's Approach
In regards to the gap between layer-4 and layer-7, this project aims to find the balance by moving away from the strict use of ’sticky’ sessions that typical layer-4 load-balancers adopt. Specifically, we want to provide a layer-4 load-balancer the freedom to switch target servers if it is deemed to bring wanted benefits such as uniformity of load in the system - in the hopes that it leads to reduction in tail-latency within the system or increase the overall utilisation of resources.

We want to provide this freedom of choice while respectably maintaining the qualities that a layer-4 flavour provides. In this regard, the main quality we will continuously inspect and aim to improve is throughput, since it is the principle factor that influences the decision of choosing layer-4 over layer-7.

Furthermore, the debate of picking which medium to use for this project will also have an influence on throughput. For this project we decide to pursue an eBPF solution, as we want to explore the advantages in terms of throughput and overhead latency it can showcase when compared to software-based solutions. eBPF is technology that provides a good balance in terms of performance as it overcomes the inefficiencies of context switching, but also provides the needed flexibility and programmability

## Setup - Dependencies (for Ubuntu)
Make sure to run the following for the XDP dependencies:
```
sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump
```

In addition, the control-plane code utilises Golang, so make sure to have `go1.18` or above.

## Assumptions
- There is a single outstanding request for every connection.
- To get a reply the request must have been fully received.
- To get the next request the previous response must have been fully received.

## Implementation
The project comprises of two main components. The first is the data-plane code, located in the `kernel` folder of the repository and it is meant to attached to a network device's `XDP_HOOK`. The other component is the control-plane code that runs in userspace, which is located in the `userspace` folder in the repository.

## Data Plane
The code for the data-plane is located in the `kernel` folder, where the main logic is located in `kernel.c`. To compile the eBPF code, run `make` in the subfolder and you may pass the arguments as shown already in the first subsection of this README. These arguments specifically are `MAX_CLIENTS`, `MAX_PER_SERVER`, and `MAX_SERVERS`. 

In order for the XDP code to run on the ingress received by the network interface, you need to load/attach it onto the interface. This can be done using a customly written loader, however this project utilises `xdp-loader` from `xdp-tools`. In order to utilise the tool, make sure to run `make` in the `xdp-tools/xdp-loader` folder.

This project created a script `kernel/setup.sh` where it utilises `xdp-loader` under the tool to load, unload or view the status of all the network interfaces on the system. An example of how to run it is below:

```
sudo bash kernel/setup.sh load <interface>
```

The script automatically looks for the ELF object file for the compiled `kernel.c` code and attaches it using `xdp-loader`. However, you may also utilise `xdp-loader` directly if you prefer not to use the srcipt.

## Control Plane
The code for the control-plane is located in the `userspace` folder. Specfically the logic is located in the `userspace/lb`, where in order to build it you run:
```
go build .
```

To start the control-plane, you run the following code:
```
sudo ./lb <IPv4 address> <interface>
```

In order for the control-plane to access the same maps that the data-plane does, you need to ensure that the `structs` utilised to marshall the data read or inserted in the maps matches the ones used to created the map in `kernel/kernel.c`. You can do this my entering the `userspace/config` directory and generating the correct structs by running:

```
go generate.go MAX_CLIENTS MAX_SERVERS MAX_PER_SERVER
```

Where the paramaters utilised should match exactly the ones utilised in the data-plane code.
