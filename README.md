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
