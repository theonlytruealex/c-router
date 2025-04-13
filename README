# Dataplane Router

This program represents the implementation of a dataplane router with the following functionalities:

## 1. IPV4 Routing

The file `router.c` has the ability of routing IPV4 packets using a _static_ routing table. When the router receives a packet, if its type is IPV4 (its ethernet type is `0x0800`) it starts processing it:

- Firstly, the Time To Live field is checked, if the value found there is 0 or 1, the packet is dropped.
- Secondly, the checksum field is checked to see whether there have been any transmission errors. If the new sum differs from the old one, the packet is dropped.
- If the destination IP address belongs to the interface where the packet arrived, we send an *ICMP response* which will be detailed in a later section.
- The Time To Live entry is decremented and the destination address is sought in the routing table. If the address is reachable, the program searches thr ARP table for the next MAC address.
- Finlly, the program either sends an ARP request if the next MAC address is not known or forwards the packet after recomputing the checksum (because of the TTL field modification).

## 2. Trie Implementation

Liniarly searching through a routing table can be slow, especially in something as time-sensitive as computer networks, which is why this program implements a Trie for searching through its static routing table. 

The trie is implemented as a tree where each node has 2 children, one representing a bit of 1 and the other a bit of 0.the leaves of this data structure contain pointers to entries in the immense routing table. The implementation has been inspired by my implementation for the SDA homework in my first year of College.

## 3. ICMP messaging

The Router implements ICMP messaging functionallity and will send ICMP messagis in the following situations:

- If the Time To Live is either 0 or 1.
- If the destination is not in the routing table.
- If it receives an Echo Request.

Essentially it edits the old packet at sends it back on the same interface with the ICMP header included.

## 4. ARP Functionality

The router implements the following functionality regardind the ARP protocol:

### a. Send ARP Request

If the process of forwarding a packet is interrupted because the MAC address of the next hop is missing then the packet is moved to the heap and then enters a queue, implemented in `queue.c`, and the program sends an ARP Request.

To send an ARP Request a new packet is constructed from scratch, using the broadcast MAC address as destination and the address of the interface towards the next hop as source.

### b. Receive ARP Request & Send ARP Reply

If an ARP message is received (its ethernet type is `0x0806`) and its opcode is that of a request, then the received packet is modified in the following ways:

- The source MAC address becomes the destination MAC address while the new source address is that of the current interface.
- In the sae way the the new target address fields in the ARP header are overwritten with the source address fields of the same header, while the new source address fields are updated with the information of the current interface.

Finally, the packet is sent back on the same interface.

### c. Receive ARP Reply

After an ARP reply is received, the size of the ARP table is checked and extended if necessary.

All packets in the queue are checked to see whether the ARP reply contains the MAC address needed to forward them. If so, they are forwarded and the memory allocated to them (as they were moved to the heap) is freed. If not, they re-enter the queue. 

Because all packets are dequeued before being either enqueued or sent, the order of the packets will remain identical.