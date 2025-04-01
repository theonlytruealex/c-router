#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>

#define IPV4_TYPE 0x0800
#define ARP_TYPE 0x0806
#define ETH_HDR_SIZE 0xe
#define IP_HDR_SIZE 0x14
#define ICMP_HDR_SIZE 0x8

typedef struct trie_node {
	short has_children;
	struct trie_node *children[2];
	struct route_table_entry *entry;
} trie_node;

void init_node(trie_node* root) {
	root->has_children = 0;
	root->children[0] = NULL;
	root->children[1] = NULL;
	root->entry = NULL;
}

void print_binary(unsigned int num) {
    for (int i = 31; i >= 0; i--) {
        printf("%d", (num >> i) & 1);
    }
    printf("\n");
}

void insert(trie_node* root, struct route_table_entry *entry, uint32_t mask, uint32_t prefix, int position) {
	if ((mask & (1 << (31 - position))) == 0 || position == 32) {
		root->entry = entry;
		return;
	}
	short byte = ((prefix << position) & 2147483648) >> 31;

	if (!root->has_children)
		root->has_children = 1;

	if (root->children[byte] == NULL){
		root->children[byte] = (trie_node *)malloc(sizeof(trie_node));
		init_node(root->children[byte]);
	}
	insert(root->children[byte], entry, mask, prefix, position + 1);
}

struct route_table_entry* get_table_entry(trie_node* root, u_int32_t address, int position) {
	if (!root->has_children)
		return root->entry;
	
	short byte = ((address << position) & 2147483648) >> 31;

	if (root->children[byte] == NULL)
		return root->entry;

	struct route_table_entry *entry = get_table_entry(root->children[byte], address, position + 1);
	if (entry == NULL)
		return root->entry;
	return entry;
}

int drop_dest_mac(uint8_t *address, size_t interface) {
	for (int i = 0; i < 7; i++) {
		if (i == 6)
			return 0;

		if (address[i] != 0xFF)
			break;
	}
	uint8_t mac[6];
	get_interface_mac(interface, mac);

	for (int i = 0; i < 7; i++) {
		if (i == 6)
			return 0;

		if (address[i] != mac[i])
			break;
	}
	return 1;
}

void icmp_response(char* buf, int interface, uint8_t type) {

	printf("ICMP, %d\n", type);
	struct ether_hdr *eth_header = (struct ether_hdr *) buf;
	uint8_t aux;

	for (int i = 0; i < 6; i++) {
		aux = eth_header->ethr_dhost[i];
		eth_header->ethr_dhost[i] = eth_header->ethr_shost[i];
		eth_header->ethr_shost[i] = aux;
	}
	char buf_aux[8 + IP_HDR_SIZE];
	memcpy(buf_aux, buf + ETH_HDR_SIZE, 8 + IP_HDR_SIZE);

	struct ip_hdr *ip_header = (struct ip_hdr *)(buf + ETH_HDR_SIZE);

	ip_header->dest_addr = ip_header->source_addr;
	ip_header->source_addr = inet_addr(get_interface_ip(interface));
	ip_header->ttl = 64;
	ip_header->proto = 1;
	ip_header->tot_len = htons(IP_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE + 8);
	ip_header->checksum = 0;
	ip_header->checksum = htons(checksum((uint16_t *)ip_header, IP_HDR_SIZE));
	
	struct icmp_hdr *icmp_header = (struct icmp_hdr *)(buf + ETH_HDR_SIZE + IP_HDR_SIZE);
	icmp_header->mcode = 0;
	icmp_header->mtype = type;
	memcpy(buf + ETH_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE, buf_aux, 8 + IP_HDR_SIZE);

	icmp_header->check = 0;
	icmp_header->check = htons(checksum((uint16_t *)icmp_header, ICMP_HDR_SIZE + IP_HDR_SIZE + 8));

	send_to_link(ETH_HDR_SIZE + IP_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE + 8, buf, interface);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc(sizeof(struct route_table_entry) * 80001);
	struct arp_table_entry *arp_table = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) * 30000);

	int arp_len = parse_arp_table("./arp_table.txt", arp_table);

	int table_len = read_rtable(argv[1], rtable);

	trie_node *root = (trie_node *)malloc(sizeof(trie_node));
	init_node(root);

	for (int i = 0; i < table_len; i++) {
		insert(root, &rtable[i], ntohl(rtable[i].mask), ntohl(rtable[i].prefix), 0);
	}
	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");
		struct ether_hdr *eth_header = (struct ether_hdr *) buf;
		if (drop_dest_mac(eth_header->ethr_dhost, interface))
			continue;

    // TODO: Implement the router forwarding logic

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		if (ntohs(eth_header->ethr_type) == IPV4_TYPE) {
			struct ip_hdr *ip_header = (struct ip_hdr *)(buf + ETH_HDR_SIZE);
			
			uint16_t old_sum = ntohs(ip_header->checksum);

			if (ip_header->ttl == 0 || ip_header->ttl == 1) {
				icmp_response(buf, interface, 11);
				continue;
			}

			ip_header->checksum = 0;
			if (old_sum != checksum((uint16_t *)ip_header, IP_HDR_SIZE))
				continue;

			if (ip_header->dest_addr == inet_addr(get_interface_ip(interface))) {
				printf("wooo\n");
				uint8_t aux;

				for (int i = 0; i < 6; i++) {
					aux = eth_header->ethr_dhost[i];
					eth_header->ethr_dhost[i] = eth_header->ethr_shost[i];
					eth_header->ethr_shost[i] = aux;
				}

				ip_header->dest_addr = ip_header->source_addr;
				ip_header->source_addr = htonl(inet_addr(get_interface_ip(interface)));
				ip_header->ttl = 255;
				ip_header->checksum = 0;
				ip_header->checksum = htons(checksum((uint16_t *)ip_header, IP_HDR_SIZE));

				struct icmp_hdr *icmp_header = (struct icmp_hdr *)(buf + ETH_HDR_SIZE + IP_HDR_SIZE);

				icmp_header->mtype = 0;
				icmp_header->check = 0;
				icmp_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct icmp_hdr)));

				send_to_link(len, buf, interface);
				continue;
			}

			ip_header->ttl -= 1;

			struct route_table_entry *entry = get_table_entry(root, ntohl(ip_header->dest_addr), 0);
			if (entry == NULL) {
				icmp_response(buf, interface, 3);
				continue;
			}
			struct arp_table_entry *arp_entry;

			for (int i = 0; i < arp_len; i++) {
				if (entry->next_hop == arp_table[i].ip){
					arp_entry = &arp_table[i];
					break;
				}
			}
			uint8_t mac[6];
			get_interface_mac(interface, mac);

			memcpy(eth_header->ethr_dhost, arp_entry->mac, 6);
			memcpy(eth_header->ethr_shost, mac, 6);

			ip_header->checksum = 0;
			ip_header->checksum = htons(checksum((uint16_t *)ip_header, IP_HDR_SIZE));
			send_to_link(len, buf, entry->interface);
		}

	}
	free(rtable);
	free(arp_table);
	// TODO FREE TRIE
}

