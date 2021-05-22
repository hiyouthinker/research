/*
 * --BigBro/2021.05
*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <linux/filter.h>

/*
 * instruction format:
 * +----------------+--------+--------+
 * |   16 bits      | 8 bits | 8 bits |
 * | operation code |   jt   |   jf   |
 * +----------------+--------+--------+
 * | (MSB)         k:32         (LSB) |
 * +----------------------------------+
 *
 * tcpdump -i eth1 tcp port 8080 -dd
 */
static struct sock_filter bpf_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 6, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 15, 0x00000006 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 12, 0, 0x00001f90 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 10, 11, 0x00001f90 },
	{ 0x15, 0, 10, 0x00000800 },
	{ 0x30, 0, 0, 0x00000017 },
	{ 0x15, 0, 8, 0x00000006 },
	{ 0x28, 0, 0, 0x00000014 },
	{ 0x45, 6, 0, 0x00001fff },
	{ 0xb1, 0, 0, 0x0000000e },
	{ 0x48, 0, 0, 0x0000000e },
	{ 0x15, 2, 0, 0x00001f90 },
	{ 0x48, 0, 0, 0x00000010 },
	{ 0x15, 0, 1, 0x00001f90 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

int main(int argc, char **argv)
{
	int sock;
	int bytes;
	char buf[4096];
	struct sockaddr_ll addr;
	struct iphdr *ip_header;
	char src_addr_str[INET_ADDRSTRLEN], dst_addr_str[INET_ADDRSTRLEN];
	char *name;
	struct sock_fprog bpf_prog;

	bpf_prog.filter = bpf_filter;
	bpf_prog.len = sizeof(bpf_filter) / sizeof(struct sock_filter);

	if (argc != 2) {
		printf("Usage: %s ifname.\n", argv[0]);
		return 1;
	}

	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		printf("Create socket failed!\n");
		return 1;
	}

	name = argv[1];
	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = if_nametoindex(name);
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		printf("bind to device %s failed!\n", name);
		return 1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &bpf_prog, sizeof(bpf_prog)) < 0) {
		printf("Attaching filter failed!\n");
		return 2;
	}

    for (;;) {
		printf("Ready to receive pkts\n");
		bytes = recv(sock, buf, sizeof(buf), 0);
		if (bytes < 1) {
			printf("recv failed!\n");
			return -1;
		}

		ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));
		inet_ntop(AF_INET, &ip_header->saddr, src_addr_str, sizeof(src_addr_str));
		inet_ntop(AF_INET, &ip_header->daddr, dst_addr_str, sizeof(dst_addr_str));
		printf("IPv%d proto=%d src=%s dst=%s\n",
				ip_header->version, ip_header->protocol, src_addr_str, dst_addr_str);
	}
	return 0;
}
