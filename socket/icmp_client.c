/***************************
 * ICMP Client (RX/TX ICMP Packet)
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "libdebug.h"

#define DEFAULT_MTU 1500
#define IP_MF		0x2000		/* Flag: "More Fragments"	*/

static unsigned short icmp_id = 0;

static int build_icmp_packet(int seq, char *buff, int data_len, int fd, struct sockaddr_in *si)
{      
	int packsize, offset = 0;
	struct iphdr *iph;
	struct icmphdr *icmp;

	iph = (struct iphdr*)buff;
	iph->version = 4;
	iph->ihl = 5;
#if 0 /* Kernel fills in */
	iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + data_len);
	iph->id = 0;/* Kernel fills in */
#endif
	iph->id = random(); /* Must be not 0 while fragment */
	iph->frag_off = 0;
	iph->ttl = 64;

	iph->protocol = IPPROTO_ICMP;
	iph->check = 0;

	icmp = (struct icmphdr*)(buff + iph->ihl * 4);
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = htons(++icmp_id);
	icmp->un.echo.sequence = htons(seq);

	/* IP Fragments */
	if ((iph->ihl * 4 + sizeof(*icmp) + data_len) > DEFAULT_MTU) {
		int ip_data_len = sizeof(*icmp) + data_len;
		char *p = (char *)malloc(ip_data_len);
		char dt[DEFAULT_MTU + 128];
		struct icmphdr *ihdr = (struct icmphdr *)p;
		int delta = DEFAULT_MTU - iph->ihl * 4;/* IP Data Length */

		assert(p);
		memcpy(p, icmp, sizeof(*icmp));				/* ICMP Header */
		memset(p + sizeof(*icmp), 'a', data_len);		/* ICMP Data */
		ihdr->checksum = checksum1((void *)p, sizeof(*icmp) + data_len);

		while (1) {
			/* offset MUST be 8 multiple */
			iph->frag_off = htons(offset >> 3);
			if(iph->ihl * 4 + ip_data_len - offset < DEFAULT_MTU){
				packsize = iph->ihl * 4 + ip_data_len - offset;
				memcpy((char *)icmp, p, ip_data_len - offset);
				break;
			}
			else{
				iph->frag_off |= htons(IP_MF);
			}
			offset += delta;
			/* IP Header */
			memcpy(dt, (char *)iph, iph->ihl * 4);
			/* 
			 * First Packet: ICMP Header + ICMP Data
			 * Other Packet: ICMP Data
			 */
			memcpy(dt + iph->ihl * 4, p, delta);
			p += delta;
			debug_out(DEBUG_LEVEL_DETAIL, "TX packet: %s.\n", bin_to_hex_string(dt, DEFAULT_MTU));
			debug_out(DEBUG_LEVEL_INFO, "TX packet to 0x%04x, fd: %d.\n", si->sin_addr.s_addr, fd);
			if (sendto(fd, dt, DEFAULT_MTU, 0, (struct sockaddr *)si, sizeof(struct sockaddr) ) < 0) {
				debug_out(DEBUG_LEVEL_ERROR, "sendto failed (%m).\n");
				continue;
			}
		}
	} 	else {
		memset((char *)icmp + sizeof(*icmp), 'a', data_len);
		icmp->checksum = checksum1((void *)icmp, sizeof(*icmp) + data_len);
		packsize = iph->ihl * 4 + sizeof(*icmp) + data_len;
	}
	debug_out(DEBUG_LEVEL_DETAIL, "TX packet: %s.\n", bin_to_hex_string((char *)iph, packsize));
	return packsize;	
}

static void help(char *cmd)
{
	if(!cmd_and_param[0])/* standalone Mode */
		sprintf(cmd_and_param, "%s\nUsage: %s", MyCopyRight, cmd);
	
	printf("%s\n", cmd_and_param);
	printf("\t-H %-20sdst ip\n", "<IP>");
	printf("\t-l %-20sicmp data length\n", "<NUMBER>");
	printf("\t-c %-20scount\n", "<NUMBER>");
	printf("\t-d %-20sdebug switch\n", "");
	printf("\t-h %-20sShow This\n", "");
	exit(0);
}

int main (int argc, char **argv)
{
	int len, fd;
	char *host = "114.114.114.114";
	char recv_buf[2048], send_buf[DEFAULT_MTU];
	struct sockaddr_in si;
	int opt, val = 1, count = 1, nsend = 0;
	int length = 56;
	
	while ((opt = getopt(argc, argv, "H:l:c:dh")) != -1) {
		switch (opt) {
			case 'H':
				host = optarg;
				break;
			case 'l':
				length = atoi(optarg);
				break;
			case 'c':
				count = atoi(optarg);
				if(count >= 1){
					break;
				}
			case 'd':
				debug_switch++;
				break;
			case 'h':
				help(argv[0]);
				break;
			default:
				printf("param error.\n");
				help(argv[0]);
				break;
		}
	}

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(fd < 0){
		perror("socket");
		goto done;
	}

	/* the IP header is built by userspace */
	if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(int)) < 0) {
		perror("setsockopt");
		close(fd);
		goto done;
	}        

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(host);

	while (nsend++ < count) {
		struct iphdr *iph = (struct iphdr*)send_buf;
		struct icmphdr *icmph;

		memset(send_buf, 0, sizeof(send_buf));
		iph->daddr = si.sin_addr.s_addr;
		len = build_icmp_packet(nsend, send_buf, length, fd, &si);

		if (sendto(fd, send_buf, len, 0, (struct sockaddr *)&si, sizeof(si) ) < 0) {
			debug_out(DEBUG_LEVEL_ERROR, "TX Packet (to %s): failure (%m), index: %d\n", host, nsend);
			continue;
		}
		debug_out(DEBUG_LEVEL_INFO, "TX Packet (to %s): success, index: %d, len: %d\n", host, nsend, len);
rerecv:
		len = recv(fd, recv_buf, sizeof(recv_buf), 0);
		if (len < 0) {
			debug_out(DEBUG_LEVEL_ERROR, "RX Packet (from %s): failure (%m), index: %d\n", host, nsend);
			continue;
		}
		debug_out(DEBUG_LEVEL_DETAIL, "RX packet: %s.\n", bin_to_hex_string(recv_buf, len));
		iph = (struct iphdr*)recv_buf;
		if ((len < sizeof(struct iphdr))
			|| ((iph->ihl << 2) + sizeof(struct icmphdr) > len)) {
			debug_out(DEBUG_LEVEL_INFO, "packet is short: %d\n", len);
			goto rerecv;
		}
		icmph = (struct icmphdr *)((char *)iph + (iph->ihl << 2));
		if (icmph->un.echo.id != htons(icmp_id)) {
			debug_out(DEBUG_LEVEL_INFO, "Not our ping: myid: %d, current id: %d\n"
				, icmp_id, ntohs(icmph->un.echo.id));
			goto rerecv;
		}
		if (icmph->type != ICMP_ECHOREPLY) {
			debug_out(DEBUG_LEVEL_INFO, "Not echo reply, type: %d\n", icmph->type);
			goto rerecv;
		}
		debug_out(DEBUG_LEVEL_INFO, "RX Packet (from %s): success, index: %d, len: %d\n", host, nsend, len);
		debug_out(DEBUG_LEVEL_NONE, "%s is alive\n", host);
	}
done:
	if (fd >= 0) {
		close(fd);
	}
	return 0;
}
