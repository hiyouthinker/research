/***************************
 * IP Client (RX/TX IP Packet)
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include "libdebug.h"

static void help(char *cmd)
{
	if(!cmd_and_param[0])/* standalone Mode */
		sprintf(cmd_and_param, "%s\nUsage: %s", MyCopyRight, cmd);
	
	printf("%s\n", cmd_and_param);
	printf("\t-H %-20sdst ip\n", "<HOST>");
	printf("\t-l %-20ssrc ip\n", "<LOCAL>");
	printf("\t-D %-20sdst port\n", "<PORT>");
	printf("\t-s %-20ssleep time\n", "<NUMBER>");
	printf("\t-z %-20sUDP data length (0 =< SIZE <= 1500)\n", "<NUMBER>");
	printf("\t-p %-20sl4 protocol\n", "<NUMBER>");
	printf("\t-c %-20scount\n", "<COUNT>");
	printf("\t-r %-20sread from peer\n", "");
	printf("\t-m %-20ssrc ip is random\n", "");
	printf("\t-d %-20sdebug switch\n", "");
	printf("\t-h %-20sShow This\n", "");
	exit(0);
}

int main (int argc, char **argv)
{
	int len, fd, rd = 0, sleep_time = 0, l3_len = 0;
	char *host = "114.114.114.114";
	char send_buf[2048];
	struct sockaddr_in si;
	struct timeval stv;
	struct timeval tx_time[64], *ptx = tx_time;
	int opt, val = 1, count = 1, nsend = 0, proto = IPPROTO_TCP;
	
	while ((opt = getopt(argc, argv, "H:l:D:s:z:p:c:rmdh")) != -1) {
		switch (opt) {
			case 'H':
				host = optarg;
				break;
			case 'l':
				local_ip = optarg;
				break;
			case 'D':
				dport = atoi(optarg);
				break;
			case 's':
				sleep_time = atoi(optarg);
				break;
			case 'z':
				udp_size = atoi(optarg);
				break;
			case 'p':
				proto = atoi(optarg);
				switch(proto){
					case IPPROTO_TCP:
					case IPPROTO_UDP:
						break;
					default:
						help(argv[0]);
						break;
				}
				break;
			case 'c':
				count = atoi(optarg);
				if(count >= 1){
					break;
				}
			case 'r':
				rd = 1;
				break;
			case 'm':/* random IP */
				local_ip = NULL;
       			srandom(time(NULL));
				break;
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

	fd = socket(AF_INET,SOCK_RAW,proto);
	if(fd < 0){
		perror("socket");
		goto done;
	}

	if(setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(int)) < 0){
		perror("setsockopt");
		close(fd);
		goto done;
	}
	
	if(setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &val, sizeof(int)) < 0){
		perror("setsockopt");
		close(fd);
		goto done;
	}

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_addr.s_addr = inet_addr(host);

	if(count > 64){
		ptx = (struct timeval *)malloc(count * sizeof(struct timeval));
	}
	
	gettimeofday(&stv, NULL);
	
	while(nsend++ < count){
		struct timeval tv;
		struct iphdr *iph = (struct iphdr*)send_buf;
		
		memset(send_buf, 0, sizeof(send_buf));
		iph->daddr = si.sin_addr.s_addr;
		l3_len = build_ip_packet(send_buf, NULL, proto);
		
 		gettimeofday(&tv, NULL);
		ptx[nsend-1] = tv;
		
		if(sendto(fd, send_buf, l3_len,0,(struct sockaddr *)&si, sizeof(si) ) < 0){
			debug_out(DEBUG_LEVEL_ERROR, "TX Packet (to %s): failure, index: %d\n", host, nsend);
			continue;
		}
		debug_out(DEBUG_LEVEL_DETAIL, "TX Packet (to %s): success, index: %d\n", host, nsend);
		debug_out(DEBUG_LEVEL_DETAIL, "Packet(%d):\n	%s\n", l3_len, bin_to_hex_string(send_buf, l3_len));
		if(rd){
			char recv_buf[2048];
rerecv:
			len = recv(fd, recv_buf, sizeof(recv_buf), 0);
			if(len < 0){
				perror("recv");
				printf("RX Packet (from %s): failure, index: %d\n", host, nsend);
				continue;
			}
			if(!is_tcpudp_packet(recv_buf, proto)){
				goto rerecv;
			}
			if(tcpudp_packet_port(recv_buf, 1) != (sport-1) ){
				debug_out(DEBUG_LEVEL_ERROR, "RX Packet (from %s): success, dest port: %d\n"
					, ip_packet_address(recv_buf, 0), tcpudp_packet_port(recv_buf, 1));
				goto rerecv;
			}
			debug_out(DEBUG_LEVEL_DETAIL, "RX Packet (from %s): success, index: %d\n", host, nsend);
			debug_out(DEBUG_LEVEL_DETAIL, "Packet(%d):\n	%s\n\n", len, bin_to_hex_string(recv_buf, len));
		}
	}
	
	debug_out(DEBUG_LEVEL_NONE, "Statistic:\n");
	debug_out(DEBUG_LEVEL_NONE, "\t%-24s: %s\n", "Protocol", proto==IPPROTO_TCP ? "TCP" : "UDP");
	debug_out(DEBUG_LEVEL_NONE, "\t%-24s: %lu seconds, %lu microseconds\n", "Start Time", stv.tv_sec, stv.tv_usec);
	debug_out(DEBUG_LEVEL_NONE, "\t%-24s: %lu seconds, %lu microseconds.\n"
		, "Total elapsed time", ptx[count - 1].tv_sec - stv.tv_sec, ptx[count - 1].tv_usec - stv.tv_usec);
	debug_out(DEBUG_LEVEL_NONE, "\t%-24s: %d\n", "TX Packet Num", count);
	debug_out(DEBUG_LEVEL_NONE, "\t%-24s: %d (length of l3 header and l3 data)\n", "Size of TX Packet", l3_len);

	for(nsend = 0; nsend < count; nsend++){
		debug_out(DEBUG_LEVEL_DETAIL, "TX Packet %04d: seconds: %lu, microseconds: %lu\n"
			, nsend, ptx[nsend].tv_sec, ptx[nsend].tv_usec);
	}
	if(tx_time != ptx){
		free(ptx);
	}
done:
	if(fd >= 0){
		if(sleep_time)
			sleep(sleep_time);
		close(fd);
	}
	return 0;
}
