/***************************
 * UDP Client (RX/TX UDP Packet)
 * 	Copyright: https://github.com/hiyouthinker @2018
 *
****************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "libdebug.h"

static char dns_packet[] = {0xe3, 0x4d	/* ID */
						, 0x01, 0x00	/* flags */
						, 0x00, 0x01	/* questions */
						, 0x00, 0x00	/* Answer RRS */
						, 0x00, 0x00	/* Authority RRS */
						, 0x00, 0x00	/* Additional RRS */
						, 0x08, 'h', 't', 't', 'p', ':', '/', '/', 'c'/* http://t */
						, 0x03, 'g', 'd', 't'	/* gdt */
						, 0x02, 'q', 'q'		/*qq */
						, 0x03, 'c','o', 'm'	/* com */
						, '\0' 
						, 0x00, 0x01	/* Type: A */
						, 0x00, 0x01	/* Class: IN */
						};

#if 0
static char udp_data[] = {
						0x30, 0x29, 0x02, 0x01, 0x01, 0x04, 0x06
						, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa5
						, 0x1c, 0x02, 0x04, 0x14, 0x1f, 0xa9, 0x16
						, 0x02, 0x01, 0x00, 0x02, 0x02, 0x27, 0x0f
						, 0x30, 0x0d, 0x30, 0x0b, 0x06, 0x07, 0x2b
						, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x05
						, 0x00, 0x00, 0x43
					};
#endif

static void help(char *cmd)
{
	if(!cmd_and_param[0])/* standalone Mode */
		sprintf(cmd_and_param, "%s\nUsage: %s", MyCopyRight, cmd);
	
	printf("%s\n", cmd_and_param);
	printf("\t-p %-20sdst port\n", "<NUMBER>");
	printf("\t-H %-20sdst ip\n", "<IP>");
	printf("\t-l %-20ssrc ip\n", "<IP>");
	printf("\t-P %-20ssrc port\n", "<PATH>");
	printf("\t-f %-20sdata come form local file\n", "<PATH>");
	printf("\t-c %-20spacket count\n", "<COUNT>");
	printf("\t-d %-20sdebug switch\n", "");
	printf("\t-h %-20sShow This\n", "");
	exit(0);
}

int main (int argc, char **argv)
{
	int fd, opt, count = 1, rv, index = 0;
	char *shost = NULL, *dhost = NULL, *rfile = NULL;
	struct sockaddr_in si;
	short sport = 0, dport = 0;
	FILE *pf = NULL;
	
	while ((opt = getopt(argc, argv, "p:H:l:P:f:c:dh")) != -1) {
		switch (opt) {
			case 'p':
				dport = atoi(optarg);
				break;
			case 'H':
				dhost = optarg;
				break;
			case 'l':
				shost = optarg;
				break;
			case 'P':
				sport = atoi(optarg);
				break;
			case 'f':
				rfile = optarg;
				pf = fopen(rfile, "r");
				if(!pf){
					debug_out(DEBUG_LEVEL_ERROR, "fopen %s error: %s\n", rfile, strerror(errno));
					help(argv[0]);
				}
				break;
			case 'c':
				count = atoi(optarg);
				break;
			case 'd':
				debug_switch++;
				break;
			case 'h':
				help(argv[0]);
				break;
			default:
				debug_out(DEBUG_LEVEL_ERROR, "param error.\n");
				help(argv[0]);
				break;
		}
	}

	if(!dhost || !dport){
		help(argv[0]);
	}
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0){
		debug_out(DEBUG_LEVEL_ERROR, "socket: %s.\n", strerror(errno));
		goto done;
	}

	if (sport || shost) {
		memset(&si, 0, sizeof(si));
		si.sin_family = AF_INET;
		si.sin_port = htons(sport);
		if (shost) {
			si.sin_addr.s_addr = inet_addr(shost);
		}
		
		if (bind(fd, (struct sockaddr *)&si, sizeof(si)) < 0) {
			debug_out(DEBUG_LEVEL_ERROR, "bind: %s.\n", strerror(errno));
			goto done;
		}
	}

	memset(&si, 0, sizeof(si));
	si.sin_family = AF_INET;
	si.sin_port = htons(dport);
	si.sin_addr.s_addr = inet_addr(dhost);

	if (count == 1 && pf) {
		count = 100;/* In order to ensure that the file transfer is completed */
	}
	
	while (index++ < count) {
		char buf[1024];

		if(!pf){
			memcpy(buf, dns_packet, sizeof(dns_packet));
			rv = sizeof(dns_packet);
		} else {
			rv = fread(buf, 1, sizeof(buf), pf);
			if (!rv) {
				debug_out(DEBUG_LEVEL_INFO, "fread: end of file.\n");
				goto done;
			}
			if (rv < 0) {
				debug_out(DEBUG_LEVEL_ERROR, "fread: %s.\n", strerror(errno));
				goto done;
			}
		}
		rv = sendto(fd, buf, rv, 0, (struct sockaddr*)&si, sizeof(si));
		if (rv < 0) {
			debug_out(DEBUG_LEVEL_ERROR, "sendto: %s.\n", strerror(errno));
			goto done;
		}
		debug_out(DEBUG_LEVEL_INFO, "The length of packet to send to %s is %d.\n", dhost, rv);
		memset(buf, 0, sizeof(buf));
		rv = recv(fd, buf, sizeof(buf), 0);
		if (rv <= 0) {
			debug_out(DEBUG_LEVEL_ERROR, "recv: %s.\n", strerror(errno));
			goto done;
		}
		debug_out(DEBUG_LEVEL_INFO, "recv packet length is %d\n", rv);
	}
done:
	if(fd>=0){
		close(fd);
	}
	if(pf){
		fclose(pf);
	}
	return 0;
}
