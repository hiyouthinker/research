/* 
 * UDP Client (RX/TX UDP Packet)
 *		Author: BigBro
 *		Date:	2021
 */

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
#include <time.h>

static int debug_level = -1;

#define debug_print(my_level, x...)	do {\
		if (debug_level >= my_level)\
			printf(x);\
	} while(0)

enum {
	F_LOCAL_IP = 1,
	F_LOCAL_PORT = 2,
	F_REMOTE_IP = 4,
	F_REMOTE_PORT = 8,
};

struct stats_s {
	unsigned int xmitted_pkts;
	unsigned int received_pkts;
} my_stats;

static void help(char *cmd)
{
	printf("%s usage:\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-p\tdest port\n");
	printf("\t-r\tdest ip\n");
	printf("\t-P\tlocal port\n");
	printf("\t-l\tlocal ip\n");
	printf("\t-c\tpacket number to xmit\n");
	printf("\t-s\tsize of packet\n");
	printf("\t-e\techo mode\n");
	printf("\t-i\tinterval to xmit\n");
	printf("\t-d\tenable debug\n");
	exit(0);
}

static void stats_output(void)
{
	printf("Statistics:\n");
	printf("\txmitted pkt :		%u\n", my_stats.xmitted_pkts);
	printf("\treceived pkt:		%u\n", my_stats.received_pkts);
}

static void sig_handler(int signo)
{
	stats_output();
	exit(0);
}

int main (int argc, char **argv)
{
	int opt, count = 1, fd;
	int flags = 0, echo = 0, interval = 0, size = 10;
	struct sockaddr_in local_si = {
		.sin_family = AF_INET,
	};
	struct sockaddr_in remote_si = {
		.sin_family = AF_INET,
	};
	time_t old = time(NULL);

	while ((opt = getopt(argc, argv, "p:r:P:l:c:s:ei:dh")) != -1) {
		int tmp;

		switch (opt) {
		case 'p':
			tmp = atoi(optarg);
			if (tmp <= 0 || tmp > 65535) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			remote_si.sin_port = ntohs(tmp);
			flags |= F_REMOTE_PORT;
			break;
		case 'r':
			if (inet_aton(optarg, &remote_si.sin_addr) == 0) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			flags |= F_REMOTE_IP;
			break;
		case 'P':
			tmp = atoi(optarg);
			if (tmp <= 0 || tmp > 65535) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			local_si.sin_port = ntohs(tmp);
			flags |= F_LOCAL_PORT;
			break;
		case 'l':
			if (inet_aton(optarg, &local_si.sin_addr) == 0) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			flags |= F_LOCAL_IP;
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 's':
			size = atoi(optarg);
			if (size <= 0 || size > 1400) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
		case 'e':
			echo = 1;
			break;
		case 'i':
			interval = atoi(optarg);
			if (interval <= 0 || interval > 2000) {
				printf("invalid param: %s\n", optarg);
				help(argv[0]);
			}
			break;
		case 'd':
			debug_level++;
			break;
		case 'h':
		default:
			help(argv[0]);
			break;
		}
	}

	if (!(flags & (F_REMOTE_IP|F_REMOTE_PORT))) {
		help(argv[0]);
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0){
		perror("socket");
		goto done;
	}

	if (flags & (F_LOCAL_IP|F_LOCAL_PORT)) {
		if (bind(fd, (struct sockaddr *)&local_si, sizeof(local_si)) < 0) {
			perror("bind");
			goto done;
		}
	}

	if (signal(SIGINT, sig_handler) || signal(SIGTERM, sig_handler)) {
		perror("signal");
		goto done;
	}

	printf("Prepare to send packet to %s:%u\n", inet_ntoa(remote_si.sin_addr), ntohs(remote_si.sin_port));

	while (count-- > 0) {
		char buf[2048] = "Hello, I'am BigBro";
		int xmitted, received;

		my_stats.xmitted_pkts++;
		xmitted = sendto(fd, buf, size, 0, (struct sockaddr*)&remote_si, sizeof(remote_si));
		if (xmitted != size) {
			if (xmitted < 0)
				perror("sendto");
			else
				printf("xmitted (%d) != expected (%d)\n", xmitted, size);
			goto done;
		}
		
		if (!echo)
			continue;

		received = recv(fd, buf, sizeof(buf), 0);
		if (received != xmitted) {
			if (received <= 0)
				perror("recv");
			else
				printf("received (%d) != xmitted (%d)", received, xmitted);
			goto done;
		}
		my_stats.received_pkts++;
		if (time(NULL) - old >= 5) {
			stats_output();
			old = time(NULL);
		}
		if (interval)
			usleep(1000 * interval);
	}
	stats_output();
done:
	if(fd >= 0){
		close(fd);
	}
	return 0;
}
