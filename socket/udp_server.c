/* 
 * UDP Server
 *		Author: BigBro
 *		Date:	2019.11.28/2020
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>

static int cur_level = -1;

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-c\tcalc pps\n");
	printf("\t-p\tlocal port\n");
	printf("\t-H\tlocal ip\n");
	printf("\t-s\tshow some infos while received pkt\n");
	printf("\t-d\tenable debug\n");
	printf("\t-e\techo mode\n");
	exit(0);
}

#define debug_print(my_level, x...)	do {\
		if (cur_level >= my_level)\
			printf(x);\
	} while(0)

static unsigned long netflow_pkts_total;
static unsigned long netflow_pkts_old;
static struct timeval stat_start_time;

static int process_packets(int fd, int show, int echo)
{
	char recv_buf[1024 * 10];
	int ret, nfds = fd + 1;
	fd_set rfds;
	struct timeval tv;
	struct sockaddr_in from;
	socklen_t addrlen = sizeof(struct sockaddr_in);

re_recv:
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	ret = select(nfds, &rfds, NULL, NULL, &tv);
	switch (ret) {
	case 0:
		debug_print(2, "Timeout\n");
		goto re_recv;
	case -1:
		debug_print(0, "select failed(%s) and will exit\n", strerror(errno));
		exit(1);
	default:
		debug_print(2, "ret of select: %d\n", ret);
		break;
	}

	if (FD_ISSET(fd, &rfds)) {
		debug_print(2, "fd %d is readable\n", fd);
	}

	memset(recv_buf, 0, sizeof(recv_buf));
	ret = recvfrom(fd, recv_buf, sizeof(recv_buf), 0, (struct sockaddr *)&from, &addrlen);
	if (ret <= 0) {
		debug_print(0, "recv: %s, prepare to close fd and exit.\n", strerror(errno));
		sleep(2);
		close(fd);
		exit(1);
	} else {
		netflow_pkts_total++;
		if (show) {
			printf(".");
			fflush(NULL);
		}
		if (show > 1) {
			printf("recv length: %d\n", ret);
			printf("\t%s\n", recv_buf);
		}
	}
	if (echo) {
		if (sendto(fd, recv_buf, ret, 0, (struct sockaddr*)&from, addrlen) < 0) {
			debug_print(0, "send failed: %s.\n", strerror(errno));
		}
	}
	goto re_recv;
}

#define TIME_INTERVAL(a, b) ((a.tv_sec * 1000000 + a.tv_usec) - (b.tv_sec * 1000000 + b.tv_usec))
static void *calc_pps(void *arg)
{
	struct timeval curr_time, start_time;
	unsigned long pkts_old, pkts_curr, pps;

	printf("Entering calc_pps\n");

	while (1) {
		sleep(5);

	 	gettimeofday(&curr_time, NULL);
		start_time = stat_start_time;
		stat_start_time = curr_time;
		pkts_curr = netflow_pkts_total;
		pkts_old = netflow_pkts_old;
		netflow_pkts_old = pkts_curr;

		pps = ((pkts_curr - pkts_old) * 1000000)/TIME_INTERVAL(curr_time, start_time);
		printf("pps: %lu, diff of pkts: %lu, interval: %lu\n"
			, pps, (pkts_curr - pkts_old) * 1000000, TIME_INTERVAL(curr_time, start_time));
	}
	return arg;
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, port = 2055, len, ret;
	char *local_ip = "0.0.0.0";
	struct sockaddr_in addr;
	int show = 0;
	pthread_t thread;
	struct timeval tv;
	int pps_calc = 0, echo = 0;

	gettimeofday(&tv, NULL);

	stat_start_time = tv;
	netflow_pkts_old = netflow_pkts_total = 0;

	while ((opt = getopt(argc, argv, "cp:sH:deh")) != -1) {
		switch (opt) {
		case 'c':
			pps_calc = 1;
			break;
		case 'p':
			port = atoi(optarg);
			if (port <= 0)
				port = 2055;
			break;
		case 's':
			show++;
			break;
		case 'H':
			local_ip = optarg;
			break;
		case 'd':
			cur_level++;
			break;
		case 'e':
			echo = 1;
			break;
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
	}

	if (pps_calc) {
		ret = pthread_create(&thread, NULL, calc_pps, NULL);
		if (ret < 0) {
			printf("pthread_create failed: %s\n", strerror(errno));
			goto error;
		}
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(local_ip);
	len = sizeof(struct sockaddr_in);

	printf("Prepare to bind to %s:%d for UDP socket\n", local_ip, port);
	if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("bind");
		goto error;
	}
	printf("bind successful\n");

	process_packets(fd, show, echo);
error:
	if (fd >= 0)
		close(fd);
	return 0;
}
