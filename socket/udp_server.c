/* 
 * UDP Server
 *		Author: BigBro
 *		Date:	2019/2020/2021/2022
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
#include <stddef.h>		/* for offsetof */
#include <net/if.h>		/* for if_nametoindex */

#include "common.h"

static int sleep_util_usr1_sig = 0;

static void usage(char *cmd)
{
	printf("(version: 1.0/BigBro)\n\n");
	printf("%s usage:\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-c\tcalculate pps\n");
	printf("\t-i\tpps interval\n");
	printf("\t-p\tlocal port\n");
	printf("\t-l\tlocal ip\n");
	printf("\t-s\tshow some infos while received pkt\n");
	printf("\t-d\tenable debug\n");
	printf("\t-u\tbind dev to send pkt\n");
	printf("\t-e\techo mode\n");
	printf("\t-R\trecv buffer size\n");
	printf("\t-S\tsleep until the SIGUSR1 signal is received\n");
	exit(0);
}

static unsigned long netflow_pkts_total;
static unsigned long netflow_pkts_old;
static struct timeval stat_start_time;

/* from busybox/libbb/udp_io.c */
static ssize_t send_to_from(int fd, void *buf, size_t len, int flags,
			const struct sockaddr_in *to, const struct sockaddr_in *from, socklen_t tolen)
{
	struct iovec iov[1];
	struct msghdr msg;
	union {
		char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))];
	} u;
	struct cmsghdr* cmsgptr;
	struct in_pktinfo *pktptr;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	memset(&u, 0, sizeof(u));

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)(struct sockaddr *)to;
	msg.msg_namelen = tolen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &u;
	msg.msg_controllen = sizeof(u);
	msg.msg_flags = flags;

	cmsgptr = CMSG_FIRSTHDR(&msg);
	cmsgptr->cmsg_level = IPPROTO_IP;
	cmsgptr->cmsg_type = IP_PKTINFO;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	pktptr = (struct in_pktinfo *)(CMSG_DATA(cmsgptr));
	pktptr->ipi_spec_dst = from->sin_addr;
	msg.msg_controllen = cmsgptr->cmsg_len;
	return sendmsg(fd, &msg, flags);
}

/* from busybox/libbb/udp_io.c */
static ssize_t recv_from_to(int fd, void *buf, size_t len, int flags,
		struct sockaddr_in *from, struct sockaddr_in *to, socklen_t sa_size)
{
	/* man recvmsg and man cmsg is needed to make sense of code below */
	struct iovec iov[1];
	union {
		char cmsg[CMSG_SPACE(sizeof(struct in_pktinfo))];
	} u;
	struct cmsghdr *cmsgptr;
	struct msghdr msg;
	ssize_t recv_length;

	iov[0].iov_base = buf;
	iov[0].iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr *)from;
	msg.msg_namelen = sa_size;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = &u;
	msg.msg_controllen = sizeof(u);

	recv_length = recvmsg(fd, &msg, flags);
	if (recv_length < 0)
		return recv_length;

	/* Here we try to retrieve destination IP and memorize it */
	for (cmsgptr = CMSG_FIRSTHDR(&msg);
			cmsgptr != NULL;
			cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)
	) {
		if (cmsgptr->cmsg_level == IPPROTO_IP
		 && cmsgptr->cmsg_type == IP_PKTINFO
		) {
			const int IPI_ADDR_OFF = offsetof(struct in_pktinfo, ipi_addr);
			to->sin_family = AF_INET;
			memcpy(&to->sin_addr, (char*)(CMSG_DATA(cmsgptr)) + IPI_ADDR_OFF, sizeof(to->sin_addr));
			/* to->sin_port = 123; - this data is not supplied by kernel */
			break;
		}
	}
	return recv_length;
}

static int process_packets(int fd, int show, int echo, int port)
{
	char recv_buf[1024 * 10];
	int ret, nfds = fd + 1;
	fd_set rfds;
	struct timeval tv;
	struct sockaddr_in from = {}, to = {};
	socklen_t addrlen = sizeof(struct sockaddr_in);

re_recv:
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	ret = select(nfds, &rfds, NULL, NULL, &tv);
	switch (ret) {
	case 0:
		debug_print(PRINT_DEBUG, "Timeout\n");
		goto re_recv;
	case -1:
		debug_print(PRINT_EMERG, "select failed(%s) and will exit\n", strerror(errno));
		exit(1);
	default:
		debug_print(PRINT_DEBUG, "readable socket num : %d\n", ret);
		break;
	}

	if (FD_ISSET(fd, &rfds)) {
		debug_print(PRINT_DEBUG, "fd %d is readable\n", fd);
	}

	memset(recv_buf, 0, sizeof(recv_buf));
	ret = recv_from_to(fd, recv_buf, sizeof(recv_buf), 0, &from, &to, addrlen);
	if (ret <= 0) {
		debug_print(PRINT_EMERG, "recv: %s, prepare to close fd and exit.\n", strerror(errno));
		sleep(2);
		close(fd);
		exit(1);
	} else {
		netflow_pkts_total++;

		debug_print(PRINT_NOTICE, "recv pkt (%d bytes) "NIPQUAD_FMT":%u => "NIPQUAD_FMT":%u\n", ret
			, NIPQUAD(from.sin_addr.s_addr), ntohs(from.sin_port)
			, NIPQUAD(to.sin_addr), port);
		debug_print(PRINT_DEBUG, "content: [%s]\n", recv_buf);

		if (show > 1) {
			printf("recv length: %d\n", ret);
			printf("\t%s\n", recv_buf);
		} else if (show) {
			printf(".");
			fflush(NULL);
		}
	}

	if (echo) {
		debug_print(PRINT_NOTICE, "sent pkt (%d bytes) "NIPQUAD_FMT":%u => "NIPQUAD_FMT":%u\n", ret
			, NIPQUAD(to.sin_addr.s_addr),  port
			, NIPQUAD(from.sin_addr.s_addr), ntohs(from.sin_port));

		/* avoid fragmenting packets */
		if (ret > 1000)
			ret = 1000;

		if (send_to_from(fd, recv_buf, ret, 0, &from, &to, addrlen) < 0) {
			debug_print(PRINT_EMERG, "send failed: %s.\n", strerror(errno));
		}
	}
	goto re_recv;
}

#define TIME_INTERVAL(a, b) ((a.tv_sec * 1000000 + a.tv_usec) - (b.tv_sec * 1000000 + b.tv_usec))
static void *calc_pps(void *arg)
{
	struct timeval curr_time, start_time;
	unsigned long pkts_old, pkts_curr, pps;
	int interval = 5;

	printf("Entering calc_pps\n");

	if (arg && (*(int *)arg > 0))
		interval = *(unsigned int *)arg;

	while (1) {
		sleep(interval);

	 	gettimeofday(&curr_time, NULL);
		start_time = stat_start_time;
		stat_start_time = curr_time;
		pkts_curr = netflow_pkts_total;
		pkts_old = netflow_pkts_old;
		netflow_pkts_old = pkts_curr;

		pps = ((pkts_curr - pkts_old) * 1000000)/TIME_INTERVAL(curr_time, start_time);
		printf("pps: %5lu, pkts: %7lu, interval: %lu us\n"
			, pps, pkts_curr, TIME_INTERVAL(curr_time, start_time));
	}
	return arg;
}

static void sig_handler(int signo)
{
	sleep_util_usr1_sig = 0;
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, len, ret, on = 1;
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
	};
	int show = 0;
	pthread_t thread;
	struct timeval tv;
	int pps_calc = 0, echo = 0;
	unsigned int ifindex = 0;
	int interval = -1, recv_buf_len = 0;

	gettimeofday(&tv, NULL);

	stat_start_time = tv;
	netflow_pkts_old = netflow_pkts_total = 0;

	while ((opt = getopt(argc, argv, "cp:sl:deu:i:R:Sh")) != -1) {
		int tmp;

		switch (opt) {
		case 'c':
			pps_calc = 1;
			break;
		case 'p':
			tmp = atoi(optarg);
			if (tmp <= 0 || tmp > 65535) {
				printf("invalid param: %s\n", optarg);
				usage(argv[0]);
			}
			addr.sin_port = ntohs(tmp);
			break;
		case 's':
			show++;
			break;
		case 'l':
			if (inet_aton(optarg, &addr.sin_addr) == 0) {
				printf("invalid param: %s\n", optarg);
				usage(argv[0]);
			}
			break;
		case 'd':
			debug_level++;
			break;
		case 'e':
			echo = 1;
			break;
		case 'u':
			ifindex = if_nametoindex(optarg);
			if (ifindex <= 0) {
				printf("invalid interface: %s\n", optarg);
				usage(argv[0]);
			} else {
				ifindex = htonl(ifindex);
			}
			break;
		case 'i':
			interval = atoi(optarg);
			if (interval <= 0) {
				printf("invalid interval: %s\n", optarg);
				usage(argv[0]);
			}
			break;
		case 'R':
			recv_buf_len = atoi(optarg);
			if (recv_buf_len <= 0) {
				printf("invalid buffer size: %s\n", optarg);
				usage(argv[0]);
			}
			break;
		case 'S':
			sleep_util_usr1_sig = 1;
			break;
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
	}

	if (pps_calc) {
		ret = pthread_create(&thread, NULL, calc_pps, (void *)&interval);
		if (ret < 0) {
			printf("pthread_create failed: %s\n", strerror(errno));
			goto error;
		}
	}

	if (signal(SIGUSR1, sig_handler)) {
		perror("signal");
		goto error;
	}

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	len = sizeof(struct sockaddr_in);

	printf("Prepare to bind to %s:%d for UDP socket\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("bind");
		goto error;
	}
	printf("bind successful\n");

	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)) < 0) {
		perror("setsockopt for IP_PKTINFO");
		goto error;
	}

	if (ifindex > 0) {
		if (setsockopt(fd, IPPROTO_IP, IP_UNICAST_IF, &ifindex, sizeof(ifindex)) < 0) {
			perror("setsockopt for IP_UNICAST_IF");
			goto error;
		}
	}

	if (recv_buf_len) {
		int val, old, size = sizeof(val);

		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &size) < 0) {
			perror("getsockopt for SO_RCVBUF");
			goto error;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &recv_buf_len, sizeof(recv_buf_len)) < 0) {
			perror("setsockopt for SO_RCVBUF");
			goto error;
		}

		old = val;

		if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, &size) < 0) {
			perror("getsockopt for SO_RCVBUF");
			goto error;
		}

		debug_print(PRINT_NOTICE, "UDP recvbuf: %d -> %d (expected: %d)\n", old, val, recv_buf_len);
	}

	while (sleep_util_usr1_sig) {
		debug_print(PRINT_DEBUG, "prepare to sleep for 5 seconds\n");
		sleep(5);
	}

	process_packets(fd, show, echo, ntohs(addr.sin_port));
error:
	if (fd >= 0)
		close(fd);
	return 0;
}
