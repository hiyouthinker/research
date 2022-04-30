/* 
 * TCP Server
 *		-- BigBro/2021
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>

static int listener_fd = -1;
static int pause_listener_ok = 0;

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\tSIGUSR1\tpause listener (based on reuseaddr)\n");
	printf("\tSIGUSR2\tresume listener\n");
	printf("\t-h\tshow this help\n");
	printf("\t-l\tlocal IP\n");
	printf("\t-L\tenabel linger and set timeout\n");
	printf("\t-p\tlocal port\n");
	printf("\t-r\tenable reuseaddr\n");
	printf("\t-R\tenable reuseport\n");
	printf("\t-k\tenable keepalive\n");
	printf("\t-f\tTCP Fast Open\n");
	exit(0);
}

static int __pause_listener(int fd)
{
	/*
	 * call tcp_disconnect in kernel
	 * change the state from TCP_LISTEN to TCP_CLOSE
	 */
	if (shutdown(fd, SHUT_RD) != 0) {
		printf("shutdown for SHUT_RDWR failed: %s\n", strerror(errno));
		return -1;
	}
	pause_listener_ok = 1;
	return 0;
}

static int __resume_listener(int fd)
{
	if (listen(fd, 5)) {
		printf("listen failed: %s\n", strerror(errno));
		return -1;
	}
	pause_listener_ok = 0;
	return 0;
}

static void pause_listener(int sig)
{
	printf("receive signal to pause server, signal num: %d\n", sig);
	if (listener_fd < 0) {
		printf("invalid fd\n");
		return;
	}
	__pause_listener(listener_fd);
}

static void resume_listener(int sig)
{
	printf("receive signal to resume server, signal num: %d\n", sig);
	if (listener_fd < 0) {
		printf("invalid fd\n");
		return;
	}
	__resume_listener(listener_fd);
}

static void child_process_packets(int fd, int pid)
{
	char rbuf[1024], sbuf[1024];

re_recv:
	memset(rbuf, 0, sizeof(rbuf));
	switch (recv(fd, rbuf, sizeof(rbuf), 0)) {
	case 0:
		printf("recv(0): %s, prepare to close fd and exit\n", strerror(errno));
		close(fd);
		break;
	case -1:
		printf("recv(-1): %s, prepare to close fd and exit\n", strerror(errno));
		sleep(2);
		close(fd);
		break;
	default:
		printf("recv length: %s\n", rbuf);
		sprintf(sbuf, "Hello! from %d\n", pid);
		send(fd, sbuf, strlen(sbuf), 0);
		if (!strcmp(rbuf, "swr")) {
			printf("shutdown for writing\n");
			shutdown(fd, SHUT_WR);
		} else if (!strcmp(rbuf, "srd")) {
			printf("shutdown for reading\n");
			shutdown(fd, SHUT_RD);
		} else if (!strcmp(rbuf, "srdwr")) {
			printf("shutdown for reading & writing\n");
			shutdown(fd, SHUT_RDWR);
		} else if (*rbuf == 'q') {
			printf("quit\n");
			close(fd);
			break;
		}
		goto re_recv;
	}
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, port = 80, len;
	char *local_ip = "0.0.0.0";
	struct sockaddr_in addr;
	int reuseaddr = 0, reuseport = 0, accept_fd;
	int keepalive_interval = 3, keepalive = 0, one = 1;
	int tcp_fast_open = -1;
	struct linger linger = {0, 0};

	while ((opt = getopt(argc, argv, "l:L:p:rRk:f:h")) != -1) {
		switch (opt) {
		case 'l':
			local_ip = optarg;
			break;
		case 'L':
			linger.l_onoff = 1;
			linger.l_linger = atoi(optarg);
			break;
		case 'p':
			port = atoi(optarg);
			if (port <= 0)
				port = 80;
			break;
		case 'r':
			reuseaddr = 1;
			break;
		case 'R':
			reuseport = 1;
			break;
		case 'k':
			keepalive = atoi(optarg);
			break;
		case 'f':
			tcp_fast_open = atoi(optarg);
			break;
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
	}

	if (0) {
		struct sigaction sa;

		memset(&sa, 0, sizeof(struct sigaction));
		sa.sa_handler = pause_listener;
		sigaction(SIGUSR1, &sa, NULL);

		sa.sa_handler = resume_listener;
		sigaction(SIGUSR2, &sa, NULL);
	} else {
		signal(SIGUSR1, pause_listener);
		signal(SIGUSR2, resume_listener);
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	if (reuseaddr && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
		perror("setsockopt for reuseaddr");
		goto error;
	}
	if (reuseport && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) < 0) {
		perror("setsockopt for reuseport");
		goto error;
	}

	if (linger.l_onoff && setsockopt(fd, SOL_SOCKET, SO_LINGER,
			   (struct linger *) &linger, sizeof(struct linger))) {
		perror("setsockopt for liner");
		goto error;
	}

	if (keepalive) {
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepalive_interval, sizeof(keepalive_interval));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepalive_interval, sizeof(keepalive_interval));
//		setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepalive_interval, sizeof(keepalive_interval));
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
	}

	if ((tcp_fast_open > 0) && setsockopt(fd, IPPROTO_TCP, TCP_FASTOPEN, (void *) &tcp_fast_open, sizeof(int))) {
		perror("setsockopt for fast open");
		goto error;
	}

#if 0
	setsockopt(fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(local_ip);
	len = sizeof(struct sockaddr_in);

	printf("Prepare to bind to %s:%d\n", local_ip, port);
	if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("bind");
		goto error;
	}
	printf("bind successful\n");

	if (listen(fd, 5)) {
		printf("listen: %s\n", strerror(errno));
		goto error;
	}
	listener_fd = fd;

	while (1) {
		int pid, parent_id;

		len = sizeof(struct sockaddr);
		accept_fd = accept(fd, (struct sockaddr *)&addr, (socklen_t *)&len);
		if (accept_fd < 0) {
			/*
			 * errno is EINVAL if state of socket isn't TCP_LISTEN
			 * errno is EINTR if signal pending
			 */
			if (pause_listener_ok && ((errno == EINVAL) || (errno == EINTR))) {
				sleep(20);
				continue;
			}
			printf("accept: %s (%d)\n", strerror(errno), errno);
			goto error;
		}
		parent_id = getpid();
		printf("\n=================================================\n");
		printf("accept for %s:%d, pid (parent): %d\n"
			, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), parent_id);
		pid = fork();
		switch (pid) {
		case -1:
			printf("fork: %s\n", strerror(errno));
			break;
		case 0:/* child */
			printf("I am child, pid: %d\n", getpid());
			close(fd);
			child_process_packets(accept_fd, parent_id);
			break;
		default:/* parent */
			close(accept_fd);
			break;
		}
	}
error:
	if (fd >= 0)
		close(fd);
	return 0;
}
