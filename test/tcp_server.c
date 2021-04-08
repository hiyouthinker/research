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
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SO_KEEPALIVE	9

#define TCP_KEEPIDLE	4	/* Start keeplives after this period */
#define TCP_KEEPINTVL	5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-l\tLocal IP\n");
	printf("\t-p\tLocal Port\n");
	printf("\t-r\tenable reuseaddr\n");
	printf("\t-R\tenable reuseport\n");
	printf("\t-k\tenable keepalive\n");
	exit(0);
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
		if (!strcmp(rbuf, "qw")) {
			printf("shutdown for writing\n");
			shutdown(fd, SHUT_WR);
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

	while ((opt = getopt(argc, argv, "l:p:rRk:h")) != -1) {
		switch (opt) {
		case 'l':
			local_ip = optarg;
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
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
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
	if (keepalive) {
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepalive_interval, sizeof(keepalive_interval));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepalive_interval, sizeof(keepalive_interval));
//		setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&keepalive_interval, sizeof(keepalive_interval));
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
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

	while (1) {
		int pid, parent_id;

		len = sizeof(struct sockaddr);
		accept_fd = accept(fd, (struct sockaddr *)&addr, &len);
		if (accept_fd < 0) {
			printf("accept: %s\n", strerror(errno));
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
