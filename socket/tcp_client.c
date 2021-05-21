/* 
 *	BigBro/2021
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TCP_QUICKACK		12	/* Block/reenable quick acks */

#define TCP_KEEPIDLE	4	/* Start keeplives after this period */
#define TCP_KEEPINTVL	5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-c\tclose after connection directly\n");
	printf("\t-d\tDST-IP\n");
	printf("\t-D\tDST-PORT\n");
	printf("\t-s\tSRC-IP\n");
	printf("\t-S\tSRC-PORT\n");
	printf("\t-p\tenable pingpong\n");
	printf("\t-k\tenable keepalive\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, len, pingpong = 0, close_after_connect = 0;
	int keepalive_interval = 3, keepalive = 0;
	char *sip = NULL, *dip = "127.0.0.1";
	char buf[128];
	struct sockaddr_in addr;
	int sport = 0, dport = 80;

	while ((opt = getopt(argc, argv, "cd:D:s:S:pk:h")) != -1) {
		switch (opt) {
		case 'c':
			close_after_connect = 1;
			break;
		case 'd':
			dip = optarg;
			break;
		case 'D':
			dport = atoi(optarg);
			if (dport <= 0)
				dport = 8000;
			break;
		case 's':
			sip = optarg;
			break;
		case 'S':
			sport = atoi(optarg);
			if (sport <= 0)
				sport = 0;
			break;
		case 'p':
			pingpong = 1;
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

	signal(SIGPIPE, SIG_IGN);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto done;
	}

	if (keepalive) {
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void *)&keepalive_interval, sizeof(keepalive_interval));
		setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&keepalive_interval, sizeof(keepalive_interval));
		setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof(keepalive));
	}

	if (sip || sport) {
		memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		if (sport)
			addr.sin_port = htons(sport);
		if (sip)
			addr.sin_addr.s_addr = inet_addr(sip);

		if (bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) < 0) {
			perror("bind");
			goto done;
		}
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(dport);
	addr.sin_addr.s_addr = inet_addr(dip);
	len = sizeof(struct sockaddr_in);

	printf("Prepare to connect to %s:%d from %s:%d, and pingpong is %s\n"
		, dip, dport, sip ?: "0.0.0.0", sport, pingpong ? "enable" : "disable");

	if (pingpong) {
		int quick_ack_off = 0;
		if (setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (void *)&quick_ack_off, sizeof(quick_ack_off)) < 0) {
			printf("setsockopt for TCP_QUICKACK: %s\n", strerror(errno));
		}
	}

	if (connect(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("connect");
		goto done;
	}

	printf("connect successful\n");

	if (close_after_connect) {
		printf("close the socket\n");
		goto done;
	}

	if (pingpong) {
		sprintf(buf, "%s", "pingpong test from bigbro.");
		if (send(fd, buf, strlen(buf), 0) <= 0) {
			printf("send: %s\n", strerror(errno));
			goto done;
		}
	}

	sprintf(buf, "%s", "client - 1");
re_send:
	if (send(fd, buf, strlen(buf), 0) <= 0) {
		printf("send: %s\n", strerror(errno));
		goto done;
	}
	printf("send '%s' to peer\n", buf);

	memset(buf, 0, sizeof(buf));
	switch (recv(fd, buf, sizeof(buf), 0)) {
	case 0:
		printf("recv: NO DATA\n");
		break;
	case -1:
		printf("recv: %s\n", strerror(errno));
		goto done;
		break;
	default:
		printf("recv: %s\n", buf);
		break;
	}

	printf("press input or press CTRL + C to quit\n");
	scanf("%s", buf);
	goto re_send;
done:
	if (fd >= 0)
		close(fd);
	return 0;
}
