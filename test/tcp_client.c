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

int main(int argc, char *argv[])
{
	int opt, fd = -1, len, ret;
	char *dip = "127.0.0.1";
	char buf[128];
	struct sockaddr_in addr;
	int sport = 0, dport = 80;

	while ((opt = getopt(argc, argv, "d:D:")) != -1) {
		switch (opt) {
		case 'd':
			dip = optarg;
			break;
		case 'D':
			dport = atoi(optarg);
			if (dport <= 0)
				dport = 8000;
			break;
		default:
			break;
		}
	}

	signal(SIGPIPE, SIG_IGN);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(dport);
	addr.sin_addr.s_addr = inet_addr(dip);
	len = sizeof(struct sockaddr_in);

	printf("Prepare to connect to %s:%d\n", dip, dport);
	if (connect(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("connect");
		goto error;
	}

	printf("connect successful\n");

	sprintf(buf, "%s", "client - 1");
re_send:
	ret = send(fd, buf, strlen(buf), 0);
	if (ret <= 0) {
		printf("send: %s\n", strerror(errno));
		goto error;
	}
	printf("send '%s' to peer\n", buf);

	memset(buf, 0, sizeof(buf));
	ret = recv(fd, buf, sizeof(buf), 0);
	switch (ret) {
	case 0:
		printf("recv: NO DATA\n");
		break;
	case -1:
		printf("recv: %s\n", strerror(errno));
		goto error;
		break;
	default:
		printf("recv: %s\n", buf);
		break;
	}

	printf("press input or press CTRL + C to quit\n");
	scanf("%s", buf);
	goto re_send;
error:
	if (fd >= 0)
		close(fd);
	return 0;
}
