/*
 * BigBro/2021
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static char http_header[] = 
	"GET / HTTP/1.1\r\n"
	"Host: %s\r\n"
	"User-Agent: XXXXXX\r\n"
	"Accept: */*\r\n"
	"Accept-Encoding: gzip, deflate\r\n"
	"Accept-Language: en-US,en;q=0.9\r\n"
	"\r\n";

static void usage(void)
{
	printf("Version: %s %s.\n", __DATE__, __TIME__);
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, dport = 80, sport = 0, len, ret;
	char *dip = "104.193.88.123", *sip = NULL, *domain = "www.baidu.com";
	struct sockaddr_in addr;
	char *header = NULL, recv_buf[1024 * 10];

	while ((opt = getopt(argc, argv, "H:p:d:s:S:h")) != -1) {
		switch (opt) {
		case 'd':
			dip = optarg;
			break;
		case 'D':
			dport = atoi(optarg);
			if (dport <= 0)
				dport = 80;
			break;
		case 's':
			sip = optarg;
			break;
		case 'S':
			sport = atoi(optarg);
			if (sport <= 0)
				sport = 0;
			break;
		case 'u':
			domain = optarg;
			break;
		default:
		case 'h':
			usage();
			break;
		}
	}

	header = malloc(sizeof(http_header) + strlen(domain));
	if (!header)
		goto error;

	sprintf(header, http_header, domain);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
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
			goto error;
		}
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(dport);
#if 1
	addr.sin_addr.s_addr = inet_addr(dip);
#else
	inet_aton(dip, &addr.sin_addr);
#endif
	len = sizeof(struct sockaddr_in);

	printf("Prepare to connect to %s:%d for %s\n", dip, dport, domain);
	if (connect(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("connect");
		goto error;
	}
	printf("connect successful\n\n");

	ret = send(fd, header, strlen(header), 0);
	if (ret < 0) {
		perror("send");
		goto error;
	} else {
		printf("request:\n[%s]\n\n", header);
	}

	memset(recv_buf, 0, sizeof(recv_buf));
	ret = recv(fd, recv_buf, sizeof(recv_buf), 0);
	if (ret < 0) {
		perror("recv");
		goto error;
	} else {
		printf("response:\n[%s]\n", recv_buf);
	}
error:
	if (fd >= 0)
		close(fd);
	if (header)
		free(header);
	return 0;
}
