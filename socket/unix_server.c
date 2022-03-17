/* 
 * Unix Server
 *		BigBro/2022
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
#include <sys/un.h>		/* for struct sockaddr_un */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/time.h>

#include "common.h"

static void usage(char *cmd)
{
	printf("(version: 1.0/BigBro)\n\n");
	printf("%s usage:\n", cmd);
	printf("\t-p\tFile or Name\n");
	printf("\t-n\tuse name-based sockets instead of file-based sockets\n");
	printf("\t-d\tenable debug\n");

	exit(0);
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, accept_fd = -1;
	int ret, len, name = 0;
	struct sockaddr_un addr;
	char *file = NULL;
	char buf[128];

	while ((opt = getopt(argc, argv, "p:ndh")) != -1) {
		switch (opt) {
		case 'p':
			file = optarg;
			break;
		case 'n':
			name = 1;
		case 'd':
			debug_level++;
			break;
		default:
		case 'h':
			usage(argv[0]);
			break;
		}
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));

	if (!name) {
		if (!file) {
			printf("please input FILE PATH\n");
			goto error;
		}

		printf("Prepare to bind to %s for file-based socket\n", file);

		sprintf(addr.sun_path, "%s", file);
		len = sizeof(struct sockaddr_un);
	} else {
		printf("Prepare to bind to %s for name-based socket\n", file);

		addr.sun_family = AF_UNIX;
		if (file) {
			sprintf(addr.sun_path + 1, "%s", file);
			len = sizeof(sa_family_t) + strlen(addr.sun_path + 1) + 1;
		} else {
			len = sizeof(addr);
		}
	}

	if (bind(fd, (struct sockaddr *)&addr, len) < 0) {
		perror("bind");
		goto error;
	}
	printf("bind successful\n");

	if (listen(fd, 5) < 0) {
		perror("listen");
		goto error;
	}

restart:
	printf("Prepare to accept peer\n");
	accept_fd = accept(fd, NULL, NULL);
	if (accept_fd < 0) {
		perror("accept");
		goto error;
	}
	printf("accept successful\n");

	while (1) {
		memset(buf, 0, sizeof(buf));
		ret = recv(accept_fd, buf, sizeof(buf), 0);
		if (!ret)
			goto restart;

		printf("size: %d, content: %s\n", ret, buf);

		if (send(accept_fd, buf, strlen(buf), 0) < 0) {
			perror("send");
			goto error;
		}
	}

error:
	if (fd >= 0)
		close(fd);
	if (accept_fd >= 0)
		close(accept_fd);
	return 0;
}
