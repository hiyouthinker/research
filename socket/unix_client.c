/* 
 * Unix Client
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
	printf("\t-h\tshow this help\n");
	printf("\t-p\tFile or Name\n");
	printf("\t-n\tuse name-based sockets instead of file-based sockets\n");
	printf("\t-w\twords to peer\n");
	printf("\t-d\tenable debug\n");

	exit(0);
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, len;
	int ret, name = 0;
	struct sockaddr_un addr;
	char *file = NULL;
	char *words = "hello!";
	char buf[128];

	while ((opt = getopt(argc, argv, "p:w:ndh")) != -1) {
		switch (opt) {
		case 'p':
			file = optarg;
			break;
		case 'w':
			words = optarg;
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

		printf("Prepare to connect to peer by file %s\n", file);

		sprintf(addr.sun_path, "%s", file);
		len = sizeof(struct sockaddr_un);
	} else {
		printf("Prepare to connect peer by abstract socket\n");

		addr.sun_family = AF_UNIX;
		if (file) {
			sprintf(addr.sun_path + 1, "%s", file);
			len = sizeof(sa_family_t) + strlen(addr.sun_path + 1) + 1;
		} else {
			len = sizeof(addr);
		}
	}

	if (connect(fd, (struct sockaddr *)&addr, len) < 0) {		
		perror("conect");
		goto error;
	}

	printf("connect successful\n");

	if (send(fd, words, strlen(words), 0) < 0) {
		perror("send");
		goto error;
	}

	ret = recv(fd, buf, sizeof(buf), 0);
	switch (ret) {
	case -1:
		printf("failed to recv: %s\n", strerror(errno));
		break;
	case 0:
		printf("Nothing to recv\n");
		break;
	default:
		printf("length: %d, content: %s\n", ret, buf);
		break;
	}

error:
	if (fd >= 0)
		close(fd);
	return 0;
}
