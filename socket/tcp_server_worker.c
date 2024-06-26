/* 
 * TCP Server
 *		-- BigBro/2024
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdbool.h>

#define MAX_FD_NUM 512
#define FLOCK_FILE "/tmp/.file_lock_123"

static void usage(char *cmd)
{
	printf("usage: %s\n", cmd);
	printf("\t-h\tshow this help\n");
	printf("\t-l\tlocal IP\n");
	printf("\t-p\tlocal port\n");
	printf("\t-r\tenable reuseaddr\n");
	printf("\t-R\tenable reuseport\n");
	printf("\t-w\tworker number\n");

	exit(0);
}

static int open_flock_file()
{
	int fd = open(FLOCK_FILE, O_RDWR | O_CREAT, 0666);
	if (fd == -1) {
		printf("failed to open file: %s\n", strerror(errno));
		exit(1);
	}

	return fd;
}

static bool fd_is_readable(int fd)
{
	struct timeval tv = {
		.tv_sec = 0,
		.tv_usec = 0,
	};
	fd_set rfds;
	int nfds = 0, ret;

	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);

	if (nfds <= fd)
		nfds = fd + 1;

	ret = select(nfds, &rfds, NULL, NULL, &tv);
	
	switch(ret) {
	case 0:
	//	printf("fd %d is not readable\n", fd);
		return false;
	case 1:
	//	printf("fd %d is readable\n", fd);
		return true;
	default:
		printf("failed to select fd %d: %s\n", fd, strerror(errno));
		break;
	}

	return false;
}

static void worker_process(int fd)
{
	int listen_fd = fd, file_fd;
	int nfds = 0;
	fd_set rfds, rfds_orig;

	file_fd = open_flock_file();

	FD_ZERO(&rfds);
	FD_SET(listen_fd, &rfds);

	rfds_orig = rfds;

	if (nfds <= listen_fd)
		nfds = listen_fd + 1;

	while (1) {
		struct sockaddr_in addr;
		struct timeval tv = {
			.tv_sec = 5,
			.tv_usec = 0,
		};
		int ret, i, len;

		rfds = rfds_orig;

		ret = select(nfds, &rfds, NULL, NULL, &tv);
		switch (ret) {
		case 0:
		//	printf("Timeout...\n");
			continue;
		case -1:
			printf("select failed(%s) and will exit\n", strerror(errno));
			exit(1);
		default:
			if (FD_ISSET(listen_fd, &rfds)) {
				len = sizeof(struct sockaddr);

				if (flock(file_fd, LOCK_EX) == -1) {
					printf("failed to flock file: %s\n", strerror(errno));
					exit(1);
				}

				if (!fd_is_readable(listen_fd)) {
					printf("worker %d: no fd is readable, ingnore.\n", getpid());
					flock(file_fd, LOCK_UN);
					continue;
				}

				fd = accept(listen_fd, (struct sockaddr *)&addr, (socklen_t *)&len);
				if (fd < 0) {
					printf("failed to accept: %s\n", strerror(errno));
					flock(file_fd, LOCK_UN);
					exit(1);
				}

				flock(file_fd, LOCK_UN);

				if (fd >= FD_SETSIZE) {
					printf("too much concurrency (fd = %d), close connection!\n", fd);
					close(fd);
					continue;
				}

				printf("worker %d accepted from %s:%d\n", getpid(), inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

				if (nfds <= fd)
					nfds = fd + 1;

				FD_SET(fd, &rfds_orig);
			} else {
				bool readable = false;

				for (i = 0; i < FD_SETSIZE; i++) {
					fd = i;
					if (FD_ISSET(fd, &rfds)) {
						char buffer[1024] = {0};

						if (getpeername(fd, (struct sockaddr *)&addr, (socklen_t *)&len) != 0) {
							printf("failed to getpeername: %s\n", strerror(errno));
							exit(1);
						}

						ret = read(fd, buffer, sizeof(buffer) - 1);
						readable = true;

						switch (ret) {
						case 0:
							printf("close connection for %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
							close(fd);
							FD_CLR(fd, &rfds_orig);
							continue;
						case -1:
							printf("failed to read: %s from %s:%d\n", strerror(errno), inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
							exit(1);
						default:
							printf("worker %d read %d bytes from %s:%d: %s\n", getpid(), ret, inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), buffer);

							len = write(fd, buffer, ret);
							if (ret != len) {
								printf("failed to write: %s (%d != %d)\n", strerror(errno), ret, len);
								exit(1);
							}
						}
					}
				}

				if (!readable) {
					printf("worker %d: no fd is readable, ignore..\n", getpid());
				}
			}
			break;
		}
	}
}

int main(int argc, char *argv[])
{
	int opt, fd = -1, port = 80, len;
	char *local_ip = "0.0.0.0";
	struct sockaddr_in addr;
	int reuseaddr = 0, reuseport = 0, defer = 0, accept_fd;
	int keepalive_interval = 3, keepalive = 0, one = 1;
	int tcp_fast_open = -1;
	int worker = 2, i;
	struct linger linger = {0, 0};

	while ((opt = getopt(argc, argv, "l:p:rRw:h")) != -1) {
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
		case 'w':
			worker = atoi(optarg);
			if (worker <= 0)
				worker = 2;
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

	for (i = 0; i < worker; i++) {
		int pid = fork();
		switch (pid) {
		case -1:
			printf("fork: %s\n", strerror(errno));
			exit(0);
		case 0:/* child */
			printf("worker %d started\n", getpid());
			worker_process(fd);
			break;
		default:/* parent */
			break;
		}
	}

	while (1) {
		sleep(5);
	}

error:
	if (fd >= 0)
		close(fd);
	return 0;
}
