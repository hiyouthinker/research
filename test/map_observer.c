/*
 * BigBro/2023
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/types.h>
#include <fcntl.h>

#define PIN_BASEDIR       "/sys/fs/bpf"
#define ENGINE_DIR_NAME   "engine"
#define SESSION_OUTER_MAP "session_nat_table_outer"
#define PROC_MAP_PATH     "/proc/net/map/print_map"

int main(int argc, char **argv)
{
	char buf[128];
	int outer_map_fd = -1, inner_map_fd;
	int key = 0, value;

	sprintf(buf, "%s/%s/%s", PIN_BASEDIR, ENGINE_DIR_NAME, SESSION_OUTER_MAP);
	outer_map_fd = bpf_obj_get(buf);
	if (outer_map_fd < 0) {
		printf("failed to execute bpf_obj_get: %s\n", strerror(errno));
		goto done;
	} else {
		printf("fd of %s: %d\n", buf, outer_map_fd);
	}

	if (bpf_map_lookup_elem(outer_map_fd, &key, &value) < 0) {
		fprintf(stderr, "failed to lookup `%s' maps: %s\n", SESSION_OUTER_MAP, strerror(errno));
		goto done;
	} else {
		int fd, len;
		char infos[1024];

		printf("value: %d\n", value);

		inner_map_fd = bpf_map_get_fd_by_id(value);
		if (inner_map_fd < 0) {
			printf("failed to execute bpf_map_get_fd_by_id: %s\n", strerror(errno));
			goto done;
		}

		fd = open(PROC_MAP_PATH, O_RDWR);
		if (fd < 0) {
			printf("failed to open %s: %s\n", PROC_MAP_PATH, strerror(errno));
			goto done;
		}

		sprintf(infos, "%d", inner_map_fd);

		if (write(fd, infos, strlen(infos) + 1) < 0) {
			printf("failed to write %s: %s\n", PROC_MAP_PATH, strerror(errno));
			close(fd);
			goto done;
		}

		memset(infos, 0, sizeof(infos));

		len = read(fd, infos, sizeof(infos));
		if (len < 0) {
			printf("failed to read %s: %s\n", PROC_MAP_PATH, strerror(errno));
			close(fd);
			goto done;
		}

		printf("The id of map for cpu%d: %d, fd: %d, infos: [%s]\n", key, value, inner_map_fd, infos);
		close(fd);
	}

done:
	if (outer_map_fd >= 0) {
		close(outer_map_fd);
	}

	return 0;
}
