/*
 * BigBro for NAT Conflict Testing @ 2021.03
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>

#define VERSION					"1.0"
#define PORT_START				1
#define PORT_END				65535
#define PORT_RANGE				(PORT_END - PORT_START + 1)
#define PORT_NUM				(PORT_END + 1)

#define PORT_RANGE_PERCENT_50		(PORT_RANGE * 50 / 100)
#define PORT_RANGE_PERCENT_80		(PORT_RANGE * 80 / 100)

#define	PRINT_BY_FIXED_TIME		1

static char port_state[PORT_NUM] = {0};
static int debug = 0;

struct stat_s {
	struct {
		int conflict;
		int success;
		int port_num_smaller_then_10;
		int port_num_smaller_then_1024;
		int port_num_smaller_then_10000;	/* < 10000 */
		int port_num_bigger_then_10000;
		int port_num_bigger_then_20000;
		int port_num_bigger_then_30000;
		int port_num_bigger_then_40000;
		int port_num_bigger_then_50000;
		int port_num_bigger_then_60000;		/* > 60000 */
	} init;
	struct {
		int conflict_num_per_port;	/* None */
		int port_num_by_detected;	/* How many ports are detected */
		int conflict_num;			/* The number of conflicts on all ports */
		int conflict_port_num;		/* How many ports are in conflict (detect failed) */
	} check;
	struct {
		int invalid_port; /* logic error */
	} error;
} stats;

enum {
	PERCENT_50,
	PERCENT_80,
};

static int init_by_percent(int percent)
{
	int i = 0, loop;
	int seed = getpid();

	srand(seed);

	switch (percent) {
	case PERCENT_50:
		printf("Generating 50%% (%d/%d) random ports\n"
			, PORT_RANGE_PERCENT_50, PORT_RANGE);
		loop = PORT_RANGE_PERCENT_50;
		break;
	case PERCENT_80:
	default:
		printf("Generating 80%% (%d/%d) random ports\n"
			, PORT_RANGE_PERCENT_80, PORT_RANGE);
		loop = PORT_RANGE_PERCENT_80;
		break;
	};

	while (i < loop) {
		int port = rand();

		port = (PORT_START + (port % PORT_RANGE));

		if ((port < PORT_START) || (port > PORT_END))
			stats.error.invalid_port;

		if (debug && port < 10)
			printf("loop %d, port %d\n", i, port);

		if (port_state[port]) {
			stats.init.conflict++;
			continue;
		}
		else {
			stats.init.success++;
			port_state[port] = 1;
			i++;
		}

		if (port > 60000) {
			stats.init.port_num_bigger_then_60000++;
		}
		else if (port > 50000) {
			stats.init.port_num_bigger_then_50000++;
		}
		else if (port > 40000) {
			stats.init.port_num_bigger_then_40000++;
		}
		else if (port > 30000) {
			stats.init.port_num_bigger_then_30000++;
		}
		else if (port > 20000) {
			stats.init.port_num_bigger_then_20000++;
		}
		else if (port > 10000) {
			stats.init.port_num_bigger_then_10000++;
		}
		else {
			stats.init.port_num_smaller_then_10000++;
			if (port <= 1000) {
				stats.init.port_num_smaller_then_1024++;
				if (port <= 10)
					stats.init.port_num_smaller_then_10++;
			}
		}
	}

	printf("Done!\n");
	return 0;
}

static int print_stats(void)
{
	printf("version: %s @ %s %s\n", VERSION, __DATE__, __TIME__);
	printf("init\n\tconflict: %d, success: %d, <= 10: %d, <= 1000: %d, <= 10000: %d\n"
		, stats.init.conflict, stats.init.success
		, stats.init.port_num_smaller_then_10
		, stats.init.port_num_smaller_then_1024
		, stats.init.port_num_smaller_then_10000);
	printf("\t > 10000: %d, > 20000: %d, > 30000: %d, > 40000: %d, > 50000: %d, > 60000: %d\n"
		, stats.init.port_num_bigger_then_10000
		, stats.init.port_num_bigger_then_20000
		, stats.init.port_num_bigger_then_30000
		, stats.init.port_num_bigger_then_40000
		, stats.init.port_num_bigger_then_50000
		, stats.init.port_num_bigger_then_60000);
	printf("check\n\t%-25s: %d\n\t%-25s: %d"
		, "conflict number per port"
		, stats.check.conflict_num_per_port
		, "port number by detected"
		, stats.check.port_num_by_detected);
	printf("\n\t%-25s: %d\n\t%-25s: %d\n\t%-25s: %d%%\n"
		, "all conflicted number"
		, stats.check.conflict_num
		, "conflicted port number"
		, stats.check.conflict_port_num
		, "conflict percent"
		, stats.check.conflict_port_num * 100/stats.check.port_num_by_detected);
	printf("error\n\tinvalid port number: %d\n",stats.error.invalid_port);
	return 0;
}

/*
 * conflict_num_per_port: How many conflicts are allowed for each port
 * port_num_by_detected: How many ports will be detected
 * alg: algorithm
 */
static int check_conflict(int conflict_num_per_port, int port_num_by_detected, int alg)
{
	int i = 0;
	time_t now, last;
	int tcp_port_rover = 0;
	int seed;

	stats.check.conflict_num_per_port = conflict_num_per_port;
	stats.check.port_num_by_detected = port_num_by_detected;
	seed = time(NULL);
	srand(seed);

	last = time(NULL);
	while (i++ < port_num_by_detected) {
		int port = rand(), j;

#ifdef PRINT_BY_FIXED_NUMBER
		if (!(i % (port_num_by_detected/10))) {
			printf("will check port %d\n", i);
		}
#endif
#ifdef PRINT_BY_FIXED_TIME
		now = time(NULL);
		if (now - last > 5) {
			printf("will check port %d\n", i);
			last = now;
		}
#endif
		port = (PORT_START + (port % PORT_RANGE));
		if ((port < PORT_START) || (port > PORT_END))
			stats.error.invalid_port;

		if (alg == 2)
			tcp_port_rover = 0;

		for (j = 0; j < conflict_num_per_port; j++) {
			int k;
#ifdef PRINT_BY_FIXED_TIME
			now = time(NULL);
			if (now - last > 5) {
				printf("will check port%d: %d\n", i, port);
				last = now;
			}
#endif
			for (k = PORT_START; k < PORT_END; k++) {
#ifdef PRINT_BY_FIXED_TIME
				now = time(NULL);
				if (now - last > 5) {
					printf("will check port%d: %d\n", i, port);
					last = now;
				}
#endif
				if ((port == k) && (port_state[k])) {
					stats.check.conflict_num++;

					switch (alg) {
					case 0:
					//	port = (PORT_START + ((port + 1) % PORT_RANGE));
						port = (PORT_START + ((port + 1 - PORT_START) % PORT_RANGE));
						break;
					case 1:
					case 2:
						port = (PORT_START + (tcp_port_rover++ % PORT_RANGE));
						break;
					case 3:
						port = (PORT_START + ((port + k) % PORT_RANGE));
						break;
					case 4:
						port = (PORT_START + ((port + (j * 2 + 1) - PORT_START) % PORT_RANGE));
						break;
					default:
						srand(time(NULL) + k);
						port = (PORT_START + (rand() % PORT_RANGE));
						break;
					}
					if ((port < PORT_START) || (port > PORT_END))
						stats.error.invalid_port;
					break;
				}
			}
			/* success */
			if (k == PORT_END)
				break;
		}
		if (j == conflict_num_per_port)
			stats.check.conflict_port_num++;
	}
	return 0;
}

static int usage(void)
{
	printf("Usage: %s\n", "");
	exit(0);
}

int main(int argc, char *argv[])
{
	int opt, percent, conflict_num = 5, port_num = 10000;
	int alg = 1;

	while ((opt = getopt(argc, argv, "a:p:c:P:dh")) != -1) {
		switch (opt) {
		case 'a':
			alg = atoi(optarg);
			break;
		case 'p':
			percent = atoi(optarg);
			break;
		case 'c':
			conflict_num = atoi(optarg);
			break;
		case 'P':
			port_num = atoi(optarg);
			break;
		case 'd':
			debug = 1;
			printf("debug: %d\n", debug);
			break;
		default:
		case 'h':
			usage();
			break;
		}
	}

	memset(port_state, 0, sizeof(port_state));
	memset(&stats, 0, sizeof(stats));

	if (percent == 5)
		init_by_percent(PERCENT_50);
	else
		init_by_percent(PERCENT_80);

	check_conflict(conflict_num, port_num, alg);
	print_stats();

	printf("Exiting!\n");
	return 0;
}
