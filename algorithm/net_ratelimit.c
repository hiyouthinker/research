/*
 * for test
 *	https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?h=linux-4.5.y&id=c2594bc37f4464bc74f2c119eb3269a643400aa0
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

struct ratelimit_state {
	int interval;
	int burst;
	int printed;
	int missed;
	unsigned long begin;
};

#define DEFINE_RATELIMIT_STATE(name, interval, burst)		\
		struct ratelimit_state name = {interval, burst,}

DEFINE_RATELIMIT_STATE(net_ratelimit_state, 1, 1);

int g_bug = 0;

int __ratelimit(struct ratelimit_state *rs)
{
	unsigned long flags;

	if (!rs->interval)
		return 1;

	if (!rs->begin)
		rs->begin = time(NULL);

	if (time(NULL) > (rs->begin + rs->interval)) {
		if (rs->missed)
			printf("%s: %d callbacks suppressed\n",
				__func__, rs->missed);
		if (g_bug)
			rs->begin = 0;
		else
			rs->begin = time(NULL);
		rs->printed = 0;
		rs->missed = 0;
	}
	if (rs->burst && rs->burst > rs->printed)
		goto print;

	rs->missed++;
	return 0;

print:
	rs->printed++;
	return 1;
}

int net_ratelimit(void)
{
	return __ratelimit(&net_ratelimit_state);
}

int main(int argc, char *argv[])
{
	int i = 0;
	int opt;

	while ((opt = getopt(argc, argv, "b:")) != -1) {
		switch (opt) {
		case 'b':
			g_bug = atoi(optarg);
			break;
		default:
			g_bug = 0;
			break;
		}
	}

	while (1) {
		if (net_ratelimit())
			printf("i = %d\n", i);
		sleep(3);
		i++;
	}

	printf("Done!\n");
	return 0;
}
