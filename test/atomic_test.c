/*
 * BigBro for Test of atomic_* functions @ 2021.03
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

#define lock_compare_exchange(ptr, oldval, newval)	\
			__atomic_compare_exchange (ptr, &oldval, &newval, 0, 0, 0)

int main(int argc, char *argv[])
{
	long packets = 100;
	long pkts1, pkts2;

	pkts1 = packets;
	pkts2 = pkts1 + 3;

	lock_compare_exchange(&packets, pkts1, pkts2);

	printf("packets: %ld\n", packets);
	printf("Done!\n");
	return 0;
}
