/*
 *  Test of atomic_* functions
 *			-- BigBro @ 2021.03/2021.07
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
#include <stdbool.h>

/*
references:
	https://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/Atomic-Builtins.html#Atomic-Builtins
	https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
*/

/*
 * __sync_fetch_and_add/__sync_fetch_and_add_1/__sync_fetch_and_add_2 ...
 * __sync_fetch_and_sub/__sync_fetch_and_sub_1/__sync_fetch_and_sub_2 ...
 * __atomic_compare_exchange
 * __atomic_compare_exchange_n
 * __sync_bool_compare_and_swap
 * __sync_val_compare_and_swap
 * 			is defined in gcc-9.3.0/gcc/sync-builtins.def
 */

#define lock_compare_exchange(ptr, oldval, newval)	\
			__atomic_compare_exchange (ptr, &oldval, &newval, 0, 0, 0)

/*
 * from glibc-2.28/sysdeps/x86_64/atomic-machine.h
 */
#define atomic_exchange_and_add(mem, value) \
  __sync_fetch_and_add (mem, value)

int main(int argc, char *argv[])
{
	long a, b, c;
	int d = 1234;

	a = 3;
	b = a + 1;
	c = 100;

	printf("argc: %d\n", argc);
	printf("a/b/c/d: %ld/%ld/%ld/%d\n", a, b, c, d);

	if (argc == 1)
		d = lock_compare_exchange(&a, b, c);
	else if (argc == 2)
		d = __sync_bool_compare_and_swap(&a, b, c);
	else
		d = __sync_val_compare_and_swap(&a, b, c);

	printf("a/b/c/d: %ld/%ld/%ld/%d\n", a, b, c, d);
	printf("Done!\n");
	return 0;
}
