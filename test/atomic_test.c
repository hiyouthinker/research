/*
 *  Test of atomic_* functions
 *			-- BigBro @ 2021.03/2021.07/2022.05
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
 * __sync_fetch_and_add/__sync_fetch_and_add_1/__sync_fetch_and_add_2 ...
 * __sync_fetch_and_sub/__sync_fetch_and_sub_1/__sync_fetch_and_sub_2 ...
 * __atomic_compare_exchange
 * __atomic_compare_exchange_n
 * __sync_bool_compare_and_swap
 * __sync_val_compare_and_swap
 * 			is defined in gcc-9.3.0/gcc/sync-builtins.def
 */

/*
* references:
	https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
	6.55 Built-in Functions for Memory Model Aware Atomic Operations

	bool __atomic_compare_exchange (type *ptr, type *expected, type *desired, bool weak, int success_memorder, int failure_memorder)

    This built-in function implements the generic version of __atomic_compare_exchange.
    The function is virtually identical to __atomic_compare_exchange_n,
    except the desired value is also a pointer.
*/
#define lock_compare_exchange(ptr, oldval, newval)	\
			__atomic_compare_exchange (ptr, &oldval, &newval, 0, 0, 0)

/*
 * references:
	https://gcc.gnu.org/onlinedocs/gcc/_005f_005fsync-Builtins.html
	6.54 Legacy __sync Built-in Functions for Atomic Memory Access

 * bool __sync_bool_compare_and_swap (type *ptr, type oldval, type newval, ...)
 * type __sync_val_compare_and_swap (type *ptr, type oldval, type newval, ...)

 * These built-in functions perform an atomic compare and swap.
 * That is, if the current value of *ptr is oldval, then write newval into *ptr.

 * The ¡°bool¡± version returns true if the comparison is successful and newval is written.
 * The ¡°val¡± version returns the contents of *ptr before the operation.
*/

/*
 * from haproxy/include/common/hathreads.h
 */
/* gcc >= 4.7 */
#define HA_ATOMIC_CAS(val, old, new)		\
		__atomic_compare_exchange_n(val, old, new, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)
#define HA_ATOMIC_XCHG(val, new)			\
		__atomic_exchange_n(val, new, __ATOMIC_SEQ_CST)

enum {
	F_XCHG = 1,
	F_XCHG_N = 2,
	F_BOOL_CAS = 4,
	F_VAL_CAS = 8,
	F_FETCH_SET = 16,
	F_FETCH_ADD = 32,
};

int main(int argc, char *argv[])
{
	int opt, flags, ret;
	long a, b, c;
	volatile int locked = 4;

	a = 1;
	b = 2;
	c = 3;
	flags = 0;

	while ((opt = getopt(argc, argv, "a:b:c:eEsStf")) != -1) {
		switch (opt) {
		case 'a':
			a = atoi(optarg);
			break;
		case 'b':
			b = atoi(optarg);
			break;
		case 'c':
			c = atoi(optarg);
			break;
		case 'e':
			flags |= F_XCHG;
			break;
		case 'E':
			flags |= F_XCHG_N;
			break;
		case 's':
			flags |= F_BOOL_CAS;
			break;
		case 'S':
			flags |= F_VAL_CAS;
			break;
		case 't':
			flags |= F_FETCH_SET;
			break;
		case 'f':
			flags |= F_FETCH_ADD;
			break;
		default:
			printf("unknown paramter\n");
			break;
		}
	}

	printf("a/b/c: %ld/%ld/%ld\n", a, b, c);

	if (flags & F_XCHG) {
		ret = lock_compare_exchange(&a, b, c);
	} else if (flags & F_XCHG_N) {
		ret = HA_ATOMIC_CAS(&a, &b, c);
	} else if (flags & F_BOOL_CAS) {
		ret = __sync_bool_compare_and_swap(&a, b, c);
	} else if (flags & F_VAL_CAS) {
		ret = __sync_val_compare_and_swap(&a, b, c);
	} else if (flags & F_FETCH_SET) {
		ret = __sync_lock_test_and_set(&locked, 2);
		__sync_lock_release(&locked);
	} else if (flags & F_FETCH_ADD) {
		ret = __sync_fetch_and_add(&a, b);
	}

	printf("a/b/c/ret: %ld/%ld/%ld/%d\n", a, b, c, ret);
	printf("locked: %d\n", locked);
	printf("Done!\n");

	return 0;
}
