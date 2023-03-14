#ifndef __COMMON_H
#define __COMMON_H

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
#define NIPQUAD_FMT "%u.%u.%u.%u"

#define PRINT_EMERG  0
#define PRINT_NOTICE 1
#define PRINT_INFO   2
#define PRINT_DEBUG  3

static int debug_level = PRINT_EMERG;

#define debug_print(my_level, x...)	do {\
		if (debug_level >= my_level)\
			printf(x);\
	} while(0)

#endif