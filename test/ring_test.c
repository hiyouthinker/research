/*
 * ring test
 * 		-- BigBro/2021
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

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef	__u8 uint8_t;
typedef	__u16 uint16_t;
typedef	__u32 uint32_t;
typedef unsigned long __u64;

struct my_log_s {
	uint8_t family;		/* inet4 or inet6 */
	uint8_t protocol;	/* TCP or UDP */
	uint8_t state;      /* establish or destroy */
	int index;
	__u64 time;
	union {
		struct {   /* for TCP/UDP over IPv4, len = 12 */
			uint32_t src_addr;
			uint32_t dst_addr;
			uint16_t src_port;
			uint16_t dst_port;
		} ip4;
		struct {   /* for TCP/UDP over IPv6, len = 36 */
			uint8_t  src_addr[16];
			uint8_t  dst_addr[16];
			uint16_t src_port;
			uint16_t dst_port;
		} ip6;
	} addr;
};

#define LOG_BUFF_LEN 32
#define LOG_BUFF_MASK (LOG_BUFF_LEN - 1)
#define LOG_BUFF_INDEX_MAX (LOG_BUFF_LEN * 2 - 1)
#define LOG_BUFF_INDEX_MASK LOG_BUFF_INDEX_MAX

static struct my_log_s log_buff[LOG_BUFF_LEN];

static void __init_log_buff(void)
{
	int index = 0;

	for (index = 0; index < LOG_BUFF_LEN; index++) {
		log_buff[index].index = -1;
	}
}

static struct my_log_s *__get_log_buff(int index)
{
	return &log_buff[index];
}

void *log_producer(void *arg)
{
	int index1 = 0, index2 = 0;

	while (1) {
		log_buff[index1].protocol = random() & 0xFF;
		log_buff[index1].index = index2;
		index1++;
		index2++;
		index1 = index1 & LOG_BUFF_MASK;
		index2 = index2 & LOG_BUFF_INDEX_MASK;
		sleep(1);
		write(2, ".\n", 2);
	}
}

void *log_consumer(void *arg)
{
	int index = 0, prev = -1;
	struct my_log_s *log;

	while (1) {
		log = __get_log_buff(index);
#if 0
		if (log->index == -1) {
			sleep(1000);
			continue;
		}
#endif
		if (((log->index == 0) && (prev == -1))
			|| ((log->index == 0) && (prev == LOG_BUFF_INDEX_MAX))
			|| (log->index == (prev + 1))) {
			printf("index: %d/%d, protocol: %u\n", index, log->index, log->protocol);
		} else {
			sleep(2);
			write(2, "#\n", 2);
			continue;
		}
		prev = log->index;
		index++;
		index = index & LOG_BUFF_MASK;
	}
}

int main(int argc, char *argv[])
{
	int rv;
	pthread_t thread;

	__init_log_buff();

	rv = pthread_create(&thread, NULL, log_producer, NULL);
	if (rv < 0) {
		printf("pthread_create failed!\n");
		exit(1);
	}

	rv = pthread_create(&thread, NULL, log_consumer, NULL);
	if (rv < 0) {
		printf("pthread_create failed!\n");
		exit(1);
	}
	while (1) {
		sleep(5);
	}
	printf("Done!\n");
	return 0;
}
