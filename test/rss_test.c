/*
 * BigBro @2023
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
#include <arpa/inet.h>

#define	RTE_DIM(a)	(sizeof (a) / sizeof ((a)[0]))
#define IPv4(a,b,c,d) ((uint32_t)(((a) & 0xff) << 24) | \
					   (((b) & 0xff) << 16) | \
					   (((c) & 0xff) << 8)  | \
					   ((d) & 0xff))

#define RTE_THASH_V4_L3_LEN	((sizeof(struct rte_ipv4_tuple) -	\
			sizeof(((struct rte_ipv4_tuple *)0)->sctp_tag)) / 4)

#define RTE_THASH_V4_L4_LEN	 ((sizeof(struct rte_ipv4_tuple)) / 4)

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#if 0
static inline uint32_t
rte_bsf32(uint32_t v)
{
	return (uint32_t)__builtin_ctz(v);
}
#else
static int loop;
static inline uint32_t
rte_bsf32(uint32_t v)
{
	uint32_t c = 0;

	if (!v)
		return 0;
	while (!(v & 0x01)) {
		c++;
		loop++;
		v >>= 1;
	}
	return c;
}
#endif

uint8_t default_rss_key[] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

uint8_t my_rss_key[] = {
#if 0 /* i40e/eth17 @ 73 */
	0xcc, 0x0d, 0xed, 0x90, 0xc4, 0xf8, 0x81, 0xb5,
	0xab, 0x54, 0xf5, 0x1f, 0x7a, 0x99, 0xf0, 0x0c,
	0x9e, 0xf7, 0x5d, 0x76, 0x41, 0xfa, 0x1c, 0x21,
	0x9f, 0xf7, 0x83, 0x45, 0x51, 0x97, 0x96, 0x7d,
	0xdc, 0xca, 0x81, 0x0d, 0x8d, 0x4f, 0x76, 0x81,
	0xc1, 0xaf, 0x18, 0x35, 0x9d, 0xbf, 0x06, 0x21,
	0x62, 0xf7, 0xf5, 0x2d
#else/* ixgbe/eth12 @ 74 */
	0x55, 0x90, 0x8c, 0xf3, 0x2a, 0xee, 0x52, 0x43,
	0x8c, 0xd0, 0xe1, 0x25, 0x54, 0xd6, 0xbc, 0xe3,
	0x14, 0xd4, 0xb6, 0x22, 0x52, 0x48, 0x5d, 0xe8,
	0xb7, 0x32, 0x7b, 0x69, 0x38, 0xc1, 0x76, 0xc3,
	0xd5, 0x5e, 0x51, 0x27, 0x30, 0x3f, 0xb0, 0xdd
#endif
};

struct rte_ipv4_tuple {
	uint32_t	src_addr;
	uint32_t	dst_addr;
	union {
		struct {
#if 1
			uint16_t dport;
			uint16_t sport;
#else
			uint16_t sport;
			uint16_t dport;
#endif
		};
		uint32_t        sctp_tag;
	};
};

union rte_thash_tuple {
	struct rte_ipv4_tuple	v4;
};

static inline uint32_t
rte_softrss(uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i, j, map, ret = 0;

	for (j = 0; j < input_len; j++) {
		for (map = input_tuple[j]; map;	map &= (map - 1)) {
			i = rte_bsf32(map);
			ret ^= htonl(((const uint32_t *)rss_key)[j]) << (31 - i) |
					(uint32_t)((uint64_t)(htonl(((const uint32_t *)rss_key)[j + 1])) >>
					(i + 1));
		}
	}
	return ret;
}

static inline uint32_t
rte_softrss_be(uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i, j, map, ret = 0;

	for (j = 0; j < input_len; j++) {
		for (map = input_tuple[j]; map;	map &= (map - 1)) {
			i = rte_bsf32(map);
			ret ^= ((const uint32_t *)rss_key)[j] << (31 - i) |
				(uint32_t)((uint64_t)(((const uint32_t *)rss_key)[j + 1]) >> (i + 1));
		}
	}
	return ret;
}

static inline uint32_t
rte_softrss_be_new(uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i, j, map, ret = 0;

	for (j = 0; j < input_len; j++) {
		map = input_tuple[j];
		for (i = 0; i < 32; i++) {
			if ((map & (0x01 << i)) == 0)
				continue;
			ret ^= ((const uint32_t *)rss_key)[j] << (31 - i) |
				(uint32_t)((uint64_t)(((const uint32_t *)rss_key)[j + 1]) >> (i + 1));
		}
	}
	return ret;
}

static inline uint32_t
rte_softrss_be_test(uint32_t *input_tuple, uint32_t input_len,
		const uint8_t *rss_key)
{
	uint32_t i, j, map, ret = 0;

	for (j = 0; j < input_len; j++) {
		map = input_tuple[j];
		do {
			if (!map)
				break;
			i = rte_bsf32(map);
			ret ^= ((const uint32_t *)rss_key)[j] << (31 - i) |
				(uint32_t)((uint64_t)(((const uint32_t *)rss_key)[j + 1]) >> (i + 1));
			map &= (map - 1);
		} while (1);
	}
	return ret;
}

static inline void
rte_convert_rss_key(const uint32_t *orig, uint32_t *targ, int len)
{
	int i;

	for (i = 0; i < (len >> 2); i++)
#if 0
		targ[i] = rte_be_to_cpu_32(orig[i]);
#else
		targ[i] = ntohl(orig[i]);
#endif
}

struct test_thash_v4 {
	uint32_t	dst_ip;
	uint32_t	src_ip;
	uint16_t	dst_port;
	uint16_t	src_port;
	uint32_t	hash_l3;
	uint32_t	hash_l3l4;
};

/*From 82599 Datasheet 7.1.2.8.3 RSS Verification Suite*/
struct test_thash_v4 v4_tbl[] = {
	{IPv4(161, 142, 100, 80), IPv4(66, 9, 149, 187),
		1766, 2794, 0x323e8fc2, 0x51ccc178},
	{IPv4(65, 69, 140, 83), IPv4(199, 92, 111, 2),
		4739, 14230, 0xd718262a, 0xc626b0ea},
	{IPv4(12, 22, 207, 184), IPv4(24, 19, 198, 95),
		38024, 12898, 0xd2d0a5de, 0x5c2b394a},
	{IPv4(209, 142, 163, 6), IPv4(38, 27, 205, 30),
		2217, 48228, 0x82989176, 0xafc7327f},
	{IPv4(202, 188, 127, 2), IPv4(153, 39, 163, 191),
		1303, 44251, 0x5d1809c5, 0x10e828a2},
};

static int
test_toeplitz_hash(void)
{
	uint32_t i, j;
	union rte_thash_tuple tuple;
	uint32_t rss_l3, rss_l3l4;
	uint8_t rss_key_be[RTE_DIM(my_rss_key)];

	/* Convert RSS key*/
	rte_convert_rss_key((uint32_t *)&default_rss_key,
		(uint32_t *)rss_key_be, RTE_DIM(default_rss_key));


	for (i = 0; i < RTE_DIM(v4_tbl); i++) {
		tuple.v4.src_addr = v4_tbl[i].src_ip;
		tuple.v4.dst_addr = v4_tbl[i].dst_ip;
		tuple.v4.sport = v4_tbl[i].src_port;
		tuple.v4.dport = v4_tbl[i].dst_port;
		/*Calculate hash with original key*/
		rss_l3 = rte_softrss((uint32_t *)&tuple,
				RTE_THASH_V4_L3_LEN, default_rss_key);
		rss_l3l4 = rte_softrss((uint32_t *)&tuple,
				RTE_THASH_V4_L4_LEN, default_rss_key);
		if ((rss_l3 != v4_tbl[i].hash_l3) ||
				(rss_l3l4 != v4_tbl[i].hash_l3l4)) {
			printf("%d: l3 = 0x%08x/0x%08x, l3l4 = 0x%08x/0x%08x\n"
				, i, rss_l3, v4_tbl[i].hash_l3
				, rss_l3l4, v4_tbl[i].hash_l3l4);
			return -1;
		}
		/*Calculate hash with converted key*/
		rss_l3 = rte_softrss_be_new((uint32_t *)&tuple,
				RTE_THASH_V4_L3_LEN, rss_key_be);
		rss_l3l4 = rte_softrss_be_test((uint32_t *)&tuple,
				RTE_THASH_V4_L4_LEN, rss_key_be);
		if ((rss_l3 != v4_tbl[i].hash_l3) ||
				(rss_l3l4 != v4_tbl[i].hash_l3l4)) {
			printf("%d: l3 = 0x%08x/0x%08x, l3l4 = 0x%08x/0x%08x -- with converted key\n"
				, i, rss_l3, v4_tbl[i].hash_l3
				, rss_l3l4, v4_tbl[i].hash_l3l4);
			return -1;
		}
	}
	printf("Successful!\n");
	return 0;
}

static int my_test_toeplitz_hash()
{
	union rte_thash_tuple tuple;
	uint32_t rss_l3, rss_l3l4, i;
	struct test_thash_v4 v4_tbl[] = {
		{IPv4(172, 51, 9, 76), IPv4(172, 51, 1, 200), 9000, 65534, 0, 0},
	};
	uint8_t rss_key_be[RTE_DIM(my_rss_key)];

	/* Convert RSS key*/
	rte_convert_rss_key((uint32_t *)&my_rss_key,
		(uint32_t *)rss_key_be, RTE_DIM(my_rss_key));

	for (i = 0; i < RTE_DIM(v4_tbl); i++) {
		tuple.v4.src_addr = v4_tbl[i].src_ip;
		tuple.v4.dst_addr = v4_tbl[i].dst_ip;
		tuple.v4.sport = v4_tbl[i].src_port;
		tuple.v4.dport = v4_tbl[i].dst_port;

		printf("==================================================================\n");
		rss_l3 = rte_softrss_be((uint32_t *)&tuple,
				RTE_THASH_V4_L3_LEN, rss_key_be);
		rss_l3l4 = rte_softrss_be((uint32_t *)&tuple,
				RTE_THASH_V4_L4_LEN, rss_key_be);
		printf("L3 Layer\n");
		printf("\tHash: 0x%08x, indir index: %d, cpu (queue index): %d\n"
			, rss_l3, rss_l3 % 128, (rss_l3 % 128) % 16);
		printf("L3/L4 Layer\n");
		printf("\tHash: 0x%08x, indir index: %d, cpu (queue index): %d\n"
			, rss_l3l4, rss_l3l4 % 128, (rss_l3l4 % 128) % 16);
	}
	return 0;
}

static uint32_t
rss_xor(uint32_t *input_tuple, uint32_t input_len)
{
	uint32_t result = 0;
	int i;

	for (i = input_len - 1; i >= 0; i--) {
		result ^= input_tuple[i];
	}
	return result;
}

/*
 * 172.51.9.76 -p 9000 -s 65534 -2 -c 1 -d 10 -a 172.51.1.200
 */
static void rss_xor_test(void)
{
	uint32_t hash;
	union rte_thash_tuple tuple = {};

	tuple.v4.src_addr = IPv4(172, 51, 9, 76);
	tuple.v4.dst_addr = IPv4(172, 51, 1, 200);
	tuple.v4.sport = 65534;
	tuple.v4.dport = 9000;

	hash = rss_xor((uint32_t *)&tuple, sizeof(tuple)/4);
	printf("index: %d\n", (hash % 128) % 16);
}

int main(int argc, char *argv[])
{
	test_toeplitz_hash();
	my_test_toeplitz_hash();
	rss_xor_test();

	printf("Done!\n");
	return 0;
}
