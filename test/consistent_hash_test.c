/*
 * for implementation of Consistent-Hashing
 *					-- BigBro @ 2021.02
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
#include <netinet/in.h>
#include <arpa/inet.h>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#define MAX_BIP_NUM 10

static int g_debug = 0;

/*
 * Store the available bips in an array
 * eBPF accesses bips iteratively, and selects the corresponding bip when hash(key) <hash
 * When the bip configuration is modified or the state changes, the user process is responsible for updating the array 
 */
struct backend_consistent_hash_s {
	struct {
		uint32_t bip;
		uint32_t hash;
	} bips[MAX_BIP_NUM];
	uint8_t bip_num;	
} g_all_bips;

static inline uint32_t hash_func(uint32_t value)
{
	char *v = (char *)&value;

	return ((v[2] << 24) | (v[3] << 16) | (v[0] << 8) | v[1]);
}

static int usage(void)
{
	printf("Usage: %s\n", "");
	exit(0);
}

static uint32_t get_hash_value(uint32_t value)
{
	uint32_t hash;
	struct in_addr addr;

	hash = hash_func(value);

	if (g_debug) {
		printf("===============================================\n");
		printf("value: %s/%08x, hash: %08x\n"
			, inet_ntoa(*(struct in_addr *)&value), value, hash);
	}
	return hash;
}

static int backend_info_init(void)
{
	g_all_bips.bip_num = 0;
	return 0;
}

static int add_bip(uint32_t bip)
{
	int i = 0, j = 0;
	uint32_t hash = get_hash_value(bip);

	if (g_debug) {
		printf("bip number: %d\n", g_all_bips.bip_num);
	}

	if (g_all_bips.bip_num == MAX_BIP_NUM)
		goto done;

	for (i = 0; i < g_all_bips.bip_num; i++) {
		if (hash == g_all_bips.bips[i].hash)
			goto done;
		if (hash < g_all_bips.bips[i].hash) {
			if (g_debug) {
				printf("bip: %s/%08x, hash: %08x (1)\n"
				, inet_ntoa(*(struct in_addr *)&bip), bip, hash);
			}
			break;
		}
		if (g_debug) {
			printf("bip: %s/%08x, hash: %08x (2)\n"
			, inet_ntoa(*(struct in_addr *)&g_all_bips.bips[i].bip), g_all_bips.bips[i].bip, g_all_bips.bips[i].hash);
		}
	}
	for (j = g_all_bips.bip_num - 1; j >= i; j--) {
		g_all_bips.bips[j + 1].bip = g_all_bips.bips[j].bip;
		g_all_bips.bips[j + 1].hash = g_all_bips.bips[j].hash;
	}
	g_all_bips.bips[i].bip = bip;
	g_all_bips.bips[i].hash = hash;
	g_all_bips.bip_num++;
done:
	return 0;
}

static int del_bip(uint32_t bip)
{
	int i = 0;
	uint32_t hash = get_hash_value(bip);

	if (g_all_bips.bip_num == 0)
		goto done;

	for (i = 0; i < g_all_bips.bip_num; i++) {
		if (hash == g_all_bips.bips[i].hash) {
			i++;
			break;
		}
	}
	for (; i < g_all_bips.bip_num; i++) {
		g_all_bips.bips[i - 1].bip = g_all_bips.bips[i].bip;
		g_all_bips.bips[i - 1].hash = g_all_bips.bips[i].hash;
	}
	g_all_bips.bip_num--;
done:
	return 0;
}

static int show_bip(void)
{
	int i = 0;

	printf("===============================================\n");
	printf("bip number: %d\n", g_all_bips.bip_num);
	for (i = 0; i < g_all_bips.bip_num; i++) {
		printf("bip: %s, hash: %08x\n"
			, inet_ntoa(*(struct in_addr *)&g_all_bips.bips[i].bip), g_all_bips.bips[i].hash);
	}
	return 0;
}

static int get_bip(uint32_t sip)
{
	int i;
	uint32_t sip_hash = hash_func(sip);

	for (i = 0; i < g_all_bips.bip_num; i++) {
		if (sip_hash <= g_all_bips.bips[i].hash) {
			break;
		}
	}
	if (i == g_all_bips.bip_num) {
		i = 0;
	}

	{
		char s[16] = {0}, b[16] = {0};

		snprintf(s, sizeof(s), "%s", inet_ntoa(*(struct in_addr *)&sip));
		snprintf(b, sizeof(b), "%s", inet_ntoa(*(struct in_addr *)&g_all_bips.bips[i].bip));
		printf("sip: %s, hash: %08x, bip: %s, hash: %08x\n"
			, s, sip_hash, b, g_all_bips.bips[i].hash);
	}
	return 0;
}
int main(int argc, char *argv[])
{
	int opt;
	struct in_addr sip1, sip2, sip3,  bip;

	inet_aton("4.8.2.5", &sip1);
	inet_aton("19.4.10.5", &sip2);
	inet_aton("123.34.9.108", &sip3);

	while ((opt = getopt(argc, argv, "a:b:c:Dh")) != -1) {
		switch (opt) {
		case 'a':
			if (inet_aton(optarg, &sip1) < 0) {
				printf("Invalid IP\n");
				usage();
			}
			break;
		case 'b':
			if (inet_aton(optarg, &sip2) < 0) {
				printf("Invalid IP\n");
				usage();
			}
			break;
		case 'c':
			if (inet_aton(optarg, &sip3) < 0) {
				printf("Invalid IP\n");
				usage();
			}
			break;
		case 'D':
			g_debug = 1;
			break;
		default:
		case 'h':
			usage();
			break;
		}
	}

	inet_aton("2.3.4.5", &bip);
	add_bip(bip.s_addr);
	inet_aton("8.8.8.8", &bip);
	add_bip(bip.s_addr);
	inet_aton("6.6.70.3", &bip);
	add_bip(bip.s_addr);
	inet_aton("109.23.2.90", &bip);
	add_bip(bip.s_addr);
	inet_aton("45.3.4.6", &bip);
	add_bip(bip.s_addr);
	inet_aton("22.112.2.7", &bip);
	add_bip(bip.s_addr);
	inet_aton("88.8.49.63", &bip);
	add_bip(bip.s_addr);
	show_bip();
	get_bip(sip1.s_addr);
	get_bip(sip2.s_addr);
	get_bip(sip3.s_addr);

	inet_aton("6.6.70.3", &bip);
	del_bip(bip.s_addr);
	show_bip();
	get_bip(sip1.s_addr);
	get_bip(sip2.s_addr);
	get_bip(sip3.s_addr);

	printf("Done!\n");
	return 0;
}
