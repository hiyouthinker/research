/*
 * BigBro for calculation of map memory @ 2021.01 - 2024
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <error.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>

#include <linux/log2.h>

#if 0
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE, MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif
#endif

#define __aligned(x) __attribute__((aligned(x)))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y)) + 1)

#define U32_MAX ((u32)~0U)

#define BUCKET_SIZE    16 /* sizeof(struct bucket) */
#define HTAB_ELEM_SIZE sizeof(struct htab_elem) /* 48 bytes */
#define MAP_LIMIT      (U32_MAX / BUCKET_SIZE)

#if 0
struct bucket {
	struct hlist_nulls_head head;
	union {
		raw_spinlock_t raw_lock;
		spinlock_t     lock;
	};
};
#endif

#if 0
struct list_head {
	struct list_head *next, *prev;
};
#endif

struct hlist_nulls_node {
	struct hlist_nulls_node *next, **pprev;
};

struct bpf_htab;

struct pcpu_freelist_node {
	struct pcpu_freelist_node *next;
};

struct callback_head {
	struct callback_head *next;
	void (*func)(struct callback_head *head);
} __attribute__((aligned(sizeof(void *))));
#define rcu_head callback_head

struct bpf_lru_node {
	struct list_head list;
	unsigned short cpu;
	unsigned char type;
	unsigned char ref;
};

struct htab_elem {
	union {
		struct hlist_nulls_node hash_node;
		struct {
			void *padding;
			union {
				struct bpf_htab *htab;
				struct pcpu_freelist_node fnode;
			};
		};
	};
	union {
		struct rcu_head rcu;
		struct bpf_lru_node lru_node;
	};
	unsigned int hash;
	char key[0] __attribute__((aligned(8)));
};

struct work_struct {
	int data;
	struct list_head entry;
	void *func;
};

struct bpf_map {
	void *ops;
	void *inner_map_meta;
	int map_type;
	int key_size;
	int value_size;
	int max_entries;
	int map_flags;
	int pages;
	int id;
	int numa_node;
	int unpriv_array;
	/* 7 bytes hole */
	void *user;
	int refcnt;
	int usercnt;
	struct work_struct work;
	char name[16];
};

struct lpm_trie {
	struct bpf_map map;
	struct lpm_trie_node *root;
	size_t n_entries;
	size_t max_prefixlen;
	size_t data_size;
	int lock;
};

struct lpm_trie_node {
	struct rcu_head rcu;
	struct lpm_trie_node *child[2];
	int prefixlen;
	int flags;
	char data[0];
};

struct bpf_lpm_trie_key {
	int prefixlen; /* up to 32 for AF_INET, 128 for AF_INET6 */
	char data[0];  /* Arbitrary size */
};

struct bpf_array {
	struct bpf_map map;
	unsigned int elem_size;
	unsigned int index_mask;
	/* 'ownership' of prog_array is claimed by the first program that
	 * is going to use this map or by the first program which FD is stored
	 * in the map to make sure that all callers and callees have the same
	 * prog_type and JITed flag
	 */
#if 0
	enum bpf_prog_type owner_prog_type;
	bool owner_jited;
#else
	int owner_prog_type;
	int owner_jited;
#endif
	union {
		char value[0] __aligned(8);
		void *ptrs[0] __aligned(8);
#if 0
		void __percpu *pptrs[0] __aligned(8);
#else
		void *pptrs[0] __aligned(8);
#endif
	};
};

struct param_st {
	int type;
	int key_size, value_size;
	long max_entries, used;
	long elem_size, total_size;
	long n_buckets1, n_buckets2;
	int percpu, cpu_num;
};

enum {
	MAP_TYPE_HASH,
	MAP_TYPE_ARRAY,
	MAP_TYPE_LPM,
};

static char *type2name(int type)
{
	switch (type) {
	case MAP_TYPE_HASH:
		return "hash";
	case MAP_TYPE_ARRAY:
		return "array";
	case MAP_TYPE_LPM:
		return "lpm";
	default:
		return "unkown";
	}
}

static int usage(void)
{
	printf("Usage: %s\n", "");
	exit(0);
}

void key_value_size_adjust(struct param_st *param)
{
	switch (param->type) {
	case MAP_TYPE_ARRAY:
		param->key_size = 0; /* don't alloc memory */
		param->elem_size = round_up(param->value_size, 8);
		break;
	case MAP_TYPE_HASH:
		param->key_size = round_up(param->key_size, 8);
		param->value_size = round_up(param->value_size, 8);

		param->elem_size = HTAB_ELEM_SIZE + param->key_size;
		if (param->percpu)
			param->elem_size += sizeof(void *);
		else
			param->elem_size += param->value_size;
		break;
	default: {/* lpm_trie */
		int data_size = param->key_size - offsetof(struct bpf_lpm_trie_key, data);

		param->elem_size = sizeof(struct lpm_trie_node) + data_size;
		param->elem_size += param->value_size;
		break;
	}
	}
}

void total_size_calc(struct param_st *param, int max_entries, int print)
{
	int total_size, n_buckets;

	switch (param->type) {
	case MAP_TYPE_ARRAY:
		param->total_size = sizeof(struct bpf_array);
		if (param->percpu)
			param->total_size += max_entries * sizeof(void *) + max_entries * param->elem_size * param->cpu_num;
		else
			param->total_size += max_entries * param->elem_size;
		break;
	case MAP_TYPE_HASH:
		param->n_buckets1 = roundup_pow_of_two(max_entries);

		param->total_size = BUCKET_SIZE * param->n_buckets1 + param->elem_size * param->used;

		if (param->percpu)
			param->total_size += (unsigned long)param->value_size * param->cpu_num * param->used;

		param->n_buckets2 = roundup_pow_of_two(max_entries + 1);
		break;
	default:
		param->total_size = sizeof(struct lpm_trie) + param->max_entries * param->elem_size;
		break;
	}

	if (!print)
		return;

	printf("%s map\n"
		"\t%-11s: %d\n"
		"\t%-11s: %d\n"
		"\t%-11s: %ld\n"
		"\t%-11s: %ld\n"
		"\t%-11s: %d\n"
		"\t%-11s: %d\n"
		"\t%-11s: %d\n"
		"\t%-11s: %ld\n",
		type2name(param->type),
		"key size", param->key_size,
		"value size", param->value_size,
		"max_entries", param->max_entries,
		"buckets", param->n_buckets1,
		"full", param->max_entries == param->used ? 1 : 0,
		"percpu", param->percpu,
		"cpu_num", param->cpu_num,
		"total size", param->total_size);
}

/*
 * gcc map_memory_calc.c -o map_memory_calc -I ~/Code/Research/linux-5.15.15/tools/include
 */
int main(int argc, char *argv[])
{
	int opt, full, fail = false;
	unsigned long num = 1024 * 1024;

	struct param_st param = {
		.type = MAP_TYPE_HASH,
		.key_size = 4,
		.value_size = 256,
		.cpu_num = 20,
	};

	while ((opt = getopt(argc, argv, "k:v:e:c:u:aptfh")) != -1) {
		switch (opt) {
		case 'k':
			param.key_size = atoi(optarg);
			if (param.key_size <= 0)
				usage();
			break;
		case 'v':
			param.value_size = atoi(optarg);
			if (param.value_size < 0)
				usage();
			break;
		case 'e':
			param.max_entries = atoi(optarg);
			if (param.max_entries <= 0)
				usage();
			break;
		case 'c':
			param.cpu_num = atoi(optarg);
			if (param.cpu_num <= 0)
				usage();
			break;
		case 'u':
			param.used = atoi(optarg);
			if (param.used <= 0)
				usage();
			break;
		case 'a':
			param.type = MAP_TYPE_ARRAY;
			break;
		case 'p':
			param.percpu = 1;
			break;
		case 't':
			param.type = MAP_TYPE_LPM;
			break;
		case 'f':
			full = 1;
			break;
		default:
		case 'h':
			usage();
			break;
		}
	}

	key_value_size_adjust(&param);

	if (param.max_entries) {
		if (full) {
			param.used = param.max_entries;
		}
		total_size_calc(&param, param.max_entries, 1);

		return 0;
	}

	if (param.type != MAP_TYPE_HASH)
		goto done;

	while (1) {
		param.used = num;

		total_size_calc(&param, param.used, 0);

		if (param.n_buckets1 > MAP_LIMIT) {
			fail = 1;
			num /= 2;
		} else if ((param.n_buckets1 <= MAP_LIMIT) && (param.n_buckets2 > MAP_LIMIT)) {
			printf("The size of key: %d, size of value: %d for %s\n", param.key_size, param.value_size, type2name(param.type));
			printf("The max entries number: %ld, size: %ld, limit: %u\n", param.n_buckets1, param.total_size, MAP_LIMIT);
			break;
		}

		if (fail)
			num++;
		else
			num *= 2;
	}

done:
	printf("Done!\n");
	return 0;
}
