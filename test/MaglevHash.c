/*
 * Maglev hashing (reference: katran)
 *		-- BigBro/2021.07
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long __u64;

typedef struct endpoint_s {
	__u32 num;
	__u32 weight;
	__u64 hash;
} Endpoint;

typedef struct {
	int *data;
	int size;
} int_object;

static __u32 kHashSeed0 = 0;
static __u32 kHashSeed1 = 2307;
static __u32 kHashSeed2 = 42;
static __u32 kHashSeed3 = 2718281828;
static __u32 kDefaultChRingSize = 65537;

enum HashFunction {
	Maglev,
	MaglevV2,
};

static int __erase(Endpoint *elems, int len, int pos)
{
	int i;

	for (i = 0; i < len; i++) {
		if (i >= pos) {
			elems[i] = elems[i + 1];
		}
	}	
	return 0;
}

static inline __u64 rotl64(__u64 x, __u8 r)
{
	return (x << r) | (x >> (64 - r));
}

__u64 MurmurHash3_x64_64(const __u64 A, const __u64 B, const __u32 seed)
{
	__u64 h1 = seed;
	__u64 h2 = seed;

	__u64 c1 = 0x87c37b91114253d5llu;
	__u64 c2 = 0x4cf5ad432745937fllu;

	__u64 k1 = A;
	__u64 k2 = B;

	k1 *= c1;
	k1 = rotl64(k1, 31);
	k1 *= c2;
	h1 ^= k1;

	h1 = rotl64(h1, 27);
	h1 += h2;
	h1 = h1 * 5 + 0x52dce729;

	k2 *= c2;
	k2 = rotl64(k2, 33);
	k2 *= c1;
	h2 ^= k2;

	h2 = rotl64(h2, 31);
	h2 += h1;
	h2 = h2 * 5 + 0x38495ab5;

	h1 ^= 16;
	h2 ^= 16;

	h1 += h2;
	h2 += h1;

	h1 ^= h1 >> 33;
	h1 *= 0xff51afd7ed558ccdllu;
	h1 ^= h1 >> 33;
	h1 *= 0xc4ceb9fe1a85ec53llu;
	h1 ^= h1 >> 33;

	h2 ^= h2 >> 33;
	h2 *= 0xff51afd7ed558ccdllu;
	h2 ^= h2 >> 33;
	h2 *= 0xc4ceb9fe1a85ec53llu;
	h2 ^= h2 >> 33;

	h1 += h2;

	return h1;
}

static void genMaglevPermutation(__u32 *permutation
							, Endpoint *endpoint, const __u32 pos
    						, const __u32 ring_size)
{
	__u64 offset_hash = MurmurHash3_x64_64(endpoint->hash, kHashSeed2, kHashSeed0);

	__u64 offset = offset_hash % ring_size;

	__u64 skip_hash = MurmurHash3_x64_64(endpoint->hash, kHashSeed3, kHashSeed1);

	__u64 skip = (skip_hash % (ring_size - 1)) + 1;

	permutation[2 * pos] = offset;
	permutation[2 * pos + 1] = skip;
}

static int_object 
generateHashRing(Endpoint *endpoints
					, int endpoint_size, const __u32 ring_size)
{
	int *result, i;
	__u32 runs = 0;
	__u32 *permutation, *next;
	int_object obj;

	result = calloc(ring_size, sizeof(int));
	if (!result) {
		printf("malloc failed\n");
		exit(-1);
	}

	for (i = 0; i < ring_size; i++)
		result[i] = -1;

	obj.data = result;
	obj.size = endpoint_size;

	if (endpoint_size == 0) {
		return obj;
	} else if (endpoint_size == 1) {
		for (i = 0; i < ring_size; i++)
			result[i] = endpoints[0].num;
		return obj;
	}

	permutation = calloc(endpoint_size * 2, sizeof(__u32));
	next = calloc(endpoint_size, sizeof(__u32));
	if (!permutation || !next) {
		printf("malloc failed\n");
		exit(-1);
	}

	for (int i = 0; i < endpoint_size; i++) {
		genMaglevPermutation(permutation, &endpoints[i], i, ring_size);
	}

	for (;;) {
		for (int i = 0; i < endpoint_size; i++) {
			__u32 offset = permutation[2 * i];
			__u32 skip = permutation[2 * i + 1];
			for (int j = 0; j < endpoints[i].weight; j++) {
				__u32 cur = (offset + next[i] * skip) % ring_size;
				while (result[cur] >= 0) {
					next[i] += 1;
					cur = (offset + next[i] * skip) % ring_size;
				}
				result[cur] = endpoints[i].num;
				next[i] += 1;
				runs++;
				if (runs == ring_size) {
					return obj;
				}
			}
			endpoints[i].weight = 1;
		}
	}
}

static int cmp(const void *a, const void *b)
{
	__u32 _a = *(__u32 *)a, _b = *(__u32 *)b;
	if (_a == _b)
		return 0;
	if (_a > _b)
		return 1;
	return -1;
}

int main(int argc, char *argv[])
{
	int FLAGS_nreals = 400, FLAGS_freq = 1
		, FLAGS_weight = 100, FLAGS_diffweight = 1
		, FLAGS_v2 = 0, FLAGS_npos = -1;
	int hash_func;
	int_object obj1, obj2;
	int deleted_real_num = 0;

	Endpoint endpoints[1024];
	Endpoint endpoint;
	__u32 endpoint_size;
	__u32 freq[FLAGS_nreals];
	__u32 sorted_freq[FLAGS_nreals];
	__u32 sorted_freq_size = FLAGS_nreals;
	double n1 = 0;
	double n2 = 0;
	int i;

	for (int i = 0; i < FLAGS_nreals; i++) {
		endpoint.num = i;
		endpoint.hash = 10 * i;
		if (i % FLAGS_freq == 0) {
			endpoint.weight = FLAGS_weight;
		} else {
			endpoint.weight = FLAGS_diffweight;
		}
		endpoints[i] = endpoint;
	}
	endpoint_size = FLAGS_nreals;

	hash_func = Maglev;
	if (FLAGS_v2) {
		hash_func = MaglevV2;
		printf("Not support");
	}

	obj1 = generateHashRing(endpoints, endpoint_size, kDefaultChRingSize);
	if (FLAGS_npos >= 0 && FLAGS_npos < FLAGS_nreals) {
		__erase(endpoints, endpoint_size, FLAGS_npos);		
		deleted_real_num = FLAGS_npos;
	} else {
		deleted_real_num = FLAGS_nreals - 1;
	}
	endpoint_size -= 1;
	obj2 = generateHashRing(endpoints, endpoint_size, kDefaultChRingSize);

	for (i = 0; i < obj1.size; i++) {
		freq[obj1.data[i]]++;
	}

#if 0
	for (i = 0; i < FLAGS_nreals; i++) {
		if (!(i % 50))
			printf("\n");
		printf("%02u  ", freq[i]);
	}
	printf("\n");
#endif

	memcpy(sorted_freq, freq, sizeof(sorted_freq));
	qsort(&sorted_freq[0], FLAGS_nreals, sizeof(__u32), cmp);

#if 0
	for (i = 0; i < FLAGS_nreals; i++) {
		if (!(i % 50))
			printf("\n");
		printf("%02u  ", sorted_freq[i]);
	}
	printf("\n");
#endif

	printf("min freq is %u, max freq is %u\n"
		, sorted_freq[0], sorted_freq[FLAGS_nreals - 1]);
	printf("p95 w: %u\n", sorted_freq[(sorted_freq_size / 20) * 19]);
	printf("p75 w: %u\n", sorted_freq[(sorted_freq_size / 20) * 15]);
	printf("p50 w: %u\n", sorted_freq[sorted_freq_size / 2]);
	printf("p25 w: %u\n", sorted_freq[sorted_freq_size / 4]);
	printf("p5 w: %u\n", sorted_freq[sorted_freq_size / 20]);

	for (int i = 0; i < obj1.size; i++) {
		if (obj1.data[i] != obj2.data[i]) {
			if (obj1.data[i] == deleted_real_num) {
				n1++;
				continue;
			}
			n2++;
		}
	}
	printf("changes for affected real: %lf; and for not affected %lf this is: %lf%%\n"
		, n1, n2, n2 / obj1.size * 100);

	free(obj1.data);
	free(obj2.data);
	return 0;
}
