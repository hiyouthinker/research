/*
 * from https://www.andreinc.net/2022/03/01/on-implementing-bloom-filters-in-c
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#define BITS_IN_BYTE 8
#define BITS_IN_TYPE(type) (BITS_IN_BYTE * (sizeof(type)))
#define DJB2_INIT 4096 // added by bigbro

typedef unsigned int uint32_t;
typedef unsigned char uint8_t;

typedef struct bit_vect_s {
	uint32_t *mem; 
	size_t size; // The number of bits
} bit_vect;

typedef uint32_t (*hash32_func)(const void *data, size_t length);

typedef struct bloom_filter_s {
	bit_vect *vect;
	hash32_func *hash_functions;
	size_t num_functions;
	size_t num_items;
} bloom_filter;

bloom_filter *bloom_filter_new(size_t size, size_t num_functions, ...);
bloom_filter *bloom_filter_new_default(size_t size);
void bloom_filter_free(bloom_filter *filter);
void bloom_filter_put(bloom_filter *filter, const void *data, size_t length);
void bloom_filter_put_str(bloom_filter *filter, const char *str);
bool bloom_filter_test(bloom_filter *filter, const void *data, size_t lentgth);
bool bloom_filter_test_str(bloom_filter *filter, const char *str);

bit_vect *bit_vect_new(size_t num_bits) {
	bit_vect *vect = malloc(sizeof(*vect));
	if (NULL==vect) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}
	size_t mem_size = num_bits / BITS_IN_TYPE(uint32_t);
	// If num_bits is not a multiplier of BITS_IN_TYPE(uint32_t)
	// We add one more chunk that will be partial occupied
	if (!(num_bits%BITS_IN_TYPE(uint32_t))) {
		mem_size++;
	}
	vect->mem = calloc(mem_size, sizeof(*(vect->mem)));
	if (NULL==vect->mem) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}
	vect->size = num_bits;
	return vect;
}

void bit_vect_set(bit_vect *vect, size_t bit_idx, bool val) {
	if (bit_idx>=vect->size) {
		fprintf(stderr, "Out of bounds bit_idx=%zu, vect->size=%zu\n", 
							bit_idx, vect->size);
		exit(EXIT_FAILURE);
	}
	size_t chunk_offset = bit_idx /  BITS_IN_TYPE(uint32_t);
	size_t bit_offset = bit_idx & (BITS_IN_TYPE(uint32_t)-1);
	uint32_t *byte = &(vect->mem[chunk_offset]);
	if (val) {
		// Sets the the `bit_idx` to 1 (true)
		*byte |= ((uint32_t)1) << bit_offset;
	}else {
		// Sets the bit `bit_idx` to 0 (false)
		*byte &= ~(1 << bit_offset);
	}
}

/**
 * @brief Sets the bit_idx inside the vect to 1 (true)
 */
void bit_vect_set1(bit_vect *vect, size_t bit_idx) {
    bit_vect_set(vect, bit_idx, true);
}

bool bit_vect_get(bit_vect *vect, size_t bit_idx) {
    if (bit_idx>=vect->size) {
        fprintf(stderr, "Out of bounds bit_idx=%zu, vect->size=%zu\n", 
                            bit_idx, vect->size);
        exit(EXIT_FAILURE);                            
    }
    size_t chunk_offset = bit_idx / BITS_IN_TYPE(uint32_t);
    size_t bit_offset = bit_idx & (BITS_IN_TYPE(uint32_t)-1);
    uint32_t byte = vect->mem[chunk_offset];
    return (byte>>bit_offset) & 1;
}

void bit_vect_free(bit_vect *vect){
	free(vect->mem);
	free(vect);
}

bloom_filter *bloom_filter_new(size_t size, size_t num_functions, ...) {
	va_list argp;
	bloom_filter *filter = malloc(sizeof(*filter));
	if (NULL==filter) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	filter->num_items = 0;
	filter->vect = bit_vect_new(size);
	filter->num_functions = num_functions;
	filter->hash_functions = malloc(sizeof(hash32_func)*num_functions);
	if (NULL==filter->hash_functions) {
		fprintf(stderr, "Out of memory.\n");
		exit(EXIT_FAILURE);
	}

	va_start(argp, num_functions);
	for(int i = 0; i < num_functions; i++) {
		filter->hash_functions[i] = va_arg(argp, hash32_func);
	}
	va_end(argp);
	return filter;
}

uint32_t djb2(const void *buff, size_t length) {
	uint32_t hash = DJB2_INIT;
	const uint8_t *data = buff;
	for(size_t i = 0; i < length; i++) {
		 hash = ((hash << 5) + hash) + data[i]; 
	}
	return hash;
}

uint32_t sdbm(const void *buff, size_t length) {
	uint32_t hash = 0;
	const uint8_t *data = buff;
	for(size_t i = 0; i < length; i++) {
		hash = data[i] + (hash << 6) + (hash << 16) - hash;
	}
	return hash;
}

bloom_filter *bloom_filter_new_default(size_t size) {
	return bloom_filter_new(size, 2, djb2, sdbm);
}

void bloom_filter_free(bloom_filter *filter) {
	bit_vect_free(filter->vect);
	free(filter->hash_functions);
	free(filter);
}

void bloom_filter_put(bloom_filter *filter, const void *data, size_t length){
	for(int i = 0; i < filter->num_functions; i++) {
		uint32_t cur_hash = filter->hash_functions[i](data, length);
		bit_vect_set1(filter->vect, cur_hash % filter->vect->size);
	}
	// We've just added a new item, we incremenet the value
	filter->num_items++;
}

void bloom_filter_put_str(bloom_filter *filter, const char *str) {
	bloom_filter_put(filter, str, strlen(str));
}

bool bloom_filter_test(bloom_filter *filter, const void *data, size_t lentgth) {
	for(int i = 0; i < filter->num_functions; i++) {
		uint32_t cur_hash = filter->hash_functions[i](data, lentgth);
		if (!bit_vect_get(filter->vect, cur_hash % filter->vect->size)) {
			return false;
		}
	}
	return true;
}

bool bloom_filter_test_str(bloom_filter *filter, const char *str) {
	return bloom_filter_test(filter, str, strlen(str));
}

int main(int argc, char *argv[]) {
	bloom_filter *filter = bloom_filter_new_default(1024);

	bloom_filter_put_str(filter, "abc");

	printf("%d\n", bloom_filter_test_str(filter, "abc"));
	printf("%d\n", bloom_filter_test_str(filter, "bcd"));
	printf("%d\n", bloom_filter_test_str(filter, "0"));
	printf("%d\n", bloom_filter_test_str(filter, "1"));

	bloom_filter_put_str(filter, "2");

	printf("%d\n", bloom_filter_test_str(filter, "2"));

	return 0;
}
