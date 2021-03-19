/*
 * for test
 *		--BigBro
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <error.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>

#define SIMPLE_OHTBL

#ifdef SIMPLE_OHTBL
#define NAME_ID_HTBL_SIZE  32	//1024
#else
#define NAME_ID_HTBL_SIZE  13	//997
#endif

#define ohtbl_lookup(htbl, data) __ohtbl_lookup(htbl, data, NULL)

static char vacated;

typedef struct
{
	uint32_t len;
	char *data;
} str_t;

typedef struct {
    uint32_t hash;
    str_t  name;
    uint16_t id;
} name_id_t;

struct ohtbl_item {
    uint32_t hash;
    uint32_t pos;
    void *data;
};

typedef struct ohtbl {
    void *vacated;

    unsigned int (*h1)(const void *key);
    unsigned int (*h2)(const void *key);
    int (*match)(const void *key1,const void *key2);
    void (*destroy)(void *data);

    unsigned int tolerance;
    unsigned int count;
    unsigned int size;
    unsigned int conflict;
    struct ohtbl_item *table;

    uint32_t *active;
} ohtbl_t;

unsigned int name_id_elem_h1(const void *__key)
{
	name_id_t *key = (name_id_t *)__key;

#ifdef SIMPLE_OHTBL
	return (key->hash);
#else
    return (key->hash % NAME_ID_HTBL_SIZE);
#endif
}
unsigned int name_id_elem_h2(const void *__key)
{
	name_id_t *key = (name_id_t *)__key;

#ifdef SIMPLE_OHTBL
	return (1 + key->hash);
#else
    return (1 + key->hash % (NAME_ID_HTBL_SIZE - 2));
#endif
}

int name_id_elem_match(const void *key1, const void *key2)
{
    name_id_t *p1 = (name_id_t *)key1;
    name_id_t *p2 = (name_id_t *)key2;

    if (p1 == NULL || p2 == NULL)
        return 0;

    return (p1 ->hash == p2->hash) &&  (p1 ->name.len == p2->name.len)
    	&& (strncmp(p1 ->name.data, p2 ->name.data, p2 ->name.len) == 0);
}

void *my_malloc(size_t size)
{
    return malloc(size);
}

void my_free(void *ptr)
{
    free(ptr);
}

uint32_t l7_shm_fnv_32a_str(char *str, uint32_t str_len, uint32_t hval)
{
    unsigned char *s = (unsigned char *)str;    /* unsigned string */
    uint32_t i = 0;

    if (s == NULL) {
        return 0;
    }

    /*
     * FNV-1a hash each octet in the buffer
     */
    while (i<str_len) {
        i++;

        /* xor the bottom with the current octet */
        hval ^= (uint32_t)*s++;

        /* #define NO_FNV_GCC_OPTIMIZATION */
        /* multiply by the 32 bit FNV magic prime mod 2^32 */
#if defined(NO_FNV_GCC_OPTIMIZATION)
        /*
         * 32 bit magic FNV-1a prime
         */
#define FNV_32_PRIME ((uint32_t)0x01000193)
        hval *= FNV_32_PRIME;
#else
        hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
#endif
    }

    /* return our new hash value */
    return hval;
}

int ohtbl_init(ohtbl_t *htbl, unsigned int size, unsigned int (*h1)(const void *elem),
                unsigned int (*h2)(const void *elem), int (*match)(const void *ohtbl_elem, const void *elem),
                void *(*alloc)(size_t), void (*destroy)(void *data), unsigned int tolerance)
{
    unsigned int i;
    unsigned int hash_size_byte, active_size_byte;

    hash_size_byte = (size + 1) * sizeof(struct ohtbl_item);
    htbl->table = (struct ohtbl_item *)alloc(hash_size_byte);
    if (htbl->table == NULL) {
        return 0;
    }
    memset(htbl->table, 0, hash_size_byte);

    active_size_byte = (size + 1) * sizeof(unsigned int);
    htbl->active = (unsigned int *)alloc(active_size_byte);
    if (htbl->active == NULL) {
        destroy(htbl->table);
        htbl->table = NULL;
        return 0;
    }
    memset(htbl->active, 0, active_size_byte);

    /* Initialize each position */
    htbl->size = size;
    for (i = 0; i < htbl->size; i++) {
        htbl->table[i].data = NULL;
    }

    /* Set the vacated member to the sentinel memory address reserved for this */
    htbl->vacated = &vacated;

    /* Encapsulate the functions */
    htbl->h1 = h1;
    htbl->h2 = h2;
    htbl->match = match;
    htbl->destroy = destroy;

    /* Initialize the number of elements in the table */
    htbl->count = htbl->conflict = 0;

    /* Initialize tolerance */
    htbl->tolerance = tolerance >= size ? (size * 0.8) : tolerance;

    return 1;
}

void *__ohtbl_lookup(ohtbl_t *htbl, const void *elem, unsigned int *ekey)
{
	unsigned int key = 0;
	unsigned int i = 0, n = 0;

	/* Use double hashing to hash the key */
	for (i = 0; i < htbl->size; i++) {
		key = (htbl->h1(elem) + i * htbl->h2(elem)) % htbl->size;
#if 0
		if (!(i % 40))
			printf("\n");

		printf("%4u ", key);
		continue;
#endif
		if (htbl->table[key].data == NULL) {
			/* Return that the elem was not found */
			if (ekey != NULL && n == 0) {
				*ekey = key;
				n++;
			}
			return NULL;
		} else if (htbl->table[key].data == htbl->vacated) {
			if (ekey != NULL && n == 0) {
				*ekey = key;
				n++;
			}
			continue;
		} else if (htbl->match(htbl->table[key].data, elem)) {
			if (ekey != NULL) {
				*ekey = key;
			}
			/* Data was found */
			return htbl->table[key].data;
		}
	}

	/* Return that the elem was not found */
	return NULL;
}

int __ohtbl_insert(ohtbl_t *htbl, void *elem)
{
    int lock_ret;
    unsigned int key = 0;

    /* Do not exceed the tolerance in the table */
    if (htbl->count == htbl->tolerance) {
        return -1;
    }

    /* Do nothing if the data is already in the table */
    if (__ohtbl_lookup(htbl, elem, &key) != NULL) {
        return 0;
    }

    /* Insert the data into the table */
    htbl->table[key].data = elem;
    htbl->table[key].hash = key;

    htbl->active[htbl->count] = key;
    htbl->count++;
    htbl->table[key].pos = htbl->count;

    if (key != htbl->h1(elem) % htbl->size) {
        htbl->conflict++;
    }

    return 1;
}

int ohtbl_insert(ohtbl_t *htbl, char *name)
{
	name_id_t element;
	uint32_t hash;

	element.id = 0x12;
	element.name.data = name;
	element.name.len = strlen(name);
	hash = l7_shm_fnv_32a_str(element.name.data, element.name.len, 0);
	element.hash = hash;
	__ohtbl_insert(htbl, &element);
}

name_id_t *find_name_id(struct ohtbl *htabl, char *name)
{
    name_id_t elem, *ret=NULL;
    uint32_t hash=0;

    elem.name.data = name;
    elem.name.len = strlen(name);
    elem.hash = l7_shm_fnv_32a_str(elem.name.data, elem.name.len, 0);
    return (name_id_t *)ohtbl_lookup(htabl, &elem);
}

int main(int argc, char *argv[])
{
	ohtbl_t htbl;
	char *insert = "wertyu", *find = "wertyu";
	name_id_t *name_id;

	if (argc > 1)
		insert = argv[1];
	if (argc > 2)
		find = argv[2];

	ohtbl_init(&htbl, NAME_ID_HTBL_SIZE, name_id_elem_h1, name_id_elem_h2
		, name_id_elem_match, my_malloc, my_free, NAME_ID_HTBL_SIZE*0.8);

	ohtbl_insert(&htbl, insert);

	name_id = find_name_id(&htbl, find);
	if (name_id)
		printf("%s, conflict: %u\n", name_id->name.data, htbl.conflict);
	else
		printf("NULL\n");

	printf("Done!\n");
	return 0;
}
