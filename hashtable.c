#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

// https://gcc.gnu.org/onlinedocs/gcc/Typeof.html
#define max(a, b) ({ \
  __auto_type lhs = (a); \
	__auto_type rhs = (b); \
	lhs > rhs ? lhs : rhs; \
})

#define min(a, b) ({ \
  __auto_type lhs = (a); \
	__auto_type rhs = (b); \
	lhs < rhs ? lhs : rhs; \
})

#define rotl(x, left) ({ \
  __auto_type right = (sizeof(x) - (left)); \
	__auto_type bits = (x); \
  (bits << left) | (bits >> right); \
})

typedef struct string_s {
	uint64_t len;
	char *data;
} string_t;

typedef struct sip_s {
	uint64_t v0;
	uint64_t v1;
	uint64_t v2;
	uint64_t v3;
} sip_t;

sip_t sipround(sip_t in) {
	sip_t res = in;

	res.v0 += res.v1;
	res.v1 = rotl(res.v1, UINT64_C(13));
	res.v1 ^= res.v0;
	res.v0 = rotl(res.v0, UINT64_C(32));
	res.v2 += res.v3;
	res.v3 = rotl(res.v3, UINT64_C(16));
	res.v3 ^= res.v2;
	res.v0 += res.v3;
	res.v3 = rotl(res.v3, UINT64_C(21));
	res.v3 ^= res.v0;
	res.v2 += res.v1;
	res.v1 = rotl(res.v1, UINT64_C(17));
	res.v1 ^= res.v2;
	res.v2 = rotl(res.v2, UINT64_C(32));

	return res;
}

// https://commandcenter.blogspot.com/2012/04/byte-order-fallacy.html
uint64_t u8_as_64le(const char *data, const char *end) {

	uint64_t res = 0;
	uint64_t shift = 0;
	uint64_t max = min(end - data, sizeof res);

	for (uint64_t i = 0; i < max; i++) {
		uint64_t byte = data[i];
		res |= byte << shift;
		shift += CHAR_BIT;
	}
	return res;
}

// https://en.wikipedia.org/wiki/SipHash
uint64_t siphash64(const string_t str) {

	sip_t s = {
		.v0 = UINT64_C(0x736f6d6570736575),
		.v1 = UINT64_C(0x646f72616e646f6d),
		.v2 = UINT64_C(0x6c7967656e657261),
		.v3 = UINT64_C(0x7465646279746573),
	};

  const char *data = str.data;
  const char *end = str.data + str.len;
	uint64_t datum = 0;
  uint64_t max = str.len / sizeof datum;

	for (uint64_t i = 0; i < max; i++) {
		datum = u8_as_64le(data, end);
		s.v3 ^= datum;
		s = sipround(s);
		s = sipround(s);
		s.v0 ^= datum;
		data += sizeof datum;
	}
	datum = str.len << (CHAR_BIT * (sizeof datum - 1));
	datum |= u8_as_64le(data, end);
	s.v3 ^= datum;
	s = sipround(s);
	s = sipround(s);
	s.v0 ^= datum;

	s.v2 ^= UINT64_C(0xff);
  s = sipround(s);
  s = sipround(s);
  s = sipround(s);
  s = sipround(s);

	return s.v0 | s.v1 | s.v2 | s.v3;
}

typedef struct hashtable_entry_s {
	uint64_t count;
	uint64_t hash;
	uint64_t len;
	char *data;
} hashtable_entry_t;

typedef struct hashtable_s {
	uint64_t count;
	uint64_t size;
	uint64_t datum_size;
	char *data;
} hashtable_t;

uint64_t hashtable_calc_new_size(hashtable_t *ht, uint64_t desired) {

	uint64_t atleast = ht->count * ht->count * ht->datum_size;
	uint64_t target = max(atleast, desired);
	uint64_t size = 2;

	while (size < target) {
		size *= 2;
	}
	return size;
}

void debug_print_mem(hashtable_t *ht, uint64_t key, uint64_t indent_level) {
	while (indent_level--) printf("\t");
	printf("bytes at key = %lu: 0x", key);
	for (uint64_t i = 0; i < ht->datum_size; i++) {
		uint8_t value = ht->data[key + i];
		if (i < 16 || value > 0) {
	    printf("%.2x", value);
		}
	}
	printf("\n");
}

void hashtable_resize(hashtable_t *ht, uint64_t desired_size) {

  printf("hashtable resize\n");
	uint64_t new_size = hashtable_calc_new_size(ht, desired_size);
	uint64_t new_mod = (new_size / ht->datum_size);
  uint64_t old_size = ht->size;
	ht->size = new_size;
	printf("\told size = %lu, new size = %lu\n", old_size, new_size);
  ht->data = realloc(ht->data, new_size);
	memset(&ht->data[old_size], 0, new_size - old_size);

	char *buf = malloc(ht->datum_size);
  for (uint64_t old_key = 0; old_key < old_size; old_key += ht->datum_size) {
		if (ht->data[old_key] != 0) {
			memcpy(buf, &ht->data[old_key], ht->datum_size);

			uint64_t offset = 0;
			uint64_t count = ht->data[old_key + offset];
			offset += sizeof count;
			uint64_t hash = ht->data[old_key + offset];
			offset += sizeof hash;
      char *value = &ht->data[old_key + offset];

			uint64_t new_key = (hash % new_mod) * ht->datum_size;
			uint64_t orig_key = new_key;
			printf("\t\tstr = %s\n", value);
			printf("\t\told key = %lu\n", old_key);
			printf("\t\tnew key = %lu\n", new_key);

      value = &ht->data[new_key + offset];
	    bool empty = (*value == '\0');

	    while (!empty) {
	    	new_key = (new_key + ht->datum_size) % new_size;
	    	if (new_key == orig_key) return;
	    	value = &ht->data[new_key + offset];
	      empty = (*value == '\0');
	    }
			memcpy(&ht->data[new_key], buf, ht->datum_size);
			memset(&ht->data[old_key], 0, ht->datum_size);
			debug_print_mem(ht, new_key, 2);
		}
	}
	free(buf);
}

void hashtable_update_entry(hashtable_t *ht, uint64_t key, uint64_t count) {

	printf("hashtable update entry\n");
	memcpy(&ht->data[key], &count, sizeof count);
  debug_print_mem(ht, key, 1);
}

void hashtable_new_entry(hashtable_t *ht, uint64_t hash, uint64_t key, uint64_t count, string_t str) {

	printf("hashtable new entry\n");

	ht->count++;
  uint64_t offset = 0;

	memcpy(&ht->data[key + offset], &count, sizeof count);
	offset += sizeof count;
	memcpy(&ht->data[key + offset], &hash, sizeof hash);
	offset += sizeof hash;
	memcpy(&ht->data[key + offset], str.data, str.len);
	offset += str.len;
	memset(&ht->data[key + offset], 0, ht->datum_size - offset);

	debug_print_mem(ht, key, 1);
}

bool hashtable_add(hashtable_t *ht, string_t str) {

	printf("hashtable add\n");
	printf("\tstr = %s\n", str.data);

	if (ht == NULL || str.data == NULL) return false;
	if (ht->count * ht->count > ht->size) hashtable_resize(ht, ht->size * 2);

	uint64_t hash = siphash64(str);
	uint64_t mod = (ht->size / ht->datum_size);
	uint64_t key = (hash % mod) * ht->datum_size;
	uint64_t orig_key = key;
	uint64_t count = u8_as_64le(&ht->data[key], &ht->data[ht->size]);
	printf("\thash = %lu, orig_key = %lu, count = %lu\n", hash, orig_key, count);

  uint64_t offset = sizeof count + sizeof hash;
	char *value = &ht->data[key + offset];
	bool match = (strcmp(str.data, value) == 0);
	bool empty = (*value == '\0');

	while (!match && !empty) {
		key = (key + ht->datum_size) % ht->size;
		if (key == orig_key) return false;
		value = &ht->data[key + offset];
	  match = (strcmp(str.data, value) == 0);
	  empty = (*value == '\0');
	}

	if (match) {
		hashtable_update_entry(ht, key, count + 1);
	}
	if (empty) {
	  hashtable_new_entry(ht, hash, key, 1, str);
	}
	return true;
}

uint64_t hashtable_query(hashtable_t *ht, string_t str) {

	printf("hashtable query\n");
	if (ht == NULL || str.data == NULL) return 0;

	uint64_t hash = siphash64(str);
	uint64_t mod = (ht->size / ht->datum_size);
	uint64_t key = (hash % mod) * ht->datum_size;
	uint64_t orig_key = key; 
	uint64_t count = u8_as_64le(&ht->data[key], &ht->data[ht->size]);

  uint64_t offset = sizeof count + sizeof hash;
	char *value = &ht->data[key + offset];
	bool match = (strcmp(str.data, value) == 0);
	bool empty = (*value == '\0');

	while (!match && !empty) {
		key = (key + ht->datum_size) % ht->size;
		if (key == orig_key) return -1;
		value = &ht->data[key + offset];
	  match = (strcmp(str.data, value) == 0);
	  empty = (*value == '\0');
	}

	count = u8_as_64le(&ht->data[key], &ht->data[ht->size]);
	printf("\tcount for %s = %lu\n", str.data, count);

  return count;
}

int main(int argc, char **argv) {

	printf("hashtable init\n");
  hashtable_t ht = {0};
	ht.datum_size = 256;
	printf("\thashtable datum size = %lu\n", ht.datum_size);
	hashtable_resize(&ht, 4096);

	for (uint64_t i = 1; i < argc; i++) {
		string_t str = {.data = argv[i], .len = strnlen(argv[i], 256 - 16)};
		hashtable_add(&ht, str);
	}
	hashtable_resize(&ht, ht.size * 2);

	for (uint64_t i = 1; i < argc; i++) {
		string_t str = {.data = argv[i], .len = strnlen(argv[i], 256 - 16)};
		hashtable_query(&ht, str);
	}
	free(ht.data);

  return 0;
}
