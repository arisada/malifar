/*
MIT License
see LICENSE for more information
Copyright (c) 2024 Aris Adamantiadis
*/
/**
 * lib hap, a very fast key:value file storage
 */

#include <stdint.h>

#define BIT(x) (1<<(x))

#define HAP_VERSION 2

#define HAP_MAGIC 0x74344c704b633448

/* no more than 24 bits limit */
#define SECTION_LIMIT 0x1000000
/* no more than 2**40 entries */
#define ENTRIES_LIMIT (1LL<<40)
#define HAP_ERROR -1
#define HAP_NOT_FOUND -2
#define HAP_MAX_HASH_LEN 32

#define HAP_FLAG_SORTED BIT(0)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hap_ctx_struct *hap_ctx;

enum hap_hash_type {
    HAP_HASH_CLEARTEXT = 0,
    HAP_HASH_FAST_NSEC3,
    HAP_HASH_NSEC3,
    HAP_HASH_MAX_VALUE
};

enum hap_verbosity_level {
    HAP_VERBOSITY_NONE = 0,
    HAP_VERBOSITY_ERROR = 1,
    HAP_VERBOSITY_WARNING = 2,
    HAP_VERBOSITY_DEBUG = 3
};

hap_ctx hap_new(void);
void hap_free(hap_ctx ctx);
void hap_set_loglevel(hap_ctx ctx, enum hap_verbosity_level level);
int hap_load_list_file(hap_ctx ctx, const char *filename);
int hap_prepare_file(hap_ctx ctx, const char *filename, uint32_t value_len);
int hap_set_hash(hap_ctx ctx, enum hap_hash_type type);
enum hap_hash_type hap_get_hash(hap_ctx ctx);
void hap_sort(hap_ctx ctx);
void hap_dedup(hap_ctx ctx);
int hap_fill_file(hap_ctx ctx);
void hap_log(hap_ctx ctx, enum hap_verbosity_level, const char *fmt, ...);
int hap_load_hap_file(hap_ctx ctx, const char *filename);
void hap_dump(hap_ctx ctx);
int64_t hap_find_bisect_hash(hap_ctx ctx, const char* value);

enum hap_bisect_behaviour {
    HAP_BISECT_EXACT_MATCH,
    HAP_BISECT_FIRST_MATCH,
    HAP_BISECT_LAST_MATCH,
    HAP_BISECT_PREVIOUS_MATCH
};

int64_t hap_find_bisect_range(hap_ctx ctx, const uint8_t *key, int bits, enum hap_bisect_behaviour flags);
int64_t hap_find_bisect_range_hex(hap_ctx ctx, const char *hash, int bits, enum hap_bisect_behaviour flags);

uint64_t hap_get_entries_count(hap_ctx ctx);
const char *hap_get_entry(hap_ctx ctx, uint64_t entry);
const char *hap_get_value(hap_ctx ctx, uint64_t entry);
const char *hap_get_global_metadata(hap_ctx ctx);
int hap_set_global_metadata(hap_ctx, const char *md);
uint32_t hap_get_key_len(hap_ctx ctx);
uint32_t hap_get_value_len(hap_ctx ctx);

int hap_add_entry(hap_ctx ctx, const uint8_t *key, const uint8_t *value);
int hap_add_entry_hex(hap_ctx ctx, const char *key, const char *value);

#ifdef __cplusplus
}
#endif
