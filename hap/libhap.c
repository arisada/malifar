/*
MIT License
see LICENSE for more information
Copyright (c) 2024 Aris Adamantiadis
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
#include <openssl/evp.h>

#include "libhap.h"

struct hap_ctx_struct {
    FILE *input;
    uint64_t input_entries;
    uint64_t allocated_entries;
    int fd;
    void *file_map;
    size_t file_mapped_len;
    struct hap_header_struct *header;
    struct hap_section_struct *sections;
    const struct hap_hash_info_struct *hash;
    void *entries;
    char *string_buffer;
    size_t string_buffer_size;
    enum hap_verbosity_level loglevel;
};

union hap_pointer_union {
    void *ptr;
    uint64_t offset;
};

struct hap_header_struct {
    uint64_t magic; /* Magic number */
    uint32_t version; /* Revision number of this header */
    uint8_t flags; /* File content flags */
    uint8_t entry_key_hash; /* hash format */
    uint8_t padding[6];
    uint64_t total_entries; /* How many entries in whole sections */
    uint32_t num_sections; /* amount of sections. Power of two */
    uint32_t entry_key_len; /* size of a key, e.g. 20 for SHA1 */
    uint32_t entry_value_len; /* size of value, may be zero */
    char global_metadata[128]; /* global metadata for this file */
} __attribute__((packed));

struct hap_section_struct {
    uint64_t offset; /* offset to first entry of that section. Not in bytes. 
                      * Each entry is key_len + value_len bytes long */
    uint64_t entries; /* how many entries in that section */
} __attribute__((packed));

/* Hash-related functions */
typedef void (*hash_fct) (hap_ctx, uint8_t *out, const char *data);

//static void hash_sha1(hap_ctx, uint8_t *out, const char *data);
static int hap_from_hex(uint8_t *dest, size_t len, const char *src);

#define ENTRY_KEY_LEN ctx->header->entry_key_len
#define ENTRY_VALUE_LEN ctx->header->entry_value_len
#define entry_len (ENTRY_KEY_LEN + ENTRY_VALUE_LEN)
#define ENTRY_KEY(i) ((uint8_t *)ctx->entries + (i) * entry_len)
#define ENTRY_VALUE(i) ((uint8_t *)ctx->entries + (i) * entry_len + \
                        ENTRY_KEY_LEN)
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static struct hap_hash_info_struct {
    size_t hash_len;
    const char *hash_name;
    enum hap_hash_type type;
    hash_fct do_hash;
} hap_hash_info[] = {
    {
        .hash_len = 16,
        .hash_name = "cleartext",
        .type = HAP_HASH_CLEARTEXT
    },
    {
        .hash_len = 8,
        .hash_name = "fastnsec3",
        .type = HAP_HASH_FAST_NSEC3
    },
    {
        .hash_len = 20,
        .hash_name = "nsec3",
        .type = HAP_HASH_NSEC3
        //.do_hash = hash_nsec3
    },
};

static int unmap_file(hap_ctx ctx);

hap_ctx hap_new(void){
    hap_ctx ctx = calloc(1, sizeof(struct hap_ctx_struct));
    ctx->loglevel = HAP_VERBOSITY_WARNING;
    return ctx;
}

void hap_free(hap_ctx ctx){
    if (ctx->input != NULL){
        fclose(ctx->input);
    }
    if (ctx->string_buffer){
        free(ctx->string_buffer);
    }
    unmap_file(ctx);
    free(ctx);
}

void hap_set_loglevel(hap_ctx ctx, enum hap_verbosity_level level){
    ctx->loglevel = level;
}

static void hap_init(){
    static volatile int inited = 0;
    if (!inited){
        inited = 1;
        OpenSSL_add_all_digests();
    }
}

int hap_load_list_file(hap_ctx ctx, const char *filename){
    FILE *f = fopen(filename, "r");
    char buffer[1024];
    uint64_t lines = 0;
    (void) ctx;
    if (f == NULL){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error opening %s: %s", filename, strerror(errno));
        return -1;
    }
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Estimating number of entries in %s", filename);
    while(fgets(buffer, sizeof(buffer), f) != NULL){
        lines += 1;
    }
    fseek(f, 0, SEEK_SET);
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "%d (0x%x) entries found", lines, lines);
    ctx->input = f;
    ctx->input_entries = lines;
    return 0;
}

static int map_file(hap_ctx ctx, int fd, size_t size, int writeenabled) {
    void *ptr = mmap(
        NULL,
        size,
        PROT_READ | (writeenabled ? PROT_WRITE:0),
        MAP_FILE | MAP_SHARED,
        fd,
        0);
    if (ptr == MAP_FAILED){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error mapping file %s", strerror(errno));
        return -1;
    }
    ctx->fd = fd;
    ctx->file_map = ptr;
    ctx->file_mapped_len = size;
    return 0;
}

static int unmap_file(hap_ctx ctx){
    if(ctx->file_map != NULL){
        close(ctx->fd);
        int rc = munmap(ctx->file_map, ctx->file_mapped_len);
        ctx->file_map=NULL;
        ctx->file_mapped_len=0;
        return rc;
    }
    return 0;
}

static int hap_resize(hap_ctx ctx){
    int rc;
    size_t allocated = ctx->file_mapped_len;
    size_t new_len = ((ctx->header->total_entries * entry_len) * 132) /128;
    size_t new_len2 = (ctx->header->total_entries + 65536) * entry_len;
    uint32_t sections = ctx->header->num_sections;
    void *ptr;
    size_t file_size = sizeof(struct hap_header_struct);    
    file_size += sizeof(struct hap_section_struct) * sections;
    file_size += MAX(new_len, new_len2);
    assert(file_size > allocated);
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Resizing: before %x after %x", allocated, file_size);
    rc = ftruncate(ctx->fd, file_size);
    if (rc != 0){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error extending file: %s", strerror(errno));
        return -1;
    }
    rc = munmap(ctx->file_map, ctx->file_mapped_len);
    if (rc != 0){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "munmap: %s", strerror(errno));
        return -1;
    }
    rc = map_file(ctx, ctx->fd, file_size, 1);
    if (rc != 0){
        return rc;
    }
    ctx->header = ctx->file_map;
    ctx->sections = ctx->file_map + sizeof(struct hap_header_struct);
    ctx->entries = ctx->file_map + \
        sizeof(struct hap_header_struct) + \
        sizeof(struct hap_section_struct) * sections;
}

int hap_set_hash(hap_ctx ctx, enum hap_hash_type type){
    if (type > HAP_HASH_MAX_VALUE){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Invalid hash type %d", type);
        return -1;
    }
    ctx->hash = &hap_hash_info[type];
    return 0;
}

enum hap_hash_type hap_get_hash(hap_ctx ctx){
    return ctx->hash->type;
}

int hap_prepare_file(hap_ctx ctx, const char *filename, uint32_t value_len){
    size_t file_size;
    int fd;
    int rc;
    uint32_t key_len;
    /* don't bother with sections */
    int sections = 1;

    if (sections > SECTION_LIMIT){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Sections limit is 0x%x", SECTION_LIMIT);
        return -1;
    }
    if (ctx->hash == NULL){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error: hash type hasn't been set");
        return -1;
    }
    key_len = ctx->hash->hash_len;
    fd = open(filename, O_RDWR | O_CREAT | O_EXCL, 0644);
    if (fd < 0){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error opening %s: %s", filename, strerror(errno));
        return -1;
    }
    file_size = sizeof(struct hap_header_struct);
    file_size += sizeof(struct hap_section_struct) * sections;
    file_size += (key_len + value_len) * ctx->input_entries;
    ctx->allocated_entries = ctx->input_entries;
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Preparing a hap file of %d bytes", file_size);
    rc = ftruncate(fd, file_size);
    if (rc != 0){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error extending file %s: %s", filename, strerror(errno));
        return -1;
    }
    rc = map_file(ctx, fd, file_size, 1);
    if (rc != 0){
        return 1;
    }
    ctx->header = ctx->file_map;
    ctx->sections = ctx->file_map + sizeof(struct hap_header_struct);
    ctx->entries = ctx->file_map + \
        sizeof(struct hap_header_struct) + \
        sizeof(struct hap_section_struct) * sections;
    /* fill global header */
    ctx->header->magic = HAP_MAGIC;
    ctx->header->version = HAP_VERSION;
    ctx->header->flags = HAP_FLAG_SORTED;
    ctx->header->entry_key_hash = ctx->hash->type;
    ctx->header->total_entries = ctx->input_entries;
    ctx->header->num_sections = sections;
    ctx->header->entry_key_len = key_len;
    ctx->header->entry_value_len = value_len;
    strcpy(ctx->header->global_metadata, "Random file data");

    return 0;
}

#define MAX_SECT 0x100000000

static int hap_getsection(int nsections, const uint8_t *hash){
    int bits;
    uint64_t mask;
    uint32_t value;
    for (bits=0; (1<< (bits)) <= nsections; ++bits)
        ;
    mask = MAX_SECT - (MAX_SECT >> (bits-1));
    value = hash[3] | (hash[2] << 8) | (hash[1] << 16) | (hash[0] << 24);

    return (value & mask) >> (32 - bits + 1);
}

int hap_fill_file(hap_ctx ctx){
    char buffer[1024];
    uint64_t i, j;
    uint8_t *key_ptr;
    char *ptr;
    int section;

    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Hashing %d entries", ctx->input_entries);
    hap_init();

    for(i=0; i<ctx->input_entries; ++i){
        if(fgets(buffer, sizeof(buffer), ctx->input) == NULL){
            hap_log(ctx, HAP_VERBOSITY_ERROR, "Unexpected EOF in input file. Did it change while busy?");
            return -1;
        }
        buffer[sizeof(buffer)-1] = '\0';
        ptr = strchr(buffer, '\r');
        if (ptr != NULL){
            *ptr = '\0';
        }
        ptr = strchr(buffer, '\n');
        if (ptr != NULL){
            *ptr = '\0';
        }
        key_ptr = ENTRY_KEY(i);
        ctx->hash->do_hash(ctx, key_ptr, buffer);
    }
    hap_sort(ctx);
    return 0;
}

int hap_add_entry(hap_ctx ctx, const uint8_t *key, const uint8_t *value){
    uint64_t idx;
    uint8_t *hash_ptr;
    char *ptr;
    int section;

    idx = ctx->header->total_entries;
    if ((void *)ENTRY_KEY(idx+1) > ctx->file_map + ctx->file_mapped_len){
        hap_log(ctx, HAP_VERBOSITY_WARNING, "File too short, extending");
        hap_resize(ctx);
    }
    memcpy(ENTRY_KEY(idx), key, ENTRY_KEY_LEN);
    memcpy(ENTRY_VALUE(idx), value, ENTRY_VALUE_LEN);
    ctx->header->total_entries++;
    ctx->header->flags &= ~HAP_FLAG_SORTED;
    return 0;
}

int hap_add_entry_hex(hap_ctx ctx, const char *key, const char *value){
    uint8_t key_buffer[ENTRY_KEY_LEN];
    uint8_t value_buffer[ENTRY_VALUE_LEN];
    int rc;
    rc = hap_from_hex(key_buffer, ENTRY_KEY_LEN, key);
    if (rc != 0)
        return rc;
    rc = hap_from_hex(value_buffer, ENTRY_VALUE_LEN, value);
    if (rc != 0)
        return rc;
    return hap_add_entry(ctx, key_buffer, value_buffer);
}

uint64_t hap_get_entries_count(hap_ctx ctx){
    return ctx->header->total_entries;
}

static int compare_hash_8(const void *a, const void *b){
    return memcmp(a, b, 8);
}

static int compare_hash_20(const void *a, const void *b){
    return memcmp(a, b, 20); /* SHA1 */
}

static int update_sections(hap_ctx ctx){
    int i,j;
    uint8_t *key_ptr;
    uint32_t section;

    for (i=0; i<ctx->header->num_sections; ++i){
        ctx->sections[i].entries=0;
    }

    for (i=0; i<ctx->header->total_entries; ++i){
        key_ptr = ENTRY_KEY(i);
        section = hap_getsection(ctx->header->num_sections, key_ptr);
        //hap_log("hash %.2x%.2x%.2x%.2x in section %x", hash_ptr[0], hash_ptr[1], hash_ptr[2], hash_ptr[3], section);
        ctx->sections[section].entries += 1;
    }
    /* Update session table */
    for (i=0, j=0; i<ctx->header->num_sections; ++i){
        ctx->sections[i].offset = j;
        j += ctx->sections[i].entries;
    }
}

void hap_sort(hap_ctx ctx){
    uint8_t *entries;

    if (ctx->header->flags & HAP_FLAG_SORTED){
        hap_log(ctx, HAP_VERBOSITY_WARNING, "Already sorted");
        return;
    }
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Sorting entries...");
    entries = (uint8_t *)ctx->entries;
    switch(ENTRY_KEY_LEN){
    case 8:
        qsort(entries, ctx->header->total_entries, entry_len, compare_hash_8);
        break;
    case 20:
        qsort(entries, ctx->header->total_entries, entry_len, compare_hash_20);
        break;
    default:
        hap_log(ctx, HAP_VERBOSITY_ERROR, "No comparison function for %d", ctx->header->entry_key_len);
        return;
    }
    
    ctx->header->flags |= HAP_FLAG_SORTED;
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Sorting finished");
    update_sections(ctx);
}

void hap_dedup(hap_ctx ctx){
    if (! (ctx->header->flags & HAP_FLAG_SORTED)){
        hap_sort(ctx);
    }
    uint64_t entry_a, entry_b;
    uint8_t prev[128]={};
    size_t entrysize = entry_len;
    uint64_t nentries = ctx->header->total_entries;
    

    for(entry_a=0, entry_b=0; entry_b < nentries; entry_a++, entry_b++) {
        //printf("a=%ld b=%ld\n", entry_a, entry_b);
        while(memcmp(ENTRY_KEY(entry_b), prev, entrysize) == 0){
            entry_b++;
            if (entry_b >= nentries){
                break;
            }
        }
        if (entry_b >= nentries){
            break;
        }
        if(entry_a != entry_b)
            memcpy(ENTRY_KEY(entry_a), ENTRY_KEY(entry_b), entrysize);
        memcpy(prev, ENTRY_KEY(entry_b), entrysize);
    }
    ctx->header->total_entries = entry_a;
    update_sections(ctx);
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Deduping finished");
}

void hap_log(hap_ctx ctx, enum hap_verbosity_level loglevel, const char *fmt, ...){
    char buffer[1024];
    va_list va;

    va_start(va, fmt);
    vsnprintf(buffer, sizeof(buffer), fmt, va);
    va_end(va);
    if (ctx && (loglevel <= ctx->loglevel)){
        fprintf(stderr, "%s\n", buffer);
    } else if (ctx == NULL){
        fprintf(stderr, "%s\n", buffer);
    }
}

int hap_load_hap_file(hap_ctx ctx, const char *filename){
    int fd;
    int rc;
    struct stat file_stat;
    uint64_t expected_file_size;

    fd = open(filename, O_RDWR);
    if (fd < 0){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Error opening %s: %s", filename, strerror(errno));
        return -1;
    }
    fstat(fd, &file_stat);
    if ((uint64_t)file_stat.st_size < sizeof(struct hap_header_struct)){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "File %s too small to contain header: %d", filename, file_stat.st_size);
        return -1;
    }
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Opening a %d bytes file %s", file_stat.st_size, filename);
    rc = map_file(ctx, fd, file_stat.st_size, 1);
    if (rc != 0){
        return -1;
    }

    ctx->header = ctx->file_map;
    /* consistency checks */
    if (ctx->header->magic != HAP_MAGIC){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Header: bad magic");
        return -1;
    }
    if (ctx->header->version != HAP_VERSION){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Unhandled version %d, current version %d", ctx->header->version, HAP_VERSION);
        return -1;
    }
    if (ctx->header->num_sections > SECTION_LIMIT){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Too many sections");
        return -1;
    }
    if (ctx->header->total_entries > ENTRIES_LIMIT){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Too many entries");
        return -1;
    }
    if (ctx->header->entry_key_hash > HAP_HASH_MAX_VALUE){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Invalid hash type %d", ctx->header->entry_key_hash);
        return -1;
    }
    ctx->hash = &hap_hash_info[ctx->header->entry_key_hash];
    if (ctx->hash == NULL){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Unsupported hash type %s", ctx->hash->hash_name);
        return -1;
    }
    if (ctx->header->entry_key_len > 64 || ctx->header->entry_value_len > 64){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Key len or value len too high, please adjust");
        return -1;
    }
    if (ctx->header->entry_key_len != ctx->hash->hash_len){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Key len does not match hash type: %d (expected %d)", 
            ctx->header->entry_key_len, ctx->hash->hash_len);
        return -1;
    }
    expected_file_size = sizeof(struct hap_header_struct);
    expected_file_size += sizeof(struct hap_section_struct) * ctx->header->num_sections;
    expected_file_size += (ctx->header->entry_key_len + ctx->header->entry_value_len) * ctx->header->total_entries;
    if (expected_file_size > (uint64_t)file_stat.st_size){
        hap_log(ctx, HAP_VERBOSITY_ERROR, "Incorrect file size. Expected %d, got %d", expected_file_size, file_stat.st_size);
        return -1;
    }
    /* header looks valid */

    ctx->sections = ctx->file_map + sizeof(struct hap_header_struct);
    ctx->entries = ctx->file_map + sizeof(struct hap_header_struct) + \
        sizeof(struct hap_section_struct) * ctx->header->num_sections;
    /* todo: check consistency */
    return 0;
}

static char *hap_hexa(char *dest, const uint8_t *src, size_t len){
    size_t i;
    dest[0] = '\0';
    for (i=0; i<len; ++i){
        snprintf(&dest[i*2], 3, "%.2x", src[i]);
    }
    return dest;
}

static int hap_from_hex(uint8_t *dest, size_t len, const char *src){
    int i;
    int rc;

    memset(dest, '\0', len);
    for (i=0; src[i*2] && src[(i*2)+1] && i < len; i++){
        rc = sscanf(&src[i*2], "%2hhx", &dest[i]);
        if (rc != 1){
            hap_log(NULL, HAP_VERBOSITY_ERROR, "hex parse error: %s", &src[i*2]);
            return -1;
        }
    }
    if (src[i*2]){
        hap_log(NULL, HAP_VERBOSITY_ERROR, "Invalid hex-encoded len");
        return -1;
    }
    return 0;
}

void dump_entry(hap_ctx ctx, uint32_t section, uint32_t entry){
    char keybuf[128];
    char valuebuf[128];
    hap_hexa(keybuf, ENTRY_KEY(entry), ENTRY_KEY_LEN);
    snprintf(valuebuf, MIN(sizeof(valuebuf), ENTRY_VALUE_LEN), "%s",
        ENTRY_VALUE(entry));
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "%.4x: %s:%s", section, keybuf, valuebuf);
}

void hap_dump(hap_ctx ctx){
    uint32_t i;
    uint64_t j;
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "%d sections, %d entries total", ctx->header->num_sections,
        ctx->header->total_entries);
    for (i=0; i<ctx->header->num_sections; ++i){
        hap_log(ctx, HAP_VERBOSITY_DEBUG, "Section %d, %d entries", i, ctx->sections[i].entries);
        for (j=ctx->sections[i].offset;
            j<ctx->sections[i].offset + ctx->sections[i].entries;
            ++j){
            dump_entry(ctx, i, j);
        }
    }
}

uint32_t hap_get_key_len(hap_ctx ctx){
    return ctx->header->entry_key_len;
}

uint32_t hap_get_value_len(hap_ctx ctx){
    return ctx->header->entry_value_len;
}

/**
 * @brief retrieve an entry in the opened context, hashing it first.
 * @param value[in] key to hash and search.
 * @returns the entry number if key was found, HAP_NOT_FOUND if the key wasn't found, HAP_ERROR on error.
 */
int64_t hap_find_bisect_hash(hap_ctx ctx, const char* value) {
    uint8_t key_buffer[HAP_MAX_HASH_LEN];

    hap_init();
    ctx->hash->do_hash(ctx, key_buffer, value);
    return hap_find_bisect_range(ctx, key_buffer, ctx->hash->hash_len * 8, HAP_BISECT_EXACT_MATCH);
}

/** @internal
 * @brief compare memory based on bits instead of bytes
 * @returns -1 if a<b, 0 if a=b, +1 if b>a.
 */
static int memcmp_bits(const uint8_t *a, const uint8_t *b, int bits){
    int rc;
    int offset;
    if (bits >= 8){
        rc = memcmp(a, b, bits/8);
        /* hap_log("memcmp returned %d", rc); */
        if (rc != 0 || bits % 8 == 0){
            return rc;
        }
    }
    /* We're left with at most 8 bits */
    offset = bits/8;
    bits = bits % 8;
    uint8_t a_8 = a[offset] >> (8-bits);
    uint8_t b_8 = b[offset] >> (8-bits);
    /* hap_log("a: %x b:%x", a_8, b_8); */
    if (a_8 == b_8){
        return 0;
    } else if (a_8 < b_8) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief retrieve an entry in the opened context.
 * @param key[in] pointer to the key to search.
 * @param bits[in] number of bits to match with.
 * @param flags[in] behavior of the bisection :
 *                  HAP_BISECT_EXACT_MATCH will return the first found element that matches
 *                  key/bits. Might not be the first or last element if there are duplicates.
 *                  HAP_BISECT_FIRST_MATCH will return the first matching element in
 *                  sequential order.
 *                  HAP_BISECT_LAST_MATCH will return the last matching element.
 * @returns the entry number if key was found, HAP_NOT_FOUND if the key wasn't found, HAP_ERROR on error.
 */
int64_t hap_find_bisect_range(hap_ctx ctx, const uint8_t *key, int bits, enum hap_bisect_behaviour flags){
    char buffer[64];
    int section;
    int rc;
    uint64_t begin, end, candidate;
    uint32_t key_len = ctx->header->entry_key_len;
    uint8_t *ptr;

    if (ctx->header->flags & HAP_FLAG_SORTED == 0){
        hap_log(ctx, HAP_VERBOSITY_WARNING, "searching through unsorted file");
    }
    if (bits > key_len * 8){
        bits = key_len * 8;
    }
    section = hap_getsection(ctx->header->num_sections, key);
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Searching for %s/%d in section %d", hap_hexa(buffer, key, bits/8 + (bits%8?1:0)), bits, section);

    begin = ctx->sections[section].offset;
    end = begin + ctx->sections[section].entries;
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "searching in %d entries", end-begin);
    while (begin != end){
        candidate = begin + (end-begin) / 2;
        ptr = ctx->entries + candidate * entry_len;
        hap_log(ctx, HAP_VERBOSITY_DEBUG, "Testing %s", hap_hexa(buffer, ptr, key_len));
        rc = memcmp_bits(ptr, key, bits);
        if ((flags == HAP_BISECT_EXACT_MATCH || flags == HAP_BISECT_PREVIOUS_MATCH) && rc == 0){
            hap_log(ctx, HAP_VERBOSITY_DEBUG, "Found !");
            return candidate;
        }
        if (rc == 0){
            hap_log(ctx, HAP_VERBOSITY_DEBUG, "Match");
            if (flags == HAP_BISECT_FIRST_MATCH){
                end = candidate;
            } else if (flags == HAP_BISECT_LAST_MATCH) {
                begin = candidate+1;
            } else {
                hap_log(ctx, HAP_VERBOSITY_ERROR, "Invalid flag %d", flags);
                return HAP_ERROR;
            }
        } else if (rc > 0){
            end=candidate;
        } else {
            begin = candidate +1;
        }
    }
    /* begin == end */
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "begin: %d end: %d", begin, end);
    if (flags == HAP_BISECT_LAST_MATCH && end >= 1){
        candidate = end-1;
    } else {
        candidate = begin;
    }
    ptr = ctx->entries + candidate * entry_len;
    if(memcmp_bits(ptr, key, bits) == 0){
        hap_log(ctx, HAP_VERBOSITY_DEBUG, "Found %d", candidate);
        return candidate;
    }
    if (flags == HAP_BISECT_PREVIOUS_MATCH){
        return candidate;
    }
    hap_log(ctx, HAP_VERBOSITY_DEBUG, "Not found");
    return HAP_NOT_FOUND;
}

/**
 * @brief retrieve an entry in the opened context.
 * @param hash[in] string to an hex-encoded key to search.
 * @param bits[in] number of bits to match with.
 * @param flags[in] behavior of the bisection :
 *                  HAP_BISECT_EXACT_MATCH will return the first found element that matches
 *                  key/bits. Might not be the first or last element if there are duplicates.
 *                  HAP_BISECT_FIRST_MATCH will return the first matching element in
 *                  sequential order.
 *                  HAP_BISECT_LAST_MATCH will return the last matching element.
 * @returns the entry number if key was found, HAP_NOT_FOUND if the key wasn't found, HAP_ERROR on error.
 */
int64_t hap_find_bisect_range_hex(hap_ctx ctx, const char *hash, int bits, enum hap_bisect_behaviour flags){
        uint8_t buffer[HAP_MAX_HASH_LEN];
        int rc;

        rc = hap_from_hex(buffer, sizeof(buffer), hash);
        if (rc < 0){
            return HAP_ERROR;
        }
        return hap_find_bisect_range(ctx, buffer, bits, flags);
    }

uint8_t *hap_get_entry_ptr(hap_ctx ctx, uint64_t entry){
    if (entry >= ctx->header->total_entries){
        hap_log(ctx, HAP_VERBOSITY_DEBUG, "Entry out of range: %lld", entry);
        return NULL;
    }
    return ENTRY_KEY(entry);
}

/** @brief returns an hex-encoded string representation of the entry key
 * @param entry[in] Entry number in file
 * @returns an hex-encoded string with key's content, or NULL on errors.
 * @warning the return buffer isn't thread safe.
 */
const char *hap_get_entry(hap_ctx ctx, uint64_t entry){
    uint8_t *ptr = hap_get_entry_ptr(ctx, entry);
    if (ptr == NULL){
        return NULL;
    }
    if (ctx->string_buffer_size < ctx->header->entry_key_len * 2 + 1){
        free(ctx->string_buffer);
        ctx->string_buffer = malloc(ctx->header->entry_key_len * 2 +1);
        ctx->string_buffer_size = ctx->header->entry_key_len * 2 +1;
    }
    hap_hexa(ctx->string_buffer, ptr, ctx->header->entry_key_len);
    return ctx->string_buffer;
}

/** @brief returns an hex-encoded string representation of the entry value
 * @param entry[in] Entry number in file
 * @returns an hex-encoded string with value's content, or NULL on errors.
 * @warning the return buffer isn't thread safe.
 */
const char *hap_get_value(hap_ctx ctx, uint64_t entry){
    uint8_t *ptr = hap_get_entry_ptr(ctx, entry);
    if (ptr == NULL){
        return NULL;
    }
    if (ctx->string_buffer_size < ctx->header->entry_value_len * 2 + 1){
        free(ctx->string_buffer);
        ctx->string_buffer = malloc(ctx->header->entry_value_len * 2 +1);
        ctx->string_buffer_size = ctx->header->entry_value_len * 2 +1;
    }
    hap_hexa(ctx->string_buffer, ptr + ctx->header->entry_key_len,
        ctx->header->entry_value_len);
    return ctx->string_buffer;
}

/** @brief returns the global metadata of the loaded file.
 * @warning the return buffer isn't thread safe.
 */
const char *hap_get_global_metadata(hap_ctx ctx){
    size_t len = strnlen(ctx->header->global_metadata,
        sizeof(ctx->header->global_metadata)) + 1;
    if (ctx->string_buffer_size < len){
        free(ctx->string_buffer);
        ctx->string_buffer = malloc(len);
        ctx->string_buffer_size = len;
    }
    snprintf(ctx->string_buffer, len, "%s", ctx->header->global_metadata);
    return ctx->string_buffer;
}

int hap_set_global_metadata(hap_ctx ctx, const char *md){
    snprintf(ctx->header->global_metadata, sizeof(ctx->header->global_metadata),
        "%s", md);
    return 0;
}
