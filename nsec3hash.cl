typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
#define SHA1_DIGEST_LEN 20

/*
MIT License
see LICENSE for more information
Copyright (c) 2024 Aris Adamantiadis
*/

typedef uint8_t in_data_t[DATA_MAX_LEN];
typedef uint8_t in_salt_t[SALT_MAX_LEN];

typedef uint8_t outbuffer_t[SHA1_DIGEST_LEN];
typedef struct {
    uint64_t from;
    uint64_t to;
} hole_t;

/* extracted from buffer_structs_template.cl
    Originally adapted from Bjorn Kerler's sha256.cl
    MIT License
*/ 
unsigned int SWAP (unsigned int val)
    {
        return (rotate(((val) & 0x00FF00FF), 24U) | rotate(((val) & 0xFF00FF00), 8U));
    }

#include "sha1.cl"

inline int align32(uint32_t v){
	return v + 4-(v%4);
}

void do_nsec3hash(__global uint8_t *data, __global uint8_t *out, __global uint8_t *salt, int data_len, int salt_len, int iterations) {

	uint32_t tmp_digest[5];
	uint8_t hash_buf[DATA_MAX_LEN + SALT_MAX_LEN];
	int i, j;

	__global uint32_t *dst = (__global uint32_t *)out;
	__global unsigned int *buf = (__global unsigned int *)data;

	if(salt_len == 0) {
		hash_glbl_to_priv(buf, data_len, tmp_digest);
	} else {
		for(i=0; i<align32(data_len)/4;++i){
			((uint32_t *)hash_buf)[i] = ((__global uint32_t *)data)[i];
		}
		if (data_len & 0x3){
			/* non-aligned memory copy */
			for (i=data_len, j=0; j< salt_len; ++i, ++j){
				hash_buf[i] = salt[j];
			}
		} else {
			for(i=0; i<align32(salt_len)/4; ++i){
				((uint32_t *)hash_buf)[data_len/4 + i] = ((__global uint32_t *)salt)[i];
			}
		}
		for(i = data_len + salt_len; i < align32(data_len + salt_len); ++i){
			hash_buf[i] = 0;
		}
		hash_private((__private unsigned int *)hash_buf, data_len+salt_len, tmp_digest);
	}

	if (iterations != 0){
		/*for(i=0; i<align32(salt_len)/4; ++i) {
			((uint32_t *)hash_buf)[5 + i] = salt[i];
		}*/
        for (i=0; i<salt_len;++i){
            hash_buf[SHA1_DIGEST_LEN + i] = salt[i];
        }
	}
	for(int it=0; it < iterations; ++it){
		for(int i=0;i<5;++i){
			((uint32_t *)hash_buf)[i] = tmp_digest[i];
		}

		hash_private((__private unsigned int *)hash_buf, SHA1_DIGEST_LEN + salt_len, tmp_digest);
	}

	for(int i=0;i<5;++i)
		dst[i]=tmp_digest[i];
}

__kernel void nsec3hash(__global in_data_t *buffer, __global in_salt_t *salt, __global outbuffer_t *out, int data_len, int salt_len, int iterations) {
    unsigned int idx = get_global_id(0);
    do_nsec3hash(buffer[idx],
    	out[idx],
    	salt[0],
    	data_len,
    	salt_len,
    	iterations);
}

void do_match_hash(__global int *solutions, __global uint8_t *nsec3_hash, __global hole_t *holes, int nholes){
	#if 0
	uint32_t hash1 = ((__global uint32_t*)nsec3_hash)[0];
	uint32_t hash2 = ((__global uint32_t*)nsec3_hash)[1];
    uint64_t hash = hash2 | (hash1 << 32);
    #endif
    #if 1
    union {
    	uint64_t u64;
    	uint8_t u8[8];
    } hash_u;

    for (int i=0; i<8;++i){
    	hash_u.u8[i] = nsec3_hash[7-i];
    }
    uint64_t hash = hash_u.u64;
    #else
    uint64_t hash=*(__global uint64_t*) nsec3_hash;
    #endif
    unsigned int idx = get_global_id(0);
//    unsigned int idx2 = get_global_id(1);


    /* n^2 algorithm. To optimize later with binary slicing */
//    if(hash > holes[idx2].from && hash<holes[idx2].to){
//        solutions[idx2] = idx;
//    }
 
    for(int i=0; i<nholes;++i){
        if((hash > holes[i].from) && (hash < holes[i].to)){
            solutions[i] = idx;
        }
    }

}

/* Find a matching hash from an index in nsec3_hashes in the holes[] array. If found, add its index in solutions[hole_idx] */
__kernel void match_hash(__global int *solutions, __global outbuffer_t *nsec3_hashes, __global hole_t *holes, int nholes) {
    unsigned int idx = get_global_id(0);
    do_match_hash(solutions, nsec3_hashes[idx], holes, nholes);
}

#define characters "abcdefghijklmnopqrstuvwxyz0123456789"
#define INC_OFFSET 1

/* Prepare an input buffer to be hashed. Each attempt requires a new counter to prevent
 * the same hashes from popping up again and again 
 * The format used is the following : 
 *  fyyyyzzzz.tld.
 *  with yyyy and zzzz being 5x5bits (global) and 5x5 bits (local) counters
 *  it becomes [10]yyyyyzzzzz[3]tld[0]
 *  */
__kernel void prepare_data_buffer(__global in_data_t *buffer, int data_len, unsigned int counter){
    unsigned int idx = get_global_id(0);
    buffer[idx][INC_OFFSET] = characters[counter & 0x1f];
    buffer[idx][INC_OFFSET+1] = characters[(counter >> 5) & 0x1f];
    buffer[idx][INC_OFFSET+2] = characters[(counter >> 10) & 0x1f];
    buffer[idx][INC_OFFSET+3] = characters[(counter >> 15) & 0x1f];
    buffer[idx][INC_OFFSET+4] = characters[(counter >> 20) & 0x1f];
    buffer[idx][INC_OFFSET+5] = characters[(idx >> 20) & 0x1f];
    buffer[idx][INC_OFFSET+6] = characters[(idx >> 15) & 0x1f];
    buffer[idx][INC_OFFSET+7] = characters[(idx >> 10) & 0x1f];
    buffer[idx][INC_OFFSET+8] = characters[(idx >> 5) & 0x1f];
    buffer[idx][INC_OFFSET+9] = characters[(idx >> 0) & 0x1f];
}
//#error check your warnings
