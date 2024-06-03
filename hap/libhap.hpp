/*
MIT License
see LICENSE for more information
Copyright (c) 2024 Aris Adamantiadis
*/

class HAP {
public:
	HAP(){
		ctx = hap_new();
	}
	~HAP(){
		hap_free(ctx);
	}
	void set_loglevel(enum hap_verbosity_level level){
		hap_set_loglevel(ctx, level);
	}
	int load_list_file(const char *filename){
		return ::hap_load_list_file(ctx, filename);
	}
	int prepare_file(const char *filename, uint32_t value_len){
		return ::hap_prepare_file(ctx, filename, value_len);
	}
	int set_hash(enum hap_hash_type htype){
		return ::hap_set_hash(ctx, htype);
	}
	enum hap_hash_type get_hash(){
		return ::hap_get_hash(ctx);
	}
	int fill_file(){
		return ::hap_fill_file(ctx);
	}
	int load_hap_file(const char *filename){
		return ::hap_load_hap_file(ctx, filename);
	}
	void dump(){
		::hap_dump(ctx);
	}
	void sort(){
		::hap_sort(ctx);
	}
	void dedup(){
		::hap_dedup(ctx);
	}
	int64_t find_bisect_hash(const char* value){
		return ::hap_find_bisect_hash(ctx, value);
	}
	int64_t find_bisect_range_hex(const char *hash, int bits, enum hap_bisect_behaviour flags){
		return ::hap_find_bisect_range_hex(ctx, hash, bits, flags);
	}
	uint64_t get_entries_count(){
		return ::hap_get_entries_count(ctx);
	}
	const char *get_entry(uint64_t entry){
		return ::hap_get_entry(ctx, entry);
	}
	const char *get_value(uint64_t entry){
		return ::hap_get_value(ctx, entry);
	}
	const char *get_global_metadata(){
		return ::hap_get_global_metadata(ctx);
	}
	int set_global_metadata(const char *md){
		return ::hap_set_global_metadata(ctx, md);
	}
	uint32_t get_key_len(){
		return ::hap_get_key_len(ctx);
	}
	uint32_t get_value_len(){
		return ::hap_get_value_len(ctx);
	}
	int add_entry(const uint8_t *key, const uint8_t *value){
		return ::hap_add_entry(ctx, key, value);
	}
	int add_entry_hex(const char *key, const char *value){
		return ::hap_add_entry_hex(ctx, key, value);
	}
	static const int HASH_CLEARTEXT = HAP_HASH_CLEARTEXT;
	static const int HASH_FAST_NSEC3 = HAP_HASH_FAST_NSEC3;
	static const int HASH_NSEC3 = HAP_HASH_NSEC3;
	static const int BISECT_EXACT_MATCH = HAP_BISECT_EXACT_MATCH;
	static const int BISECT_FIRST_MATCH = HAP_BISECT_FIRST_MATCH;
	static const int BISECT_LAST_MATCH = HAP_BISECT_LAST_MATCH;
	static const int BISECT_PREVIOUS_MATCH = HAP_BISECT_PREVIOUS_MATCH;
	static const int ERROR = HAP_ERROR;
	static const int NOT_FOUND = HAP_NOT_FOUND;
	static const int VERBOSITY_NONE = HAP_VERBOSITY_NONE;
    static const int VERBOSITY_ERROR = HAP_VERBOSITY_ERROR;
    static const int VERBOSITY_WARNING = HAP_VERBOSITY_WARNING;
    static const int VERBOSITY_DEBUG = HAP_VERBOSITY_DEBUG;
private:
	hap_ctx ctx;
};
