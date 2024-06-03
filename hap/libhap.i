%module("threads"=1) hap
%{
    #include "libhap.h"
    #include "libhap.hpp"
%}

%include "std_string.i"
%include "stdint.i"

%nothread HAP::add_entry_hex;

/*%include "libhap.hpp"*/

class HAP {
public:
    HAP();
    ~HAP();
    %nothread;
    void set_loglevel(enum hap_verbosity_level level);
    int load_list_file(const char *filename);
    int prepare_file(const char *filename, uint32_t value_len);
    int set_hash(enum hap_hash_type htype);
    enum hap_hash_type get_hash();
    int fill_file();
    int load_hap_file(const char *filename);
    %thread;
    void dump();
    void sort();
    void dedup();
    %nothread;
    int64_t find_bisect_hash(const char* value);
    int64_t find_bisect_range_hex(const char *hash, int bits, enum hap_bisect_behaviour flags);
    uint64_t get_entries_count();
    const char *get_entry(uint64_t entry);
    const char *get_value(uint64_t entry);
    const char *get_global_metadata();
    int set_global_metadata(const char *md);
    uint32_t get_key_len();
    uint32_t get_value_len();
    int add_entry(const uint8_t *key, const uint8_t *value);
    int add_entry_hex(const char *key, const char *value);
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

%extend HAP {
    %nothread;
    int add_entry(const std::string& key, const std::string& value) {
        return $self->add_entry(reinterpret_cast<const uint8_t*>(key.c_str()), reinterpret_cast<const uint8_t*>(value.c_str()));
    }
}



