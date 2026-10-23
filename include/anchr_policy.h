#ifndef ANCHR_POLICY_H
#define ANCHR_POLICY_H

#include "anchr_common.h"
#include "anchr_kfunc_types.h"

/* Policy change tracking */
#define MAX_POLICY_CHANGES_STR 1024
#define MAX_POLICY_STRING_SIZE 512

/**
 * struct policy_change_entry - Single policy change record
 * @list: Linked list node
 * @change_hash: SHA-256 hash of the policy_string
 * @policy_string: Full policy configuration string (e.g., "enabled=1,filter_flags=0x0,action_flags=0x3F,min_file_size=0,log_level=2")
 */
struct policy_change_entry {
    struct list_head list;
    u8 change_hash[MERKLE_HASH_SIZE];
    char policy_string[MAX_POLICY_STRING_SIZE];
};

/**
 * struct anchr_policy_namespace - Per-namespace policy configuration
 * @namespace_id: Namespace/container identifier
 * Active namespace configuration is stored only in the policy map.
 * @changes_str: Concatenated string of all policy changes (e.g., "filter_flags=0x7,action_flags=0x3F")
 * @changes_hash: SHA-256 hash of the changes_str
 * @list: Linked list node
 * @change_history: List of policy_change_entry records
 * @change_history_lock: Spinlock protecting the change history list
 */
struct anchr_policy_namespace {
    char namespace_id[CONTAINER_ID_MAX_LEN];
    char changes_str[MAX_POLICY_CHANGES_STR];
    u8 changes_hash[MERKLE_HASH_SIZE];
    struct list_head list;
    struct list_head change_history;
    spinlock_t change_history_lock;
};

#ifdef __KERNEL__
extern struct mutex anchr_policy_namespace_mutex;
int anchr_policy_init(void);
void anchr_policy_cleanup(void);
int anchr_policy_bind_map(u32 fd);
int anchr_policy_apply(const struct anchr_policy_request *request);
int anchr_policy_update_field(const char *namespace_id, const char *field, u32 value);
int anchr_policy_read(const char *namespace_id, struct anchr_policy_config *config);
int anchr_policy_read_locked(const char *namespace_id, struct anchr_policy_config *config, u64 *generation);
void anchr_policy_get_config(struct anchr_policy_config *config);
u64 anchr_policy_generation(void);
u32 anchr_policy_map_id(void);
int anchr_policy_resolve_context(const struct anchr_policy_context *context,
                                  struct anchr_policy_result *result);
bool anchr_policy_match_root(const char *text, u32 filter_flags, bool path);

int anchr_policy_namespace_init(void);
void anchr_policy_namespace_cleanup(void);
struct anchr_policy_namespace *anchr_policy_namespace_get_or_create(const char *namespace_id);
struct anchr_policy_namespace *anchr_policy_namespace_get_locked(const char *namespace_id);
void anchr_policy_namespace_remove(const char *namespace_id);
int anchr_policy_namespace_update_filter_flags(const char *namespace_id, u32 value);
int anchr_policy_namespace_update_action_flags(const char *namespace_id, u32 value);
int anchr_policy_namespace_update_min_file_size(const char *namespace_id, u32 value);
int anchr_policy_namespace_update_log_level(const char *namespace_id, u32 value);
int anchr_policy_namespace_get_changes_hash(const char *namespace_id, u8 *hash, u32 size);
__bpf_kfunc int anchr_policy_namespace_get_config(const char *namespace_id, u32 namespace_id__sz,
                                                  void *config, u32 config__sz);
void anchr_global_policy_cleanup_history(void);
struct list_head *anchr_global_policy_get_history(void);
spinlock_t *anchr_global_policy_get_history_lock(void);
bool anchr_policy_should_ignore_cgroup(const char *text__nullable, u32 text__sz, u32 filter_flags);
bool anchr_policy_should_ignore_path(const char *text__nullable, u32 text__sz, u32 filter_flags);
#endif

#endif /* ANCHR_POLICY_H */
