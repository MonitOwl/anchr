#ifndef ANCHR_MERKLE_H
#define ANCHR_MERKLE_H

#include "anchr_common.h"
#include "anchr_container.h"

extern struct list_head merkle_root_history;
extern spinlock_t merkle_root_history_lock;
extern struct merkle_tree_root system_merkle_root;

/* Lock order: policy namespace mutex -> commit mutex -> data spinlocks/TPM mutex. */
extern struct mutex anchr_commit_mutex;
void __init anchr_commit_init(void);
int anchr_commit_get_error(void);
int anchr_commit_check_locked(void);
int anchr_commit_fail_locked(int error);
bool anchr_commit_hardware_allowed_locked(void);
bool anchr_commit_requires_hardware_locked(void);

/* Caller holds the commit mutex. A successful call takes ownership of entry. */
int anchr_commit_measurement_locked(struct container_node *container,
                                     struct measurement_entry *entry, bool deduplicate);
int anchr_commit_root_locked(const u8 *value, const char *source_id);

/* Circular buffer management */
int aggregate_merkle_entries(struct list_head *entries_to_aggregate, u8 *aggregate_hash, u32 *count_out);
u32 get_merkle_root_history_count(void);

void cleanup_merkle_root_history(void);

#endif /* ANCHR_MERKLE_H */
