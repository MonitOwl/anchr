#include "anchr_common.h"
#include "anchr_policy.h"
#include "anchr_kfunc_buffer.h"
#include "anchr_kfuncs.h"

/* Namespace configuration lives in the policy map; this list contains audit metadata. */
static LIST_HEAD(policy_namespace_list);
DEFINE_MUTEX(anchr_policy_namespace_mutex);

static struct anchr_policy_namespace *find_policy_namespace(const char *id)
{
    struct anchr_policy_namespace *entry;

    lockdep_assert_held(&anchr_policy_namespace_mutex);
    list_for_each_entry(entry, &policy_namespace_list, list)
        if (!strcmp(entry->namespace_id, id))
            return entry;
    return NULL;
}

struct anchr_policy_namespace *anchr_policy_namespace_get_locked(const char *id)
{
    struct anchr_policy_namespace *entry;

    lockdep_assert_held(&anchr_policy_namespace_mutex);
    if (anchr_validate_namespace(id) || strlen(id) >= ANCHR_NAMESPACE_SIZE)
        return ERR_PTR(-EINVAL);
    entry = find_policy_namespace(id);
    if (entry)
        return entry;
    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return ERR_PTR(-ENOMEM);
    strscpy(entry->namespace_id, id, sizeof(entry->namespace_id));
    INIT_LIST_HEAD(&entry->change_history);
    spin_lock_init(&entry->change_history_lock);
    list_add_tail(&entry->list, &policy_namespace_list);
    return entry;
}

struct anchr_policy_namespace *anchr_policy_namespace_get_or_create(const char *id)
{
    struct anchr_policy_namespace *entry;

    mutex_lock(&anchr_policy_namespace_mutex);
    entry = anchr_policy_namespace_get_locked(id);
    mutex_unlock(&anchr_policy_namespace_mutex);
    return entry;
}

__bpf_kfunc int anchr_policy_namespace_get_config(const char *namespace_id, u32 namespace_id__sz,
                                                  void *config, u32 config__sz)
{
    char id[ANCHR_NAMESPACE_SIZE];
    int ret;

    if (!config || config__sz != sizeof(struct anchr_policy_config))
        return -EINVAL;
    ret = anchr_copy_kfunc_string(id, sizeof(id), namespace_id, namespace_id__sz, false);
    if (ret || anchr_validate_namespace(id))
        return -EINVAL;
    return anchr_policy_read(id, config);
}

int anchr_policy_namespace_update_filter_flags(const char *id, u32 value)
{
    return anchr_policy_update_field(id, "filter_flags", value);
}

int anchr_policy_namespace_update_action_flags(const char *id, u32 value)
{
    return anchr_policy_update_field(id, "action_flags", value);
}

int anchr_policy_namespace_update_min_file_size(const char *id, u32 value)
{
    return anchr_policy_update_field(id, "min_file_size", value);
}

int anchr_policy_namespace_update_log_level(const char *id, u32 value)
{
    return anchr_policy_update_field(id, "log_level", value);
}

int anchr_policy_namespace_get_changes_hash(const char *id, u8 *hash, u32 size)
{
    struct anchr_policy_namespace *entry;
    int ret = 0;

    if (!hash || size != MERKLE_HASH_SIZE)
        return -EINVAL;
    mutex_lock(&anchr_policy_namespace_mutex);
    entry = find_policy_namespace(id);
    if (!entry)
        ret = -ENOENT;
    else
        memcpy(hash, entry->changes_hash, MERKLE_HASH_SIZE);
    mutex_unlock(&anchr_policy_namespace_mutex);
    return ret;
}

int anchr_policy_namespace_init(void)
{
    return 0;
}

static void free_namespace(struct anchr_policy_namespace *entry)
{
    struct policy_change_entry *change, *tmp;

    list_for_each_entry_safe(change, tmp, &entry->change_history, list) {
        list_del(&change->list);
        kfree(change);
    }
    list_del(&entry->list);
    kfree(entry);
}

void anchr_policy_namespace_remove(const char *id)
{
    struct anchr_policy_namespace *entry;

    mutex_lock(&anchr_policy_namespace_mutex);
    entry = find_policy_namespace(id);
    if (entry)
        free_namespace(entry);
    mutex_unlock(&anchr_policy_namespace_mutex);
    /* Map rules persist for the epoch: teardown cannot silently weaken policy. */
}

void anchr_policy_namespace_cleanup(void)
{
    struct anchr_policy_namespace *entry, *tmp;

    mutex_lock(&anchr_policy_namespace_mutex);
    list_for_each_entry_safe(entry, tmp, &policy_namespace_list, list)
        free_namespace(entry);
    mutex_unlock(&anchr_policy_namespace_mutex);
}
