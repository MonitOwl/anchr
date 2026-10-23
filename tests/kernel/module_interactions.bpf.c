#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../../utils/bpf_kfunc_defs.h"
#include "module_interactions.h"

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct module_test_state);
} module_test_map SEC(".maps");

static __noinline void snapshot(struct module_test_state *state)
{
    state->exists = anchr_container_exists(state->namespace_id, sizeof(state->namespace_id));
    state->measurement_count = anchr_container_get_measurement_count(state->namespace_id,
                                                                      sizeof(state->namespace_id));
    state->container_count = anchr_container_get_count();
    state->leaf_result = anchr_container_get_leaf_hash(state->namespace_id, sizeof(state->namespace_id),
                                                       state->leaf, TEST_HASH_SIZE);
    state->root_result = anchr_merkle_get_root(state->root, TEST_HASH_SIZE);
    state->policy_result = anchr_policy_namespace_get_config(state->namespace_id,
                                                               sizeof(state->namespace_id),
                                                               &state->policy, sizeof(state->policy));
    state->changes_result = anchr_policy_get_changes_hash(state->namespace_id, sizeof(state->namespace_id),
                                                           state->changes, TEST_HASH_SIZE);
}

SEC("lsm.s/file_open")
int BPF_PROG(module_interactions, struct file *file, int previous_ret)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tid = pid_tgid;
    struct module_test_state *state;
    __u32 command;

    if (previous_ret != 0)
        return previous_ret;

    state = bpf_map_lookup_elem(&module_test_map, &tid);
    if (!state || state->target_pid != pid_tgid >> 32 || state->command == TEST_IDLE)
        return 0;

    command = state->command;
    /* Disarm before entering a kfunc that could trigger a nested hook. */
    state->command = TEST_IDLE;
    state->calls++;

    switch (command)
    {
    case TEST_CREATE:
        state->result = anchr_container_get_or_create(state->namespace_id, sizeof(state->namespace_id));
        break;
    case TEST_MEASURE:
        state->result = anchr_measurement_extend(&state->request, sizeof(state->request));
        break;
    case TEST_UPDATE_FILTER:
        state->result = anchr_policy_update_filter_flags(state->namespace_id, sizeof(state->namespace_id),
                                                          state->policy.filter_flags);
        break;
    case TEST_UPDATE_ACTION:
        state->result = anchr_policy_update_action_flags(state->namespace_id, sizeof(state->namespace_id),
                                                          state->policy.action_flags);
        break;
    case TEST_UPDATE_MIN_SIZE:
        state->result = anchr_policy_update_min_file_size(state->namespace_id, sizeof(state->namespace_id),
                                                           state->policy.min_file_size);
        break;
    case TEST_UPDATE_LOG_LEVEL:
        state->result = anchr_policy_update_log_level(state->namespace_id, sizeof(state->namespace_id),
                                                       state->policy.log_level);
        break;
    case TEST_FILTERS:
        state->ignore_cgroup = anchr_policy_should_ignore_cgroup(state->namespace_id,
                                                                   sizeof(state->namespace_id),
                                                                   state->policy.filter_flags);
        state->ignore_path = anchr_policy_should_ignore_path(state->request.additional_data,
                                                               sizeof(state->request.additional_data),
                                                               state->policy.filter_flags);
        return 0;
    case TEST_PCR:
        state->tpm_available = anchr_tpm_is_available();
        state->result = anchr_tpm_get_pcr_value(state->pcr, ANCHR_PCR_BUFFER_SIZE);
        return 0;
    case TEST_SNAPSHOT:
        state->result = 0;
        break;
    default:
        state->result = -22;
        return 0;
    }

    snapshot(state);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
