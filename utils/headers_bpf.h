#ifndef HEADERS_BPF_H
#define HEADERS_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../include/anchr_kfunc_types.h"
#include "bpf_kfunc_defs.h"

/* Configuration is written only by the module's audited transaction. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct anchr_policy_state);
    __uint(max_entries, ANCHR_POLICY_MAP_ENTRIES);
    __uint(map_flags, ANCHR_POLICY_MAP_FLAGS);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} anchr_policy_map SEC(".maps");

#endif /* HEADERS_BPF_H */
