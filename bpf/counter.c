//go:build tools
// +build tools

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2024 Your Name */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// #include <bpf/bpf_printk.h> // Add if needed, often included via bpf_helpers.h

// Define the structure for our configuration (target syscall ID)
struct config {
	__u64 target_syscall_nr;
};

// Define the configuration map (simple array map, size 1)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

// Define the counter map (per-CPU array is efficient for counters)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} counter_map SEC(".maps");

SEC("tp/raw_syscalls/sys_enter_execve")
int handle_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    __u32 config_key = 0;
    struct config *cfg;
    __u64 syscall_nr = (__u64)ctx->id; // Get syscall ID early
    __u32 counter_key = 0;
    __u64 *count_ptr; // Use different name from map
    __u64 target_nr = 0; // For logging
    int comparison_result = 0;

    // 1. Read the configuration
    cfg = bpf_map_lookup_elem(&config_map, &config_key);
   /* if (cfg) {
        target_nr = cfg->target_syscall_nr; // Get target for logging
    } else {
        // Config map failed - log and exit?
        // Use bpf_printk carefully - limited buffer size
        char fmt_cfg_fail[] = "BPF: Config map lookup failed\n";
        bpf_trace_printk(fmt_cfg_fail, sizeof(fmt_cfg_fail));
        return 0;
    }*/
    if (!cfg) {
        char fmt_cfg_fail[] = "BPF: Config map lookup failed\n";
        bpf_trace_printk(fmt_cfg_fail, sizeof(fmt_cfg_fail));
        return 0;
    }
    target_nr = cfg->target_syscall_nr;
    // Compare syscall ID
    comparison_result = (syscall_nr == target_nr); // Store result

    // ---> ADDED PRINTK <---
    // Log every syscall entry, the ID found, and the target ID read from the map
    char fmt_entry[] = "BPF: raw_sys_enter: syscall_nr=%llu, target_nr=%llu, match=%d\n";
    bpf_trace_printk(fmt_entry, sizeof(fmt_entry), syscall_nr, target_nr, comparison_result);

    // 3. Compare with the target syscall ID
    if (comparison_result) {
        char fmt_match[] = "BPF: Match found for syscall %llu! Incrementing.\n";
        bpf_trace_printk(fmt_match, sizeof(fmt_match), syscall_nr);

        // 4. Increment the counter
        count_ptr = bpf_map_lookup_elem(&counter_map, &counter_key);
        if (count_ptr) {
            __sync_fetch_and_add(count_ptr, 1);
        } else {
            // ---> ADDED PRINTK <---
            char fmt_ctr_fail[] = "BPF: Counter map lookup failed for key %d\n";
            bpf_trace_printk(fmt_ctr_fail, sizeof(fmt_ctr_fail), counter_key);
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";