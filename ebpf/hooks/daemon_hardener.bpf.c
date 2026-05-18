#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/magic.h>
#include <errno.h>

#include "ebpf_types.h"

const volatile __u32 DAEMON_PID = 0;

static __always_inline int is_unauthorized_external_actor(struct task_struct *p);

/**
 * SEC("lsm/bpf") - Mandatory Access Control for eBPF Map/Program Operations
 * 
 * Intent: Isolates the kernel-space engine from external administrative tampering.
 * Once DAEMON_PID is set, any process other than the authorized user-space 
 * daemon attempting to load, unload, or modify eBPF structures will be denied.
 */
SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_to_self, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (DAEMON_PID == 0) return 0;

    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    if (current_pid != DAEMON_PID) {
        return -EPERM;
    }

    return 0; 
}

/**
 * SEC("lsm/task_kill") - Inter-Process Communication (IPC) Shield
 * 
 * Intent: Prevents external processes (including root/sudo users) from killing 
 * the daemon. Crucially allows the daemon to issue signals to itself or handle 
 * kernel-driven cleanup signals.
 */
SEC("lsm/task_kill")
int BPF_PROG(prevent_closure_of_ts, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    if (DAEMON_PID == 0) return 0;

    // Read target process ID using CO-RE safety bounds
    __u32 target_pid = BPF_CORE_READ(p, tgid);

    if (target_pid == DAEMON_PID) {
        __u32 current_pid = bpf_get_current_pid_tgid() >> 32;

        // CRITICAL SAFETY: Allow the daemon to signal itself or handle kernel events
        if (current_pid == DAEMON_PID || current_pid == 0) {
            return 0;
        }

        return -EPERM;
    } 

    return 0;
}

/* =========================================================================
 *                  RESOURCE & SCHEDULING HARDENING SECTION
 * =========================================================================
 * These LSM hooks trap and reject attempts by external entities to degrade
 * the daemon's host priorities, starve it of hardware time, or crash it by 
 * artificially lowering its operational resource constraints (rlimits).
 */

SEC("lsm/task_setscheduler")
int BPF_PROG(prevent_scheduling_changes, struct task_struct *p)
{
    return is_unauthorized_external_actor(p);
}

SEC("lsm/task_setnice")
int BPF_PROG(prevent_nice_changes, struct task_struct *p, int nice)
{
    return is_unauthorized_external_actor(p);
}

SEC("lsm/task_setioprio")
int BPF_PROG(prevent_io_throttle, struct task_struct *p, int ioprio) {
    return is_unauthorized_external_actor(p);
}

SEC("lsm/task_setrlimit")
int BPF_PROG(prevent_rlimit_drop, struct task_struct *p, unsigned int resource, struct rlimit *new_rlim) {
    return is_unauthorized_external_actor(p);
}

/* =========================================================================
 *                    ANTI-DEBUGGING & INSPECTION SHIELD
 * =========================================================================
 */

 /**
 * SEC("lsm/ptrace_access_check") - Anti-Memory Inspection Hook
 * 
 * Intent: Block external actors from attaching via ptrace (GDB, Strace, Cheat Engines)
 * to read/write to the user-space process memory layouts.
 */

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_proc, struct task_struct* child, unsigned int mode) {
  return is_unauthorized_external_actor(child);
}

/**
 * SEC("lsm/ptrace_traceme") - Anti-Debugger Attachment Prevention
 * 
 * Intent: Rejects a debugger's request to trace the daemon process from 
 * inside a fork or initialization sequence.
 */
SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_me, struct task_struct *parent)
{
    if (DAEMON_PID == 0) return 0;

    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    if (current_pid == DAEMON_PID) {
        __u32 parent_pid = BPF_CORE_READ(parent, tgid);
        
        if (parent_pid != DAEMON_PID && parent_pid != 0) {
            return -EPERM;
        }
    }
    return 0;
}

/**
 * SEC("lsm/inode_permission") - ProcFS Isolation & Information Leak Mitigation
 * 
 * Performance Note: This is an aggressive hotpath executing frequently inside the VFS layer.
 * Short-circuit loops are placed immediately at the entry point to preserve system stability.
 */
SEC("lsm/inode_permission")
int BPF_PROG(prevent_proc_recon, struct inode *inode, int mask, int ret)
{
    if (ret || !inode || DAEMON_PID == 0) return ret;

    // 1. Performance Fast-Path
    if (!inode->i_sb || inode->i_sb->s_magic != PROC_SUPER_MAGIC) return 0;

    // 2. Extract and evaluate target PID in one flow
    struct proc_inode *pi = container_of(inode, struct proc_inode, vfs_inode);
    struct pid *pid_ptr = BPF_CORE_READ(pi, pid);
    
    if (pid_ptr && BPF_CORE_READ(pid_ptr, numbers[0].nr) == DAEMON_PID) {
        __u32 caller = bpf_get_current_pid_tgid() >> 32;
        
        if (caller != DAEMON_PID && caller != 0) {
            bpf_printk("procfs sandbox: Blocked PID %u\n", caller);
            return -EPERM;
        }
    }
    return 0;
}

/**
 * is_unauthorized_external_actor() - Core Integrity Assessment Engine
 * 
 * Determines whether a caller hitting a restricted structural task 
 * is allowed to perform operations on the underlying daemon.
 */
static __always_inline int is_unauthorized_external_actor(struct task_struct *p)
{
    if (DAEMON_PID == 0) return 0; // Allowed if not initialized

    if (BPF_CORE_READ(p, tgid) == DAEMON_PID) {
        __u32 current_pid = bpf_get_current_pid_tgid() >> 32;

        if (current_pid == DAEMON_PID || current_pid == 0) {
            return 0; // Allow self and kernel contexts
        }
        return -EPERM; // Block unauthorized external process
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
