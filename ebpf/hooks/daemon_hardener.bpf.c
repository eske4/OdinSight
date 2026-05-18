#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/magic.h>
#include <errno.h>

#include "ebpf_types.h"

const volatile __u32 DAEMON_PID = 0;

static __always_inline int is_unauthorized_external_actor(struct task_struct *p);

SEC("lsm/bpf")
int BPF_PROG(restrict_bpf_to_self, int cmd, union bpf_attr *attr, unsigned int size)
{
  __u32 current_pid = bpf_get_current_pid_tgid() >> 32;

    if(DAEMON_PID == 0) {
      return 0;
    }

    if (current_pid != DAEMON_PID) {
       return -EPERM;
    }

    return 0; 
}

SEC("lsm/task_kill")
int BPF_PROG(prevent_closure_of_ts, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred)
{
    // If the C++ loader hasn't initialized the PID yet, don't block anything
    if (DAEMON_PID == 0) {
        return 0;
    }

    int target_pid = p->tgid;

    if (target_pid == DAEMON_PID) {
        //CRITICAL SAFETY: Extract the PID of the process sending the signal
        u64 pid_tgid = bpf_get_current_pid_tgid();
        int ready_to_kill_pid = pid_tgid >> 32;

        // If the daemon is sending a signal to itself, ALLOW IT.
        if (ready_to_kill_pid == DAEMON_PID) {
            //return 0;
        }

        // Block all external signals
        return -EPERM;
    } 

    return 0;
}

// === RESOURCE & SCHEDULING PROTECTION ===

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

// === ANTI-DEBUGGING & INSPECTION ===

SEC("lsm/ptrace_access_check")
int BPF_PROG(ptrace_proc, struct task_struct* child, unsigned int mode) {
  return is_unauthorized_external_actor(child);
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(ptrace_me, struct task_struct *parent)
{
    if (DAEMON_PID == 0) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    int current_pid = pid_tgid >> 32;

    // If our protected daemon is the one being targeted for a trace request
    if (current_pid == DAEMON_PID) {
        int parent_pid = BPF_CORE_READ(parent, tgid);
        
        // Deny the request if the parent process isn't the daemon itself or the kernel
        if (parent_pid != DAEMON_PID && parent_pid != 0) {
            return -EPERM;
        }
    }
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(prevent_proc_recon, struct inode *inode, int mask, int ret)
{
    if (ret) return ret;
    if (!inode) return 0;
    if (DAEMON_PID == 0) return 0;

    // 1. PERFORMANCE FAST-PATH: Drop out immediately if this isn't procfs
    if (!inode->i_sb || inode->i_sb->s_magic != PROC_SUPER_MAGIC) {
        return 0;
    }

    // 2. Extract the private data pointer assigned by procfs
    struct proc_inode *pi;
    struct pid *pid_ptr;
    int target_pid = 0;

    pi = container_of(inode, struct proc_inode, vfs_inode);
    pid_ptr = BPF_CORE_READ(pi, pid);

    if (pid_ptr) { 
        target_pid = BPF_CORE_READ(pid_ptr, numbers[0].nr); 
    }

    if (target_pid == 0) return 0;
    // Fixed print format for debugging
    bpf_printk("Stable Target PID hitting procfs: %d", target_pid);

    if (target_pid == DAEMON_PID) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        int current_pid = pid_tgid >> 32;

        if (current_pid != DAEMON_PID && current_pid != 0) {
            bpf_printk("procfs protection triggered: Blocked PID %u from viewing daemon procfs.\n", current_pid);
            return -EPERM; 
        }
    }

    return 0;
}

static __always_inline int is_unauthorized_external_actor(struct task_struct *p)
{
    if (DAEMON_PID == 0) return 0; // Allowed if not initialized

    int target_pid = BPF_CORE_READ(p, tgid);
    if (target_pid == DAEMON_PID) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        int current_pid = pid_tgid >> 32;

        if (current_pid == DAEMON_PID || current_pid == 0) {
            return 0; // Allow self and kernel contexts
        }
        return -EPERM; // Block unauthorized external process
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
