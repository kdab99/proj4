#include <linux/module.h>   /* Needed by all kernel modules */
#include <linux/kernel.h>   /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>     /* Needed for __init and __exit macros. */
#include <linux/unistd.h>   /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>       /* filp_open */
#include <linux/slab.h>     /* kmalloc */
#include <linux/kallsyms.h> /* to find syscall table */
#include <asm/ptrace.h>     /* get pt_regs */
#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */
#include <linux/fcntl.h>
#include <linux/types.h>
#include <linux/namei.h>
#include <linux/security.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/file.h>
#include "hooks.h"
#define MAX_PATH_LEN   256
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YOUR NAME HERE");
MODULE_DESCRIPTION("A simple example Linux module.");
MODULE_VERSION("0.01");
// for later hooking
unsigned long long *syscall_table = NULL;
// function pointer declarations for original syscall functions
asmlinkage long (*original_mkdir)(const struct pt_regs *);
asmlinkage long (*original_close)(const struct pt_regs *);
asmlinkage long (*original_creat)(const char __user *pathname, umode_t mode);
asmlinkage long (*original_open)(const struct pt_regs *);
asmlinkage long (*original_openat)(const struct pt_regs *);
// MORE ORIGINAL SYSCALL FUNCTION POINTERS DEFINED HERE
// define what you want to do for each hook
asmlinkage long new_mkdir(const struct pt_regs *regs) {
    printk(KERN_EMERG "[+] mkdir() called ===> directory %s made\n", regs->di);
    struct dentry *dentry;
    struct path path;
    int error;
    unsigned int lookup_flags = LOOKUP_DIRECTORY;
    int dfd = AT_FDCWD;
    umode_t mode = regs->di;
     return original_mkdir(regs);
}
asmlinkage long new_close(const struct pt_regs *regs) {
    struct file *file;
    int fd = regs->di;
    file = fget(fd);
   if (file) {
        printk(KERN_INFO "[+] close() called by PID: %d, Process: %s ===> file descriptor %d closed for file %s\n",
               current->pid, current->comm, fd, file->f_path.dentry->d_name.name);
        fput(file);
    }
    return original_close(regs);
}
asmlinkage long new_creat(const char __user *pathname, umode_t mode) {
    char *kernel_pathname = kmalloc(MAX_PATH_LEN, GFP_KERNEL);
    if (kernel_pathname) {
        copy_from_user(kernel_pathname, pathname, MAX_PATH_LEN);
        printk(KERN_INFO "[+] creat() called by PID: %d, Process: %s ===> file %s\n",
               current->pid, current->comm, kernel_pathname);
        kfree(kernel_pathname);
    }
    return original_creat(pathname, mode);
}
asmlinkage long new_open(const struct pt_regs *regs) {
    char filename[MAX_PATH_LEN];
    long ret;
    // Safely copy the filename from user-space
    if (copy_from_user(filename, (char *)regs->di, MAX_PATH_LEN)) {
        // Error copying from user-space
        return -EFAULT;
    }
    // Null-terminate the string just in case
    filename[MAX_PATH_LEN - 1] = '\0';
    // Print the filename to the kernel log
    printk(KERN_INFO "[+] open() called for file: %s\n", filename);
    // Call the original open syscall
    ret = original_open(regs);
    return ret;
}
asmlinkage long new_openat(const struct pt_regs *regs) {
    char *filename;
    long ret;
    // Get the filename from the registers
    filename = (char *)regs->si; // Note: The second argument to openat is the filename
    // Print the filename to the kernel log
    printk(KERN_INFO "[+] openat() called for file: %s\n", filename);
    // Call the original openat syscall
    ret = original_openat(regs);
    return ret;
}
// DEFINE MORE HOOK ACTIONS HERE
inline void mywrite_cr0(unsigned long cr0) {
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}
void enable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    mywrite_cr0(cr0);
}
void disable_write_protection(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    mywrite_cr0(cr0);
}
static int __init onload(void) {
    printk(KERN_WARNING "Hello world!\n");
    syscall_table = kallsyms_lookup_name("sys_call_table");
    printk(KERN_EMERG "Syscall table address: %p\n", syscall_table);
    printk(KERN_EMERG "sizeof(unsigned long long *): %zx\n", sizeof(unsigned long long *));
    printk(KERN_EMERG "sizeof(sys_call_table) : %zx\n", sizeof(syscall_table));
    if (syscall_table != NULL) {
        disable_write_protection(); // clear write protect
        original_mkdir = (void *)syscall_table[__NR_mkdir];
        syscall_table[__NR_mkdir] = &new_mkdir;
        // HOOK MORE SYSCALLS HERE
    //original_close = (void *)syscall_table[__NR_close];
    //syscall_table[__NR_close] = &new_close;
    original_creat = (void *)syscall_table[__NR_creat];
    syscall_table[__NR_creat] = &new_creat;
        original_open = (void *)syscall_table[__NR_open];
        syscall_table[__NR_open] = &new_open;
    original_openat = (void *)syscall_table[__NR_openat];
    syscall_table[__NR_openat] = &new_openat;
        enable_write_protection(); // reinstate write protect
    } else {
        printk(KERN_EMERG "[-] onload: syscall_table is NULL\n");
    }
    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}
static void __exit onunload(void) {
    if (syscall_table != NULL) {
        disable_write_protection();
    syscall_table[__NR_mkdir] = original_mkdir;
    //syscall_table[__NR_close] = original_close;
    syscall_table[__NR_creat] = original_creat;
    syscall_table[__NR_open] = original_open;
    syscall_table[__NR_openat] = original_openat;
        // CLEAN UP YOUR SYSCALLS HERE
        enable_write_protection();
        printk(KERN_EMERG "[+] onunload: sys_call_table unhooked\n");
    } else {
        printk(KERN_EMERG "[-] onunload: syscall_table is NULL\n");
    }
    printk(KERN_INFO "Goodbye world!\n");
}
module_init(onload);
module_exit(onunload);