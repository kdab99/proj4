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
#include <linux/fs_struct.h>
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
asmlinkage long (*original_rename)(const char __user *oldname, const char __user *newname);
asmlinkage long (*original_renameat)(int olddirfd, const char __user *oldpath, int newdirfd, const char __user *newpath);
asmlinkage long (*original_brk)(unsigned long brk);
asmlinkage long (*original_mmap)(struct pt_regs *regs);
asmlinkage long (*original_munmap)(unsigned long addr, size_t length);
asmlinkage long (*original_mprotect)(unsigned long start, size_t len, unsigned long prot);
asmlinkage ssize_t (*original_read)(int fd, void *buf, size_t count);
asmlinkage long (*original_clone)(struct pt_regs *regs);
asmlinkage long (*original_fork)(struct pt_regs *regs);
asmlinkage long (*original_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
asmlinkage void (*original_exit)(struct pt_regs *regs);









// MORE ORIGINAL SYSCALL FUNCTION POINTERS DEFINED HERE
// define what you want to do for each hook


asmlinkage long new_mkdir(const struct pt_regs *regs) {
    struct dentry *dentry;
    struct path path;
    char *dir_name = (char *)regs->di;
    char full_path[PATH_MAX];
    char *cwd;

    // Use kern_path to get the current working directory
    if (kern_path(".", LOOKUP_FOLLOW, &path) == 0) {
        dentry = path.dentry;
        cwd = dentry_path_raw(dentry, full_path, PATH_MAX - 1);
        
        if (!IS_ERR(cwd)) {
            printk(KERN_INFO "mkdir() called for directory: %s/%s\n", cwd, dir_name);
        }
        path_put(&path);
    } else {
        printk(KERN_ERR "Error getting current working directory\n");
    }

    return original_mkdir(regs);
}

asmlinkage long new_close(const struct pt_regs *regs) {
    struct file *file;
    char cwd[MAX_PATH_LEN];
    struct path path;
    int fd = regs->di;
 
    file = fget(fd);
    if (file) {
        // Get the current working directory
        get_fs_pwd(current->fs, &path);
        dentry_path_raw(path.dentry, cwd, MAX_PATH_LEN - 1);  // Ensure null-termination
        cwd[MAX_PATH_LEN - 1] = '\0';  // Null-terminate just in case
 
        // Check if the filename starts with `/` (absolute path)
        if (file->f_path.dentry->d_name.name[0] != '/') {
            // If not, it's a relative path, so prepend the cwd
            strncat(cwd, "/", MAX_PATH_LEN - strlen(cwd) - 1);
            strncat(cwd, file->f_path.dentry->d_name.name, MAX_PATH_LEN - strlen(cwd) - 1);
        } else {
            strncpy(cwd, file->f_path.dentry->d_name.name, MAX_PATH_LEN - 1);
        }
 
        printk(KERN_INFO "[+] close() called by PID: %d, Process: %s ===> file descriptor %d closed for file %s\n",
               current->pid, current->comm, fd, cwd);
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
    char cwd[MAX_PATH_LEN];
    long ret;
    struct path path;
 
    // Get the filename from the registers
    filename = (char *)regs->si;
 
    // Get the current working directory
    get_fs_pwd(current->fs, &path);
    dentry_path_raw(path.dentry, cwd, MAX_PATH_LEN);
 
    // Check if the filename starts with the current working directory
    if (strncmp(filename, cwd, strlen(cwd)) == 0) {
        // Print the filename to the kernel log
        printk(KERN_INFO "[+] openat() called for file: %s\n", filename);
    }
 
    // Call the original openat syscall
    ret = original_openat(regs);
 
    return ret;
}


asmlinkage long new_rename(const char __user *oldname, const char __user *newname) {
    char kernel_oldname[MAX_PATH_LEN];
    char kernel_newname[MAX_PATH_LEN];

    if (!copy_from_user(kernel_oldname, oldname, MAX_PATH_LEN)) {
        kernel_oldname[MAX_PATH_LEN - 1] = '\0';  // Ensure null-termination
    } else {
        strcpy(kernel_oldname, "UNKNOWN_OLD_PATH");
    }

    if (!copy_from_user(kernel_newname, newname, MAX_PATH_LEN)) {
        kernel_newname[MAX_PATH_LEN - 1] = '\0';  // Ensure null-termination
    } else {
        strcpy(kernel_newname, "UNKNOWN_NEW_PATH");
    }

    printk(KERN_INFO "[+] rename() called by PID: %d, Process: %s ===> file %s renamed to %s\n",
           current->pid, current->group_leader->comm, kernel_oldname, kernel_newname);

    return original_rename(oldname, newname);
}

asmlinkage long new_renameat(int olddirfd, const char __user *oldpath, int newdirfd, const char __user *newpath) {
    char kernel_oldpath[MAX_PATH_LEN];
    char kernel_newpath[MAX_PATH_LEN];

    if (!copy_from_user(kernel_oldpath, oldpath, MAX_PATH_LEN)) {
        kernel_oldpath[MAX_PATH_LEN - 1] = '\0';  // Ensure null-termination
    } else {
        strcpy(kernel_oldpath, "UNKNOWN_OLD_PATH");
    }

    if (!copy_from_user(kernel_newpath, newpath, MAX_PATH_LEN)) {
        kernel_newpath[MAX_PATH_LEN - 1] = '\0';  // Ensure null-termination
    } else {
        strcpy(kernel_newpath, "UNKNOWN_NEW_PATH");
    }

    printk(KERN_INFO "[+] renameat() called by PID: %d, Process: %s ===> file %s renamed to %s\n",
           current->pid, current->group_leader->comm, kernel_oldpath, kernel_newpath);

    return original_renameat(olddirfd, oldpath, newdirfd, newpath);
}

asmlinkage long new_brk(unsigned long brk) {
    printk(KERN_INFO "[+] brk() called by PID: %d, Process: %s ===> requested break at address: %lx\n",
           current->pid, current->comm, brk);

    return original_brk(brk);
}


asmlinkage long new_mmap(struct pt_regs *regs) {
    unsigned long addr = regs->di;
    unsigned long length = regs->si;
    unsigned long prot = regs->dx;
    unsigned long flags = regs->r10;
    unsigned long fd = regs->r8;
    unsigned long offset = regs->r9;

    printk(KERN_INFO "[+] mmap() called by PID: %d, Process: %s ===> addr: %lx, length: %lx, prot: %lx, flags: %lx, fd: %lx, offset: %lx\n",
           current->pid, current->comm, addr, length, prot, flags, fd, offset);
      return original_mmap(regs);
}

asmlinkage long new_munmap(unsigned long addr, size_t length) {
    printk(KERN_INFO "[+] munmap() called by PID: %d, Process: %s ===> addr: %lx, length: %zx\n",
           current->pid, current->comm, addr, length);

    return original_munmap(addr, length);
}

asmlinkage long new_mprotect(unsigned long start, size_t len, unsigned long prot) {
    printk(KERN_INFO "[+] mprotect() called by PID: %d, Process: %s ===> start: %lx, length: %zx, protection: %lx\n",
           current->pid, current->comm, start, len, prot);

    return original_mprotect(start, len, prot);
}

asmlinkage ssize_t new_read(int fd, void *buf, size_t count) {
    ssize_t ret;
    struct file *file;
    char *filename = NULL;
    struct task_struct *parent_task;

    ret = original_read(fd, buf, count);

    file = fget(fd);
    if (file) {
        filename = kmalloc(PATH_MAX, GFP_KERNEL);
        if (filename) {
            filename = d_path(&file->f_path, filename, PATH_MAX);
        }
        fput(file);
    }

    parent_task = current->real_parent;

    // Check if the parent process is a common shell
    if (parent_task && (strcmp(parent_task->comm, "bash") == 0 || 
                        strcmp(parent_task->comm, "sh") == 0 || 
                        strcmp(parent_task->comm, "zsh") == 0)) {
        printk(KERN_INFO "[+] read() called by PID: %d, Process: %s ===> file descriptor %d for file %s, read %zd bytes\n",
               current->pid, current->comm, fd, filename, ret);
    }

    if (filename) {
        kfree(filename);
    }

    return ret;
}

asmlinkage long new_clone(struct pt_regs *regs) {
    long ret;

    // Call the original clone syscall first
    ret = original_clone(regs);

    // If the return value is 0, then we are in the child process
    if (ret == 0) {
        printk(KERN_INFO "[+] clone() created a new child process with PID: %d by parent %s\n", current->pid, current->comm);
    }

    return ret;
}

asmlinkage long new_fork(struct pt_regs *regs) {
    printk(KERN_INFO "[+] fork() called by PID: %d, Process: %s\n", current->pid, current->comm);
    return original_fork(regs);
}


asmlinkage long new_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp) {
    printk(KERN_INFO "[+] execve() called by PID: %d, Process: %s to execute: %s\n", current->pid, current->comm, filename);
    return original_execve(filename, argv, envp);
}

asmlinkage void new_exit(struct pt_regs *regs) {
    int error_code = regs->di;  // Assuming the error_code is the first argument
printk(KERN_INFO "[+] exit() called by PID: %d, Process: %s with exit code: %d\n", current->pid, current->comm, error_code);
    original_exit(regs);
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
    //original_openat = (void *)syscall_table[__NR_openat];
    //syscall_table[__NR_openat] = &new_openat;

	original_rename = (void *)syscall_table[__NR_rename];
	syscall_table[__NR_rename] = &new_rename;
	original_renameat = (void *)syscall_table[__NR_renameat];
	syscall_table[__NR_renameat] = &new_renameat;
	//original_brk = (void *)syscall_table[__NR_brk];
	//syscall_table[__NR_brk] = &new_brk;
	//original_mmap = (void *)syscall_table[__NR_mmap];
	//syscall_table[__NR_mmap] = &new_mmap;
	//original_munmap = (void *)syscall_table[__NR_munmap];
	//syscall_table[__NR_munmap] = &new_munmap;
	//original_mprotect = (void *)syscall_table[__NR_mprotect];
	//syscall_table[__NR_mprotect] = &new_mprotect;
	//original_read = (void *)syscall_table[__NR_read];
	//syscall_table[__NR_read] = &new_read;
	original_clone = (void *)syscall_table[__NR_clone];
	syscall_table[__NR_clone] = &new_clone;
	original_fork = (void *)syscall_table[__NR_fork];
	syscall_table[__NR_fork] = &new_fork;
	original_execve = (void *)syscall_table[__NR_execve];
	syscall_table[__NR_execve] = &new_execve;
	original_exit = (void *)syscall_table[__NR_exit];
	syscall_table[__NR_exit] = &new_exit;








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
    
    //syscall_table[__NR_openat] = original_openat;
    syscall_table[__NR_rename] = original_rename;
    syscall_table[__NR_renameat] = original_renameat;
    //syscall_table[__NR_brk] = original_brk;
    //syscall_table[__NR_mmap] = original_mmap;
    //syscall_table[__NR_munmap] = original_munmap;
    //syscall_table[__NR_mprotect] = original_mprotect;
    //syscall_table[__NR_read] = original_read;
    syscall_table[__NR_clone] = original_clone;
    syscall_table[__NR_fork] = original_fork;
    syscall_table[__NR_execve] = original_execve;
    syscall_table[__NR_exit] = original_exit;




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
