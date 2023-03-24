a collection of tests and random bits that will eventually make up a rootkit


/ARM_write_protect_disable - flip write protection bit of vaddr through pagetable
/direct_hook_test - system call hooking via directly over-writing sys_call_table
    - some useful header files here
        -> resolve_kallsyms.h: does exactly as youd expect, uses kprobes to find kallsyms_lookup_name and then uses that to resolve syms
        -> set_page_flags.h: given a vaddr, set its corresponding PTEs flags
        -> direct_syscall_hook.h: ftrace-like wrapper for direct hooking of sys_call_table
/fg-kaslr_test - fg-kaslr bypass, this isnt actually anything important i was just using pr_info wrong
/ftrace_hook_epic_fail - FTRACE_OPS_FL_SAVE_REGS is not supported on arm64 and i spent 2 days debugging this, however this will work on x86
/phe - partial homomorphic encryption of LKM, unfinished
/exception_handler hooking - THIS IS THE COOLEST ONE, hooks exception handler and redirects to 2 different tables based on syscall #, original table unmodified
/assembler - assembles mov absolute address for shellcode generation on the fly without leaving kernelmode !

todo:
- dropper
- find fg-kaslr offsets via bootkit
- overwrite ftrace records
- integrate functionality of my other projects into this one
- finish rk scanner hiding via PHE
- process hiding from usermode
- network connection hiding from usermode
- redirect entire sys_call_table
- use OP-TEE to hide functions




new exception hooking process:
copy (el0_svc_common entry, length x) -> hooked_el0_svc_common
copy shellcode (jmp hooked_el0_svc_common, length x) -> el0_svc_common

el0_svc_common entry
0 ---------------
jmp hooked_el0_svc_common
x ---------------
el0_svc_common body

>>>>>>>>>>>

hooked_el0_svc_common entry
0 ---------------
OVERWRITTEN el0_svc_common body
x ---------------
set sys_call_table to new addr
jmp el0_svc_common entry + x
