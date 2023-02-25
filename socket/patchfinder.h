#ifndef PATCHFINDER_H
#define PATCHFINDER_H

#include <stdint.h>
#include <string.h>

#include <mach-o/nlist.h>
#include <mach-o/dyld.h>
#include <mach-o/fat.h>
#include <mach/vm_types.h>

// Helper gadget.
uint32_t find_memmove(uint32_t region, uint8_t* kdata, size_t ksize);

// Use for write-anywhere gadget.
uint32_t find_str_r1_r2_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);

// Helper gadget.
uint32_t find_mov_r0_r1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mov_r0_0_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mov_r0_1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);

// Use for read-anywhere gadget.
uint32_t find_ldr_r0_r1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);

// Helper gadget for changing page tables / patching.
uint32_t find_flush_dcache(uint32_t region, uint8_t* kdata, size_t ksize);

// Helper gadget for changing page tables.
uint32_t find_invalidate_tlb(uint32_t region, uint8_t* kdata, size_t ksize);

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 0 here.
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 0 here.
uint32_t find_vnode_enforce(uint32_t region, uint8_t* kdata, size_t ksize);

// Write 1 here.
uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize);

// Change this to what you want the value to be (non-zero appears to work).
uint32_t find_i_can_has_debugger_2_90(uint32_t region, uint8_t* kdata, size_t ksize);

// Utility function, necessary for the sandbox hook.
uint32_t find_vn_getpath(uint32_t region, uint8_t* kdata, size_t ksize);

// Utility function, necessary for the sandbox hook.
uint32_t find_memcmp(uint32_t region, uint8_t* kdata, size_t ksize);

// Dereference this, add 0x38 to the resulting pointer, and write whatever boot-args are suitable to affect kern.bootargs.
uint32_t find_p_bootargs(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_p_bootargs_generic(uint32_t region, uint8_t* kdata, size_t ksize);

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t find_syscall0(uint32_t region, uint8_t* kdata, size_t ksize);

// Function to copy strings to the kernel
uint32_t find_copyinstr(uint32_t region, uint8_t* kdata, size_t ksize);

/* ios 10 */
void* find_sym(struct mach_header *mh, const char *name);
uint32_t find_kextbase(void *kernelcache, size_t size);

uint32_t find_pid_check(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_convert_port_to_locked_task(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount_103(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_enter_103(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect_103(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops_103(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_fault_enter_103(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_mapForIO_103(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_execve_ret(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sandbox_call_i_can_has_debugger_103(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_i_can_has_debugger_1_103(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_2_103(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_amfi_cred_label_update_execve(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_vnode_check_signature(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_loadEntitlementsFromVnode(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_vnode_check_exec(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_lwvm_i_can_has_krnl_conf_stub(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vfs_context_current(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vnode_getattr(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_allproc(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_kernel_pmap(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_patch(uint32_t region, uint8_t* kdata, size_t ksize);

uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize);
#endif
