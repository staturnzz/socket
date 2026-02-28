//
//  patchfinder.h
//  socket
//
//  Created by staturnz on 2/27/26.
//

#ifndef patchfinder_h
#define patchfinder_h

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mov_r0_1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_pid_check(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_convert_port_to_locked_task(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_convert_port_to_locked_task(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mount_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_enter(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_map_protect(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vm_fault_enter(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_cred_label_update_execve(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_vnode_check_signature(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_loadEntitlementsFromVnode(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_vnode_check_exec(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_mapForIO(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sandbox_call_i_can_has_debugger(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vfs_context_current(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_vnode_getattr(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_kernel_pmap(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_lwvm_i_can_has_krnl_conf_stub(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_sb_disable(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_cs_system_require_lv(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_amfi_cs_flags_patch(uint32_t region, uint8_t* kdata, size_t ksize);
uint32_t find_invalidate_icache(uint32_t region, uint8_t *kdata, size_t ksize);
uint32_t find_flush_dcache(uint32_t region, uint8_t *kdata, size_t ksize);
uint32_t find_kcall_gadget(uint32_t region, uint8_t *kdata, size_t ksize);
uint32_t find_priv_realhost(uint32_t region, uint8_t *kdata, size_t ksize);

#endif /* patchfinder_h */
