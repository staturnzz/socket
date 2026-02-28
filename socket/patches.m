//
//  patches.c
//  socket
//
//  Created by staturnz on 2/27/26.
//

#include <Foundation/Foundation.h>
#include "exploit/oob_entry.h"
#include "exploit/memory.h"
#include "exploit/util.h"
#include "patchfinder.h"
#include "patches.h"
#include "util.h"

static uint8_t *kernel_data = NULL;
static size_t kernel_data_size = 0;
static patches_t *patches = NULL;

uint32_t find_patch_offset(uint32_t (*func)(uint32_t, uint8_t *, size_t)) {
    uint32_t addr = func(kinfo->kernel_base, kernel_data, kernel_data_size);
    if (addr <= 0xffff) return 0;
    if ((addr & 0x80000000) == 0x80000000) return addr;
    return addr + 0x80001000;
}

static void phys_set_nop(uint32_t pa, uint32_t count) {
    uint32_t size = count * 0x2;
    uint16_t *buf = calloc(1, size);
    for (uint32_t i = 0; i < count; i++) {
        buf[i] = 0xbf00;
    }
    
    physwrite_buf(pa, buf, size);
    free(buf);
}

int apply_patches(void) {
    kernel_data_size = 0x1800000;
    kernel_data = calloc(1, kernel_data_size);
    patches = calloc(1, sizeof(patches_t));
    physread_buf(0x80001000, kernel_data, kernel_data_size);
    
    {
#if 0
        printf("testing patchfinder...\n");
        printf("proc_enforce: 0x%x\n", find_patch_offset(find_proc_enforce));
        printf("ret1_gadget: 0x%x\n", find_patch_offset(find_mov_r0_1_bx_lr));
        printf("pid_check: 0x%x\n", find_patch_offset(find_pid_check));
        printf("i_can_has_debugger_1: 0x%x\n", find_patch_offset(find_i_can_has_debugger_1));
        printf("i_can_has_debugger_2: 0x%x\n", find_patch_offset(find_i_can_has_debugger_2));
        printf("mount_patch: 0x%x\n", find_patch_offset(find_mount_patch));
        printf("vm_map_enter: 0x%x\n", find_patch_offset(find_vm_map_enter));
        printf("vm_map_protect: 0x%x\n", find_patch_offset(find_vm_map_protect));
        printf("vm_fault_enter: 0x%x\n", find_patch_offset(find_vm_fault_enter));
        printf("csops_patch: 0x%x\n", find_patch_offset(find_csops));
        printf("amfi_cred_label_update_execve: 0x%x\n", find_patch_offset(find_amfi_cred_label_update_execve));
        printf("amfi_vnode_check_signature: 0x%x\n", find_patch_offset(find_amfi_vnode_check_signature));
        printf("amfi_loadEntitlementsFromVnode: 0x%x\n", find_patch_offset(find_amfi_loadEntitlementsFromVnode));
        printf("amfi_vnode_check_exec: 0x%x\n", find_patch_offset(find_amfi_vnode_check_exec));
        printf("mapForIO: 0x%x\n", find_patch_offset(find_mapForIO));
        printf("sbcall_debugger: 0x%x\n", find_patch_offset(find_sandbox_call_i_can_has_debugger));
        printf("vfsContextCurrent: 0x%x\n", find_patch_offset(find_vfs_context_current));
        printf("vnodeGetattr: 0x%x\n", find_patch_offset(find_vnode_getattr));
        printf("kernelConfig_stub: 0x%x\n", find_patch_offset(find_lwvm_i_can_has_krnl_conf_stub));
        printf("sb_ops: 0x%x\n", find_patch_offset(find_sbops));
        printf("sb_disable: 0x%x\n", find_patch_offset(find_sb_disable));
        printf("cs_system_require_lv: 0x%x\n", find_patch_offset(find_cs_system_require_lv));
        printf("amfi_cs_flags_patch: 0x%x\n", find_patch_offset(find_amfi_cs_flags_patch));
        exit(0);
#endif
    }
    
    if ((patches->proc_enforce = find_patch_offset(find_proc_enforce)) == 0) return 1;
    if (physread32(patches->proc_enforce) == 0) return 0;
    
    if (kinfo->version[1] == 3) {
        if ((patches->locked_task = find_patch_offset(find_convert_port_to_locked_task)) == 0) return 4;
        if ((patches->sb_disable = find_patch_offset(find_sb_disable)) == 0) return 22;
        patches->sb_disable_size = (physread16(patches->sb_disable + 0x2) == 0x4625) ? 0x2 : 0x4;
    }
    
    if ((patches->ret1_gadget = find_patch_offset(find_mov_r0_1_bx_lr)) == 0) return 2;
    if ((patches->pid_check = find_patch_offset(find_pid_check)) == 0) return 3;
    if ((patches->i_can_has_debugger_1 = find_patch_offset(find_i_can_has_debugger_1)) == 0) return 5;
    if ((patches->i_can_has_debugger_2 = find_patch_offset(find_i_can_has_debugger_2)) == 0) return 6;
    if ((patches->mount_patch = find_patch_offset(find_mount_patch)) == 0) return 7;
    if ((patches->vm_map_enter = find_patch_offset(find_vm_map_enter)) == 0) return 8;
    if ((patches->vm_map_protect = find_patch_offset(find_vm_map_protect)) == 0) return 9;
    if ((patches->vm_fault_enter = find_patch_offset(find_vm_fault_enter)) == 0) return 10;
    if ((patches->csops_patch = find_patch_offset(find_csops)) == 0) return 11;
    if ((patches->amfi_cred_label_update_execve = find_patch_offset(find_amfi_cred_label_update_execve)) == 0) return 12;
    if ((patches->amfi_vnode_check_signature = find_patch_offset(find_amfi_vnode_check_signature)) == 0) return 13;
    if ((patches->amfi_loadEntitlementsFromVnode = find_patch_offset(find_amfi_loadEntitlementsFromVnode)) == 0) return 14;
    if ((patches->amfi_vnode_check_exec = find_patch_offset(find_amfi_vnode_check_exec)) == 0) return 15;
    if ((patches->mapForIO = find_patch_offset(find_mapForIO)) == 0) return 16;
    if ((patches->sbcall_debugger = find_patch_offset(find_sandbox_call_i_can_has_debugger)) == 0) return 17;
    if ((patches->vfsContextCurrent = find_patch_offset(find_vfs_context_current)) == 0) return 18;
    if ((patches->vnodeGetattr = find_patch_offset(find_vnode_getattr)) == 0) return 19;
    if ((patches->kernelConfig_stub = find_patch_offset(find_lwvm_i_can_has_krnl_conf_stub)) == 0) return 20;
    if ((patches->sb_ops = find_patch_offset(find_sbops)) == 0) return 21;
    if ((patches->cs_system_require_lv = find_patch_offset(find_cs_system_require_lv)) == 0) return 23;
    if ((patches->amfi_cs_flags_patch = find_patch_offset(find_amfi_cs_flags_patch)) == 0) return 24;
    patches->csops_patch_size = ((physread16(patches->csops_patch + 0x2) & 0xF8FF) == 0x2000) ? 0x4 : 0x6;
    
    
    printf("-- proc_enforce: 0x%x\n", patches->proc_enforce);
    printf("-- locked_task: 0x%x\n", patches->locked_task);
    printf("-- ret1_gadget: 0x%x\n", patches->ret1_gadget);
    printf("-- i_can_has_debugger_1: 0x%x\n", patches->i_can_has_debugger_1);
    printf("-- i_can_has_debugger_2: 0x%x\n", patches->i_can_has_debugger_2);
    printf("-- mount_patch: 0x%x\n", patches->mount_patch);
    printf("-- vm_map_enter: 0x%x\n", patches->vm_map_enter);
    printf("-- vm_map_protect: 0x%x\n", patches->vm_map_protect);
    printf("-- vm_fault_enter: 0x%x\n", patches->vm_fault_enter);
    printf("-- csops_patch: 0x%x\n", patches->csops_patch);
    printf("-- amfi_cred_label_update_execve: 0x%x\n", patches->amfi_cred_label_update_execve);
    printf("-- amfi_vnode_check_signature: 0x%x\n", patches->amfi_vnode_check_signature);
    printf("-- amfi_loadEntitlementsFromVnode: 0x%x\n", patches->amfi_loadEntitlementsFromVnode);
    printf("-- amfi_vnode_check_exec: 0x%x\n", patches->amfi_vnode_check_exec);
    printf("-- mapForIO: 0x%x\n", patches->mapForIO);
    printf("-- sbcall_debugger: 0x%x\n", patches->sbcall_debugger);
    printf("-- vfsContextCurrent: 0x%x\n", patches->vfsContextCurrent);
    printf("-- vnodeGetattr: 0x%x\n", patches->vnodeGetattr);
    printf("-- kernelConfig_stub: 0x%x\n", patches->kernelConfig_stub);
    printf("-- sb_ops: 0x%x\n", patches->sb_ops);
    printf("-- sb_disable: 0x%x\n", patches->sb_disable);
    printf("-- cs_system_require_lv: 0x%x\n", patches->cs_system_require_lv);
    printf("-- amfi_cs_flags_patch: 0x%x\n", patches->amfi_cs_flags_patch);
    printf("-- sb_disable_size: 0x%x\n", patches->sb_disable_size);
    printf("-- csops_patch_size: 0x%x\n", patches->csops_patch_size);

    /*
        issues:
            - csops find wrong addr?
     
     
     */

    physwrite32(patches->proc_enforce, 0);
    printf("proc_enforce: patched\n");
    
    physwrite32(patches->i_can_has_debugger_1, 1);
    physwrite32(patches->i_can_has_debugger_2, 1);
    physwrite32(patches->vm_fault_enter, 0x0b01f04f);
    physwrite32(patches->vm_map_enter, 0xbf00bf00);
    physwrite32(patches->vm_map_protect, 0xbf00bf00);
    physwrite16(patches->cs_system_require_lv, 0x2000);

    if (patches->csops_patch_size == 0x6) {
        physwrite32(patches->csops_patch, 0xbf00bf00);
        physwrite16(patches->csops_patch+0x4, 0xbf00);
    } else {
        physwrite32(patches->csops_patch, 0xbf00bf00);
    }

    physwrite8(patches->mount_patch+0x1, 0xe0);
    physwrite32(patches->mapForIO, 0xbf002000);
    physwrite32(patches->mapForIO+0x4, 0xbf00bf00);
    physwrite32(patches->kernelConfig_stub, patches->ret1_gadget + kinfo->kernel_slide);
    physwrite32(patches->sbcall_debugger, 0xbf00bf00);
    physwrite16(patches->pid_check, 0xbf00);

    if (kinfo->version[1] == 3) {
        if (patches->sb_disable_size == 0x4) {
            physwrite32(patches->sb_disable, 0xbf00bf00);
        } else {
            physwrite16(patches->sb_disable, 0xbf00);
        }
        physwrite8(patches->locked_task+0x1, 0xe0);
    }
    
    uint16_t amfi_patch_data[] = {
        0xF421, 0x517C, 0x4620, 0xF041, 0x6180,
        0xF041, 0x010F, 0xF8CA, 0x1000,
    };
    
    physwrite_buf(patches->amfi_cs_flags_patch, amfi_patch_data, sizeof(amfi_patch_data));
    phys_set_nop(patches->amfi_cred_label_update_execve, 2);
    physwrite32(patches->amfi_cred_label_update_execve+0x5, 0xe0);
    phys_set_nop(patches->amfi_vnode_check_signature, 10);
    phys_set_nop(patches->amfi_loadEntitlementsFromVnode, 3);
    physwrite16(patches->amfi_loadEntitlementsFromVnode+0x6, 0x2001);
    phys_set_nop(patches->amfi_vnode_check_exec, 6);
   
    
    uint32_t mpo_execve = patches->sb_ops + offsetof(mac_policy_ops_t, mpo_cred_label_update_execve);
    uint32_t mpo_execve_ptr = physread32(mpo_execve);
    uint32_t mpo_execve_start = (uint32_t)mpo_execve_hook_start & ~0x1;
    uint32_t mpo_execve_end = (uint32_t)mpo_execve_hook_end & ~0x1;
    uint32_t mpo_execve_size = mpo_execve_end - mpo_execve_start;
    mpo_execve_size += (mpo_execve_size % 4);

    uint32_t shc_addr = kinfo->kernel_base + 0xd00;
    uint8_t *shc_data = calloc(1, mpo_execve_size);
    memcpy(shc_data, (void *)mpo_execve_start, mpo_execve_size);

    *(uint32_t *)(shc_data+0x160) = (patches->vfsContextCurrent + kinfo->kernel_slide) | 0x1;
    *(uint32_t *)(shc_data+0x164) = (patches->vnodeGetattr + kinfo->kernel_slide) | 0x1;
    *(uint32_t *)(shc_data+0x168) = mpo_execve_ptr;

    physwrite_buf(shc_addr - kinfo->kernel_slide, shc_data, mpo_execve_size);
    uint8_t *mpo_mapped = map_data(patches->sb_ops & ~0xfff, 0x4000, VM_PROT_READ|VM_PROT_WRITE);
    uint32_t mpo_offset = (patches->sb_ops & 0xfff);
    *(volatile uint32_t *)(mpo_mapped + mpo_offset + offsetof(mac_policy_ops_t, mpo_cred_label_update_execve)) = (shc_addr | 0x1);

    patch_mpo(mpo_mount_check_mount);
    patch_mpo(mpo_mount_check_remount);
    patch_mpo(mpo_mount_check_umount);
    patch_mpo(mpo_vnode_check_write);
    patch_mpo(mpo_file_check_mmap);
    patch_mpo(mpo_vnode_check_rename);
    patch_mpo(mpo_vnode_check_access);
    patch_mpo(mpo_vnode_check_chroot);
    patch_mpo(mpo_vnode_check_create);
    patch_mpo(mpo_vnode_check_deleteextattr);
    patch_mpo(mpo_vnode_check_exchangedata);
    patch_mpo(mpo_vnode_check_exec);
    patch_mpo(mpo_vnode_check_getattrlist);
    patch_mpo(mpo_vnode_check_getextattr);
    patch_mpo(mpo_vnode_check_ioctl);
    patch_mpo(mpo_vnode_check_link);
    patch_mpo(mpo_vnode_check_listextattr);
    patch_mpo(mpo_vnode_check_open);
    patch_mpo(mpo_vnode_check_readlink);
    patch_mpo(mpo_vnode_check_setattrlist);
    patch_mpo(mpo_vnode_check_setextattr);
    patch_mpo(mpo_vnode_check_setflags);
    patch_mpo(mpo_vnode_check_setmode);
    patch_mpo(mpo_vnode_check_setowner);
    patch_mpo(mpo_vnode_check_setutimes);
    patch_mpo(mpo_vnode_check_stat);
    patch_mpo(mpo_vnode_check_truncate);
    patch_mpo(mpo_vnode_check_unlink);
    patch_mpo(mpo_vnode_notify_create);
    patch_mpo(mpo_vnode_check_fsgetpath);
    patch_mpo(mpo_vnode_check_getattr);
    patch_mpo(mpo_mount_check_stat);
    patch_mpo(mpo_proc_check_setauid);
    patch_mpo(mpo_proc_check_getauid);
    patch_mpo(mpo_proc_check_fork);
    patch_mpo(mpo_proc_check_get_cs_info);
    patch_mpo(mpo_proc_check_set_cs_info);
    printf("mpo: patched\n");

    usleep(100000);
    for (uint32_t i = 0; i < 1000; i++) {
        sync();
        usleep(1);
    }
    
   // free(shc_data);
    free(kernel_data);
    kernel_data = NULL;
    kernel_data_size = 0;
    return 0;
}
