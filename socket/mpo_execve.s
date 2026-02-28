.align 4
.global _mpo_execve_hook_start, _mpo_execve_hook_end

.thumb
.thumb_func
_mpo_execve_hook_start:
    cmp     r3, #0
    it eq
    beq     _mpo_cred_label_update_execve_stub
    b       _mpo_execve_hook
    
_mpo_execve_hook:
    push    {r4, r5, r6, r7, lr}
    add     r7, sp, #0xc
    push.w  {r8, sl, fp}
    sub     sp, #0x1d8
    mov     r4, sp
    bfc     r4, #0x0, #0x3
    mov     sp, r4
    ldr.w   sb, [r7, #0xc]
    ldr.w   ip, [r7, #0x8]
    ldr.w   lr, [r7, #0x2c]
    ldr     r4, [r7, #0x28]
    ldr     r5, [r7, #0x24]
    ldr     r6, [r7, #0x20]
    ldr.w   r8, [r7, #0x1c]
    ldr.w   sl, [r7, #0x18]
    ldr.w   fp, [r7, #0x14]
    str     r0, [sp, #0x68]
    ldr     r0, [r7, #0x10]
    str     r0, [sp, #0x64]
    ldr     r0, [sp, #0x68]
    str     r0, [sp, #0x60]
    add     r0, sp, #0x74
    str     r0, [sp, #0x5c]
    movs    r0, #0x0
    str     r0, [sp, #0x58]
    ldr     r0, [sp, #0x60]
    str     r0, [sp, #0x1d4]
    str     r1, [sp, #0x1d0]
    str     r2, [sp, #0x1cc]
    str     r3, [sp, #0x1c8]
    str.w   sb, [sp, #0x1c4]
    str.w   ip, [sp, #0x1c0]
    str.w   fp, [sp, #0x54]
    str.w   r8, [sp, #0x50]
    str.w   sl, [sp, #0x4c]
    str     r6, [sp, #0x48]
    str     r5, [sp, #0x44]
    str.w   lr, [sp, #0x40]
    str     r4, [sp, #0x3c]
    
    bl      _vfs_context_current_stub
    str     r0, [sp, #0x70]
    movs    r0, #0x0
    str     r0, [sp, #0x78]
    str     r0, [sp, #0x74]
    str     r0, [sp, #0x80]
    mov     r0, #0x380
    
    str     r0, [sp, #0x7c]
    ldr     r0, [sp, #0x58]
    str     r0, [sp, #0x84]
    ldr     r0, [sp, #0x1c8]
    ldr     r2, [sp, #0x70]
    ldr     r1, [sp, #0x5c]
    bl      _vnode_getattr_stub
    str     r0, [sp, #0x1bc]
    cmp     r0, #0x0
    bne     L_call_orig
    
    movs    r0, #0x0
    str     r0, [sp, #0x6c]
    ldrh.w  r0, [sp, #0xc0]
    and     r0, r0, #0x800
    cmp     r0, #0x0
    beq.n   L_handle_gid
    
    movs    r0, #0x1
    ldr     r1, [sp, #0xb8]
    ldr     r2, [sp, #0x1d0]
    str     r1, [r2, #0xc]
    str     r0, [sp, #0x6c]


L_handle_gid:
    ldrh.w  r0, [sp, #0xc0]
    and     r0, r0, #0x400
    cmp     r0, #0x0
    beq.n   L_handle_flags

    movs    r0, #0x1
    ldr     r1, [sp, #0xbc]
    ldr     r2, [sp, #0x1d0]
    str     r1, [r2, #0x1c]
    str     r0, [sp, #0x6c]


L_handle_flags:
    ldr     r0, [sp, #0x6c]
    cmp     r0, #0x0
    beq.n   L_call_orig

    ldr     r0, [sp, #0x1cc]
    ldr.w   r0, [r0, #0xbc]
    orr     r0, r0, #0x100
    ldr     r1, [sp, #0x1cc]
    str.w   r0, [r1, #0xbc]

L_call_orig:
    ldr     r0, [sp, #0x1d4]
    ldr     r1, [sp, #0x1d0]
    ldr     r2, [sp, #0x1cc]
    ldr     r3, [sp, #0x1c8]
    ldr.w   sb, [sp, #0x1c0]
    ldr.w   ip, [sp, #0x1c4]
    ldr.w   lr, [r7, #0x10]
    ldr     r4, [r7, #0x14]
    ldr     r5, [r7, #0x18]
    ldr     r6, [r7, #0x1c]
    ldr.w   r8, [r7, #0x20]
    ldr.w   sl, [r7, #0x24]
    ldr.w   fp, [r7, #0x28]
    str     r0, [sp, #0x38]
    ldr     r0, [r7, #0x2c]
    str     r0, [sp, #0x34]
    mov     r0, sp
    str     r0, [sp, #0x30]
    ldr     r0, [sp, #0x34]
    str     r1, [sp, #0x2c]
    ldr     r1, [sp, #0x30]
    str     r0, [r1, #0x24]
    str.w   fp, [r1, #0x20]
    str.w   sl, [r1, #0x1c]
    str.w   r8, [r1, #0x18]
    str     r6, [r1, #0x14]
    str     r5, [r1, #0x10]
    str     r4, [r1, #0xc]
    str.w   lr, [r1, #0x8]
    str.w   ip, [r1, #0x4]
    str.w   sb, [r1]
    ldr     r0, [sp, #0x38]
    ldr     r1, [sp, #0x2c]
    bl      _mpo_cred_label_update_execve_stub
    sub.w   r4, r7, #0x18
    mov     sp, r4
    pop.w   {r8, sl, fp}
    pop     {r4, r5, r6, r7, pc}
    
    
_vfs_context_current_stub:
    adr     r0, _vfs_context_current
    ldr     r0, [r0]
    bx      r0

_vnode_getattr_stub:
    adr     r3, _vnode_getattr
    ldr     r3, [r3]
    bx      r3

_mpo_cred_label_update_execve_stub:
    adr     sb, _mpo_cred_label_update_execve
    ldr.w   ip, [sb]
    bx      ip

    
_vfs_context_current:
.long 0x41414141

_vnode_getattr:
.long 0x42424242

_mpo_cred_label_update_execve:
.long 0x43434343
    
_mpo_execve_hook_end:
.long 0x13371337

