//
//  patchfinder.c
//  socket
//
//  Created by staturnz on 2/27/26.
//

#include "patchfinder.h"
#include "exploit/oob_entry.h"
#include "exploit/memory.h"
#include "exploit/util.h"

static uint32_t bit_range(uint32_t x, int start, int end) {
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places) {
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12) {
    if(bit_range(imm12, 11, 10) == 0) {
        switch(bit_range(imm12, 9, 8)) {
            case 0:
                return bit_range(imm12, 7, 0);
            case 1:
                return (bit_range(imm12, 7, 0) << 16) | bit_range(imm12, 7, 0);
            case 2:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 8);
            case 3:
                return (bit_range(imm12, 7, 0) << 24) | (bit_range(imm12, 7, 0) << 16) | (bit_range(imm12, 7, 0) << 8) | bit_range(imm12, 7, 0);
            default:
                return 0;
        }
    } else {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

static int insn_is_32bit(uint16_t* i) {
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

static int insn_is_bl(uint16_t* i) {
    if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd000) == 0xd000)
        return 1;
    else if((*i & 0xf800) == 0xf000 && (*(i + 1) & 0xd001) == 0xc000)
        return 1;
    else
        return 0;
}

static uint32_t insn_bl_imm32(uint16_t* i) {
    uint16_t insn0 = *i;
    uint16_t insn1 = *(i + 1);
    uint32_t s = (insn0 >> 10) & 1;
    uint32_t j1 = (insn1 >> 13) & 1;
    uint32_t j2 = (insn1 >> 11) & 1;
    uint32_t i1 = ~(j1 ^ s) & 1;
    uint32_t i2 = ~(j2 ^ s) & 1;
    uint32_t imm10 = insn0 & 0x3ff;
    uint32_t imm11 = insn1 & 0x7ff;
    uint32_t imm32 = (imm11 << 1) | (imm10 << 12) | (i2 << 22) | (i1 << 23) | (s ? 0xff000000 : 0);
    return imm32;
}

static int insn_is_b_conditional(uint16_t* i) {
    return (*i & 0xF000) == 0xD000 && (*i & 0x0F00) != 0x0F00 && (*i & 0x0F00) != 0xE;
}

static int insn_is_b_unconditional(uint16_t* i) {
    if((*i & 0xF800) == 0xE000)
        return 1;
    else if((*i & 0xF800) == 0xF000 && (*(i + 1) & 0xD000) == 9)
        return 1;
    else
        return 0;
}

static int insn_is_ldr_literal(uint16_t* i) {
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

static int insn_ldr_literal_rt(uint16_t* i) {
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_ldr_literal_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

static int insn_ldr_imm_rt(uint16_t* i) {
    return (*i & 7);
}

static int insn_ldr_imm_rn(uint16_t* i) {
    return ((*i >> 3) & 7);
}

static int insn_ldr_imm_imm(uint16_t* i) {
    return ((*i >> 6) & 0x1F);
}


static int insn_ldrb_imm_rt(uint16_t* i) {
    return (*i & 7);
}

int insn_ldr_reg_rt(uint16_t* i) {
    if((*i & 0xFE00) == 0x5800)
        return *i & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_reg_rm(uint16_t* i) {
    if((*i & 0xFE00) == 0x5800)
        return (*i >> 6) & 0x7;
    else if((*i & 0xFFF0) == 0xF850 && (*(i + 1) & 0x0FC0) == 0x0000)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_add_reg(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

static int insn_add_reg_rd(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_add_reg_rn(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

static int insn_add_reg_rm(uint16_t* i) {
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

static int insn_is_movt(uint16_t* i) {
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

static int insn_movt_rd(uint16_t* i) {
    return (*(i + 1) >> 8) & 0xF;
}

static int insn_movt_imm(uint16_t* i) {
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

static int insn_is_mov_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

static int insn_mov_imm_rd(uint16_t* i) {
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

static int insn_mov_imm_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_is_push(uint16_t* i) {
    if((*i & 0xFE00) == 0xB400)
        return 1;
    else if(*i == 0xE92D)
        return 1;
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1;
    else
        return 0;
}

static int insn_push_registers(uint16_t* i) {
    if((*i & 0xFE00) == 0xB400)
        return (*i & 0x00FF) | ((*i & 0x0100) << 6);
    else if(*i == 0xE92D)
        return *(i + 1);
    else if(*i == 0xF84D && (*(i + 1) & 0x0FFF) == 0x0D04)
        return 1 << ((*(i + 1) >> 12) & 0xF);
    else
        return 0;
}

static int insn_is_preamble_push(uint16_t* i) {
    return insn_is_push(i) && (insn_push_registers(i) & (1 << 14)) != 0;
}

static uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*)) {
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {--current_instruction;}
        if(match_func(current_instruction)) {return current_instruction;}
    }
    return NULL;
}

static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg) {
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if(insn_is_32bit(current_instruction - 2)) { current_instruction -= 2;
        } else { --current_instruction; }

        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {found = 1;break;}
        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {found = 1;break;}
    }

    if(!found) return 0;
    uint32_t value = 0;
    while((uintptr_t)current_instruction < (uintptr_t)insn) {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {
            value = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {
            value = *(uint32_t*)(kdata + (((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction)));
        } else if(insn_is_movt(current_instruction) && insn_movt_rd(current_instruction) == reg) {
            value |= insn_movt_imm(current_instruction) << 16;
        } else if(insn_is_add_reg(current_instruction) && insn_add_reg_rd(current_instruction) == reg) {
            if(insn_add_reg_rm(current_instruction) != 15 || insn_add_reg_rn(current_instruction) != reg) {return 0;}
            value += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return value;
}

static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address) {
    uint16_t* current_instruction = insn;
    uint32_t value[16] = {0};
    memset(value, 0, sizeof(value));

    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize)) {
        if(insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        } else if(insn_is_ldr_literal(current_instruction)) {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize)) {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        } else if(insn_is_movt(current_instruction)) {
            int reg = insn_movt_rd(current_instruction);
            value[reg] |= insn_movt_imm(current_instruction) << 16;
            if(value[reg] == address) {return current_instruction;}
        } else if(insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address) {return current_instruction;}
            }
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return NULL;
}

struct find_search_mask {
    uint16_t mask;
    uint16_t value;
};

static uint16_t* find_with_search_mask(uint32_t region, uint8_t* kdata, size_t ksize, int num_masks, const struct find_search_mask* masks) {
    uint16_t* end = (uint16_t*)(kdata + ksize - (num_masks * sizeof(uint16_t)));
    uint16_t* cur;
    for(cur = (uint16_t*) kdata; cur <= end; ++cur) {
        int matched = 1;
        int i;
        for(i = 0; i < num_masks; ++i) {
            if((*(cur + i) & masks[i].mask) != masks[i].value) {matched = 0;break;}
        }
        if(matched) return cur;
    }
    return NULL;
}

uint32_t find_mov_r0_1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x01, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint8_t* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on process operations", sizeof("Enforce MAC policy on process operations"));
    if(!proc_enforce_description) return 0;

    uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
    uint8_t* proc_enforce_description_ptr = memmem(kdata, ksize, &proc_enforce_description_address, sizeof(proc_enforce_description_address));
    if(!proc_enforce_description_ptr) return 0;

    uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *proc_enforce_ptr - region;
}

uint32_t find_i_can_has_debugger_2(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFD07, 0xB101},  // CBZ  R1, loc_xxx
        {0xFBF0, 0xF240},
        {0x8F00, 0x0100},
        {0xFBF0, 0xF2C0},
        {0xFF00, 0x0100},
        {0xFFFF, 0x4479},
        {0xF807, 0x6801},  // LDR  R1, [Ry,#X]
        {0xFF00, 0xE000}   // B  x
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) return 0;
    insn += 5;
    
    uint32_t value = find_pc_rel_value(region, kdata, ksize, insn, insn_ldrb_imm_rt(insn));
    if(!value) return 0;
    value +=4;
    return value + ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_pid_check(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xE9C0}, // strd rx, ry, [sp, #z]
        {0x0000, 0x0000},
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFF00, 0xD000}, // beq.n
        {0xF800, 0xF000}, // bl _port_name_to_task
        {0xF800, 0xF800},
        {0xF800, 0x9000}, // str rx, [sp, #y]
        {0xF800, 0x2800}  // cmp rx, #0
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 6 - ((uintptr_t)kdata);
}

uint32_t find_convert_port_to_locked_task(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xF800, 0x6800}, // ldr rx, [ry, #z] (y!=sp, z<0x80)
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry]
        {0x0FFF, 0x0000},
        {0xFF00, 0x4200}, // cmp rx, ry (x,y = r0~7)
        {0xFF00, 0xD100}, // bne.n
        {0xFFFF, 0xEE1D}, // mrc p15, #0, r0, c13, c0, #4
        {0xFFFF, 0x0F90}
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 8 - ((uintptr_t)kdata);
}

uint32_t find_mount_patch(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xF010}, // tst.w rx, #0x40
        {0xFFFF, 0x0F40},
        {0xFF00, 0xD000}, // beq.n
        {0xFFF0, 0xF010}, // tst.w rx, #0x1
        {0xFFFF, 0x0F01},
        {0xFF00, 0xD100}  // bne.n
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 4 - ((uintptr_t)kdata);
}

uint32_t find_vm_map_enter(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xF010}, // tst.w rz, #4
        {0xFFFF, 0x0F04},
        {0xFF00, 0x4600}, // mov rx, ry
        {0xFFF0, 0xBF10}, // it ne (?)
        {0xFFF0, 0xF020}, // bic.w rx, ry, #4
        {0xF0FF, 0x0004}
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 8 - ((uintptr_t)kdata);
}

uint32_t find_vm_map_protect(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFBF0, 0xF010}, // tst.w rx, #0x20000000
        {0x8F00, 0x0F00},
        {0xFF00, 0x4600}, // mov rx, ry
        {0xFFF0, 0xBF00}, // it eq
        {0xFFF0, 0xF020}, // bic.w rx, ry, #4
        {0xF0FF, 0x0004},
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFFF0, 0xBF00}, // it eq
        {0xFF00, 0x4600}  // mov rx, ry
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 8 - ((uintptr_t)kdata);
}

// needs fix for < 10.3
uint32_t find_csops(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xEA10}, // tst.w rx, ry
        {0xFFF0, 0x0F00},
        {0xFBC0, 0xF000}, // beq.w
        {0xD000, 0x8000},
        {0xF8FF, 0x2000}  // movs rk, #0
    };
    
    uint16_t *loc = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if (loc != NULL) return ((uintptr_t)loc) + 8 - ((uintptr_t)kdata);
    const struct find_search_mask search_masks_alt[] = {
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xff00, 0x4200}, // tst rx, ry
        {0xf000, 0xd000}, // beq ...
        {0xF8FF, 0x2000}, // movs rd, #0
        {0xFFF0, 0xE9C0}, // strd rx, ry, [sp, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
    };
    
    loc = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_alt) / sizeof(*search_masks_alt), search_masks_alt);
    if (loc != NULL) return ((uintptr_t)loc) + 6 - ((uintptr_t)kdata);
    return 0;
}

uint32_t find_vm_fault_enter(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xF410}, // ands rx, ry, #0x100000
        {0xF0FF, 0x1080},
        {0xFFF0, 0xF020}, // bic.w rx, ry, #4
        {0xF0FF, 0x0004},
        {0xFF00, 0x4600}  // mov rx, ry
    };
    
    uint16_t *loc = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if (loc != NULL) return ((uintptr_t)loc) + 0 - ((uintptr_t)kdata);
    
    const struct find_search_mask search_masks_alt[] = {
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xF410}, // ands rx, ry, #0x100000
        {0xF0FF, 0x1080},
        {0xFFF0, 0xF020}, // bic.w rx, ry, #4
        {0xF0FF, 0x0004},
        {0xF800, 0x9000}, // str rx, [sp, #y]
    };
    
    loc = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_alt) / sizeof(*search_masks_alt), search_masks_alt);
    if (loc != NULL) return ((uintptr_t)loc) + 0 - ((uintptr_t)kdata);
    return 0;
}

uint32_t find_mapForIO(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xF800, 0x9800}, // ldr rx, [sp, #z]
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFF00, 0xD100}, // bne loc_xxx
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z] -> movs r0, #0
        {0x0000, 0x0000}, //                    -> nop
        {0xFFF0, 0xF890}, // ldrb rx, [ry, #z]  -> nop
        {0x0000, 0x0000}, //                    -> nop
        {0xFD00, 0xB100}, // cbz rx, loc_xxx
        {0xF800, 0x9800}  // ldr rx, [sp, #z]
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 6 - ((uintptr_t)kdata);
}

uint32_t find_sandbox_call_i_can_has_debugger(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFFF, 0xB590}, // PUSH {R4,R7,LR}
        {0xFFFF, 0xAF01}, // ADD  R7, SP, #4
        {0xFFFF, 0x2400}, // MOVS R4, #0
        {0xFFFF, 0x2000}, // MOVS R0, #0
        {0xF800, 0xF000}, // BL   i_can_has_debugger
        {0xD000, 0xD000},
        {0xFD07, 0xB100}  // CBZ  R0, loc_xxx
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr) return 0;
    return (uintptr_t)ptr + 8 - ((uintptr_t)kdata);
}

uint32_t find_i_can_has_debugger_1(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFD07, 0xB100},  // CBZ  R0, loc_xxx
        {0xFBF0, 0xF240},
        {0x8F00, 0x0100},
        {0xFBF0, 0xF2C0},
        {0xFF00, 0x0100},
        {0xFFFF, 0x4479},
        {0xF807, 0x6801},  // LDR  R1, [Ry,#X]
        {0xFD07, 0xB101},  // CBZ  R1, loc_xxx
        {0xFBF0, 0xF240},
        {0x8F00, 0x0100},
    };
    
    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) return 0;
    insn += 5;
    uint32_t value = find_pc_rel_value(region, kdata, ksize, insn, insn_ldrb_imm_rt(insn));
    if(!value) return 0;
    value +=4;
    return value + ((uintptr_t)insn) - ((uintptr_t)kdata);
}

uint32_t find_amfi_cred_label_update_execve(uint32_t region, uint8_t* kdata, size_t ksize) {
    const char *str = "AMFI: hook..execve() killing pid %u: dyld signature cannot be verified. You either have a corrupt system image or are trying to run an unsigned application outside of a supported development configuration.\n";
    uint8_t* hook_execve = memmem(kdata, ksize, str, strlen(str));
    if(!hook_execve) return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)hook_execve - (uintptr_t)kdata);
    if(!ref) return 0;
    
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start) return 0;
    uint32_t addr = (uintptr_t)fn_start - ((uintptr_t)kdata);
    
    const struct find_search_mask search_masks[] = {
        {0xFBF0, 0xF010}, // TST.W Rx, #0x200000
        {0x0F00, 0x0F00},
        {0xFF00, 0xD100}  // BNE x
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata+addr, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr) return 0;
    return (uintptr_t)ptr - ((uintptr_t)kdata);
}

uint32_t find_amfi_vnode_check_signature(uint32_t region, uint8_t* kdata, size_t ksize) {
    const char *str = "The signature could not be validated because AMFI could not load its entitlements for validation: %s";
    uint8_t* point = memmem(kdata, ksize, str, strlen(str));
    if(!point) return 1;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref) return 2;
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start) return 3;
    uint32_t addr = (uintptr_t)fn_start - ((uintptr_t)kdata);
    
    const struct find_search_mask search_masks[] = {
        {0xFF00, 0x4600}, // mov rx, ry
        {0xF800, 0xF000}, // bl  loc_xxx
        {0xD000, 0xD000},
        {0xFF00, 0x4600}, // mov rx, ry
        {0xFD00, 0xB100}, // cbz rx, loc_xxx
        {0xFF00, 0x4600}, // mov rx, ry
        {0xF800, 0xF000}, // bl  loc_xxx
        {0xD000, 0xD000},
        {0xF80F, 0x2801}, // cmp rx, #1
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata+addr, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr) return 4;
    return (uintptr_t)ptr - ((uintptr_t)kdata);
}

uint32_t find_amfi_loadEntitlementsFromVnode(uint32_t region, uint8_t* kdata, size_t ksize) {
    const char *str = "no code signature";
    uint8_t* point = memmem(kdata, ksize, str, strlen(str));
    if(!point) return 0;
    
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref) return 0;
    return (uintptr_t)ref - 0x2 - ((uintptr_t)kdata);
}

uint32_t find_amfi_vnode_check_exec(uint32_t region, uint8_t* kdata, size_t ksize) {
    const char *str = "csflags";
    uint8_t *point = memmem(kdata, ksize, str, strlen(str));
    if (point != NULL) {
        uint16_t *ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
        if (ref != NULL) {
            uint16_t *fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
            if (fn_start != NULL) return (uintptr_t)fn_start + 4 - ((uintptr_t)kdata);
        }
    }

    const struct find_search_mask search_masks[] = {
        {0xFFFF, 0x697C},
        {0xFFFF, 0xB12C},
        {0xFFFF, 0x6820},
        {0xFFFF, 0xF440},
        {0xFFFF, 0x7040},
        {0xFFFF, 0x6020},
    };
    
    uint16_t *loc = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if (loc != NULL) return (uintptr_t)loc - ((uintptr_t)kdata);
   
    return 0;
}
uint32_t find_lwvm_i_can_has_krnl_conf_stub(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xF80F, 0x2801}, // cmp rx, #1
        {0xFF00, 0xD100}, // bne.n
        {0xF800, 0xF000}, // bl  loc_xxx <- this
        {0xD000, 0xD000},
        {0xFFF0, 0xF010}, // tst.w rx, #0x1
        {0xFFFF, 0x0F01},
        {0xFF00, 0xD000}, // beq.n
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    fn_start += 2;
    uint32_t imm32 = insn_bl_imm32(fn_start);
    uint32_t target = ((uintptr_t)fn_start - (uintptr_t)kdata) + 4 + imm32;
    uint32_t movw_val = insn_mov_imm_imm((uint16_t *)((uintptr_t)kdata+target));
    uint32_t movt_val = insn_movt_imm((uint16_t *)((uintptr_t)kdata+target+4));
    uint32_t val = (movt_val << 16) + movw_val;
    
    const struct find_search_mask add_ip_pc[] = {{0xFFFF, 0x44fc}};
    uint16_t* point = find_with_search_mask(region, kdata+target, ksize, sizeof(add_ip_pc) / sizeof(*add_ip_pc), add_ip_pc);
    if(!point) return 0;
    uint32_t ret = ((uintptr_t)point - (uintptr_t)kdata) + 4 + val;
    return ret;
}

uint32_t find_vfs_context_current(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFF80, 0xB080}, // sub sp, x
        {0xFFFF, 0xEE1D}, // mrc p15, #0x0, r0, c13, c0, #0x4
        {0xFFFF, 0x0F90}, //
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xF800, 0x9000}, // str rx, [sp, #y]
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr) return 0;
    return (uintptr_t)ptr - ((uintptr_t)kdata);
}

uint32_t find_vnode_getattr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFC0, 0x6800}, // ldr rx, [ry]
        {0xFFF0, 0xF410}, // tst.w rx, #0x800
        {0xFFFF, 0x6F00},
        {0xFF00, 0xD000}, // beq
        {0xFFF0, 0xF010}, // tst.w rx, #0x4000000
        {0xFFFF, 0x6F80},
        {0xFF00, 0xD000}, // beq
        {0xFFC0, 0x6800}, // ldr rx, [ry]
        {0xFFF0, 0xF010}, // tst.w rx, #0x4000000
        {0xFFFF, 0x6F80},
        {0xFF00, 0xD000}  // beq
    };
    
    uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr) return 0;
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_preamble_push);
    if(!fn_start) return 0;
    return (uintptr_t)fn_start - ((uintptr_t)kdata);
}


static void * buggy_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (haystack == NULL || haystacklen == 0 || needle == NULL || needlelen == 0) {return NULL;}
    for (size_t i = 0; i < haystacklen; i++) {
        if (*(uint8_t *)(haystack + i) == *(uint8_t *)needle && i + needlelen <= haystacklen && 0 == memcmp(((uint8_t *)haystack) + i, needle, needlelen)) { return (void *)(((uint8_t *)haystack) + i);
        }
    }
    return NULL;
}

static uint32_t find_kernel_pmap_post_iOS_6(uint32_t region, uint8_t *pmap_map_bd, uint8_t *kdata, size_t ksize) {
    uint16_t *ptr = find_literal_ref(region, kdata, ksize, (uint16_t *)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr) return 0;
    
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata) return 0;
        ptr--;
    }
    
    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = buggy_memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr) return 0;
    
    uint16_t *bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if (!bl) return 0;
    
    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {current_instruction -= 2;
        } else {--current_instruction;}
        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {ldr_r2 = current_instruction;break;
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {break;}
    }
    
    if (ldr_r2) return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));
        uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t) bl - (uintptr_t) kdata) + 4 + imm32;
    if (target > ksize) return 0;
    
    current_instruction = (uint16_t *) (kdata + target);
    while ((uintptr_t) current_instruction < (uintptr_t) (kdata + ksize)) {
        if (insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15) {
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            return find_pc_rel_value(region, kdata, ksize, current_instruction, insn_add_reg_rd(current_instruction));
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    return 0;
}

uint32_t find_kernel_pmap(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint8_t *pmap_map_bd = buggy_memmem(kdata, ksize, "\"pmap_map_bd\"", strlen("\"pmap_map_bd\""));
    if (NULL == pmap_map_bd) return 0;
    uint32_t kernel_pmap_offset = 0;
    kernel_pmap_offset = find_kernel_pmap_post_iOS_6(region, pmap_map_bd, kdata, ksize);
    if (0 == kernel_pmap_offset)return 0;
    return kernel_pmap_offset;
}

uint32_t find_sbops(uint32_t region, uint8_t* kdata, size_t ksize) {
    uintptr_t sbPolicyFullName = (uintptr_t)memmem(kdata, ksize, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy"));
    sbPolicyFullName -= (uintptr_t)kdata;

    uint32_t search[1];
    search[0] = sbPolicyFullName+region;

    uintptr_t policyConf_mpcName = (uintptr_t)memmem(kdata, ksize, &search, 4);
    if (policyConf_mpcName == 0) return 0;
    policyConf_mpcName -= ((uintptr_t)kdata + 4);

    uint32_t sb_mpcOps = *(uint32_t*)(kdata + (policyConf_mpcName + 0x10));
    uint32_t sbops = sb_mpcOps - region;
    return sbops;
}

uint32_t find_sb_disable(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_mask[] = {
        {0xFFF0, 0xE9C0},
        {0x0000, 0x0000},
        {0xF800, 0x9800},
        {0xF800, 0x2800},
        {0xF800, 0x9800},
        {0xFBC0, 0xF000},
        {0xD000, 0x8000}
    };
    
    uint16_t *ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask) / sizeof(*search_mask), search_mask);
    if (ptr != NULL) return (uintptr_t)ptr - ((uintptr_t)kdata) + 0xa;

    const struct find_search_mask search_mask_alt[] = {
        {0xF800, 0x9800}, // ldr rx, [sp, #z]
        {0xF800, 0x2800}, // cmp r0, #0
        {0xff00, 0xd000}, // beq ...
        {0xffff, 0x4625}, // mov r5, r4
        {0xF800, 0x9800}, // ldr rx, [sp, #z]
    };

    ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask_alt) / sizeof(*search_mask_alt), search_mask_alt);
    if (ptr != NULL) return (uintptr_t)ptr - ((uintptr_t)kdata) + 0x4;
    return 0;
}

uint32_t find_cs_system_require_lv(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_mask[] = {
        {0xFFFF, 0x2001}, // MOVS R0, #1
        {0xFFFF, 0x4770}, // BX LR
        {0xFFFF, 0x68C2}, // LDR R2, [R0,#0xC]
        {0xFFFF, 0x6901}, // LDR R1, [R0,#0x10]
        {0xFFFF, 0x4610}, // MOV R0, R2
        {0xFFFF, 0x4770}, // BX LR
    };
    
    uint16_t *ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask) / sizeof(*search_mask), search_mask);
    if (ptr == NULL) return 0;
    return (uintptr_t)ptr - ((uintptr_t)kdata);
}

uint32_t find_amfi_cs_flags_patch(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_mask[] = {
        {0xFFF0, 0xF010}, // tst.w r?, #8
        {0xFFFF, 0x0F08},
        {0xFFFF, 0xBF1C}, // itt ne
        {0xFFF0, 0xF440}, // orrne.w r0, r?, #0x800000
        {0xFFFF, 0x0000},
        {0xFFFF, 0xF8CA}, // strne.w R0, [R10]
        {0xFFFF, 0x0000},
        {0xFFFF, 0xF04F}, // mov.w R0, #0
        {0xFFFF, 0x0000}
    };
    
    uint16_t *ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask) / sizeof(*search_mask), search_mask);
    if (ptr == NULL) return 0;
    return (uintptr_t)ptr - ((uintptr_t)kdata);
}

uint32_t find_invalidate_icache(uint32_t region, uint8_t *kdata, size_t ksize) {
    const struct find_search_mask search_mask[] = {
        {0xFFFF, 0x0000}, // cmp r2, #0
        {0xFFFF, 0xE352}, // ...
        {0xFFFF, 0x0000}, // bne #0x8
        {0xFFFF, 0x1A00}, // ...
        {0x0000, 0x0000}, // ???
        {0x0000, 0x0000}, // ???
        {0x0000, 0x0000}, // ???
        {0x0000, 0x0000}, // ???
        {0x0000, 0x0000}, // ???
        {0x0000, 0x0000}, // ???
        {0xFFFF, 0x2002}, // ldr r2, [pc, r2]
        {0xFFFF, 0xE79F}, // ...
        {0xFFFF, 0x2000}, // ldr r2, [r2]
        {0xFFFF, 0xE592}  // ...
    };

    uint16_t *ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask) / sizeof(*search_mask), search_mask);
    if (ptr == NULL) return 0;
    return (uintptr_t)ptr - ((uintptr_t)kdata);
}

uint32_t find_flush_dcache(uint32_t region, uint8_t *kdata, size_t ksize) {
    const struct find_search_mask search_mask[] = {
        {0xFFFF, 0xB5F0}, // push {r4-r7, lr}
        {0xFFFF, 0xAF03}, // add r7, sp, #0xc
        {0xFFFF, 0xE92D}, // push.w {r8,r10,r11}
        {0xFFFF, 0x0D00}, // ...
        {0xFFFF, 0x460C}, // mov r4, r1
        {0xFFFF, 0x4605}, // mov r5, r0
    };

    uint16_t *ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask) / sizeof(*search_mask), search_mask);
    if (ptr == NULL) return 0;
    return ((uintptr_t)ptr - ((uintptr_t)kdata)) | 1;
}

uint32_t find_kcall_gadget(uint32_t region, uint8_t *kdata, size_t ksize) {
    const struct find_search_mask search_mask[] = {
        {0xFFFF, 0xF100}, // add.w r0, r0, #0x18
        {0xFFFF, 0x0018}, // ...
        {0xFFFF, 0x4770}, // bx lr
    };

    uint16_t *ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_mask) / sizeof(*search_mask), search_mask);
    if (ptr == NULL) return 0;
    return ((uintptr_t)ptr - ((uintptr_t)kdata)) | 1;
}
