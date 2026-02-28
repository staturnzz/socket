#include <stdint.h>
#include <string.h>

#include "patchfinder.h"

/* Find start of a load command in a macho */
static struct load_command *find_load_command(struct mach_header *mh, uint32_t cmd) {
    struct load_command *lc, *flc;
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    
    while (1) {
        if ((uintptr_t)lc->cmd == cmd) {flc = (struct load_command *)(uintptr_t)lc; break;}
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return flc;
}

/* Find offset of an exported symbol in a macho */
void* find_sym(struct mach_header *mh, const char *name) {
    struct segment_command* first = (struct segment_command*) find_load_command(mh, LC_SEGMENT);
    struct symtab_command* symtab = (struct symtab_command*) find_load_command(mh, LC_SYMTAB);
    vm_address_t vmaddr_slide = (vm_address_t)mh - (vm_address_t)first->vmaddr;
    
    char* sym_str_table = (char*) (((char*)mh) + symtab->stroff);
    struct nlist* sym_table = (struct nlist*)(((char*)mh) + symtab->symoff);
    for (int i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void*)(uintptr_t)(sym_table[i].n_value + vmaddr_slide);
        }
    }
    return 0;
}

/* Find the VM base for prelinked kexts in a kernelcache */
uint32_t find_kextbase(void *kernelcache, size_t size) {
    if (!(*(uint32_t*)&kernelcache[0] == 0xFEEDFACE)) {return 0;}
    struct mach_header *mh = kernelcache;
    struct segment_command *sc = (kernelcache+sizeof(struct mach_header));
    
    for (int i = 0; i < mh->ncmds; i++) {
        if (!strcmp(sc->segname, "__PRELINK_TEXT")) {
            uint32_t ret = (sc->vmaddr - sc->fileoff); return ret;}
        
        uintptr_t next = (uintptr_t)sc->cmdsize+(void*)sc-kernelcache;
        if (next+(uintptr_t)kernelcache > mh->sizeofcmds+(uintptr_t)kernelcache) {break;}
        sc=kernelcache+next;
    }
    return 0;
}

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

static int insn_is_ldrb_imm(uint16_t* i) {
    return (*i & 0xF800) == 0x7800;
}

static int insn_ldrb_imm_rt(uint16_t* i) {
    return (*i & 7);
}

static int insn_ldrb_imm_rn(uint16_t* i) {
    return ((*i >> 3) & 7);
}

static int insn_ldrb_imm_imm(uint16_t* i) {
    return ((*i >> 6) & 0x1F);
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

static int insn_is_str_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x6000)
        return 1;
    else if((*i & 0xF800) == 0x9000)
        return 1;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return 1;
    else
        return 0;
}

static int insn_str_imm_postindexed(uint16_t* i) {
    if((*i & 0xF800) == 0x6000)
        return 1;
    else if((*i & 0xF800) == 0x9000)
        return 1;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 1;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 10) & 1;
    else
        return 0;
}

static int insn_str_imm_wback(uint16_t* i) {
    if((*i & 0xF800) == 0x6000)
        return 0;
    else if((*i & 0xF800) == 0x9000)
        return 0;
    else if((*i & 0xFFF0) == 0xF8C0)
        return 0;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 8) & 1;
    else
        return 0;
}

static int insn_str_imm_imm(uint16_t* i) {
    if((*i & 0xF800) == 0x6000)
        return (*i & 0x07C0) >> 4;
    else if((*i & 0xF800) == 0x9000)
        return (*i & 0xFF) << 2;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) & 0xFFF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) & 0xFF);
    else
        return 0;
}

static int insn_str_imm_rt(uint16_t* i) {
    if((*i & 0xF800) == 0x6000)
        return (*i & 7);
    else if((*i & 0xF800) == 0x9000)
        return (*i >> 8) & 7;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*(i + 1) >> 12) & 0xF;
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

static int insn_str_imm_rn(uint16_t* i) {
    if((*i & 0xF800) == 0x6000)
        return (*i >> 3) & 7;
    else if((*i & 0xF800) == 0x9000)
        return 13;
    else if((*i & 0xFFF0) == 0xF8C0)
        return (*i & 0xF);
    else if((*i & 0xFFF0) == 0xF840 && (*(i + 1) & 0x0800) == 0x0800)
        return (*i & 0xF);
    else
        return 0;
}

// Given an instruction, search backwards until an instruction is found matching the specified criterion.
static uint16_t* find_last_insn_matching(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* current_instruction, int (*match_func)(uint16_t*)) {
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {
            current_instruction -= 2;
        } else {--current_instruction;}
        if(match_func(current_instruction)) {return current_instruction;}
    }
    return NULL;
}

// Given an instruction and a register, find the PC-relative address that was stored inside the register by the time the instruction was reached.
static uint32_t find_pc_rel_value(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, int reg) {
    // Find the last instruction that completely wiped out this register
    int found = 0;
    uint16_t* current_instruction = insn;
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if(insn_is_32bit(current_instruction - 2)) { current_instruction -= 2;
        } else { --current_instruction; }

        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_rd(current_instruction) == reg) {found = 1;break;}
        if(insn_is_ldr_literal(current_instruction) && insn_ldr_literal_rt(current_instruction) == reg) {found = 1;break;}
    }

    if(!found) return 0;

    // Step through instructions, executing them as a virtual machine, only caring about instructions that affect the target register and are commonly used for PC-relative addressing.
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

// Find PC-relative references to a certain address (relative to kdata). This is basically a virtual machine that only cares about instructions used in PC-relative addressing, so no branches, etc.
static uint16_t* find_literal_ref(uint32_t region, uint8_t* kdata, size_t ksize, uint16_t* insn, uint32_t address) {
    uint16_t* current_instruction = insn;
    uint32_t value[16];
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

// Search the range of kdata for a series of 16-bit values that match the search mask.
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

static uint32_t find_memmove_arm(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x00, 0x00, 0x52, 0xE3, 0x01, 0x00, 0x50, 0x11, 0x1E, 0xFF, 0x2F, 0x01, 0xB1, 0x40, 0x2D, 0xE9};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

static uint32_t find_memmove_thumb(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x03, 0x46, 0x08, 0x46, 0x19, 0x46, 0x80, 0xB5};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr) return 0;
    return ((uintptr_t)ptr + 6 + 1) - ((uintptr_t)kdata);
}

// Helper gadget.
uint32_t find_memmove(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint32_t thumb = find_memmove_thumb(region, kdata, ksize);
    if(thumb) return thumb;
   return find_memmove_arm(region, kdata, ksize);
}

// Use for write-anywhere gadget.
uint32_t find_str_r1_r2_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x11, 0x60, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget.
uint32_t find_mov_r0_r1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x08, 0x46, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Use for read-anywhere gadget.
uint32_t find_ldr_r0_r1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x08, 0x68, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget.
uint32_t find_mov_r0_0_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x00, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget.
uint32_t find_mov_r0_1_bx_lr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x01, 0x20, 0x70, 0x47};
    void* ptr = memmem(kdata, ksize, search, sizeof(search)) + 1;
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget for changing page tables / patching.
uint32_t find_flush_dcache(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x00, 0x00, 0xA0, 0xE3, 0x5E, 0x0F, 0x07, 0xEE};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// Helper gadget for changing page tables.
uint32_t find_invalidate_tlb(uint32_t region, uint8_t* kdata, size_t ksize) {
    const uint8_t search[] = {0x00, 0x00, 0xA0, 0xE3, 0x17, 0x0F, 0x08, 0xEE};
    void* ptr = memmem(kdata, ksize, search, sizeof(search));
    if(!ptr) return 0;
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
uint32_t find_pmap_location(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find location of the pmap_map_bd string.
    uint8_t* pmap_map_bd = memmem(kdata, ksize, "\"pmap_map_bd\"", sizeof("\"pmap_map_bd\""));
    if(!pmap_map_bd) return 0;

    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t* ptr = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if(!ptr) return 0;

    // Find the end of it.
    const uint8_t search_function_end[] = {0xF0, 0xBD};
    ptr = memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if(!ptr) return 0;

    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t* bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if(!bl) return 0;

    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t* ldr_r2 = NULL;
    uint16_t* current_instruction = bl;
    while((uintptr_t)current_instruction > (uintptr_t)kdata) {
        if(insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {current_instruction -= 2;
        } else {--current_instruction;}

        if(insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {
            ldr_r2 = current_instruction;break;
        } else if(insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {break;}
    }

    // The function has a third argument, which must be kernel_pmap. Find out its address
    if(ldr_r2) return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));

    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t)bl - (uintptr_t)kdata) + 4 + imm32;
    if(target > ksize)return 0;

    // Find the first PC-relative reference in this function.
    int found = 0;
    int rd;
    current_instruction = (uint16_t*)(kdata + target);
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize)) {
        if(insn_is_add_reg(current_instruction) && insn_add_reg_rm(current_instruction) == 15) {
            found = 1;
            rd = insn_add_reg_rd(current_instruction);
            current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
            break;
        }
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if(!found) return 0;
    return find_pc_rel_value(region, kdata, ksize, current_instruction, rd);
}

// Write 0 here.
uint32_t find_proc_enforce(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find the description.
    uint8_t* proc_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on process operations", sizeof("Enforce MAC policy on process operations"));
    if(!proc_enforce_description) return 0;

    // Find what references the description.
    uint32_t proc_enforce_description_address = region + ((uintptr_t)proc_enforce_description - (uintptr_t)kdata);
    uint8_t* proc_enforce_description_ptr = memmem(kdata, ksize, &proc_enforce_description_address, sizeof(proc_enforce_description_address));
    if(!proc_enforce_description_ptr) return 0;

    // Go up the struct to find the pointer to the actual data element.
    uint32_t* proc_enforce_ptr = (uint32_t*)(proc_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *proc_enforce_ptr - region;
}

// Write 0 here.
uint32_t find_vnode_enforce(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find the description.
    uint8_t* vnode_enforce_description = memmem(kdata, ksize, "Enforce MAC policy on vnode operations", sizeof("Enforce MAC policy on vnode operations"));
    if(!vnode_enforce_description) return 0;

    // Find what references the description.
    uint32_t vnode_enforce_description_address = region + ((uintptr_t)vnode_enforce_description - (uintptr_t)kdata);
    uint8_t* vnode_enforce_description_ptr = memmem(kdata, ksize, &vnode_enforce_description_address, sizeof(vnode_enforce_description_address));
    if(!vnode_enforce_description_ptr) return 0;

    // Go up the struct to find the pointer to the actual data element.
    uint32_t* vnode_enforce_ptr = (uint32_t*)(vnode_enforce_description_ptr - (5 * sizeof(uint32_t)));
    return *vnode_enforce_ptr - region;
}

// Write 1 here.
uint32_t find_cs_enforcement_disable_amfi(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find a function referencing cs_enforcement_disable_amfi
    const uint8_t search_function[] = {0x20, 0x68, 0x40, 0xF4, 0x40, 0x70, 0x20, 0x60, 0x00, 0x20, 0x90, 0xBD};
    uint8_t* ptr = memmem(kdata, ksize, search_function, sizeof(search_function));
    if(!ptr) return 0;

    // Only LDRB in there should try to dereference cs_enforcement_disable_amfi
    uint16_t* ldrb = find_last_insn_matching(region, kdata, ksize, (uint16_t*) ptr, insn_is_ldrb_imm);
    if(!ldrb) return 0;

    // Weird, not the right one.
    if(insn_ldrb_imm_imm(ldrb) != 0 || insn_ldrb_imm_rt(ldrb) > 12) return 0;

    // See what address that LDRB is dereferencing
    return find_pc_rel_value(region, kdata, ksize, ldrb, insn_ldrb_imm_rn(ldrb));
}

// Change this to what you want the value to be (non-zero appears to work).
uint32_t find_i_can_has_debugger_2_90(uint32_t region, uint8_t* kdata, size_t ksize) {
    // find PE_i_can_has_debugger
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


// Write this with a jump to the sandbox hook, then write a trampoline back to just after the jump you wrote here. Sandbox hook should look at the path in *(r3 + 0x14) and force
// it to be allowed if it is outside of /private/var/mobile, or inside of /private/var/mobile/Library/Preferences but not /private/var/mobile/Library/Preferences/com.apple*
// To force it to allow, *r0 = 0 and *(r0 + 0x4) = 0x18. If not, just call the original function via the trampoline.
uint32_t find_sb_patch(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find location of the "control_name" string.
    uint8_t* control_name = memmem(kdata, ksize, "control_name", sizeof("control_name"));
    if(!control_name) return 0;

    // Find a reference to the "control_name" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)control_name - (uintptr_t)kdata);
    if(!ref) return 0;

    // Find the start of the function referencing "control_name"
    uint16_t* fn_start = ref;
    while(1) {
        fn_start = find_last_insn_matching(region, kdata, ksize, fn_start, insn_is_push);
        if(!fn_start) return 0;
        uint16_t registers = insn_push_registers(fn_start);
        // We match PUSH {R0, R1} as well to detect an already patched version.
        if((registers & (1 << 14)) != 0 || (registers & (1 << 0 | 1 << 1)) == (1 << 0 | 1 << 1)) break;
    }
    return ((uintptr_t)fn_start) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_vn_getpath(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find a string inside the vn_getpath function
    const struct  find_search_mask search_masks_84[] = {
        {0xF8FF, 0x2001},
        {0xFFFF, 0xE9CD},
        {0x0000, 0x0000},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600}
    };

    const struct find_search_mask search_masks[] = {
        {0xFF00, 0x4600},
        {0xF8FF, 0x2001},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600},
        {0xFFFF, 0xE9CD},
        {0x0000, 0x0000},
        {0xFF00, 0x4600},
        {0xFF00, 0x4600}
    };

    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks_84) / sizeof(*search_masks_84), search_masks_84);
    if(!insn) insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) return 0;

    // Find the start of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, insn, insn_is_preamble_push);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start | 1) - ((uintptr_t)kdata);
}

// Utility function, necessary for the sandbox hook.
uint32_t find_memcmp(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Okay, search is actually the entire text of memcmp. This is in order to distinguish it from bcmp. However, memcmp is the same as bcmp if you only care about equality.
    const struct find_search_mask search_masks[] = {
        {0xFD00, 0xB100},
        {0xFFF0, 0xF890},
        {0x0000, 0x0000},
        {0xF800, 0x7800},
        {0xFF00, 0x4500},
        {0xFF00, 0xBF00},
        {0xFFF0, 0xEBA0},
        {0x8030, 0x0000},
        {0xFFFF, 0x4770},
        {0xF8FF, 0x3801},
        {0xFFF0, 0xF100},
        {0xF0FF, 0x0001},
        {0xFFF0, 0xF100},
        {0xF0FF, 0x0001},
        {0xFF00, 0xD100},
        {0xF8FF, 0x2000},
        {0xFFFF, 0x4770}
    };

    uint16_t* ptr = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!ptr) return 0;
    return ((uintptr_t)ptr | 1) - ((uintptr_t)kdata);
}

// Dereference this, add 0x38 to the resulting pointer, and write whatever boot-args are suitable to affect kern.bootargs.
uint32_t find_p_bootargs(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find location of the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint8_t* pixel_format = memmem(kdata, ksize, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof("BBBBBBBBGGGGGGGGRRRRRRRR"));
    if(!pixel_format) return 0;

    // Find a reference to the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pixel_format - (uintptr_t)kdata);
    if(!ref) return 0;

    // Find the beginning of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start) return 0;

    // Find the first MOV Rx, #1. This is to eventually set PE_state as initialized
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)ref) {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_imm(current_instruction) == 1) {found = 1;break;}
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }

    if(!found) return 0;
    // This finds the STR Rx, [Ry] instrunction following that actually writes the #1. We will use Ry to find PE_state.
    found = 0;
    current_instruction += 2;
    uint32_t str_val = insn_str_imm_imm(current_instruction);
    current_instruction += 2;
    
    // Now find the location of PE_state
    uint32_t pe_state = find_pc_rel_value(region, kdata, ksize, current_instruction, insn_str_imm_rn(current_instruction)) + str_val;
    if(!pe_state)return 0;

    // p_boot_args is 0x70 offset in that struct.
    return pe_state + 0x70;
}

uint32_t find_p_bootargs_generic(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find location of the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint8_t* pixel_format = memmem(kdata, ksize, "BBBBBBBBGGGGGGGGRRRRRRRR", sizeof("BBBBBBBBGGGGGGGGRRRRRRRR"));
    if(!pixel_format) return 0;
    
    // Find a reference to the "BBBBBBBBGGGGGGGGRRRRRRRR" string.
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)pixel_format - (uintptr_t)kdata);
    if(!ref) return 0;
    
    // Find the beginning of the function
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start) return 0;
    
    // Find the first MOV Rx, #1. This is to eventually set PE_state as initialized
    int found = 0;
    uint16_t* current_instruction = fn_start;
    while((uintptr_t)current_instruction < (uintptr_t)ref) {
        if(insn_is_mov_imm(current_instruction) && insn_mov_imm_imm(current_instruction) == 1) {found = 1;break;}
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    if(!found)return 0;
    int reg = insn_mov_imm_rd(current_instruction);
    
    // This finds the STR Rx, [Ry] instrunction following that actually writes the #1. We will use Ry to find PE_state.
    found = 0;
    while((uintptr_t)current_instruction < (uintptr_t)ref) {
        if(insn_is_str_imm(current_instruction) && insn_str_imm_imm(current_instruction) == 0
           && insn_str_imm_postindexed(current_instruction) == 1 && insn_str_imm_wback(current_instruction) == 0
           && insn_str_imm_rt(current_instruction) == reg) {found = 1;break;}
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    // Now find the location of PE_state
    uint32_t pe_state = find_pc_rel_value(region, kdata, ksize, current_instruction, insn_str_imm_rn(current_instruction));
    if(!pe_state)return 0;
    
    // p_boot_args is 0x70 offset in that struct.
    return pe_state + 0x70;
}

// Function to find the syscall 0 function pointer. Used to modify the syscall table to call our own code.
uint32_t Find_syscall0(uint32_t region, uint8_t* kdata, size_t ksize) {
    uint8_t* str = memmem(kdata, ksize, ".HFS+ Private Directory Data\r", sizeof(".HFS+ Private Directory Data\r"));
    if(str) {
        uint32_t address = ((uintptr_t)str) + region - ((uintptr_t)kdata);
        uint8_t *offset = memmem(kdata, ksize, (const char *)&address, sizeof(uint32_t));
        // "HFS+" string offset preceded syscall table
        return ((uintptr_t)offset) + 4 - ((uintptr_t)kdata);
    }
    return 0;
}

// Function to copy strings to the kernel
uint32_t find_copyinstr(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0x0FFF, 0x0F90},
        {0xFFFF, 0xEE1D},
        {0x0000, 0x0000},
        {0xFFF0, 0xE590},
        {0x0000, 0x0000},
        {0xFFF0, 0xE580},
        {0x0000, 0x0000},
        {0xFFF0, 0xE590},
        {0x0FFF, 0x0F10},
        {0xFFFF, 0xEE02},
        {0x0000, 0x0000},
        {0xFFF0, 0xE590},
        {0x0FFF, 0x0F30},
        {0xFFFF, 0xEE0D}
    };

    uint16_t* insn = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!insn) return 0;

    // Find the beginning of the function
    for ( ; (uint8_t*)insn > kdata; insn -= 2 ) {if ( (insn[1] & 0xFFF0) == 0xE920 )break;}
    return ((uintptr_t)insn) - ((uintptr_t)kdata);
}

// ios 10
uint32_t find_pid_check(uint32_t region, uint8_t* kdata, size_t ksize) {
    // Find the beginning of task_for_pid function
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xE9C0}, // strd rx, ry, [sp, #z]
        {0x0000, 0x0000},
        {0xF800, 0x2800}, // cmp rx, #0
        {0xFF00, 0xD000}, // beq.n                      <-- NOP
        {0xF800, 0xF000}, // bl _port_name_to_task
        {0xF800, 0xF800},
        {0xF800, 0x9000}, // str rx, [sp, #y]
        {0xF800, 0x2800}  // cmp rx, #0
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 6 - ((uintptr_t)kdata);
}

// iOS 10.3.x
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

uint32_t find_mount_103(uint32_t region, uint8_t* kdata, size_t ksize) {
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

uint32_t find_vm_map_enter_103(uint32_t region, uint8_t* kdata, size_t ksize) {
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

uint32_t find_vm_map_protect_103(uint32_t region, uint8_t* kdata, size_t ksize) {
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

uint32_t find_csops_103(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xEA10}, // tst.w rx, ry
        {0xFFF0, 0x0F00},
        {0xFBC0, 0xF000}, // beq.w
        {0xD000, 0x8000},
        {0xF8FF, 0x2000}  // movs rk, #0
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 8 - ((uintptr_t)kdata);
}

uint32_t find_vm_fault_enter_103(uint32_t region, uint8_t* kdata, size_t ksize) {
    const struct find_search_mask search_masks[] = {
        {0xFFF0, 0xF8D0}, // ldr.w rx, [ry, #z]
        {0x0000, 0x0000},
        {0xFFF0, 0xF410}, // ands rx, ry, #0x100000
        {0xF0FF, 0x1080},
        {0xFFF0, 0xF020}, // bic.w rx, ry, #4
        {0xF0FF, 0x0004},
        {0xFF00, 0x4600}  // mov rx, ry
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 0 - ((uintptr_t)kdata);
}

// modify the cs flags
uint32_t find_amfi_execve_ret(uint32_t region, uint8_t* kdata, size_t ksize) {
    // :: AMFI.kext
    const struct find_search_mask search_masks[] = {
        {0xFFFF, 0xF8DA},   // ldr.w rx, [sl]   <- replace with: b.w _shc @ jump to shellcode
        {0x0FFF, 0x0000},
        {0xFFF0, 0xF010},   // tst.w rx, #8
        {0xFFFF, 0x0F08},
        {0xFFF0, 0xBF10},   // it    ne
        {0xFFF0, 0xF440},   // orr   rx, rx, #0xa00
        {0xF0FF, 0x6020},
        {0xFFFF, 0xF8CA},   // str.w rx, [sl]
        {0x0FFF, 0x0000},
        {0xF8FF, 0x2000},   // movs  rk, #0
        {0xFF80, 0xB000},   // add   sp, #x
        {0xFFFF, 0xE8BD},   // pop.w {r8, sl, fp}
        {0xFFFF, 0x0D00},
        {0xFFFF, 0xBDF0},   // pop   {r4, r5, r6, r7, pc}
    };
    
    uint16_t* fn_start = find_with_search_mask(region, kdata, ksize, sizeof(search_masks) / sizeof(*search_masks), search_masks);
    if(!fn_start) return 0;
    return ((uintptr_t)fn_start) + 0 - ((uintptr_t)kdata);
}

uint32_t find_mapForIO_103(uint32_t region, uint8_t* kdata, size_t ksize) {
    // :: LwVM.kext
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

// NOP out the BL call here.
uint32_t find_sandbox_call_i_can_has_debugger_103(uint32_t region, uint8_t* kdata, size_t ksize) {
    
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

uint32_t find_i_can_has_debugger_1_103(uint32_t region, uint8_t* kdata, size_t ksize) {
    // find PE_i_can_has_debugger
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

uint32_t find_i_can_has_debugger_2_103(uint32_t region, uint8_t* kdata, size_t ksize) {
    return find_i_can_has_debugger_2_90(region, kdata, ksize);
}

uint32_t find_amfi_cred_label_update_execve(uint32_t region, uint8_t* kdata, size_t ksize) {
    const char *str = "AMFI: hook..execve() killing pid %u: dyld signature cannot be verified. You either have a corrupt system image or are trying to run an unsigned application outside of a supported development configuration.\n";
    uint8_t* hook_execve = memmem(kdata, ksize, str, strlen(str));
    if(!hook_execve) return 0;
    
    //printf("ref: 0x%08x\n", (uint32_t)((uintptr_t)hook_execve - (uintptr_t)kdata));
    // Find a reference to the "AMFI: hook..execve() killing pid ..." string.
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
    
    //printf("ref: 0x%08x\n", (uint32_t)((uintptr_t)point - (uintptr_t)kdata));
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
    if(!point) return 1;
    
    //printf("ref: 0x%08x\n", (uint32_t)((uintptr_t)point - (uintptr_t)kdata));
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref) return 2;
    
    //  ldr        r0, =0xXXX  <- this
    //  add        r0, pc     ; "no code signature"
    return (uintptr_t)ref - 2 - ((uintptr_t)kdata);
}

uint32_t find_amfi_vnode_check_exec(uint32_t region, uint8_t* kdata, size_t ksize) {
    const char *str = "csflags";
    uint8_t* point = memmem(kdata, ksize, str, strlen(str));
    if(!point) return 0;
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref) return 0;
    uint16_t* fn_start = find_last_insn_matching(region, kdata, ksize, ref, insn_is_preamble_push);
    if(!fn_start) return 0;
    
    //  push {r4, r7, lr}
    //  add  r7, sp, #0x4
    //  ldr  r4, [r7, #x] <- this
    return (uintptr_t)fn_start + 4 - ((uintptr_t)kdata);
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
    uint32_t movw_val = insn_mov_imm_imm((uintptr_t)kdata+target);
    uint32_t movt_val = insn_movt_imm((uintptr_t)kdata+target+4);
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

uint32_t find_allproc(uint32_t region, uint8_t* kdata, size_t ksize) {
    int i=0;
    int j=0;
    const char *str = "shutdownwait";
    uint8_t* point = memmem(kdata, ksize, str, strlen(str));
    if(!point) return 0;
    uint16_t* ref = find_literal_ref(region, kdata, ksize, (uint16_t*) kdata, (uintptr_t)point - (uintptr_t)kdata);
    if(!ref) return 0;
    
    // find next movt
    for(i=0;i<64;i++) { j = insn_is_movt(ref+i); if(j!=0) break; }
    if(j==0) return 0;
    ref += i+2; // add pc, [rx]
    uint32_t value = find_pc_rel_value(region, kdata, ksize, ref, insn_ldrb_imm_rt(ref));
    if(!value) return 0;
    value += 4;
    return value + ((uintptr_t)ref) - ((uintptr_t)kdata);
}

/* Buggy, but re-implemented because some old versions of iOS don't have memmem */
static void * buggy_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (haystack == NULL || haystacklen == 0 || needle == NULL || needlelen == 0) {return NULL;}
    for (size_t i = 0; i < haystacklen; i++) {
        if (*(uint8_t *)(haystack + i) == *(uint8_t *)needle && i + needlelen <= haystacklen && 0 == memcmp(((uint8_t *)haystack) + i, needle, needlelen)) { return (void *)(((uint8_t *)haystack) + i);
        }
    }
    return NULL;
}

// This points to kernel_pmap. Use that to change the page tables if necessary.
static uint32_t find_kernel_pmap_post_iOS_6(uint32_t region, uint8_t *pmap_map_bd, uint8_t *kdata, size_t ksize) {
    // Find a reference to the pmap_map_bd string. That function also references kernel_pmap
    uint16_t *ptr = find_literal_ref(region, kdata, ksize, (uint16_t *)kdata, (uintptr_t)pmap_map_bd - (uintptr_t)kdata);
    if (!ptr) return 0;
    
    // Find the beginning of it (we may have a version that throws panic after the function end).
    while (*ptr != 0xB5F0) {
        if ((uint8_t *)ptr == kdata) return 0;
        ptr--;
    }
    
    // Find the end of it.
    const uint8_t search_function_end[] = { 0xF0, 0xBD };
    ptr = buggy_memmem(ptr, ksize - ((uintptr_t)ptr - (uintptr_t)kdata), search_function_end, sizeof(search_function_end));
    if (!ptr) return 0;
    
    // Find the last BL before the end of it. The third argument to it should be kernel_pmap
    uint16_t *bl = find_last_insn_matching(region, kdata, ksize, ptr, insn_is_bl);
    if (!bl) return 0;
    
    // Find the last LDR R2, [R*] before it that's before any branches. If there are branches, then we have a version of the function that assumes kernel_pmap instead of being passed it.
    uint16_t *ldr_r2 = NULL;
    uint16_t *current_instruction = bl;
    while ((uintptr_t) current_instruction > (uintptr_t) kdata) {
        if (insn_is_32bit(current_instruction - 2) && !insn_is_32bit(current_instruction - 3)) {current_instruction -= 2;
        } else {--current_instruction;}
        if (insn_ldr_imm_rt(current_instruction) == 2 && insn_ldr_imm_imm(current_instruction) == 0) {ldr_r2 = current_instruction;break;
        } else if (insn_is_b_conditional(current_instruction) || insn_is_b_unconditional(current_instruction)) {break;}
    }
    
    // The function has a third argument, which must be kernel_pmap. Find out its address
    if (ldr_r2) return find_pc_rel_value(region, kdata, ksize, ldr_r2, insn_ldr_imm_rn(ldr_r2));
    
    // The function has no third argument, Follow the BL.
    uint32_t imm32 = insn_bl_imm32(bl);
    uint32_t target = ((uintptr_t) bl - (uintptr_t) kdata) + 4 + imm32;
    if (target > ksize) return 0;
    
    // Find the first PC-relative reference in this function.
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
    uint32_t sbPolicyFullName = (uint32_t)memmem(kdata, ksize, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy"));
    sbPolicyFullName -= (uintptr_t)kdata;
    //printf("policyFullName: 0x%08x\n", sbPolicyFullName);
    
    uint32_t search[1];
    search[0] = sbPolicyFullName+region;
    uint32_t policyConf_mpcName = (uint32_t)memmem(kdata, ksize, &search, 4);
    policyConf_mpcName -= ((uintptr_t)kdata + 4);
    //printf("policyConf_mpcName: 0x%08x\n", policyConf_mpcName);
    
    uint32_t sb_mpcOps = *(uint32_t*)(kdata + (policyConf_mpcName + 0x10));
    //printf("mpcOps: 0x%08x\n", sb_mpcOps);
    uint32_t sbops = sb_mpcOps - region;
    return sbops;
}


