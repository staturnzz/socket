//
//  common.h
//  socket
//
//  Created by staturnz on 1/24/23.
//  Copyright © 2023 Staturnz. All rights reserved.
//


#ifndef common_h
#define common_h

#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/mount.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <spawn.h>
#include <fcntl.h>
#include "patchfinder.h"

#define KERNEL_TEXT_BASEADDR (0x80001000)

#define text_addr kernel_data.text._text.addr
#define const_addr kernel_data.text._const.addr
#define cstr_addr kernel_data.text._cstring.addr
#define os_log_addr kernel_data.text._os_log.addr
#define base_addr kernel_data.data.base.addr

#define text_size kernel_data.text._text.size
#define const_size kernel_data.text._const.size
#define cstr_size kernel_data.text._cstring.size
#define os_log_size kernel_data.text._os_log.size
#define base_size kernel_data.data.base.size
    
#define text_section kernel_data.text._text.addr+(uint32_t)kernel_data.text._text.size
#define const_section kernel_data.text._const.addr+(uint32_t)kernel_data.text._const.size
#define cstring_section kernel_data.text._cstring.addr+(uint32_t)kernel_data.text._cstring.size
#define os_log_section kernel_data.text._os_log.addr+(uint32_t)kernel_data.text._os_log.size

#define TTB_SIZE            4096
#define L1_SECT_S_BIT       (1 << 16)
#define L1_SECT_PROTO       (1 << 1)        /* 0b10 */
#define L1_SECT_AP_URW      (1 << 10) | (1 << 11)
#define L1_SECT_APX         (1 << 15)
#define L1_SECT_DEFPROT     (L1_SECT_AP_URW | L1_SECT_APX)
#define L1_SECT_SORDER      (0)            /* 0b00, not cacheable, strongly ordered. */
#define L1_SECT_DEFCACHE    (L1_SECT_SORDER)
#define L1_PROTO_TTE(entry) (entry | L1_SECT_S_BIT | L1_SECT_DEFPROT | L1_SECT_DEFCACHE)
#define L1_PAGE_PROTO       (1 << 0)
#define L1_COARSE_PT        (0xFFFFFC00)
#define PT_SIZE             256
#define L2_PAGE_APX         (1 << 9)
#define CHUNK_SIZE 0x800

struct kinfo {
    uint32_t addr;
    size_t   size;
};

struct kernel_text {
    struct kinfo base;
    struct kinfo _text;
    struct kinfo _const;
    struct kinfo _cstring;
    struct kinfo _os_log;
};

struct kernel_data {
    struct kinfo base;
};

typedef struct {
    struct kinfo base;
    uint32_t kdumpbase;
    uint32_t kernel_entry;
    struct kernel_text          text;
    struct kernel_data          data;
} kdata_t;

#endif /* common_h */
