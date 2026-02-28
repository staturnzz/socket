//
//  jailbreak.h
//  socket
//
//  Created by staturnz on 1/24/23.
//  Copyright © 2023 Staturnz. All rights reserved.
//

#ifndef jailbreak_h
#define jailbreak_h
#include "common.h"
void status(NSString* str);
int p_spawn(NSString *path, NSArray *arg);
int start_jailbreak(void);
extern mach_port_t tfp0_port;
extern uint32_t k_base;
extern uint32_t k_slide;
extern uint32_t tte_virt;
extern int32_t tte_phys;
extern kdata_t kernel_data;
extern pid_t uid;
extern uint32_t myproc;
extern uint32_t mycred;
extern uint32_t shc_base;
extern uint32_t shc;
extern unsigned int shc_len;

#endif /* jailbreak_h */
