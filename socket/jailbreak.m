//
//  jailbreak.m
//  socket
//
//  Created by staturnz on 1/24/23.
//  Copyright © 2023 Staturnz. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <spawn.h>
#include <pthread.h>
#include <copyfile.h>
#include <spawn.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "common.h"
#include "patches.h"
#include "patchfinder.h"
#include "exploit/s0cket.h"


#pragma mark - [*]--   Defines/Vars and Stuff   --[*]

#define bundle(a) [[NSBundle mainBundle]URLForResource:@a withExtension:@""]
#define fm [NSFileManager defaultManager]
#define filter(a) filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@a]
#define concat(a,b) [NSString stringWithFormat:a, b]

extern char* const* environ;
mach_port_t tfp0_port;
uint32_t k_base;
uint32_t kernel_slide;
uint32_t tte_virt;
uint32_t tte_phys;
kdata_t kernel_data;
uint32_t shc_base;
uint32_t shc;


#pragma mark - [*]--   Common Stuff   --[*]

int p_spawn(NSString *path, NSArray *arg){
    NSURL *bin = [NSURL fileURLWithPath:path];
    NSMutableArray *p_spawn_arg = [arg mutableCopy];
    [p_spawn_arg insertObject:[bin lastPathComponent] atIndex:0];
    int argc = (int)p_spawn_arg.count +1 ;
    char **args = (char**)calloc(argc, sizeof(char *));
    for (int i = 0; i < p_spawn_arg.count; i++)
        args[i]= (char *)[p_spawn_arg[i] UTF8String];

    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    pid_t pid = 0;
    int ret = posix_spawn(&pid, bin.path.UTF8String, &action, NULL, args, environ);

    if (ret == 0) if (waitpid(pid, &ret, 0) != -1) {}
    posix_spawn_file_actions_destroy(&action);
    return ret;
}

void status(NSString* str) {
    printf("%s", str.UTF8String);
    NSDictionary* data = @{@"msg": @[str]};
    [[NSNotificationCenter defaultCenter] postNotificationName:@"status" object:nil userInfo:data];
}

void launchctl(NSString *path, bool load) {
    int ret;
    NSString *type = @"load";
    if (!load) type = @"unload";
    ret = p_spawn(@"/bin/launchctl", @[type, path]);
    if (ret != 0) printf("[-] Error (un)loading daemon: %d", ret);
}

void cleanup(void) {
    // set user defaults back to what we want default to be
    [[NSUserDefaults standardUserDefaults] setObject:@"yes" forKey:@"tweaks"];
    [[NSUserDefaults standardUserDefaults] setObject:@"no" forKey:@"restrap"];
    [[NSUserDefaults standardUserDefaults] synchronize];
}


#pragma mark - [*]--   Bootstrap   --[*]

void install_zebra(void) {
    chmod("/usr/libexec/zebra", 0777);
    chmod(bundle("zebra.deb").path.UTF8String, 0777);
    p_spawn(@"/usr/bin/dpkg", @[@"-i", bundle("zebra.deb").path]);
    status(@"[*] setting supersling permissions\n");
    setuid(0);
    sleep(1);
    p_spawn(@"/bin/bash", @[@"-c", @"chmod 6755 /usr/libexec/zebra/supersling"]);
}

void install_bootstrap(void) {
    status(@"[*] moving files\n");
    copyfile(bundle("tar").path.UTF8String, "/bin/tar", NULL, COPYFILE_ALL);
    copyfile(bundle("launchctl").path.UTF8String, "/bin/launchctl", NULL, COPYFILE_ALL);
    mkdir("/Library/LaunchDaemons", 0755);
    mkdir("/tmp/.omnis", 0777);
    chmod("/bin/tar", 0777);
    chmod(bundle("bootstrap.tar").path.UTF8String, 0777);
    chmod("/bin/launchctl", 0777);

    status(@"[*] installing base\n");
    p_spawn(@"/bin/tar", @[@"-xvf", bundle("bootstrap.tar").path, @"-C", @"/", @"--preserve-permissions"]);
    p_spawn(@"/bin/touch", @[@"/.cydia_no_stash"]);
    if(![[NSFileManager defaultManager]fileExistsAtPath:@"/.cydia_no_stash"]) NSLog(@"cydia fucked bro\n");

    status(@"[*] showing non default apps\n");
    NSMutableDictionary *md = [[NSMutableDictionary alloc] initWithContentsOfFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist"];
    [md setObject:[NSNumber numberWithBool:YES] forKey:@"SBShowNonDefaultSystemApps"];
    [md writeToFile:@"/var/mobile/Library/Preferences/com.apple.springboard.plist" atomically:YES];
    p_spawn(@"/usr/bin/killall", @[@"-9", @"cfprefsd"]);
    p_spawn(@"/bin/touch", @[@"/.installed_socket"]);

    status(@"[*] setting permissions\n");
    chmod("/private", 0777);
    chmod("/private/var", 0777);
    chmod("/private/var/mobile", 0777);
    chmod("/private/var/mobile/Library", 0777);
    chmod("/private/var/mobile/Library/Preferences", 0777);
    
    status(@"[*] installing zebra\n");
    install_zebra();
    
    status(@"[*] running uicache\n");
    p_spawn(@"/usr/bin/uicache", @[]);

}


#pragma mark - [*]--   Load/Unloading Daemons   --[*]

void load_daemons(void) {
    launchctl(@"/System/Library/NanoLaunchDaemons", false);
    launchctl(@"/System/Library/LaunchDaemons", true);
    launchctl(@"/System/Library/NanoLaunchDaemons", true);
    launchctl(@"/Library/LaunchDaemons/com.openssh.sshd.plist", false);
    launchctl(@"/Library/LaunchDaemons", true);
    
    p_spawn(@"/usr/libexec/sshd-keygen-wrapper", @[]);
    p_spawn(@"/bin/bash", @[@"-c", @"ls /Library/LaunchDaemons |\
    while read a; do launchctl load /Library/LaunchDaemons/$a; done; ls /etc/rc.d |\
    while read a; do /etc/rc.d/$a; done;"]);
    status(@"[*] daemons loaded\n");
}


#pragma mark - [*]--   Remount RootFS   --[*]

bool remount(void) {
    int fd;
    FILE *check_perm = fopen("/.socket", "w");
    if (check_perm) {status(@"[*] rootfs already rw\n");return true;}
    struct statfs output;
    statfs("/", &output);

    char* nm = strdup("/dev/disk0s1s1");
    int mntr = mount(output.f_fstypename, "/", MNT_UPDATE, &nm);
    printf("mntr: %d", mntr);
    if ((fd = open("/.socket", O_CREAT | O_RDWR, 0644)) < 0) {printf("[-] failed to mount\n");return false;}
    remove("/.socket");
    close(fd);

    status(@"[+] rootfs remounted\n");
    return true;
}


#pragma mark - [*]--   Root Stuff   --[*]

bool get_root(void) {
    uint32_t k_proc = 0;
    uint32_t my_proc = 0;
    uint32_t my_cred = 0;
    pid_t my_pid = getpid();
    uint32_t proc = rk32(k_base + _allproc);
    while (proc) {
        uint32_t pid = rk32(proc + 8);
        if (pid == my_pid) my_proc = proc;
        else if (pid == 0) k_proc = proc;
        proc = rk32(proc);
    }

    my_cred = rk32(my_proc + 0x98);
    uint32_t k_cred = rk32(k_proc + 0x98);
    wk32(my_proc + 0x98, k_cred);
    setuid(0);
    if (getuid() != 0) {status(@"[-] failed to get root\n");return false;}
    status(concat(@"[*] UID: %x\n", getuid()));
    return true;
}


#pragma mark - [*]--   Kernel Stuff   --[*]

void k_dumper(uint32_t region, uint8_t *k_data, size_t ksize) {
    for (vm_address_t addr = region, e = 0; addr < region + ksize; addr += 2048, e += 2048) {
        pointer_t buf = 0;
        mach_msg_type_number_t sz = 0;
        vm_read(tfp0_port, addr, 2048, &buf, &sz);
        if (buf == 0 || sz == 0)
            continue;
        bcopy((uint8_t *)buf, k_data + e, 2048);
    }
}

bool k_init(uint8_t *buf) {
    uint32_t min_addr = -1;
    uint32_t max_addr = 0;
    memset(&kernel_data, '\0', sizeof(kdata_t));
    
    if (*(uint32_t*)buf != MH_MAGIC) return false;
    const struct mach_header *mach_hdr = (struct mach_header *)buf;
    const uint8_t *q = (uint8_t*)buf + sizeof(struct mach_header);
    
    for (uint32_t i = 0; i < mach_hdr->ncmds; i++) {
        const struct load_command *cmd = (struct load_command *)q;
        if (cmd->cmd == LC_SEGMENT && ((struct segment_command *)q)->vmsize) {
            
            const struct segment_command *seg = (struct segment_command *)q;
            if (min_addr > seg->vmaddr) min_addr = seg->vmaddr;
            if (max_addr < seg->vmaddr + seg->vmsize) max_addr = seg->vmaddr + seg->vmsize;
            
            if (!strcmp(seg->segname, "__TEXT")) {
                kernel_data.text.base.addr = seg->vmaddr;
                kernel_data.text.base.size = seg->vmsize;
                const struct section *sect = (struct section *)(seg + 1);
                
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (!strcmp(sect[j].sectname, "__text")) text_addr = sect[j].addr; text_size = sect[j].size;
                    if (!strcmp(sect[j].sectname, "__const")) const_addr = sect[j].addr; const_size = sect[j].size;
                    if (!strcmp(sect[j].sectname, "__cstring")) cstr_addr = sect[j].addr; cstr_size = sect[j].size;
                    if (!strcmp(sect[j].sectname, "__os_log")) os_log_addr = sect[j].addr; os_log_addr = sect[j].size;
                }
            }
            if (!strcmp(seg->segname, "__DATA")) base_addr = seg->vmaddr; base_size = seg->vmsize;
        }
        
        if (cmd->cmd == LC_UNIXTHREAD) {
            uint32_t *ptr = (uint32_t *)(cmd + 1);
            uint32_t flavor = ptr[0];
            struct {
                uint32_t    r[13];  /* General purpose register r0-r12 */
                uint32_t    sp;     /* Stack pointer r13 */
                uint32_t    lr;     /* Link register r14 */
                uint32_t    pc;     /* Program counter r15 */
                uint32_t    cpsr;   /* Current program status register */
            } *thread = (typeof(thread))(ptr + 2);
            
            if (flavor == 6) kernel_data.kernel_entry = thread->pc;
        }
        q = q + cmd->cmdsize;
    }
    
    kernel_data.kdumpbase = min_addr;
    kernel_data.base.size = max_addr - min_addr;
    return true;
}
 

#pragma mark - [*]--   Main Jailbreak Functions   --[*]

int jailbreak(mach_port_t tfp0) {
    k_base = (uint32_t)get_k_base(tfp0);
    status(concat(@"[*] k_base: 0x%x\n", k_base));
    unsigned char *k_data = (unsigned char *)malloc(0x1800000);
    k_dumper(k_base, k_data, 0x1800000);
    uint32_t last_sect = 0;
    
    status(@"[*] initializing kernel\n");
    if (k_init(k_data) == 0) {status(@"[-] failed to init kernel\n"); return 1;}

    uint32_t text_last = kernel_data.text.base.addr + (uint32_t)kernel_data.text.base.size;
    if (kernel_data.data.base.addr != text_last) last_sect = 0;
    if (text_section > last_sect) last_sect = text_section;
    if (const_section > last_sect) last_sect = const_section;
    if (cstring_section > last_sect) last_sect = cstring_section;
    if (os_log_section > last_sect) last_sect = os_log_section;
    if(text_last <= (last_sect+0x100+432)) last_sect = 0;
    else last_sect += 0x100; last_sect = (last_sect & ~0xFF);
   
    status(@"[*] finding patches\n");
    find_patches(k_base, k_data, kernel_data.base.size);
    status(@"[*] gaining root\n");
    if (!get_root()) {return 1;}
    status(@"[*] applying patches\n");
    apply_patches();
    status(@"[*] patching amfi\n");
    patch_amfi();
    status(@"[*] patching done\n");
    if (!remount()) {return 1;}
    status(@"[*] remounted\n");
    
    NSString *restrap = [[NSUserDefaults standardUserDefaults] stringForKey:@"restrap"];
    if(![[NSFileManager defaultManager]fileExistsAtPath:@"/.installed_socket"]) {
        status(@"[*] installing bootstrap\n");
        install_bootstrap();
    } else if ([restrap isEqual:@"yes"]) {
        status(@"[*] reinstalling bootstrap\n");
        install_bootstrap();
    }
    return 0;
}

int start_jailbreak(void) {
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *release = [NSString stringWithCString:systemInfo.release encoding:NSUTF8StringEncoding];
    if (![release hasPrefix:@"16"]) {status(@"[-] unsupported device, not iOS 10");return 1;}
    if (UINTPTR_MAX == 0xffffffffffffffff) {status(@"[-] unsupported device, not armv7");return 1;}
    NSString *tweaks = [[NSUserDefaults standardUserDefaults] stringForKey:@"tweaks"];
    
    status(@"[*] starting exploit\n");
    mach_port_t tfp0 = s0cket();

    if (tfp0 != MACH_PORT_NULL) {
        tfp0_port = tfp0;
        usleep(100000);
        int ret = jailbreak(tfp0);
        if (ret != 0) {status(concat(@"[-] jailbreak failed: %d\n", ret));return 1;}
        
        status(@"[*] loading daemons\n");
        if ([tweaks isEqual:@"yes"]) load_daemons();
        
        cleanup();
        status(@"[*] all done!\n\n");
    } else {
        status(concat(@"[-] failed to get tfp0: %d\n", tfp0));
        return 1;
    }
    return 0;
}
