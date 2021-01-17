#include "lib/aeabi.h"
#include "lib/putc.h"
#include "lib/printf.h"

#include "drivers/drivers.h"
#include "drivers/display/display.h"


#include "patchfinder.h"
#include "kernel.h"
#include "args.h"

#include "mac.h"

#define KERNEL_SIZE         0x1200000
#define IBOOT_SIZE          0x48000

#define INSN2_NOP__NOP      0xBF00BF00
#define INSN2_RETURN_1      0x47702001
#define INSNT_NOP           0xBF00
#define STR__JBD            0x64626a2e

typedef void (*prepare_and_jump_t)(void* boot, void *ptr, boot_args *arg);

uintptr_t* framebuffer_address;
uintptr_t* base_address;
uint32_t display_width;
uint32_t display_height;
int iBootVer;

get_env_uint_t _get_env_uint;
get_env_t _get_env;

static void print_banner() {
    fb_print_row('=');
    printf(":: OneLol1n for A6-devices\n");
    printf("::\n");
    printf("::   BUILD_VERSION: 1.0 [1A566]\n");
#ifdef DEGUG
    printf("::   BUILD_STYLE: DEBUG\n");
#else
    printf("::   BUILD_STYLE: RELEASE\n");
#endif
    printf("::   Copyright 2021, dora2ios.\n");
    fb_print_row('=');
    printf("* Thanks to:\n");
    printf("axi0mX\n");
    printf("geohot\n");
    printf("iH8sn0w\n");
    printf("JonathanSeals\n");
    printf("planetbeing\n");
    printf("posixninja\n");
    printf("qwertyoruiopz\n");
    printf("synackuk\n");
    printf("xerub\n");
    fb_print_row('-');
}

void WriteAnywhere8(uint32_t addr, uint8_t val){
    *(uint8_t*)addr = val;
}

void WriteAnywhere16(uint32_t addr, uint16_t val){
    *(uint16_t*)addr = val;
}

void WriteAnywhere32(uint32_t addr, uint32_t val){
    *(uint32_t*)addr = val;
}

uint32_t POLICY_OPS(uint32_t addr, uint32_t val){
    if(*(uint32_t*)addr == 0x0){ /* *mpc_ops == 0 -> SKIP */
        return 0;
    }
    
    WriteAnywhere32(addr, val); /* replace with ret0 gadget */
    return 0;
}

/* make_bl - from iloader by xerub */
uint32_t make_bl(int blx, int pos, int tgt)
{
    int delta;
    unsigned short pfx;
    unsigned short sfx;
    unsigned int omask = 0xF800;
    unsigned int amask = 0x7FF;
    if (blx) { /* untested */
        omask = 0xE800;
        amask = 0x7FE;
        pos &= ~3;
    }
    delta = tgt - pos - 4; /* range: 0x400000 */
    pfx = 0xF000 | ((delta >> 12) & 0x7FF);
    sfx =  omask | ((delta >>  1) & amask);
    return (unsigned int)pfx | ((unsigned int)sfx << 16);
}

unsigned int
make_b_w(int pos, int tgt)
{
    int delta;
    unsigned int i;
    unsigned short pfx;
    unsigned short sfx;
    
    unsigned int omask_1k = 0xB800;
    unsigned int omask_2k = 0xB000;
    unsigned int omask_3k = 0x9800;
    unsigned int omask_4k = 0x9000;
    
    unsigned int amask = 0x7FF;
    unsigned int range;
    
    range = 0x400000;
    
    delta = tgt - pos - 4; /* range: 0x400000 */
    i = 0;
    if(tgt > pos) i = tgt - pos - 4;
    if(tgt < pos) i = pos - tgt - 4;
    
    if (i < range){
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_1k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range < i && i < range*2){ /* range: 0x400000-0x800000 */
        delta -= range;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_2k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*2 < i && i < range*3){ /* range: 0x800000-0xc000000 */
        delta -= range*2;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_3k | ((delta >>  1) & amask);
        
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    if (range*3 < i && i < range*4){ /* range: 0xc00000-0x10000000 */
        delta -= range*3;
        pfx = 0xF000 | ((delta >> 12) & 0x7FF);
        sfx =  omask_4k | ((delta >>  1) & amask);
        return (unsigned int)pfx | ((unsigned int)sfx << 16);
    }
    
    return -1;
}

#ifdef HAVE_PAYLOAD
/* This code is private by the sakuRdev team */
void payload_hook(uint32_t base, uint32_t slide, uint32_t _strcmp, uint32_t _copyinstr, uint32_t _syscall_stat, uint32_t _sysent_stat){
    
    /* This code is used at https://dora2ios.web.app/tetherbootx32/. But, This payload is covered by the following Creative Commons license. */
    
    /*
     *  Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0) https://creativecommons.org/licenses/by-nc-nd/4.0/
     *
     *    You are free to:
     *      Share — copy and redistribute the material in any medium or format
     *      The licensor cannot revoke these freedoms as long as you follow the license terms.
     *
     *    Under the following terms:
     *      Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
     *      NonCommercial — You may not use the material for commercial purposes.
     *      NoDerivatives — If you remix, transform, or build upon the material, you may not distribute the modified material.
     *      No additional restrictions — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.
     *
     */
    
    
    
    /* ... */
}
#endif

int
_main(void* boot, void *ptr, boot_args *arg)
{
    prepare_and_jump_t prepare_and_jump;
    
    uint32_t JBp;
    uint32_t gPhysBase;
    uint32_t gVirtBase;
    uint32_t ret0_gadget;
    uint32_t mount_common;
    uint32_t nosuid;
    uint32_t PE_i_can_haz_debugger;
    uint32_t tfp;
    uint32_t locked_task;
    uint32_t sbops;
    uint32_t mapforio1;
    uint32_t mapforio2;
    uint32_t amfi_memcmp;
    uint32_t amfi_substrate;
    uint32_t gasgauge_entitlement;
    uint32_t beq;
    uint32_t launchd;
    
#ifdef HAVE_PAYLOAD
    uint32_t _copyinstr;
    uint32_t _sysent_stat;
    uint32_t _syscall_stat;
    uint32_t _strcmp;
    uint32_t __DATA_SEGMENT;
    uint32_t shellcode_base;
#endif
    
    uint32_t slide; /* unused? */
    
    base_address = find_base_address();
    _get_env_uint = find_get_env_uint();
    framebuffer_address = find_framebuffer_address();
    _get_env = find_get_env();
    display_width = find_display_width();
    display_height = find_display_height();
    iBootVer = find_version();
    
    prepare_and_jump = (prepare_and_jump_t)find_prepare_and_jump(base_address, IBOOT_SIZE);
    
    drivers_init((uint32_t*)framebuffer_address, display_width, display_height);
    
    print_banner();
    
#ifdef DEGUG
    printf("BASE_ADDRESS: 0x%x\n", base_address);
    printf("GET_ENV_UINT: 0x%x\n", _get_env_uint);
    printf("FRAMEBUFFER: 0x%x\n", framebuffer_address);
    printf("GET_ENV: 0x%x\n", _get_env);
    printf("DISPLAY: 0x%x, 0x%x\n", display_width, display_height);
    printf("IBOOT_VERSION: 0x%x\n", iBootVer);
    printf("PREPARE_AND_JUMP: 0x%x\n", prepare_and_jump);
#endif
    
    gVirtBase = arg->virtBase;
    gPhysBase = arg->physBase;
    slide = gVirtBase - gPhysBase;
    printf("Found virtBase: 0x%x\n", gVirtBase);
    printf("Found physBase: 0x%x\n", gPhysBase);
    printf("KASLR slide: 0x%x\n", slide);
    
    /*** patchfinder ***/
    printf("Searching for Kernel offsets...\n");
    
    ret0_gadget = find_ret_0_gadget(gPhysBase, KERNEL_SIZE);
    if(ret0_gadget == 0){
        printf("Failed to get ret0 gadget\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found ret0 gadget: 0x%x\n", ret0_gadget);
#else
    printf("Found ret0 gadget\n");
#endif
    
    
    mount_common = find_mount(gPhysBase, KERNEL_SIZE);
    if(mount_common == 0){
        printf("Failed to get mount\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found mount: 0x%x\n", mount_common);
#else
    printf("Found mount\n");
#endif
    
    
    
    nosuid = find_nosuid(gPhysBase, KERNEL_SIZE);
    if(nosuid == 0){
        printf("nosuid: not found. SKIP\n");
    } else {
#ifdef DEGUG
        printf("Found nosuid: 0x%x\n", nosuid);
#else
        printf("Found nosuid\n");
#endif
    }
    
    PE_i_can_haz_debugger = find_PE_i_can_has_debugger(gPhysBase, gVirtBase);
    if(PE_i_can_haz_debugger == 0){
        printf("Failed to get PE_i_can_has_debugger\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found PE_i_can_has_debugger: 0x%x\n", PE_i_can_haz_debugger);
#else
    printf("Found PE_i_can_has_debugger\n");
#endif
    
    
    tfp = find_task_for_pid(gPhysBase, KERNEL_SIZE);
    if(tfp == 0){
        printf("Failed to get task_for_pid\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found task_for_pid: 0x%x\n", tfp);
#else
    printf("Found task_for_pid\n");
#endif
    
    locked_task = find_convert_port_to_locked_task(gPhysBase, KERNEL_SIZE);
    if(locked_task == 0){
        printf("locked_task: not found. SKIP\n");
    } else {
#ifdef DEGUG
        printf("Found convert_port_to_locked_task: 0x%x\n", locked_task);
#else
        printf("Found convert_port_to_locked_task\n");
#endif
    }
    
    
    
    sbops = (uint32_t)find_sbops(gPhysBase, KERNEL_SIZE);
    if(!sbops){
        printf("Failed to get sbops\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found sbops: 0x%x\n", sbops);
#else
    printf("Found sbops\n");
#endif
    
    
    beq = find_mpo_cred_label_update_execve(gPhysBase, KERNEL_SIZE);
    if(beq == 0){
        printf("update_execve: not found. SKIP\n");
    } else {
#ifdef DEGUG
        printf("Found update_execve: 0x%x\n", beq);
#else
        printf("Found update_execve\n");
#endif
    }
    
    
    mapforio1 = find_mapforio(gPhysBase, gVirtBase, KERNEL_SIZE, 1);
    if(mapforio1 == 0){
        printf("Failed to get mapForIO\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found mapForIO1: 0x%x\n", mapforio1);
#endif
    
    mapforio2 = find_mapforio(gPhysBase, gVirtBase, KERNEL_SIZE, 0);
    if(mapforio2 == 0){
        printf("Failed to get mapForIO\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found mapForIO2: 0x%x\n", mapforio2);
#else
    printf("Found mapForIO\n");
#endif
    
    
    amfi_memcmp = find_amfi_memcmp(gPhysBase, gVirtBase, KERNEL_SIZE);
    if(amfi_memcmp == 0){
        printf("Failed to get amfi memcmp\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found amfi memcmp: 0x%x\n", amfi_memcmp);
#else
    printf("Found amfi memcmp\n");
#endif
    
    
    amfi_substrate = find_amfi_substrate(gPhysBase, KERNEL_SIZE);
    if(amfi_substrate == 0){
        printf("Failed to get amfi substrate\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found amfi substrate: 0x%x\n", amfi_substrate);
#else
    printf("Found amfi substrate\n");
#endif
    
    
    gasgauge_entitlement = find_gasgauge_entitlement(gPhysBase, KERNEL_SIZE);
    if(gasgauge_entitlement == 0){
        printf("Failed to get gasgauge entitlement\n");
        goto out;
    }
#ifdef DEGUG
    printf("Found gasgauge entitlement: 0x%x\n", gasgauge_entitlement);
#else
    printf("Found gasgauge entitlement\n");
#endif
    
    
    launchd = find_launchd(gPhysBase, KERNEL_SIZE);
    if(launchd == 0){
        printf("launchd: not found. SKIP\n");
    } else {
#ifdef DEGUG
        printf("Found launchd: 0x%x\n", beq);
#else
        printf("Found launchd\n");
#endif
    }
    
#ifdef HAVE_PAYLOAD
    _copyinstr = find_copyinstr(gPhysBase, KERNEL_SIZE);
    _sysent_stat = find_syscall(gPhysBase, gVirtBase, KERNEL_SIZE, 0);
    _syscall_stat = find_syscall(gPhysBase, gVirtBase, KERNEL_SIZE, 1);
    _strcmp = find_strcmp(gPhysBase, KERNEL_SIZE);
    
#ifdef DEGUG
    printf("Found _copyinstr: 0x%x\n", _copyinstr);
    printf("Found _sysent_stat: 0x%x\n", _sysent_stat);
    printf("Found _syscall_stat: 0x%x\n", _syscall_stat);
    printf("Found _strcmp: 0x%x\n", _strcmp);
#endif
#endif
    
    /******** kernel patch ********/
    printf("patching PE_i_can_has_debugger\n");
    WriteAnywhere32(PE_i_can_haz_debugger, INSN2_RETURN_1);
    
    printf("patching task_for_pid\n");
    WriteAnywhere16(tfp, INSNT_NOP);
    if(locked_task != 0){
        printf("patching convert_port_to_locked_task\n");
        WriteAnywhere8(locked_task, 0xe0);
    }
    
    printf("patching mount\n");
    WriteAnywhere8(mount_common, 0xe0);
    
    if(nosuid != 0){
        printf("patching nosuid\n");
        WriteAnywhere8(nosuid, 0x00);
    }
    
    printf("patching mapForIO\n");
    WriteAnywhere32(mapforio2, mapforio1);
    
    printf("patching amfi memcmp\n");
    WriteAnywhere32(amfi_memcmp, ret0_gadget);
    
    printf("patching amfi substrate\n");
    WriteAnywhere8(amfi_substrate, 0x04);
    
    printf("patching gasgauge entitlement\n");
    WriteAnywhere32(gasgauge_entitlement, 0xbf00e014);
    
    printf("patching mac_policy_ops\n");
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_mount), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_remount), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_umount), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_write), ret0_gadget);
    
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_file_check_mmap), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_rename), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_access), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_chroot), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_create), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_deleteextattr), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exchangedata), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_exec), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattrlist), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getextattr), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_ioctl), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_link), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_listextattr), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_open), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_readlink), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setattrlist), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setextattr), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setflags), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setmode), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setowner), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_setutimes), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_stat), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_truncate), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_unlink), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_notify_create), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_fsgetpath), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_vnode_check_getattr), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_mount_check_stat), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_setauid), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_getauid), ret0_gadget);
    
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_fork), ret0_gadget);
    
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_get_cs_info), ret0_gadget);
    POLICY_OPS(sbops+offsetof(struct mac_policy_ops, mpo_proc_check_set_cs_info), ret0_gadget);
    
    if(beq != 0){
        WriteAnywhere32(beq, INSN2_NOP__NOP);
    }
    
    JBp = ((uint32_t)base_address) + 0x1f0;
    if(launchd != 0){
        if(*(uint32_t*)(JBp) == 0){
            printf("patching launchd\n");
            WriteAnywhere32(launchd+1, STR__JBD);
        } else {
            /* if(*(uint32_t*)(ibootbase + 0x1f0) != 0), disable the launchd rename hack. */
            printf("SKIP: patch to launchd\n");
        }
    }
    
#ifdef HAVE_PAYLOAD
    __DATA_SEGMENT = *(uint32_t*)(gPhysBase + 0x117c) - slide;
#ifdef DEGUG
    printf("Found __DATA SEGMENT: 0x%x\n", __DATA_SEGMENT);
#else
    printf("Found __DATA SEGMENT\n");
#endif
    shellcode_base = __DATA_SEGMENT - 0x800;
    
    /* Checking whether the r-x area is free space... */
    if(*(uint32_t*)(shellcode_base) == 0x0 && /* shit code.. */
       *(uint32_t*)(shellcode_base+0x200) == 0x0 &&
       *(uint32_t*)(shellcode_base+0x400) == 0x0 &&
       *(uint32_t*)(shellcode_base+0x600) == 0x0 &&
       *(uint32_t*)(shellcode_base+0x7fc) == 0x0 &&
       _copyinstr &&
       _strcmp &&
       _syscall_stat &&
       _sysent_stat){
        printf("Hooking Payload...\n");
#ifdef DEGUG
        printf("Found shellcode_base: 0x%x\n", shellcode_base);
#endif
        payload_hook(shellcode_base, slide, _strcmp, _copyinstr, _syscall_stat, _sysent_stat);
    }
#endif
    
out:
    printf("Booting...\n");
    prepare_and_jump(boot, ptr, arg);
    
    return 0;
}
