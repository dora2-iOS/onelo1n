#include <stdint.h>
#include "kernel.h"
#include "lib/lib.h"

/* --- planetbeing patchfinder --- */
static uint32_t bit_range(uint32_t x, int start, int end)
{
    x = (x << (31 - start)) >> (31 - start);
    x = (x >> end);
    return x;
}

static uint32_t ror(uint32_t x, int places)
{
    return (x >> places) | (x << (32 - places));
}

static int thumb_expand_imm_c(uint16_t imm12)
{
    if(bit_range(imm12, 11, 10) == 0)
    {
        switch(bit_range(imm12, 9, 8))
        {
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
    } else
    {
        uint32_t unrotated_value = 0x80 | bit_range(imm12, 6, 0);
        return ror(unrotated_value, bit_range(imm12, 11, 7));
    }
}

int insn_is_32bit(insn_t* i)
{
    return (*i & 0xe000) == 0xe000 && (*i & 0x1800) != 0x0;
}

int insn_is_bne(insn_t* i) {
    return (*i & 0xFF00) == 0xD100;
}

int insn_is_beq(insn_t* i) {
    return (*i & 0xFF00) == 0xD000;
}

int insn_is_beqw(insn_t* i) {
    return ((i[0] & 0xFBC0) == 0xf000) && ((i[1] & 0xD000) == 0x8000);
}

int insn_is_ldr_literal(insn_t* i)
{
    return (*i & 0xF800) == 0x4800 || (*i & 0xFF7F) == 0xF85F;
}

int insn_ldr_literal_rt(insn_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i >> 8) & 7;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) >> 12) & 0xF;
    else
        return 0;
}

int insn_ldr_literal_imm(insn_t* i)
{
    if((*i & 0xF800) == 0x4800)
        return (*i & 0xF) << 2;
    else if((*i & 0xFF7F) == 0xF85F)
        return (*(i + 1) & 0xFFF) * (((*i & 0x0800) == 0x0800) ? 1 : -1);
    else
        return 0;
}

int insn_is_add_reg(insn_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return 1;
    else if((*i & 0xFF00) == 0x4400)
        return 1;
    else if((*i & 0xFFE0) == 0xEB00)
        return 1;
    else
        return 0;
}

int insn_add_reg_rd(insn_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

int insn_add_reg_rn(insn_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return ((*i >> 3) & 7);
    else if((*i & 0xFF00) == 0x4400)
        return (*i & 7) | ((*i & 0x80) >> 4) ;
    else if((*i & 0xFFE0) == 0xEB00)
        return (*i & 0xF);
    else
        return 0;
}

int insn_add_reg_rm(insn_t* i)
{
    if((*i & 0xFE00) == 0x1800)
        return (*i >> 6) & 7;
    else if((*i & 0xFF00) == 0x4400)
        return (*i >> 3) & 0xF;
    else if((*i & 0xFFE0) == 0xEB00)
        return *(i + 1) & 0xF;
    else
        return 0;
}

int insn_is_movt(insn_t* i)
{
    return (*i & 0xFBF0) == 0xF2C0 && (*(i + 1) & 0x8000) == 0;
}

int insn_movt_rd(insn_t* i)
{
    return (*(i + 1) >> 8) & 0xF;
}

int insn_movt_imm(insn_t* i)
{
    return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
}

int insn_is_mov_imm(insn_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return 1;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return 1;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return 1;
    else
        return 0;
}

int insn_mov_imm_rd(insn_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return (*i >> 8) & 7;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return (*(i + 1) >> 8) & 0xF;
    else
        return 0;
}

int insn_mov_imm_imm(insn_t* i)
{
    if((*i & 0xF800) == 0x2000)
        return *i & 0xF;
    else if((*i & 0xFBEF) == 0xF04F && (*(i + 1) & 0x8000) == 0)
        return thumb_expand_imm_c(((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF));
    else if((*i & 0xFBF0) == 0xF240 && (*(i + 1) & 0x8000) == 0)
        return ((*i & 0xF) << 12) | ((*i & 0x0400) << 1) | ((*(i + 1) & 0x7000) >> 4) | (*(i + 1) & 0xFF);
    else
        return 0;
}

insn_t* find_literal_ref(uint8_t* kdata, size_t ksize, insn_t* insn, uintptr_t address) {
    insn_t* current_instruction = insn;
    uint32_t value[16];
    memset(value, 0, sizeof(value));
    
    while((uintptr_t)current_instruction < (uintptr_t)(kdata + ksize)) {
        if(insn_is_mov_imm(current_instruction)) {
            value[insn_mov_imm_rd(current_instruction)] = insn_mov_imm_imm(current_instruction);
        }
        else if(insn_is_ldr_literal(current_instruction)) {
            uintptr_t literal_address  = (uintptr_t)kdata + ((((uintptr_t)current_instruction - (uintptr_t)kdata) + 4) & 0xFFFFFFFC) + insn_ldr_literal_imm(current_instruction);
            if(literal_address >= (uintptr_t)kdata && (literal_address + 4) <= ((uintptr_t)kdata + ksize)) {
                value[insn_ldr_literal_rt(current_instruction)] = *(uint32_t*)(literal_address);
            }
        }
        else if(insn_is_movt(current_instruction)) {
            value[insn_movt_rd(current_instruction)] |= insn_movt_imm(current_instruction) << 16;
        }
        else if(insn_is_add_reg(current_instruction)) {
            int reg = insn_add_reg_rd(current_instruction);
            if(insn_add_reg_rm(current_instruction) == 15 && insn_add_reg_rn(current_instruction) == reg) {
                value[reg] += ((uintptr_t)current_instruction - (uintptr_t)kdata) + 4;
                if(value[reg] == address) {
                    return current_instruction;
                }
            }
        }
        
        current_instruction += insn_is_32bit(current_instruction) ? 2 : 1;
    }
    
    return NULL;
}

struct segment_command *find_segment(struct mach_header *mh, const char *segname) {
    struct load_command *lc;
    struct segment_command *s, *fs = NULL;
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    while ((uintptr_t)lc < (uintptr_t)mh + (uintptr_t)mh->sizeofcmds) {
        if (lc->cmd == LC_SEGMENT) {
            s = (struct segment_command *)lc;
            if (!strcmp(s->segname, segname)) {
                fs = s;
                break;
            }
        }
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return fs;
}

/* Find start of a load command in a macho */
struct load_command *find_load_command(struct mach_header *mh, uint32_t cmd)
{
    struct load_command *lc, *flc;
    
    lc = (struct load_command *)((uintptr_t)mh + sizeof(struct mach_header));
    
    while (1) {
        if ((uintptr_t)lc->cmd == cmd) {
            flc = (struct load_command *)(uintptr_t)lc;
            break;
        }
        lc = (struct load_command *)((uintptr_t)lc + (uintptr_t)lc->cmdsize);
    }
    return flc;
}

struct section *find_section(struct segment_command *seg, const char *name) {
    struct section *sect, *fs = NULL;
    uint32_t i = 0;
    for (i = 0, sect = (struct section *)((uintptr_t)seg + (uintptr_t)sizeof(struct segment_command));
         i < seg->nsects;
         i++, sect = (struct section*)((uintptr_t)sect + sizeof(struct section))) {
        if (!strcmp(sect->sectname, name)) {
            fs = sect;
            break;
        }
    }
    return fs;
}

void* find_sym(struct mach_header *mh, const char *name, uintptr_t phys_base, uintptr_t virt_base) {
    struct segment_command* linkedit;
    struct symtab_command* symtab;
    uint32_t linkedit_phys;
    char* sym_str_table;
    struct nlist* sym_table;
    uint32_t i;
    
    linkedit = find_segment(mh, SEG_LINKEDIT);
    symtab = (struct symtab_command*) find_load_command(mh, LC_SYMTAB);
    
    linkedit_phys = VIRT_TO_PHYS(linkedit->vmaddr);
    
    sym_str_table = (char*) (((char*)(linkedit_phys - linkedit->fileoff)) + symtab->stroff);
    sym_table = (struct nlist*)(((char*)(linkedit_phys - linkedit->fileoff)) + symtab->symoff);
    
    for (i = 0; i < symtab->nsyms; i++) {
        if (sym_table[i].n_value && !strcmp(name,&sym_str_table[sym_table[i].n_un.n_strx])) {
            return (void*)VIRT_TO_PHYS(sym_table[i].n_value);
        }
    }
    return 0;
}


uint32_t find_ret_0_gadget(uint32_t phys_base, uint32_t ksize) {
    uint32_t ret_0_gadget;
    insn_t search[2];
    
    search[0] = MOVS_R0_0;
    search[1] = BX_LR;
    
    ret_0_gadget = (uint32_t)memmem((void*)phys_base, ksize, search, 2 * sizeof(insn_t));
    
    if(!ret_0_gadget) {
        return 0;
    }
    
    ret_0_gadget |= 1;
    return ret_0_gadget;
}


uintptr_t* find_sbops(uintptr_t phys_base, uint32_t ksize) {
    
    uintptr_t seatbelt_sandbox_str_addr;
    char* seatbelt_sandbox_str_xref;
    uint32_t val;
    uintptr_t* sbops_address_loc;
    uintptr_t* sbops_address;
    
    seatbelt_sandbox_str_addr = (uintptr_t)memmem((void*)phys_base, ksize, "Seatbelt sandbox policy", strlen("Seatbelt sandbox policy"));
    
    if(!seatbelt_sandbox_str_addr) {
        return NULL;
    }
    seatbelt_sandbox_str_xref = memmem((void*)phys_base, ksize, &seatbelt_sandbox_str_addr, sizeof(uintptr_t));
    
    if(!seatbelt_sandbox_str_xref) {
        return NULL;
    }
    
    val = 1;
    
    sbops_address_loc = memmem((void*)seatbelt_sandbox_str_xref, 0x10, &val, sizeof(uint32_t));
    
    if(!sbops_address_loc) {
        return NULL;
    }
    sbops_address = (uintptr_t*)*(uintptr_t*)((uintptr_t)sbops_address_loc + 4);
    
    return (uintptr_t*)sbops_address;
}

uint32_t find_amfi_memcmp(uint32_t phys_base, uint32_t virt_base, uint32_t ksize) {
    uint32_t i;
    uint32_t mach_msg_rpc_from_kernel_proper;
    uint32_t search_ptr[2];
    uint32_t amfi_memcmp;
    
    i = (uint32_t)find_sym((void*)(phys_base+0x1000), "_memcmp", phys_base, virt_base);
    if(!i) {
        return 0;
    }
    
    i += 1;
    
    mach_msg_rpc_from_kernel_proper = (uint32_t)find_sym((void*)(phys_base+0x1000), "_mach_msg_rpc_from_kernel_proper", phys_base, virt_base);
    if(!mach_msg_rpc_from_kernel_proper) {
        return 0;
    }
    
    mach_msg_rpc_from_kernel_proper += 1;
    
    search_ptr[0] = mach_msg_rpc_from_kernel_proper;
    search_ptr[1] = i;
    
    amfi_memcmp = (uint32_t)memmem((void*)phys_base, ksize, search_ptr, 2 * sizeof(uint32_t));
    if(!amfi_memcmp) {
        return 0;
    }
    
    return amfi_memcmp+4;
}

uint32_t find_mapforio(uint32_t phys_base, uint32_t virt_base, uint32_t ksize, int val) {
    uint32_t mapforio;
    insn_t search[3];
    uint32_t search_ptr[1];
    uint32_t i;
    uint32_t a;
    
    i = (uint32_t)find_sym((void*)(phys_base+0x1000), "_PE_i_can_has_kernel_configuration", phys_base, virt_base);
    if(!i) {
        return 0;
    }
    
    i += 1;
    
    
    a = (uint32_t)find_sym((void*)(phys_base+0x1000), "_OSMalloc_Tagfree", phys_base, virt_base);
    if(!a) {
        return 0;
    }
    
    a += 1;
    /*
     ldr        r0, [r5, #0x58]
     add        r0, r8
     ldrb       r0, [r0, #0x6]
     */
    search[0] = 0x6da8;
    search[1] = 0x4440;
    search[2] = 0x7980;
    
    mapforio = (uint32_t)memmem((void*)phys_base, ksize, search, 3 * sizeof(insn_t));
    if(!mapforio) {
        return 0;
    }

    mapforio += 1;
    
    if(val == 1){
        return mapforio;
    }
    
    search_ptr[0] = a;
    mapforio = (uint32_t)memmem((void*)phys_base, ksize, search_ptr, 1 * sizeof(uint32_t));
    if(!mapforio) {
        return 0;
    }
    
    if(*(uint32_t*)(mapforio+4) == i){
        return mapforio+4;
    }
    
    return 0;
}

uint32_t find_amfi_substrate(uint32_t phys_base, uint32_t ksize) {
    uint32_t search[2];
    uint32_t substrate;
    
    search[0] = 0x90004478;
    search[1] = 0xe03a2600;
    
    substrate = (uint32_t)memmem((void*)phys_base, ksize, search, 2 * sizeof(uint32_t));
    if(!substrate) {
        
        search[0] = 0x90006800;
        search[1] = 0xe0362600;
        
        substrate = (uint32_t)memmem((void*)phys_base, ksize, search, 2 * sizeof(uint32_t));
        
        if(!substrate) {
            return 0;
        }
    }
    
    return substrate+4;
}

uint32_t find_gasgauge_entitlement(uint32_t phys_base, uint32_t ksize) {
    uint16_t search1[5];
    uint32_t s1;
    
    search1[0] = 0xd015; /* beq */
    search1[1] = 0xf10d; /* add.w r5, sp, #0x1 */
    search1[2] = 0x0501;
    search1[3] = 0x21ff; /* movs r1, #0xff */
    search1[4] = 0x4628; /* mov r0, r5 */
    
    s1 = (uint32_t)memmem((void*)phys_base, ksize, search1, 5 * sizeof(uint16_t));
    if(!s1) {
        return 0;
    }
    s1 += 6;
    s1 -= 4;
    
    return s1;
}

uint32_t find_mpo_cred_label_update_execve(uint32_t phys_base, uint32_t ksize) {
    uint32_t search[2];
    uint32_t strd;
    uint32_t beq;
    
    /* iOS 10.3 or higher
     80fc28d0         strd       r4, r0, [sp, #0x64]
     80fc28d4         ldr        r0, [sp, #0x64]
     80fc28d6         cmp        r0, #0x0
     80fc28d8         ldr        r4, [sp, #0x28]
     80fc28da         beq.w      dword_80fc2870+640 <- NOP out
     */
    search[0] = 0x4019e9cd;
    search[1] = 0x28009819;
    
    strd = (uint32_t)memmem((void*)phys_base, ksize, search, 2 * sizeof(uint32_t));
    if(!strd) {
        return 0;
    }
    beq = strd + 0xa;
    
    return beq;
}

uint32_t find_PE_i_can_has_debugger(uint32_t phys_base, uint32_t virt_base) {
    uint32_t i;
    
    i = (uint32_t)find_sym((void*)(phys_base+0x1000), "_PE_i_can_has_debugger", phys_base, virt_base);
    if(!i) {
        return 0;
    }
    
    return i;
}

uint32_t find_nosuid(uint32_t phys_base, uint32_t ksize) {
    uint16_t search[5];
    uint32_t i;
    
    /* iOS 10.3 or higher
     80102092         and.w      r1, r4, r2
     80102096         orrs       r0, r1
     80102098         orr        r1, r0, #0x8 <- orr r1, r0, #0x0
     8010209c         str.w      r1, [r8, #0x38]
     */
    
    search[0] = 0xea04;
    search[1] = 0x0102;
    search[2] = 0x4308;
    search[3] = 0xf040;
    search[4] = 0x0108;
    
    
    i = (uint32_t)memmem((void*)phys_base, ksize, search, 5 * sizeof(uint16_t));
    if(!i) {
        return 0;
    }
    
    i += 8;
    
    return i;
}

uint32_t find_mount(uint32_t phys_base, uint32_t ksize) {
    uint16_t search1[3];
    uint16_t search2[5];
    uint32_t i;
    /* iOS 10.3.4
     801030de         tst.w      r0, #0x40
     801030e2         beq        loc_80103166 <- b loc_80103166
     
     801030e4         tst.w      sl, #0x1
     801030e8         bne        loc_80103162
     */
    
    search1[0] = 0xf01a;
    search1[1] = 0x0f01;
    search1[2] = 0xd13b;
    i = (uint32_t)memmem((void*)phys_base, ksize, search1, 3 * sizeof(uint16_t));
    if(!i) {
        /* iOS 10.2.1
         80104ff4         tst.w      r0, #0x40
         80104ff8         beq        loc_8010500e <- b loc_8010500e
         
         80104ffa         tst.w      fp, #0x1
         80104ffe         bne        loc_8010500a
         80105000         mov.w      r8, #0x1
         */
        search2[0] = 0xf01b;
        search2[1] = 0x0f01;
        search2[2] = 0xd104;
        search2[3] = 0xf04f;
        search2[4] = 0x0801;
        i = (uint32_t)memmem((void*)phys_base, ksize, search2, 5 * sizeof(uint16_t));
        if(!i) {
            return 0;
        }
    }
    
    i -= 1;
    
    return i;
}

uint32_t find_task_for_pid(uint32_t phys_base, uint32_t ksize) {
    int i;
    uint16_t search[4];
    
    /* task_for_pid():
     *      if (pid == 0) -> if (0)
     *
     * 802d8ccc         movs       r1, #0x0
     * 802d8cce         strd       r1, r1, [sp, #0x24 + var_20]
     * 802d8cd2         cmp        r6, #0x0
     * 802d8cd4         beq        loc_802d8d72 <- NOP
     
     * 802d8cd6         bl         _port_name_to_task
     */
    search[0] = 0x2100;
    search[1] = 0xe9cd;
    search[2] = 0x1101;
    search[3] = 0x2e00;
    i = (uint32_t)memmem((void*)phys_base, ksize, search, 4 * sizeof(uint16_t));
    if(!i) {
        return 0;
    }
    
    i += 8;
    
    return i;
}

uint32_t find_convert_port_to_locked_task(uint32_t phys_base, uint32_t ksize) {
    int i;
    uint16_t search[4];
    
    /* convert_port_to_locked_task():
     *      if (task == kernel_task && ..) -> if(0)
     * 8002a904         ldr        r6, [r5, #0x48]
     * 8002a906         ldr.w      r0, [fp]
     * 8002a90a         cmp        r6, r0
     * 8002a90c         bne        loc_8002a91e <- b loc_8002a91e
     */
    search[0] = 0x6cae;
    search[1] = 0xf8db;
    search[2] = 0x0000;
    search[3] = 0x4286;
    i = (uint32_t)memmem((void*)phys_base, ksize, search, 4 * sizeof(uint16_t));
    if(!i) {
        return 0;
    }
    
    i += 9;
    
    return i;
}


uint32_t find_launchd(uint32_t phys_base, uint32_t ksize) {
    uint32_t str;
    uint8_t search[14];
    
    search[0]  = 0x2f; /* '/' */
    search[1]  = 0x73; /* 's' */
    search[2]  = 0x62; /* 'b' */
    search[3]  = 0x69; /* 'i' */
    search[4]  = 0x6e; /* 'n' */
    search[5]  = 0x2f; /* '/' */
    search[6]  = 0x6c; /* 'l' */
    search[7]  = 0x61; /* 'a' */
    search[8]  = 0x75; /* 'u' */
    search[9]  = 0x6e; /* 'n' */
    search[10] = 0x63; /* 'c' */
    search[11] = 0x68; /* 'h' */
    search[12] = 0x64; /* 'd' */
    search[13] = 0x00; /* '.' */
    
    str = (uint32_t)memmem((void*)phys_base, ksize, search, 14 * sizeof(uint8_t));
    if(!str) {
        return 0;
    }
    
    return str;
}


uint32_t find_syscall(uint32_t phys_base, uint32_t virt_base, uint32_t ksize, int sysent) {
    uint32_t syscall0;
    uint32_t syscall;
    uint32_t search[4];
    uint32_t search_ptr[1];
    uint32_t slide;
    
    
    slide = virt_base - phys_base;
    search[0]  = 0x466fb580;
    search[1]  = 0xee1db082;
    search[2]  = 0x20002f90;
    search[3]  = 0x200c9001;
    
    syscall0 = (uint32_t)memmem((void*)phys_base, ksize, search, 4 * sizeof(uint32_t));
    if(!syscall0) {
        return 0;
    }
    
    syscall0 += 1;
    syscall0 += slide;
    
    search_ptr[0] = syscall0;
    syscall = (uint32_t)memmem((void*)phys_base, ksize, search_ptr, 1 * sizeof(uint32_t));
    if(!syscall) {
        return 0;
    }
    
    syscall += 0x8D0;
    if(sysent) return (*(uint32_t*)syscall) - slide - 1;
    if(!sysent) return syscall;
    
    return 0;
}

uint32_t find_strcmp(uint32_t phys_base, uint32_t ksize) {
    uint32_t i;
    uint8_t search[12];
        
    search[0] = 0x01;
    search[1] = 0x31;
    search[2] = 0x01;
    search[3] = 0x30;
    search[4] = 0x00;
    search[5] = 0x2a;
    search[6] = 0x04;
    search[7] = 0xbf;
    search[8] = 0x00;
    search[9] = 0x20;
    search[10] = 0x70;
    search[11] = 0x47;
    
    
    i = (uint32_t)memmem((void*)phys_base, ksize, search, 12 * sizeof(uint8_t));
    if(!i) {
        return 0;
    }
    
    return i - 0x2;
}

uint32_t find_copyinstr(uint32_t phys_base, uint32_t ksize) {
    uint32_t i;
    uint32_t search[3];
    
    search[0] = 0xe92d0030;
    search[1] = 0xe0804002;
    search[2] = 0xe3540102;
    
    i = (uint32_t)memmem((void*)phys_base, ksize, search, 3 * sizeof(uint32_t));
    if(!i) {
        return 0;
    }
    
    return i;
}

uint32_t find_prepare_and_jump(uint32_t iboot_base, uint32_t isize){
    uint32_t i;
    uint8_t search[10];
    
    search[0] = 0xf0;
    search[1] = 0xb5;
    search[2] = 0x03;
    search[3] = 0xaf;
    search[4] = 0x15;
    search[5] = 0x46;
    search[6] = 0x0c;
    search[7] = 0x46;
    search[8] = 0x06;
    search[9] = 0x46;
    
    i = (uint32_t)memmem((void*)iboot_base, isize, search, 10 * sizeof(uint8_t));
    if(!i) {
        return 0;
    }
    
    return i+1;
}

