/*
 *  i386 helpers (without register variable usage)
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#ifndef CONFIG_USER_ONLY
#include "sysemu/sysemu.h"
#endif

void cpu_sync_bndcs_hflags(CPUX86State *env)
{
    uint32_t hflags = env->hflags;
    uint32_t hflags2 = env->hflags2;
    uint32_t bndcsr;

    if ((hflags & HF_CPL_MASK) == 3) {
        bndcsr = env->bndcs_regs.cfgu;
    } else {
        bndcsr = env->msr_bndcfgs;
    }

    if ((env->cr[4] & CR4_OSXSAVE_MASK)
        && (env->xcr0 & XSTATE_BNDCSR_MASK)
        && (bndcsr & BNDCFG_ENABLE)) {
        hflags |= HF_MPX_EN_MASK;
    } else {
        hflags &= ~HF_MPX_EN_MASK;
    }

    if (bndcsr & BNDCFG_BNDPRESERVE) {
        hflags2 |= HF2_MPX_PR_MASK;
    } else {
        hflags2 &= ~HF2_MPX_PR_MASK;
    }

    env->hflags = hflags;
    env->hflags2 = hflags2;
}

static void cpu_x86_version(CPUX86State *env, int *family, int *model)
{
    int cpuver = env->cpuid_version;

    if (family == NULL || model == NULL) {
        return;
    }

    *family = (cpuver >> 8) & 0x0f;
    *model = ((cpuver >> 12) & 0xf0) + ((cpuver >> 4) & 0x0f);
}

/* Broadcast MCA signal for processor version 06H_EH and above */
int cpu_x86_support_mca_broadcast(CPUX86State *env)
{
    int family = 0;
    int model = 0;

    cpu_x86_version(env, &family, &model);
    if ((family == 6 && model >= 14) || family > 6) {
        return 1;
    }

    return 0;
}

/***********************************************************/
/* x86 debug */

static const char *cc_op_str[CC_OP_NB] = {
    "DYNAMIC",
    "EFLAGS",

    "MULB",
    "MULW",
    "MULL",
    "MULQ",

    "ADDB",
    "ADDW",
    "ADDL",
    "ADDQ",

    "ADCB",
    "ADCW",
    "ADCL",
    "ADCQ",

    "SUBB",
    "SUBW",
    "SUBL",
    "SUBQ",

    "SBBB",
    "SBBW",
    "SBBL",
    "SBBQ",

    "LOGICB",
    "LOGICW",
    "LOGICL",
    "LOGICQ",

    "INCB",
    "INCW",
    "INCL",
    "INCQ",

    "DECB",
    "DECW",
    "DECL",
    "DECQ",

    "SHLB",
    "SHLW",
    "SHLL",
    "SHLQ",

    "SARB",
    "SARW",
    "SARL",
    "SARQ",

    "BMILGB",
    "BMILGW",
    "BMILGL",
    "BMILGQ",

    "ADCX",
    "ADOX",
    "ADCOX",

    "CLR",
};

static void
cpu_x86_dump_seg_cache(CPUX86State *env, FILE *f, fprintf_function cpu_fprintf,
                       const char *name, struct SegmentCache *sc)
{
#ifdef TARGET_X86_64
    if (env->hflags & HF_CS64_MASK) {
        cpu_fprintf(f, "%-3s=%04x %016" PRIx64 " %08x %08x", name,
                    sc->selector, sc->base, sc->limit, sc->flags & 0x00ffff00);
    } else
#endif
    {
        cpu_fprintf(f, "%-3s=%04x %08x %08x %08x", name, sc->selector,
                    (uint32_t)sc->base, sc->limit, sc->flags & 0x00ffff00);
    }

    if (!(env->hflags & HF_PE_MASK) || !(sc->flags & DESC_P_MASK))
        goto done;

    cpu_fprintf(f, " DPL=%d ", (sc->flags & DESC_DPL_MASK) >> DESC_DPL_SHIFT);
    if (sc->flags & DESC_S_MASK) {
        if (sc->flags & DESC_CS_MASK) {
            cpu_fprintf(f, (sc->flags & DESC_L_MASK) ? "CS64" :
                           ((sc->flags & DESC_B_MASK) ? "CS32" : "CS16"));
            cpu_fprintf(f, " [%c%c", (sc->flags & DESC_C_MASK) ? 'C' : '-',
                        (sc->flags & DESC_R_MASK) ? 'R' : '-');
        } else {
            cpu_fprintf(f,
                        (sc->flags & DESC_B_MASK || env->hflags & HF_LMA_MASK)
                        ? "DS  " : "DS16");
            cpu_fprintf(f, " [%c%c", (sc->flags & DESC_E_MASK) ? 'E' : '-',
                        (sc->flags & DESC_W_MASK) ? 'W' : '-');
        }
        cpu_fprintf(f, "%c]", (sc->flags & DESC_A_MASK) ? 'A' : '-');
    } else {
        static const char *sys_type_name[2][16] = {
            { /* 32 bit mode */
                "Reserved", "TSS16-avl", "LDT", "TSS16-busy",
                "CallGate16", "TaskGate", "IntGate16", "TrapGate16",
                "Reserved", "TSS32-avl", "Reserved", "TSS32-busy",
                "CallGate32", "Reserved", "IntGate32", "TrapGate32"
            },
            { /* 64 bit mode */
                "<hiword>", "Reserved", "LDT", "Reserved", "Reserved",
                "Reserved", "Reserved", "Reserved", "Reserved",
                "TSS64-avl", "Reserved", "TSS64-busy", "CallGate64",
                "Reserved", "IntGate64", "TrapGate64"
            }
        };
        cpu_fprintf(f, "%s",
                    sys_type_name[(env->hflags & HF_LMA_MASK) ? 1 : 0]
                                 [(sc->flags & DESC_TYPE_MASK)
                                  >> DESC_TYPE_SHIFT]);
    }
done:
    cpu_fprintf(f, "\n");
}

#define DUMP_CODE_BYTES_TOTAL    50
#define DUMP_CODE_BYTES_BACKWARD 20

void x86_cpu_dump_state(CPUState *cs, FILE *f, fprintf_function cpu_fprintf,
                        int flags)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;
    int eflags, i, nb;
    char cc_op_name[32];
    static const char *seg_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };

    eflags = cpu_compute_eflags(env);
#ifdef TARGET_X86_64
    if (env->hflags & HF_CS64_MASK) {
        cpu_fprintf(f,
                    "RAX=%016" PRIx64 " RBX=%016" PRIx64 " RCX=%016" PRIx64 " RDX=%016" PRIx64 "\n"
                    "RSI=%016" PRIx64 " RDI=%016" PRIx64 " RBP=%016" PRIx64 " RSP=%016" PRIx64 "\n"
                    "R8 =%016" PRIx64 " R9 =%016" PRIx64 " R10=%016" PRIx64 " R11=%016" PRIx64 "\n"
                    "R12=%016" PRIx64 " R13=%016" PRIx64 " R14=%016" PRIx64 " R15=%016" PRIx64 "\n"
                    "RIP=%016" PRIx64 " RFL=%08x [%c%c%c%c%c%c%c] CPL=%d II=%d A20=%d SMM=%d HLT=%d\n",
                    env->regs[R_EAX],
                    env->regs[R_EBX],
                    env->regs[R_ECX],
                    env->regs[R_EDX],
                    env->regs[R_ESI],
                    env->regs[R_EDI],
                    env->regs[R_EBP],
                    env->regs[R_ESP],
                    env->regs[8],
                    env->regs[9],
                    env->regs[10],
                    env->regs[11],
                    env->regs[12],
                    env->regs[13],
                    env->regs[14],
                    env->regs[15],
                    env->eip, eflags,
                    eflags & DF_MASK ? 'D' : '-',
                    eflags & CC_O ? 'O' : '-',
                    eflags & CC_S ? 'S' : '-',
                    eflags & CC_Z ? 'Z' : '-',
                    eflags & CC_A ? 'A' : '-',
                    eflags & CC_P ? 'P' : '-',
                    eflags & CC_C ? 'C' : '-',
                    env->hflags & HF_CPL_MASK,
                    (env->hflags >> HF_INHIBIT_IRQ_SHIFT) & 1,
                    (env->a20_mask >> 20) & 1,
                    (env->hflags >> HF_SMM_SHIFT) & 1,
                    cs->halted);
    } else
#endif
    {
        cpu_fprintf(f, "EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n"
                    "ESI=%08x EDI=%08x EBP=%08x ESP=%08x\n"
                    "EIP=%08x EFL=%08x [%c%c%c%c%c%c%c] CPL=%d II=%d A20=%d SMM=%d HLT=%d\n",
                    (uint32_t)env->regs[R_EAX],
                    (uint32_t)env->regs[R_EBX],
                    (uint32_t)env->regs[R_ECX],
                    (uint32_t)env->regs[R_EDX],
                    (uint32_t)env->regs[R_ESI],
                    (uint32_t)env->regs[R_EDI],
                    (uint32_t)env->regs[R_EBP],
                    (uint32_t)env->regs[R_ESP],
                    (uint32_t)env->eip, eflags,
                    eflags & DF_MASK ? 'D' : '-',
                    eflags & CC_O ? 'O' : '-',
                    eflags & CC_S ? 'S' : '-',
                    eflags & CC_Z ? 'Z' : '-',
                    eflags & CC_A ? 'A' : '-',
                    eflags & CC_P ? 'P' : '-',
                    eflags & CC_C ? 'C' : '-',
                    env->hflags & HF_CPL_MASK,
                    (env->hflags >> HF_INHIBIT_IRQ_SHIFT) & 1,
                    (env->a20_mask >> 20) & 1,
                    (env->hflags >> HF_SMM_SHIFT) & 1,
                    cs->halted);
    }

    for(i = 0; i < 6; i++) {
        cpu_x86_dump_seg_cache(env, f, cpu_fprintf, seg_name[i],
                               &env->segs[i]);
    }
    cpu_x86_dump_seg_cache(env, f, cpu_fprintf, "LDT", &env->ldt);
    cpu_x86_dump_seg_cache(env, f, cpu_fprintf, "TR", &env->tr);

#ifdef TARGET_X86_64
    if (env->hflags & HF_LMA_MASK) {
        cpu_fprintf(f, "GDT=     %016" PRIx64 " %08x\n",
                    env->gdt.base, env->gdt.limit);
        cpu_fprintf(f, "IDT=     %016" PRIx64 " %08x\n",
                    env->idt.base, env->idt.limit);
        cpu_fprintf(f, "CR0=%08x CR2=%016" PRIx64 " CR3=%016" PRIx64 " CR4=%08x\n",
                    (uint32_t)env->cr[0],
                    env->cr[2],
                    env->cr[3],
                    (uint32_t)env->cr[4]);
        for(i = 0; i < 4; i++)
            cpu_fprintf(f, "DR%d=%016" PRIx64 " ", i, env->dr[i]);
        cpu_fprintf(f, "\nDR6=%016" PRIx64 " DR7=%016" PRIx64 "\n",
                    env->dr[6], env->dr[7]);
    } else
#endif
    {
        cpu_fprintf(f, "GDT=     %08x %08x\n",
                    (uint32_t)env->gdt.base, env->gdt.limit);
        cpu_fprintf(f, "IDT=     %08x %08x\n",
                    (uint32_t)env->idt.base, env->idt.limit);
        cpu_fprintf(f, "CR0=%08x CR2=%08x CR3=%08x CR4=%08x\n",
                    (uint32_t)env->cr[0],
                    (uint32_t)env->cr[2],
                    (uint32_t)env->cr[3],
                    (uint32_t)env->cr[4]);
        for(i = 0; i < 4; i++) {
            cpu_fprintf(f, "DR%d=" TARGET_FMT_lx " ", i, env->dr[i]);
        }
        cpu_fprintf(f, "\nDR6=" TARGET_FMT_lx " DR7=" TARGET_FMT_lx "\n",
                    env->dr[6], env->dr[7]);
    }
    if (flags & CPU_DUMP_CCOP) {
        if ((unsigned)env->cc_op < CC_OP_NB)
            snprintf(cc_op_name, sizeof(cc_op_name), "%s", cc_op_str[env->cc_op]);
        else
            snprintf(cc_op_name, sizeof(cc_op_name), "[%d]", env->cc_op);
#ifdef TARGET_X86_64
        if (env->hflags & HF_CS64_MASK) {
            cpu_fprintf(f, "CCS=%016" PRIx64 " CCD=%016" PRIx64 " CCO=%-8s\n",
                        env->cc_src, env->cc_dst,
                        cc_op_name);
        } else
#endif
        {
            cpu_fprintf(f, "CCS=%08x CCD=%08x CCO=%-8s\n",
                        (uint32_t)env->cc_src, (uint32_t)env->cc_dst,
                        cc_op_name);
        }
    }
    cpu_fprintf(f, "EFER=%016" PRIx64 "\n", env->efer);
    if (flags & CPU_DUMP_FPU) {
        int fptag;
        fptag = 0;
        for(i = 0; i < 8; i++) {
            fptag |= ((!env->fptags[i]) << i);
        }
        update_mxcsr_from_sse_status(env);
        cpu_fprintf(f, "FCW=%04x FSW=%04x [ST=%d] FTW=%02x MXCSR=%08x\n",
                    env->fpuc,
                    (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11,
                    env->fpstt,
                    fptag,
                    env->mxcsr);
        for(i=0;i<8;i++) {
            CPU_LDoubleU u;
            u.d = env->fpregs[i].d;
            cpu_fprintf(f, "FPR%d=%016" PRIx64 " %04x",
                        i, u.l.lower, u.l.upper);
            if ((i & 1) == 1)
                cpu_fprintf(f, "\n");
            else
                cpu_fprintf(f, " ");
        }
        if (env->hflags & HF_CS64_MASK)
            nb = 16;
        else
            nb = 8;
        for(i=0;i<nb;i++) {
            cpu_fprintf(f, "XMM%02d=%08x%08x%08x%08x",
                        i,
                        env->xmm_regs[i].ZMM_L(3),
                        env->xmm_regs[i].ZMM_L(2),
                        env->xmm_regs[i].ZMM_L(1),
                        env->xmm_regs[i].ZMM_L(0));
            if ((i & 1) == 1)
                cpu_fprintf(f, "\n");
            else
                cpu_fprintf(f, " ");
        }
    }
    if (flags & CPU_DUMP_CODE) {
        target_ulong base = env->segs[R_CS].base + env->eip;
        target_ulong offs = MIN(env->eip, DUMP_CODE_BYTES_BACKWARD);
        uint8_t code;
        char codestr[3];

        cpu_fprintf(f, "Code=");
        for (i = 0; i < DUMP_CODE_BYTES_TOTAL; i++) {
            if (cpu_memory_rw_debug(cs, base - offs + i, &code, 1, 0) == 0) {
                snprintf(codestr, sizeof(codestr), "%02x", code);
            } else {
                snprintf(codestr, sizeof(codestr), "??");
            }
            cpu_fprintf(f, "%s%s%s%s", i > 0 ? " " : "",
                        i == offs ? "<" : "", codestr, i == offs ? ">" : "");
        }
        cpu_fprintf(f, "\n");
    }
}

/***********************************************************/
/* x86 mmu */
/* XXX: add PGE support */

void x86_cpu_set_a20(X86CPU *cpu, int a20_state)
{
    CPUX86State *env = &cpu->env;

    a20_state = (a20_state != 0);
    if (a20_state != ((env->a20_mask >> 20) & 1)) {
        CPUState *cs = CPU(cpu);

#if defined(DEBUG_MMU)
        printf("A20 update: a20=%d\n", a20_state);
#endif
        /* if the cpu is currently executing code, we must unlink it and
           all the potentially executing TB */
        cpu_interrupt(cs, CPU_INTERRUPT_EXITTB);

        /* when a20 is changed, all the MMU mappings are invalid, so
           we must flush everything */
        tlb_flush(cs);
        env->a20_mask = ~(1 << 20) | (a20_state << 20);
    }
}

void cpu_x86_update_cr0(CPUX86State *env, uint32_t new_cr0)
{
    X86CPU *cpu = env_archcpu(env);
    int pe_state;

#if defined(DEBUG_MMU)
    printf("CR0 update: CR0=0x%08x\n", new_cr0);
#endif
    if ((new_cr0 & (CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK)) !=
        (env->cr[0] & (CR0_PG_MASK | CR0_WP_MASK | CR0_PE_MASK))) {
        tlb_flush(CPU(cpu));
    }

#ifdef TARGET_X86_64
    if (!(env->cr[0] & CR0_PG_MASK) && (new_cr0 & CR0_PG_MASK) &&
        (env->efer & MSR_EFER_LME)) {
        /* enter in long mode */
        /* XXX: generate an exception */
        if (!(env->cr[4] & CR4_PAE_MASK))
            return;
        env->efer |= MSR_EFER_LMA;
        env->hflags |= HF_LMA_MASK;
    } else if ((env->cr[0] & CR0_PG_MASK) && !(new_cr0 & CR0_PG_MASK) &&
               (env->efer & MSR_EFER_LMA)) {
        /* exit long mode */
        env->efer &= ~MSR_EFER_LMA;
        env->hflags &= ~(HF_LMA_MASK | HF_CS64_MASK);
        env->eip &= 0xffffffff;
    }
#endif
    env->cr[0] = new_cr0 | CR0_ET_MASK;

    /* update PE flag in hidden flags */
    pe_state = (env->cr[0] & CR0_PE_MASK);
    env->hflags = (env->hflags & ~HF_PE_MASK) | (pe_state << HF_PE_SHIFT);
    /* ensure that ADDSEG is always set in real mode */
    env->hflags |= ((pe_state ^ 1) << HF_ADDSEG_SHIFT);
    /* update FPU flags */
    env->hflags = (env->hflags & ~(HF_MP_MASK | HF_EM_MASK | HF_TS_MASK)) |
        ((new_cr0 << (HF_MP_SHIFT - 1)) & (HF_MP_MASK | HF_EM_MASK | HF_TS_MASK));
}

/* XXX: in legacy PAE mode, generate a GPF if reserved bits are set in
   the PDPT */
void cpu_x86_update_cr3(CPUX86State *env, target_ulong new_cr3)
{
    env->cr[3] = new_cr3;
    if (env->cr[0] & CR0_PG_MASK) {
#if defined(DEBUG_MMU)
        printf("CR3 update: CR3=" TARGET_FMT_lx "\n", new_cr3);
#endif
        tlb_flush(env_cpu(env));
    }
}

void cpu_x86_update_cr4(CPUX86State *env, uint32_t new_cr4)
{
    uint32_t hflags;

#if defined(DEBUG_MMU)
    printf("CR4 update: %08x -> %08x\n", (uint32_t)env->cr[4], new_cr4);
#endif
    if ((new_cr4 ^ env->cr[4]) &
        (CR4_PGE_MASK | CR4_PAE_MASK | CR4_PSE_MASK |
         CR4_SMEP_MASK | CR4_SMAP_MASK | CR4_LA57_MASK)) {
        tlb_flush(env_cpu(env));
    }

    /* Clear bits we're going to recompute.  */
    hflags = env->hflags & ~(HF_OSFXSR_MASK | HF_SMAP_MASK);

    /* SSE handling */
    if (!(env->features[FEAT_1_EDX] & CPUID_SSE)) {
        new_cr4 &= ~CR4_OSFXSR_MASK;
    }
    if (new_cr4 & CR4_OSFXSR_MASK) {
        hflags |= HF_OSFXSR_MASK;
    }

    if (!(env->features[FEAT_7_0_EBX] & CPUID_7_0_EBX_SMAP)) {
        new_cr4 &= ~CR4_SMAP_MASK;
    }
    if (new_cr4 & CR4_SMAP_MASK) {
        hflags |= HF_SMAP_MASK;
    }

    if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKU)) {
        new_cr4 &= ~CR4_PKE_MASK;
    }
    if (!(env->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_PKS)) {
        new_cr4 &= ~CR4_PKS_MASK;
    }

    env->cr[4] = new_cr4;
    env->hflags = hflags;

    cpu_sync_bndcs_hflags(env);
}

#if !defined(CONFIG_USER_ONLY)
hwaddr x86_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;
    target_ulong pde_addr, pte_addr;
    uint64_t pte;
    int32_t a20_mask;
    uint32_t page_offset;
    int page_size;

    a20_mask = x86_get_a20_mask(env);
    if (!(env->cr[0] & CR0_PG_MASK)) {
        pte = addr & a20_mask;
        page_size = 4096;
    } else if (env->cr[4] & CR4_PAE_MASK) {
        target_ulong pdpe_addr;
        uint64_t pde, pdpe;

#ifdef TARGET_X86_64
        if (env->hflags & HF_LMA_MASK) {
            bool la57 = env->cr[4] & CR4_LA57_MASK;
            uint64_t pml5e_addr, pml5e;
            uint64_t pml4e_addr, pml4e;
            int32_t sext;

            /* test virtual address sign extension */
            sext = la57 ? (int64_t)addr >> 56 : (int64_t)addr >> 47;
            if (sext != 0 && sext != -1) {
                return -1;
            }

            if (la57) {
                pml5e_addr = ((env->cr[3] & ~0xfff) +
                        (((addr >> 48) & 0x1ff) << 3)) & a20_mask;
                pml5e = x86_ldq_phys(cs, pml5e_addr);
                if (!(pml5e & PG_PRESENT_MASK)) {
                    return -1;
                }
            } else {
                pml5e = env->cr[3];
            }

            pml4e_addr = ((pml5e & PG_ADDRESS_MASK) +
                    (((addr >> 39) & 0x1ff) << 3)) & a20_mask;
            pml4e = x86_ldq_phys(cs, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                return -1;
            }
            pdpe_addr = ((pml4e & PG_ADDRESS_MASK) +
                         (((addr >> 30) & 0x1ff) << 3)) & a20_mask;
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                return -1;
            }
            if (pdpe & PG_PSE_MASK) {
                page_size = 1024 * 1024 * 1024;
                pte = pdpe;
                goto out;
            }

        } else
#endif
        {
            pdpe_addr = ((env->cr[3] & ~0x1f) + ((addr >> 27) & 0x18)) &
                a20_mask;
            pdpe = x86_ldq_phys(cs, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK))
                return -1;
        }

        pde_addr = ((pdpe & PG_ADDRESS_MASK) +
                    (((addr >> 21) & 0x1ff) << 3)) & a20_mask;
        pde = x86_ldq_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            return -1;
        }
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            pte = pde;
        } else {
            /* 4 KB page */
            pte_addr = ((pde & PG_ADDRESS_MASK) +
                        (((addr >> 12) & 0x1ff) << 3)) & a20_mask;
            page_size = 4096;
            pte = x86_ldq_phys(cs, pte_addr);
        }
        if (!(pte & PG_PRESENT_MASK)) {
            return -1;
        }
    } else {
        uint32_t pde;

        /* page directory entry */
        pde_addr = ((env->cr[3] & ~0xfff) + ((addr >> 20) & 0xffc)) & a20_mask;
        pde = x86_ldl_phys(cs, pde_addr);
        if (!(pde & PG_PRESENT_MASK))
            return -1;
        if ((pde & PG_PSE_MASK) && (env->cr[4] & CR4_PSE_MASK)) {
            pte = pde | ((pde & 0x1fe000LL) << (32 - 13));
            page_size = 4096 * 1024;
        } else {
            /* page directory entry */
            pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) & a20_mask;
            pte = x86_ldl_phys(cs, pte_addr);
            if (!(pte & PG_PRESENT_MASK)) {
                return -1;
            }
            page_size = 4096;
        }
        pte = pte & a20_mask;
    }

#ifdef TARGET_X86_64
out:
#endif
    pte &= PG_ADDRESS_MASK & ~(page_size - 1);
    page_offset = (addr & TARGET_PAGE_MASK) & (page_size - 1);
    return pte | page_offset;
}

typedef struct MCEInjectionParams {
    int bank;
    uint64_t status;
    uint64_t mcg_status;
    uint64_t addr;
    uint64_t misc;
    int flags;
} MCEInjectionParams;

void cpu_report_tpr_access(CPUX86State *env, TPRAccess access)
{
    X86CPU *cpu = env_archcpu(env);
    CPUState *cs = env_cpu(env);

    if (tcg_enabled(env->uc)) {
        cpu_restore_state(cs, cs->mem_io_pc, false);

        apic_handle_tpr_access_report(cpu->apic_state, env->eip, access);
    }
}
#endif /* !CONFIG_USER_ONLY */

int cpu_x86_get_descr_debug(CPUX86State *env, unsigned int selector,
                            target_ulong *base, unsigned int *limit,
                            unsigned int *flags)
{
    CPUState *cs = env_cpu(env);
    SegmentCache *dt;
    target_ulong ptr;
    uint32_t e1, e2;
    int index;

    if (selector & 0x4)
        dt = &env->ldt;
    else
        dt = &env->gdt;
    index = selector & ~7;
    ptr = dt->base + index;
    if ((uint32_t)(index + 7) > dt->limit
        || cpu_memory_rw_debug(cs, ptr, (uint8_t *)&e1, sizeof(e1), 0) != 0
        || cpu_memory_rw_debug(cs, ptr+4, (uint8_t *)&e2, sizeof(e2), 0) != 0)
        return 0;

    *base = ((e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000));
    *limit = (e1 & 0xffff) | (e2 & 0x000f0000);
    if (e2 & DESC_G_MASK)
        *limit = (*limit << 12) | 0xfff;
    *flags = e2;

    return 1;
}

#if !defined(CONFIG_USER_ONLY)
void do_cpu_init(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    CPUX86State *save = g_new(CPUX86State, 1);
    int sipi = cs->interrupt_request & CPU_INTERRUPT_SIPI;

    *save = *env;

    cpu_reset(cs);
    cs->interrupt_request = sipi;
    memcpy(&env->start_init_save, &save->start_init_save,
           offsetof(CPUX86State, end_init_save) -
           offsetof(CPUX86State, start_init_save));
    g_free(save);

    apic_init_reset(env->uc, cpu->apic_state);
}

void do_cpu_sipi(X86CPU *cpu)
{
    apic_sipi(cpu->apic_state);
}
#else
void do_cpu_init(X86CPU *cpu)
{
}
void do_cpu_sipi(X86CPU *cpu)
{
}
#endif

/* Frob eflags into and out of the CPU temporary format.  */

void x86_cpu_exec_enter(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

    CC_SRC = env->eflags & (CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
    env->df = 1 - (2 * ((env->eflags >> 10) & 1));
    CC_OP = CC_OP_EFLAGS;
    env->eflags &= ~(DF_MASK | CC_O | CC_S | CC_Z | CC_A | CC_P | CC_C);
}

void x86_cpu_exec_exit(CPUState *cs)
{
    X86CPU *cpu = X86_CPU(cs->uc, cs);
    CPUX86State *env = &cpu->env;

    env->eflags = cpu_compute_eflags(env);
    env->eflags0 = env->eflags;
}

#ifndef CONFIG_USER_ONLY
uint8_t x86_ldub_phys(CPUState *cs, hwaddr addr)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    return address_space_ldub(as, addr, attrs, NULL);
}

uint32_t x86_lduw_phys(CPUState *cs, hwaddr addr)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    return address_space_lduw(as, addr, attrs, NULL);
}

uint32_t x86_ldl_phys(CPUState *cs, hwaddr addr)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    return address_space_ldl(as, addr, attrs, NULL);
}

uint64_t x86_ldq_phys(CPUState *cs, hwaddr addr)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    return address_space_ldq(as, addr, attrs, NULL);
}

void x86_stb_phys(CPUState *cs, hwaddr addr, uint8_t val)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    address_space_stb(as, addr, val, attrs, NULL);
}

void x86_stl_phys_notdirty(CPUState *cs, hwaddr addr, uint32_t val)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    address_space_stl_notdirty(as, addr, val, attrs, NULL);
}

void x86_stw_phys(CPUState *cs, hwaddr addr, uint32_t val)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    address_space_stw(as, addr, val, attrs, NULL);
}

void x86_stl_phys(CPUState *cs, hwaddr addr, uint32_t val)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    address_space_stl(as, addr, val, attrs, NULL);
}

void x86_stq_phys(CPUState *cs, hwaddr addr, uint64_t val)
{
    X86CPU *cpu = X86_CPU(NULL, cs);
    CPUX86State *env = &cpu->env;
    MemTxAttrs attrs = cpu_get_mem_attrs(env);
    AddressSpace *as = cpu_addressspace(cs, attrs);

    address_space_stq(as, addr, val, attrs, NULL);
}
#endif
