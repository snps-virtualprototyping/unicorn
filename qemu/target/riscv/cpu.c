/*
 * QEMU RISC-V CPU
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2 or later, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "qapi/error.h"
#include "fpu/softfloat-helpers.h"

#include "uc_priv.h"

/* RISC-V CPU definitions */

static const char riscv_exts[26] = "IEMAFDQCLBJTPVNSUHKORWXYZG";

const char * const riscv_int_regnames[] = {
  "x0/zero", "x1/ra",  "x2/sp",  "x3/gp",  "x4/tp",  "x5/t0",   "x6/t1",
  "x7/t2",   "x8/s0",  "x9/s1",  "x10/a0", "x11/a1", "x12/a2",  "x13/a3",
  "x14/a4",  "x15/a5", "x16/a6", "x17/a7", "x18/s2", "x19/s3",  "x20/s4",
  "x21/s5",  "x22/s6", "x23/s7", "x24/s8", "x25/s9", "x26/s10", "x27/s11",
  "x28/t3",  "x29/t4", "x30/t5", "x31/t6"
};

const char * const riscv_fpr_regnames[] = {
  "f0/ft0",   "f1/ft1",  "f2/ft2",   "f3/ft3",   "f4/ft4",  "f5/ft5",
  "f6/ft6",   "f7/ft7",  "f8/fs0",   "f9/fs1",   "f10/fa0", "f11/fa1",
  "f12/fa2",  "f13/fa3", "f14/fa4",  "f15/fa5",  "f16/fa6", "f17/fa7",
  "f18/fs2",  "f19/fs3", "f20/fs4",  "f21/fs5",  "f22/fs6", "f23/fs7",
  "f24/fs8",  "f25/fs9", "f26/fs10", "f27/fs11", "f28/ft8", "f29/ft9",
  "f30/ft10", "f31/ft11"
};

static const char * const riscv_excp_names[] = {
    "misaligned_fetch",
    "fault_fetch",
    "illegal_instruction",
    "breakpoint",
    "misaligned_load",
    "fault_load",
    "misaligned_store",
    "fault_store",
    "user_ecall",
    "supervisor_ecall",
    "hypervisor_ecall",
    "machine_ecall",
    "exec_page_fault",
    "load_page_fault",
    "reserved",
    "store_page_fault",
    "reserved",
    "reserved",
    "reserved",
    "reserved",
    "guest_exec_page_fault",
    "guest_load_page_fault",
    "reserved",
    "guest_store_page_fault",
};

static const char * const riscv_intr_names[] = {
    "u_software",
    "s_software",
    "vs_software",
    "m_software",
    "u_timer",
    "s_timer",
    "vs_timer",
    "m_timer",
    "u_external",
    "s_external",
    "vs_external",
    "m_external",
    "reserved",
    "reserved",
    "reserved",
    "reserved"
};

const char *riscv_cpu_get_trap_name(target_ulong cause, bool async)
{
    if (async) {
        return (cause < ARRAY_SIZE(riscv_intr_names)) ?
               riscv_intr_names[cause] : "(unknown)";
    } else {
        return (cause < ARRAY_SIZE(riscv_excp_names)) ?
               riscv_excp_names[cause] : "(unknown)";
    }
}

bool riscv_cpu_is_32bit(CPURISCVState *env)
{
    if (env->misa & RV64) {
        return false;
    }

    return true;
}

static void set_misa(CPURISCVState *env, target_ulong misa)
{
    env->misa_mask = env->misa = misa;
}

static void set_priv_version(CPURISCVState *env, int priv_ver)
{
    env->priv_ver = priv_ver;
}

static void set_bext_version(CPURISCVState *env, int bext_ver)
{
    env->bext_ver = bext_ver;
}

static void set_vext_version(CPURISCVState *env, int vext_ver)
{
    env->vext_ver = vext_ver;
}

static void set_feature(CPURISCVState *env, int feature)
{
    env->features |= (1ULL << feature);
}

static void set_resetvec(CPURISCVState *env, target_ulong resetvec)
{
#ifndef CONFIG_USER_ONLY
    env->resetvec = resetvec;
#endif
}

static void riscv_any_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
#if defined(TARGET_RISCV32)
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVU);
#elif defined(TARGET_RISCV64)
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVU);
#endif
    set_priv_version(env, PRIV_VERSION_1_11_0);
    set_vext_version(env, VEXT_VERSION_0_07_1);
    set_resetvec(env, DEFAULT_RSTVEC);
}

#if defined(TARGET_RISCV64)
static void rv64_base_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    RISCVCPU *cpu = RISCV_CPU(uc, obj);
    CPURISCVState *env = &cpu->env;
    cpu->cfg.ext_i = true;
    cpu->cfg.ext_m = true;
    cpu->cfg.ext_a = true;
    cpu->cfg.ext_f = true;
    cpu->cfg.ext_d = true;
    cpu->cfg.ext_c = true;
    cpu->cfg.ext_u = true;
    set_misa(env, RV64);
}

static void rv64_sifive_u_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
}

static void rv64_sifive_e_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    RISCVCPU *cpu = RISCV_CPU(uc, obj);
    CPURISCVState *env = &cpu->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    cpu->cfg.mmu = false;
}
#else
static void rv32_base_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    RISCVCPU *cpu = RISCV_CPU(uc, obj);
    CPURISCVState *env = &cpu->env;
    cpu->cfg.ext_i = true;
    cpu->cfg.ext_m = true;
    cpu->cfg.ext_a = true;
    cpu->cfg.ext_f = true;
    cpu->cfg.ext_d = true;
    cpu->cfg.ext_c = true;
    cpu->cfg.ext_u = true;
    set_misa(env, RV32);
}

static void rv32_sifive_u_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
}

static void rv32_sifive_e_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    RISCVCPU *cpu = RISCV_CPU(uc, obj);
    CPURISCVState *env = &cpu->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    cpu->cfg.mmu = false;

    // JHW added
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
    //set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
}

static void rv32_ibex_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    RISCVCPU *cpu = RISCV_CPU(uc, obj);
    CPURISCVState *env = &cpu->env;
    set_misa(env, RV32 | RVI | RVM | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    cpu->cfg.mmu = false;
}

static void rv32_imafcu_nommu_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    RISCVCPU *cpu = RISCV_CPU(uc, obj);
    CPURISCVState *env = &cpu->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    cpu->cfg.mmu = false;
}
#endif

static ObjectClass *riscv_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;
    char **cpuname;

    cpuname = g_strsplit(cpu_model, ",", 1);
    typename = g_strdup_printf(RISCV_CPU_TYPE_NAME("%s"), cpuname[0]);
    oc = object_class_by_name(uc, typename);
    g_strfreev(cpuname);
    g_free(typename);
    if (!oc || !object_class_dynamic_cast(uc, oc, TYPE_RISCV_CPU) ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

// Unicorn: if'd out
#if 0
static void riscv_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    int i;

#if !defined(CONFIG_USER_ONLY)
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s %d\n", "V      =  ", riscv_cpu_virt_enabled(env));
    }
#endif
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "pc      ", env->pc);
#ifndef CONFIG_USER_ONLY
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mhartid ", env->mhartid);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mstatus ", (target_ulong)env->mstatus);
    if (riscv_cpu_is_32bit(env)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mstatush ",
                     (target_ulong)(env->mstatus >> 32));
    }
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "hstatus ", env->hstatus);
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vsstatus ",
                     (target_ulong)env->vsstatus);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mip     ", env->mip);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mie     ", env->mie);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mideleg ", env->mideleg);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "hideleg ", env->hideleg);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "medeleg ", env->medeleg);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "hedeleg ", env->hedeleg);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtvec   ", env->mtvec);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "stvec   ", env->stvec);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vstvec  ", env->vstvec);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mepc    ", env->mepc);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "sepc    ", env->sepc);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vsepc   ", env->vsepc);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mcause  ", env->mcause);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "scause  ", env->scause);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "vscause ", env->vscause);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtval ", env->mtval);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "stval   ", env->stval);
    if (riscv_has_ext(env, RVH)) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "htval ", env->htval);
        qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtval2 ", env->mtval2);
    }
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mscratch", env->mscratch);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "sscratch", env->sscratch);
    qemu_fprintf(f, " %s " TARGET_FMT_lx "\n", "satp    ", env->satp);
#endif

    for (i = 0; i < 32; i++) {
        qemu_fprintf(f, " %s " TARGET_FMT_lx,
            riscv_int_regnames[i], env->gpr[i]);
        if ((i & 3) == 3) {
            qemu_fprintf(f, "\n");
        }
    }
    if (flags & CPU_DUMP_FPU) {
        for (i = 0; i < 32; i++) {
            qemu_fprintf(f, " %s %016" PRIx64,
                riscv_fpr_regnames[i], env->fpr[i]);
            if ((i & 3) == 3) {
                qemu_fprintf(f, "\n");
            }
        }
    }
}
#endif

static void riscv_cpu_set_pc(CPUState *cs, vaddr value)
{
    RISCVCPU *cpu = RISCV_CPU(cs->uc, cs);
    CPURISCVState *env = &cpu->env;
    env->pc = value;
}

static void riscv_cpu_set_irq(CPUState *cs, int irq, int level)
{
    RISCVCPU *cpu = RISCV_CPU(cs->uc, cs);
    riscv_cpu_update_mip(cpu, 1u << irq, BOOL_TO_MASK(level));
}

static void riscv_cpu_synchronize_from_tb(CPUState *cs,
                                          const TranslationBlock *tb)
{
    RISCVCPU *cpu = RISCV_CPU(cs->uc, cs);
    CPURISCVState *env = &cpu->env;
    env->pc = tb->pc;
}

static bool riscv_cpu_has_work(CPUState *cs)
{
#ifndef CONFIG_USER_ONLY
    RISCVCPU *cpu = RISCV_CPU(cs->uc, cs);
    CPURISCVState *env = &cpu->env;
    /*
     * Definition of the WFI instruction requires it to ignore the privilege
     * mode and delegation registers, but respect individual enables
     */
    return (qatomic_read(&env->mip) & env->mie) != 0;
#else
    return true;
#endif
}

void restore_state_to_opc(CPURISCVState *env, TranslationBlock *tb,
                          target_ulong *data)
{
    env->pc = data[0];
}

static void riscv_cpu_reset(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs->uc, cs);
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(cs->uc, cpu);
    CPURISCVState *env = &cpu->env;

    mcc->parent_reset(cs);
#ifndef CONFIG_USER_ONLY
    env->priv = PRV_M;
    env->mstatus &= ~(MSTATUS_MIE | MSTATUS_MPRV);
    env->mcause = 0;
    env->pc = env->resetvec;
    env->two_stage_lookup = false;
#endif
    cs->exception_index = RISCV_EXCP_NONE;
    env->load_res = -1;
    set_default_nan_mode(1, &env->fp_status);

    // Unicorn: Allow vector operations.
    cpu->cfg.ext_v = true;
    cpu->cfg.elen = 64;
    cpu->cfg.vlen = 128;

    // JHW: allow CSRs and instruction fences
    cpu->cfg.ext_icsr = true;
    cpu->cfg.ext_ifencei = true;
}

// Unicorn: if'd out
#if 0
static void riscv_cpu_disas_set_info(CPUState *s, disassemble_info *info)
{
    RISCVCPU *cpu = RISCV_CPU(s);
    if (riscv_cpu_is_32bit(&cpu->env)) {
    info->print_insn = print_insn_riscv32;
    } else {
    info->print_insn = print_insn_riscv64;
}
#endif

static int riscv_cpu_realize(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    RISCVCPU *cpu = RISCV_CPU(uc, dev);
    CPURISCVState *env = &cpu->env;
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(uc, dev);
    int priv_version = PRIV_VERSION_1_11_0;
    int bext_version = BEXT_VERSION_0_93_0;
    int vext_version = VEXT_VERSION_0_07_1;
    target_ulong target_misa = env->misa;
    Error *local_err = NULL;

    if (cpu->cfg.priv_spec) {
        if (!strcmp(cpu->cfg.priv_spec, "v1.11.0")) {
            priv_version = PRIV_VERSION_1_11_0;
        } else if (!strcmp(cpu->cfg.priv_spec, "v1.10.0")) {
            priv_version = PRIV_VERSION_1_10_0;
        } else {
            error_setg(errp,
                       "Unsupported privilege spec version '%s'",
                       cpu->cfg.priv_spec);
            return -1;
        }
    }

    set_priv_version(env, priv_version);
    set_bext_version(env, bext_version);
    set_vext_version(env, vext_version);

    if (cpu->cfg.mmu) {
        set_feature(env, RISCV_FEATURE_MMU);
    }

    if (cpu->cfg.pmp) {
        set_feature(env, RISCV_FEATURE_PMP);

        /*
         * Enhanced PMP should only be available
         * on harts with PMP support
         */
        if (cpu->cfg.epmp) {
            set_feature(env, RISCV_FEATURE_EPMP);
        }
    }

    set_resetvec(env, cpu->cfg.resetvec);

    /* If only XLEN is set for misa, then set misa from properties */
    if (env->misa == RV32 || env->misa == RV64) {
        /* Do some ISA extension error checking */
        if (cpu->cfg.ext_i && cpu->cfg.ext_e) {
            error_setg(errp,
                       "I and E extensions are incompatible");
                       return -1;
       }

        if (!cpu->cfg.ext_i && !cpu->cfg.ext_e) {
            error_setg(errp,
                       "Either I or E extension must be set");
                       return -1;
       }

       if (cpu->cfg.ext_g && !(cpu->cfg.ext_i & cpu->cfg.ext_m &
                               cpu->cfg.ext_a & cpu->cfg.ext_f &
                               cpu->cfg.ext_d)) {
            fprintf(stderr, "Setting G will also set IMAFD\n");
            cpu->cfg.ext_i = true;
            cpu->cfg.ext_m = true;
            cpu->cfg.ext_a = true;
            cpu->cfg.ext_f = true;
            cpu->cfg.ext_d = true;
        }

        /* Set the ISA extensions, checks should have happened above */
        if (cpu->cfg.ext_i) {
            target_misa |= RVI;
        }
        if (cpu->cfg.ext_e) {
            target_misa |= RVE;
        }
        if (cpu->cfg.ext_m) {
            target_misa |= RVM;
        }
        if (cpu->cfg.ext_a) {
            target_misa |= RVA;
        }
        if (cpu->cfg.ext_f) {
            target_misa |= RVF;
        }
        if (cpu->cfg.ext_d) {
            target_misa |= RVD;
        }
        if (cpu->cfg.ext_c) {
            target_misa |= RVC;
        }
        if (cpu->cfg.ext_s) {
            target_misa |= RVS;
        }
        if (cpu->cfg.ext_u) {
            target_misa |= RVU;
        }
        if (cpu->cfg.ext_h) {
            target_misa |= RVH;
        }
        if (cpu->cfg.ext_b) {
            target_misa |= RVB;

            if (cpu->cfg.bext_spec) {
                if (!strcmp(cpu->cfg.bext_spec, "v0.93")) {
                    bext_version = BEXT_VERSION_0_93_0;
                } else {
                    error_setg(errp,
                           "Unsupported bitmanip spec version '%s'",
                           cpu->cfg.bext_spec);
                    return -1;
                }
            } else {
                qemu_log("bitmanip version is not specified, "
                         "use the default value v0.93\n");
            }
            set_bext_version(env, bext_version);
        }
        if (cpu->cfg.ext_v) {
            target_misa |= RVV;
            if (!is_power_of_2(cpu->cfg.vlen)) {
                error_setg(errp,
                        "Vector extension VLEN must be power of 2");
                return -1;
            }
            if (cpu->cfg.vlen > RV_VLEN_MAX || cpu->cfg.vlen < 128) {
                error_setg(errp,
                        "Vector extension implementation only supports VLEN "
                        "in the range [128, %d]", RV_VLEN_MAX);
                return -1;
            }
            if (!is_power_of_2(cpu->cfg.elen)) {
                error_setg(errp,
                        "Vector extension ELEN must be power of 2");
                return -1;
            }
            if (cpu->cfg.elen > 64 || cpu->cfg.vlen < 8) {
                error_setg(errp,
                        "Vector extension implementation only supports ELEN "
                        "in the range [8, 64]");
                return -1;
            }
            if (cpu->cfg.vext_spec) {
                if (!strcmp(cpu->cfg.vext_spec, "v0.7.1")) {
                    vext_version = VEXT_VERSION_0_07_1;
                } else {
                    error_setg(errp,
                           "Unsupported vector spec version '%s'",
                           cpu->cfg.vext_spec);
                    return -1;
                }
            } else {
                qemu_log("vector version is not specified, "
                        "use the default value v0.7.1\n");
            }
            set_vext_version(env, vext_version);
        }

        set_misa(env, target_misa);
    }

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    return mcc->parent_realize(uc, dev, errp);
}

static void riscv_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    RISCVCPU *cpu = RISCV_CPU(uc, obj);

    cpu_set_cpustate_pointers(cpu);
    cpu_exec_init(cs, &error_abort, opaque);
}

static void riscv_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    RISCVCPUClass *mcc = RISCV_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, oc);
    DeviceClass *dc = DEVICE_CLASS(uc, oc);

    mcc->parent_realize = dc->realize;
    dc->realize = riscv_cpu_realize;

    mcc->parent_reset = cc->reset;
    cc->reset = riscv_cpu_reset;

    cc->class_by_name = riscv_cpu_class_by_name;
    cc->has_work = riscv_cpu_has_work;
    cc->tcg_ops.do_interrupt = riscv_cpu_do_interrupt;
    cc->tcg_ops.cpu_exec_interrupt = riscv_cpu_exec_interrupt;
    //cc->dump_state = riscv_cpu_dump_state;
    cc->set_pc = riscv_cpu_set_pc;
    cc->tcg_ops.synchronize_from_tb = riscv_cpu_synchronize_from_tb;
    //cc->gdb_read_register = riscv_cpu_gdb_read_register;
    //cc->gdb_write_register = riscv_cpu_gdb_write_register;
    //cc->gdb_num_core_regs = 65;
    //cc->gdb_stop_before_watchpoint = true;
    //cc->disas_set_info = riscv_cpu_disas_set_info;
#ifndef CONFIG_USER_ONLY
    cc->do_unassigned_access = riscv_cpu_unassigned_access;
    cc->tcg_ops.do_unaligned_access = riscv_cpu_do_unaligned_access;
    cc->get_phys_page_debug = riscv_cpu_get_phys_page_debug;
#endif
    cc->tcg_ops.initialize = riscv_translate_init;
    cc->tcg_ops.tlb_fill = riscv_cpu_tlb_fill;
    /* For now, mark unmigratable: */
    //cc->vmsd = &vmstate_riscv_cpu;

    // JHW: added set_irq callback
    cc->set_irq = riscv_cpu_set_irq;
}

#define DEFINE_CPU(type_name, initfn)      \
    {                                      \
        .name = type_name,                 \
        .parent = TYPE_RISCV_CPU,          \
        .instance_init = initfn            \
    }

static const TypeInfo riscv_cpu_type_infos[] = {
    DEFINE_CPU(TYPE_RISCV_CPU_ANY,              riscv_any_cpu_init),
#if defined(TARGET_RISCV32)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE32,           rv32_base_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_IBEX,             rv32_ibex_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E31,       rv32_sifive_e_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E34,       rv32_imafcu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U34,       rv32_sifive_u_cpu_init),
#elif defined(TARGET_RISCV64)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE64,           rv64_base_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E51,       rv64_sifive_e_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U54,       rv64_sifive_u_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SHAKTI_C,         rv64_sifive_u_cpu_init),
#endif
    { .name = NULL }
};

void riscv_cpu_register_types(void *opaque) {
    const TypeInfo* cpu_infos = riscv_cpu_type_infos;

    TypeInfo parent_type_info = {
        .name = TYPE_RISCV_CPU,
        .parent = TYPE_CPU,
        .instance_userdata = opaque,
        .instance_size = sizeof(RISCVCPU),
        .instance_align = __alignof__(RISCVCPU),
        .instance_init = riscv_cpu_init,
        .abstract = true,
        .class_size = sizeof(RISCVCPUClass),
        .class_init = riscv_cpu_class_init,
    };
    type_register(opaque, &parent_type_info);

    while (cpu_infos->name) {
        type_register(opaque, cpu_infos);
        ++cpu_infos;
    }
}
