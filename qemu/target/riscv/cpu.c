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

const char * const riscv_int_regnames[] = {
  "zero", "ra", "sp",  "gp",  "tp", "t0", "t1", "t2",
  "s0",   "s1", "a0",  "a1",  "a2", "a3", "a4", "a5",
  "a6",   "a7", "s2",  "s3",  "s4", "s5", "s6", "s7",
  "s8",   "s9", "s10", "s11", "t3", "t4", "t5", "t6"
};

const char * const riscv_fpr_regnames[] = {
  "ft0", "ft1", "ft2",  "ft3",  "ft4", "ft5", "ft6",  "ft7",
  "fs0", "fs1", "fa0",  "fa1",  "fa2", "fa3", "fa4",  "fa5",
  "fa6", "fa7", "fs2",  "fs3",  "fs4", "fs5", "fs6",  "fs7",
  "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"
};

const char * const riscv_excp_names[] = {
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
    "guest_store_page_fault"
};

const char * const riscv_intr_names[] = {
    "u_software",
    "s_software",
    "vs_software",
    "m_software",
    "u_timer",
    "s_timer",
    "vs_timer",
    "m_timer",
    "u_external",
    "vs_external",
    "h_external",
    "m_external",
    "reserved",
    "reserved",
    "reserved",
    "reserved"
};

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

static void set_vext_version(CPURISCVState *env, int vext_ver)
{
    env->vext_ver = vext_ver;
}

static void set_feature(CPURISCVState *env, int feature)
{
    env->features |= (1ULL << feature);
}

static void set_resetvec(CPURISCVState *env, int resetvec)
{
#ifndef CONFIG_USER_ONLY
    env->resetvec = resetvec;
#endif
}

static void riscv_any_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RVXLEN | RVI | RVM | RVA | RVF | RVD | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_11_0);
    set_vext_version(env, VEXT_VERSION_0_07_1);
    set_resetvec(env, DEFAULT_RSTVEC);
}

#if defined(TARGET_RISCV32)

static void riscv_base32_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
}

static void rv32gcsu_priv1_10_0_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv32imcu_nommu_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, 0x8090);
}

static void rv32imacu_nommu_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv32imafcu_nommu_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV32 | RVI | RVM | RVA | RVF | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
}

#elif defined(TARGET_RISCV64)

static void riscv_base64_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
}

static void rv64gcsu_priv1_10_0_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVF | RVD | RVC | RVS | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_MMU);
    set_feature(env, RISCV_FEATURE_PMP);
}

static void rv64imacu_nommu_cpu_init(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPURISCVState *env = &RISCV_CPU(uc, obj)->env;
    set_misa(env, RV64 | RVI | RVM | RVA | RVC | RVU);
    set_priv_version(env, PRIV_VERSION_1_10_0);
    set_resetvec(env, DEFAULT_RSTVEC);
    set_feature(env, RISCV_FEATURE_PMP);
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
static void riscv_cpu_dump_state(CPUState *cs, FILE *f,
    fprintf_function cpu_fprintf, int flags)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    int i;

    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "pc      ", env->pc);
#ifndef CONFIG_USER_ONLY
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mhartid ", env->mhartid);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mstatus ", env->mstatus);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mip     ",
        (target_ulong)qatomic_read(&env->mip));
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mie     ", env->mie);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mideleg ", env->mideleg);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "medeleg ", env->medeleg);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mtvec   ", env->mtvec);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mepc    ", env->mepc);
    cpu_fprintf(f, " %s " TARGET_FMT_lx "\n", "mcause  ", env->mcause);
#endif

    for (i = 0; i < 32; i++) {
        cpu_fprintf(f, " %s " TARGET_FMT_lx,
            riscv_int_regnames[i], env->gpr[i]);
        if ((i & 3) == 3) {
            cpu_fprintf(f, "\n");
        }
    }
    if (flags & CPU_DUMP_FPU) {
        for (i = 0; i < 32; i++) {
            cpu_fprintf(f, " %s %016" PRIx64,
                riscv_fpr_regnames[i], env->fpr[i]);
            if ((i & 3) == 3) {
                cpu_fprintf(f, "\n");
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

static void riscv_cpu_synchronize_from_tb(CPUState *cs, const TranslationBlock *tb)
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
    cs->exception_index = EXCP_NONE;
    env->load_res = -1;
    set_default_nan_mode(1, &env->fp_status);

    // Unicorn: Allow vector operations.
    cpu->cfg.ext_v = true;
    cpu->cfg.elen = 64;
    cpu->cfg.vlen = 128;
}

// Unicorn: if'd out
#if 0
static void riscv_cpu_disas_set_info(CPUState *s, disassemble_info *info)
{
#if defined(TARGET_RISCV32)
    info->print_insn = print_insn_riscv32;
#elif defined(TARGET_RISCV64)
    info->print_insn = print_insn_riscv64;
#endif
}
#endif

static int riscv_cpu_realize(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    RISCVCPUClass *mcc = RISCV_CPU_GET_CLASS(uc, dev);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(uc, dev, errp);
    return 0;
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
    DEFINE_CPU(TYPE_RISCV_CPU_BASE32,           riscv_base32_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_IBEX,             rv32imcu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E31,       rv32imacu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E34,       rv32imafcu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U34,       rv32gcsu_priv1_10_0_cpu_init),
#elif defined(TARGET_RISCV64)
    DEFINE_CPU(TYPE_RISCV_CPU_BASE64,           riscv_base64_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_E51,       rv64imacu_nommu_cpu_init),
    DEFINE_CPU(TYPE_RISCV_CPU_SIFIVE_U54,       rv64gcsu_priv1_10_0_cpu_init),
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
