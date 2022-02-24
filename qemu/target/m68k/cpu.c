/*
 * QEMU Motorola 68k CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/m68k/m68k.h"
#include "cpu.h"
#include "qemu-common.h"
#include "exec/exec-all.h"
#include "fpu/softfloat.h"

static void m68k_cpu_set_pc(CPUState *cs, vaddr value)
{
    M68kCPU *cpu = M68K_CPU(cs->uc, cs);

    cpu->env.pc = value;
}

static bool m68k_cpu_has_work(CPUState *cs)
{
    return cs->interrupt_request & CPU_INTERRUPT_HARD;
}

static void m68k_set_feature(CPUM68KState *env, int feature)
{
    env->features |= (1u << feature);
}

static void m68k_unset_feature(CPUM68KState *env, int feature)
{
    env->features &= (-1u - (1u << feature));
}

/* CPUClass::reset() */
static void m68k_cpu_reset(CPUState *s)
{
    M68kCPU *cpu = M68K_CPU(s->uc, s);
    M68kCPUClass *mcc = M68K_CPU_GET_CLASS(s->uc, cpu);
    CPUM68KState *env = &cpu->env;
    floatx80 nan = floatx80_default_nan(NULL);
    int i;

    mcc->parent_reset(s);

    memset(env, 0, offsetof(CPUM68KState, end_reset_fields));
#ifdef CONFIG_SOFTMMU
    cpu_m68k_set_sr(env, SR_S | SR_I);
#else
    cpu_m68k_set_sr(env, 0);
#endif
    for (i = 0; i < 8; i++) {
        env->fregs[i].d = nan;
    }
    cpu_m68k_set_fpcr(env, 0);
    env->fpsr = 0;

    /* TODO: We should set PC from the interrupt vector.  */
    env->pc = 0;
}

/* CPU models */

static ObjectClass *m68k_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    if (cpu_model == NULL) {
        return NULL;
    }

    typename = g_strdup_printf(M68K_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(uc, typename);
    g_free(typename);
    if (oc != NULL && (object_class_dynamic_cast(uc, oc, TYPE_M68K_CPU) == NULL ||
                       object_class_is_abstract(oc))) {
        return NULL;
    }
    return oc;
}

static void m5206_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
}

/* Base feature set, including isns. for m68k family */
static void m68000_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_MOVEP);
}

/*
 * Adds BKPT, MOVE-from-SR *now priv instr, and MOVEC, MOVES, RTD
 */
static void m68010_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68000_cpu_initfn(uc, obj, opaque);
    m68k_set_feature(env, M68K_FEATURE_M68010);
    m68k_set_feature(env, M68K_FEATURE_RTD);
    m68k_set_feature(env, M68K_FEATURE_BKPT);
    m68k_set_feature(env, M68K_FEATURE_MOVEC);
}

/* common features for 68020, 68030 and 68040 */
static void m680x0_cpu_common(CPUM68KState *env)
{
    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_QUAD_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_BCCL);
    m68k_set_feature(env, M68K_FEATURE_BITFIELD);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_SCALED_INDEX);
    m68k_set_feature(env, M68K_FEATURE_LONG_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_FPU);
    m68k_set_feature(env, M68K_FEATURE_CAS);
    m68k_set_feature(env, M68K_FEATURE_BKPT);
    m68k_set_feature(env, M68K_FEATURE_RTD);
    m68k_set_feature(env, M68K_FEATURE_CHK2);
    m68k_set_feature(env, M68K_FEATURE_MOVEP);
}

/*
 * Adds BFCHG, BFCLR, BFEXTS, BFEXTU, BFFFO, BFINS, BFSET, BFTST, CAS, CAS2,
 *      CHK2, CMP2, DIVSL, DIVUL, EXTB, PACK, TRAPcc, UNPK.
 *
 * 68020/30 only:
 *      CALLM, cpBcc, cpDBcc, cpGEN, cpRESTORE, cpSAVE, cpScc, cpTRAPcc
 */
static void m68020_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68010_cpu_initfn(uc, obj, opaque);
    m68k_unset_feature(env, M68K_FEATURE_M68010);
    m68k_set_feature(env, M68K_FEATURE_M68020);
    m68k_set_feature(env, M68K_FEATURE_QUAD_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_BCCL);
    m68k_set_feature(env, M68K_FEATURE_BITFIELD);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_SCALED_INDEX);
    m68k_set_feature(env, M68K_FEATURE_LONG_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_FPU);
    m68k_set_feature(env, M68K_FEATURE_CAS);
    m68k_set_feature(env, M68K_FEATURE_CHK2);
    m68k_set_feature(env, M68K_FEATURE_MSP);
    m68k_set_feature(env, M68K_FEATURE_UNALIGNED_DATA);
}

/*
 * Adds: PFLUSH (*5)
 * 68030 Only: PFLUSHA (*5), PLOAD (*5), PMOVE
 * 68030/40 Only: PTEST
 *
 * NOTES:
 *  5. Not valid on MC68EC030
 */
static void m68030_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m680x0_cpu_common(env);
    m68k_set_feature(env, M68K_FEATURE_M68030);
}

/*
 * Adds: CINV, CPUSH
 * Adds all with Note *2: FABS, FSABS, FDABS, FADD, FSADD, FDADD, FBcc, FCMP,
 *                        FDBcc, FDIV, FSDIV, FDDIV, FMOVE, FSMOVE, FDMOVE,
 *                        FMOVEM, FMUL, FSMUL, FDMUL, FNEG, FSNEG, FDNEG, FNOP,
 *                        FRESTORE, FSAVE, FScc, FSQRT, FSSQRT, FDSQRT, FSUB,
 *                        FSSUB, FDSUB, FTRAPcc, FTST
 *
 * Adds with Notes *2, and *3: FACOS, FASIN, FATAN, FATANH, FCOS, FCOSH, FETOX,
 *                             FETOXM, FGETEXP, FGETMAN, FINT, FINTRZ, FLOG10,
 *                             FLOG2, FLOGN, FLOGNP1, FMOD, FMOVECR, FREM,
 *                             FSCALE, FSGLDIV, FSGLMUL, FSIN, FSINCOS, FSINH,
 *                             FTAN, FTANH, FTENTOX, FTWOTOX
 * NOTES:
 * 2. Not applicable to the MC68EC040, MC68LC040, MC68EC060, and MC68LC060.
 * 3. These are software-supported instructions on the MC68040 and MC68060.
 */
static void m68040_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m680x0_cpu_common(env);
    m68k_set_feature(env, M68K_FEATURE_M68040);
}

/*
 * Adds: PLPA
 * Adds all with Note *2: CAS, CAS2, MULS, MULU, CHK2, CMP2, DIVS, DIVU
 * All Fxxxx instructions are as per m68040 with exception to; FMOVEM NOTE3
 *
 * Does NOT implement MOVEP
 *
 * NOTES:
 * 2. Not applicable to the MC68EC040, MC68LC040, MC68EC060, and MC68LC060.
 * 3. These are software-supported instructions on the MC68040 and MC68060.
 */
static void m68060_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_M68000);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_BCCL);
    m68k_set_feature(env, M68K_FEATURE_BITFIELD);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_SCALED_INDEX);
    m68k_set_feature(env, M68K_FEATURE_LONG_MULDIV);
    m68k_set_feature(env, M68K_FEATURE_FPU);
    m68k_set_feature(env, M68K_FEATURE_CAS);
    m68k_set_feature(env, M68K_FEATURE_BKPT);
    m68k_set_feature(env, M68K_FEATURE_RTD);
    m68k_set_feature(env, M68K_FEATURE_CHK2);
    m68k_set_feature(env, M68K_FEATURE_M68060);
}

static void m5208_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void cfv4e_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_B);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_FPU);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_USP);
}

static void any_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    M68kCPU *cpu = M68K_CPU(uc, obj);
    CPUM68KState *env = &cpu->env;

    m68k_set_feature(env, M68K_FEATURE_CF_ISA_A);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_B);
    m68k_set_feature(env, M68K_FEATURE_CF_ISA_APLUSC);
    m68k_set_feature(env, M68K_FEATURE_BRAL);
    m68k_set_feature(env, M68K_FEATURE_CF_FPU);
    /*
     * MAC and EMAC are mututally exclusive, so pick EMAC.
     * It's mostly backwards compatible.
     */
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC);
    m68k_set_feature(env, M68K_FEATURE_CF_EMAC_B);
    m68k_set_feature(env, M68K_FEATURE_USP);
    m68k_set_feature(env, M68K_FEATURE_EXT_FULL);
    m68k_set_feature(env, M68K_FEATURE_WORD_INDEX);
}

static int m68k_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    M68kCPU *cpu = M68K_CPU(uc, dev);
    M68kCPUClass *mcc = M68K_CPU_GET_CLASS(uc, dev);

    register_m68k_insns(&cpu->env);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(cs->uc, dev, errp);

    return 0;
}

static void m68k_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    M68kCPU *cpu = M68K_CPU(uc, obj);

    cpu_set_cpustate_pointers(cpu);
    cpu_exec_init(cs, &error_abort, opaque);
}

static void m68k_cpu_class_init(struct uc_struct *uc, ObjectClass *c, void *data)
{
    M68kCPUClass *mcc = M68K_CPU_CLASS(uc, c);
    CPUClass *cc = CPU_CLASS(uc, c);
    DeviceClass *dc = DEVICE_CLASS(uc, c);

    mcc->parent_realize = dc->realize;
    dc->realize = m68k_cpu_realizefn;

    mcc->parent_reset = cc->reset;
    cc->reset = m68k_cpu_reset;

    cc->class_by_name = m68k_cpu_class_by_name;
    cc->has_work = m68k_cpu_has_work;
    cc->tcg_ops.do_interrupt = m68k_cpu_do_interrupt;
    cc->tcg_ops.cpu_exec_interrupt = m68k_cpu_exec_interrupt;
    cc->set_pc = m68k_cpu_set_pc;
    cc->tcg_ops.tlb_fill = m68k_cpu_tlb_fill;
#if defined(CONFIG_SOFTMMU)
    cc->tcg_ops.do_transaction_failed = m68k_cpu_transaction_failed;
    cc->get_phys_page_debug = m68k_cpu_get_phys_page_debug;
#endif
    cc->tcg_ops.initialize = m68k_tcg_init;
}

#define DEFINE_M68K_CPU_TYPE(cpu_model, initfn) \
    {                                           \
        .name = M68K_CPU_TYPE_NAME(cpu_model),  \
        .parent = TYPE_M68K_CPU,                \
                                                \
        .instance_init = initfn,                \
    }

static TypeInfo m68k_cpus_type_infos[] = {
    { /* base class should be registered first */
        .name = TYPE_M68K_CPU,
        .parent = TYPE_CPU,

        .class_size = sizeof(M68kCPUClass),
        .instance_size = sizeof(M68kCPU),

        .instance_init = m68k_cpu_initfn,
        .class_init = m68k_cpu_class_init,

        .abstract = true,
    },
    DEFINE_M68K_CPU_TYPE("m68000", m68000_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68010", m68010_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68020", m68020_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68030", m68030_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68040", m68040_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m68060", m68060_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m5206", m5206_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("m5208", m5208_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("cfv4e", cfv4e_cpu_initfn),
    DEFINE_M68K_CPU_TYPE("any", any_cpu_initfn),
};

void m68k_cpu_register_types(void *opaque)
{
    m68k_cpus_type_infos[0].instance_userdata = opaque;

    type_register_static_array(opaque, m68k_cpus_type_infos, ARRAY_SIZE(m68k_cpus_type_infos));
}
