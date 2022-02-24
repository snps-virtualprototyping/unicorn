/*
 * QEMU MIPS CPU
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
#include "cpu.h"
#include "internal.h"
#include "qemu-common.h"
#include "exec/exec-all.h"
#include "hw/mips/mips.h"


static void mips_cpu_set_pc(CPUState *cs, vaddr value)
{
    MIPSCPU *cpu = MIPS_CPU(cs->uc, cs);
    CPUMIPSState *env = &cpu->env;

    env->active_tc.PC = value & ~(target_ulong)1;
    if (value & 1) {
        env->hflags |= MIPS_HFLAG_M16;
    } else {
        env->hflags &= ~(MIPS_HFLAG_M16);
    }
}

#ifdef CONFIG_TCG
static void mips_cpu_synchronize_from_tb(CPUState *cs, const TranslationBlock *tb)
{
    MIPSCPU *cpu = MIPS_CPU(cs->uc, cs);
    CPUMIPSState *env = &cpu->env;

    env->active_tc.PC = tb->pc;
    env->hflags &= ~MIPS_HFLAG_BMASK;
    env->hflags |= tb->flags & MIPS_HFLAG_BMASK;
}
#endif /* CONFIG_TCG */

static bool mips_cpu_has_work(CPUState *cs)
{
    MIPSCPU *cpu = MIPS_CPU(cs->uc, cs);
    CPUMIPSState *env = &cpu->env;
    bool has_work = false;

    /*
     * Prior to MIPS Release 6 it is implementation dependent if non-enabled
     * interrupts wake-up the CPU, however most of the implementations only
     * check for interrupts that can be taken.
     */
    if ((cs->interrupt_request & CPU_INTERRUPT_HARD) &&
        cpu_mips_hw_interrupts_pending(env)) {
        if (cpu_mips_hw_interrupts_enabled(env) ||
            (env->insn_flags & ISA_MIPS32R6)) {
            has_work = true;
        }
    }

    /* MIPS-MT has the ability to halt the CPU.  */
    if (env->CP0_Config3 & (1 << CP0C3_MT)) {
        /*
         * The QEMU model will issue an _WAKE request whenever the CPUs
         * should be woken up.
         */
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }

        if (!mips_vpe_active(env)) {
            has_work = false;
        }
    }
    /* MIPS Release 6 has the ability to halt the CPU.  */
    if (env->CP0_Config5 & (1 << CP0C5_VP)) {
        if (cs->interrupt_request & CPU_INTERRUPT_WAKE) {
            has_work = true;
        }
        if (!mips_vp_active(env)) {
            has_work = false;
        }
    }
    return has_work;
}

/* CPUClass::reset() */
static void mips_cpu_reset(CPUState *s)
{
    MIPSCPU *cpu = MIPS_CPU(s->uc, s);
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(s->uc, cpu);
    CPUMIPSState *env = &cpu->env;

    mcc->parent_reset(s);

    memset(env, 0, offsetof(CPUMIPSState, end_reset_fields));

    cpu_state_reset(env);
}

static int mips_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    MIPSCPU *cpu = MIPS_CPU(uc, dev);
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(uc, dev);

    cpu_mips_realize_env(&cpu->env);

    cpu_reset(cs);
    qemu_init_vcpu(cs);

    mcc->parent_realize(uc, dev, errp);

    return 0;
}

static void mips_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    MIPSCPU *cpu = MIPS_CPU(uc, obj);
    CPUMIPSState *env = &cpu->env;
    MIPSCPUClass *mcc = MIPS_CPU_GET_CLASS(uc, obj);

    cpu_set_cpustate_pointers(cpu);
    env->cpu_model = mcc->cpu_def;
    cpu_exec_init(cs, &error_abort, opaque);
}

static char *mips_cpu_type_name(const char *cpu_model)
{
    return g_strdup_printf("%s-" TYPE_MIPS_CPU, cpu_model);
}

static ObjectClass *mips_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    if (cpu_model == NULL) {
        return NULL;
    }

    typename = mips_cpu_type_name(cpu_model);
    oc = object_class_by_name(uc, typename);
    g_free(typename);
    return oc;
}

static void mips_cpu_class_init(struct uc_struct *uc, ObjectClass *c, void *data)
{
    MIPSCPUClass *mcc = MIPS_CPU_CLASS(uc, c);
    CPUClass *cc = CPU_CLASS(uc, c);
    DeviceClass *dc = DEVICE_CLASS(uc, c);

    mcc->parent_realize = dc->realize;
    dc->realize = mips_cpu_realizefn;

    mcc->parent_reset = cc->reset;
    cc->reset = mips_cpu_reset;

    cc->class_by_name = mips_cpu_class_by_name;
    cc->has_work = mips_cpu_has_work;
    cc->set_pc = mips_cpu_set_pc;
#ifndef CONFIG_USER_ONLY
    cc->get_phys_page_debug = mips_cpu_get_phys_page_debug;
#endif
#ifdef CONFIG_TCG
    cc->tcg_ops.initialize = mips_tcg_init;
    cc->tcg_ops.do_interrupt = mips_cpu_do_interrupt;
    cc->tcg_ops.cpu_exec_interrupt = mips_cpu_exec_interrupt;
    cc->tcg_ops.synchronize_from_tb = mips_cpu_synchronize_from_tb;
    cc->tcg_ops.tlb_fill = mips_cpu_tlb_fill;
#ifndef CONFIG_USER_ONLY
    cc->tcg_ops.do_transaction_failed = mips_cpu_do_transaction_failed;
    cc->tcg_ops.do_unaligned_access = mips_cpu_do_unaligned_access;
#endif /* CONFIG_USER_ONLY */
#endif /* CONFIG_TCG */
}

static void mips_cpu_cpudef_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    MIPSCPUClass *mcc = MIPS_CPU_CLASS(uc, oc);
    mcc->cpu_def = data;
}

static void mips_register_cpudef_type(struct uc_struct *uc, const struct mips_def_t *def)
{
    char *typename = mips_cpu_type_name(def->name);
    TypeInfo ti = {
        .name = typename,
        .parent = TYPE_MIPS_CPU,

        .class_data = (void *)def,
        .class_init = mips_cpu_cpudef_class_init,
    };

    type_register(uc, &ti);
    g_free(typename);
}

void mips_cpu_register_types(void *opaque)
{
    int i;

    const TypeInfo mips_cpu_type_info = {
        .name = TYPE_MIPS_CPU,
        .parent = TYPE_CPU,

        .class_size = sizeof(MIPSCPUClass),
        .instance_size = sizeof(MIPSCPU),
        .instance_userdata = opaque,

        .instance_init = mips_cpu_initfn,
        .class_init = mips_cpu_class_init,

        .abstract = true,
    };

    type_register(opaque, &mips_cpu_type_info);
    for (i = 0; i < mips_defs_number; i++) {
        mips_register_cpudef_type(opaque, &mips_defs[i]);
    }
}
