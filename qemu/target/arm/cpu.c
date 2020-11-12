/*
 * QEMU ARM CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "cpu.h"
#include "internals.h"
#include "qemu-common.h"
#include "exec/exec-all.h"
#include "qapi/qmp/qerror.h"
#include "hw/arm/arm.h"
#include "sysemu/sysemu.h"
#include "fpu/softfloat.h"

#include "uc_priv.h"

static void arm_cpu_set_pc(CPUState *cs, vaddr value)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);
    CPUARMState *env = &cpu->env;

    if (is_a64(env)) {
        env->pc = value;
        env->thumb = 0;
    } else {
        env->regs[15] = value & ~1;
        env->thumb = value & 1;
    }
}

static void arm_cpu_synchronize_from_tb(CPUState *cs, TranslationBlock *tb)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);
    CPUARMState *env = &cpu->env;

    /*
     * It's OK to look at env for the current mode here, because it's
     * never possible for an AArch64 TB to chain to an AArch32 TB.
     */
    if (is_a64(env)) {
        env->pc = tb->pc;
    } else {
        env->regs[15] = tb->pc;
    }
}

static bool arm_cpu_has_work(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);

    return !cpu->powered_off
        && cs->interrupt_request &
        (CPU_INTERRUPT_FIQ | CPU_INTERRUPT_HARD
         | CPU_INTERRUPT_VFIQ | CPU_INTERRUPT_VIRQ
         | CPU_INTERRUPT_EXITTB);
}

void arm_register_pre_el_change_hook(ARMCPU *cpu, ARMELChangeHookFn *hook,
                                 void *opaque)
{
    ARMELChangeHook *entry = g_new0(ARMELChangeHook, 1);

    entry->hook = hook;
    entry->opaque = opaque;

    QLIST_INSERT_HEAD(&cpu->pre_el_change_hooks, entry, node);
}

void arm_register_el_change_hook(ARMCPU *cpu, ARMELChangeHookFn *hook,
                                 void *opaque)
{
    ARMELChangeHook *entry = g_new0(ARMELChangeHook, 1);

    entry->hook = hook;
    entry->opaque = opaque;

    QLIST_INSERT_HEAD(&cpu->el_change_hooks, entry, node);
}

static void cp_reg_reset(gpointer key, gpointer value, gpointer opaque)
{
    /* Reset a single ARMCPRegInfo register */
    ARMCPRegInfo *ri = value;
    ARMCPU *cpu = opaque;

    if (ri->type & (ARM_CP_SPECIAL | ARM_CP_ALIAS)) {
        return;
    }

    if (ri->resetfn) {
        ri->resetfn(&cpu->env, ri);
        return;
    }

    /* A zero offset is never possible as it would be regs[0]
     * so we use it to indicate that reset is being handled elsewhere.
     * This is basically only used for fields in non-core coprocessors
     * (like the pxa2xx ones).
     */
    if (!ri->fieldoffset) {
        return;
    }

    if (cpreg_field_is_64bit(ri)) {
        CPREG_FIELD64(&cpu->env, ri) = ri->resetvalue;
    } else {
        CPREG_FIELD32(&cpu->env, ri) = ri->resetvalue;
    }
}

static void cp_reg_check_reset(gpointer key, gpointer value,  gpointer opaque)
{
    /* Purely an assertion check: we've already done reset once,
     * so now check that running the reset for the cpreg doesn't
     * change its value. This traps bugs where two different cpregs
     * both try to reset the same state field but to different values.
     */
    ARMCPRegInfo *ri = value;
    ARMCPU *cpu = opaque;
    uint64_t oldvalue, newvalue;

    if (ri->type & (ARM_CP_SPECIAL | ARM_CP_ALIAS | ARM_CP_NO_RAW)) {
        return;
    }

    oldvalue = read_raw_cp_reg(&cpu->env, ri);
    cp_reg_reset(key, value, opaque);
    newvalue = read_raw_cp_reg(&cpu->env, ri);
    assert(oldvalue == newvalue);
}

/* CPUClass::reset() */
static void arm_cpu_reset(CPUState *s)
{
    CPUARMState *env = s->env_ptr;
    ARMCPU *cpu = ARM_CPU(env->uc, s);
    ARMCPUClass *acc = ARM_CPU_GET_CLASS(env->uc, cpu);

    acc->parent_reset(s);

    memset(env, 0, offsetof(CPUARMState, end_reset_fields));

    g_hash_table_foreach(cpu->cp_regs, cp_reg_reset, cpu);
    g_hash_table_foreach(cpu->cp_regs, cp_reg_check_reset, cpu);

    env->vfp.xregs[ARM_VFP_FPSID] = cpu->reset_fpsid;
    env->vfp.xregs[ARM_VFP_MVFR0] = cpu->isar.mvfr0;
    env->vfp.xregs[ARM_VFP_MVFR1] = cpu->isar.mvfr1;
    env->vfp.xregs[ARM_VFP_MVFR2] = cpu->isar.mvfr2;

    cpu->powered_off = cpu->start_powered_off;
    s->halted = cpu->start_powered_off;

    if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
        env->iwmmxt.cregs[ARM_IWMMXT_wCID] = 0x69051000 | 'Q';
    }

    if (arm_feature(env, ARM_FEATURE_AARCH64)) {
        /* 64 bit CPUs always start in 64 bit mode */
        env->aarch64 = 1;
#if defined(CONFIG_USER_ONLY)
        env->pstate = PSTATE_MODE_EL0t;
        /* Userspace expects access to DC ZVA, CTL_EL0 and the cache ops */
        env->cp15.sctlr_el[1] |= SCTLR_UCT | SCTLR_UCI | SCTLR_DZE;
        /* Enable all PAC keys.  */
        env->cp15.sctlr_el[1] |= (SCTLR_EnIA | SCTLR_EnIB |
                                  SCTLR_EnDA | SCTLR_EnDB);
        /* Enable all PAC instructions */
        env->cp15.hcr_el2 |= HCR_API;
        env->cp15.scr_el3 |= SCR_API;
        /* and to the FP/Neon instructions */
        env->cp15.cpacr_el1 = deposit64(env->cp15.cpacr_el1, 20, 2, 3);
        /* and to the SVE instructions */
        env->cp15.cpacr_el1 = deposit64(env->cp15.cpacr_el1, 16, 2, 3);
        env->cp15.cptr_el[3] |= CPTR_EZ;
        /* with maximum vector length */
        env->vfp.zcr_el[1] = cpu->sve_max_vq - 1;
        env->vfp.zcr_el[2] = env->vfp.zcr_el[1];
        env->vfp.zcr_el[3] = env->vfp.zcr_el[1];
        /*
         * Enable TBI0 and TBI1.  While the real kernel only enables TBI0,
         * turning on both here will produce smaller code and otherwise
         * make no difference to the user-level emulation.
         */
        env->cp15.tcr_el[1].raw_tcr = (3ULL << 37);
#else
        /* Reset into the highest available EL */
        if (arm_feature(env, ARM_FEATURE_EL3)) {
            env->pstate = PSTATE_MODE_EL3h;
        } else if (arm_feature(env, ARM_FEATURE_EL2)) {
            env->pstate = PSTATE_MODE_EL2h;
        } else {
            env->pstate = PSTATE_MODE_EL1h;
        }
        env->pc = cpu->rvbar;
#endif
    } else {
// SNPS changed
#if defined(CONFIG_USER_ONLY)
        /* Userspace expects access to cp10 and cp11 for FP/Neon */
        env->cp15.cpacr_el1 = deposit64(env->cp15.cpacr_el1, 20, 4, 0xf);
#endif
    }

#if defined(CONFIG_USER_ONLY)
    env->uncached_cpsr = ARM_CPU_MODE_USR;
    /* For user mode we must enable access to coprocessors */
    env->vfp.xregs[ARM_VFP_FPEXC] = 1 << 30;
    if (arm_feature(env, ARM_FEATURE_IWMMXT)) {
        env->cp15.c15_cpar = 3;
    } else if (arm_feature(env, ARM_FEATURE_XSCALE)) {
        env->cp15.c15_cpar = 1;
    }

#if defined(CONFIG_USER_ONLY)
    env->uncached_cpsr = ARM_CPU_MODE_USR;
#else
    /*
     * If the highest available EL is EL2, AArch32 will start in Hyp
     * mode; otherwise it starts in SVC. Note that if we start in
     * AArch64 then these values in the uncached_cpsr will be ignored.
     */
    if (arm_feature(env, ARM_FEATURE_EL2) &&
        !arm_feature(env, ARM_FEATURE_EL3)) {
        env->uncached_cpsr = ARM_CPU_MODE_HYP;
    } else {
        env->uncached_cpsr = ARM_CPU_MODE_SVC;
    }
    env->daif = PSTATE_D | PSTATE_A | PSTATE_I | PSTATE_F;

    if (arm_feature(env, ARM_FEATURE_M)) {
        uint32_t initial_msp; /* Loaded from 0x0 */
        uint32_t initial_pc; /* Loaded from 0x4 */
        uint32_t vecbase = 0;

        if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
            env->v7m.secure = true;
        } else {
            /* This bit resets to 0 if security is supported, but 1 if
             * it is not. The bit is not present in v7M, but we set it
             * here so we can avoid having to make checks on it conditional
             * on ARM_FEATURE_V8 (we don't let the guest see the bit).
             */
            env->v7m.aircr = R_V7M_AIRCR_BFHFNMINS_MASK;
            /*
             * Set NSACR to indicate "NS access permitted to everything";
             * this avoids having to have all the tests of it being
             * conditional on ARM_FEATURE_M_SECURITY. Note also that from
             * v8.1M the guest-visible value of NSACR in a CPU without the
             * Security Extension is 0xcff.
             */
            env->v7m.nsacr = 0xcff;
        }

        /* In v7M the reset value of this bit is IMPDEF, but ARM recommends
         * that it resets to 1, so QEMU always does that rather than making
         * it dependent on CPU model. In v8M it is RES1.
         */
        env->v7m.ccr[M_REG_NS] = R_V7M_CCR_STKALIGN_MASK;
        env->v7m.ccr[M_REG_S] = R_V7M_CCR_STKALIGN_MASK;
        if (arm_feature(env, ARM_FEATURE_V8)) {
            /* in v8M the NONBASETHRDENA bit [0] is RES1 */
            env->v7m.ccr[M_REG_NS] |= R_V7M_CCR_NONBASETHRDENA_MASK;
            env->v7m.ccr[M_REG_S] |= R_V7M_CCR_NONBASETHRDENA_MASK;
        }
        if (!arm_feature(env, ARM_FEATURE_M_MAIN)) {
            env->v7m.ccr[M_REG_NS] |= R_V7M_CCR_UNALIGN_TRP_MASK;
            env->v7m.ccr[M_REG_S] |= R_V7M_CCR_UNALIGN_TRP_MASK;
        }

        if (cpu_isar_feature(aa32_vfp_simd, cpu)) {
            env->v7m.fpccr[M_REG_NS] = R_V7M_FPCCR_ASPEN_MASK;
            env->v7m.fpccr[M_REG_S] = R_V7M_FPCCR_ASPEN_MASK |
                R_V7M_FPCCR_LSPEN_MASK | R_V7M_FPCCR_S_MASK;
        }
        /* Unlike A/R profile, M profile defines the reset LR value */
        env->regs[14] = 0xffffffff;

        env->v7m.vecbase[M_REG_S] = cpu->init_svtor & 0xffffff80;
#if 0
        uint8_t *rom;

        /* Load the initial SP and PC from offset 0 and 4 in the vector table */
        vecbase = env->v7m.vecbase[env->v7m.secure];
        rom = rom_ptr(vecbase);
        if (rom) {
            /* Address zero is covered by ROM which hasn't yet been
             * copied into physical memory.
             */
            initial_msp = ldl_p(rom);
            initial_pc = ldl_p(rom + 4);
        } else
#endif
        {
            /* Address zero not covered by a ROM blob, or the ROM blob
             * is in non-modifiable memory and this is a second reset after
             * it got copied into memory. In the latter case, rom_ptr
             * will return a NULL pointer and we should use ldl_phys instead.
             */
            initial_msp = ldl_phys(s->as, vecbase);
            initial_pc = ldl_phys(s->as, vecbase + 4);
        }

        env->regs[13] = initial_msp & 0xFFFFFFFC;
        env->regs[15] = initial_pc & ~1;
        env->thumb = initial_pc & 1;
    }

    // Unicorn: force Thumb mode by setting of uc_open()
    env->thumb = env->uc->thumb;

    /* AArch32 has a hard highvec setting of 0xFFFF0000.  If we are currently
     * executing as AArch32 then check if highvecs are enabled and
     * adjust the PC accordingly.
     */
    if (A32_BANKED_CURRENT_REG_GET(env, sctlr) & SCTLR_V) {
        env->regs[15] = 0xFFFF0000;
    }

    /* M profile requires that reset clears the exclusive monitor;
     * A profile does not, but clearing it makes more sense than having it
     * set with an exclusive access on address zero.
     */
    arm_clear_exclusive(env);

    env->vfp.xregs[ARM_VFP_FPEXC] = 0;
#endif

    if (arm_feature(env, ARM_FEATURE_PMSA)) {
        if (cpu->pmsav7_dregion > 0) {
            if (arm_feature(env, ARM_FEATURE_V8)) {
                memset(env->pmsav8.rbar[M_REG_NS], 0,
                       sizeof(*env->pmsav8.rbar[M_REG_NS])
                       * cpu->pmsav7_dregion);
                memset(env->pmsav8.rlar[M_REG_NS], 0,
                       sizeof(*env->pmsav8.rlar[M_REG_NS])
                       * cpu->pmsav7_dregion);
                if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
                    memset(env->pmsav8.rbar[M_REG_S], 0,
                           sizeof(*env->pmsav8.rbar[M_REG_S])
                           * cpu->pmsav7_dregion);
                    memset(env->pmsav8.rlar[M_REG_S], 0,
                           sizeof(*env->pmsav8.rlar[M_REG_S])
                           * cpu->pmsav7_dregion);
                }
            } else if (arm_feature(env, ARM_FEATURE_V7)) {
                memset(env->pmsav7.drbar, 0,
                       sizeof(*env->pmsav7.drbar) * cpu->pmsav7_dregion);
                memset(env->pmsav7.drsr, 0,
                       sizeof(*env->pmsav7.drsr) * cpu->pmsav7_dregion);
                memset(env->pmsav7.dracr, 0,
                       sizeof(*env->pmsav7.dracr) * cpu->pmsav7_dregion);
            }
        }
        env->pmsav7.rnr[M_REG_NS] = 0;
        env->pmsav7.rnr[M_REG_S] = 0;
        env->pmsav8.mair0[M_REG_NS] = 0;
        env->pmsav8.mair0[M_REG_S] = 0;
        env->pmsav8.mair1[M_REG_NS] = 0;
        env->pmsav8.mair1[M_REG_S] = 0;
    }

    if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
        if (cpu->sau_sregion > 0) {
            memset(env->sau.rbar, 0, sizeof(*env->sau.rbar) * cpu->sau_sregion);
            memset(env->sau.rlar, 0, sizeof(*env->sau.rlar) * cpu->sau_sregion);
        }
        env->sau.rnr = 0;
        /* SAU_CTRL reset value is IMPDEF; we choose 0, which is what
         * the Cortex-M33 does.
         */
        env->sau.ctrl = 0;
    }

    set_flush_to_zero(1, &env->vfp.standard_fp_status);
    set_flush_inputs_to_zero(1, &env->vfp.standard_fp_status);
    set_default_nan_mode(1, &env->vfp.standard_fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.standard_fp_status);
    set_float_detect_tininess(float_tininess_before_rounding,
                              &env->vfp.fp_status_f16);

    hw_breakpoint_update_all(cpu);
    hw_watchpoint_update_all(cpu);

    // SNPS changed: set config registers (taken from hw/arm/boot.c)
    if (arm_feature(env, ARM_FEATURE_EL3) && env->aarch64)
        env->cp15.scr_el3 |= SCR_RW;  // 64bit registers on el3

    if (arm_feature(env, ARM_FEATURE_EL2) && env->aarch64)
        env->cp15.hcr_el2 |= HCR_RW;  // 64bit registers on el2

    if (arm_feature(env, ARM_FEATURE_EL3) && arm_feature(env, ARM_FEATURE_EL2))
        env->cp15.scr_el3 |= SCR_HCE; // hypervisor call available
}

static inline bool arm_excp_unmasked(CPUState *cs, unsigned int excp_idx,
                                     unsigned int target_el,
                                     unsigned int cur_el, bool secure,
                                     uint64_t hcr_el2)
{
    CPUARMState *env = cs->env_ptr;
    bool pstate_unmasked;
    bool unmasked = false;

    /*
     * Don't take exceptions if they target a lower EL.
     * This check should catch any exceptions that would not be taken
     * but left pending.
     */
    if (cur_el > target_el) {
        return false;
    }

    switch (excp_idx) {
    case EXCP_FIQ:
        pstate_unmasked = !(env->daif & PSTATE_F);
        break;

    case EXCP_IRQ:
        pstate_unmasked = !(env->daif & PSTATE_I);
        break;

    case EXCP_VFIQ:
        if (secure || !(hcr_el2 & HCR_FMO) || (hcr_el2 & HCR_TGE)) {
            /* VFIQs are only taken when hypervized and non-secure.  */
            return false;
        }
        return !(env->daif & PSTATE_F);
    case EXCP_VIRQ:
        if (secure || !(hcr_el2 & HCR_IMO) || (hcr_el2 & HCR_TGE)) {
            /* VIRQs are only taken when hypervized and non-secure.  */
            return false;
        }
        return !(env->daif & PSTATE_I);
    default:
        g_assert_not_reached();
    }

    /*
     * Use the target EL, current execution state and SCR/HCR settings to
     * determine whether the corresponding CPSR bit is used to mask the
     * interrupt.
     */
    if ((target_el > cur_el) && (target_el != 1)) {
        /* Exceptions targeting a higher EL may not be maskable */
        if (arm_feature(env, ARM_FEATURE_AARCH64)) {
            /*
             * 64-bit masking rules are simple: exceptions to EL3
             * can't be masked, and exceptions to EL2 can only be
             * masked from Secure state. The HCR and SCR settings
             * don't affect the masking logic, only the interrupt routing.
             */
            if (target_el == 3 || !secure) {
                unmasked = true;
            }
        } else {
            /*
             * The old 32-bit-only environment has a more complicated
             * masking setup. HCR and SCR bits not only affect interrupt
             * routing but also change the behaviour of masking.
             */
            bool hcr, scr;

            switch (excp_idx) {
            case EXCP_FIQ:
                /*
                 * If FIQs are routed to EL3 or EL2 then there are cases where
                 * we override the CPSR.F in determining if the exception is
                 * masked or not. If neither of these are set then we fall back
                 * to the CPSR.F setting otherwise we further assess the state
                 * below.
                 */
                hcr = hcr_el2 & HCR_FMO;
                scr = (env->cp15.scr_el3 & SCR_FIQ);

                /*
                 * When EL3 is 32-bit, the SCR.FW bit controls whether the
                 * CPSR.F bit masks FIQ interrupts when taken in non-secure
                 * state. If SCR.FW is set then FIQs can be masked by CPSR.F
                 * when non-secure but only when FIQs are only routed to EL3.
                 */
                scr = scr && !((env->cp15.scr_el3 & SCR_FW) && !hcr);
                break;
            case EXCP_IRQ:
                /*
                 * When EL3 execution state is 32-bit, if HCR.IMO is set then
                 * we may override the CPSR.I masking when in non-secure state.
                 * The SCR.IRQ setting has already been taken into consideration
                 * when setting the target EL, so it does not have a further
                 * affect here.
                 */
                hcr = hcr_el2 & HCR_IMO;
                scr = false;
                break;
            default:
                g_assert_not_reached();
            }

            if ((scr || hcr) && !secure) {
                unmasked = true;
            }
        }
    }

    /*
     * The PSTATE bits only mask the interrupt if we have not overriden the
     * ability above.
     */
    return unmasked || pstate_unmasked;
}

bool arm_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    CPUARMState *env = cs->env_ptr;
    CPUClass *cc = CPU_GET_CLASS(env->uc, cs);
    uint32_t cur_el = arm_current_el(env);
    bool secure = arm_is_secure(env);
    uint64_t hcr_el2 = arm_hcr_el2_eff(env);
    uint32_t target_el;
    uint32_t excp_idx;

    /* The prioritization of interrupts is IMPLEMENTATION DEFINED. */

    if (interrupt_request & CPU_INTERRUPT_FIQ) {
        excp_idx = EXCP_FIQ;
        target_el = arm_phys_excp_target_el(cs, excp_idx, cur_el, secure);
        if (arm_excp_unmasked(cs, excp_idx, target_el,
                              cur_el, secure, hcr_el2)) {
            goto found;
        }
    }
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        excp_idx = EXCP_IRQ;
        target_el = arm_phys_excp_target_el(cs, excp_idx, cur_el, secure);
        if (arm_excp_unmasked(cs, excp_idx, target_el,
                              cur_el, secure, hcr_el2)) {
            goto found;
        }
    }
    if (interrupt_request & CPU_INTERRUPT_VIRQ) {
        excp_idx = EXCP_VIRQ;
        target_el = 1;
        if (arm_excp_unmasked(cs, excp_idx, target_el,
                              cur_el, secure, hcr_el2)) {
            goto found;
        }
    }
    if (interrupt_request & CPU_INTERRUPT_VFIQ) {
        excp_idx = EXCP_VFIQ;
        target_el = 1;
        if (arm_excp_unmasked(cs, excp_idx, target_el,
                              cur_el, secure, hcr_el2)) {
            goto found;
        }
    }
    return false;

 found:
    cs->exception_index = excp_idx;
    env->exception.target_el = target_el;
    cc->do_interrupt(cs);
    return true;
}

#if !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64)
static bool arm_v7m_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    CPUARMState *env = cs->env_ptr;
    CPUClass *cc = CPU_GET_CLASS(env->uc, cs);
    bool ret = false;

    /*
     * ARMv7-M interrupt masking works differently than -A or -R.
     * There is no FIQ/IRQ distinction. Instead of I and F bits
     * masking FIQ and IRQ interrupts, an exception is taken only
     * if it is higher priority than the current execution priority
     * (which depends on state like BASEPRI, FAULTMASK and the
     * currently active exception).
     */
    if (interrupt_request & CPU_INTERRUPT_HARD
        /*&& (armv7m_nvic_can_take_pending_exception(env->nvic)) */) {
        cs->exception_index = EXCP_IRQ;
        cc->do_interrupt(cs);
        ret = true;
    }
    return ret;
}
#endif

void arm_cpu_update_virq(ARMCPU *cpu)
{
    /*
     * Update the interrupt level for VIRQ, which is the logical OR of
     * the HCR_EL2.VI bit and the input line level from the GIC.
     */
    CPUARMState *env = &cpu->env;
    CPUState *cs = CPU(cpu);

    bool new_state = (env->cp15.hcr_el2 & HCR_VI) ||
        (env->irq_line_state & CPU_INTERRUPT_VIRQ);

    if (new_state != ((cs->interrupt_request & CPU_INTERRUPT_VIRQ) != 0)) {
        if (new_state) {
            cpu_interrupt(cs, CPU_INTERRUPT_VIRQ);
        } else {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_VIRQ);
        }
    }
}

void arm_cpu_update_vfiq(ARMCPU *cpu)
{
    /*
     * Update the interrupt level for VFIQ, which is the logical OR of
     * the HCR_EL2.VF bit and the input line level from the GIC.
     */
    CPUARMState *env = &cpu->env;
    CPUState *cs = CPU(cpu);

    bool new_state = (env->cp15.hcr_el2 & HCR_VF) ||
        (env->irq_line_state & CPU_INTERRUPT_VFIQ);

    if (new_state != ((cs->interrupt_request & CPU_INTERRUPT_VFIQ) != 0)) {
        if (new_state) {
            cpu_interrupt(cs, CPU_INTERRUPT_VFIQ);
        } else {
            cpu_reset_interrupt(cs, CPU_INTERRUPT_VFIQ);
        }
    }
}

static QEMU_UNUSED_FUNC bool arm_cpu_is_big_endian(CPUState *cs)
{
    ARMCPU *cpu = ARM_CPU(NULL, cs);
    CPUARMState *env = &cpu->env;
    int cur_el;

    // UNICORN: Commented out
    //cpu_synchronize_state(cs);

    /* In 32bit guest endianness is determined by looking at CPSR's E bit */
    if (!is_a64(env)) {
        return (env->uncached_cpsr & CPSR_E) ? 1 : 0;
    }

    cur_el = arm_current_el(env);

    if (cur_el == 0) {
        return (env->cp15.sctlr_el[1] & SCTLR_E0E) != 0;
    }

    return (env->cp15.sctlr_el[cur_el] & SCTLR_EE) != 0;
}

#define ARM_CPUS_PER_CLUSTER 8

static void cpreg_hashtable_data_destroy(gpointer data)
{
    /*
     * Destroy function for cpu->cp_regs hashtable data entries.
     * We must free the name string because it was g_strdup()ed in
     * add_cpreg_to_hashtable(). It's OK to cast away the 'const'
     * from r->name because we know we definitely allocated it.
     */
    ARMCPRegInfo *r = data;

    g_free((void *)r->name);
    g_free(r);
}

static void arm_cpu_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    CPUState *cs = CPU(obj);
    ARMCPU *cpu = ARM_CPU(uc, obj);
    uint32_t Aff1, Aff0;

    cpu_set_cpustate_pointers(cpu);
    cpu_exec_init(cs, &error_abort, opaque);
    cpu->cp_regs = g_hash_table_new_full(g_int_hash, g_int_equal,
                                         g_free, cpreg_hashtable_data_destroy);

    QLIST_INIT(&cpu->pre_el_change_hooks);
    QLIST_INIT(&cpu->el_change_hooks);

    /* This cpu-id-to-MPIDR affinity is used only for TCG; KVM will override it.
     * We don't support setting cluster ID ([16..23]) (known as Aff2
     * in later ARM ARM versions), or any of the higher affinity level fields,
     * so these bits always RAZ.
     */
    Aff1 = cs->cpu_index / ARM_CPUS_PER_CLUSTER;
    Aff0 = cs->cpu_index % ARM_CPUS_PER_CLUSTER;
    cpu->mp_affinity = (Aff1 << ARM_AFF1_SHIFT) | Aff0;

#if 0
#ifndef CONFIG_USER_ONLY
    /* Our inbound IRQ and FIQ lines */

    cpu->gt_timer[GTIMER_PHYS] = timer_new(QEMU_CLOCK_VIRTUAL, GTIMER_SCALE,
                                                arm_gt_ptimer_cb, cpu);
    cpu->gt_timer[GTIMER_VIRT] = timer_new(QEMU_CLOCK_VIRTUAL, GTIMER_SCALE,
                                                arm_gt_vtimer_cb, cpu);
    cpu->gt_timer[GTIMER_HYP] = timer_new(QEMU_CLOCK_VIRTUAL, GTIMER_SCALE,
                                                arm_gt_htimer_cb, cpu);
    cpu->gt_timer[GTIMER_SEC] = timer_new(QEMU_CLOCK_VIRTUAL, GTIMER_SCALE,
                                                arm_gt_stimer_cb, cpu);
    //qdev_init_gpio_out(DEVICE(cpu), cpu->gt_timer_outputs,
    //                   ARRAY_SIZE(cpu->gt_timer_outputs));
#endif
#endif

    /* DTB consumers generally don't in fact care what the 'compatible'
     * string is, so always provide some string and trust that a hypothetical
     * picky DTB consumer will also provide a helpful error message.
     */
    cpu->dtb_compatible = "qemu,unknown";
    cpu->psci_version = 1; /* By default assume PSCI v0.1 */
    cpu->kvm_target = QEMU_KVM_ARM_TARGET_NONE;

    if (tcg_enabled(uc)) {
        cpu->psci_version = 2; /* TCG implements PSCI 0.2 */
    }
}

static void arm_cpu_post_init(struct uc_struct *uc, Object *obj)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    /* M profile implies PMSA. We have to do this here rather than
     * in realize with the other feature-implication checks because
     * we look at the PMSA bit to see if we should add some properties.
     */
    if (arm_feature(&cpu->env, ARM_FEATURE_M)) {
        set_feature(&cpu->env, ARM_FEATURE_PMSA);
    }

    if (arm_feature(&cpu->env, ARM_FEATURE_CBAR) ||
        arm_feature(&cpu->env, ARM_FEATURE_CBAR_RO)) {
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_reset_cbar_property,
        //                         &error_abort);
    }

    if (!arm_feature(&cpu->env, ARM_FEATURE_M)) {
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_reset_hivecs_property,
        //                         &error_abort);
    }

    if (arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_rvbar_property,
        //                         &error_abort);
    }

    if (arm_feature(&cpu->env, ARM_FEATURE_EL3)) {
        /* Add the has_el3 state CPU property only if EL3 is allowed.  This will
         * prevent "has_el3" from existing on CPUs which cannot support EL3.
         */
        //qdev_property_add_static(DEVICE(obj), &arm_cpu_has_el3_property,
        //                         &error_abort);

#ifndef CONFIG_USER_ONLY
        /* Unicorn: if'd out */
#if 0
        object_property_add_link(obj, "secure-memory",
                                 TYPE_MEMORY_REGION,
                                 (Object **)&cpu->secure_memory,
                                 qdev_prop_allow_set_link_before_realize,
                                 OBJ_PROP_LINK_UNREF_ON_RELEASE,
                                 &error_abort);*/
        qdev_property_add_static(DEVICE(obj), &arm_cpu_initsvtor_property,
                                 &error_abort);
#endif
#endif
    }
}

static void arm_cpu_finalizefn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    ARMELChangeHook *hook, *next;

    g_hash_table_destroy(cpu->cp_regs);

    QLIST_FOREACH_SAFE(hook, &cpu->pre_el_change_hooks, node, next) {
        QLIST_REMOVE(hook, node);
        g_free(hook);
    }
    QLIST_FOREACH_SAFE(hook, &cpu->el_change_hooks, node, next) {
        QLIST_REMOVE(hook, node);
        g_free(hook);
    }
}

static int arm_cpu_realizefn(struct uc_struct *uc, DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    ARMCPU *cpu = ARM_CPU(uc, dev);
    ARMCPUClass *acc = ARM_CPU_GET_CLASS(uc, dev);
    CPUARMState *env = &cpu->env;
    bool no_aa32 = false;

    /* Some features automatically imply others: */
    if (arm_feature(env, ARM_FEATURE_V8)) {
        if (arm_feature(env, ARM_FEATURE_M)) {
            set_feature(env, ARM_FEATURE_V7);
        } else {
            set_feature(env, ARM_FEATURE_V7VE);
        }
    }

    /*
     * There exist AArch64 cpus without AArch32 support.  When KVM
     * queries ID_ISAR0_EL1 on such a host, the value is UNKNOWN.
     * Similarly, we cannot check ID_AA64PFR0 without AArch64 support.
     * As a general principle, we also do not make ID register
     * consistency checks anywhere unless using TCG, because only
     * for TCG would a consistency-check failure be a QEMU bug.
     */
    if (arm_feature(&cpu->env, ARM_FEATURE_AARCH64)) {
        no_aa32 = !cpu_isar_feature(aa64_aa32, cpu);
    }

    if (arm_feature(env, ARM_FEATURE_V7VE)) {
        /* v7 Virtualization Extensions. In real hardware this implies
         * EL2 and also the presence of the Security Extensions.
         * For QEMU, for backwards-compatibility we implement some
         * CPUs or CPU configs which have no actual EL2 or EL3 but do
         * include the various other features that V7VE implies.
         * Presence of EL2 itself is ARM_FEATURE_EL2, and of the
         * Security Extensions is ARM_FEATURE_EL3.
         */
        assert(!tcg_enabled(uc) || no_aa32 ||
               cpu_isar_feature(aa32_arm_div, cpu));
        set_feature(env, ARM_FEATURE_LPAE);
        set_feature(env, ARM_FEATURE_V7);
    }
    if (arm_feature(env, ARM_FEATURE_V7)) {
        set_feature(env, ARM_FEATURE_VAPA);
        set_feature(env, ARM_FEATURE_THUMB2);
        set_feature(env, ARM_FEATURE_MPIDR);
        if (!arm_feature(env, ARM_FEATURE_M)) {
            set_feature(env, ARM_FEATURE_V6K);
        } else {
            set_feature(env, ARM_FEATURE_V6);
        }

        /* Always define VBAR for V7 CPUs even if it doesn't exist in
         * non-EL3 configs. This is needed by some legacy boards.
         */
        set_feature(env, ARM_FEATURE_VBAR);
    }
    if (arm_feature(env, ARM_FEATURE_V6K)) {
        set_feature(env, ARM_FEATURE_V6);
        set_feature(env, ARM_FEATURE_MVFR);
    }
    if (arm_feature(env, ARM_FEATURE_V6)) {
        set_feature(env, ARM_FEATURE_V5);
        if (!arm_feature(env, ARM_FEATURE_M)) {
            assert(!tcg_enabled(uc) || no_aa32 ||
                   cpu_isar_feature(aa32_jazelle, cpu));
            set_feature(env, ARM_FEATURE_AUXCR);
        }
    }
    if (arm_feature(env, ARM_FEATURE_V5)) {
        set_feature(env, ARM_FEATURE_V4T);
    }
    if (arm_feature(env, ARM_FEATURE_LPAE)) {
        set_feature(env, ARM_FEATURE_V7MP);
        set_feature(env, ARM_FEATURE_PXN);
    }
    if (arm_feature(env, ARM_FEATURE_CBAR_RO)) {
        set_feature(env, ARM_FEATURE_CBAR);
    }
    if (arm_feature(env, ARM_FEATURE_THUMB2) &&
        !arm_feature(env, ARM_FEATURE_M)) {
        set_feature(env, ARM_FEATURE_THUMB_DSP);
    }

    /*
     * We rely on no XScale CPU having VFP so we can use the same bits in the
     * TB flags field for VECSTRIDE and XSCALE_CPAR.
     */
    assert(arm_feature(&cpu->env, ARM_FEATURE_AARCH64) ||
           !cpu_isar_feature(aa32_vfp_simd, cpu) ||
           !arm_feature(env, ARM_FEATURE_XSCALE));

    if (cpu->reset_hivecs) {
            cpu->reset_sctlr |= (1 << 13);
    }

    if (cpu->cfgend) {
        if (arm_feature(&cpu->env, ARM_FEATURE_V7)) {
            cpu->reset_sctlr |= SCTLR_EE;
        } else {
            cpu->reset_sctlr |= SCTLR_B;
        }
    }

    if (!cpu->has_el3) {
        /* If the has_el3 CPU property is disabled then we need to disable the
         * feature.
         */
        unset_feature(env, ARM_FEATURE_EL3);

        /* Disable the security extension feature bits in the processor feature
         * registers as well. These are id_pfr1[7:4] and id_aa64pfr0[15:12].
         */
        cpu->id_pfr1 &= ~0xf0;
        cpu->isar.id_aa64pfr0 &= ~0xf000;
    }

    if (!cpu->has_el2) {
        unset_feature(env, ARM_FEATURE_EL2);
    }

    if (!cpu->has_pmu) {
        unset_feature(env, ARM_FEATURE_PMU);
    }
    if (arm_feature(env, ARM_FEATURE_PMU)) {
        pmu_init(cpu);

        arm_register_pre_el_change_hook(cpu, &pmu_pre_el_change, 0);
        arm_register_el_change_hook(cpu, &pmu_post_el_change, 0);
    } else {
        cpu->isar.id_aa64dfr0 =
            FIELD_DP64(cpu->isar.id_aa64dfr0, ID_AA64DFR0, PMUVER, 0);
        cpu->isar.id_dfr0 = FIELD_DP32(cpu->isar.id_dfr0, ID_DFR0, PERFMON, 0);
        cpu->pmceid0 = 0;
        cpu->pmceid1 = 0;
    }

    if (!arm_feature(env, ARM_FEATURE_EL2)) {
        /* Disable the hypervisor feature bits in the processor feature
         * registers if we don't have EL2. These are id_pfr1[15:12] and
         * id_aa64pfr0_el1[11:8].
         */
        cpu->isar.id_aa64pfr0 &= ~0xf00;
        cpu->id_pfr1 &= ~0xf000;
    }

    /* MPU can be configured out of a PMSA CPU either by setting has-mpu
     * to false or by setting pmsav7-dregion to 0.
     */
    if (!cpu->has_mpu) {
        cpu->pmsav7_dregion = 0;
    }
    if (cpu->pmsav7_dregion == 0) {
        cpu->has_mpu = false;
    }

    if (arm_feature(env, ARM_FEATURE_PMSA) &&
        arm_feature(env, ARM_FEATURE_V7)) {
        uint32_t nr = cpu->pmsav7_dregion;

        if (nr > 0xff) {
            error_setg(errp, "PMSAv7 MPU #regions invalid %" PRIu32 "\n", nr);
            return -1;
        }

        if (nr) {
            if (arm_feature(env, ARM_FEATURE_V8)) {
                /* PMSAv8 */
                env->pmsav8.rbar[M_REG_NS] = g_new0(uint32_t, nr);
                env->pmsav8.rlar[M_REG_NS] = g_new0(uint32_t, nr);
                if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
                    env->pmsav8.rbar[M_REG_S] = g_new0(uint32_t, nr);
                    env->pmsav8.rlar[M_REG_S] = g_new0(uint32_t, nr);
                }
            } else {
                env->pmsav7.drbar = g_new0(uint32_t, nr);
                env->pmsav7.drsr = g_new0(uint32_t, nr);
                env->pmsav7.dracr = g_new0(uint32_t, nr);
            }
        }
    }

    if (arm_feature(env, ARM_FEATURE_M_SECURITY)) {
        uint32_t nr = cpu->sau_sregion;

        if (nr > 0xff) {
            error_setg(errp, "v8M SAU #regions invalid %" PRIu32, nr);
            return -1;
        }

        if (nr) {
            env->sau.rbar = g_new0(uint32_t, nr);
            env->sau.rlar = g_new0(uint32_t, nr);
        }
    }

    if (arm_feature(env, ARM_FEATURE_EL3)) {
        set_feature(env, ARM_FEATURE_VBAR);
    }

    register_cp_regs_for_features(cpu);
    arm_cpu_register_gdb_regs_for_features(cpu);

    init_cpreg_list(cpu);

#ifndef CONFIG_USER_ONLY
    if (cpu->has_el3 || arm_feature(env, ARM_FEATURE_M_SECURITY)) {
        cs->num_ases = 2;

        if (!cpu->secure_memory) {
            cpu->secure_memory = cs->memory;
        }
        cpu_address_space_init(cs, ARMASIdx_S, "cpu-secure-memory",
                               cpu->secure_memory);
    } else {
        cs->num_ases = 1;
    }
    cpu_address_space_init(cs, ARMASIdx_NS, "cpu-memory", cs->memory);

    /* No core_count specified, default to smp_cpus. */
    if (cpu->core_count == -1) {
        cpu->core_count = smp_cpus;
    }
#endif

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    acc->parent_realize(uc, dev, errp);

    return 0;
}

static ObjectClass *arm_cpu_class_by_name(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;
    char **cpuname;
    const char *cpunamestr;

    cpuname = g_strsplit(cpu_model, ",", 1);
    cpunamestr = cpuname[0];
#ifdef CONFIG_USER_ONLY
    /* For backwards compatibility usermode emulation allows "-cpu any",
     * which has the same semantics as "-cpu max".
     */
    if (!strcmp(cpunamestr, "any")) {
        cpunamestr = "max";
    }
#endif
    typename = g_strdup_printf(ARM_CPU_TYPE_NAME("%s"), cpunamestr);
    oc = object_class_by_name(uc, typename);
    g_strfreev(cpuname);
    g_free(typename);
    if (!oc || !object_class_dynamic_cast(uc, oc, TYPE_ARM_CPU) ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

/* CPU models. These are not needed for the AArch64 linux-user build. */
#if !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64)

static void arm926_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm926";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_TEST_CLEAN);
    cpu->midr = 0x41069265;
    cpu->reset_fpsid = 0x41011090;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00090078;

    /*
     * ARMv5 does not have the ID_ISAR registers, but we can still
     * set the field to indicate Jazelle support within QEMU.
     */
    cpu->isar.id_isar1 = FIELD_DP32(cpu->isar.id_isar1, ID_ISAR1, JAZELLE, 1);
    /*
     * Similarly, we need to set MVFR0 fields to enable vfp and short vector
     * support even though ARMv5 doesn't have this register.
     */
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPSHVEC, 1);
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPSP, 1);
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPDP, 1);
}

static void arm946_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm946";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_PMSA);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x41059461;
    cpu->ctr = 0x0f004006;
    cpu->reset_sctlr = 0x00000078;
}

static void arm1026_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm1026";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_AUXCR);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_TEST_CLEAN);
    cpu->midr = 0x4106a262;
    cpu->reset_fpsid = 0x410110a0;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00090078;
    cpu->reset_auxcr = 1;

    /*
     * ARMv5 does not have the ID_ISAR registers, but we can still
     * set the field to indicate Jazelle support within QEMU.
     */
    cpu->isar.id_isar1 = FIELD_DP32(cpu->isar.id_isar1, ID_ISAR1, JAZELLE, 1);
    /*
     * Similarly, we need to set MVFR0 fields to enable vfp and short vector
     * support even though ARMv5 doesn't have this register.
     */
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPSHVEC, 1);
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPSP, 1);
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPDP, 1);

    {
        /* The 1026 had an IFAR at c6,c0,0,1 rather than the ARMv6 c6,c0,0,2 */
        ARMCPRegInfo ifar = {
            .name = "IFAR", .cp = 15, .crn = 6, .crm = 0, .opc1 = 0, .opc2 = 1,
            .access = PL1_RW,
            .fieldoffset = offsetof(CPUARMState, cp15.ifar_ns),
            .resetvalue = 0
        };
        define_one_arm_cp_reg(cpu, &ifar);
    }
}

static void arm1136_r2_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    /*
     * What qemu calls "arm1136_r2" is actually the 1136 r0p2, ie an
     * older core than plain "arm1136". In particular this does not
     * have the v6K features.
     * These ID register values are correct for 1136 but may be wrong
     * for 1136_r2 (in particular r0p2 does not actually implement most
     * of the ID registers).
     */

    cpu->dtb_compatible = "arm,arm1136";
    set_feature(&cpu->env, ARM_FEATURE_V6);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_DIRTY_REG);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_BLOCK_OPS);
    cpu->midr = 0x4107b362;
    cpu->reset_fpsid = 0x410120b4;
    cpu->isar.mvfr0 = 0x11111111;
    cpu->isar.mvfr1 = 0x00000000;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00050078;
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x1;
    cpu->isar.id_dfr0 = 0x2;
    cpu->id_afr0 = 0x3;
    cpu->isar.id_mmfr0 = 0x01130003;
    cpu->isar.id_mmfr1 = 0x10030302;
    cpu->isar.id_mmfr2 = 0x01222110;
    cpu->isar.id_isar0 = 0x00140011;
    cpu->isar.id_isar1 = 0x12002111;
    cpu->isar.id_isar2 = 0x11231111;
    cpu->isar.id_isar3 = 0x01102131;
    cpu->isar.id_isar4 = 0x141;
    cpu->reset_auxcr = 7;
}

static void arm1136_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm1136";
    set_feature(&cpu->env, ARM_FEATURE_V6K);
    set_feature(&cpu->env, ARM_FEATURE_V6);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_DIRTY_REG);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_BLOCK_OPS);
    cpu->midr = 0x4117b363;
    cpu->reset_fpsid = 0x410120b4;
    cpu->isar.mvfr0 = 0x11111111;
    cpu->isar.mvfr1 = 0x00000000;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00050078;
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x1;
    cpu->isar.id_dfr0 = 0x2;
    cpu->id_afr0 = 0x3;
    cpu->isar.id_mmfr0 = 0x01130003;
    cpu->isar.id_mmfr1 = 0x10030302;
    cpu->isar.id_mmfr2 = 0x01222110;
    cpu->isar.id_isar0 = 0x00140011;
    cpu->isar.id_isar1 = 0x12002111;
    cpu->isar.id_isar2 = 0x11231111;
    cpu->isar.id_isar3 = 0x01102131;
    cpu->isar.id_isar4 = 0x141;
    cpu->reset_auxcr = 7;
}

static void arm1176_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm1176";
    set_feature(&cpu->env, ARM_FEATURE_V6K);
    set_feature(&cpu->env, ARM_FEATURE_VAPA);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_DIRTY_REG);
    set_feature(&cpu->env, ARM_FEATURE_CACHE_BLOCK_OPS);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    cpu->midr = 0x410fb767;
    cpu->reset_fpsid = 0x410120b5;
    cpu->isar.mvfr0 = 0x11111111;
    cpu->isar.mvfr1 = 0x00000000;
    cpu->ctr = 0x1dd20d2;
    cpu->reset_sctlr = 0x00050078;
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x11;
    cpu->isar.id_dfr0 = 0x33;
    cpu->id_afr0 = 0;
    cpu->isar.id_mmfr0 = 0x01130003;
    cpu->isar.id_mmfr1 = 0x10030302;
    cpu->isar.id_mmfr2 = 0x01222100;
    cpu->isar.id_isar0 = 0x0140011;
    cpu->isar.id_isar1 = 0x12002111;
    cpu->isar.id_isar2 = 0x11231121;
    cpu->isar.id_isar3 = 0x01102131;
    cpu->isar.id_isar4 = 0x01141;
    cpu->reset_auxcr = 7;
}

static void arm11mpcore_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,arm11mpcore";
    set_feature(&cpu->env, ARM_FEATURE_V6K);
    set_feature(&cpu->env, ARM_FEATURE_VAPA);
    set_feature(&cpu->env, ARM_FEATURE_MPIDR);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x410fb022;
    cpu->reset_fpsid = 0x410120b4;
    cpu->isar.mvfr0 = 0x11111111;
    cpu->isar.mvfr1 = 0x00000000;
    cpu->ctr = 0x1d192992; /* 32K icache 32K dcache */
    cpu->id_pfr0 = 0x111;
    cpu->id_pfr1 = 0x1;
    cpu->isar.id_dfr0 = 0;
    cpu->id_afr0 = 0x2;
    cpu->isar.id_mmfr0 = 0x01100103;
    cpu->isar.id_mmfr1 = 0x10020302;
    cpu->isar.id_mmfr2 = 0x01222000;
    cpu->isar.id_isar0 = 0x00100011;
    cpu->isar.id_isar1 = 0x12002111;
    cpu->isar.id_isar2 = 0x11221011;
    cpu->isar.id_isar3 = 0x01102131;
    cpu->isar.id_isar4 = 0x141;
    cpu->reset_auxcr = 1;
}

static void cortex_m0_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_V6);
    set_feature(&cpu->env, ARM_FEATURE_M);

    cpu->midr = 0x410cc200;
}

static void cortex_m3_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_M);
    set_feature(&cpu->env, ARM_FEATURE_M_MAIN);
    cpu->midr = 0x410fc231;
    cpu->pmsav7_dregion = 8;
    cpu->id_pfr0 = 0x00000030;
    cpu->id_pfr1 = 0x00000200;
    cpu->isar.id_dfr0 = 0x00100000;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x00000030;
    cpu->isar.id_mmfr1 = 0x00000000;
    cpu->isar.id_mmfr2 = 0x00000000;
    cpu->isar.id_mmfr3 = 0x00000000;
    cpu->isar.id_isar0 = 0x01141110;
    cpu->isar.id_isar1 = 0x02111000;
    cpu->isar.id_isar2 = 0x21112231;
    cpu->isar.id_isar3 = 0x01111110;
    cpu->isar.id_isar4 = 0x01310102;
    cpu->isar.id_isar5 = 0x00000000;
    cpu->isar.id_isar6 = 0x00000000;
}

static void cortex_m4_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_M);
    set_feature(&cpu->env, ARM_FEATURE_M_MAIN);
    set_feature(&cpu->env, ARM_FEATURE_THUMB_DSP);
    cpu->midr = 0x410fc240; /* r0p0 */
    cpu->pmsav7_dregion = 8;
    cpu->isar.mvfr0 = 0x10110021;
    cpu->isar.mvfr1 = 0x11000011;
    cpu->isar.mvfr2 = 0x00000000;
    cpu->id_pfr0 = 0x00000030;
    cpu->id_pfr1 = 0x00000200;
    cpu->isar.id_dfr0 = 0x00100000;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x00000030;
    cpu->isar.id_mmfr1 = 0x00000000;
    cpu->isar.id_mmfr2 = 0x00000000;
    cpu->isar.id_mmfr3 = 0x00000000;
    cpu->isar.id_isar0 = 0x01141110;
    cpu->isar.id_isar1 = 0x02111000;
    cpu->isar.id_isar2 = 0x21112231;
    cpu->isar.id_isar3 = 0x01111110;
    cpu->isar.id_isar4 = 0x01310102;
    cpu->isar.id_isar5 = 0x00000000;
    cpu->isar.id_isar6 = 0x00000000;
}

static void cortex_m7_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_M);
    set_feature(&cpu->env, ARM_FEATURE_M_MAIN);
    set_feature(&cpu->env, ARM_FEATURE_THUMB_DSP);
    cpu->midr = 0x411fc272; /* r1p2 */
    cpu->pmsav7_dregion = 8;
    cpu->isar.mvfr0 = 0x10110221;
    cpu->isar.mvfr1 = 0x12000011;
    cpu->isar.mvfr2 = 0x00000040;
    cpu->id_pfr0 = 0x00000030;
    cpu->id_pfr1 = 0x00000200;
    cpu->isar.id_dfr0 = 0x00100000;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x00100030;
    cpu->isar.id_mmfr1 = 0x00000000;
    cpu->isar.id_mmfr2 = 0x01000000;
    cpu->isar.id_mmfr3 = 0x00000000;
    cpu->isar.id_isar0 = 0x01101110;
    cpu->isar.id_isar1 = 0x02112000;
    cpu->isar.id_isar2 = 0x20232231;
    cpu->isar.id_isar3 = 0x01111131;
    cpu->isar.id_isar4 = 0x01310132;
    cpu->isar.id_isar5 = 0x00000000;
    cpu->isar.id_isar6 = 0x00000000;
}


static void cortex_m33_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    set_feature(&cpu->env, ARM_FEATURE_V8);
    set_feature(&cpu->env, ARM_FEATURE_M);
    set_feature(&cpu->env, ARM_FEATURE_M_MAIN);
    set_feature(&cpu->env, ARM_FEATURE_M_SECURITY);
    set_feature(&cpu->env, ARM_FEATURE_THUMB_DSP);
    cpu->midr = 0x410fd213; /* r0p3 */
    cpu->pmsav7_dregion = 16;
    cpu->sau_sregion = 8;
    cpu->isar.mvfr0 = 0x10110021;
    cpu->isar.mvfr1 = 0x11000011;
    cpu->isar.mvfr2 = 0x00000040;
    cpu->id_pfr0 = 0x00000030;
    cpu->id_pfr1 = 0x00000210;
    cpu->isar.id_dfr0 = 0x00200000;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x00101F40;
    cpu->isar.id_mmfr1 = 0x00000000;
    cpu->isar.id_mmfr2 = 0x01000000;
    cpu->isar.id_mmfr3 = 0x00000000;
    cpu->isar.id_isar0 = 0x01101110;
    cpu->isar.id_isar1 = 0x02212000;
    cpu->isar.id_isar2 = 0x20232232;
    cpu->isar.id_isar3 = 0x01111131;
    cpu->isar.id_isar4 = 0x01310132;
    cpu->isar.id_isar5 = 0x00000000;
    cpu->isar.id_isar6 = 0x00000000;
    cpu->clidr = 0x00000000;
    cpu->ctr = 0x8000c000;
}

static void arm_v7m_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    CPUClass *cc = CPU_CLASS(uc, oc);

#ifndef CONFIG_USER_ONLY
    cc->do_interrupt = arm_v7m_cpu_do_interrupt;
#endif

    cc->cpu_exec_interrupt = arm_v7m_cpu_exec_interrupt;
}

static const ARMCPRegInfo cortexr5_cp_reginfo[] = {
    /* Dummy the TCM region regs for the moment */
    { .name = "ATCM", .cp = 15, .opc1 = 0, .crn = 9, .crm = 1, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_CONST },
    { .name = "BTCM", .cp = 15, .opc1 = 0, .crn = 9, .crm = 1, .opc2 = 1,
      .access = PL1_RW, .type = ARM_CP_CONST },
    { .name = "DCACHE_INVAL", .cp = 15, .opc1 = 0, .crn = 15, .crm = 5,
      .opc2 = 0, .access = PL1_W, .type = ARM_CP_NOP },
    REGINFO_SENTINEL
};

static void cortex_r5_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_V7MP);
    set_feature(&cpu->env, ARM_FEATURE_PMSA);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->midr = 0x411fc153; /* r1p3 */
    cpu->id_pfr0 = 0x0131;
    cpu->id_pfr1 = 0x001;
    cpu->isar.id_dfr0 = 0x010400;
    cpu->id_afr0 = 0x0;
    cpu->isar.id_mmfr0 = 0x0210030;
    cpu->isar.id_mmfr1 = 0x00000000;
    cpu->isar.id_mmfr2 = 0x01200000;
    cpu->isar.id_mmfr3 = 0x0211;
    cpu->isar.id_isar0 = 0x02101111;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232141;
    cpu->isar.id_isar3 = 0x01112131;
    cpu->isar.id_isar4 = 0x0010142;
    cpu->isar.id_isar5 = 0x0;
    cpu->isar.id_isar6 = 0x0;
    cpu->mp_is_up = true;
    cpu->pmsav7_dregion = 16;
    define_arm_cp_regs(cpu, cortexr5_cp_reginfo);
}

static void cortex_r5f_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cortex_r5_initfn(uc, obj, opaque);
    cpu->isar.mvfr0 = 0x10110221;
    cpu->isar.mvfr1 = 0x00000011;
}

static const ARMCPRegInfo cortexa8_cp_reginfo[] = {
    { .name = "L2LOCKDOWN", .cp = 15, .crn = 9, .crm = 0, .opc1 = 1, .opc2 = 0,
      .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    { .name = "L2AUXCR", .cp = 15, .crn = 9, .crm = 0, .opc1 = 1, .opc2 = 2,
      .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    REGINFO_SENTINEL
};

static void cortex_a8_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a8";
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    cpu->midr = 0x410fc080;
    cpu->reset_fpsid = 0x410330c0;
    cpu->isar.mvfr0 = 0x11110222;
    cpu->isar.mvfr1 = 0x00011111;
    cpu->ctr = 0x82048004;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x1031;
    cpu->id_pfr1 = 0x11;
    cpu->isar.id_dfr0 = 0x400;
    cpu->id_afr0 = 0;
    cpu->isar.id_mmfr0 = 0x31100003;
    cpu->isar.id_mmfr1 = 0x20000000;
    cpu->isar.id_mmfr2 = 0x01202000;
    cpu->isar.id_mmfr3 = 0x11;
    cpu->isar.id_isar0 = 0x00101111;
    cpu->isar.id_isar1 = 0x12112111;
    cpu->isar.id_isar2 = 0x21232031;
    cpu->isar.id_isar3 = 0x11112131;
    cpu->isar.id_isar4 = 0x00111142;
    cpu->isar.dbgdidr = 0x15141000;
    cpu->clidr = (1 << 27) | (2 << 24) | 3;
    cpu->ccsidr[0] = 0xe007e01a; /* 16k L1 dcache. */
    cpu->ccsidr[1] = 0x2007e01a; /* 16k L1 icache. */
    cpu->ccsidr[2] = 0xf0000000; /* No L2 icache. */
    cpu->reset_auxcr = 2;
    define_arm_cp_regs(cpu, cortexa8_cp_reginfo);
}

static const ARMCPRegInfo cortexa9_cp_reginfo[] = {
    /* power_control should be set to maximum latency. Again,
     * default to 0 and set by private hook
     */
    { .name = "A9_PWRCTL", .cp = 15, .crn = 15, .crm = 0, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_power_control) },
    { .name = "A9_DIAG", .cp = 15, .crn = 15, .crm = 0, .opc1 = 0, .opc2 = 1,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_diagnostic) },
    { .name = "A9_PWRDIAG", .cp = 15, .crn = 15, .crm = 0, .opc1 = 0, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0,
      .fieldoffset = offsetof(CPUARMState, cp15.c15_power_diagnostic) },
    { .name = "NEONBUSY", .cp = 15, .crn = 15, .crm = 1, .opc1 = 0, .opc2 = 0,
      .access = PL1_RW, .resetvalue = 0, .type = ARM_CP_CONST },
    /* TLB lockdown control */
    { .name = "TLB_LOCKR", .cp = 15, .crn = 15, .crm = 4, .opc1 = 5, .opc2 = 2,
      .access = PL1_W, .resetvalue = 0, .type = ARM_CP_NOP },
    { .name = "TLB_LOCKW", .cp = 15, .crn = 15, .crm = 4, .opc1 = 5, .opc2 = 4,
      .access = PL1_W, .resetvalue = 0, .type = ARM_CP_NOP },
    { .name = "TLB_VA", .cp = 15, .crn = 15, .crm = 5, .opc1 = 5, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0, .type = ARM_CP_CONST },
    { .name = "TLB_PA", .cp = 15, .crn = 15, .crm = 6, .opc1 = 5, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0, .type = ARM_CP_CONST },
    { .name = "TLB_ATTR", .cp = 15, .crn = 15, .crm = 7, .opc1 = 5, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0, .type = ARM_CP_CONST },
    REGINFO_SENTINEL
};

static void cortex_a9_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a9";
    set_feature(&cpu->env, ARM_FEATURE_V7);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    /* Note that A9 supports the MP extensions even for
     * A9UP and single-core A9MP (which are both different
     * and valid configurations; we don't model A9UP).
     */
    set_feature(&cpu->env, ARM_FEATURE_V7MP);
    set_feature(&cpu->env, ARM_FEATURE_CBAR);
    cpu->midr = 0x410fc090;
    cpu->reset_fpsid = 0x41033090;
    cpu->isar.mvfr0 = 0x11110222;
    cpu->isar.mvfr1 = 0x01111111;
    cpu->ctr = 0x80038003;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x1031;
    cpu->id_pfr1 = 0x11;
    cpu->isar.id_dfr0 = 0x000;
    cpu->id_afr0 = 0;
    cpu->isar.id_mmfr0 = 0x00100103;
    cpu->isar.id_mmfr1 = 0x20000000;
    cpu->isar.id_mmfr2 = 0x01230000;
    cpu->isar.id_mmfr3 = 0x00002111;
    cpu->isar.id_isar0 = 0x00101111;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232041;
    cpu->isar.id_isar3 = 0x11112131;
    cpu->isar.id_isar4 = 0x00111142;
    cpu->isar.dbgdidr = 0x35141000;
    cpu->clidr = (1 << 27) | (1 << 24) | 3;
    cpu->ccsidr[0] = 0xe00fe019; /* 16k L1 dcache. */
    cpu->ccsidr[1] = 0x200fe019; /* 16k L1 icache. */
    define_arm_cp_regs(cpu, cortexa9_cp_reginfo);
}

#ifndef CONFIG_USER_ONLY
static uint64_t a15_l2ctlr_read(CPUARMState *env, const ARMCPRegInfo *ri)
{
    /* Linux wants the number of processors from here.
     * Might as well set the interrupt-controller bit too.
     */
    return ((smp_cpus - 1) << 24) | (1 << 23);
}
#endif

static const ARMCPRegInfo cortexa15_cp_reginfo[] = {
#ifndef CONFIG_USER_ONLY
    { .name = "L2CTLR", .cp = 15, .crn = 9, .crm = 0, .opc1 = 1, .opc2 = 2,
      .access = PL1_RW, .resetvalue = 0, .readfn = a15_l2ctlr_read,
      .writefn = arm_cp_write_ignore, },
#endif
    { .name = "L2ECTLR", .cp = 15, .crn = 9, .crm = 0, .opc1 = 1, .opc2 = 3,
      .access = PL1_RW, .type = ARM_CP_CONST, .resetvalue = 0 },
    REGINFO_SENTINEL
};

static void cortex_a7_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a7";
    set_feature(&cpu->env, ARM_FEATURE_V7VE);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->kvm_target = QEMU_KVM_ARM_TARGET_CORTEX_A7;
    cpu->midr = 0x410fc075;
    cpu->reset_fpsid = 0x41023075;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x11111111;
    cpu->ctr = 0x84448003;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x00001131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x02010555;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10101105;
    cpu->isar.id_mmfr1 = 0x40000000;
    cpu->isar.id_mmfr2 = 0x01240000;
    cpu->isar.id_mmfr3 = 0x02102211;
    /* a7_mpcore_r0p5_trm, page 4-4 gives 0x01101110; but
     * table 4-41 gives 0x02101110, which includes the arm div insns.
     */
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232041;
    cpu->isar.id_isar3 = 0x11112131;
    cpu->isar.id_isar4 = 0x10011142;
    cpu->isar.dbgdidr = 0x3515f005;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32K L1 dcache */
    cpu->ccsidr[1] = 0x201fe00a; /* 32K L1 icache */
    cpu->ccsidr[2] = 0x711fe07a; /* 4096K L2 unified cache */
    define_arm_cp_regs(cpu, cortexa15_cp_reginfo); /* Same as A15 */
}

static void cortex_a15_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "arm,cortex-a15";
    set_feature(&cpu->env, ARM_FEATURE_V7VE);
    set_feature(&cpu->env, ARM_FEATURE_NEON);
    set_feature(&cpu->env, ARM_FEATURE_THUMB2EE);
    set_feature(&cpu->env, ARM_FEATURE_GENERIC_TIMER);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    set_feature(&cpu->env, ARM_FEATURE_CBAR_RO);
    set_feature(&cpu->env, ARM_FEATURE_EL2);
    set_feature(&cpu->env, ARM_FEATURE_EL3);
    set_feature(&cpu->env, ARM_FEATURE_PMU);
    cpu->kvm_target = QEMU_KVM_ARM_TARGET_CORTEX_A15;
    cpu->midr = 0x412fc0f1;
    cpu->reset_fpsid = 0x410430f0;
    cpu->isar.mvfr0 = 0x10110222;
    cpu->isar.mvfr1 = 0x11111111;
    cpu->ctr = 0x8444c004;
    cpu->reset_sctlr = 0x00c50078;
    cpu->id_pfr0 = 0x00001131;
    cpu->id_pfr1 = 0x00011011;
    cpu->isar.id_dfr0 = 0x02010555;
    cpu->id_afr0 = 0x00000000;
    cpu->isar.id_mmfr0 = 0x10201105;
    cpu->isar.id_mmfr1 = 0x20000000;
    cpu->isar.id_mmfr2 = 0x01240000;
    cpu->isar.id_mmfr3 = 0x02102211;
    cpu->isar.id_isar0 = 0x02101110;
    cpu->isar.id_isar1 = 0x13112111;
    cpu->isar.id_isar2 = 0x21232041;
    cpu->isar.id_isar3 = 0x11112131;
    cpu->isar.id_isar4 = 0x10011142;
    cpu->isar.dbgdidr = 0x3515f021;
    cpu->clidr = 0x0a200023;
    cpu->ccsidr[0] = 0x701fe00a; /* 32K L1 dcache */
    cpu->ccsidr[1] = 0x201fe00a; /* 32K L1 icache */
    cpu->ccsidr[2] = 0x711fe07a; /* 4096K L2 unified cache */
    define_arm_cp_regs(cpu, cortexa15_cp_reginfo);
}

static void ti925t_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_V4T);
    set_feature(&cpu->env, ARM_FEATURE_OMAPCP);
    cpu->midr = ARM_CPUID_TI925T;
    cpu->ctr = 0x5109149;
    cpu->reset_sctlr = 0x00000070;
}

static void sa1100_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "intel,sa1100";
    set_feature(&cpu->env, ARM_FEATURE_STRONGARM);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x4401A11B;
    cpu->reset_sctlr = 0x00000070;
}

static void sa1110_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);
    set_feature(&cpu->env, ARM_FEATURE_STRONGARM);
    set_feature(&cpu->env, ARM_FEATURE_DUMMY_C15_REGS);
    cpu->midr = 0x6901B119;
    cpu->reset_sctlr = 0x00000070;
}

static void pxa250_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052100;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa255_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052d00;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa260_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052903;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa261_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052d05;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa262_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    cpu->midr = 0x69052d06;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270a0_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054110;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270a1_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054111;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270b0_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054112;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270b1_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054113;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270c0_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054114;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

static void pxa270c5_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cpu->dtb_compatible = "marvell,xscale";
    set_feature(&cpu->env, ARM_FEATURE_V5);
    set_feature(&cpu->env, ARM_FEATURE_XSCALE);
    set_feature(&cpu->env, ARM_FEATURE_IWMMXT);
    cpu->midr = 0x69054117;
    cpu->ctr = 0xd172172;
    cpu->reset_sctlr = 0x00000078;
}

#ifndef TARGET_AARCH64
/* -cpu max: if KVM is enabled, like -cpu host (best possible with this host);
 * otherwise, a CPU with as many features enabled as our emulation supports.
 * The version of '-cpu max' for qemu-system-aarch64 is defined in cpu64.c;
 * this only needs to handle 32 bits.
 */
static void arm_max_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
    ARMCPU *cpu = ARM_CPU(uc, obj);

    cortex_a15_initfn(uc, obj, opaque);

    /* old-style VFP short-vector support */
    cpu->isar.mvfr0 = FIELD_DP32(cpu->isar.mvfr0, MVFR0, FPSHVEC, 1);

    // Unicorn: We lie and enable them anyway.
    /* We don't set these in system emulation mode for the moment,
     * since we don't correctly set (all of) the ID registers to
     * advertise them.
     */
    set_feature(&cpu->env, ARM_FEATURE_V8);
    {
        uint32_t t;

        t = cpu->isar.id_isar5;
        t = FIELD_DP32(t, ID_ISAR5, AES, 2);
        t = FIELD_DP32(t, ID_ISAR5, SHA1, 1);
        t = FIELD_DP32(t, ID_ISAR5, SHA2, 1);
        t = FIELD_DP32(t, ID_ISAR5, CRC32, 1);
        t = FIELD_DP32(t, ID_ISAR5, RDM, 1);
        t = FIELD_DP32(t, ID_ISAR5, VCMA, 1);
        cpu->isar.id_isar5 = t;

        t = cpu->isar.id_isar6;
        t = FIELD_DP32(t, ID_ISAR6, JSCVT, 1);
        t = FIELD_DP32(t, ID_ISAR6, DP, 1);
        t = FIELD_DP32(t, ID_ISAR6, FHM, 1);
        t = FIELD_DP32(t, ID_ISAR6, SB, 1);
        t = FIELD_DP32(t, ID_ISAR6, SPECRES, 1);
        cpu->isar.id_isar6 = t;

        t = cpu->isar.mvfr1;
        t = FIELD_DP32(t, MVFR1, FPHP, 2);     /* v8.0 FP support */
        cpu->isar.mvfr1 = t;

        t = cpu->isar.mvfr2;
        t = FIELD_DP32(t, MVFR2, SIMDMISC, 3); /* SIMD MaxNum */
        t = FIELD_DP32(t, MVFR2, FPMISC, 4);   /* FP MaxNum */
        cpu->isar.mvfr2 = t;

        t = cpu->isar.id_mmfr3;
        t = FIELD_DP32(t, ID_MMFR3, PAN, 2); /* ATS1E1 */
        cpu->isar.id_mmfr3 = t;

        t = cpu->isar.id_mmfr4;
        t = FIELD_DP32(t, ID_MMFR4, HPDS, 1); /* AA32HPD */
        t = FIELD_DP32(t, ID_MMFR4, AC2, 1); /* ACTLR2, HACTLR2 */
        t = FIELD_DP32(t, ID_MMFR4, CNP, 1); /* TTCNP */
        t = FIELD_DP32(t, ID_MMFR4, XNX, 1); /* TTS2UXN */
        cpu->isar.id_mmfr4 = t;
    }
}
#endif

#endif /* !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64) */

static const ARMCPUInfo arm_cpus[] = {
#if !defined(CONFIG_USER_ONLY) || !defined(TARGET_AARCH64)
    { .name = "arm926",      .initfn = arm926_initfn },
    { .name = "arm946",      .initfn = arm946_initfn },
    { .name = "arm1026",     .initfn = arm1026_initfn },
    /*
     * What QEMU calls "arm1136-r2" is actually the 1136 r0p2, i.e. an
     * older core than plain "arm1136". In particular this does not
     * have the v6K features.
     */
    { .name = "arm1136-r2",  .initfn = arm1136_r2_initfn },
    { .name = "arm1136",     .initfn = arm1136_initfn },
    { .name = "arm1176",     .initfn = arm1176_initfn },
    { .name = "arm11mpcore", .initfn = arm11mpcore_initfn },
    { .name = "cortex-m0",   .initfn = cortex_m0_initfn,
                             .class_init = arm_v7m_class_init },
    { .name = "cortex-m3",   .initfn = cortex_m3_initfn,
                             .class_init = arm_v7m_class_init },
    { .name = "cortex-m4",   .initfn = cortex_m4_initfn,
                             .class_init = arm_v7m_class_init },
    { .name = "cortex-m7",   .initfn = cortex_m7_initfn,
                             .class_init = arm_v7m_class_init },
    { .name = "cortex-m33",  .initfn = cortex_m33_initfn,
                             .class_init = arm_v7m_class_init },
    { .name = "cortex-r5",   .initfn = cortex_r5_initfn },
    { .name = "cortex-r5f",  .initfn = cortex_r5f_initfn },
    { .name = "cortex-a7",   .initfn = cortex_a7_initfn },
    { .name = "cortex-a8",   .initfn = cortex_a8_initfn },
    { .name = "cortex-a9",   .initfn = cortex_a9_initfn },
    { .name = "cortex-a15",  .initfn = cortex_a15_initfn },
    { .name = "ti925t",      .initfn = ti925t_initfn },
    { .name = "sa1100",      .initfn = sa1100_initfn },
    { .name = "sa1110",      .initfn = sa1110_initfn },
    { .name = "pxa250",      .initfn = pxa250_initfn },
    { .name = "pxa255",      .initfn = pxa255_initfn },
    { .name = "pxa260",      .initfn = pxa260_initfn },
    { .name = "pxa261",      .initfn = pxa261_initfn },
    { .name = "pxa262",      .initfn = pxa262_initfn },
    /* "pxa270" is an alias for "pxa270-a0" */
    { .name = "pxa270",      .initfn = pxa270a0_initfn },
    { .name = "pxa270-a0",   .initfn = pxa270a0_initfn },
    { .name = "pxa270-a1",   .initfn = pxa270a1_initfn },
    { .name = "pxa270-b0",   .initfn = pxa270b0_initfn },
    { .name = "pxa270-b1",   .initfn = pxa270b1_initfn },
    { .name = "pxa270-c0",   .initfn = pxa270c0_initfn },
    { .name = "pxa270-c5",   .initfn = pxa270c5_initfn },
#ifndef TARGET_AARCH64
    { .name = "max",         .initfn = arm_max_initfn },
#endif
#ifdef CONFIG_USER_ONLY
    { .name = "any",         .initfn = arm_max_initfn },
#endif
#endif
};

static void arm_cpu_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    ARMCPUClass *acc = ARM_CPU_CLASS(uc, oc);
    CPUClass *cc = CPU_CLASS(uc, acc);
    DeviceClass *dc = DEVICE_CLASS(uc, oc);

    acc->parent_realize = dc->realize;
    dc->realize = arm_cpu_realizefn;
    //dc->props = arm_cpu_properties;

    acc->parent_reset = cc->reset;
    cc->reset = arm_cpu_reset;

    cc->class_by_name = arm_cpu_class_by_name;
    cc->has_work = arm_cpu_has_work;
    cc->cpu_exec_interrupt = arm_cpu_exec_interrupt;
    //cc->dump_state = arm_cpu_dump_state;
    cc->set_pc = arm_cpu_set_pc;
    cc->synchronize_from_tb = arm_cpu_synchronize_from_tb;
#ifndef CONFIG_USER_ONLY
    cc->do_interrupt = arm_cpu_do_interrupt;
    cc->get_phys_page_attrs_debug = arm_cpu_get_phys_page_attrs_debug;
    cc->asidx_from_attrs = arm_asidx_from_attrs;
    // UNICORN: Commented out
    //cc->vmsd = &vmstate_arm_cpu;
    //cc->virtio_is_big_endian = arm_cpu_is_big_endian;
#endif
#ifdef CONFIG_TCG
    cc->tcg_initialize = arm_translate_init;
    cc->tlb_fill = arm_cpu_tlb_fill;
    cc->debug_excp_handler = arm_debug_excp_handler;
    cc->debug_check_watchpoint = arm_debug_check_watchpoint;
#if !defined(CONFIG_USER_ONLY)
    cc->do_unaligned_access = arm_cpu_do_unaligned_access;
    cc->do_transaction_failed = arm_cpu_do_transaction_failed;
    cc->adjust_watchpoint_address = arm_adjust_watchpoint_address;
#endif
#endif
}

void arm_cpu_register(struct uc_struct *uc, const ARMCPUInfo *info)
{
    TypeInfo type_info = {
        .parent = TYPE_ARM_CPU,
        .instance_size = sizeof(ARMCPU),
        .instance_init = info->initfn,
        .class_size = sizeof(ARMCPUClass),
        .class_init = info->class_init,
        .class_data = (void *)info,
    };

    type_info.name = g_strdup_printf("%s-" TYPE_ARM_CPU, info->name);
    type_register(uc, &type_info);
    g_free((void *)type_info.name);
}

void arm_cpu_register_types(void *opaque)
{
    const size_t cpu_count = ARRAY_SIZE(arm_cpus);

    TypeInfo arm_cpu_type_info = {0};
    arm_cpu_type_info.name = TYPE_ARM_CPU,
    arm_cpu_type_info.parent = TYPE_CPU,
    arm_cpu_type_info.instance_userdata = opaque,
    arm_cpu_type_info.instance_size = sizeof(ARMCPU),
    arm_cpu_type_info.instance_init = arm_cpu_initfn,
    arm_cpu_type_info.instance_post_init = arm_cpu_post_init,
    arm_cpu_type_info.instance_finalize = arm_cpu_finalizefn,
    arm_cpu_type_info.abstract = true,
    arm_cpu_type_info.class_size = sizeof(ARMCPUClass),
    arm_cpu_type_info.class_init = arm_cpu_class_init,

    type_register(opaque, &arm_cpu_type_info);

    if (cpu_count) {
        size_t i;

        for (i = 0; i < cpu_count; ++i) {
            arm_cpu_register(opaque, &arm_cpus[i]);
        }
    }
}
