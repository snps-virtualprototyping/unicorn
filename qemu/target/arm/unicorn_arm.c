/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "hw/boards.h"
#include "hw/arm/arm.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "unicorn_common.h"
#include "uc_priv.h"

const int ARM_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

static void arm_set_pc(struct uc_struct *uc, uint64_t address)
{
    CPUArchState *state = uc->cpu->env_ptr;

    state->pc = address;
    state->regs[15] = address;
}

void arm_release(void* ctx);

void arm_release(void* ctx)
{
    TCGContext *s = (TCGContext *) ctx;
    struct uc_struct* uc = s->uc;
    ARMCPU* cpu = ARM_CPU(uc, uc->cpu);
    CPUArchState *env = &cpu->env;

    g_free(s->tb_ctx.tbs);
    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);
    g_free(env->pmsav7.drbar);
    g_free(env->pmsav7.drsr);
    g_free(env->pmsav7.dracr);

    release_common(ctx);
}

void arm_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->regs, 0, sizeof(env->regs));

    env->pc = 0;
}

uint32_t helper_v7m_mrs(CPUARMState *env, uint32_t reg);
void helper_v7m_msr(CPUARMState *env, uint32_t maskreg, uint32_t val);

int arm_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    static const uint32_t r13_14_mode_map[] = {
        ARM_CPU_MODE_USR,
        ARM_CPU_MODE_SVC,
        ARM_CPU_MODE_ABT,
        ARM_CPU_MODE_UND,
        ARM_CPU_MODE_IRQ,
        ARM_CPU_MODE_FIQ,
        ARM_CPU_MODE_HYP,
        ARM_CPU_MODE_SVC
    };

    CPUState *mycpu = uc->cpu;
    ARMCPU *cpu = ARM_CPU(uc, mycpu);
    CPUARMState *state = &cpu->env;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        uint32_t* value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12) {
            *(int32_t *)value = state->regs[regid - UC_ARM_REG_R0];
        } else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31) {
            const float64 *d_reg = aa32_vfp_dreg(state, regid - UC_ARM_REG_D0);
            *(float64 *)value = *d_reg;
        } else {
            switch(regid) {
            case UC_ARM_REG_APSR:
                *value = cpsr_read(state) & CPSR_NZCV;
                break;
            case UC_ARM_REG_CPSR:
                *value = cpsr_read(state);
                break;
            //case UC_ARM_REG_SP:
            case UC_ARM_REG_R13:
                *value = state->regs[13];
                break;
            //case UC_ARM_REG_LR:
            case UC_ARM_REG_R14:
                *value = state->regs[14];
                break;
            //case UC_ARM_REG_PC:
            case UC_ARM_REG_R15:
                *value = state->regs[15];
                break;
            case UC_ARM_REG_C1_C0_2:
                *value = state->cp15.cpacr_el1;
                break;
            case UC_ARM_REG_C13_C0_3:
                *value = state->cp15.tpidrro_el[0];
                break;
            case UC_ARM_REG_FPEXC:
                *value = state->vfp.xregs[ARM_VFP_FPEXC];
                break;
            case UC_ARM_REG_FPSCR:
                *value = vfp_get_fpscr(state);
                break;
            case UC_ARM_REG_IPSR:
                *value = xpsr_read(state) & 0x1ff;
                break;
            case UC_ARM_REG_MSP:
                *value = helper_v7m_mrs(state, 8);
                break;
            case UC_ARM_REG_PSP:
                *value = helper_v7m_mrs(state, 9);
                break;
            case UC_ARM_REG_CONTROL:
                *value = helper_v7m_mrs(state, 20);
                break;

            case UC_ARM_REG_R8_USR:
            case UC_ARM_REG_R9_USR:
            case UC_ARM_REG_R10_USR:
            case UC_ARM_REG_R11_USR:
            case UC_ARM_REG_R12_USR: {
                uint32_t mode = state->uncached_cpsr & CPSR_M;
                if (mode == ARM_CPU_MODE_USR || mode == ARM_CPU_MODE_SYS)
                    *value = state->regs[8 + regid - UC_ARM_REG_R8_USR];
                else
                    *value = state->usr_regs[regid - UC_ARM_REG_R8_USR];
                break;
            }

            case UC_ARM_REG_R8_FIQ:
            case UC_ARM_REG_R9_FIQ:
            case UC_ARM_REG_R10_FIQ:
            case UC_ARM_REG_R11_FIQ:
            case UC_ARM_REG_R12_FIQ: {
                uint32_t mode = state->uncached_cpsr & CPSR_M;
                if (mode == ARM_CPU_MODE_FIQ)
                    *value = state->regs[8 + regid - UC_ARM_REG_R8_FIQ];
                else
                    *value = state->fiq_regs[regid - UC_ARM_REG_R8_FIQ];
                break;
            }

            case UC_ARM_REG_R13_USR: {
                uint32_t mode = state->uncached_cpsr & CPSR_M;
                if (mode == ARM_CPU_MODE_USR || mode == ARM_CPU_MODE_SYS)
                    *value = state->regs[13];
                else
                    *value = state->banked_r13[0];
                break;
            }

            case UC_ARM_REG_R13_SVC:
            case UC_ARM_REG_R13_ABT:
            case UC_ARM_REG_R13_UND:
            case UC_ARM_REG_R13_IRQ:
            case UC_ARM_REG_R13_FIQ:
            case UC_ARM_REG_R13_HYP:
            case UC_ARM_REG_R13_MON: {
                uint32_t mode = r13_14_mode_map[regid - UC_ARM_REG_R13_USR];
                if ((state->uncached_cpsr & CPSR_M) == mode)
                    *value = state->regs[13];
                else
                    *value = state->banked_r13[regid - UC_ARM_REG_R13_USR];
                break;
            }

            case UC_ARM_REG_R14_USR: {
                uint32_t mode = state->uncached_cpsr & CPSR_M;
                if (mode == ARM_CPU_MODE_USR || mode == ARM_CPU_MODE_SYS)
                    *value = state->regs[14];
                else
                    *value = state->banked_r14[0];
                break;
            }

            case UC_ARM_REG_R14_SVC:
            case UC_ARM_REG_R14_ABT:
            case UC_ARM_REG_R14_UND:
            case UC_ARM_REG_R14_IRQ:
            case UC_ARM_REG_R14_FIQ:
            case UC_ARM_REG_R14_HYP:
            case UC_ARM_REG_R14_MON: {
                uint32_t mode = r13_14_mode_map[regid - UC_ARM_REG_R14_USR];
                if ((state->uncached_cpsr & CPSR_M) == mode)
                    *value = state->regs[14];
                else
                    *value = state->banked_r14[regid - UC_ARM_REG_R14_USR];
                break;
            }

            case UC_ARM_REG_SPSR_USR:
            case UC_ARM_REG_SPSR_SVC:
            case UC_ARM_REG_SPSR_ABT:
            case UC_ARM_REG_SPSR_UND:
            case UC_ARM_REG_SPSR_IRQ:
            case UC_ARM_REG_SPSR_FIQ:
            case UC_ARM_REG_SPSR_HYP:
            case UC_ARM_REG_SPSR_MON:
                *value = state->banked_spsr[regid - UC_ARM_REG_SPSR_USR];
                break;

            case UC_ARM_REG_SCR:
                *value = state->cp15.scr_el3;
                break;

            case UC_ARM_REG_VBAR:
                if (arm_is_secure(state))
                    *value = state->cp15.vbar_s;
                else
                    *value = state->cp15.vbar_ns;
                break;

            case UC_ARM_REG_VBAR_S:
                *value = state->cp15.vbar_s;
                break;

            case UC_ARM_REG_VBAR_NS:
                *value = state->cp15.vbar_ns;
                break;

            case UC_ARM_REG_DACR:
                if (arm_is_secure(state))
                    *value = state->cp15.dacr_s;
                else
                    *value = state->cp15.dacr_ns;
                break;

            case UC_ARM_REG_DACR_S:
                *value = state->cp15.dacr_s;
                break;

            case UC_ARM_REG_DACR_NS:
                *value = state->cp15.dacr_ns;
                break;

            case UC_ARM_REG_SCTLR:
                if (arm_is_secure(state))
                    *value = state->cp15.sctlr_s;
                else
                    *value = state->cp15.sctlr_ns;
                break;

            case UC_ARM_REG_SCTLR_S:
                *value = state->cp15.sctlr_s;
                break;

            case UC_ARM_REG_SCTLR_NS:
                *value = state->cp15.sctlr_ns;
                break;

            case UC_ARM_REG_FCSEIDR:
                if (arm_is_secure(state))
                    *value = state->cp15.fcseidr_s;
                else
                    *value = state->cp15.fcseidr_ns;
                break;

            case UC_ARM_REG_FCSEIDR_S:
                *value = state->cp15.fcseidr_s;
                break;

            case UC_ARM_REG_FCSEIDR_NS:
                *value = state->cp15.fcseidr_ns;
                break;

            case UC_ARM_REG_CONTEXTIDR:
                if (arm_is_secure(state))
                    *value = state->cp15.contextidr_s;
                else
                    *value = state->cp15.contextidr_ns;
                break;

            case UC_ARM_REG_CONTEXTIDR_S:
                *value = state->cp15.contextidr_s;
                break;

            case UC_ARM_REG_CONTEXTIDR_NS:
                *value = state->cp15.contextidr_ns;
                break;

            case UC_ARM_REG_TTBR0:
                if (arm_is_secure(state))
                    *value = state->cp15.ttbr0_s;
                else
                    *value = state->cp15.ttbr0_ns;
                break;

            case UC_ARM_REG_TTBR0_S:
                *value = state->cp15.ttbr0_s;
                break;

            case UC_ARM_REG_TTBR0_NS:
                *value = state->cp15.ttbr0_ns;
                break;

            case UC_ARM_REG_TTBR1:
                if (arm_is_secure(state))
                    *value = state->cp15.ttbr1_s;
                else
                    *value = state->cp15.ttbr1_ns;
                break;

            case UC_ARM_REG_TTBR1_S:
                *value = state->cp15.ttbr1_s;
                break;

            case UC_ARM_REG_TTBR1_NS:
                *value = state->cp15.ttbr1_ns;
                break;

            case UC_ARM_REG_TTBCR:
                *value = state->cp15.tcr_el[arm_is_secure(state) ? 3 : 1].raw_tcr;
                break;

            case UC_ARM_REG_TTBCR_S:
                *value = state->cp15.tcr_el[3].raw_tcr;
                break;

            case UC_ARM_REG_TTBCR_NS:
                *value = state->cp15.tcr_el[1].raw_tcr;
                break;

            case UC_ARM_REG_PRRR:
                if (arm_is_secure(state))
                    *value = state->cp15.mair0_s;
                else
                    *value = state->cp15.mair0_ns;
                break;

            case UC_ARM_REG_PRRR_S:
                *value = state->cp15.mair0_s;
                break;

            case UC_ARM_REG_PRRR_NS:
                *value = state->cp15.mair0_ns;
                break;

            case UC_ARM_REG_NMRR:
                if (arm_is_secure(state))
                    *value = state->cp15.mair1_s;
                else
                    *value = state->cp15.mair1_ns;
                break;

            case UC_ARM_REG_NMRR_S:
                *value = state->cp15.mair1_s;
                break;

            case UC_ARM_REG_NMRR_NS:
                *value = state->cp15.mair1_ns;
                break;

            case UC_ARM_REG_DBGDSCREXT:
                *value = state->cp15.mdscr_el1;
                break;

            case UC_ARM_REG_MPIDR:
                *value = cpu->mp_affinity & 0xfff;
                break;

            case UC_ARM_VREG_AA64:
                *value = state->aarch64;
                break;

            case UC_ARM_VREG_THUMB:
                *value = state->thumb;
                break;

            case UC_ARM_REG_NOIMP:
                *value = 0xeeeeeeee;
                break;

            default:
                return -1;
            }
        }
    }

    return 0;
}

int arm_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    ARMCPU *cpu = ARM_CPU(uc, mycpu);
    CPUARMState *state = &cpu->env;
    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];
        if (regid >= UC_ARM_REG_R0 && regid <= UC_ARM_REG_R12) {
            state->regs[regid - UC_ARM_REG_R0] = *(uint32_t *)value;
        } else if (regid >= UC_ARM_REG_D0 && regid <= UC_ARM_REG_D31) {
            float64 *d_reg = aa32_vfp_dreg(state, regid - UC_ARM_REG_D0);
            *d_reg = *(float64 *)value;
        } else {
            switch(regid) {
            case UC_ARM_REG_APSR:
                cpsr_write(state, *(uint32_t *)value, CPSR_NZCV, CPSRWriteRaw);
                break;
            case UC_ARM_REG_CPSR:
                cpsr_write(state, *(uint32_t *)value, ~0, CPSRWriteRaw);
                break;
            //case UC_ARM_REG_SP:
            case UC_ARM_REG_R13:
                state->regs[13] = *(uint32_t *)value;
                break;
            //case UC_ARM_REG_LR:
            case UC_ARM_REG_R14:
                state->regs[14] = *(uint32_t *)value;
                break;
            //case UC_ARM_REG_PC:
            case UC_ARM_REG_R15:
                state->pc = (*(uint32_t *)value & ~1);
                state->thumb = (*(uint32_t *)value & 1);
                //state->uc->thumb = (*(uint32_t *)value & 1);
                state->regs[15] = (*(uint32_t *)value & ~1);
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);

                break;
            case UC_ARM_REG_C1_C0_2:
                state->cp15.cpacr_el1 = *(int32_t *)value;
                break;

            case UC_ARM_REG_C13_C0_3:
                state->cp15.tpidrro_el[0] = *(int32_t *)value;
                break;
            case UC_ARM_REG_FPEXC:
                state->vfp.xregs[ARM_VFP_FPEXC] = *(int32_t *)value;
                break;
            case UC_ARM_REG_FPSCR:
                vfp_set_fpscr(state, *(uint32_t *)value);
                break;
            case UC_ARM_REG_IPSR:
                xpsr_write(state, *(uint32_t *)value, 0x1ff);
                break;
            case UC_ARM_REG_MSP:
                helper_v7m_msr(state, 8, *(uint32_t *)value);
                break;
            case UC_ARM_REG_PSP:
                helper_v7m_msr(state, 9, *(uint32_t *)value);
                break;
            case UC_ARM_REG_CONTROL:
                helper_v7m_msr(state, 20, *(uint32_t *)value);
                break;
            case UC_ARM_REG_R8_USR:
            case UC_ARM_REG_R9_USR:
            case UC_ARM_REG_R10_USR:
            case UC_ARM_REG_R11_USR:
            case UC_ARM_REG_R12_USR:
                state->usr_regs[regid - UC_ARM_REG_R8_USR] = *(uint32_t *)value;
                break;

            case UC_ARM_REG_R8_FIQ:
            case UC_ARM_REG_R9_FIQ:
            case UC_ARM_REG_R10_FIQ:
            case UC_ARM_REG_R11_FIQ:
            case UC_ARM_REG_R12_FIQ:
                state->fiq_regs[regid - UC_ARM_REG_R8_FIQ] = *(uint32_t *)value;
                break;

            case UC_ARM_REG_R13_USR:
            case UC_ARM_REG_R13_SVC:
            case UC_ARM_REG_R13_ABT:
            case UC_ARM_REG_R13_UND:
            case UC_ARM_REG_R13_IRQ:
            case UC_ARM_REG_R13_FIQ:
            case UC_ARM_REG_R13_HYP:
            case UC_ARM_REG_R13_MON:
                state->banked_r13[regid - UC_ARM_REG_R13_USR] = *(uint32_t *)value;
                break;

            case UC_ARM_REG_R14_USR:
            case UC_ARM_REG_R14_SVC:
            case UC_ARM_REG_R14_ABT:
            case UC_ARM_REG_R14_UND:
            case UC_ARM_REG_R14_IRQ:
            case UC_ARM_REG_R14_FIQ:
            case UC_ARM_REG_R14_HYP:
            case UC_ARM_REG_R14_MON:
                state->banked_r14[regid - UC_ARM_REG_R14_USR] = *(uint32_t *)value;
                break;

            case UC_ARM_REG_SPSR_USR:
            case UC_ARM_REG_SPSR_SVC:
            case UC_ARM_REG_SPSR_ABT:
            case UC_ARM_REG_SPSR_UND:
            case UC_ARM_REG_SPSR_IRQ:
            case UC_ARM_REG_SPSR_FIQ:
            case UC_ARM_REG_SPSR_HYP:
            case UC_ARM_REG_SPSR_MON:
                state->banked_spsr[regid - UC_ARM_REG_SPSR_USR] = *(uint32_t *)value;
                break;

            case UC_ARM_REG_SCR:
                state->cp15.scr_el3 = *(uint32_t *)value;
                break;

            case UC_ARM_REG_VBAR_NS:
                state->cp15.vbar_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_VBAR_S:
                state->cp15.vbar_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_DACR:
                if (arm_is_secure(state))
                    state->cp15.dacr_s = *(uint32_t *)value;
                else
                    state->cp15.dacr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_DACR_S:
                state->cp15.dacr_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_DACR_NS:
                state->cp15.dacr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_SCTLR:
                if (arm_is_secure(state))
                    state->cp15.sctlr_s = *(uint32_t *)value;
                else
                    state->cp15.sctlr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_SCTLR_S:
                state->cp15.sctlr_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_SCTLR_NS:
                state->cp15.sctlr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_FCSEIDR:
                if (arm_is_secure(state))
                    state->cp15.fcseidr_s = *(uint32_t *)value;
                else
                    state->cp15.fcseidr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_FCSEIDR_S:
                state->cp15.fcseidr_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_FCSEIDR_NS:
                state->cp15.fcseidr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_CONTEXTIDR:
                if (arm_is_secure(state))
                    state->cp15.contextidr_s = *(uint32_t *)value;
                else
                    state->cp15.contextidr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_CONTEXTIDR_S:
                state->cp15.contextidr_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_CONTEXTIDR_NS:
                state->cp15.contextidr_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBR0:
                if (arm_is_secure(state))
                    state->cp15.ttbr0_s = *(uint32_t *)value;
                else
                    state->cp15.ttbr0_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBR0_S:
                state->cp15.ttbr0_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBR0_NS:
                state->cp15.ttbr0_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBR1:
                if (arm_is_secure(state))
                    state->cp15.ttbr1_s = *(uint32_t *)value;
                else
                    state->cp15.ttbr1_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBR1_S:
                state->cp15.ttbr1_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBR1_NS:
                state->cp15.ttbr1_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBCR:
                state->cp15.tcr_el[arm_is_secure(state) ? 3 : 1].raw_tcr = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBCR_S:
                state->cp15.tcr_el[3].raw_tcr = *(uint32_t *)value;
                break;

            case UC_ARM_REG_TTBCR_NS:
                state->cp15.tcr_el[1].raw_tcr = *(uint32_t *)value;
                break;

            case UC_ARM_REG_PRRR:
                if (arm_is_secure(state))
                    state->cp15.mair0_s = *(uint32_t *)value;
                else
                    state->cp15.mair0_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_PRRR_S:
                state->cp15.mair0_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_PRRR_NS:
               state->cp15.mair0_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_NMRR:
                if (arm_is_secure(state))
                    state->cp15.mair1_s = *(uint32_t *)value;
                else
                    state->cp15.mair1_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_NMRR_S:
                state->cp15.mair1_s = *(uint32_t *)value;
                break;

            case UC_ARM_REG_NMRR_NS:
                state->cp15.mair1_ns = *(uint32_t *)value;
                break;

            case UC_ARM_REG_DBGDSCREXT:
                state->cp15.mdscr_el1 = *(uint32_t *)value;
                break;

            case UC_ARM_REG_MPIDR:
                cpu->mp_affinity = *(uint32_t *)value & 0xfff;
                break;

            case UC_ARM_REG_NOIMP:
            default:
                return -1;
            }
        }
    }

    return 0;
}

#ifdef jhw
static bool arm_stop_interrupt(int intno)
{
    switch(intno) {
        default:
            return false;
        case EXCP_UDEF:
        case EXCP_YIELD:
            return true;
    }
}
#endif

static uc_err arm_query(struct uc_struct *uc, uc_query_type type, size_t *result)
{
    CPUState *mycpu = uc->cpu;
    CPUARMState *state = &ARM_CPU(uc, mycpu)->env;
    uint32_t mode;

    switch(type) {
        case UC_QUERY_MODE:
            // zero out ARM/THUMB mode
            mode = uc->mode & ~(UC_MODE_ARM | UC_MODE_THUMB);
            // THUMB mode or ARM MOde
            mode += ((state->thumb != 0) ? UC_MODE_THUMB : UC_MODE_ARM);
            *result = mode;
            return UC_ERR_OK;
        default:
            return UC_ERR_ARG;
    }
}

// JHW
void arm_timer_recalc(CPUState *cpu, int timeridx);

void arm_timer_recalc(CPUState *cpu, int timeridx)
{
    switch (timeridx) {
    case GTIMER_PHYS:
        arm_gt_ptimer_cb(ARM_CPU(cpu->uc, cpu));
        break;

    case GTIMER_VIRT:
        arm_gt_vtimer_cb(ARM_CPU(cpu->uc, cpu));
        break;

    case GTIMER_HYP:
        arm_gt_htimer_cb(ARM_CPU(cpu->uc, cpu));
        break;

    case GTIMER_SEC:
        arm_gt_stimer_cb(ARM_CPU(cpu->uc, cpu));
        break;

    default:
        assert(0 && "invalid timer index");
    }

}

#ifdef TARGET_WORDS_BIGENDIAN
void armeb_uc_init(struct uc_struct* uc)
#else
void arm_uc_init(struct uc_struct* uc)
#endif
{
    register_accel_types(uc);
    arm_cpu_register_types(uc);
    //tosa_machine_init_register_types(uc);
    machvirt_machine_init(uc);
    uc->reg_read = arm_reg_read;
    uc->reg_write = arm_reg_write;
    uc->reg_reset = arm_reg_reset;
    uc->set_pc = arm_set_pc;
    //uc->stop_interrupt = arm_stop_interrupt; // jhw
    uc->release = arm_release;
    uc->query = arm_query;
    uc_common_init(uc);

    uc->timer_recalc = arm_timer_recalc;
}
