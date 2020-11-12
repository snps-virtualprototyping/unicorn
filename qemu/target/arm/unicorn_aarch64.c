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

const int ARM64_REGS_STORAGE_SIZE = offsetof(CPUARMState, tlb_table);

static void arm64_set_pc(struct uc_struct *uc, uint64_t address)
{
    CPUArchState *state = uc->cpu->env_ptr;

    if (uc->is_memcb) { // SNPS added
        fprintf(stderr, "cannot set PC during memory callback\n");
        abort();
    }

    state->pc = address;
}

void arm64_release(void* ctx);

void arm64_release(void* ctx)
{
    TCGContext *s = (TCGContext *) ctx;
    struct uc_struct* uc = s->uc;
    ARMCPU* cpu = ARM_CPU(uc, uc->cpu);

    g_free(s->tb_ctx.tbs);
    g_free(cpu->cpreg_indexes);
    g_free(cpu->cpreg_values);
    g_free(cpu->cpreg_vmstate_indexes);
    g_free(cpu->cpreg_vmstate_values);

    release_common(ctx);
}

void arm64_reg_reset(struct uc_struct *uc)
{
    CPUArchState *env = uc->cpu->env_ptr;
    memset(env->xregs, 0, sizeof(env->xregs));

    env->pc = 0;
}

// SNPS added
#ifdef UNICORN_HAS_ARM
// defined in unicorn_arm.c
int arm_reg_read_arm(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
int arm_reg_write_arm(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count);
#endif

static uint64_t calc_pc_offset(struct uc_struct *uc, CPUARMState *state) {
    if (!uc->is_memcb)
        return 0;

    if (!state->aarch64 && state->thumb)
        return 2;

    return 4;
}

int arm64_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count)
{
    CPUState *mycpu = uc->cpu;
    ARMCPU *cpu = ARM_CPU(uc, mycpu);
    CPUARMState *state = &cpu->env;

    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        void *value = vals[i];

#ifdef UNICORN_HAS_ARM // SNPS added
        if (regid < UC_ARM64_REG_INVALID) {
            int res = arm_reg_read_arm(uc, &regid, &value, 1);
            if (res != 0)
                return res;
            continue;
        }
#endif

        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            *(int64_t *)value = state->xregs[regid - UC_ARM64_REG_X0];
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            *(int32_t *)value = READ_DWORD(state->xregs[regid - UC_ARM64_REG_W0]);
            // V & Q registers are the same
        } else if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            const float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_V0);
            memcpy(value, q_reg, 8);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            const float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_Q0);
            memcpy(value, q_reg, 16);
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            const float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_D0);
            *(float64*)value = *q_reg;
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            const float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_S0);
            *(int32_t*)value = READ_DWORD(*q_reg);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            const float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_H0);
            *(int16_t*)value = READ_WORD(*q_reg);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            const float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_B0);
            *(int8_t*)value = READ_BYTE_L(*q_reg);
        } else {
            switch(regid) {
            case UC_ARM64_REG_CPACR_EL1:
                *(uint32_t *)value = state->cp15.cpacr_el1;
                break;
            case UC_ARM64_REG_ESR:
                *(uint32_t *)value = state->exception.syndrome;
                break;
            case UC_ARM64_REG_X29:
                *(int64_t *)value = state->xregs[29];
                break;
            case UC_ARM64_REG_X30:
                *(int64_t *)value = state->xregs[30];
                break;
            case UC_ARM64_REG_PC:
                *(uint64_t *)value = state->pc - calc_pc_offset(uc, state);
                break;
            case UC_ARM64_REG_SP:
                *(int64_t *)value = state->xregs[31];
                break;
            case UC_ARM64_REG_NZCV:
                *(int32_t *)value = cpsr_read(state) & CPSR_NZCV;
                break;
            case UC_ARM64_REG_PSTATE:
                *(uint32_t *)value = pstate_read(state);
                break;
            case UC_ARM64_REG_FPCR:
                *(uint32_t *)value = vfp_get_fpcr(state);
                break;
            case UC_ARM64_REG_FPSR:
                *(uint32_t *)value = vfp_get_fpsr(state);
                break;
            case UC_ARM64_REG_FPEXC:
                *(int32_t *)value = state->vfp.xregs[ARM_VFP_FPEXC];
                break;
            case UC_ARM64_REG_MIDR:
                *(uint32_t *)value = cpu->midr;
                break;
            case UC_ARM64_REG_MPIDR:
                *(uint64_t *)value = cpu->mp_affinity;
                break;
            case UC_ARM64_REG_VPIDR:
                *(uint64_t *)value = state->cp15.vpidr_el2;
                break;
            case UC_ARM64_REG_VMPIDR:
                *(uint64_t *)value = state->cp15.vmpidr_el2;
                break;
            case UC_ARM64_REG_RVBAR:
                *(uint64_t *)value = cpu->rvbar;
                break;
            case UC_ARM64_VREG_AA64:
                *(uint32_t *)value = state->aarch64;
                break;
            case UC_ARM64_VREG_THUMB:
                *(uint32_t *)value = state->thumb;
                break;
            case UC_ARM64_REG_NOIMP:
                *(uint32_t *)value = 0xeeeeeeee;
                break;

            case UC_ARM64_REG_SP_EL0:
            case UC_ARM64_REG_SP_EL1:
            case UC_ARM64_REG_SP_EL2:
            case UC_ARM64_REG_SP_EL3:
                *(uint64_t *)value = state->sp_el[regid - UC_ARM64_REG_SP_EL0];
                break;

            case UC_ARM64_REG_ELR_EL0:
            case UC_ARM64_REG_ELR_EL1:
            case UC_ARM64_REG_ELR_EL2:
            case UC_ARM64_REG_ELR_EL3:
                *(uint64_t *)value = state->elr_el[regid - UC_ARM64_REG_ELR_EL0];
                break;

            case UC_ARM64_REG_SPSR_EL1:
            case UC_ARM64_REG_SPSR_EL2:
            case UC_ARM64_REG_SPSR_EL3: {
                static const unsigned int map[] = { 0, 6, 7 };
                *(uint64_t*)value = state->banked_spsr[map[regid - UC_ARM64_REG_SPSR_EL1]];
                break;
            }

            case UC_ARM64_REG_SCTLR_EL1:
            case UC_ARM64_REG_SCTLR_EL2:
            case UC_ARM64_REG_SCTLR_EL3:
                *(uint64_t*)value = state->cp15.sctlr_el[1 + regid - UC_ARM64_REG_SCTLR_EL1];
                break;

            case UC_ARM64_REG_VBAR_EL1:
            case UC_ARM64_REG_VBAR_EL2:
            case UC_ARM64_REG_VBAR_EL3:
                *(uint64_t*)value = state->cp15.vbar_el[1 + regid - UC_ARM64_REG_VBAR_EL1];
                break;

            case UC_ARM64_REG_MAIR_EL1:
            case UC_ARM64_REG_MAIR_EL2:
            case UC_ARM64_REG_MAIR_EL3:
                *(uint64_t*)value = state->cp15.mair_el[1 + regid - UC_ARM64_REG_MAIR_EL1];
                break;

            case UC_ARM64_REG_TCR_EL1:
            case UC_ARM64_REG_TCR_EL2:
            case UC_ARM64_REG_TCR_EL3:
                *(uint64_t*)value = state->cp15.tcr_el[1 + regid - UC_ARM64_REG_TCR_EL1].raw_tcr;
                break;

            case UC_ARM64_REG_TTBR0_EL1:
            case UC_ARM64_REG_TTBR0_EL2:
            case UC_ARM64_REG_TTBR0_EL3:
                *(uint64_t*)value = state->cp15.ttbr0_el[1 + regid - UC_ARM64_REG_TTBR0_EL1];
                break;

            case UC_ARM64_REG_TTBR1_EL1:
            case UC_ARM64_REG_TTBR1_EL2:
            case UC_ARM64_REG_TTBR1_EL3:
                *(uint64_t*)value = state->cp15.ttbr1_el[1 + regid - UC_ARM64_REG_TTBR1_EL1];
                break;

            case UC_ARM64_REG_TPIDR_EL0:
            case UC_ARM64_REG_TPIDR_EL1:
            case UC_ARM64_REG_TPIDR_EL2:
            case UC_ARM64_REG_TPIDR_EL3:
                *(uint64_t*)value = state->cp15.tpidr_el[regid - UC_ARM64_REG_TPIDR_EL0];
                break;

            case UC_ARM64_REG_TPIDRRO_EL0:
                *(int64_t *)value = state->cp15.tpidrro_el[0];
                break;

            case UC_ARM64_REG_VTTBR_EL2:
                *(uint64_t*)value = state->cp15.vttbr_el2;
                break;

            case UC_ARM64_REG_VTCR_EL2:
                *(uint64_t*)value = state->cp15.vtcr_el2.raw_tcr;
                break;

            case UC_ARM64_REG_DACR_S:
                *(uint64_t*)value = state->cp15.dacr_s;
                break;

            case UC_ARM64_REG_DACR_NS:
                *(uint64_t*)value = state->cp15.dacr_ns;
                break;

            case UC_ARM64_REG_DACR32:
                *(uint64_t*)value = state->cp15.dacr32_el2;
                break;

            case UC_ARM64_REG_HCR_EL2:
                *(uint64_t*)value = state->cp15.hcr_el2;
                break;

            case UC_ARM64_REG_SCR_EL3:
                *(uint64_t*)value = state->cp15.scr_el3;
                break;

            case UC_ARM64_REG_MDSCR_EL1:
                *(uint32_t*)value = state->cp15.mdscr_el1;
                break;

            default:
                return -1;
            }
        }
    }

    return 0;
}

int arm64_reg_write(struct uc_struct *uc, unsigned int *regs, void* const* vals, int count)
{
    CPUState *mycpu = uc->cpu;
    ARMCPU *cpu = ARM_CPU(uc, mycpu);
    CPUARMState *state = &cpu->env;

    int i;

    for (i = 0; i < count; i++) {
        unsigned int regid = regs[i];
        const void *value = vals[i];

#ifdef UNICORN_HAS_ARM
        if (regid < UC_ARM64_REG_INVALID) {
            int res = arm_reg_write_arm(uc, &regid, (void* const*)&value, 1);
            if (res != 0)
                return res;
            continue;
        }
#endif

        if (regid >= UC_ARM64_REG_X0 && regid <= UC_ARM64_REG_X28) {
            state->xregs[regid - UC_ARM64_REG_X0] = *(uint64_t *)value;
        } else if (regid >= UC_ARM64_REG_W0 && regid <= UC_ARM64_REG_W30) {
            WRITE_DWORD(state->xregs[regid - UC_ARM64_REG_W0], *(uint32_t *)value);
        } else if (regid >= UC_ARM64_REG_V0 && regid <= UC_ARM64_REG_V31) {
            float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_V0);
            memcpy(q_reg, value, 8);
        } else if (regid >= UC_ARM64_REG_Q0 && regid <= UC_ARM64_REG_Q31) {
            float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_Q0);
            memcpy(q_reg, value, 16);
        } else if (regid >= UC_ARM64_REG_D0 && regid <= UC_ARM64_REG_D31) {
            float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_D0);
            *q_reg = *(float64*) value;
        } else if (regid >= UC_ARM64_REG_S0 && regid <= UC_ARM64_REG_S31) {
            float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_S0);
            WRITE_DWORD(*q_reg, *(int32_t*) value);
        } else if (regid >= UC_ARM64_REG_H0 && regid <= UC_ARM64_REG_H31) {
            float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_H0);
            WRITE_WORD(*q_reg, *(int16_t*) value);
        } else if (regid >= UC_ARM64_REG_B0 && regid <= UC_ARM64_REG_B31) {
            float64 *q_reg = aa64_vfp_qreg(state, regid - UC_ARM64_REG_B0);
            WRITE_BYTE_L(*q_reg, *(int8_t*) value);
        } else {
            switch(regid) {
            case UC_ARM64_REG_CPACR_EL1:
                state->cp15.cpacr_el1 = *(uint32_t *)value;
                break;
            case UC_ARM64_REG_X29:
                state->xregs[29] = *(uint64_t *)value;
                break;
            case UC_ARM64_REG_X30:
                state->xregs[30] = *(uint64_t *)value;
                break;
            case UC_ARM64_REG_PC:
                if (uc->is_memcb) {
                    fprintf(stderr, "cannot set PC during memory callback\n");
                    abort();
                }

                state->pc = *(uint64_t *)value;
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);
                break;
            case UC_ARM64_REG_SP:
                state->xregs[31] = *(uint64_t *)value;
                break;
            case UC_ARM64_REG_NZCV:
                cpsr_write(state, *(uint32_t *) value, CPSR_NZCV, CPSRWriteRaw);
                break;
            case UC_ARM64_REG_PSTATE:
                pstate_write(state, *(uint32_t *)value);
                break;
            case UC_ARM64_REG_FPCR:
                vfp_set_fpcr(state, *(uint32_t *)value);
                break;
            case UC_ARM64_REG_FPSR:
                vfp_set_fpsr(state, *(uint32_t *)value);
                break;
            case UC_ARM64_REG_FPEXC:
                state->vfp.xregs[ARM_VFP_FPEXC] = *(int32_t *)value;
                break;
            case UC_ARM64_REG_MIDR:
                cpu->midr = *(uint32_t*)value;
                break;
            case UC_ARM64_REG_MPIDR:
                cpu->mp_affinity = *(uint64_t*)value | (1ull << 31);
                cpu->mp_affinity &= 0xffc1fffffull;
                break;
            case UC_ARM64_REG_VPIDR:
                state->cp15.vpidr_el2 = *(uint64_t*)value & 0xffffffffull;
                break;
            case UC_ARM64_REG_VMPIDR:
                state->cp15.vmpidr_el2 = *(uint64_t*)value | (1ull << 31);
                state->cp15.vmpidr_el2 &= 0xffc1fffffull;
                break;
            case UC_ARM64_REG_RVBAR:
                cpu->rvbar = *(uint64_t*)value;
                state->cp15.vbar_el[0] = cpu->rvbar;
                state->cp15.vbar_el[1] = cpu->rvbar;
                state->cp15.vbar_el[2] = cpu->rvbar;
                state->cp15.vbar_el[3] = cpu->rvbar;
                break;

            case UC_ARM64_REG_SP_EL0:
            case UC_ARM64_REG_SP_EL1:
            case UC_ARM64_REG_SP_EL2:
            case UC_ARM64_REG_SP_EL3:
                 state->sp_el[regid - UC_ARM64_REG_SP_EL0] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_ELR_EL0:
            case UC_ARM64_REG_ELR_EL1:
            case UC_ARM64_REG_ELR_EL2:
            case UC_ARM64_REG_ELR_EL3:
                state->elr_el[regid - UC_ARM64_REG_ELR_EL0] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_SPSR_EL1:
            case UC_ARM64_REG_SPSR_EL2:
            case UC_ARM64_REG_SPSR_EL3: {
                static const unsigned int map[] = { 0, 6, 7 };
                state->banked_spsr[map[regid - UC_ARM64_REG_SPSR_EL1]] = *(uint64_t*)value;
                break;
            }

            case UC_ARM64_REG_SCTLR_EL1:
            case UC_ARM64_REG_SCTLR_EL2:
            case UC_ARM64_REG_SCTLR_EL3:
                state->cp15.sctlr_el[1 + regid - UC_ARM64_REG_SCTLR_EL1] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_VBAR_EL1:
            case UC_ARM64_REG_VBAR_EL2:
            case UC_ARM64_REG_VBAR_EL3:
                state->cp15.vbar_el[1 + regid - UC_ARM64_REG_VBAR_EL1] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_MAIR_EL1:
            case UC_ARM64_REG_MAIR_EL2:
            case UC_ARM64_REG_MAIR_EL3:
                state->cp15.mair_el[1 + regid - UC_ARM64_REG_MAIR_EL1] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_TCR_EL1:
            case UC_ARM64_REG_TCR_EL2:
            case UC_ARM64_REG_TCR_EL3:
                state->cp15.tcr_el[1 + regid - UC_ARM64_REG_TCR_EL1].raw_tcr = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_TTBR0_EL1:
            case UC_ARM64_REG_TTBR0_EL2:
            case UC_ARM64_REG_TTBR0_EL3:
                state->cp15.ttbr0_el[1 + regid - UC_ARM64_REG_TTBR0_EL1] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_TTBR1_EL1:
            case UC_ARM64_REG_TTBR1_EL2:
            case UC_ARM64_REG_TTBR1_EL3:
                state->cp15.ttbr1_el[1 + regid - UC_ARM64_REG_TTBR1_EL1] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_TPIDR_EL0:
            case UC_ARM64_REG_TPIDR_EL1:
            case UC_ARM64_REG_TPIDR_EL2:
            case UC_ARM64_REG_TPIDR_EL3:
                state->cp15.tpidr_el[regid - UC_ARM64_REG_TPIDR_EL0] = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_TPIDRRO_EL0:
                state->cp15.tpidrro_el[0] = *(uint64_t *)value;
                break;

            case UC_ARM64_REG_VTTBR_EL2:
                state->cp15.vttbr_el2 = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_VTCR_EL2:
                state->cp15.vtcr_el2.raw_tcr = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_DACR_S:
                state->cp15.dacr_s = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_DACR_NS:
                state->cp15.dacr_ns = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_DACR32:
                state->cp15.dacr32_el2 = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_HCR_EL2:
                state->cp15.hcr_el2 = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_SCR_EL3:
                state->cp15.scr_el3 = *(uint64_t*)value;
                break;

            case UC_ARM64_REG_MDSCR_EL1:
                state->cp15.mdscr_el1 = *(uint32_t*)value;
                break;

            case UC_ARM64_REG_NOIMP:
            default:
                return -1;

            }
        }
    }

    return 0;
}

// SNPS added
void arm64_timer_recalc(CPUState *cpu, int timeridx);

void arm64_timer_recalc(CPUState *cpu, int timeridx)
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

DEFAULT_VISIBILITY
#ifdef TARGET_WORDS_BIGENDIAN
void arm64eb_uc_init(struct uc_struct* uc)
#else
void arm64_uc_init(struct uc_struct* uc)
#endif
{
    register_accel_types(uc);
    arm_cpu_register_types(uc);
    aarch64_cpu_register_types(uc);
    machvirt_machine_init(uc);
    uc->reg_read = arm64_reg_read;
    uc->reg_write = arm64_reg_write;
    uc->reg_reset = arm64_reg_reset;
    uc->set_pc = arm64_set_pc;
    uc->release = arm64_release;
    uc_common_init(uc);

    // SNPS added
    uc->timer_recalc = arm64_timer_recalc;
}
