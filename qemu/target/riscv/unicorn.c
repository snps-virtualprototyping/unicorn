/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#include <string.h>
#include <assert.h>

#include "qemu/osdep.h"
#include "cpu.h"
#include "fpu/softfloat.h"
#include "hw/boards.h"
#include "hw/riscv/spike.h"
#include "sysemu/cpus.h"
#include "unicorn.h"
#include "unicorn_common.h"
#include "uc_priv.h"

#ifdef TARGET_RISCV32
const int RISCV32_REGS_STORAGE_SIZE = offsetof(CPURISCVState, tlb_table);
#else
const int RISCV64_REGS_STORAGE_SIZE = offsetof(CPURISCVState, tlb_table);
#endif

static void riscv_release(void *ctx) {
    TCGContext *tcg_ctx = (TCGContext *) ctx;

    release_common(ctx);
    g_free(tcg_ctx->tb_ctx.tbs);
}

static void riscv_reg_reset(struct uc_struct *uc) {
    CPUArchState *env = uc->cpu->env_ptr;

    memset(env->gpr, 0, sizeof(env->gpr));
    memset(env->fpr, 0, sizeof(env->fpr));

    env->priv = PRV_M;
    env->mstatus &= ~(MSTATUS_MIE | MSTATUS_MPRV);
    env->mcause = 0;
    env->pc = env->resetvec;

    set_default_nan_mode(1, &env->fp_status);
}

_Static_assert(UC_RISCV_VLEN_MAX == RV_VLEN_MAX, "vector register size mismatch");

static int riscv_reg_read(struct uc_struct *uc, unsigned int *regs, void **vals, int count) {
    CPUState *const cs = uc->cpu;
    CPURISCVState *const state = &RISCV_CPU(uc, cs)->env;
    int status  = 0;

    for (int i = 0; i < count; i++) {
        const unsigned int reg_id = regs[i];
        void *const value = vals[i];

        if (reg_id >= UC_RISCV_REG_X0 && reg_id <= UC_RISCV_REG_X31) {
            memcpy(value, &state->gpr[reg_id - UC_RISCV_REG_X0], sizeof(state->gpr[0]));
        } else if (reg_id >= UC_RISCV_REG_F0 && reg_id <= UC_RISCV_REG_F31) {
            memcpy(value, &state->fpr[reg_id - UC_RISCV_REG_F0], sizeof(state->fpr[0]));
        } else if (reg_id >= UC_RISCV_REG_V0 &&  reg_id <= UC_RISCV_REG_V31) { // SNPS added
            const size_t VREG_BYTES = RV_VLEN_MAX / 8;
            const size_t VREG_OFFSET = VREG_BYTES / sizeof(state->vreg[0]);
            memcpy(value, &state->vreg[(reg_id - UC_RISCV_REG_V0) * VREG_OFFSET], VREG_BYTES);
        } else {
            // SNPS changed
            switch (reg_id) {
            case UC_RISCV_REG_PC:
                memcpy(value, &state->pc, sizeof(state->pc));
                break;
            case UC_RISCV_REG_MHARTID:
                memcpy(value, &state->mhartid, sizeof(state->mhartid));
                break;
            case UC_RISCV_REG_MSTATUS:
                memcpy(value, &state->mstatus, sizeof(state->mstatus));
                break;
            case UC_RISCV_REG_VSTART:
                memcpy(value, &state->vstart, sizeof(state->vstart));
                break;
            case UC_RISCV_REG_VXSAT:
                memcpy(value, &state->vxsat, sizeof(state->vxsat));
                break;
            case UC_RISCV_REG_VXRM:
                memcpy(value, &state->vxrm, sizeof(state->vxrm));
                break;
            case UC_RISCV_REG_VTYPE:
                memcpy(value, &state->vtype, sizeof(state->vtype));
                break;
            case UC_RISCV_REG_VL:
                memcpy(value, &state->vl, sizeof(state->vl));
                break;
            default:
                fprintf(stderr, "trying to read unknown RISCV register id 0x%x\n", reg_id);
                status = 1;
                break;
            }
        }
    }

    return status;
}

static int riscv_reg_write(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count) {
    CPUState *const cs = uc->cpu;
    CPURISCVState *const state = &RISCV_CPU(uc, cs)->env;
    int status = 0;

    for (int i = 0; i < count; i++) {
        const unsigned int reg_id = regs[i];
        const void *value = vals[i];

        // Intentionally exclude the zero register (X0) in the lower-bound
        if (reg_id > UC_RISCV_REG_X0 && reg_id <= UC_RISCV_REG_X31) {
            memcpy(&state->gpr[reg_id - UC_RISCV_REG_X0], value, sizeof(state->gpr[0]));
        } else if (reg_id >= UC_RISCV_REG_F0 && reg_id <= UC_RISCV_REG_F31) {
            memcpy(&state->fpr[reg_id - UC_RISCV_REG_F0], value, sizeof(state->fpr[0]));
        } else if (reg_id >= UC_RISCV_REG_V0 && reg_id <= UC_RISCV_REG_V31) {
            const size_t VREG_BYTES = RV_VLEN_MAX / 8;
            const size_t VREG_OFFSET = VREG_BYTES / sizeof(state->vreg[0]);
            memcpy(&state->vreg[(reg_id - UC_RISCV_REG_V0) * VREG_OFFSET], value, VREG_BYTES);
        } else {
            // SNPS changed
            switch (reg_id) {
            case UC_RISCV_REG_PC:
                memcpy(&state->pc, value, sizeof(state->pc));
                // force to quit execution and flush TB
                uc->quit_request = true;
                uc_emu_stop(uc);
                break;
            case UC_RISCV_REG_MHARTID:
                memcpy(&state->mhartid, value, sizeof(state->mhartid));
                break;
            default:
                fprintf(stderr, "trying to write read-only or unknown RISCV register id 0x%x\n", reg_id);
                status = 1;
                break;
            }
        }
    }

    return status;
}

static void riscv_set_pc(struct uc_struct *uc, uint64_t address) {
    CPURISCVState *state = uc->cpu->env_ptr;

    state->pc = address;
}

static bool riscv_stop_interrupt(int int_no) {
    switch(int_no) {
    default:
        return false;
    }
}

DEFAULT_VISIBILITY
#ifdef TARGET_RISCV32
void riscv32_uc_init(struct uc_struct *uc) {
#else
void riscv64_uc_init(struct uc_struct *uc) {
#endif
    register_accel_types(uc);
    riscv_cpu_register_types(uc);
    spike_v1_10_0_machine_init_register_types(uc);

    uc->release = riscv_release;
    uc->reg_read = riscv_reg_read;
    uc->reg_write = riscv_reg_write;
    uc->reg_reset = riscv_reg_reset;
    uc->set_pc = riscv_set_pc;
    uc->stop_interrupt = riscv_stop_interrupt;

    uc_common_init(uc);
}
