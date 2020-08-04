#include "cpu.h"

uint64_t encode_cpreg(const ARMCPRegInfo *ri);
uint64_t encode_cpreg(const ARMCPRegInfo *ri) {
    return (uint64_t)(ri->opc0 & 0x3) << 14 |
           (uint64_t)(ri->opc1 & 0x7) << 11 |
           (uint64_t)(ri->crn  & 0xf) <<  7 |
           (uint64_t)(ri->crm  & 0xf) <<  3 |
           (uint64_t)(ri->opc2 & 0x7) <<  0;
}

static uint64_t gicv3reg_read(CPUARMState *env, const ARMCPRegInfo *ri) {
    uc_engine *uc = env->uc;
    uc_cb_mmio_t func = uc->uc_portio_func;
    void* opaque = uc->uc_portio_opaque;

    if (!func) {
        fprintf(stderr, "cannot find portio callback needed for register %s\n",
                ri->name);
        abort();
    }

    uint64_t val;
    uc_mmio_tx_t tx;
    tx.addr = encode_cpreg(ri);
    tx.cpuid = ~0;
    tx.data = &val;
    tx.size = 4;
    tx.is_io = true;
    tx.is_read = true;
    tx.is_secure = arm_is_secure(env);
    tx.is_user = false;

    //fprintf(stderr, "gicv3reg_read %s @ 0x%016lx\n", ri->name, tx.addr);
    func(env->uc, opaque, &tx);

    return val;
}

static void gicv3reg_write(CPUARMState *env, const ARMCPRegInfo *ri,
                           uint64_t val) {
    uc_engine *uc = env->uc;
    uc_cb_mmio_t func = uc->uc_portio_func;
    void* opaque = uc->uc_portio_opaque;

    if (!func) {
        fprintf(stderr, "cannot find portio callback needed for register %s\n",
                ri->name);
        abort();
    }

    uc_mmio_tx_t tx;
    tx.addr = encode_cpreg(ri);
    tx.cpuid = ~0;
    tx.data = &val;
    tx.size = 4;
    tx.is_io = true;
    tx.is_read = false;
    tx.is_secure = arm_is_secure(env);
    tx.is_user = false;

    //fprintf(stderr, "gicv3reg_write %s @ 0x%016lx pc = 0x%016lx\n", ri->name, tx.addr, env->pc);
    func(env->uc, opaque, &tx);
}

static CPAccessResult gicv3reg_access(CPUARMState *env,
                                      const ARMCPRegInfo *ri, bool isread)
{
    // TODO: figure out how we can communicate with the outside world register
    // access permissions, since they depend on:
    // 1. GIC state, for example config and status registers (external)
    // 2. core state, for example current exception level (internal)
    // a hypervisor might use access traps to intercept guest OS registers...
    CPAccessResult r = CP_ACCESS_OK;
    return r;
}

static CPAccessResult gicv3_fiq_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;
    //GICv3CPUState *cs = icc_cs_from_env(env);
    int el = arm_current_el(env);

    //if ((cs->ich_hcr_el2 & ICH_HCR_EL2_TALL0) &&
    //    el == 1 && !arm_is_secure_below_el3(env)) {
    //    /* Takes priority over a possible EL3 trap */
    //    return CP_ACCESS_TRAP_EL2;
    //}

    if (env->cp15.scr_el3 & SCR_FIQ) {
        switch (el) {
        case 1:
            if ((arm_hcr_el2_eff(env) & HCR_FMO) == 0) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3))
        r = CP_ACCESS_TRAP;
    return r;
}

static CPAccessResult gicv3_irq_access(CPUARMState *env,
                                       const ARMCPRegInfo *ri, bool isread)
{
    CPAccessResult r = CP_ACCESS_OK;
    //GICv3CPUState *cs = icc_cs_from_env(env);
    int el = arm_current_el(env);

    //if ((cs->ich_hcr_el2 & ICH_HCR_EL2_TALL1) &&
    //    el == 1 && !arm_is_secure_below_el3(env)) {
    //    /* Takes priority over a possible EL3 trap */
    //    return CP_ACCESS_TRAP_EL2;
    //}

    if (env->cp15.scr_el3 & SCR_IRQ) {
        switch (el) {
        case 1:
            if ((arm_hcr_el2_eff(env) & HCR_IMO) == 0) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        case 2:
            r = CP_ACCESS_TRAP_EL3;
            break;
        case 3:
            if (!is_a64(env) && !arm_is_el3_or_mon(env)) {
                r = CP_ACCESS_TRAP_EL3;
            }
            break;
        default:
            g_assert_not_reached();
        }
    }

    if (r == CP_ACCESS_TRAP_EL3 && !arm_el_is_aa64(env, 3))
        r = CP_ACCESS_TRAP;
    return r;
}

static const ARMCPRegInfo gicv3_cpuif_reginfo[] = {
    {
        .name = "ICC_PMR_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 4, .crm = 6, .opc2 = 0,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3reg_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_IAR0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 0,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_R,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
    }, {
        .name = "ICC_EOIR0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 1,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_W,
        .accessfn = gicv3_fiq_access,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_HPPIR0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 2,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_R,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
    }, {
        .name = "ICC_BPR0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 3,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP0R0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 4,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP0R1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 5,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP0R2_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 6,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP0R3_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 8, .opc2 = 7,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_fiq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP1R0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 0,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP1R1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 1,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP1R2_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 2,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_AP1R3_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 9, .opc2 = 3,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_DIR_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 1,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_W,
        .accessfn = gicv3_irq_access,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_RPR_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 3,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_R,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
    }, {
        .name = "ICC_SGI1R_EL1", .state = ARM_CP_STATE_AA64,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 5,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_W,
        .accessfn = gicv3_irq_access,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_ASGI1R_EL1", .state = ARM_CP_STATE_AA64,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 6,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_W,
        .accessfn = gicv3_irq_access,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_SGI0R_EL1", .state = ARM_CP_STATE_AA64,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 11, .opc2 = 7,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_W,
        .accessfn = gicv3_irq_access,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_IAR1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 0,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_R,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
    }, {
        .name = "ICC_EOIR1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 1,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_W,
        .accessfn = gicv3_irq_access,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_HPPIR1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 2,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_R,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
    }, {
        .name = "ICC_BPR1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 3,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3reg_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_CTLR_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 4,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3reg_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_SRE_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 5,
        .type = ARM_CP_NO_RAW | ARM_CP_CONST,
        .access = PL1_RW,
        .resetvalue = 0x7, // system register enable -> no callbacks!
    }, {
        .name = "ICC_IGRPEN0_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 6,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_IGRPEN1_EL1", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 0, .crn = 12, .crm = 12, .opc2 = 7,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL1_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_SRE_EL2", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 9, .opc2 = 5,
        .type = ARM_CP_NO_RAW | ARM_CP_CONST,
        .access = PL2_RW,
        .resetvalue = 0xf, // system register enable -> no callbacks!
    }, {
        .name = "ICC_CTLR_EL3", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 4,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL3_RW,
        .accessfn = gicv3reg_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    }, {
        .name = "ICC_SRE_EL3", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 5,
        .type = ARM_CP_NO_RAW | ARM_CP_CONST,
        .access = PL3_RW,
        .resetvalue = 0xf, // system register enable -> no callbacks!
    }, {
        .name = "ICC_IGRPEN1_EL3", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 6, .crn = 12, .crm = 12, .opc2 = 7,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL3_RW,
        .accessfn = gicv3_irq_access,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    },

    REGINFO_SENTINEL
};

static const ARMCPRegInfo gicv3_cpuif_hcr_reginfo[] = {
    {
        .name = "ICH_HCR_EL2", .state = ARM_CP_STATE_BOTH,
        .opc0 = 3, .opc1 = 4, .crn = 12, .crm = 11, .opc2 = 0,
        .type = ARM_CP_IO | ARM_CP_NO_RAW,
        .access = PL2_RW,
        .readfn = gicv3reg_read,
        .writefn = gicv3reg_write,
    },

    REGINFO_SENTINEL
};

void gicv3_init_cpuif(ARMCPU *cpu)
{
    // this needs to be there always
    define_arm_cp_regs(cpu, gicv3_cpuif_hcr_reginfo);

    // these are only available when the "gicv3" option is set to "true"
    const char* cfg = uc_get_config(cpu->env.uc, "gicv3");
    if (strcmp(cfg, "true") == 0) {
        cpu->env.gicv3state = (void*)~0ull;
        define_arm_cp_regs(cpu, gicv3_cpuif_reginfo);
    }
}
