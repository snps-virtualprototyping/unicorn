/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef UNICORN_RISCV_H
#define UNICORN_RISCV_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum uc_riscv_reg {
    UC_RISCV_REG_INVALID = 0,

    /* General-purpose registers */
    UC_RISCV_REG_X0,
    UC_RISCV_REG_X1,
    UC_RISCV_REG_X2,
    UC_RISCV_REG_X3,
    UC_RISCV_REG_X4,
    UC_RISCV_REG_X5,
    UC_RISCV_REG_X6,
    UC_RISCV_REG_X7,
    UC_RISCV_REG_X8,
    UC_RISCV_REG_X9,
    UC_RISCV_REG_X10,
    UC_RISCV_REG_X11,
    UC_RISCV_REG_X12,
    UC_RISCV_REG_X13,
    UC_RISCV_REG_X14,
    UC_RISCV_REG_X15,
    UC_RISCV_REG_X16,
    UC_RISCV_REG_X17,
    UC_RISCV_REG_X18,
    UC_RISCV_REG_X19,
    UC_RISCV_REG_X20,
    UC_RISCV_REG_X21,
    UC_RISCV_REG_X22,
    UC_RISCV_REG_X23,
    UC_RISCV_REG_X24,
    UC_RISCV_REG_X25,
    UC_RISCV_REG_X26,
    UC_RISCV_REG_X27,
    UC_RISCV_REG_X28,
    UC_RISCV_REG_X29,
    UC_RISCV_REG_X30,
    UC_RISCV_REG_X31,

    /* Program counter */
    UC_RISCV_REG_PC,

    /* Floating-point registers */
    UC_RISCV_REG_F0,
    UC_RISCV_REG_F1,
    UC_RISCV_REG_F2,
    UC_RISCV_REG_F3,
    UC_RISCV_REG_F4,
    UC_RISCV_REG_F5,
    UC_RISCV_REG_F6,
    UC_RISCV_REG_F7,
    UC_RISCV_REG_F8,
    UC_RISCV_REG_F9,
    UC_RISCV_REG_F10,
    UC_RISCV_REG_F11,
    UC_RISCV_REG_F12,
    UC_RISCV_REG_F13,
    UC_RISCV_REG_F14,
    UC_RISCV_REG_F15,
    UC_RISCV_REG_F16,
    UC_RISCV_REG_F17,
    UC_RISCV_REG_F18,
    UC_RISCV_REG_F19,
    UC_RISCV_REG_F20,
    UC_RISCV_REG_F21,
    UC_RISCV_REG_F22,
    UC_RISCV_REG_F23,
    UC_RISCV_REG_F24,
    UC_RISCV_REG_F25,
    UC_RISCV_REG_F26,
    UC_RISCV_REG_F27,
    UC_RISCV_REG_F28,
    UC_RISCV_REG_F29,
    UC_RISCV_REG_F30,
    UC_RISCV_REG_F31,

    /* SNSP added system registers */

    UC_RISCV_REG_MHARTID,
    UC_RISCV_REG_MSTATUS,

    /* General-purpose register aliases */

    /* Zero register */
    UC_RISCV_REG_ZERO = UC_RISCV_REG_X0,
    /* Return address */
    UC_RISCV_REG_RA = UC_RISCV_REG_X1,
    /* Stack pointer */
    UC_RISCV_REG_SP = UC_RISCV_REG_X2,
    /* Global pointer */
    UC_RISCV_REG_GP = UC_RISCV_REG_X3,
    /* Thread pointer */
    UC_RISCV_REG_TP = UC_RISCV_REG_X4,
    /* Temporary registers */
    UC_RISCV_REG_T0 = UC_RISCV_REG_X5,
    UC_RISCV_REG_T1 = UC_RISCV_REG_X6,
    UC_RISCV_REG_T2 = UC_RISCV_REG_X7,
    UC_RISCV_REG_T3 = UC_RISCV_REG_X28,
    UC_RISCV_REG_T4 = UC_RISCV_REG_X29,
    UC_RISCV_REG_T5 = UC_RISCV_REG_X30,
    UC_RISCV_REG_T6 = UC_RISCV_REG_X31,

    /* Frame pointer */
    UC_RISCV_REG_FP = UC_RISCV_REG_X8,

    /* Saved registers */
    UC_RISCV_REG_S0 = UC_RISCV_REG_X8,
    UC_RISCV_REG_S1 = UC_RISCV_REG_X9,
    UC_RISCV_REG_S2 = UC_RISCV_REG_X18,
    UC_RISCV_REG_S3 = UC_RISCV_REG_X19,
    UC_RISCV_REG_S4 = UC_RISCV_REG_X20,
    UC_RISCV_REG_S5 = UC_RISCV_REG_X21,
    UC_RISCV_REG_S6 = UC_RISCV_REG_X22,
    UC_RISCV_REG_S7 = UC_RISCV_REG_X23,
    UC_RISCV_REG_S8 = UC_RISCV_REG_X24,
    UC_RISCV_REG_S9 = UC_RISCV_REG_X25,
    UC_RISCV_REG_S10 = UC_RISCV_REG_X26,
    UC_RISCV_REG_S11 = UC_RISCV_REG_X27,

    /* Function argument registers */
    UC_RISCV_REG_A0 = UC_RISCV_REG_X10,
    UC_RISCV_REG_A1 = UC_RISCV_REG_X11,
    UC_RISCV_REG_A2 = UC_RISCV_REG_X12,
    UC_RISCV_REG_A3 = UC_RISCV_REG_X13,
    UC_RISCV_REG_A4 = UC_RISCV_REG_X14,
    UC_RISCV_REG_A5 = UC_RISCV_REG_X15,
    UC_RISCV_REG_A6 = UC_RISCV_REG_X16,
    UC_RISCV_REG_A7 = UC_RISCV_REG_X17,
} uc_riscv_reg;


#ifdef __cplusplus
}
#endif

#endif /* UNICORN_RISCV_H */
