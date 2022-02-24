/*
 * QEMU RISC-V Spike Board
 *
 * Copyright (c) 2016-2017 Sagar Karandikar, sagark@eecs.berkeley.edu
 * Copyright (c) 2017-2018 SiFive, Inc.
 *
 * This provides a RISC-V Board with the following devices:
 *
 * 0) HTIF Console and Poweroff
 * 1) CLINT (Timer and IPI)
 * 2) PLIC (Platform Level Interrupt Controller)
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
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/riscv/spike.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"

static int spike_v1_10_0_board_init(struct uc_struct *uc, MachineState *machine)
{
    uc->cpu = cpu_create(uc, machine->cpu_type);

    if (uc->cpu == NULL) {
        fprintf(stderr, "Unable to make CPU definition\n");
        return -1;
    }

    return 0;
}

static void spike_v1_10_0_machine_init(struct uc_struct *uc, MachineClass *mc)
{
    mc->init = spike_v1_10_0_board_init;
    mc->max_cpus = 1;
    mc->is_default = 1;

    // Unicorn: instead of using SPIKE_V1_10_0_CPU like qemu,
    //          we use specific values to allow selection of the
    //          preferred bitness of the architecture.
    if (uc->mode == UC_MODE_RISCV32) {
        mc->default_cpu_type = TYPE_RISCV_CPU_RV32GCSU_V1_10_0;
    } else {
        mc->default_cpu_type = TYPE_RISCV_CPU_RV64GCSU_V1_10_0;
    }

    mc->arch = UC_ARCH_RISCV;
}

DEFINE_MACHINE("spike_v1.10", spike_v1_10_0_machine_init)
