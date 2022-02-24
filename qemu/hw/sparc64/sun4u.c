/*
 * QEMU Sun4u/Sun4v System Emulator
 *
 * Copyright (c) 2005 Fabrice Bellard
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu-common.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/sparc/sparc.h"
#include "qemu/timer.h"
#include "sysemu/sysemu.h"
#include "hw/boards.h"
#include "exec/address-spaces.h"
#include "qemu/cutils.h"

/* Sun4u hardware initialisation */
static int sun4u_init(struct uc_struct *uc, MachineState *machine)
{
    uc->cpu = cpu_create(uc, machine->cpu_type);

    SPARCCPU *cpu = SPARC_CPU(uc, uc->cpu);
    if (cpu == NULL) {
        fprintf(stderr, "Unable to find Sparc CPU definition\n");
        return -1;
    }

    return 0;
}

static void sun4u_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(uc, oc);

    mc->init = sun4u_init;
    mc->max_cpus = 1; /* XXX for now */
    mc->is_default = 1;
    mc->arch = UC_ARCH_SPARC;
    mc->default_cpu_type = SPARC_CPU_TYPE_NAME("Sun UltraSparc IV");
}

static const TypeInfo sun4u_type = {
    .name = MACHINE_TYPE_NAME("sun4u"),
    .parent = TYPE_MACHINE,
    .class_init = sun4u_class_init,
};

void sun4u_machine_init(struct uc_struct *uc)
{
    type_register_static(uc, &sun4u_type);
}
