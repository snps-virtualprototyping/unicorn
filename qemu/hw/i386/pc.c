/*
 * QEMU PC System Emulator
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
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
/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "sysemu/cpus.h"
#include "sysemu/sysemu.h"
#include "target/i386/topology.h"
#include "qapi/error.h"
#include "qapi/qapi-visit-common.h"
#include "qapi/visitor.h"


/* XXX: add IGNNE support */
void cpu_set_ferr(CPUX86State *s)
{
//    qemu_irq_raise(ferr_irq);
}

/* TSC handling */
uint64_t cpu_get_tsc(CPUX86State *env)
{
    return cpu_get_ticks();
}

/* SMM support */

static cpu_set_smm_t smm_set;
static void *smm_arg;

void cpu_smm_register(cpu_set_smm_t callback, void *arg)
{
    assert(smm_set == NULL);
    assert(smm_arg == NULL);
    smm_set = callback;
    smm_arg = arg;
}

void cpu_smm_update(CPUX86State *env)
{
    struct uc_struct *uc = env_archcpu(env)->parent_obj.uc;

    if (smm_set && smm_arg && env_cpu(env) == uc->cpu) {
        smm_set(!!(env->hflags & HF_SMM_MASK), smm_arg);
    }
}

/* IRQ handling */
int cpu_get_pic_interrupt(CPUX86State *env)
{
    X86CPU *cpu = env_archcpu(env);
    int intno;

    intno = apic_get_interrupt(cpu->apic_state);
    if (intno >= 0) {
        return intno;
    }
    /* read the irq from the PIC */
    if (!apic_accept_pic_intr(cpu->apic_state)) {
        return -1;
    }

    return 0;
}

DeviceState *cpu_get_current_apic(struct uc_struct *uc)
{
    if (uc->current_cpu) {
        X86CPU *cpu = X86_CPU(uc, uc->current_cpu);
        return cpu->apic_state;
    } else {
        return NULL;
    }
}

static X86CPU *pc_new_cpu(struct uc_struct *uc, const char *typename, int64_t apic_id,
                          Error **errp)
{
    X86CPU *cpu;
    Error *local_err = NULL;

    cpu = X86_CPU(uc, object_new(uc, typename));

    object_property_set_int(uc, OBJECT(cpu), apic_id, "apic-id", &local_err);
    object_property_set_bool(uc, OBJECT(cpu), true, "realized", &local_err);

    if (local_err) {
        error_propagate(errp, local_err);
        object_unref(uc, OBJECT(cpu));
        cpu = NULL;
    }
    return cpu;
}

int pc_cpus_init(struct uc_struct *uc, PCMachineState *pcms)
{
    int i;
    Error *error = NULL;
    MachineState *ms = MACHINE(uc, pcms);

    for (i = 0; i < smp_cpus; i++) {
        uc->cpu = (CPUState *)pc_new_cpu(uc, ms->cpu_type, x86_cpu_apic_id_from_index(i), &error);
        if (error) {
            error_free(error);
            return -1;
        }
    }

    return 0;
}

static void pc_machine_initfn(struct uc_struct *uc, Object *obj, void *opaque)
{
}

static void pc_machine_class_init(struct uc_struct *uc, ObjectClass *oc, void *data)
{
    MachineClass *mc = MACHINE_CLASS(uc, oc);
    mc->default_cpu_type = TARGET_DEFAULT_CPU_TYPE;
}

static const TypeInfo pc_machine_info = {
    .name = TYPE_PC_MACHINE,
    .parent = TYPE_MACHINE,

    .class_size = sizeof(PCMachineClass),
    .instance_size = sizeof(PCMachineState),

    .instance_init = pc_machine_initfn,
    .class_init = pc_machine_class_init,

    .abstract = true,

    // should this be added somehow?
    //.interfaces = (InterfaceInfo[]) { { } },
};

void pc_machine_register_types(struct uc_struct *uc)
{
    type_register_static(uc, &pc_machine_info);
}

/* Enables contiguous-apic-ID mode, for compatibility */
static bool compat_apic_id_mode;

void enable_compat_apic_id_mode(void)
{
    compat_apic_id_mode = true;
}

/* Calculates initial APIC ID for a specific CPU index
 *
 * Currently we need to be able to calculate the APIC ID from the CPU index
 * alone (without requiring a CPU object), as the QEMU<->Seabios interfaces have
 * no concept of "CPU index", and the NUMA tables on fw_cfg need the APIC ID of
 * all CPUs up to max_cpus.
 */
uint32_t x86_cpu_apic_id_from_index(unsigned int cpu_index)
{
    uint32_t correct_id;

    correct_id = x86_apicid_from_cpu_idx(1, smp_cores, smp_threads, cpu_index);
    if (compat_apic_id_mode) {
        if (cpu_index != correct_id) {
            //error_report("APIC IDs set in compatibility mode, "
            //        "CPU topology won't match the configuration");
        }
        return cpu_index;
    } else {
        return correct_id;
    }
}
