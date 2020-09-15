/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include <time.h>   // nanosleep

#include <string.h>

#include "uc_priv.h"

// target specific headers
#include "qemu/target/arm/unicorn.h"
#include "qemu/target/i386/unicorn.h"
#include "qemu/target/m68k/unicorn.h"
#include "qemu/target/mips/unicorn.h"
#include "qemu/target/riscv/unicorn.h"
#include "qemu/target/sparc/unicorn.h"

#include "qemu/include/hw/boards.h"
#include "qemu/include/qemu/queue.h"

static void helper_tlb_cluster_flush(CPUState* cpu) {
    uc_engine *uc = cpu->uc;
    if (!uc->uc_tlb_cluster_flush) {
        uc_tlb_flush(uc);
    } else {
        uc->uc_tlb_cluster_flush(uc->uc_tlb_cluster_opaque);
    }
}

static void helper_tlb_cluster_flush_page(CPUState* cpu, uint64_t addr) {
    uc_engine *uc = cpu->uc;
    if (!uc->uc_tlb_cluster_flush_page) {
        uc_tlb_flush_page(uc, addr);
    } else {
        uc->uc_tlb_cluster_flush_page(uc->uc_tlb_cluster_opaque, addr);
    }
}

static void helper_tlb_cluster_flush_mmuidx(CPUState* cpu, uint16_t idxmap) {
    uc_engine *uc = cpu->uc;
    if (!uc->uc_tlb_cluster_flush_mmuidx) {
        uc_tlb_flush_mmuidx(uc, idxmap);
    } else {
        uc->uc_tlb_cluster_flush_mmuidx(uc->uc_tlb_cluster_opaque, idxmap);
    }
}

static void helper_tlb_cluster_flush_page_mmuidx(CPUState* cpu, uint64_t addr, uint16_t idxmap) {
    uc_engine *uc = cpu->uc;
     if (!uc->uc_tlb_cluster_flush_page_mmuidx) {
        uc_tlb_flush_page_mmuidx(uc, addr, idxmap);
    } else {
        uc->uc_tlb_cluster_flush_page_mmuidx(uc->uc_tlb_cluster_opaque, addr, idxmap);
    }
}

static void free_class_properties(uc_engine *uc, ObjectClass *klass)
{
    ObjectProperty *prop;
    GHashTableIter iter;
    gpointer key, value;
    bool released;

    do {
        released = false;
        g_hash_table_iter_init(&iter, klass->properties);
        while (g_hash_table_iter_next(&iter, &key, &value)) {
            prop = value;
            if (prop->release) {
                prop->release(uc, NULL, prop->name, prop->opaque);
                prop->release = NULL;
                released = true;
                break;
            }
            g_hash_table_iter_remove(&iter);
        }
    } while (released);

    g_hash_table_destroy(klass->properties);
}

static void free_table(gpointer key, gpointer value, gpointer data)
{
    TypeInfo *ti = (TypeInfo*) value;
    uc_engine *uc = (uc_engine *)data;
    free_class_properties(uc, ti->class);
    g_free((void *) ti->class);
    g_free((void *) ti->name);
    g_free((void *) ti->parent);
    g_free((void *) ti);
}

UNICORN_EXPORT
unsigned int uc_version(unsigned int *major, unsigned int *minor)
{
    if (major != NULL && minor != NULL) {
        *major = UC_API_MAJOR;
        *minor = UC_API_MINOR;
    }

    return (UC_API_MAJOR << 8) + UC_API_MINOR;
}


UNICORN_EXPORT
uc_err uc_errno(uc_engine *uc)
{
    return uc->errnum;
}

UNICORN_EXPORT
const char *uc_strerror(uc_err code)
{
    switch(code) {
        case UC_ERR_OK:
            return "OK (UC_ERR_OK)";
        case UC_ERR_NOMEM:
            return "No memory available or memory not present (UC_ERR_NOMEM)";
        case UC_ERR_ARCH:
            return "Invalid/unsupported architecture (UC_ERR_ARCH)";
        case UC_ERR_HANDLE:
            return "Invalid handle (UC_ERR_HANDLE)";
        case UC_ERR_MODE:
            return "Invalid mode (UC_ERR_MODE)";
        case UC_ERR_VERSION:
            return "Different API version between core & binding (UC_ERR_VERSION)";
        case UC_ERR_READ_UNMAPPED:
            return "Invalid memory read (UC_ERR_READ_UNMAPPED)";
        case UC_ERR_WRITE_UNMAPPED:
            return "Invalid memory write (UC_ERR_WRITE_UNMAPPED)";
        case UC_ERR_FETCH_UNMAPPED:
            return "Invalid memory fetch (UC_ERR_FETCH_UNMAPPED)";
        case UC_ERR_HOOK:
            return "Invalid hook type (UC_ERR_HOOK)";
        case UC_ERR_INSN_INVALID:
            return "Invalid instruction (UC_ERR_INSN_INVALID)";
        case UC_ERR_MAP:
            return "Invalid memory mapping (UC_ERR_MAP)";
        case UC_ERR_WRITE_PROT:
            return "Write to write-protected memory (UC_ERR_WRITE_PROT)";
        case UC_ERR_READ_PROT:
            return "Read from non-readable memory (UC_ERR_READ_PROT)";
        case UC_ERR_FETCH_PROT:
            return "Fetch from non-executable memory (UC_ERR_FETCH_PROT)";
        case UC_ERR_ARG:
            return "Invalid argument (UC_ERR_ARG)";
        case UC_ERR_READ_UNALIGNED:
            return "Read from unaligned memory (UC_ERR_READ_UNALIGNED)";
        case UC_ERR_WRITE_UNALIGNED:
            return "Write to unaligned memory (UC_ERR_WRITE_UNALIGNED)";
        case UC_ERR_FETCH_UNALIGNED:
            return "Fetch from unaligned memory (UC_ERR_FETCH_UNALIGNED)";
        case UC_ERR_RESOURCE:
            return "Insufficient resource (UC_ERR_RESOURCE)";
        case UC_ERR_EXCEPTION:
            return "Unhandled CPU exception (UC_ERR_EXCEPTION)";
        case UC_ERR_BREAKPOINT:
            return "CPU hit breakpoint (UC_ERR_BREAKPOINT)";
        case UC_ERR_WATCHPOINT:
            return "CPU triggered watchpoint (UC_ERR_WATCHPOINT)";
        case UC_ERR_YIELD:
            return "CPU wants to yield (UC_ERR_YIELD)";
        case UC_ERR_INTERNAL:
            return "Internal error (UC_ERR_INTERNAL)";
        default:
            return "Unknown error code";
    }
}


UNICORN_EXPORT
bool uc_arch_supported(uc_arch arch)
{
    switch (arch) {
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:   return true;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64: return true;
#endif
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:  return true;
#endif
#ifdef UNICORN_HAS_MIPS
        case UC_ARCH_MIPS:  return true;
#endif
#ifdef UNICORN_HAS_PPC
        case UC_ARCH_PPC:   return true;
#endif
#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC: return true;
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV: return true;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:   return true;
#endif
        /* Invalid or disabled arch */
        default:            return false;
    }
}

#define UC_DEFAULT_TBSZ (8ull * 1024ull * 1024ull) // 8MB

static size_t parse_tbsz(const char* tbsz) {
    char* postfix = NULL;
    size_t sz = strtoull(tbsz, &postfix, 10);

    if (sz == 0ull) {
        if (strlen(tbsz) > 0) {
            fprintf(stderr, "[QEMU TCG] failed to parse '%s' using %llu bytes "
                    "default", tbsz, UC_DEFAULT_TBSZ);
        }
        return UC_DEFAULT_TBSZ;
    }

    if (!strcmp(postfix, "kB") || !strcmp(postfix, "kb"))
        return sz * 1024ull;
    if (!strcmp(postfix, "MB") || !strcmp(postfix, "mb"))
        return sz * 1024ull * 1024ull;
    if (!strcmp(postfix, "GB") || !strcmp(postfix, "gb"))
        return sz * 1024ull * 1024ull * 1024ull;

    return sz;
}

UNICORN_EXPORT
uc_err uc_open(const char* model, void *cfg_opaque, uc_get_config_t cfg_func,
               uc_engine **result)
{
    struct uc_struct *uc;

    uc_arch arch = UC_ARCH_MAX;
    uc_mode mode;

#ifdef UNICORN_HAS_ARM
    if (strcmp(model, "Cortex-M0") == 0 ||
        strcmp(model, "Cortex-M3") == 0 ||
        strcmp(model, "Cortex-M4") == 0 ||
        strcmp(model, "Cortex-M33") == 0) {
        arch = UC_ARCH_ARM;
        mode = UC_MODE_THUMB;
    }

    if (strcmp(model, "Cortex-R5") == 0 ||
        strcmp(model, "Cortex-R5f") == 0) {
        arch = UC_ARCH_ARM;
        mode = UC_MODE_ARM;
    }

    if (strcmp(model, "Cortex-A7") == 0 ||
        strcmp(model, "Cortex-A8") == 0 ||
        strcmp(model, "Cortex-A9") == 0 ||
        strcmp(model, "Cortex-A15") == 0) {
        arch = UC_ARCH_ARM;
        mode = UC_MODE_ARM;
    }
#endif

#ifdef UNICORN_HAS_ARM64
    if (strcmp(model, "Cortex-A53") == 0 ||
        strcmp(model, "Cortex-A57") == 0 ||
        strcmp(model, "Cortex-A72") == 0 ||
        strcmp(model, "Cortex-Max") == 0) {
        arch = UC_ARCH_ARM64;
        mode = UC_MODE_ARM;
    }
#endif

    if (arch == UC_ARCH_MAX)
        return UC_ERR_ARCH;

    if (arch < UC_ARCH_MAX) {
        uc = calloc(1, sizeof(*uc));
        if (!uc) {
            // memory insufficient
            return UC_ERR_NOMEM;
        }

        uc->errnum = UC_ERR_OK;
        uc->arch = arch;
        uc->mode = mode;

        uc->uc_config_func = cfg_func;
        uc->uc_config_opaque = cfg_opaque;

        const char* tbsz = uc_get_config(uc, "tbsize");
        uc->tb_size = parse_tbsz(tbsz);

        snprintf(uc->model, sizeof(uc->model), "%s-arm-cpu", model);

        // uc->ram_list = { .blocks = QLIST_HEAD_INITIALIZER(ram_list.blocks) };
        uc->ram_list.blocks.lh_first = NULL;

        uc->memory_listeners.tqh_first = NULL;
        uc->memory_listeners.tqh_last = &uc->memory_listeners.tqh_first;

        uc->address_spaces.tqh_first = NULL;
        uc->address_spaces.tqh_last = &uc->address_spaces.tqh_first;

        uc->phys_map_node_alloc_hint = 16;

        uc->mmios = NULL;

        uc->timer_initialized = false;
        uc->timer_timefunc = NULL;
        uc->timer_irqfunc  = NULL;
        uc->timer_schedule = NULL;

        uc->uc_tlb_cluster_flush = NULL;
        uc->uc_tlb_cluster_flush_page = NULL;
        uc->uc_tlb_cluster_flush_mmuidx = NULL;
        uc->uc_tlb_cluster_flush_page_mmuidx = NULL;
        uc->uc_tlb_cluster_opaque = NULL;

        uc->tlb_cluster_flush = helper_tlb_cluster_flush;
        uc->tlb_cluster_flush_page = helper_tlb_cluster_flush_page;
        uc->tlb_cluster_flush_mmuidx = helper_tlb_cluster_flush_mmuidx;
        uc->tlb_cluster_flush_page_mmuidx = helper_tlb_cluster_flush_page_mmuidx;

        uc->uc_breakpoint_func = NULL;
        uc->uc_breakpoint_opaque = NULL;

        uc->uc_watchpoint_func = NULL;
        uc->uc_watchpoint_opaque = NULL;

        uc->uc_hint_func = NULL;
        uc->uc_hint_opaque = NULL;

        uc->uc_semihost_func = NULL;
        uc->uc_semihost_opaque = NULL;

        uc->uc_trace_bb_func = NULL;
        uc->uc_trace_bb_opaque = NULL;

        uc->setup_once = NULL;

        uc->is_debug = false;
        uc->is_excl = false;

        switch(arch) {
            default:
                break;
#ifdef UNICORN_HAS_M68K
            case UC_ARCH_M68K:
                if ((mode & ~UC_MODE_M68K_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN)) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                uc->init_arch = m68k_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_X86
            case UC_ARCH_X86:
                if ((mode & ~UC_MODE_X86_MASK) ||
                        (mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_16|UC_MODE_32|UC_MODE_64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                uc->init_arch = x86_uc_init;
                break;
#endif
#ifdef UNICORN_HAS_ARM
            case UC_ARCH_ARM:
                if ((mode & ~UC_MODE_ARM_MASK)) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
                    assert(0);
                    //uc->init_arch = armeb_uc_init;
                } else {
                    uc->init_arch = arm_uc_init;
                }

                //if (mode & UC_MODE_THUMB)
                //    uc->thumb = 1;
                break;
#endif
#ifdef UNICORN_HAS_ARM64
            case UC_ARCH_ARM64:
                if (mode & ~UC_MODE_ARM_MASK) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
                    assert(0);
                    //uc->init_arch = arm64eb_uc_init;
                } else {
                    uc->init_arch = arm64_uc_init;
                }
                break;
#endif

#if defined(UNICORN_HAS_MIPS) || defined(UNICORN_HAS_MIPSEL) || defined(UNICORN_HAS_MIPS64) || defined(UNICORN_HAS_MIPS64EL)
            case UC_ARCH_MIPS:
                if ((mode & ~UC_MODE_MIPS_MASK) ||
                        !(mode & (UC_MODE_MIPS32|UC_MODE_MIPS64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_BIG_ENDIAN) {
#ifdef UNICORN_HAS_MIPS
                    if (mode & UC_MODE_MIPS32)
                        uc->init_arch = mips_uc_init;
#endif
#ifdef UNICORN_HAS_MIPS64
                    if (mode & UC_MODE_MIPS64)
                        uc->init_arch = mips64_uc_init;
#endif
                } else {    // little endian
#ifdef UNICORN_HAS_MIPSEL
                    if (mode & UC_MODE_MIPS32)
                        uc->init_arch = mipsel_uc_init;
#endif
#ifdef UNICORN_HAS_MIPS64EL
                    if (mode & UC_MODE_MIPS64)
                        uc->init_arch = mips64el_uc_init;
#endif
                }
                break;
#endif

#ifdef UNICORN_HAS_RISCV
            case UC_ARCH_RISCV:
                if (mode & ~UC_MODE_RISCV_MASK) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_RISCV64) {
#ifdef UNICORN_HAS_RISCV64
                    uc->init_arch = riscv64_uc_init;
#endif
                } else {
#ifdef UNICORN_HAS_RISCV32
                    uc->init_arch = riscv32_uc_init;
#endif
                }
                break;
#endif /* UNICORN_HAS_RISCV */

#ifdef UNICORN_HAS_SPARC
            case UC_ARCH_SPARC:
                if ((mode & ~UC_MODE_SPARC_MASK) ||
                        !(mode & UC_MODE_BIG_ENDIAN) ||
                        !(mode & (UC_MODE_SPARC32|UC_MODE_SPARC64))) {
                    free(uc);
                    return UC_ERR_MODE;
                }
                if (mode & UC_MODE_SPARC64)
                    uc->init_arch = sparc64_uc_init;
                else
                    uc->init_arch = sparc_uc_init;
                break;
#endif
        }

        if (uc->init_arch == NULL) {
            return UC_ERR_ARCH;
        }

        if (machine_initialize(uc)) {
            return UC_ERR_RESOURCE;
        }

        *result = uc;

        if (uc->reg_reset)
            uc->reg_reset(uc);

        return UC_ERR_OK;
    } else {
        return UC_ERR_ARCH;
    }
}

static void free_hooks(uc_engine *uc)
{
    struct list_item *cur;
    struct hook *hook;
    int i;

    // free hooks and hook lists
    for (i = 0; i < UC_HOOK_MAX; i++) {
        cur = uc->hook[i].head;
        // hook can be in more than one list
        // so we refcount to know when to free
        while (cur) {
            hook = (struct hook *)cur->data;
            if (--hook->refs == 0) {
                free(hook);
            }
            cur = cur->next;
        }
        list_clear(&uc->hook[i]);
    }
}

static void free_mmios(uc_engine *uc)
{
    uc_mmio_region_t *p = uc->mmios;
    while (p != NULL) {
        uc_mmio_region_t *next = p->next;
        g_free(p);
        p = next;
    }
}

static void free_breakpoints(uc_engine *uc)
{
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &uc->cpu->breakpoints, entry, next) {
        QTAILQ_REMOVE(&uc->cpu->breakpoints, bp, entry);
        g_free(bp);
    }
}

UNICORN_EXPORT
uc_err uc_close(uc_engine *uc)
{
    // Cleanup internally.
    if (uc->release)
        uc->release(uc->tcg_ctx);
    g_free(uc->tcg_ctx);

    // Cleanup CPU.
    g_free(uc->cpu->cpu_ases);
    g_free(uc->cpu->thread);

    // Cleanup all objects.
    free_breakpoints(uc);

    OBJECT(uc->machine_state->accelerator)->ref = 1;
    OBJECT(uc->machine_state)->ref = 1;
    OBJECT(uc->owner)->ref = 1;
    OBJECT(uc->root)->ref = 1;

    object_unref(uc, OBJECT(uc->machine_state->accelerator));
    object_unref(uc, OBJECT(uc->machine_state));
    object_unref(uc, OBJECT(uc->cpu));

    // These seem to be auto deleted when uc->root gets deleted, no need to
    // unref them manually (?)
    //object_unref(uc, OBJECT(&uc->io_mem_notdirty));
    //object_unref(uc, OBJECT(&uc->io_mem_unassigned));
    //object_unref(uc, OBJECT(&uc->io_mem_rom));
    //object_unref(uc, OBJECT(&uc->io_mem_watch));
    object_unref(uc, OBJECT(uc->root));

    // System memory.
    g_free(uc->system_memory);

    // Thread relateds.
    if (uc->qemu_thread_data)
        g_free(uc->qemu_thread_data);

    // Other auxilaries.
    if (uc->bounce.buffer) {
        free(uc->bounce.buffer);
    }

    g_hash_table_foreach(uc->type_table, free_table, uc);
    g_hash_table_destroy(uc->type_table);

    free_hooks(uc);
    free_mmios(uc);
    free(uc->mapped_blocks);

    // finally, free uc itself.
    memset(uc, 0, sizeof(*uc));
    free(uc);

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reg_read_batch(uc_engine *uc, int *ids, void **vals, int count)
{
    if (uc->reg_read &&
        uc->reg_read(uc, (unsigned int *)ids, vals, count) == 0)
        return UC_ERR_OK;
    return UC_ERR_HANDLE;
}


UNICORN_EXPORT
uc_err uc_reg_write_batch(uc_engine *uc, int *ids, void *const *vals, int count)
{
    if (uc->reg_write &&
        uc->reg_write(uc, (unsigned int *)ids, vals, count) == 0)
        return UC_ERR_OK;
    return UC_ERR_HANDLE;
}

UNICORN_EXPORT
uc_err uc_reg_read(uc_engine *uc, int regid, void *value)
{
    return uc_reg_read_batch(uc, &regid, &value, 1);
}

UNICORN_EXPORT
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value)
{
    return uc_reg_write_batch(uc, &regid, (void *const *)&value, 1);
}

// check if a memory area is mapped
// this is complicated because an area can overlap adjacent blocks
static bool check_mem_area(uc_engine *uc, uint64_t address, size_t size)
{
    size_t count = 0, len;

    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            count += len;
            address += len;
        } else  // this address is not mapped in yet
            break;
    }

    return (count == size);
}


UNICORN_EXPORT
uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *_bytes, size_t size)
{
    size_t count = 0, len;
    uint8_t *bytes = _bytes;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    if (!check_mem_area(uc, address, size))
        return UC_ERR_READ_UNMAPPED;

    uc->is_debug = true;

    // memory area can overlap adjacent memory blocks
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            len = (size_t)MIN(size - count, mr->end - address);
            if (uc->read_mem(uc->cpu->as, address, bytes, len) == false)
                break;
            count += len;
            address += len;
            bytes += len;
        } else  // this address is not mapped in yet
            break;
    }

    uc->is_debug = false;

    if (count == size)
        return UC_ERR_OK;
    else
        return UC_ERR_READ_UNMAPPED;
}

UNICORN_EXPORT
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *_bytes, size_t size)
{
    size_t count = 0, len;
    const uint8_t *bytes = _bytes;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    if (!check_mem_area(uc, address, size))
        return UC_ERR_WRITE_UNMAPPED;

    uc->is_debug = true;

    // memory area can overlap adjacent memory blocks
    while(count < size) {
        MemoryRegion *mr = memory_mapping(uc, address);
        if (mr) {
            uint32_t operms = mr->perms;
            if (!(operms & UC_PROT_WRITE)) // write protected
                // but this is not the program accessing memory, so temporarily mark writable
                uc->readonly_mem(mr, false);

            len = (size_t)MIN(size - count, mr->end - address);
            if (uc->write_mem(uc->cpu->as, address, bytes, len) == false)
                break;

            if (!(operms & UC_PROT_WRITE)) // write protected
                // now write protect it again
                uc->readonly_mem(mr, true);

            count += len;
            address += len;
            bytes += len;
        } else  // this address is not mapped in yet
            break;
    }

    uc->is_debug = false;

    if (count == size)
        return UC_ERR_OK;
    else
        return UC_ERR_WRITE_UNMAPPED;
}

#define TIMEOUT_STEP 2    // microseconds
static void *_timeout_fn(void *arg)
{
    struct uc_struct *uc = arg;
    int64_t current_time = get_clock();

    do {
        usleep(TIMEOUT_STEP);
        // perhaps emulation is even done before timeout?
        if (uc->emulation_done)
            break;
    } while((uint64_t)(get_clock() - current_time) < uc->timeout);

    // timeout before emulation is done?
    if (!uc->emulation_done) {
        // force emulation to stop
        uc_emu_stop(uc);
    }

    return NULL;
}

static void enable_emu_timer(uc_engine *uc, uint64_t timeout)
{
    uc->timeout = timeout;
    qemu_thread_create(uc, &uc->timer, "timeout", _timeout_fn,
            uc, QEMU_THREAD_JOINABLE);
}

UNICORN_EXPORT
uc_err uc_emu_start(uc_engine* uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count)
{
    // reset the counter
    uc->emu_counter = 0;
    uc->emu_count = count;
    uc->invalid_error = UC_ERR_OK;
    uc->block_full = false;
    uc->emulation_done = false;
    uc->parallel_cpus = true;

    switch(uc->arch) {
        default:
            break;
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:
            uc_reg_write(uc, UC_M68K_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:
            switch(uc->mode) {
                default:
                    break;
                case UC_MODE_16: {
                    uint64_t ip;
                    uint16_t cs;

                    uc_reg_read(uc, UC_X86_REG_CS, &cs);
                    // compensate for later adding up IP & CS
                    ip = begin - cs*16;
                    uc_reg_write(uc, UC_X86_REG_IP, &ip);
                    break;
                }
                case UC_MODE_32:
                    uc_reg_write(uc, UC_X86_REG_EIP, &begin);
                    break;
                case UC_MODE_64:
                    uc_reg_write(uc, UC_X86_REG_RIP, &begin);
                    break;
            }
            break;
#endif
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            uc_reg_write(uc, UC_ARM_REG_R15, &begin);
            break;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64:
            uc_reg_write(uc, UC_ARM64_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_MIPS
        case UC_ARCH_MIPS:
            // TODO: MIPS32/MIPS64/BIGENDIAN etc
            uc_reg_write(uc, UC_MIPS_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV:
            uc_reg_write(uc, UC_RISCV_REG_PC, &begin);
            break;
#endif
#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC:
            // TODO: Sparc/Sparc64
            uc_reg_write(uc, UC_SPARC_REG_PC, &begin);
            break;
#endif
    }

#if 0
    // remove count hook if counting isn't necessary
    // remove hooks as soon as we are not single stepping anymore
    //if (count <= 0 && uc->count_hook != 0) {
    if (count != 1 && uc->count_hook != 0) {
        uc_hook_del(uc, uc->count_hook);
        uc->count_hook = 0;
    }
    // set up count hook to count instructions.
    // JHW: only include hooks if we are single stepping
    //if (count == 0 && uc->count_hook == 0) {
    if (count == 1 && uc->count_hook == 0) {
        uc_err err;
        // callback to count instructions must be run before everything else,
        // so instead of appending, we must insert the hook at the begin
        // of the hook list
        uc->hook_insert = 1;
        err = uc_hook_add(uc, &uc->count_hook, UC_HOOK_CODE, hook_count_cb, NULL, 1, 0);
        // restore to append mode for uc_hook_add()
        uc->hook_insert = 0;
        if (err != UC_ERR_OK) {
            return err;
        }
    }
#endif

    uc->stop_request = false;
    uc->addr_end = until;
    uc->cpu->singlestep_enabled = (count == 1);

    if (uc->setup_once) {
        uc->setup_once(uc->cpu);
        uc->setup_once = NULL;
    }

    if (timeout)
        enable_emu_timer(uc, timeout * 1000);   // microseconds -> nanoseconds

    uc->is_running = true;
    int res = uc->vm_start(uc);
    uc->is_running = false;

    if (res != 0)
        return UC_ERR_RESOURCE;

    // emulation is done
    uc->emulation_done = true;

    if (timeout) {
        // wait for the timer to finish
        qemu_thread_join(&uc->timer);
    }

    if (uc->invalid_error == UC_ERR_OK && uc->cpu->is_idle)
        uc->invalid_error = UC_ERR_YIELD;

    return uc->invalid_error;
}

UNICORN_EXPORT
uc_err uc_emu_stop(uc_engine *uc)
{
    if (uc->emulation_done)
        return UC_ERR_OK;

    uc->stop_request = true;
    // TODO: make this atomic somehow?
    if (uc->current_cpu) {
        // exit the current TB
        cpu_exit(uc->current_cpu);
    }

    return UC_ERR_OK;
}

// find if a memory range overlaps with existing mapped regions
static bool memory_overlap(struct uc_struct *uc, uint64_t begin, size_t size)
{
    unsigned int i;
    uint64_t end = begin + size - 1;

    for(i = 0; i < uc->mapped_block_count; i++) {
        // begin address falls inside this region?
        if (begin >= uc->mapped_blocks[i]->addr && begin <= uc->mapped_blocks[i]->end - 1)
            return true;

        // end address falls inside this region?
        if (end >= uc->mapped_blocks[i]->addr && end <= uc->mapped_blocks[i]->end - 1)
            return true;

        // this region falls totally inside this range?
        if (begin < uc->mapped_blocks[i]->addr && end > uc->mapped_blocks[i]->end - 1)
            return true;
    }

    // not found
    return false;
}

// common setup/error checking shared between uc_mem_map and uc_mem_map_ptr
static uc_err mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, MemoryRegion *block)
{
    MemoryRegion **regions;

    if (block == NULL)
        return UC_ERR_NOMEM;

    if ((uc->mapped_block_count & (MEM_BLOCK_INCR - 1)) == 0) {  //time to grow
        regions = (MemoryRegion**)g_realloc(uc->mapped_blocks,
                sizeof(MemoryRegion*) * (uc->mapped_block_count + MEM_BLOCK_INCR));
        if (regions == NULL) {
            return UC_ERR_NOMEM;
        }
        uc->mapped_blocks = regions;
    }

    uc->mapped_blocks[uc->mapped_block_count] = block;
    uc->mapped_block_count++;

    return UC_ERR_OK;
}

static uc_err mem_map_check(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    if (size == 0)
        // invalid memory mapping
        return UC_ERR_ARG;

    // address cannot wrapp around
    if (address + size - 1 < address)
        return UC_ERR_ARG;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0)
        return UC_ERR_ARG;

    // this area overlaps existing mapped regions?
    if (memory_overlap(uc, address, size)) {
        return UC_ERR_MAP;
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms)
{
    uc_err res;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    res = mem_map_check(uc, address, size, perms);
    if (res)
        return res;

    return mem_map(uc, address, size, perms, uc->memory_map(uc, address, size, perms));
}

UNICORN_EXPORT
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr)
{
    uc_err res;

    if (ptr == NULL)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

//    res = mem_map_check(uc, address, size, perms);
//    if (res)
//        return res;

    return mem_map(uc, address, size, UC_PROT_ALL, uc->memory_map_ptr(uc, address, size, perms, ptr));
}

// Create a backup copy of the indicated MemoryRegion.
// Generally used in prepartion for splitting a MemoryRegion.
static uint8_t *copy_region(struct uc_struct *uc, MemoryRegion *mr)
{
    uint8_t *block = (uint8_t *)g_malloc0((size_t)int128_get64(mr->size));
    if (block != NULL) {
        uc_err err = uc_mem_read(uc, mr->addr, block, (size_t)int128_get64(mr->size));
        if (err != UC_ERR_OK) {
            free(block);
            block = NULL;
        }
    }

    return block;
}

/*
   Split the given MemoryRegion at the indicated address for the indicated size
   this may result in the create of up to 3 spanning sections. If the delete
   parameter is true, the no new section will be created to replace the indicate
   range. This functions exists to support uc_mem_protect and uc_mem_unmap.

   This is a static function and callers have already done some preliminary
   parameter validation.

   The do_delete argument indicates that we are being called to support
   uc_mem_unmap. In this case we save some time by choosing NOT to remap
   the areas that are intended to get unmapped
 */
// TODO: investigate whether qemu region manipulation functions already offered
// this capability
static bool split_region(struct uc_struct *uc, MemoryRegion *mr, uint64_t address,
        size_t size, bool do_delete)
{
    uint8_t *backup;
    uint32_t perms;
    uint64_t begin, end, chunk_end;
    size_t l_size, m_size, r_size;

    chunk_end = address + size;

    // if this region belongs to area [address, address+size],
    // then there is no work to do.
    if (address <= mr->addr && chunk_end >= mr->end)
        return true;

    if (size == 0)
        // trivial case
        return true;

    if (address >= mr->end || chunk_end <= mr->addr)
        // impossible case
        return false;

    backup = copy_region(uc, mr);
    if (backup == NULL)
        return false;

    // save the essential information required for the split before mr gets deleted
    perms = mr->perms;
    begin = mr->addr;
    end = mr->end;

    // unmap this region first, then do split it later
    if (uc_mem_unmap(uc, mr->addr, (size_t)int128_get64(mr->size)) != UC_ERR_OK)
        goto error;

    /* overlapping cases
     *               |------mr------|
     * case 1    |---size--|
     * case 2           |--size--|
     * case 3                  |---size--|
     */

    // adjust some things
    if (address < begin)
        address = begin;
    if (chunk_end > end)
        chunk_end = end;

    // compute sub region sizes
    l_size = (size_t)(address - begin);
    r_size = (size_t)(end - chunk_end);
    m_size = (size_t)(chunk_end - address);

    // If there are error in any of the below operations, things are too far gone
    // at that point to recover. Could try to remap orignal region, but these smaller
    // allocation just failed so no guarantee that we can recover the original
    // allocation at this point
    if (l_size > 0) {
        if (uc_mem_map(uc, begin, l_size, perms) != UC_ERR_OK)
            goto error;
        if (uc_mem_write(uc, begin, backup, l_size) != UC_ERR_OK)
            goto error;
    }

    if (m_size > 0 && !do_delete) {
        if (uc_mem_map(uc, address, m_size, perms) != UC_ERR_OK)
            goto error;
        if (uc_mem_write(uc, address, backup + l_size, m_size) != UC_ERR_OK)
            goto error;
    }

    if (r_size > 0) {
        if (uc_mem_map(uc, chunk_end, r_size, perms) != UC_ERR_OK)
            goto error;
        if (uc_mem_write(uc, chunk_end, backup + l_size + m_size, r_size) != UC_ERR_OK)
            goto error;
    }

    free(backup);
    return true;

error:
    free(backup);
    return false;
}

UNICORN_EXPORT
uc_err uc_mem_protect(struct uc_struct *uc, uint64_t address, size_t size, uint32_t perms)
{
    MemoryRegion *mr;
    uint64_t addr = address;
    size_t count, len;
    bool remove_exec = false;

    if (size == 0)
        // trivial case, no change
        return UC_ERR_OK;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // check for only valid permissions
    if ((perms & ~UC_PROT_ALL) != 0)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size))
        return UC_ERR_NOMEM;

    // Now we know entire region is mapped, so change permissions
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, false))
            return UC_ERR_NOMEM;

        mr = memory_mapping(uc, addr);
        // will this remove EXEC permission?
        if (((mr->perms & UC_PROT_EXEC) != 0) && ((perms & UC_PROT_EXEC) == 0))
            remove_exec = true;
        mr->perms = perms;
        uc->readonly_mem(mr, (perms & UC_PROT_WRITE) == 0);

        count += len;
        addr += len;
    }

    // if EXEC permission is removed, then quit TB and continue at the same place
    if (remove_exec) {
        uc->quit_request = true;
        uc_emu_stop(uc);
    }

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_mem_unmap(struct uc_struct *uc, uint64_t address, size_t size)
{
    MemoryRegion *mr;
    uint64_t addr;
    size_t count, len;

    if (size == 0)
        // nothing to unmap
        return UC_ERR_OK;

    // address must be aligned to uc->target_page_size
    if ((address & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    // size must be multiple of uc->target_page_size
    if ((size & uc->target_page_align) != 0)
        return UC_ERR_ARG;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // check that user's entire requested block is mapped
    if (!check_mem_area(uc, address, size))
        return UC_ERR_NOMEM;

    // Now we know entire region is mapped, so do the unmap
    // We may need to split regions if this area spans adjacent regions
    addr = address;
    count = 0;
    while(count < size) {
        mr = memory_mapping(uc, addr);
        len = (size_t)MIN(size - count, mr->end - addr);
        if (!split_region(uc, mr, addr, len, true))
            return UC_ERR_NOMEM;

        // if we can retrieve the mapping, then no splitting took place
        // so unmap here
        mr = memory_mapping(uc, addr);
        if (mr != NULL)
           uc->memory_unmap(uc, mr);
        count += len;
        addr += len;
    }

    return UC_ERR_OK;
}

// find the memory region of this address
MemoryRegion *memory_mapping(struct uc_struct* uc, uint64_t address)
{
    unsigned int i;

    if (uc->mapped_block_count == 0)
        return NULL;

    if (uc->mem_redirect) {
        address = uc->mem_redirect(address);
    }

    // try with the cache index first
    i = uc->mapped_block_cache_index;

    if (i < uc->mapped_block_count && address >= uc->mapped_blocks[i]->addr && address < uc->mapped_blocks[i]->end)
        return uc->mapped_blocks[i];

    for(i = 0; i < uc->mapped_block_count; i++) {
        if (address >= uc->mapped_blocks[i]->addr && address <= uc->mapped_blocks[i]->end - 1) {
            // cache this index for the next query
            uc->mapped_block_cache_index = i;
            return uc->mapped_blocks[i];
        }
    }

    // not found
    return NULL;
}

UNICORN_EXPORT
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
        void *user_data, uint64_t begin, uint64_t end, ...)
{
    int ret = UC_ERR_OK;
    int i = 0;

    struct hook *hook = calloc(1, sizeof(struct hook));
    if (hook == NULL) {
        return UC_ERR_NOMEM;
    }

    hook->begin = begin;
    hook->end = end;
    hook->type = type;
    hook->callback = callback;
    hook->user_data = user_data;
    hook->refs = 0;
    *hh = (uc_hook)hook;

    // UC_HOOK_INSN has an extra argument for instruction ID
    if (type & UC_HOOK_INSN) {
        va_list valist;

        va_start(valist, end);
        hook->insn = va_arg(valist, int);
        va_end(valist);

        if (uc->insn_hook_validate) {
            if (! uc->insn_hook_validate(hook->insn)) {
                free(hook);
                return UC_ERR_HOOK;
            }
        }

        if (uc->hook_insert) {
            if (list_insert(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return UC_ERR_NOMEM;
            }
        } else {
            if (list_append(&uc->hook[UC_HOOK_INSN_IDX], hook) == NULL) {
                free(hook);
                return UC_ERR_NOMEM;
            }
        }

        hook->refs++;
        return UC_ERR_OK;
    }

    while ((type >> i) > 0) {
        if ((type >> i) & 1) {
            // TODO: invalid hook error?
            if (i < UC_HOOK_MAX) {
                if (uc->hook_insert) {
                    if (list_insert(&uc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return UC_ERR_NOMEM;
                    }
                } else {
                    if (list_append(&uc->hook[i], hook) == NULL) {
                        if (hook->refs == 0) {
                            free(hook);
                        }
                        return UC_ERR_NOMEM;
                    }
                }
                hook->refs++;
            }
        }
        i++;
    }

    // we didn't use the hook
    // TODO: return an error?
    if (hook->refs == 0) {
        free(hook);
    }

    return ret;
}

UNICORN_EXPORT
uc_err uc_hook_del(uc_engine *uc, uc_hook hh)
{
    int i;
    struct hook *hook = (struct hook *)hh;
    // we can't dereference hook->type if hook is invalid
    // so for now we need to iterate over all possible types to remove the hook
    // which is less efficient
    // an optimization would be to align the hook pointer
    // and store the type mask in the hook pointer.
    for (i = 0; i < UC_HOOK_MAX; i++) {
        if (list_remove(&uc->hook[i], (void *)hook)) {
            if (--hook->refs == 0) {
                free(hook);
                break;
            }
        }
    }
    return UC_ERR_OK;
}

// TCG helper
void helper_uc_tracecode(int32_t size, uc_hook_type type, void *handle, int64_t address);
void helper_uc_tracecode(int32_t size, uc_hook_type type, void *handle, int64_t address)
{
    struct uc_struct *uc = handle;
    struct list_item *cur = uc->hook[type].head;
    struct hook *hook;

    // sync PC in CPUArchState with address
    if (uc->set_pc) {
        uc->set_pc(uc, address);
    }

    while (cur != NULL && !uc->stop_request) {
        hook = (struct hook *)cur->data;
        if (HOOK_BOUND_CHECK(hook, (uint64_t)address)) {
            ((uc_cb_hookcode_t)hook->callback)(uc, address, size, hook->user_data);
        }
        cur = cur->next;
    }
}

UNICORN_EXPORT
uint32_t uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count)
{
    uint32_t i;
    uc_mem_region *r = NULL;

    *count = uc->mapped_block_count;

    if (*count) {
        r = g_malloc0(*count * sizeof(uc_mem_region));
        if (r == NULL) {
            // out of memory
            return UC_ERR_NOMEM;
        }
    }

    for (i = 0; i < *count; i++) {
        r[i].begin = uc->mapped_blocks[i]->addr;
        r[i].end = uc->mapped_blocks[i]->end - 1;
        r[i].perms = uc->mapped_blocks[i]->perms;
    }

    *regions = r;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result)
{
    if (type == UC_QUERY_PAGE_SIZE) {
        *result = uc->target_page_size;
        return UC_ERR_OK;
    }

    if (type == UC_QUERY_ARCH) {
        *result = uc->arch;
        return UC_ERR_OK;
    }

    switch(uc->arch) {
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:
            return uc->query(uc, type, result);
#endif
        default:
            return UC_ERR_ARG;
    }

    return UC_ERR_OK;
}

static size_t cpu_context_size(uc_arch arch, uc_mode mode)
{
    // each of these constants is defined by offsetof(CPUXYZState, tlb_table)
    // tbl_table is the first entry in the CPU_COMMON macro, so it marks the end
    // of the interesting CPU registers
    switch (arch) {
#ifdef UNICORN_HAS_M68K
        case UC_ARCH_M68K:  return M68K_REGS_STORAGE_SIZE;
#endif
#ifdef UNICORN_HAS_X86
        case UC_ARCH_X86:   return X86_REGS_STORAGE_SIZE;
#endif
#ifdef UNICORN_HAS_ARM
        case UC_ARCH_ARM:   return /*mode & UC_MODE_BIG_ENDIAN ? ARM_REGS_STORAGE_SIZE_armeb :*/ ARM_REGS_STORAGE_SIZE_arm;
#endif
#ifdef UNICORN_HAS_ARM64
        case UC_ARCH_ARM64: return /*mode & UC_MODE_BIG_ENDIAN ? ARM64_REGS_STORAGE_SIZE_aarch64eb :*/ ARM64_REGS_STORAGE_SIZE_aarch64;
#endif
#ifdef UNICORN_HAS_MIPS
        case UC_ARCH_MIPS:
            if (mode & UC_MODE_MIPS64) {
                if (mode & UC_MODE_BIG_ENDIAN) {
                    return MIPS64_REGS_STORAGE_SIZE_mips64;
                } else {
                    return MIPS64_REGS_STORAGE_SIZE_mips64el;
                }
            } else {
                if (mode & UC_MODE_BIG_ENDIAN) {
                    return MIPS_REGS_STORAGE_SIZE_mips;
                } else {
                    return MIPS_REGS_STORAGE_SIZE_mipsel;
                }
            }
#endif
#ifdef UNICORN_HAS_RISCV
        case UC_ARCH_RISCV:
            if (mode & UC_MODE_RISCV64) {
                return RISCV64_REGS_STORAGE_SIZE_riscv64;
            }
            return RISCV32_REGS_STORAGE_SIZE_riscv32;
#endif
#ifdef UNICORN_HAS_SPARC
        case UC_ARCH_SPARC: return mode & UC_MODE_SPARC64 ? SPARC64_REGS_STORAGE_SIZE : SPARC_REGS_STORAGE_SIZE;
#endif
        default: return 0;
    }
}

UNICORN_EXPORT
uc_err uc_context_alloc(uc_engine *uc, uc_context **context)
{
    struct uc_context **_context = context;
    size_t size = cpu_context_size(uc->arch, uc->mode);

    *_context = malloc(size + sizeof(uc_context));
    if (*_context) {
        (*_context)->size = size;
        return UC_ERR_OK;
    } else {
        return UC_ERR_NOMEM;
    }
}

UNICORN_EXPORT
uc_err uc_free(void *mem)
{
    g_free(mem);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_save(uc_engine *uc, uc_context *context)
{
    struct uc_context *_context = context;
    memcpy(_context->data, uc->cpu->env_ptr, _context->size);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_context_restore(uc_engine *uc, uc_context *context)
{
    struct uc_context *_context = context;
    memcpy(uc->cpu->env_ptr, _context->data, _context->size);
    return UC_ERR_OK;
}

UNICORN_EXPORT
size_t uc_instruction_count(uc_engine *uc) {
    return uc->cpu->insn_count;
}

UNICORN_EXPORT
uc_err uc_mem_map_io(uc_engine *uc, uint64_t addr, size_t size,
                     uc_cb_mmio_t callback, void* opaque)
{

    uc_err res;
    uc_mmio_region_t *ops;

    if (callback == NULL)
        return UC_ERR_ARG;

    if (uc->mem_redirect)
        addr = uc->mem_redirect(addr);

//    res = mem_map_check(uc, addr, size, UC_PROT_ALL);
//    if (res)
//        return res;

    ops = g_new(uc_mmio_region_t, 1);
    ops->user_data = opaque;
    ops->callback = callback;
    ops->region = uc->memory_map_mmio(uc, addr, size, ops);

    ops->next = uc->mmios;
    ops->prev = NULL;

    if (uc->mmios)
        uc->mmios->prev = ops;
    uc->mmios = ops;

    return mem_map(uc, addr, size, UC_PROT_ALL, ops->region);
}

UNICORN_EXPORT
uc_err uc_mem_map_portio(uc_engine *uc, uc_cb_mmio_t callback, void *opaque)
{
    if (!uc || !callback)
        return UC_ERR_ARG;

    uc->uc_portio_func = callback;
    uc->uc_portio_opaque = opaque;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_tb_flush(uc_engine *uc) {
    if (!uc || !uc->tb_flush)
        return UC_ERR_ARG;
    uc->tb_flush(uc->cpu);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_tb_flush_page(uc_engine *uc, uint64_t start, uint64_t end) {
    if (!uc || !uc->tb_flush_page)
        return UC_ERR_ARG;
    uc->tb_flush_page(uc->cpu, start, end);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_tlb_flush(uc_engine *uc) {
    if (!uc || !uc->tlb_flush)
        return UC_ERR_ARG;
    uc->tlb_flush(uc->cpu);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_tlb_flush_page(uc_engine *uc, uint64_t addr) {
    if (!uc || !uc->tlb_flush_page)
        return UC_ERR_ARG;
    uc->tlb_flush_page(uc->cpu, addr);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_tlb_flush_mmuidx(uc_engine *uc, uint16_t idxmap) {
    if (!uc || !uc->tlb_flush_mmuidx)
        return UC_ERR_ARG;
    uc->tlb_flush_mmuidx(uc->cpu, idxmap);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_tlb_flush_page_mmuidx(uc_engine *uc, uint64_t addr, uint16_t idxmap) {
    if (!uc || !uc->tlb_flush_page_mmuidx)
        return UC_ERR_ARG;
    uc->tlb_flush_page_mmuidx(uc->cpu, addr, idxmap);
    return UC_ERR_OK;
}

uc_err uc_register_tlb_cluster(uc_engine *uc, void *opaque,
    uc_tlb_cluster_flush_t             tlb_cluster_flush_fn,
    uc_tlb_cluster_flush_page_t        tlb_cluster_flush_page_fn,
    uc_tlb_cluster_flush_mmuidx_t      tlb_cluster_flush_mmuidx_fn,
    uc_tlb_cluster_flush_page_mmuidx_t tlb_cluster_flush_page_mmuidx_fn) {
    uc->uc_tlb_cluster_flush = tlb_cluster_flush_fn;
    uc->uc_tlb_cluster_flush_page = tlb_cluster_flush_page_fn;
    uc->uc_tlb_cluster_flush_mmuidx = tlb_cluster_flush_mmuidx_fn;
    uc->uc_tlb_cluster_flush_page_mmuidx = tlb_cluster_flush_page_mmuidx_fn;
    uc->uc_tlb_cluster_opaque = opaque;
    return UC_ERR_OK;
}

static uc_err __uc_breakpoint_insert(uc_engine *uc, uint64_t addr, int flags) {
    if (!uc->breakpoint_insert(uc->cpu, addr, flags, NULL))
        return UC_ERR_OK;
    return UC_ERR_ARG;
}

static uc_err __uc_breakpoint_remove(uc_engine *uc, uint64_t addr, int flags) {
    if (!uc->breakpoint_remove(uc->cpu, addr, flags))
        return UC_ERR_OK;
    return UC_ERR_ARG;
}

UNICORN_EXPORT
uc_err uc_breakpoint_insert(uc_engine *uc, uint64_t addr) {
    uc->is_debug = true;
    uc_err ret = __uc_breakpoint_insert(uc, addr, BP_GDB);
    uc->is_debug = false;
    return ret;
}

UNICORN_EXPORT
uc_err uc_breakpoint_remove(uc_engine *uc, uint64_t addr) {
    uc->is_debug = true;
    uc_err ret = __uc_breakpoint_remove(uc, addr, BP_GDB);
    uc->is_debug = false;
    return ret;
}


UNICORN_EXPORT
uc_err uc_cbbreakpoint_setup(uc_engine *uc, void *p, uc_breakpoint_hit_t fn) {
    uc->uc_breakpoint_opaque = p;
    uc->uc_breakpoint_func = fn;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_cbbreakpoint_insert(uc_engine *uc, uint64_t addr) {
    uc->is_debug = true;
    uc_err ret = __uc_breakpoint_insert(uc, addr, BP_CALL);
    uc->is_debug = false;
    return ret;
}

UNICORN_EXPORT
uc_err uc_cbbreakpoint_remove(uc_engine *uc, uint64_t addr) {
    uc->is_debug = true;
    uc_err ret = __uc_breakpoint_remove(uc, addr, BP_CALL);
    uc->is_debug = false;
    return ret;
}

static int __uc_convert_watchpoint_flags(int flags) {
    int qemu_flags = 0;
    if (flags & UC_WP_READ)
        qemu_flags |= BP_MEM_READ;
    if (flags & UC_WP_WRITE)
        qemu_flags |= BP_MEM_WRITE;
    if (flags & UC_WP_BEFORE)
        qemu_flags |= BP_STOP_BEFORE_ACCESS;
    if (flags & UC_WP_CALL)
        qemu_flags |= BP_CALL;

    return qemu_flags;
}

static uc_err __uc_watchpoint_insert(uc_engine *uc, uint64_t addr, size_t size, int flags) {
    int qemu_flags = __uc_convert_watchpoint_flags(flags);

    if (!uc->watchpoint_insert(uc->cpu, addr, size, qemu_flags, NULL))
        return UC_ERR_OK;

    return UC_ERR_ARG;
}

static uc_err __uc_watchpoint_remove(uc_engine *uc, uint64_t addr, size_t size, int flags) {
    int qemu_flags = __uc_convert_watchpoint_flags(flags);

    if (!uc->watchpoint_remove(uc->cpu, addr, size, qemu_flags))
        return UC_ERR_OK;

    return UC_ERR_ARG;
}

UNICORN_EXPORT
uc_err uc_watchpoint_insert(uc_engine *uc, uint64_t addr, size_t size, int flags) {
    uc->is_debug = true;
    uc_err ret = __uc_watchpoint_insert(uc, addr, size, flags);
    uc->is_debug = false;
    return ret;
}

UNICORN_EXPORT
uc_err uc_watchpoint_remove(uc_engine *uc, uint64_t addr, size_t size, int flags) {
    uc->is_debug = true;
    uc_err ret = __uc_watchpoint_remove(uc, addr, size, flags);
    uc->is_debug = false;
    return ret;
}

UNICORN_EXPORT
uc_err uc_cbwatchpoint_setup(uc_engine *uc, void *ptr, uc_watchpoint_hit_t f) {
    uc->uc_watchpoint_opaque = ptr;
    uc->uc_watchpoint_func = f;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_cbwatchpoint_insert(uc_engine *uc, uint64_t addr, size_t size, int flags) {
    return uc_watchpoint_insert(uc, addr, size, flags | UC_WP_CALL);
}

UNICORN_EXPORT
uc_err uc_cbwatchpoint_remove(uc_engine *uc, uint64_t addr, size_t size, int flags) {
    uc->is_debug = true;
    uc_err ret = __uc_watchpoint_remove(uc, addr, size, flags | UC_WP_CALL);
    uc->is_debug = false;
    return ret;
}

UNICORN_EXPORT
uc_err uc_interrupt(uc_engine *uc, int irqid, int set) {
    CPUClass *cc = CPU_GET_CLASS(uc, uc->cpu);
    cc->set_irq(uc->cpu, irqid, set);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_va2pa(uc_engine *uc, uint64_t va, uint64_t *pa) {
    if (pa == NULL)
        return UC_ERR_ARG;

    CPUClass *cc = CPU_GET_CLASS(uc, uc->cpu);
    MemTxAttrs attrs = { 0 };

    // Translating virtual addresses might cause QEMU to perform memory
    // accesses, which are routed through the regular memory API and can
    // invoke our transaction callback. There is currently no way to
    // annotate debugger accesses in this API, so we mark this via our
    // unicorn global state struct.
    uc->is_debug = true;

    // This debug call just causes potential faults to be ignored, but does
    // not annotate its nature to the memory API that it uses.
    uint64_t addr = cc->get_phys_page_attrs_debug(uc->cpu, va, &attrs);

    uc->is_debug = false;

    if (addr == ~0)
        return UC_ERR_NOMEM;

    *pa = addr;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_setup_timer(uc_engine *uc, void *opaque, uc_timer_timefunc_t timefn,
                      uc_timer_irqfunc_t irqfn, uc_timer_schedule_t schedfn) {
    if (timefn == NULL || irqfn == NULL || schedfn == NULL)
        return UC_ERR_ARG;

    uc->timer_timefunc = timefn;
    uc->timer_irqfunc = irqfn;
    uc->timer_schedule = schedfn;
    uc->timer_opaque = opaque;
    uc->timer_initialized = true;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_update_timer(uc_engine *uc, int timeridx) {
    if (!uc->timer_recalc)
        return UC_ERR_ARG;
    uc->timer_recalc(uc->cpu, timeridx);
    return UC_ERR_OK;
}

UNICORN_EXPORT
bool uc_is_idle(uc_engine *uc) {
    if (!uc)
        return false;
    return uc->cpu->is_idle;
}

UNICORN_EXPORT
bool uc_is_debug(uc_engine *uc) {
    if (!uc)
        return false;
    return uc->is_debug;
}

UNICORN_EXPORT
bool uc_is_excl(uc_engine *uc) {
    if (!uc)
        return false;
    return uc->is_excl;
}

UNICORN_EXPORT
uc_err uc_clear_excl(uc_engine *uc) {
    if (!uc || !uc->is_excl)
        return UC_ERR_RESOURCE;
    uc->is_excl = false;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_setup_dmi(uc_engine *uc, void *opaque, uc_cb_dmiptr_t dmifn) {
    if (uc == NULL || dmifn == NULL)
        return UC_ERR_ARG;

    uc->get_dmi_ptr = dmifn;
    uc->dmi_opaque = opaque;

    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_dmi_invalidate(uc_engine *uc, uint64_t start, uint64_t end) {
    if (uc == NULL)
        return UC_ERR_ARG;

    if (uc->inv_dmi_ptr == NULL)
        return UC_ERR_INTERNAL;

    uc->inv_dmi_ptr(uc->cpu, start, end);
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_setup_hint(uc_engine *uc, void *opaque, uc_hintfunc_t fn) {
    if (uc == NULL)
        return UC_ERR_ARG;

    uc->uc_hint_opaque = opaque;
    uc->uc_hint_func = fn;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_setup_semihosting(uc_engine *uc, void* opaque, uc_shfunc_t fn) {
    if (uc == NULL)
        return UC_ERR_ARG;

    uc->uc_semihost_opaque = opaque;
    uc->uc_semihost_func = fn;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_setup_basic_block_trace(uc_engine *uc, void *opaque,
                                  uc_trace_basic_block_t fn) {
    if (uc == NULL)
        return UC_ERR_ARG;

    if (uc->uc_trace_bb_func != fn)
        uc_tb_flush(uc);

    uc->uc_trace_bb_opaque = opaque;
    uc->uc_trace_bb_func = fn;
    return UC_ERR_OK;
}

UNICORN_EXPORT
uc_err uc_reset_cpu(uc_engine *uc) {
    CPUClass *cc = CPU_GET_CLASS(uc, uc->cpu);
    cc->reset(uc->cpu);
    return UC_ERR_OK;
}

UNICORN_EXPORT
bool uc_is_running(uc_engine *uc) {
    if (!uc || !uc->is_running)
        return false;
    return true;
}
