#ifndef UNICORN_COMMON_H_
#define UNICORN_COMMON_H_

#include "tcg.h"

// This header define common patterns/codes that will be included in all arch-sepcific
// codes for unicorns purposes.

// return true on success, false on failure
static inline bool cpu_physical_mem_read(AddressSpace *as, hwaddr addr,
                                            uint8_t *buf, int len)
{
    return cpu_physical_memory_rw(as, addr, (void *)buf, len, 0);
}

static inline bool cpu_physical_mem_write(AddressSpace *as, hwaddr addr,
                                            const uint8_t *buf, int len)
{
    return cpu_physical_memory_rw(as, addr, (void *)buf, len, 1);
}

void tb_cleanup(struct uc_struct *uc);
void free_code_gen_buffer(struct uc_struct *uc);

static inline void free_address_spaces(struct uc_struct *uc)
{
    int i;

    address_space_destroy(&uc->as);
    for (i = 0; i < uc->cpu->num_ases; i++) {
        AddressSpace *as = uc->cpu->cpu_ases[i].as;
        address_space_destroy(as);
        g_free(as);
    }
}

/* This is *supposed* to be done by the class finalizer but it never executes */
static inline void free_machine_class_name(struct uc_struct *uc) {
    MachineClass *mc = MACHINE_GET_CLASS(uc, uc->machine_state);

    g_free(mc->name);
    mc->name = NULL;
}

static inline void free_tcg_temp_names(TCGContext *s)
{
#if TCG_TARGET_REG_BITS == 32
    int i;

    for (i = 0; i < s->nb_globals; i++) {
        TCGTemp *ts = &s->temps[i];
        if (ts->base_type == TCG_TYPE_I64) {
            if (ts->name && ((strcmp(ts->name+(strlen(ts->name)-2), "_0") == 0) ||
                        (strcmp(ts->name+(strlen(ts->name)-2), "_1") == 0))) {
                free((void *)ts->name);
            }
        }
    }
#endif
}

// SNPS added
void tb_invalidate_phys_range(struct uc_struct *uc, tb_page_addr_t start,
                              tb_page_addr_t end);

static inline void tb_flush_page(CPUState* cpu,  uint64_t start,
                                 uint64_t end)
{
    uc_engine *uc = cpu->uc;
    tb_invalidate_phys_range(uc, start, end);
}

/** Freeing common resources */
static void release_common(void *t)
{
    TCGPool *po, *to;
    TCGContext *s = (TCGContext *)t;

    // Clean TCG.
    TCGOpDef* def = &s->tcg_op_defs[0];
    g_free(def->args_ct);
    //g_free(def->sorted_args); // SNPS removed
    g_free(s->tcg_op_defs);

    for (po = s->pool_first; po; po = to) {
        to = po->next;
        g_free(po);
    }
    tcg_pool_reset(s);
    g_hash_table_destroy(s->helpers);

    // Destory flat view hash table
    g_hash_table_destroy(s->uc->flat_views);
    unicorn_free_empty_flat_view(s->uc);

    // TODO(danghvu): these function is not available outside qemu
    // so we keep them here instead of outside uc_close.
    free_address_spaces(s->uc);
    memory_free(s->uc);
    tb_cleanup(s->uc);
    free_code_gen_buffer(s->uc);
    free_machine_class_name(s->uc);
    free_tcg_temp_names(s);
}

static inline void uc_common_init(struct uc_struct* uc)
{
    memory_register_types(uc);
    uc->write_mem = cpu_physical_mem_write;
    uc->read_mem = cpu_physical_mem_read;
    uc->tcg_enabled = tcg_enabled;
    uc->tcg_exec_init = tcg_exec_init;
    uc->cpu_exec_init_all = cpu_exec_init_all;
    uc->cpu_exec_exit = cpu_exec_exit;
    uc->vm_start = vm_start;

    uc->tb_flush = tb_flush; // SNPS added
    uc->tb_flush_page = tb_flush_page; // SNPS added

    uc->inv_dmi_ptr = dmi_invalidate; // SNPS added

    uc->tlb_flush = tlb_flush; // SNPS added
    uc->tlb_flush_page = tlb_flush_page; // SNPS added
    uc->tlb_flush_mmuidx = tlb_flush_by_mmuidx; // SNPS added
    uc->tlb_flush_page_mmuidx = tlb_flush_page_by_mmuidx; // SNPS added

    uc->breakpoint_insert = cpu_breakpoint_insert; // SNPS added
    uc->breakpoint_remove = cpu_breakpoint_remove; // SNPS added
    uc->watchpoint_insert = cpu_watchpoint_insert; // SNPS added
    uc->watchpoint_remove = cpu_watchpoint_remove; // SNPS added

    uc->memory_map = memory_map;
    uc->memory_map_ptr = memory_map_ptr;
    uc->memory_map_mmio = memory_map_io; // SNPS added
    uc->memory_unmap = memory_unmap;
    uc->readonly_mem = memory_region_set_readonly;

    uc->target_page_size = TARGET_PAGE_SIZE;
    uc->target_page_align = TARGET_PAGE_SIZE - 1;

    uc->is_running = false; // SNPS added
    uc->is_memcb = false; // SNPS added

    if (!uc->release) {
        uc->release = release_common;
    }
}

#endif
