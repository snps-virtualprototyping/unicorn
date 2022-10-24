/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015 */

#ifndef UC_PRIV_H
#define UC_PRIV_H

#include "unicorn/platform.h"
#include <stdio.h>

#include "qemu.h"
#include "exec/ramlist.h"
#include "unicorn/unicorn.h"
#include "list.h"

// These are masks of supported modes for each cpu/arch.
// They should be updated when changes are made to the uc_mode enum typedef.
#define UC_MODE_ARM_MASK    (UC_MODE_ARM|UC_MODE_THUMB|UC_MODE_LITTLE_ENDIAN|UC_MODE_MCLASS | \
                             UC_MODE_ARM926|UC_MODE_ARM946|UC_MODE_ARM1176|UC_MODE_BIG_ENDIAN)
#define UC_MODE_M68K_MASK   (UC_MODE_BIG_ENDIAN)
#define UC_MODE_MIPS_MASK   (UC_MODE_MIPS32|UC_MODE_MIPS64|UC_MODE_LITTLE_ENDIAN|UC_MODE_BIG_ENDIAN)
#define UC_MODE_PPC_MASK    (UC_MODE_PPC64|UC_MODE_BIG_ENDIAN)
#define UC_MODE_RISCV_MASK  (UC_MODE_RISCV32|UC_MODE_RISCV64)
#define UC_MODE_SPARC_MASK  (UC_MODE_SPARC32|UC_MODE_SPARC64|UC_MODE_BIG_ENDIAN)
#define UC_MODE_X86_MASK    (UC_MODE_16|UC_MODE_32|UC_MODE_64|UC_MODE_LITTLE_ENDIAN)

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

#define READ_QWORD(x) ((uint64_t)x)
#define READ_DWORD(x) (x & 0xffffffff)
#define READ_WORD(x) (x & 0xffff)
#define READ_BYTE_H(x) ((x & 0xffff) >> 8)
#define READ_BYTE_L(x) (x & 0xff)
#define WRITE_DWORD(x, w) (x = (x & ~0xffffffffLL) | (w & 0xffffffff))
#define WRITE_WORD(x, w) (x = (x & ~0xffff) | (w & 0xffff))
#define WRITE_BYTE_H(x, b) (x = (x & ~0xff00) | ((b & 0xff) << 8))
#define WRITE_BYTE_L(x, b) (x = (x & ~0xff) | (b & 0xff))


typedef struct ModuleEntry {
    void (*init)(void);
    QTAILQ_ENTRY(ModuleEntry) node;
    module_init_type type;
} ModuleEntry;

typedef QTAILQ_HEAD(, ModuleEntry) ModuleTypeList;

typedef uc_err (*query_t)(struct uc_struct *uc, uc_query_type type, size_t *result);

// return 0 on success, -1 on failure
typedef int (*reg_read_t)(struct uc_struct *uc, unsigned int *regs, void **vals, int count);
typedef int (*reg_write_t)(struct uc_struct *uc, unsigned int *regs, void *const *vals, int count);

typedef void (*reg_reset_t)(struct uc_struct *uc);

typedef bool (*uc_write_mem_t)(AddressSpace *as, hwaddr addr, const uint8_t *buf, int len);

typedef bool (*uc_read_mem_t)(AddressSpace *as, hwaddr addr, uint8_t *buf, int len);

typedef void (*uc_args_void_t)(void*);

typedef void (*uc_args_uc_t)(struct uc_struct*);
typedef int (*uc_args_int_uc_t)(struct uc_struct*);
typedef void (*uc_cpu_exec_exit_t)(CPUState*);

typedef void (*tb_flush_t)(CPUState*); // SNPS added
typedef void (*tb_flush_page_t)(CPUState*, uint64_t,  uint64_t); // SNPS added

typedef void (*dmi_invalidate_t)(CPUState*, uint64_t, uint64_t); // SNPS added

typedef void (*tlb_flush_t)(CPUState*); // SNPS added
typedef void (*tlb_flush_page_t)(CPUState*, uint64_t); // SNPS added
typedef void (*tlb_flush_mmuidx_t)(CPUState*, uint16_t); // SNPS added
typedef void (*tlb_flush_page_mmuidx_t)(CPUState*, uint64_t, uint16_t); // SNPS added

typedef void (*tlb_cluster_flush_t)(CPUState*); // SNPS added
typedef void (*tlb_cluster_flush_page_t)(CPUState*, uint64_t); // SNPS added
typedef void (*tlb_cluster_flush_mmuidx_t)(CPUState*, uint16_t); // SNPS added
typedef void (*tlb_cluster_flush_page_mmuidx_t)(CPUState*, uint64_t, uint16_t); // SNPS added

typedef int  (*cpu_breakpoint_insert_t)(CPUState*, vaddr, int, CPUBreakpoint**); // SNPS added
typedef int  (*cpu_breakpoint_remove_t)(CPUState*, vaddr, int); // SNPS added
typedef int  (*cpu_watchpoint_insert_t)(CPUState*, vaddr, vaddr, int, CPUWatchpoint**); // SNPS added
typedef int  (*cpu_watchpoint_remove_t)(CPUState*, vaddr, vaddr, int); // SNPS added

typedef void (*uc_timer_recalc_t)(CPUState*, int); // SNPS added

typedef void (*uc_setup_once_t)(CPUState*); // SNPS added

typedef bool (*uc_args_tcg_enable_t)(struct uc_struct*);

typedef void (*uc_args_uc_long_t)(struct uc_struct*, unsigned long);

typedef void (*uc_args_uc_u64_t)(struct uc_struct *, uint64_t addr);

typedef MemoryRegion* (*uc_args_uc_ram_size_t)(struct uc_struct*,  hwaddr begin, size_t size, uint32_t perms);

typedef MemoryRegion* (*uc_args_uc_ram_size_ptr_t)(struct uc_struct*,  hwaddr begin, size_t size, uint32_t perms, void *ptr);

typedef MemoryRegion* (*uc_args_uc_mmio_size_t)(struct uc_struct*, hwaddr begin, size_t size, void* opaque); // SNPS added

typedef void (*uc_mem_unmap_t)(struct uc_struct*, MemoryRegion *mr);

typedef void (*uc_readonly_mem_t)(MemoryRegion *mr, bool readonly);

// which interrupt should make emulation stop?
typedef bool (*uc_args_int_t)(int intno);

// some architecture redirect virtual memory to physical memory like Mips
typedef uint64_t (*uc_mem_redirect_t)(uint64_t address);

// validate if Unicorn supports hooking a given instruction
typedef bool(*uc_insn_hook_validate)(uint32_t insn_enum);

struct hook {
    int type;            // UC_HOOK_*
    int insn;            // instruction for HOOK_INSN
    int refs;            // reference count to free hook stored in multiple lists
    uint64_t begin, end; // only trigger if PC or memory access is in this address (depends on hook type)
    void *callback;      // a uc_cb_* type
    void *user_data;
};

// hook list offsets
// mirrors the order of uc_hook_type from include/unicorn/unicorn.h
enum uc_hook_idx {
    UC_HOOK_INTR_IDX,
    UC_HOOK_INSN_IDX,
    UC_HOOK_CODE_IDX,
    UC_HOOK_BLOCK_IDX,
    UC_HOOK_MEM_READ_UNMAPPED_IDX,
    UC_HOOK_MEM_WRITE_UNMAPPED_IDX,
    UC_HOOK_MEM_FETCH_UNMAPPED_IDX,
    UC_HOOK_MEM_READ_PROT_IDX,
    UC_HOOK_MEM_WRITE_PROT_IDX,
    UC_HOOK_MEM_FETCH_PROT_IDX,
    UC_HOOK_MEM_READ_IDX,
    UC_HOOK_MEM_WRITE_IDX,
    UC_HOOK_MEM_FETCH_IDX,
    UC_HOOK_MEM_READ_AFTER_IDX,
    UC_HOOK_INSN_INVALID_IDX,

    UC_HOOK_MAX,
};

#define HOOK_FOREACH_VAR_DECLARE                          \
    struct list_item *cur

// for loop macro to loop over hook lists
#define HOOK_FOREACH(uc, hh, idx) while (false) // SNPS changed
//    for (                                                 \
//        cur = (uc)->hook[idx##_IDX].head;                 \
//        cur != NULL && ((hh) = (struct hook *)cur->data)  \
//            /* stop excuting callbacks on stop request */ \
//            && !uc->stop_request;                         \
//        cur = cur->next)

// if statement to check hook bounds
#define HOOK_BOUND_CHECK(hh, addr)                  \
    ((((addr) >= (hh)->begin && (addr) <= (hh)->end) \
         || (hh)->begin > (hh)->end))

#define HOOK_EXISTS(uc, idx) ((uc)->hook[idx##_IDX].head != NULL)
#define HOOK_EXISTS_BOUNDED(uc, idx, addr) _hook_exists_bounded((uc)->hook[idx##_IDX].head, addr)

static inline bool _hook_exists_bounded(struct list_item *cur, uint64_t addr)
{
    while (cur != NULL) {
        if (HOOK_BOUND_CHECK((struct hook *)cur->data, addr))
            return true;
        cur = cur->next;
    }
    return false;
}

//relloc increment, KEEP THIS A POWER OF 2!
#define MEM_BLOCK_INCR 32

struct uc_struct {
    uc_arch arch;
    uc_mode mode;
    uc_err errnum;  // qemu/cpu-exec.c
    AddressSpace as;
    query_t query;
    reg_read_t reg_read;
    reg_write_t reg_write;
    reg_reset_t reg_reset;

    uc_write_mem_t write_mem;
    uc_read_mem_t read_mem;
    uc_args_void_t release;     // release resource when uc_close()
    uc_args_uc_u64_t set_pc;  // set PC for tracecode
    uc_args_int_t stop_interrupt;   // check if the interrupt should stop emulation

    uc_args_uc_t init_arch, cpu_exec_init_all;
    uc_cpu_exec_exit_t cpu_exec_exit;
    uc_args_int_uc_t vm_start;
    uc_args_tcg_enable_t tcg_enabled;
    uc_args_uc_long_t tcg_exec_init;
    uc_args_uc_ram_size_t memory_map;
    uc_args_uc_ram_size_ptr_t memory_map_ptr;
    uc_args_uc_mmio_size_t memory_map_mmio; // SNPS added
    uc_mem_unmap_t memory_unmap;
    uc_readonly_mem_t readonly_mem;
    uc_mem_redirect_t mem_redirect;

    size_t tb_size; // SNPS added
    tb_flush_t tb_flush; // SNPS added
    tb_flush_page_t tb_flush_page; // SNPS added

    uc_cb_mmio_t uc_portio_func; // SNPS added
    void*        uc_portio_opaque; // SNPS added

    uc_cb_dmiptr_t   get_dmi_ptr; // SNPS added
    uc_cb_pgprot_t   protect_dmi_ptr; // SNPS added
    dmi_invalidate_t inv_dmi_ptr; // SNPS added
    void*            dmi_opaque; // SNPS added

    tlb_flush_t             tlb_flush; // SNPS added
    tlb_flush_page_t        tlb_flush_page; // SNPS added
    tlb_flush_mmuidx_t      tlb_flush_mmuidx; // SNPS added
    tlb_flush_page_mmuidx_t tlb_flush_page_mmuidx; // SNPS added

    tlb_cluster_flush_t             tlb_cluster_flush; // SNPS added
    tlb_cluster_flush_page_t        tlb_cluster_flush_page; // SNPS added
    tlb_cluster_flush_mmuidx_t      tlb_cluster_flush_mmuidx; // SNPS added
    tlb_cluster_flush_page_mmuidx_t tlb_cluster_flush_page_mmuidx; // SNPS added

    uc_tlb_cluster_flush_t             uc_tlb_cluster_flush; // SNPS added
    uc_tlb_cluster_flush_page_t        uc_tlb_cluster_flush_page; // SNPS added
    uc_tlb_cluster_flush_mmuidx_t      uc_tlb_cluster_flush_mmuidx; // SNPS added
    uc_tlb_cluster_flush_page_mmuidx_t uc_tlb_cluster_flush_page_mmuidx; // SNPS added
    void*                              uc_tlb_cluster_opaque; // SNPS added

    cpu_breakpoint_insert_t breakpoint_insert; // SNPS added
    cpu_breakpoint_remove_t breakpoint_remove; // SNPS added
    cpu_watchpoint_insert_t watchpoint_insert; // SNPS added
    cpu_watchpoint_remove_t watchpoint_remove; // SNPS added

    uc_breakpoint_hit_t uc_breakpoint_func; // SNPS added
    void*               uc_breakpoint_opaque; // SNPS added

    uc_watchpoint_hit_t uc_watchpoint_func; // SNPS added
    void*               uc_watchpoint_opaque; // SNPS added

    uc_hintfunc_t uc_hint_func; // SNPS added
    void*         uc_hint_opaque; // SNPS added

    uc_shfunc_t uc_semihost_func; // SNPS added
    void*       uc_semihost_opaque; // SNPS added

    uc_trace_basic_block_t uc_trace_bb_func; // SNPS added
    void*                  uc_trace_bb_opaque; // SNPS added

    uc_get_config_t uc_config_func; // SNPS added
    void*           uc_config_opaque; // SNPS added

    uc_timer_timefunc_t timer_timefunc; // SNPS added
    uc_timer_irqfunc_t  timer_irqfunc; // SNPS added
    uc_timer_schedule_t timer_schedule; // SNPS added
    uc_timer_recalc_t   timer_recalc; // SNPS added
    void*               timer_opaque; // SNPS added
    bool                timer_initialized; // SNPS added

    uc_setup_once_t setup_once; // SNPS added

    bool is_debug; // SNPS added
    bool is_excl; // SNPS added
    bool is_running; // SNPS added
    bool is_memcb; // SNPS added

    char model[80]; // SNPS added

    // TODO: remove current_cpu, as it's a flag for something else ("cpu running"?)
    CPUState *cpu, *current_cpu;

    uc_insn_hook_validate insn_hook_validate;

    // qemu/cpus.c
    bool mttcg_enabled;

    // qemu/exec.c
    MemoryRegion *system_memory;
    MemoryRegion io_mem_rom;
    MemoryRegion io_mem_notdirty;
    MemoryRegion io_mem_unassigned;
    MemoryRegion io_mem_watch;
    RAMList ram_list;
    // Renamed from "alloc_hint" in qemu.
    unsigned phys_map_node_alloc_hint;
    // Used when a target's page bits can vary
    int target_page_bits;
    bool target_page_bits_decided;

    // qemu/cpu-exec.c
    BounceBuffer bounce;
    CPUState *tcg_current_rr_cpu;

    // qemu/user-exec.c
    uintptr_t helper_retaddr;

    // qemu/memory.c
    FlatView *empty_view;
    GHashTable *flat_views;
    bool global_dirty_log;

    /* This is a multi-level map on the virtual address space.
       The bottom level has pointers to PageDesc.  */
    void **l1_map;  // qemu/translate-all.c
    size_t l1_map_size;
    int v_l1_size;
    int v_l1_shift;
    int v_l2_levels;
    uintptr_t qemu_real_host_page_size;
    intptr_t qemu_real_host_page_mask;
    uintptr_t qemu_host_page_size;
    intptr_t qemu_host_page_mask;

    /* code generation context */
    void *tcg_ctx;  // for "TCGContext tcg_ctx" in qemu/translate-all.c
    bool parallel_cpus; // for "bool parallel_cpus" in qemu/translate-all.c

    /* memory.c */
    unsigned memory_region_transaction_depth;
    bool memory_region_update_pending;
    bool ioeventfd_update_pending;
    QTAILQ_HEAD(memory_listeners, MemoryListener) memory_listeners;
    QTAILQ_HEAD(, AddressSpace) address_spaces;
    MachineState *machine_state;
    // qom/cpu.c
    bool cpu_globals_initialized;
    // qom/object.c
    GHashTable *type_table;
    Type type_interface;
    Object *root;
    Object *owner;
    bool enumerating_types;
    // util/module.c
    ModuleTypeList init_type_list[MODULE_INIT_MAX];
    // hw/intc/apic_common.c
    DeviceState *vapic;
    int apic_no;
    bool mmio_registered;
    bool apic_report_tpr_access;

    // linked lists containing hooks per type
    struct list hook[UC_HOOK_MAX];

    // hook to count number of instructions for uc_emu_start()
    uc_hook count_hook;

    size_t emu_counter; // current counter of uc_emu_start()
    size_t emu_count; // save counter of uc_emu_start()

    uint64_t block_addr;    // save the last block address we hooked

    bool init_tcg;      // already initialized local TCGv variables?
    bool stop_request;  // request to immediately stop emulation - for uc_emu_stop()
    bool quit_request;  // request to quit the current TB, but continue to emulate - for uc_mem_protect()
    bool emulation_done;  // emulation is done by uc_emu_start()
    bool timed_out;     // emulation timed out, uc_emu_start() will result in EC_ERR_TIMEOUT
    QemuThread timer;   // timer for emulation timeout
    uint64_t timeout;   // timeout for uc_emu_start()

    uint64_t invalid_addr;  // invalid address to be accessed
    int invalid_error;  // invalid memory code: 1 = READ, 2 = WRITE, 3 = CODE

    uint64_t addr_end;  // address where emulation stops (@end param of uc_emu_start())

    int thumb;  // thumb mode for ARM
    // full TCG cache leads to middle-block break in the last translation?
    bool block_full;
    int size_arg;     // what tcg arg slot do we need to update with the size of the block?
    MemoryRegion **mapped_blocks;
    uint32_t mapped_block_count;
    uint32_t mapped_block_cache_index;
    void *qemu_thread_data; // to support cross compile to Windows (qemu-thread-win32.c)
    uint32_t target_page_size;
    uint32_t target_page_align;
    uint64_t next_pc;   // save next PC for some special cases
    bool hook_insert;	// insert new hook at begin of the hook list (append by default)

    // util/cacheinfo.c
    int qemu_icache_linesize;
    int qemu_dcache_linesize;

    uc_mmio_region_t *mmios; // SNPS added
};

// Metadata stub for the variable-size cpu context used with uc_context_*()
struct uc_context {
   size_t size;
   char data[0];
};

// check if this address is mapped in (via uc_mem_map())
MemoryRegion *memory_mapping(struct uc_struct* uc, uint64_t address);

// Defined in util/cacheinfo.c. Made externally linked to
// allow calling it directly.
void init_cache_info(struct uc_struct *uc);

 // SNPS added
static inline const char* uc_get_config(struct uc_struct *uc, const char* cfg) {
    if (!uc || !uc->uc_config_func)
        return "";

    void* opaque = uc->uc_config_opaque;
    uc_get_config_t fn = uc->uc_config_func;

    const char* res = fn(opaque, cfg);
    return res ? res : "";
}

#endif
/* vim: set ts=4 noet:  */
