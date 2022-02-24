/*
 * QEMU CPU model
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <http://www.gnu.org/licenses/gpl-2.0.html>
 */
#ifndef QEMU_CPU_H
#define QEMU_CPU_H

#include "hw/qdev-core.h"
#include "exec/hwaddr.h"
#include "exec/memory.h"
#include "qemu/queue.h"
#include "qemu/thread.h"
#include "qemu/typedefs.h"

typedef int (*WriteCoreDumpFunction)(const void *buf, size_t size,
                                     void *opaque);

/**
 * vaddr:
 * Type wide enough to contain any #target_ulong virtual address.
 */
typedef uint64_t vaddr;
#define VADDR_PRId PRId64
#define VADDR_PRIu PRIu64
#define VADDR_PRIo PRIo64
#define VADDR_PRIx PRIx64
#define VADDR_PRIX PRIX64
#define VADDR_MAX UINT64_MAX

/**
 * SECTION:cpu
 * @section_id: QEMU-cpu
 * @title: CPU Class
 * @short_description: Base class for all CPUs
 */

#define TYPE_CPU "cpu"

/* Since this macro is used a lot in hot code paths and in conjunction with
 * FooCPU *foo_env_get_cpu(), we deviate from usual QOM practice by using
 * an unchecked cast.
 */
#define CPU(obj) ((CPUState *)(obj))

#define CPU_CLASS(uc, class) OBJECT_CLASS_CHECK(uc, CPUClass, (class), TYPE_CPU)
#define CPU_GET_CLASS(uc, obj) OBJECT_GET_CLASS(uc, CPUClass, (obj), TYPE_CPU)

typedef enum MMUAccessType {
    MMU_DATA_LOAD  = 0,
    MMU_DATA_STORE = 1,
    MMU_INST_FETCH = 2
} MMUAccessType;

typedef struct CPUWatchpoint CPUWatchpoint;

typedef void (*CPUUnassignedAccess)(CPUState *cpu, hwaddr addr,
                                    bool is_write, bool is_exec, int opaque,
                                    unsigned size);

struct TranslationBlock;

/**
 * struct TcgCpuOperations: TCG operations specific to a CPU class
 */
typedef struct TcgCpuOperations {
    /**
     * @initialize: Initalize TCG state
     *
     * Called when the first CPU is realized.
     */
    void (*initialize)(struct uc_struct *uc);

    /**
     * @synchronize_from_tb: Synchronize state from a TCG #TranslationBlock
     *
     * This is called when we abandon execution of a TB before starting it,
     * and must set all parts of the CPU state which the previous TB in the
     * chain may not have updated.
     * By default, when this is NULL, a call is made to @set_pc(tb->pc).
     *
     * If more state needs to be restored, the target must implement a
     * function to restore all the state, and register it here.
     */
    void (*synchronize_from_tb)(CPUState *cpu,
                                const struct TranslationBlock *tb);
    /** @cpu_exec_enter: Callback for cpu_exec preparation */
    void (*cpu_exec_enter)(CPUState *cpu);
    /** @cpu_exec_exit: Callback for cpu_exec cleanup */
    void (*cpu_exec_exit)(CPUState *cpu);
    /** @cpu_exec_interrupt: Callback for processing interrupts in cpu_exec */
    bool (*cpu_exec_interrupt)(CPUState *cpu, int interrupt_request);
    /** @do_interrupt: Callback for interrupt handling. */
    void (*do_interrupt)(CPUState *cpu);
    /**
     * @tlb_fill: Handle a softmmu tlb miss or user-only address fault
     *
     * For system mode, if the access is valid, call tlb_set_page
     * and return true; if the access is invalid, and probe is
     * true, return false; otherwise raise an exception and do
     * not return.  For user-only mode, always raise an exception
     * and do not return.
     */
    bool (*tlb_fill)(CPUState *cpu, vaddr address, int size,
                     MMUAccessType access_type, int mmu_idx,
                     bool probe, uintptr_t retaddr);
    /** @debug_excp_handler: Callback for handling debug exceptions */
    void (*debug_excp_handler)(CPUState *cpu);

    /**
     * @do_transaction_failed: Callback for handling failed memory transactions
     * (ie bus faults or external aborts; not MMU faults)
     */
    void (*do_transaction_failed)(CPUState *cpu, hwaddr physaddr, vaddr addr,
                                  unsigned size, MMUAccessType access_type,
                                  int mmu_idx, MemTxAttrs attrs,
                                  MemTxResult response, uintptr_t retaddr);
    /**
     * @do_unaligned_access: Callback for unaligned access handling
     */
    void (*do_unaligned_access)(CPUState *cpu, vaddr addr,
                                MMUAccessType access_type,
                                int mmu_idx, uintptr_t retaddr);
    /**
     * @adjust_watchpoint_address: hack for cpu_check_watchpoint used by ARM
     */
    vaddr (*adjust_watchpoint_address)(CPUState *cpu, vaddr addr, int len);

    /**
     * @debug_check_watchpoint: return true if the architectural
     * watchpoint whose address has matched should really fire, used by ARM
     */
    bool (*debug_check_watchpoint)(CPUState *cpu, CPUWatchpoint *wp);

} TcgCpuOperations;

/**
 * CPUClass:
 * @class_by_name: Callback to map -cpu command line model name to an
 * instantiatable CPU type.
 * @parse_features: Callback to parse command line arguments.
 * @reset: Callback to reset the #CPUState to its initial state.
 * @reset_dump_flags: #CPUDumpFlags to use for reset logging.
 * @has_work: Callback for checking if there is work to do.
 * @do_unassigned_access: Callback for unassigned access handling.
 * (this is deprecated: new targets should use do_transaction_failed instead)
 * @memory_rw_debug: Callback for GDB memory access.
 * @dump_state: Callback for dumping state.
 * @dump_statistics: Callback for dumping statistics.
 * @get_arch_id: Callback for getting architecture-dependent CPU ID.
 * @get_paging_enabled: Callback for inquiring whether paging is enabled.
 * @get_memory_mapping: Callback for obtaining the memory mappings.
 * @set_pc: Callback for setting the Program Counter register. This
 *       should have the semantics used by the target architecture when
 *       setting the PC from a source such as an ELF file entry point;
 *       for example on Arm it will also set the Thumb mode bit based
 *       on the least significant bit of the new PC value.
 *       If the target behaviour here is anything other than "set
 *       the PC register to the value passed in" then the target must
 *       also implement the synchronize_from_tb hook.
 * @get_phys_page_debug: Callback for obtaining a physical address.
 * @get_phys_page_attrs_debug: Callback for obtaining a physical address and the
 *       associated memory transaction attributes to use for the access.
 *       CPUs which use memory transaction attributes should implement this
 *       instead of get_phys_page_debug.
 * @asidx_from_attrs: Callback to return the CPU AddressSpace to use for
 *       a memory access with the specified memory transaction attributes.
 * @vmsd: State description for migration.
 * @adjust_watchpoint_address: Perform a target-specific adjustment to an
 * address before attempting to match it against watchpoints.
 *
 * Represents a CPU family or model.
 */
typedef struct CPUClass {
    /*< private >*/
    DeviceClass parent_class;
    /*< public >*/

    ObjectClass *(*class_by_name)(struct uc_struct *uc, const char *cpu_model);
    void (*parse_features)(struct uc_struct *uc, const char *typename, char *str, Error **errp);

    void (*set_irq)(CPUState *cpu, int irq, int level); // SNPS added
    void (*reset)(CPUState *cpu);
    int reset_dump_flags;
    bool (*has_work)(CPUState *cpu);
    CPUUnassignedAccess do_unassigned_access;
    int (*memory_rw_debug)(CPUState *cpu, vaddr addr,
                           uint8_t *buf, int len, bool is_write);
    void (*dump_state)(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                       int flags);
    void (*dump_statistics)(CPUState *cpu, FILE *f,
                            fprintf_function cpu_fprintf, int flags);
    int64_t (*get_arch_id)(CPUState *cpu);
    bool (*get_paging_enabled)(const CPUState *cpu);
    void (*get_memory_mapping)(CPUState *cpu, MemoryMappingList *list,
                               Error **errp);
    void (*set_pc)(CPUState *cpu, vaddr value);
    hwaddr (*get_phys_page_debug)(CPUState *cpu, vaddr addr);
    hwaddr (*get_phys_page_attrs_debug)(CPUState *cpu, vaddr addr,
                                        MemTxAttrs *attrs);
    int (*asidx_from_attrs)(CPUState *cpu, MemTxAttrs attrs);

    const struct VMStateDescription *vmsd;

    /* Keep non-pointer data at the end to minimize holes.  */
    TcgCpuOperations tcg_ops;
    bool tcg_initialized;
} CPUClass;

/*
 * Low 16 bits: number of cycles left, used only in icount mode.
 * High 16 bits: Set to -1 to force TCG to stop executing linked TBs
 * for this CPU and return to its top level loop (even in non-icount mode).
 * This allows a single read-compare-cbranch-write sequence to test
 * for both decrementer underflow and exceptions.
 */
typedef union IcountDecr {
    uint32_t u32;
    struct {
#ifdef HOST_WORDS_BIGENDIAN
        uint16_t high;
        uint16_t low;
#else
        uint16_t low;
        uint16_t high;
#endif
    } u16;
} IcountDecr;

typedef struct CPUBreakpoint {
    vaddr pc;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUBreakpoint) entry;
} CPUBreakpoint;

struct CPUWatchpoint {
    vaddr vaddr;
    vaddr len;
    vaddr hitaddr;
    MemTxAttrs hitattrs;
    int flags; /* BP_* */
    QTAILQ_ENTRY(CPUWatchpoint) entry;
};

struct CPUWatchpointCallInfo {
    vaddr addr;
    vaddr len;
    QTAILQ_ENTRY(CPUWatchpointCallInfo) entry;
};

struct KVMState;
struct kvm_run;

#define TB_JMP_CACHE_BITS 12
#define TB_JMP_CACHE_SIZE (1 << TB_JMP_CACHE_BITS)

/* The union type allows passing of 64 bit target pointers on 32 bit
 * hosts in a single parameter
 */
typedef union {
    int           host_int;
    unsigned long host_ulong;
    void         *host_ptr;
    vaddr         target_ptr;
} run_on_cpu_data;

#define RUN_ON_CPU_HOST_PTR(p)    ((run_on_cpu_data){.host_ptr = (p)})
#define RUN_ON_CPU_HOST_INT(i)    ((run_on_cpu_data){.host_int = (i)})
#define RUN_ON_CPU_HOST_ULONG(ul) ((run_on_cpu_data){.host_ulong = (ul)})
#define RUN_ON_CPU_TARGET_PTR(v)  ((run_on_cpu_data){.target_ptr = (v)})
#define RUN_ON_CPU_NULL RUN_ON_CPU_HOST_PTR(NULL)

typedef void (*run_on_cpu_func)(CPUState *cpu, void *data);

// Unicorn: Moved CPUAddressSpace here from exec.c
/**
 * CPUAddressSpace: all the information a CPU needs about an AddressSpace
 * @cpu: the CPU whose AddressSpace this is
 * @as: the AddressSpace itself
 * @memory_dispatch: its dispatch pointer (cached, RCU protected)
 * @tcg_as_listener: listener for tracking changes to the AddressSpace
 */
struct CPUAddressSpace {
    CPUState *cpu;
    AddressSpace *as;
    struct AddressSpaceDispatch *memory_dispatch;
    MemoryListener tcg_as_listener;
};

/**
 * CPUState:
 * @cpu_index: CPU index (informative).
 * @cluster_index: Identifies which cluster this CPU is in.
 *   For boards which don't define clusters or for "loose" CPUs not assigned
 *   to a cluster this will be UNASSIGNED_CLUSTER_INDEX; otherwise it will
 *   be the same as the cluster-id property of the CPU object's TYPE_CPU_CLUSTER
 *   QOM parent.
 * @nr_cores: Number of cores within this CPU package.
 * @nr_threads: Number of threads within this CPU.
 * @host_tid: Host thread ID.
 * @running: #true if CPU is currently running (usermode).
 * @created: Indicates whether the CPU thread has been successfully created.
 * @interrupt_request: Indicates a pending interrupt request.
 * @halted: Nonzero if the CPU is in suspended state.
 * @stop: Indicates a pending stop request.
 * @stopped: Indicates the CPU has been artificially stopped.
 * @crash_occurred: Indicates the OS reported a crash (panic) for this CPU
 * @tcg_exit_req: Set to force TCG to stop executing linked TBs for this
 *           CPU and return to its top level loop.
 * @singlestep_enabled: Flags for single-stepping.
 * @icount_extra: Instructions until next timer event.
 * @icount_decr: Number of cycles left, with interrupt flag in high bit.
 * This allows a single read-compare-cbranch-write sequence to test
 * for both decrementer underflow and exceptions.
 * @can_do_io: Nonzero if memory-mapped IO is safe.
 * @cpu_ases: Pointer to array of CPUAddressSpaces (which define the
 *            AddressSpaces this CPU has)
 * @num_ases: number of CPUAddressSpaces in @cpu_ases
 * @as: Pointer to the first AddressSpace, for the convenience of targets which
 *      only have a single AddressSpace
 * @env_ptr: Pointer to subclass-specific CPUArchState field.
 * @icount_decr_ptr: Pointer to IcountDecr field within subclass.
 * @next_cpu: Next CPU sharing TB cache.
 * @opaque: User data.
 * @mem_io_pc: Host Program Counter at which the memory was accessed.
 * @mem_io_vaddr: Target virtual address at which the memory was accessed.
 * @kvm_fd: vCPU file descriptor for KVM.
 *
 * State of one CPU core or thread.
 */
struct CPUState {
    /*< private >*/
    DeviceState parent_obj;
    /*< public >*/

    int nr_cores;
    int nr_threads;

    struct QemuThread *thread;
#ifdef _WIN32
    HANDLE hThread;
#endif
    int thread_id;
    uint32_t host_tid;
    bool running;
    struct qemu_work_item *queued_work_first, *queued_work_last;
    bool thread_kicked;
    bool created;
    bool stop;
    bool stopped;
    bool crash_occurred;
    uint32_t cflags_next_tb;
    bool tb_flushed;
    volatile sig_atomic_t exit_request;
    uint32_t interrupt_request;
    int singlestep_enabled;
    int64_t icount_extra;
    sigjmp_buf jmp_env;

    CPUAddressSpace *cpu_ases;
    int num_ases;
    AddressSpace *as;
    MemoryRegion *memory;

    void *env_ptr; /* CPUArchState */
    IcountDecr *icount_decr_ptr;

    /* Accessed in parallel; all accesses must be atomic */
    struct TranslationBlock *tb_jmp_cache[TB_JMP_CACHE_SIZE];

    QTAILQ_ENTRY(CPUState) node;

    /* ice debug support */
    QTAILQ_HEAD(breakpoints_head, CPUBreakpoint) breakpoints;

    QTAILQ_HEAD(watchpoints_head, CPUWatchpoint) watchpoints;
    CPUWatchpoint *watchpoint_hit;

    void *opaque;

    /* In order to avoid passing too many arguments to the MMIO helpers,
     * we store some rarely used information in the CPU context.
     */
    uintptr_t mem_io_pc;
    vaddr mem_io_vaddr;
    /*
     * This is only needed for the legacy cpu_unassigned_access() hook;
     * when all targets using it have been converted to use
     * cpu_transaction_failed() instead it can be removed.
     */
    MMUAccessType mem_io_access_type;

    int kvm_fd;
    bool kvm_vcpu_dirty;
    struct KVMState *kvm_state;
    struct kvm_run *kvm_run;

    /* TODO Move common fields from CPUArchState here. */
    int cpu_index;
    int cluster_index;
    uint32_t halted;
    uint32_t can_do_io;
    int32_t exception_index;

    /* Used to keep track of an outstanding cpu throttle thread for migration
     * autoconverge
     */
    bool throttle_thread_scheduled;

    bool ignore_memory_transaction_failures;

    /* Note that this is accessed at the start of every TB via a negative
       offset from AREG0.  Leave this field at the end so as to make the
       (absolute value) offset as small as possible.  This reduces code
       size, especially for hosts without large memory offsets.  */
    volatile sig_atomic_t tcg_exit_req;
    struct uc_struct* uc;

    size_t insn_count; // SNPS added
    size_t insn_limit; // SNPS added

    bool is_idle; // SNPS added
};

static inline void cpu_tb_jmp_cache_clear(CPUState *cpu)
{
    unsigned int i;

    for (i = 0; i < TB_JMP_CACHE_SIZE; i++) {
        qatomic_set(&cpu->tb_jmp_cache[i], NULL);
    }
}

/**
 * qemu_tcg_mttcg_enabled:
 * Check whether we are running MultiThread TCG or not.
 *
 * Returns: %true if we are in MTTCG mode %false otherwise.
 */
extern bool mttcg_enabled;
#define qemu_tcg_mttcg_enabled() (mttcg_enabled)

/**
 * cpu_paging_enabled:
 * @cpu: The CPU whose state is to be inspected.
 *
 * Returns: %true if paging is enabled, %false otherwise.
 */
bool cpu_paging_enabled(const CPUState *cpu);

/**
 * cpu_get_memory_mapping:
 * @cpu: The CPU whose memory mappings are to be obtained.
 * @list: Where to write the memory mappings to.
 * @errp: Pointer for reporting an #Error.
 */
void cpu_get_memory_mapping(CPUState *cpu, MemoryMappingList *list,
                            Error **errp);

/**
 * cpu_write_elf64_note:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf64_note(WriteCoreDumpFunction f, CPUState *cpu,
                         int cpuid, void *opaque);

/**
 * cpu_write_elf64_qemunote:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf64_qemunote(WriteCoreDumpFunction f, CPUState *cpu,
                             void *opaque);

/**
 * cpu_write_elf32_note:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf32_note(WriteCoreDumpFunction f, CPUState *cpu,
                         int cpuid, void *opaque);

/**
 * cpu_write_elf32_qemunote:
 * @f: pointer to a function that writes memory to a file
 * @cpu: The CPU whose memory is to be dumped
 * @cpuid: ID number of the CPU
 * @opaque: pointer to the CPUState struct
 */
int cpu_write_elf32_qemunote(WriteCoreDumpFunction f, CPUState *cpu,
                             void *opaque);

/**
 * CPUDumpFlags:
 * @CPU_DUMP_CODE:
 * @CPU_DUMP_FPU: dump FPU register state, not just integer
 * @CPU_DUMP_CCOP: dump info about TCG QEMU's condition code optimization state
 */
enum CPUDumpFlags {
    CPU_DUMP_CODE = 0x00010000,
    CPU_DUMP_FPU  = 0x00020000,
    CPU_DUMP_CCOP = 0x00040000,
};

/**
 * cpu_dump_state:
 * @cpu: The CPU whose state is to be dumped.
 * @f: File to dump to.
 * @cpu_fprintf: Function to dump with.
 * @flags: Flags what to dump.
 *
 * Dumps CPU state.
 */
void cpu_dump_state(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                    int flags);

/**
 * cpu_dump_statistics:
 * @cpu: The CPU whose state is to be dumped.
 * @f: File to dump to.
 * @cpu_fprintf: Function to dump with.
 * @flags: Flags what to dump.
 *
 * Dumps CPU statistics.
 */
void cpu_dump_statistics(CPUState *cpu, FILE *f, fprintf_function cpu_fprintf,
                         int flags);

#ifndef CONFIG_USER_ONLY
/**
 * cpu_get_phys_page_attrs_debug:
 * @cpu: The CPU to obtain the physical page address for.
 * @addr: The virtual address.
 * @attrs: Updated on return with the memory transaction attributes to use
 *         for this access.
 *
 * Obtains the physical page corresponding to a virtual one, together
 * with the corresponding memory transaction attributes to use for the access.
 * Use it only for debugging because no protection checks are done.
 *
 * Returns: Corresponding physical page address or -1 if no page found.
 */
static inline hwaddr cpu_get_phys_page_attrs_debug(CPUState *cpu, vaddr addr,
                                                   MemTxAttrs *attrs)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (cc->get_phys_page_attrs_debug) {
        return cc->get_phys_page_attrs_debug(cpu, addr, attrs);
    }
    /* Fallback for CPUs which don't implement the _attrs_ hook */
    *attrs = MEMTXATTRS_UNSPECIFIED;
    assert(cc->get_phys_page_debug); // SNPS added
    return cc->get_phys_page_debug(cpu, addr);
}
/**
 * cpu_get_phys_page_debug:
 * @cpu: The CPU to obtain the physical page address for.
 * @addr: The virtual address.
 *
 * Obtains the physical page corresponding to a virtual one.
 * Use it only for debugging because no protection checks are done.
 *
 * Returns: Corresponding physical page address or -1 if no page found.
 */
static inline hwaddr cpu_get_phys_page_debug(CPUState *cpu, vaddr addr)
{
    MemTxAttrs attrs = {0};

    return cpu_get_phys_page_attrs_debug(cpu, addr, &attrs);
}
/** cpu_asidx_from_attrs:
 * @cpu: CPU
 * @attrs: memory transaction attributes
 *
 * Returns the address space index specifying the CPU AddressSpace
 * to use for a memory access with the given transaction attributes.
 */
static inline int cpu_asidx_from_attrs(CPUState *cpu, MemTxAttrs attrs)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);
    int ret = 0;

    if (cc->asidx_from_attrs) {
        ret = cc->asidx_from_attrs(cpu, attrs);
        assert(ret < cpu->num_ases && ret >= 0);
    }
    return ret;
}
#endif

/**
 * cpu_reset:
 * @cpu: The CPU whose state is to be reset.
 */
void cpu_reset(CPUState *cpu);

/**
 * cpu_class_by_name:
 * @typename: The CPU base type.
 * @cpu_model: The model string without any parameters.
 *
 * Looks up a CPU #ObjectClass matching name @cpu_model.
 *
 * Returns: A #CPUClass or %NULL if not matching class is found.
 */
ObjectClass *cpu_class_by_name(struct uc_struct *uc, const char *typename, const char *cpu_model);

/**
 * cpu_create:
 * @typename: The CPU type.
 *
 * Instantiates a CPU and realizes the CPU.
 *
 * Returns: A #CPUState or %NULL if an error occurred.
 */
CPUState *cpu_create(struct uc_struct *uc, const char *typename);

/**
 * parse_cpu_model:
 * @cpu_model: The model string including optional parameters.
 *
 * processes optional parameters and registers them as global properties
 *
 * Returns: type of CPU to create or %NULL if an error occurred.
 */
const char *parse_cpu_model(struct uc_struct *uc, const char *cpu_model);

/**
 * cpu_has_work:
 * @cpu: The vCPU to check.
 *
 * Checks whether the CPU has work to do.
 *
 * Returns: %true if the CPU has work, %false otherwise.
 */
static inline bool cpu_has_work(CPUState *cpu)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    g_assert(cc->has_work);
    return cc->has_work(cpu);
}

/**
 * qemu_cpu_kick:
 * @cpu: The vCPU to kick.
 *
 * Kicks @cpu's thread.
 */
void qemu_cpu_kick(CPUState *cpu);

/**
 * cpu_is_stopped:
 * @cpu: The CPU to check.
 *
 * Checks whether the CPU is stopped.
 *
 * Returns: %true if run state is not running or if artificially stopped;
 * %false otherwise.
 */
bool cpu_is_stopped(CPUState *cpu);

/**
 * run_on_cpu:
 * @cpu: The vCPU to run on.
 * @func: The function to be executed.
 * @data: Data to pass to the function.
 *
 * Schedules the function @func for execution on the vCPU @cpu.
 */
void run_on_cpu(CPUState *cpu, run_on_cpu_func func, void *data);

/**
 * async_run_on_cpu:
 * @cpu: The vCPU to run on.
 * @func: The function to be executed.
 * @data: Data to pass to the function.
 *
 * Schedules the function @func for execution on the vCPU @cpu asynchronously.
 */
void async_run_on_cpu(CPUState *cpu, run_on_cpu_func func, void *data);

/**
 * qemu_get_cpu:
 * @index: The CPUState@cpu_index value of the CPU to obtain.
 *
 * Gets a CPU matching @index.
 *
 * Returns: The CPU or %NULL if there is no matching CPU.
 */
CPUState *qemu_get_cpu(struct uc_struct *uc, int index);

/**
 * cpu_exists:
 * @id: Guest-exposed CPU ID to lookup.
 *
 * Search for CPU with specified ID.
 *
 * Returns: %true - CPU is found, %false - CPU isn't found.
 */
bool cpu_exists(struct uc_struct* uc, int64_t id);

/**
 * cpu_by_arch_id:
 * @id: Guest-exposed CPU ID of the CPU to obtain.
 *
 * Get a CPU with matching @id.
 *
 * Returns: The CPU or %NULL if there is no matching CPU.
 */
CPUState *cpu_by_arch_id(struct uc_struct *uc, int64_t id);

#ifndef CONFIG_USER_ONLY

typedef void (*CPUInterruptHandler)(CPUState *, int);

extern CPUInterruptHandler cpu_interrupt_handler;

/**
 * cpu_interrupt:
 * @cpu: The CPU to set an interrupt on.
 * @mask: The interrupts to set.
 *
 * Invokes the interrupt handler.
 */
static inline void cpu_interrupt(CPUState *cpu, int mask)
{
    cpu_interrupt_handler(cpu, mask);
}

#else /* USER_ONLY */

void cpu_interrupt(CPUState *cpu, int mask);

#endif /* USER_ONLY */

static inline void cpu_unassigned_access(CPUState *cpu, hwaddr addr,
                                         bool is_write, bool is_exec,
                                         int opaque, unsigned size)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (cc->do_unassigned_access) {
        cc->do_unassigned_access(cpu, addr, is_write, is_exec, opaque, size);
    }
}

static inline void cpu_unaligned_access(CPUState *cpu, vaddr addr,
                                        MMUAccessType access_type,
                                        int mmu_idx, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    cc->tcg_ops.do_unaligned_access(cpu, addr, access_type, mmu_idx, retaddr);
}

static inline void cpu_transaction_failed(CPUState *cpu, hwaddr physaddr,
                                          vaddr addr, unsigned size,
                                          MMUAccessType access_type,
                                          int mmu_idx, MemTxAttrs attrs,
                                          MemTxResult response,
                                          uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    if (!cpu->ignore_memory_transaction_failures &&
        cc->tcg_ops.do_transaction_failed) {
        cc->tcg_ops.do_transaction_failed(cpu, physaddr, addr, size,
                                          access_type, mmu_idx, attrs,
                                          response, retaddr);
    }
}

/**
 * cpu_set_pc:
 * @cpu: The CPU to set the program counter for.
 * @addr: Program counter value.
 *
 * Sets the program counter for a CPU.
 */
static inline void cpu_set_pc(CPUState *cpu, vaddr addr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);

    cc->set_pc(cpu, addr);
}

/**
 * cpu_reset_interrupt:
 * @cpu: The CPU to clear the interrupt on.
 * @mask: The interrupt mask to clear.
 *
 * Resets interrupts on the vCPU @cpu.
 */
void cpu_reset_interrupt(CPUState *cpu, int mask);

/**
 * cpu_exit:
 * @cpu: The CPU to exit.
 *
 * Requests the CPU @cpu to exit execution.
 */
void cpu_exit(CPUState *cpu);

/**
 * cpu_resume:
 * @cpu: The CPU to resume.
 *
 * Resumes CPU, i.e. puts CPU into runnable state.
 */
void cpu_resume(CPUState *cpu);

/**
 * qemu_init_vcpu:
 * @cpu: The vCPU to initialize.
 *
 * Initializes a vCPU.
 */
int qemu_init_vcpu(CPUState *cpu);

#define SSTEP_ENABLE  0x1  /* Enable simulated HW single stepping */
#define SSTEP_NOIRQ   0x2  /* Do not use IRQ while single stepping */
#define SSTEP_NOTIMER 0x4  /* Do not Timers while single stepping */

/**
 * cpu_single_step:
 * @cpu: CPU to the flags for.
 * @enabled: Flags to enable.
 *
 * Enables or disables single-stepping for @cpu.
 */
void cpu_single_step(CPUState *cpu, int enabled);

/* Breakpoint/watchpoint flags */
#define BP_MEM_READ           0x01
#define BP_MEM_WRITE          0x02
#define BP_MEM_ACCESS         (BP_MEM_READ | BP_MEM_WRITE)
#define BP_STOP_BEFORE_ACCESS 0x04
#define BP_CALL               0x08 // SNPS changed
#define BP_GDB                0x10
#define BP_CPU                0x20
#define BP_ANY                (BP_GDB | BP_CPU)
#define BP_WATCHPOINT_HIT_READ 0x40
#define BP_WATCHPOINT_HIT_WRITE 0x80
#define BP_WATCHPOINT_HIT (BP_WATCHPOINT_HIT_READ | BP_WATCHPOINT_HIT_WRITE)

int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags,
                          CPUBreakpoint **breakpoint);
int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags);
void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint);
void cpu_breakpoint_remove_all(CPUState *cpu, int mask);

int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
                          int flags, CPUWatchpoint **watchpoint);
int cpu_watchpoint_remove(CPUState *cpu, vaddr addr,
                          vaddr len, int flags);
void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint);
void cpu_watchpoint_remove_all(CPUState *cpu, int mask);

/**
 * cpu_get_address_space:
 * @cpu: CPU to get address space from
 * @asidx: index identifying which address space to get
 *
 * Return the requested address space of this CPU. @asidx
 * specifies which address space to read.
 */
AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx);

/* Return true if PC matches an installed breakpoint.  */
static inline bool cpu_breakpoint_test(CPUState *cpu, vaddr pc, int mask)
{
    CPUBreakpoint *bp;

    if (unlikely(!QTAILQ_EMPTY(&cpu->breakpoints))) {
        QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
            if (bp->pc == pc && (bp->flags & mask)) {
                return true;
            }
        }
    }
    return false;
}

void QEMU_NORETURN cpu_abort(CPUState *cpu, const char *fmt, ...)
    GCC_FMT_ATTR(2, 3);
void cpu_exec_exit(CPUState *cpu);

void cpu_register_types(struct uc_struct *uc);

#ifdef CONFIG_SOFTMMU
extern const struct VMStateDescription vmstate_cpu_common;
#else
#define vmstate_cpu_common vmstate_dummy
#endif

#define VMSTATE_CPU() {                                                     \
    .name = "parent_obj",                                                   \
    .size = sizeof(CPUState),                                               \
    .vmsd = &vmstate_cpu_common,                                            \
    .flags = VMS_STRUCT,                                                    \
    .offset = 0,                                                            \
}

#endif
