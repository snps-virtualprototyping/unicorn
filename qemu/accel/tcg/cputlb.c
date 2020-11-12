/*
 *  Common CPU TLB handling
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */

/* Modified for Unicorn Engine by Nguyen Anh Quynh, 2015 */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#include "exec/cpu_ldst.h"
#include "exec/cputlb.h"
#include "exec/memory-internal.h"
#include "exec/ram_addr.h"
#include "tcg/tcg.h"
#include "exec/helper-proto.h"
#include "qemu/atomic.h"
#include "qemu/atomic128.h"

#include "uc_priv.h"

/* DEBUG defines, enable DEBUG_TLB_LOG to log to the CPU_LOG_MMU target */
/* #define DEBUG_TLB */
/* #define DEBUG_TLB_LOG */

#ifdef DEBUG_TLB
# define DEBUG_TLB_GATE 1
# ifdef DEBUG_TLB_LOG
#  define DEBUG_TLB_LOG_GATE 1
# else
#  define DEBUG_TLB_LOG_GATE 0
# endif
#else
# define DEBUG_TLB_GATE 0
# define DEBUG_TLB_LOG_GATE 0
#endif

#define tlb_debug(fmt, ...) do { \
    if (DEBUG_TLB_LOG_GATE) { \
        qemu_log_mask(CPU_LOG_MMU, "%s: " fmt, __func__, \
                      ## __VA_ARGS__); \
    } else if (DEBUG_TLB_GATE) { \
        fprintf(stderr, "%s: " fmt, __func__, ## __VA_ARGS__); \
    } \
} while (0)

#define ALL_MMUIDX_BITS ((1 << NB_MMU_MODES) - 1)

void tlb_init(CPUState *cpu)
{
}

static void tlb_flush_one_mmuidx_locked(CPUArchState *env, int mmu_idx)
{
    memset(env->tlb_table[mmu_idx], -1, sizeof(env->tlb_table[0]));
    memset(env->tlb_v_table[mmu_idx], -1, sizeof(env->tlb_v_table[0]));
    env->tlb_d[mmu_idx].large_page_addr = -1;
    env->tlb_d[mmu_idx].large_page_mask = -1;
    env->tlb_d[mmu_idx].vindex = 0;
}

static void tlb_flush_by_mmuidx_async_work(CPUState *cpu, run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    unsigned long mmu_idx_bitmask = data.host_int;
    int mmu_idx;

    tlb_debug("mmu_idx:0x%04lx\n", mmu_idx_bitmask);

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        if (test_bit(mmu_idx, &mmu_idx_bitmask)) {
            tlb_flush_one_mmuidx_locked(env, mmu_idx);
        }
    }

    cpu_tb_jmp_cache_clear(cpu);
}

void tlb_flush_by_mmuidx(CPUState *cpu, uint16_t idxmap)
{
    tlb_debug("mmu_idx: 0x%" PRIx16 "\n", idxmap);

    tlb_flush_by_mmuidx_async_work(cpu, RUN_ON_CPU_HOST_INT(idxmap));
}

void tlb_flush(CPUState *cpu)
{
    tlb_flush_by_mmuidx(cpu, ALL_MMUIDX_BITS);
}

static inline bool tlb_hit_page_anyprot(CPUTLBEntry *tlb_entry,
                                        target_ulong page)
{
    return tlb_hit_page(tlb_entry->addr_read, page) ||
           tlb_hit_page(tlb_addr_write(tlb_entry), page) ||
           tlb_hit_page(tlb_entry->addr_code, page);
}

/* Called with tlb_c.lock held */
static inline bool tlb_flush_entry_locked(CPUTLBEntry *tlb_entry,
                                          target_ulong page)
{
    if (tlb_hit_page_anyprot(tlb_entry, page)) {
        memset(tlb_entry, -1, sizeof(*tlb_entry));
        return true;
    }
    return false;
}

/* Called with tlb_c.lock held */
static inline void tlb_flush_vtlb_page_locked(CPUArchState *env, int mmu_idx,
                                              target_ulong page)
{
    int k;
    //assert_cpu_is_self(env_cpu(env));
    for (k = 0; k < CPU_VTLB_SIZE; k++) {
        tlb_flush_entry_locked(&env->tlb_v_table[mmu_idx][k], page);
    }
}

static void tlb_flush_page_locked(CPUArchState *env, int midx,
                                  target_ulong page)
{
    target_ulong lp_addr = env->tlb_d[midx].large_page_addr;
    target_ulong lp_mask = env->tlb_d[midx].large_page_mask;

    /* Check if we need to flush due to large pages.  */
    if ((page & lp_mask) == lp_addr) {
        tlb_debug("forcing full flush midx %d ("
                  TARGET_FMT_lx "/" TARGET_FMT_lx ")\n",
                  midx, lp_addr, lp_mask);
        tlb_flush_one_mmuidx_locked(env, midx);
    } else {
        tlb_flush_entry_locked(tlb_entry(env, midx, page), page);
        tlb_flush_vtlb_page_locked(env, midx, page);
    }
}

static void tlb_flush_page_async_work(CPUState *cpu, run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong addr = (target_ulong) data.target_ptr;
    int mmu_idx;

    tlb_debug("page addr:" TARGET_FMT_lx "\n", addr);

    addr &= TARGET_PAGE_MASK;
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        tlb_flush_page_locked(env, mmu_idx, addr);
    }

    tb_flush_jmp_cache(cpu, addr);
}

/* As we are going to hijack the bottom bits of the page address for a
 * mmuidx bit mask we need to fail to build if we can't do that
 */
QEMU_BUILD_BUG_ON(NB_MMU_MODES > TARGET_PAGE_BITS_MIN);

static void tlb_flush_page_by_mmuidx_async_work(CPUState *cpu,
                                                run_on_cpu_data data)
{
    CPUArchState *env = cpu->env_ptr;
    target_ulong addr_and_mmuidx = (target_ulong) data.target_ptr;
    target_ulong addr = addr_and_mmuidx & TARGET_PAGE_MASK;
    unsigned long mmu_idx_bitmap = addr_and_mmuidx & ALL_MMUIDX_BITS;
    int mmu_idx;

    tlb_debug("page addr:" TARGET_FMT_lx " mmu_map:0x%lx\n",
              addr, mmu_idx_bitmap);

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        if (test_bit(mmu_idx, &mmu_idx_bitmap)) {
            tlb_flush_page_locked(env, mmu_idx, addr);
        }
    }

    tb_flush_jmp_cache(cpu, addr);
}

void tlb_flush_page_by_mmuidx(CPUState *cpu, target_ulong addr, uint16_t idxmap)
{
    target_ulong addr_and_mmu_idx;

    tlb_debug("addr: "TARGET_FMT_lx" mmu_idx:%" PRIx16 "\n", addr, idxmap);

    /* This should already be page aligned */
    addr_and_mmu_idx = addr & TARGET_PAGE_MASK;
    addr_and_mmu_idx |= idxmap;

    tlb_flush_page_by_mmuidx_async_work(
        cpu, RUN_ON_CPU_TARGET_PTR(addr_and_mmu_idx));
}

void tlb_flush_page(CPUState *cpu, target_ulong addr)
{
    tlb_flush_page_async_work(cpu, RUN_ON_CPU_TARGET_PTR(addr));
}

// SNPS added
void tlb_flush_all_cpus_synced(CPUState *cpu) {
    uc_engine *uc = cpu->uc;
    g_assert(uc->tlb_cluster_flush != NULL);
    uc->tlb_cluster_flush(cpu);
}

// SNPS added
void tlb_flush_page_all_cpus_synced(CPUState *cpu, target_ulong addr) {
    uc_engine *uc = cpu->uc;
    g_assert(uc->tlb_cluster_flush_page != NULL);
    uc->tlb_cluster_flush_page(cpu, addr);
}

// SNPS added
void tlb_flush_by_mmuidx_all_cpus_synced(CPUState *cpu, uint16_t idxmap) {
    uc_engine *uc = cpu->uc;
    g_assert(uc->tlb_cluster_flush_mmuidx != NULL);
    uc->tlb_cluster_flush_mmuidx(cpu, idxmap);
}

// SNPS added
void tlb_flush_page_by_mmuidx_all_cpus_synced(CPUState *cpu, target_ulong addr, uint16_t idxmap) {
    uc_engine *uc = cpu->uc;
    g_assert(uc->tlb_cluster_flush_page_mmuidx != NULL);
    uc->tlb_cluster_flush_page_mmuidx(cpu, addr, idxmap);
}

/*
 * Dirty write flag handling
 *
 * When the TCG code writes to a location it looks up the address in
 * the TLB and uses that data to compute the final address. If any of
 * the lower bits of the address are set then the slow path is forced.
 * There are a number of reasons to do this but for normal RAM the
 * most usual is detecting writes to code regions which may invalidate
 * generated code.
 *
 * Other vCPUs might be reading their TLBs during guest execution, so we update
 * te->addr_write with atomic_set. We don't need to worry about this for
 * oversized guests as MTTCG is disabled for them.
 *
 * Called with tlb_c.lock held.
 */
static void tlb_reset_dirty_range_locked(CPUTLBEntry *tlb_entry,
                                         uintptr_t start, uintptr_t length)
{
    uintptr_t addr = tlb_entry->addr_write;

    if ((addr & (TLB_INVALID_MASK | TLB_MMIO | TLB_NOTDIRTY)) == 0) {
        addr &= TARGET_PAGE_MASK;
        addr += tlb_entry->addend;
        if ((addr - start) < length) {
#if TCG_OVERSIZED_GUEST
            tlb_entry->addr_write |= TLB_NOTDIRTY;
#else
            atomic_set(&tlb_entry->addr_write,
                       tlb_entry->addr_write | TLB_NOTDIRTY);
#endif
        }
    }
}

/*
 * Called with tlb_c.lock held.
 * Called only from the vCPU context, i.e. the TLB's owner thread.
 */
static inline void copy_tlb_helper_locked(CPUTLBEntry *d, const CPUTLBEntry *s)
{
    *d = *s;
}

/* This is a cross vCPU call (i.e. another vCPU resetting the flags of
 * the target vCPU).
 * We must take tlb_c.lock to avoid racing with another vCPU update. The only
 * thing actually updated is the target TLB entry ->addr_write flags.
 */
void tlb_reset_dirty(CPUState *cpu, ram_addr_t start1, ram_addr_t length)
{
    CPUArchState *env;

    int mmu_idx;

    env = cpu->env_ptr;
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        unsigned int i;

        for (i = 0; i < CPU_TLB_SIZE; i++) {
            tlb_reset_dirty_range_locked(&env->tlb_table[mmu_idx][i], start1,
                                         length);
        }

        for (i = 0; i < CPU_VTLB_SIZE; i++) {
            tlb_reset_dirty_range_locked(&env->tlb_v_table[mmu_idx][i], start1,
                                         length);
        }
    }
}

/* Called with tlb_c.lock held */
static inline void tlb_set_dirty1_locked(CPUTLBEntry *tlb_entry,
                                         target_ulong vaddr)
{
    if (tlb_entry->addr_write == (vaddr | TLB_NOTDIRTY)) {
        tlb_entry->addr_write = vaddr;
    }
}

/* update the TLB corresponding to virtual page vaddr
   so that it is no longer dirty */
void tlb_set_dirty(CPUState *cpu, target_ulong vaddr)
{
    CPUArchState *env = cpu->env_ptr;
    int mmu_idx;

    vaddr &= TARGET_PAGE_MASK;
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        tlb_set_dirty1_locked(tlb_entry(env, mmu_idx, vaddr), vaddr);
    }

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        int k;
        for (k = 0; k < CPU_VTLB_SIZE; k++) {
            tlb_set_dirty1_locked(&env->tlb_v_table[mmu_idx][k], vaddr);
        }
    }
}

/* Our TLB does not support large pages, so remember the area covered by
   large pages and trigger a full TLB flush if these are invalidated.  */
static void tlb_add_large_page(CPUArchState *env, int mmu_idx,
                               target_ulong vaddr, target_ulong size)
{
    target_ulong lp_addr = env->tlb_d[mmu_idx].large_page_addr;
    target_ulong lp_mask = ~(size - 1);

    if (lp_addr == (target_ulong)-1) {
        /* No previous large page.  */
        lp_addr = vaddr;
    } else {
        /* Extend the existing region to include the new page.
           This is a compromise between unnecessary flushes and
           the cost of maintaining a full variable size TLB.  */
        lp_mask &= env->tlb_d[mmu_idx].large_page_mask;
        while (((lp_addr ^ vaddr) & lp_mask) != 0) {
            lp_mask <<= 1;
        }
    }
    env->tlb_d[mmu_idx].large_page_addr = lp_addr & lp_mask;
    env->tlb_d[mmu_idx].large_page_mask = lp_mask;
}

/* Add a new TLB entry. At most one entry for a given virtual address
 * is permitted. Only a single TARGET_PAGE_SIZE region is mapped, the
 * supplied size is only used by tlb_flush_page.
 *
 * Called from TCG-generated code, which is under an RCU read-side
 * critical section.
 */
void tlb_set_page_with_attrs(CPUState *cpu, target_ulong vaddr,
                             hwaddr paddr, MemTxAttrs attrs, int prot,
                             int mmu_idx, target_ulong size)
{
    CPUArchState *env = cpu->env_ptr;
    MemoryRegionSection *section;
    unsigned int index;
    target_ulong address;
    target_ulong code_address;
    uintptr_t addend;
    CPUTLBEntry *te;
    hwaddr iotlb, xlat, sz, paddr_page;
    target_ulong vaddr_page;
    unsigned vidx = env->tlb_d[mmu_idx].vindex++ % CPU_VTLB_SIZE;
    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    int wp_flags;
    int newprot = prot; // SNPS added

    if (size <= TARGET_PAGE_SIZE) {
        sz = TARGET_PAGE_SIZE;
    } else {
        tlb_add_large_page(env, mmu_idx, vaddr, size);
        sz = size;
    }
    vaddr_page = vaddr & TARGET_PAGE_MASK;
    paddr_page = paddr & TARGET_PAGE_MASK;

    section = address_space_translate_for_iotlb(cpu, asidx, paddr_page,
                                                &xlat, &sz, attrs, &prot);
    assert(sz >= TARGET_PAGE_SIZE);

    tlb_debug("vaddr=" TARGET_FMT_lx " paddr=0x" TARGET_FMT_plx
              " prot=%x idx=%d\n",
              vaddr, paddr, prot, mmu_idx);

    address = vaddr_page;
    if (size < TARGET_PAGE_SIZE) {
        /* Repeat the MMU check and TLB fill on every access.  */
        address |= TLB_INVALID_MASK;
    }
    if (attrs.byte_swap) {
        /* Force the access through the I/O slow path.  */
        address |= TLB_MMIO;
    }
    if (!memory_region_is_ram(section->mr) &&
        !memory_region_is_romd(section->mr)) {
        /* IO memory case */
        // SNPS added: DMI/b_transport handling
        if (env->uc->get_dmi_ptr != NULL &&
            env->uc->get_dmi_ptr(env->uc->dmi_opaque, paddr_page, &dmiptr, &newprot)) {
            address &= ~TLB_MMIO;
            addend = (uintptr_t)dmiptr;
            prot = prot & newprot; // don't take more than we're allowed to
        } else {
            address |= TLB_MMIO;
            addend = 0;
        }
    } else {
        /* TLB_MMIO for rom/romd handled below */
        addend = (uintptr_t)((char*)memory_region_get_ram_ptr(section->mr) + xlat);
    }

    code_address = address;
    iotlb = memory_region_section_get_iotlb(cpu, section, vaddr_page,
                                            paddr_page, xlat, prot, &address);
    wp_flags = cpu_watchpoint_address_matches(cpu, vaddr_page,
                                              TARGET_PAGE_SIZE);

    index = tlb_index(env, mmu_idx, vaddr_page);
    te = tlb_entry(env, mmu_idx, vaddr_page);

    /* do not discard the translation in te, evict it into a victim tlb */
    env->tlb_v_table[mmu_idx][vidx] = *te;
    env->iotlb_v[mmu_idx][vidx] = env->iotlb[mmu_idx][index];

    /* refill the tlb */
    /*
     * At this point iotlb contains a physical section number in the lower
     * TARGET_PAGE_BITS, and either
     *  + the ram_addr_t of the page base of the target RAM (if NOTDIRTY or ROM)
     *  + the offset within section->mr of the page base (otherwise)
     * We subtract the vaddr_page (which is page aligned and thus won't
     * disturb the low bits) to give an offset which can be added to the
     * (non-page-aligned) vaddr of the eventual memory access to get
     * the MemoryRegion offset for the access. Note that the vaddr we
     * subtract here is that of the page base, and not the same as the
     * vaddr we add back in io_readx()/io_writex()/get_page_addr_code().
     */
    env->iotlb[mmu_idx][index].addr = iotlb - vaddr_page;
    env->iotlb[mmu_idx][index].attrs = attrs;

    // SNPS added: link iotlb back to tlb to enable dmi
    env->iotlb[mmu_idx][index].phys = paddr_page;
    env->iotlb[mmu_idx][index].p2v = te;

    te->addend = addend - vaddr_page;
    if (prot & PAGE_READ) {
        te->addr_read = address;
        if (wp_flags & BP_MEM_READ) {
            te->addr_read |= TLB_WATCHPOINT;
        }
    } else {
        te->addr_read = -1;
    }

    if (prot & PAGE_EXEC) {
        te->addr_code = code_address | TLB_NOTPROTECTED; // SNPS changed
    } else {
        te->addr_code = -1;
    }

    te->addr_write = -1;
    if (prot & PAGE_WRITE) {
        te->addr_write = address | TLB_NOTDIRTY; // SNPS changed
        if (prot & PAGE_WRITE_INV) {
            te->addr_write |= TLB_INVALID_MASK;
        }
        if (wp_flags & BP_MEM_WRITE) {
            te->addr_write |= TLB_WATCHPOINT;
        }
    }
}

/* Add a new TLB entry, but without specifying the memory
 * transaction attributes to be used.
 */
void tlb_set_page(CPUState *cpu, target_ulong vaddr,
                  hwaddr paddr, int prot,
                  int mmu_idx, target_ulong size)
{
    tlb_set_page_with_attrs(cpu, vaddr, paddr, MEMTXATTRS_UNSPECIFIED,
                            prot, mmu_idx, size);
}

static inline ram_addr_t qemu_ram_addr_from_host_nofail(struct uc_struct *uc, void *ptr)
{
    ram_addr_t ram_addr;

    ram_addr = qemu_ram_addr_from_host(uc, ptr);
    if (ram_addr == RAM_ADDR_INVALID) {
        //error_report("Bad ram pointer %p", ptr);
        return RAM_ADDR_INVALID;
    }

    return ram_addr;
}

/*
 * Note: tlb_fill() can trigger a resize of the TLB. This means that all of the
 * caller's prior references to the TLB table (e.g. CPUTLBEntry pointers) must
 * be discarded and looked up again (e.g. via tlb_entry()).
 */
static void tlb_fill(CPUState *cpu, target_ulong addr, int size,
                     MMUAccessType access_type, int mmu_idx, uintptr_t retaddr)
{
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);
    bool ok;

    /*
     * This is not a probe, so only valid return is success; failure
     * should result in exception + longjmp to the cpu loop.
     */
    ok = cc->tlb_fill(cpu, addr, size, access_type, mmu_idx, false, retaddr);
    assert(ok);
}

/* Macro to call the above, with local variables from the use context.  */
#define VICTIM_TLB_HIT(TY, ADDR) \
  victim_tlb_hit(env, mmu_idx, index, offsetof(CPUTLBEntry, TY), \
                 (ADDR) & TARGET_PAGE_MASK)

static inline target_ulong tlb_read_ofs(CPUTLBEntry *entry, size_t ofs)
{
#if TCG_OVERSIZED_GUEST
    return *(target_ulong *)((uintptr_t)entry + ofs);
#else
    /* ofs might correspond to .addr_write, so use atomic_read */
    return atomic_read((target_ulong *)((uintptr_t)entry + ofs));
#endif
}

/* Return true if ADDR is present in the victim tlb, and has been copied
   back to the main tlb.  */
static bool victim_tlb_hit(CPUArchState *env, size_t mmu_idx, size_t index,
                           size_t elt_ofs, target_ulong page)
{
    size_t vidx;
    for (vidx = 0; vidx < CPU_VTLB_SIZE; ++vidx) {
        CPUTLBEntry *vtlb = &env->tlb_v_table[mmu_idx][vidx];

        /* elt_ofs might correspond to .addr_write, so use atomic_read */
        target_ulong cmp = tlb_read_ofs(vtlb, elt_ofs);

        if (cmp == page) {
            /* Found entry in victim tlb, swap tlb and iotlb.  */
            CPUTLBEntry tmptlb, *tlb = &env->tlb_table[mmu_idx][index];

            copy_tlb_helper_locked(&tmptlb, tlb);
            copy_tlb_helper_locked(tlb, vtlb);
            copy_tlb_helper_locked(vtlb, &tmptlb);

            CPUIOTLBEntry tmpio, *io = &env->iotlb[mmu_idx][index];
            CPUIOTLBEntry *vio = &env->iotlb_v[mmu_idx][vidx];
            tmpio = *io; *io = *vio; *vio = tmpio;
            return true;
        }
    }
    return false;
}

/*
 * Return a ram_addr_t for the virtual address for execution.
 *
 * Return -1 if we can't translate and execute from an entire page
 * of RAM.  This will force us to execute by loading and translating
 * one insn at a time, without caching.
 *
 * NOTE: This function will trigger an exception if the page is
 * not executable.
 */
tb_page_addr_t get_page_addr_code(CPUArchState *env, target_ulong addr)
{
    uintptr_t mmu_idx = cpu_mmu_index(env, true);
    uintptr_t index = tlb_index(env, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    void *p;
    MemoryRegion *mr;
    MemoryRegionSection *section;
    ram_addr_t  ram_addr;
    CPUState *cpu = env_cpu(env);
    CPUIOTLBEntry *iotlbentry;
    hwaddr physaddr, mr_offset;

    if (unlikely(!tlb_hit(entry->addr_code, addr))) {
#if 0 // SNPS disabled
        cpu_ldub_code(env, addr);
        //check for NX related error from softmmu
        if (env->invalid_error == UC_ERR_FETCH_PROT) {
            return RAM_ADDR_INVALID;
        }
#endif

        if (!VICTIM_TLB_HIT(addr_code, addr)) {
            tlb_fill(env_cpu(env), addr, 0, MMU_INST_FETCH, mmu_idx, 0);
            index = tlb_index(env, mmu_idx, addr);
            entry = tlb_entry(env, mmu_idx, addr);

            if (unlikely(entry->addr_code & TLB_INVALID_MASK)) {
                /*
                 * The MMU protection covers a smaller range than a target
                 * page, so we must redo the MMU check for every insn.
                 */
                assert(0 && "entry->addr_code invalid"); // SNPS added
                return -1;
            }
        }
        assert(tlb_hit(entry->addr_code, addr));
    }

    // SNPS added
    if (unlikely(entry->addr_code & (TLB_RECHECK | TLB_MMIO))) {
        /*
         * Return -1 if we can't translate and execute from an entire
         * page of RAM here, which will cause us to execute by loading
         * and translating one insn at a time, without caching:
         *  - TLB_RECHECK: means the MMU protection covers a smaller range
         *    than a target page, so we must redo the MMU check every insn
         *  - TLB_MMIO: region is not backed by RAM
         */
        return -1;
    }

    iotlbentry = &env->iotlb[mmu_idx][index];
    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    if (memory_region_is_unassigned(cpu->uc, mr)) {
        /* Give the new-style cpu_transaction_failed() hook first chance
         * to handle this.
         * This is not the ideal place to detect and generate CPU
         * exceptions for instruction fetch failure (for instance
         * we don't know the length of the access that the CPU would
         * use, and it would be better to go ahead and try the access
         * and use the MemTXResult it produced). However it is the
         * simplest place we have currently available for the check.
         */
        mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
        physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;
        cpu_transaction_failed(cpu, physaddr, addr, 0, MMU_INST_FETCH, mmu_idx,
                               iotlbentry->attrs, MEMTX_DECODE_ERROR, 0);

        cpu_unassigned_access(cpu, addr, false, true, 0, 4);
        /* The CPU's unassigned access hook might have longjumped out
         * with an exception. If it didn't (or there was no hook) then
         * we can't proceed further.
         */
        env->invalid_addr = addr;
        env->invalid_error = UC_ERR_FETCH_UNMAPPED;
        return RAM_ADDR_INVALID;
    }
    p = (void *)((uintptr_t)addr + entry->addend);
    ram_addr = (ioentry->addr & TARGET_PAGE_MASK) + addr; // SNPS changed
    // ToDo: protect p?
    if (ram_addr == RAM_ADDR_INVALID) {
        env->invalid_addr = addr;
        env->invalid_error = UC_ERR_FETCH_UNMAPPED;
        return RAM_ADDR_INVALID;
    } else {
        return ram_addr;
    }
}

// SNPS added
static bool tlb_is_dirty_ram(CPUTLBEntry *tlbe)
{
    return (tlb_addr_write(tlbe) & (TLB_INVALID_MASK|TLB_MMIO|TLB_NOTDIRTY)) == 0;
}

// SNPS added
void tlb_flush_by_mmuidx(CPUState *cpu, uint16_t idxmap)
{
    CPUArchState *env = cpu->env_ptr;
    unsigned long mmu_idx_bitmask = idxmap;
    int mmu_idx;

    tlb_debug("start\n");

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        if (test_bit(mmu_idx, &mmu_idx_bitmask)) {
            tlb_debug("%d\n", mmu_idx);

            memset(env->tlb_table[mmu_idx], -1, sizeof(env->tlb_table[0]));
            memset(env->tlb_v_table[mmu_idx], -1, sizeof(env->tlb_v_table[0]));

            env->tlb_flush_addr[mmu_idx] = (target_ulong)-1;
            env->tlb_flush_mask[mmu_idx] = 0;
        }
    }

    cpu_tb_jmp_cache_clear(cpu);
}

// SNPS added
static inline void tlb_flush_entry(CPUTLBEntry *tlb_entry, target_ulong addr)
{
    if (tlb_hit_page(tlb_entry->addr_read, addr) ||
        tlb_hit_page(tlb_addr_write(tlb_entry), addr) ||
        tlb_hit_page(tlb_entry->addr_code, addr)) {
        memset(tlb_entry, -1, sizeof(*tlb_entry));
    }
}

// SNPS added
void tlb_flush_page_by_mmuidx(CPUState *cpu, uint64_t addr, uint16_t idxmap)
{
    CPUArchState *env = cpu->env_ptr;
    unsigned long mmu_idx_bitmap = idxmap;
    int i, page, mmu_idx;

    tlb_debug("addr 0x%lx\n", addr);

    /* Check if we need to flush due to large pages.  */
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        target_ulong flush_mask = env->tlb_flush_mask[mmu_idx];
        target_ulong flush_addr = env->tlb_flush_addr[mmu_idx];
        if ((addr & flush_mask) == flush_addr) {
            tlb_debug("forced full flush ("
                      TARGET_FMT_lx "/" TARGET_FMT_lx ")\n",
                      flush_addr, flush_mask);

            tlb_flush_one_mmu(cpu, mmu_idx);
        }
    }

    addr &= TARGET_PAGE_MASK;
    page = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        if (test_bit(mmu_idx, &mmu_idx_bitmap)) {
            tlb_flush_entry(&env->tlb_table[mmu_idx][page], addr);
            /* check whether there are vltb entries that need to be flushed */
            for (i = 0; i < CPU_VTLB_SIZE; i++) {
                tlb_flush_entry(&env->tlb_v_table[mmu_idx][i], addr);
            }
        }
    }

    tb_flush_jmp_cache(cpu, addr);
}

static uint64_t io_readx(CPUArchState *env, CPUIOTLBEntry *iotlbentry,
                         int mmu_idx, target_ulong addr, uintptr_t retaddr,
                         MMUAccessType access_type, MemOp op)
{
    CPUState *cpu = env_cpu(env);
    hwaddr mr_offset;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    uint64_t val;
    MemTxResult r;

    if (iotlbentry->attrs.byte_swap) {
        op ^= MO_BSWAP;
    }

    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
    cpu->mem_io_pc = retaddr;
    if (mr != &cpu->uc->io_mem_rom && mr != &cpu->uc->io_mem_notdirty && !cpu->can_do_io) {
        cpu_io_recompile(cpu, retaddr);
    }

    cpu->mem_io_vaddr = addr;
    cpu->mem_io_access_type = access_type;

    r = memory_region_dispatch_read(mr, mr_offset, &val, op, iotlbentry->attrs);
    if (r != MEMTX_OK) {
        hwaddr physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;

        cpu_transaction_failed(cpu, physaddr, addr, memop_size(op), access_type,
                               mmu_idx, iotlbentry->attrs, r, retaddr);
    }
    return val;
}

static void io_writex(CPUArchState *env, CPUIOTLBEntry *iotlbentry,
                      int mmu_idx, uint64_t val, target_ulong addr,
                      uintptr_t retaddr, MemOp op)
{
    CPUState *cpu = env_cpu(env);
    hwaddr mr_offset;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    MemTxResult r;

    if (iotlbentry->attrs.byte_swap) {
        op ^= MO_BSWAP;
    }

    section = iotlb_to_section(cpu, iotlbentry->addr, iotlbentry->attrs);
    mr = section->mr;
    mr_offset = (iotlbentry->addr & TARGET_PAGE_MASK) + addr;
    if (mr != &cpu->uc->io_mem_rom && mr != &cpu->uc->io_mem_notdirty &&
        mr != &cpu->uc->io_mem_watch && !cpu->can_do_io) { // SNPS added
        cpu_io_recompile(cpu, retaddr);
    }
    cpu->mem_io_vaddr = addr;
    cpu->mem_io_pc = retaddr;
    r = memory_region_dispatch_write(mr, mr_offset, val, op, iotlbentry->attrs);
    if (r != MEMTX_OK) {
        hwaddr physaddr = mr_offset +
            section->offset_within_address_space -
            section->offset_within_region;

        cpu_transaction_failed(cpu, physaddr, addr, memop_size(op),
                               MMU_DATA_STORE, mmu_idx, iotlbentry->attrs, r,
                               retaddr);
    }
}

/*
 * Probe for whether the specified guest access is permitted. If it is not
 * permitted then an exception will be taken in the same way as if this
 * were a real access (and we will not return).
 * If the size is 0 or the page requires I/O access, returns NULL; otherwise,
 * returns the address of the host page similar to tlb_vaddr_to_host().
 */
void *probe_access(CPUArchState *env, target_ulong addr, int size,
                   MMUAccessType access_type, int mmu_idx, uintptr_t retaddr)
{
    uintptr_t index = tlb_index(env, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr;
    size_t elt_ofs;
    int wp_access;

    g_assert(-(addr | TARGET_PAGE_MASK) >= size);

    switch (access_type) {
    case MMU_DATA_LOAD:
        elt_ofs = offsetof(CPUTLBEntry, addr_read);
        wp_access = BP_MEM_READ;
        break;
    case MMU_DATA_STORE:
        elt_ofs = offsetof(CPUTLBEntry, addr_write);
        wp_access = BP_MEM_WRITE;
        break;
    case MMU_INST_FETCH:
        elt_ofs = offsetof(CPUTLBEntry, addr_code);
        wp_access = BP_MEM_READ;
        break;
    default:
        g_assert_not_reached();
    }
    tlb_addr = tlb_read_ofs(entry, elt_ofs);

    if (unlikely(!tlb_hit(tlb_addr, addr))) {
        if (!victim_tlb_hit(env, mmu_idx, index, elt_ofs,
                            addr & TARGET_PAGE_MASK)) {
            tlb_fill(env_cpu(env), addr, size, access_type, mmu_idx, retaddr);
            /* TLB resize via tlb_fill may have moved the entry. */
            index = tlb_index(env, mmu_idx, addr);
            entry = tlb_entry(env, mmu_idx, addr);
        }
        tlb_addr = tlb_read_ofs(entry, elt_ofs);
    }

    if (!size) {
        return NULL;
    }

    /* Handle watchpoints.  */
    if (tlb_addr & TLB_WATCHPOINT) {
        cpu_check_watchpoint(env_cpu(env), addr, size,
                             env->iotlb[mmu_idx][index].attrs,
                             wp_access, retaddr);
    }

    if (tlb_addr & (TLB_NOTDIRTY | TLB_MMIO)) {
        /* I/O access */
        return NULL;
    }

    return (void *)((uintptr_t)addr + entry->addend);
}

void *tlb_vaddr_to_host(CPUArchState *env, abi_ptr addr,
                        MMUAccessType access_type, int mmu_idx)
{
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    uintptr_t tlb_addr, page;
    size_t elt_ofs;

    switch (access_type) {
    case MMU_DATA_LOAD:
        elt_ofs = offsetof(CPUTLBEntry, addr_read);
        break;
    case MMU_DATA_STORE:
        elt_ofs = offsetof(CPUTLBEntry, addr_write);
        break;
    case MMU_INST_FETCH:
        elt_ofs = offsetof(CPUTLBEntry, addr_code);
        break;
    default:
        g_assert_not_reached();
    }

    page = addr & TARGET_PAGE_MASK;
    tlb_addr = tlb_read_ofs(entry, elt_ofs);

    if (!tlb_hit_page(tlb_addr, page)) {
        uintptr_t index = tlb_index(env, mmu_idx, addr);

        if (!victim_tlb_hit(env, mmu_idx, index, elt_ofs, page)) {
            CPUState *cs = env_cpu(env);
            CPUClass *cc = CPU_GET_CLASS(cs->uc, cs);

            if (!cc->tlb_fill(cs, addr, 0, access_type, mmu_idx, true, 0)) {
                /* Non-faulting page table read failed.  */
                return NULL;
            }

            /* TLB resize via tlb_fill may have moved the entry.  */
            entry = tlb_entry(env, mmu_idx, addr);
        }
        tlb_addr = tlb_read_ofs(entry, elt_ofs);
    }

    if (tlb_addr & ~TARGET_PAGE_MASK) {
        /* IO access */
        return NULL;
    }

    return (void *)((uintptr_t)addr + entry->addend);
}

/* Probe for a read-modify-write atomic operation.  Do not allow unaligned
 * operations, or io operations to proceed.  Return the host address.  */
static void *atomic_mmu_lookup(CPUArchState *env, target_ulong addr,
                               TCGMemOpIdx oi, uintptr_t retaddr)
{
    size_t mmu_idx = get_mmuidx(oi);
    uintptr_t index = tlb_index(env, mmu_idx, addr);
    CPUTLBEntry *tlbe = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = tlb_addr_write(tlbe);
    MemOp mop = get_memop(oi);
    int a_bits = get_alignment_bits(mop);
    int s_bits = mop & MO_SIZE;

    /* Adjust the given return address.  */
    retaddr -= GETPC_ADJ;

    /* Enforce guest required alignment.  */
    if (unlikely(a_bits > 0 && (addr & ((1 << a_bits) - 1)))) {
        /* ??? Maybe indicate atomic op to cpu_unaligned_access */
        cpu_unaligned_access(env_cpu(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }

    /* Enforce qemu required alignment.  */
    if (unlikely(addr & ((1 << s_bits) - 1))) {
        /* We get here if guest alignment was not requested,
           or was not enforced by cpu_unaligned_access above.
           We might widen the access and emulate, but for now
           mark an exception and exit the cpu loop.  */
        goto stop_the_world;
    }

    /* Check TLB entry and enforce page permissions.  */
    if (!tlb_hit(tlb_addr, addr)) {
        if (!VICTIM_TLB_HIT(addr_write, addr)) {
            tlb_fill(env_cpu(env), addr, 1 << s_bits, MMU_DATA_STORE,
                     mmu_idx, retaddr);
            index = tlb_index(env, mmu_idx, addr);
            tlbe = tlb_entry(env, mmu_idx, addr);
        }
        tlb_addr = tlb_addr_write(tlbe) & ~TLB_INVALID_MASK;
    }

    /* Check notdirty */
    if (unlikely(tlb_addr & TLB_NOTDIRTY)) {
        tlb_set_dirty(env_cpu(env), addr);
        tlb_addr = tlb_addr & ~TLB_NOTDIRTY;
    }

    /* Notice an IO access or a needs-MMU-lookup access */
    if (unlikely(tlb_addr & TLB_MMIO)) {
        /* There's really nothing that can be done to
           support this apart from stop-the-world.  */
        goto stop_the_world;
    }

    /* Let the guest notice RMW on a write-only page.  */
    if (unlikely(tlbe->addr_read != (tlb_addr & ~TLB_NOTDIRTY))) {
        tlb_fill(env_cpu(env), addr, 1 << s_bits, MMU_DATA_LOAD,
                 mmu_idx, retaddr);
        /* Since we don't support reads and writes to different addresses,
           and we do have the proper page loaded for write, this shouldn't
           ever return.  But just in case, handle via stop-the-world.  */
        goto stop_the_world;
    }

    return (void *)((uintptr_t)addr + tlbe->addend);

 stop_the_world:
    assert(0 && "unexpected goto stop_the_world"); // SNPS added
    cpu_loop_exit_atomic(env_cpu(env), retaddr);
}

/*
 * Load Helpers
 *
 * We support two different access types. SOFTMMU_CODE_ACCESS is
 * specifically for reading instructions from system memory. It is
 * called by the translation loop and in some helpers where the code
 * is disassembled. It shouldn't be called directly by guest code.
 */

typedef uint64_t FullLoadHelper(CPUArchState *env, target_ulong addr,
                                TCGMemOpIdx oi, uintptr_t retaddr);

static inline uint64_t __attribute__((always_inline))
load_helper(CPUArchState *env, target_ulong addr, TCGMemOpIdx oi,
            uintptr_t retaddr, MemOp op, bool code_read, bool is_softmmu_access,
            FullLoadHelper *full_load)
{
    uintptr_t mmu_idx = get_mmuidx(oi);
    uintptr_t index = tlb_index(env, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = code_read ? entry->addr_code : entry->addr_read;
    const size_t tlb_off = code_read ?
        offsetof(CPUTLBEntry, addr_code) : offsetof(CPUTLBEntry, addr_read);
    const MMUAccessType access_type =
        code_read ? MMU_INST_FETCH : MMU_DATA_LOAD;
    unsigned a_bits = get_alignment_bits(get_memop(oi));
    void *haddr;
    uint64_t res;
    size_t size = memop_size(op);
    int error_code;
    struct hook *hook;
    bool handled;
    HOOK_FOREACH_VAR_DECLARE;

    struct uc_struct *uc = env->uc;
    MemoryRegion *mr = memory_mapping(uc, addr);

    // memory might be still unmapped while reading or fetching
    if (mr == NULL) {
        handled = false;
        if (is_softmmu_access) {
            error_code = UC_ERR_FETCH_UNMAPPED;
            HOOK_FOREACH(uc, hook, UC_HOOK_MEM_FETCH_UNMAPPED) {
                if (!HOOK_BOUND_CHECK(hook, addr)) {
                    continue;
                }
                if ((handled = ((uc_cb_eventmem_t)hook->callback)(uc, UC_MEM_FETCH_UNMAPPED, addr, size, 0, hook->user_data))) {
                    break;
                }
            }
        } else {
            error_code = UC_ERR_READ_UNMAPPED;
            HOOK_FOREACH(uc, hook, UC_HOOK_MEM_READ_UNMAPPED) {
                if (!HOOK_BOUND_CHECK(hook, addr)) {
                    continue;
                }
                if ((handled = ((uc_cb_eventmem_t)hook->callback)(uc, UC_MEM_READ_UNMAPPED, addr, size, 0, hook->user_data))) {
                    break;
                }
            }
        }
        if (handled) {
            env->invalid_error = UC_ERR_OK;
            mr = memory_mapping(uc, addr);  // FIXME: what if mr is still NULL at this time?
        } else {
            env->invalid_addr = addr;
            env->invalid_error = error_code;
            // printf("***** Invalid fetch (unmapped memory) at " TARGET_FMT_lx "\n", addr);
            cpu_exit(uc->current_cpu);
            return 0;
        }
    }

    if (is_softmmu_access) {
        // Unicorn: callback on fetch from NX
        if (mr != NULL && !(mr->perms & UC_PROT_EXEC)) {
            handled = false;
            HOOK_FOREACH(uc, hook, UC_HOOK_MEM_FETCH_PROT) {
                if (!HOOK_BOUND_CHECK(hook, addr)) {
                    continue;
                }
                if ((handled = ((uc_cb_eventmem_t)hook->callback)(uc, UC_MEM_FETCH_PROT, addr, size, 0, hook->user_data))) {
                    break;
                }
            }

            if (handled) {
                env->invalid_error = UC_ERR_OK;
            } else {
                env->invalid_addr = addr;
                env->invalid_error = UC_ERR_FETCH_PROT;
                // printf("***** Invalid fetch (non-executable) at " TARGET_FMT_lx "\n", addr);
                cpu_exit(uc->current_cpu);
                return 0;
            }
        }
    }

    // Unicorn: callback on memory read
    // NOTE: this happens before the actual read, so we cannot tell
    // the callback if read access is succesful, or not.
    // See UC_HOOK_MEM_READ_AFTER & UC_MEM_READ_AFTER if you only care
    // about successful read
    if (!code_read) {
        HOOK_FOREACH(uc, hook, UC_HOOK_MEM_READ) {
            if (!HOOK_BOUND_CHECK(hook, addr)) {
                continue;
            }
            ((uc_cb_hookmem_t)hook->callback)(env->uc, UC_MEM_READ, addr, size, 0, hook->user_data);
        }
    }

    // Unicorn: callback on non-readable memory
    if (!code_read && mr != NULL && !(mr->perms & UC_PROT_READ)) {
        handled = false;
        HOOK_FOREACH(uc, hook, UC_HOOK_MEM_READ_PROT) {
            if (!HOOK_BOUND_CHECK(hook, addr)) {
                continue;
            }
            if ((handled = ((uc_cb_eventmem_t)hook->callback)(uc, UC_MEM_READ_PROT, addr, size, 0, hook->user_data))) {
                break;
            }
        }

        if (handled) {
            env->invalid_error = UC_ERR_OK;
        } else {
            env->invalid_addr = addr;
            env->invalid_error = UC_ERR_READ_PROT;
            // printf("***** Invalid memory read (non-readable) at " TARGET_FMT_lx "\n", addr);
            cpu_exit(uc->current_cpu);
            return 0;
        }
    }

    /* Handle CPU specific unaligned behaviour */
    if (addr & ((1 << a_bits) - 1)) {
        cpu_unaligned_access(env_cpu(env), addr, access_type,
                             mmu_idx, retaddr);
    }

    /* If the TLB entry is for a different page, reload and try again.  */
    if (!tlb_hit(tlb_addr, addr)) {
        if (!victim_tlb_hit(env, mmu_idx, index, tlb_off,
                            addr & TARGET_PAGE_MASK)) {
            tlb_fill(env_cpu(env), addr, size,
                     access_type, mmu_idx, retaddr);
            index = tlb_index(env, mmu_idx, addr);
            entry = tlb_entry(env, mmu_idx, addr);
        }
        tlb_addr = code_read ? entry->addr_code : entry->addr_read;
        tlb_addr &= ~TLB_INVALID_MASK;
    }

    /* Handle anything that isn't just a straight memory access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        CPUIOTLBEntry *iotlbentry;

        /* For anything that is unaligned, recurse through full_load.  */
        if ((addr & (size - 1)) != 0) {
            goto do_unaligned_access;
        }

        iotlbentry = &env->iotlb[mmu_idx][index];

        /* Handle watchpoints.  */
        if (unlikely(tlb_addr & TLB_WATCHPOINT)) {
            /* On watchpoint hit, this will longjmp out.  */
            cpu_check_watchpoint(env_cpu(env), addr, size,
                                 iotlbentry->attrs, BP_MEM_READ, retaddr);

            /* The backing page may or may not require I/O.  */
            tlb_addr &= ~TLB_WATCHPOINT;
            if ((tlb_addr & ~TARGET_PAGE_MASK) == 0) {
                goto do_aligned_access;
            }
        }

        /* Handle I/O access.  */
        return io_readx(env, iotlbentry, mmu_idx, addr,
                        retaddr, access_type, op);
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (size > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + size - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;
        uint64_t r1, r2;
        unsigned shift;
    do_unaligned_access:
        addr1 = addr & ~((target_ulong)size - 1);
        addr2 = addr1 + size;
        r1 = full_load(env, addr1, oi, retaddr);
        r2 = full_load(env, addr2, oi, retaddr);
        shift = (addr & (size - 1)) * 8;

        if (memop_big_endian(op)) {
            /* Big-endian combine.  */
            res = (r1 << shift) | (r2 >> ((size * 8) - shift));
        } else {
            /* Little-endian combine.  */
            res = (r1 >> shift) | (r2 << ((size * 8) - shift));
        }
        res = res & MAKE_64BIT_MASK(0, size * 8);
        goto finished;
    }

 do_aligned_access:
    haddr = (void *)((uintptr_t)addr + entry->addend);
    switch (op) {
    case MO_UB:
        res = ldub_p(haddr);
        break;
    case MO_BEUW:
        res = lduw_be_p(haddr);
        break;
    case MO_LEUW:
        res = lduw_le_p(haddr);
        break;
    case MO_BEUL:
        res = (uint32_t)ldl_be_p(haddr);
        break;
    case MO_LEUL:
        res = (uint32_t)ldl_le_p(haddr);
        break;
    case MO_BEQ:
        res = ldq_be_p(haddr);
        break;
    case MO_LEQ:
        res = ldq_le_p(haddr);
        break;
    default:
        g_assert_not_reached();
    }

finished:
    // Unicorn: callback on successful read
    if (!code_read) {
        HOOK_FOREACH(uc, hook, UC_HOOK_MEM_READ_AFTER) {
            if (!HOOK_BOUND_CHECK(hook, addr)) {
                continue;
            }
            ((uc_cb_hookmem_t)hook->callback)(env->uc, UC_MEM_READ_AFTER, addr, size, res, hook->user_data);
        }
    }

    return res;
}

/*
 * For the benefit of TCG generated code, we want to avoid the
 * complication of ABI-specific return type promotion and always
 * return a value extended to the register size of the host. This is
 * tcg_target_long, except in the case of a 32-bit host and 64-bit
 * data, and for that we always have uint64_t.
 *
 * We don't bother with this widened value for SOFTMMU_CODE_ACCESS.
 */

static uint64_t full_ldub_mmu(CPUArchState *env, target_ulong addr,
                              TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_UB, false, false,
                       full_ldub_mmu);
}

tcg_target_ulong helper_ret_ldub_mmu(CPUArchState *env, target_ulong addr,
                                     TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_ldub_mmu(env, addr, oi, retaddr);
}

static uint64_t full_le_lduw_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEUW, false, false,
                       full_le_lduw_mmu);
}

tcg_target_ulong helper_le_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_le_lduw_mmu(env, addr, oi, retaddr);
}

static uint64_t full_be_lduw_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEUW, false, false,
                       full_be_lduw_mmu);
}

tcg_target_ulong helper_be_lduw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_be_lduw_mmu(env, addr, oi, retaddr);
}

static uint64_t full_le_ldul_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEUL, false, false,
                       full_le_ldul_mmu);
}

tcg_target_ulong helper_le_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_le_ldul_mmu(env, addr, oi, retaddr);
}

static uint64_t full_be_ldul_mmu(CPUArchState *env, target_ulong addr,
                                 TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEUL, false, false,
                       full_be_ldul_mmu);
}

tcg_target_ulong helper_be_ldul_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_be_ldul_mmu(env, addr, oi, retaddr);
}

uint64_t helper_le_ldq_mmu(CPUArchState *env, target_ulong addr,
                           TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEQ, false, false,
                       helper_le_ldq_mmu);
}

uint64_t helper_be_ldq_mmu(CPUArchState *env, target_ulong addr,
                           TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEQ, false, false,
                       helper_be_ldq_mmu);
}

/*
 * Provide signed versions of the load routines as well.  We can of course
 * avoid this for 64-bit data, or for 32-bit data on 32-bit host.
 */


tcg_target_ulong helper_ret_ldsb_mmu(CPUArchState *env, target_ulong addr,
                                     TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int8_t)helper_ret_ldub_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_le_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_le_lduw_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_be_ldsw_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int16_t)helper_be_lduw_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_le_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_le_ldul_mmu(env, addr, oi, retaddr);
}

tcg_target_ulong helper_be_ldsl_mmu(CPUArchState *env, target_ulong addr,
                                    TCGMemOpIdx oi, uintptr_t retaddr)
{
    return (int32_t)helper_be_ldul_mmu(env, addr, oi, retaddr);
}

/*
 * Store Helpers
 */

static inline void __attribute__((always_inline))
store_helper(CPUArchState *env, target_ulong addr, uint64_t val,
             TCGMemOpIdx oi, uintptr_t retaddr, MemOp op)
{
    uintptr_t mmu_idx = get_mmuidx(oi);
    uintptr_t index = tlb_index(env, mmu_idx, addr);
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = tlb_addr_write(entry);
    const size_t tlb_off = offsetof(CPUTLBEntry, addr_write);
    unsigned a_bits = get_alignment_bits(get_memop(oi));
    void *haddr;
    size_t size = memop_size(op);
    struct hook *hook;
    bool handled;
    HOOK_FOREACH_VAR_DECLARE;

    struct uc_struct *uc = env->uc;
    MemoryRegion *mr = memory_mapping(uc, addr);

    // Unicorn: callback on memory write
    HOOK_FOREACH(uc, hook, UC_HOOK_MEM_WRITE) {
            if (!HOOK_BOUND_CHECK(hook, addr)) {
                continue;
            }
        ((uc_cb_hookmem_t)hook->callback)(uc, UC_MEM_WRITE, addr, size, val, hook->user_data);
    }

    // Unicorn: callback on invalid memory
    if (mr == NULL) {
        handled = false;
        HOOK_FOREACH(uc, hook, UC_HOOK_MEM_WRITE_UNMAPPED) {
            if (!HOOK_BOUND_CHECK(hook, addr)) {
                continue;
            }
            if ((handled = ((uc_cb_eventmem_t)hook->callback)(uc, UC_MEM_WRITE_UNMAPPED, addr, size, val, hook->user_data))) {
                break;
            }
        }

        if (!handled) {
            // save error & quit
            env->invalid_addr = addr;
            env->invalid_error = UC_ERR_WRITE_UNMAPPED;
            // printf("***** Invalid memory write at " TARGET_FMT_lx "\n", addr);
            cpu_exit(uc->current_cpu);
            return;
        } else {
            env->invalid_error = UC_ERR_OK;
            mr = memory_mapping(uc, addr);  // FIXME: what if mr is still NULL at this time?
        }
    }

    // Unicorn: callback on non-writable memory
    if (mr != NULL && !(mr->perms & UC_PROT_WRITE)) {  //non-writable
        handled = false;
        HOOK_FOREACH(uc, hook, UC_HOOK_MEM_WRITE_PROT) {
            if (!HOOK_BOUND_CHECK(hook, addr)) {
                continue;
            }
            if ((handled = ((uc_cb_eventmem_t)hook->callback)(uc, UC_MEM_WRITE_PROT, addr, size, val, hook->user_data))) {
                break;
            }
        }

        if (handled) {
            env->invalid_error = UC_ERR_OK;
        } else {
            env->invalid_addr = addr;
            env->invalid_error = UC_ERR_WRITE_PROT;
            // printf("***** Invalid memory write (ro) at " TARGET_FMT_lx "\n", addr);
            cpu_exit(uc->current_cpu);
            return;
        }
    }

    /* Handle CPU specific unaligned behaviour */
    if (addr & ((1 << a_bits) - 1)) {
        cpu_unaligned_access(env_cpu(env), addr, MMU_DATA_STORE,
                             mmu_idx, retaddr);
    }

    /* If the TLB entry is for a different page, reload and try again.  */
    if (!tlb_hit(tlb_addr, addr)) {
        if (!victim_tlb_hit(env, mmu_idx, index, tlb_off,
            addr & TARGET_PAGE_MASK)) {
            tlb_fill(env_cpu(env), addr, size, MMU_DATA_STORE,
                     mmu_idx, retaddr);
            index = tlb_index(env, mmu_idx, addr);
            entry = tlb_entry(env, mmu_idx, addr);
        }
        tlb_addr = tlb_addr_write(entry) & ~TLB_INVALID_MASK;
    }

    /* Handle anything that isn't just a straight memory access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK)) {
        CPUIOTLBEntry *iotlbentry;

        /* For anything that is unaligned, recurse through byte stores.  */
        if ((addr & (size - 1)) != 0) {
            goto do_unaligned_access;
        }

        iotlbentry = &env->iotlb[mmu_idx][index];

        /* Handle watchpoints.  */
        if (unlikely(tlb_addr & TLB_WATCHPOINT)) {
            /* On watchpoint hit, this will longjmp out.  */
            cpu_check_watchpoint(env_cpu(env), addr, size,
                                 iotlbentry->attrs, BP_MEM_WRITE, retaddr);

            /* The backing page may or may not require I/O.  */
            tlb_addr &= ~TLB_WATCHPOINT;
            if ((tlb_addr & ~TARGET_PAGE_MASK) == 0) {
                goto do_aligned_access;
            }
        }

        /* Handle I/O access.  */
        io_writex(env, iotlbentry, mmu_idx, val, addr, retaddr, op);
        return;
    }

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (size > 1
        && unlikely((addr & ~TARGET_PAGE_MASK) + size - 1
                     >= TARGET_PAGE_SIZE)) {
        int i;
        uintptr_t index2;
        CPUTLBEntry *entry2;
        target_ulong page2, tlb_addr2;
        size_t size2;

    do_unaligned_access:
        /*
         * Ensure the second page is in the TLB.  Note that the first page
         * is already guaranteed to be filled, and that the second page
         * cannot evict the first.
         */
        page2 = (addr + size) & TARGET_PAGE_MASK;
        size2 = (addr + size) & ~TARGET_PAGE_MASK;
        index2 = tlb_index(env, mmu_idx, page2);
        entry2 = tlb_entry(env, mmu_idx, page2);
        tlb_addr2 = tlb_addr_write(entry2);
        if (!tlb_hit_page(tlb_addr2, page2)) {
            if (!victim_tlb_hit(env, mmu_idx, index2, tlb_off, page2)) {
                tlb_fill(env_cpu(env), page2, size2, MMU_DATA_STORE,
                         mmu_idx, retaddr);
                index2 = tlb_index(env, mmu_idx, page2);
                entry2 = tlb_entry(env, mmu_idx, page2);
            }
            tlb_addr2 = tlb_addr_write(entry2);
        }

        /*
         * Handle watchpoints.  Since this may trap, all checks
         * must happen before any store.
         */
        if (unlikely(tlb_addr & TLB_WATCHPOINT)) {
            cpu_check_watchpoint(env_cpu(env), addr, size - size2,
                                 env->iotlb[mmu_idx][index].attrs,
                                 BP_MEM_WRITE, retaddr);
        }
        if (unlikely(tlb_addr2 & TLB_WATCHPOINT)) {
            cpu_check_watchpoint(env_cpu(env), page2, size2,
                                 env->iotlb[mmu_idx][index2].attrs,
                                 BP_MEM_WRITE, retaddr);
        }

        /*
         * XXX: not efficient, but simple.
         * This loop must go in the forward direction to avoid issues
         * with self-modifying code in Windows 64-bit.
         */
        for (i = 0; i < size; ++i) {
            uint8_t val8;
            if (memop_big_endian(op)) {
                /* Big-endian extract.  */
                val8 = val >> (((size - 1) * 8) - (i * 8));
            } else {
                /* Little-endian extract.  */
                val8 = val >> (i * 8);
            }
            helper_ret_stb_mmu(env, addr + i, val8, oi, retaddr);
        }
        return;
    }

 do_aligned_access:
    haddr = (void *)((uintptr_t)addr + entry->addend);
    switch (op) {
    case MO_UB:
        stb_p(haddr, val);
        break;
    case MO_BEUW:
        stw_be_p(haddr, val);
        break;
    case MO_LEUW:
        stw_le_p(haddr, val);
        break;
    case MO_BEUL:
        stl_be_p(haddr, val);
        break;
    case MO_LEUL:
        stl_le_p(haddr, val);
        break;
    case MO_BEQ:
        stq_be_p(haddr, val);
        break;
    case MO_LEQ:
        stq_le_p(haddr, val);
        break;
    default:
        g_assert_not_reached();
        break;
    }
}

void helper_ret_stb_mmu(CPUArchState *env, target_ulong addr, uint8_t val,
                        TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_UB);
}

void helper_le_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_LEUW);
}

void helper_be_stw_mmu(CPUArchState *env, target_ulong addr, uint16_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_BEUW);
}

void helper_le_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_LEUL);
}

void helper_be_stl_mmu(CPUArchState *env, target_ulong addr, uint32_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_BEUL);
}

void helper_le_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_LEQ);
}

void helper_be_stq_mmu(CPUArchState *env, target_ulong addr, uint64_t val,
                       TCGMemOpIdx oi, uintptr_t retaddr)
{
    store_helper(env, addr, val, oi, retaddr, MO_BEQ);
}

/* First set of helpers allows passing in of OI and RETADDR.  This makes
   them callable from other helpers.  */

#define EXTRA_ARGS     , TCGMemOpIdx oi, uintptr_t retaddr
#define ATOMIC_NAME(X) \
    HELPER(glue(glue(glue(atomic_ ## X, SUFFIX), END), _mmu))
#define ATOMIC_MMU_LOOKUP  atomic_mmu_lookup(env, addr, oi, retaddr)
#define ATOMIC_MMU_CLEANUP do { } while (0)

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

#if HAVE_CMPXCHG128 || HAVE_ATOMIC128
#define DATA_SIZE 16
#include "atomic_template.h"
#endif

/* Second set of helpers are directly callable from TCG as helpers.  */

#undef EXTRA_ARGS
#undef ATOMIC_NAME
#undef ATOMIC_MMU_LOOKUP
#define EXTRA_ARGS         , TCGMemOpIdx oi
#define ATOMIC_NAME(X)     HELPER(glue(glue(atomic_ ## X, SUFFIX), END))
#define ATOMIC_MMU_LOOKUP  atomic_mmu_lookup(env, addr, oi, GETPC())

#define DATA_SIZE 1
#include "atomic_template.h"

#define DATA_SIZE 2
#include "atomic_template.h"

#define DATA_SIZE 4
#include "atomic_template.h"

#ifdef CONFIG_ATOMIC64
#define DATA_SIZE 8
#include "atomic_template.h"
#endif

/* Code access functions.  */

static uint64_t full_ldub_cmmu(CPUArchState *env, target_ulong addr,
                               TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_8, true, true, full_ldub_cmmu);
}

uint8_t helper_ret_ldb_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_ldub_cmmu(env, addr, oi, retaddr);
}

static uint64_t full_le_lduw_cmmu(CPUArchState *env, target_ulong addr,
                                  TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEUW, true, true,
                       full_le_lduw_cmmu);
}

uint16_t helper_le_ldw_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_le_lduw_cmmu(env, addr, oi, retaddr);
}

static uint64_t full_be_lduw_cmmu(CPUArchState *env, target_ulong addr,
                                  TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEUW, true, true,
                       full_be_lduw_cmmu);
}

uint16_t helper_be_ldw_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_be_lduw_cmmu(env, addr, oi, retaddr);
}

static uint64_t full_le_ldul_cmmu(CPUArchState *env, target_ulong addr,
                                  TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEUL, true, true,
                       full_le_ldul_cmmu);
}

uint32_t helper_le_ldl_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_le_ldul_cmmu(env, addr, oi, retaddr);
}

static uint64_t full_be_ldul_cmmu(CPUArchState *env, target_ulong addr,
                                  TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEUL, true, true,
                       full_be_ldul_cmmu);
}

uint32_t helper_be_ldl_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return full_be_ldul_cmmu(env, addr, oi, retaddr);
}

uint64_t helper_le_ldq_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_LEQ, true, true,
                       helper_le_ldq_cmmu);
}

uint64_t helper_be_ldq_cmmu(CPUArchState *env, target_ulong addr,
                            TCGMemOpIdx oi, uintptr_t retaddr)
{
    return load_helper(env, addr, oi, retaddr, MO_BEQ, true, true,
                       helper_be_ldq_cmmu);
}

// SNPS added
static target_ulong lookup_virt_addr(CPUIOTLBEntry* iotlbe);
static target_ulong lookup_virt_addr(CPUIOTLBEntry* iotlbe) {
    CPUTLBEntry* tlbe = iotlbe->p2v;
    if (iotlbe->phys == -1 || tlbe == NULL)
        return -1;

    if (tlbe->addr_read != -1)
        return tlbe->addr_read & TARGET_PAGE_MASK;
    if (tlbe->addr_write != -1)
        return tlbe->addr_write & TARGET_PAGE_MASK;
    if (tlbe->addr_code != -1)
        return tlbe->addr_code & TARGET_PAGE_MASK;

    return -1;
}

// SNPS added
void dmi_invalidate(CPUState *cpu, uint64_t start, uint64_t end) {
    CPUArchState *env = cpu->env_ptr;
    int mmu_idx, idx;

    if (start == 0 && end == ~0ull) {
        tlb_flush(cpu);
        return;
    }

    for (mmu_idx = 0; mmu_idx < NB_MMU_MODES; mmu_idx++) {
        for (idx = 0; idx < CPU_TLB_SIZE; idx++) {
            CPUIOTLBEntry* entry = &env->iotlb[mmu_idx][idx];
            target_ulong vaddr = lookup_virt_addr(entry);
            if (entry->phys >= start && entry->phys < end && vaddr != -1) {
                if (tlb_flush_page(cpu, vaddr))
                    // that caused a full flush - we are done here
                    return;
            }
        }

        for (idx = 0; idx < CPU_VTLB_SIZE; idx++) {
            CPUIOTLBEntry* entry = &env->iotlb_v[mmu_idx][idx];
            target_ulong vaddr = lookup_virt_addr(entry);
            if (entry->phys >= start && entry->phys < end && vaddr != -1) {
                if (tlb_flush_page(cpu, vaddr))
                    // that caused a full flush - we are done here
                    return;
            }
        }
    }
}
