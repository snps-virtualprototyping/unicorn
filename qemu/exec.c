/*
 *  Virtual page mapping
 *
 *  Copyright (c) 2003 Fabrice Bellard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
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
#include "qapi/error.h"
#ifndef _WIN32
#include <sys/mman.h>
#endif

#include "qemu/cutils.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#include "hw/hw.h"
#include "hw/qdev.h"
#include "sysemu/sysemu.h"
#include "qemu/timer.h"
#include "exec/memory.h"
#include "exec/address-spaces.h"
#if defined(CONFIG_USER_ONLY)
#include "qemu.h"
#endif
#include "exec/cpu-all.h"

#include "translate-all.h"

#include "exec/memory-internal.h"
#include "exec/ram_addr.h"

#include "qemu/range.h"
#ifndef _WIN32
#include "qemu/mmap-alloc.h"
#endif

#include "uc_priv.h"

//#define DEBUG_SUBPAGE

bool set_preferred_target_page_bits(struct uc_struct *uc, int bits)
{
    /* The target page size is the lowest common denominator for all
     * the CPUs in the system, so we can only make it smaller, never
     * larger. And we can't make it smaller once we've committed to
     * a particular size.
     */
#ifdef TARGET_PAGE_BITS_VARY
    assert(bits >= TARGET_PAGE_BITS_MIN);
    if (uc->target_page_bits == 0 || uc->target_page_bits > bits) {
        if (uc->target_page_bits_decided) {
            return false;
        }
        uc->target_page_bits = bits;
    }
#endif
    return true;
}

#if !defined(CONFIG_USER_ONLY)
/* current CPU in the current thread. It is only valid inside
   cpu_exec() */
//DEFINE_TLS(CPUState *, current_cpu);

static void finalize_target_page_bits(struct uc_struct *uc)
{
#ifdef TARGET_PAGE_BITS_VARY
    if (uc->target_page_bits == 0) {
        uc->target_page_bits = TARGET_PAGE_BITS_MIN;
    }
    uc->target_page_bits_decided = true;
#endif
}

typedef struct PhysPageEntry PhysPageEntry;

struct PhysPageEntry {
    /* How many bits skip to next level (in units of L2_SIZE). 0 for a leaf. */
    uint32_t skip : 6;
    /* index into phys_sections (!skip) or phys_map_nodes (skip) */
    uint32_t ptr : 26;
};

#define PHYS_MAP_NODE_NIL (((uint32_t)~0) >> 6)

/* Size of the L2 (and L3, etc) page tables.  */
#define ADDR_SPACE_BITS 64

#define P_L2_BITS 9
#define P_L2_SIZE (1 << P_L2_BITS)

#define P_L2_LEVELS (((ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / P_L2_BITS) + 1)

typedef PhysPageEntry Node[P_L2_SIZE];

typedef struct PhysPageMap {
    unsigned sections_nb;
    unsigned sections_nb_alloc;
    unsigned nodes_nb;
    unsigned nodes_nb_alloc;
    Node *nodes;
    MemoryRegionSection *sections;
} PhysPageMap;

struct AddressSpaceDispatch {
    MemoryRegionSection *mru_section;
    /* This is a multi-level map on the physical address space.
     * The bottom level has pointers to MemoryRegionSections.
     */
    PhysPageEntry phys_map;
    PhysPageMap map;
    struct uc_struct *uc;
};

#define SUBPAGE_IDX(addr) ((addr) & ~TARGET_PAGE_MASK)
typedef struct subpage_t {
    MemoryRegion iomem;
    FlatView *fv;
    hwaddr base;
    uint16_t sub_section[];
} subpage_t;

#define PHYS_SECTION_UNASSIGNED 0
#define PHYS_SECTION_NOTDIRTY 1
#define PHYS_SECTION_ROM 2

static void memory_map_init(struct uc_struct *uc);
static void tcg_commit(MemoryListener *listener);

#endif

#if !defined(CONFIG_USER_ONLY)

static void phys_map_node_reserve(struct uc_struct *uc, PhysPageMap *map, unsigned nodes)
{
    if (map->nodes_nb + nodes > map->nodes_nb_alloc) {
        map->nodes_nb_alloc = MAX(uc->phys_map_node_alloc_hint, map->nodes_nb + nodes);
        map->nodes = g_renew(Node, map->nodes, map->nodes_nb_alloc);
        uc->phys_map_node_alloc_hint = map->nodes_nb_alloc;
    }
}

static uint32_t phys_map_node_alloc(PhysPageMap *map, bool leaf)
{
    unsigned i;
    uint32_t ret;
    PhysPageEntry e;
    PhysPageEntry *p;

    ret = map->nodes_nb++;
    p = map->nodes[ret];
    assert(ret != PHYS_MAP_NODE_NIL);
    assert(ret != map->nodes_nb_alloc);

    e.skip = leaf ? 0 : 1;
    e.ptr = leaf ? PHYS_SECTION_UNASSIGNED : PHYS_MAP_NODE_NIL;
    for (i = 0; i < P_L2_SIZE; ++i) {
        memcpy(&p[i], &e, sizeof(e));
    }
    return ret;
}

static void phys_page_set_level(PhysPageMap *map, PhysPageEntry *lp,
        hwaddr *index, uint64_t *nb, uint16_t leaf,
        int level)
{
    PhysPageEntry *p;
    hwaddr step = (hwaddr)1 << (level * P_L2_BITS);

    if (lp->skip && lp->ptr == PHYS_MAP_NODE_NIL) {
        lp->ptr = phys_map_node_alloc(map, level == 0);
    }
    p = map->nodes[lp->ptr];
    lp = &p[(*index >> (level * P_L2_BITS)) & (P_L2_SIZE - 1)];

    while (*nb && lp < &p[P_L2_SIZE]) {
        if ((*index & (step - 1)) == 0 && *nb >= step) {
            lp->skip = 0;
            lp->ptr = leaf;
            *index += step;
            *nb -= step;
        } else {
            phys_page_set_level(map, lp, index, nb, leaf, level - 1);
        }
        ++lp;
    }
}

static void phys_page_set(AddressSpaceDispatch *d,
                          hwaddr index, uint64_t nb,
                          uint16_t leaf)
{
    /* Wildly overreserve - it doesn't matter much. */
    phys_map_node_reserve(d->uc, &d->map, 3 * P_L2_LEVELS);

    phys_page_set_level(&d->map, &d->phys_map, &index, &nb, leaf, P_L2_LEVELS - 1);
}

/* Compact a non leaf page entry. Simply detect that the entry has a single child,
 * and update our entry so we can skip it and go directly to the destination.
 */
static void phys_page_compact(PhysPageEntry *lp, Node *nodes, unsigned long *compacted)
{
    unsigned valid_ptr = P_L2_SIZE;
    int valid = 0;
    PhysPageEntry *p;
    int i;

    if (lp->ptr == PHYS_MAP_NODE_NIL) {
        return;
    }

    p = nodes[lp->ptr];
    for (i = 0; i < P_L2_SIZE; i++) {
        if (p[i].ptr == PHYS_MAP_NODE_NIL) {
            continue;
        }

        valid_ptr = i;
        valid++;
        if (p[i].skip) {
            phys_page_compact(&p[i], nodes, compacted);
        }
    }

    /* We can only compress if there's only one child. */
    if (valid != 1) {
        return;
    }

    assert(valid_ptr < P_L2_SIZE);

    /* Don't compress if it won't fit in the # of bits we have. */
    if (P_L2_LEVELS >= (1 << 6) &&
        lp->skip + p[valid_ptr].skip >= (1 << 6)) {
        return;
    }

    lp->ptr = p[valid_ptr].ptr;
    if (!p[valid_ptr].skip) {
        /* If our only child is a leaf, make this a leaf. */
        /* By design, we should have made this node a leaf to begin with so we
         * should never reach here.
         * But since it's so simple to handle this, let's do it just in case we
         * change this rule.
         */
        lp->skip = 0;
    } else {
        lp->skip += p[valid_ptr].skip;
    }
}

void address_space_dispatch_compact(AddressSpaceDispatch *d)
{
    //DECLARE_BITMAP(compacted, nodes_nb);
    // this isnt actually used
    unsigned long* compacted = NULL;

    if (d->phys_map.skip) {
        phys_page_compact(&d->phys_map, d->map.nodes, compacted);
    }
}

static inline bool section_covers_addr(const MemoryRegionSection *section,
                                       hwaddr addr)
{
    /* Memory topology clips a memory region to [0, 2^64); size.hi > 0 means
     * the section must cover the entire address space.
     */
    return int128_gethi(section->size) ||
           range_covers_byte(section->offset_within_address_space,
                             int128_getlo(section->size), addr);
}

static MemoryRegionSection *phys_page_find(AddressSpaceDispatch *d, hwaddr addr)
{
    PhysPageEntry lp = d->phys_map, *p;
    Node *nodes = d->map.nodes;
    MemoryRegionSection *sections = d->map.sections;
    hwaddr index = addr >> TARGET_PAGE_BITS;
    int i;

    for (i = P_L2_LEVELS; lp.skip && (i -= lp.skip) >= 0;) {
        if (lp.ptr == PHYS_MAP_NODE_NIL) {
            return &sections[PHYS_SECTION_UNASSIGNED];
        }
        p = nodes[lp.ptr];
        lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
    }

    if (section_covers_addr(&sections[lp.ptr], addr)) {
        return &sections[lp.ptr];
    } else {
        return &sections[PHYS_SECTION_UNASSIGNED];
    }
}

bool memory_region_is_unassigned(struct uc_struct* uc, MemoryRegion *mr)
{
    return false; // SNPS added
    return mr != &uc->io_mem_rom && mr != &uc->io_mem_notdirty &&
        !mr->rom_device && mr != &uc->io_mem_watch;
}

static MemoryRegionSection *address_space_lookup_region(AddressSpaceDispatch *d,
                                                        hwaddr addr,
                                                        bool resolve_subpage)
{
    MemoryRegionSection *section = qatomic_read(&d->mru_section);
    subpage_t *subpage;
    bool update;

    if (section && section != &d->map.sections[PHYS_SECTION_UNASSIGNED] &&
        section_covers_addr(section, addr)) {
        update = false;
    } else {
        section = phys_page_find(d, addr);
        update = true;
    }
    if (resolve_subpage && section->mr->subpage) {
        subpage = container_of(section->mr, subpage_t, iomem);
        section = &d->map.sections[subpage->sub_section[SUBPAGE_IDX(addr)]];
    }
    if (update) {
        qatomic_set(&d->mru_section, section);
    }
    return section;
}

static MemoryRegionSection *
address_space_translate_internal(AddressSpaceDispatch *d, hwaddr addr, hwaddr *xlat,
        hwaddr *plen, bool resolve_subpage)
{
    MemoryRegionSection *section;
    MemoryRegion *mr;
    Int128 diff;

    section = address_space_lookup_region(d, addr, resolve_subpage);
    /* Compute offset within MemoryRegionSection */
    addr -= section->offset_within_address_space;

    /* Compute offset within MemoryRegion */
    *xlat = addr + section->offset_within_region;

    mr = section->mr;

    /* MMIO registers can be expected to perform full-width accesses based only
     * on their address, without considering adjacent registers that could
     * decode to completely different MemoryRegions.  When such registers
     * exist (e.g. I/O ports 0xcf8 and 0xcf9 on most PC chipsets), MMIO
     * regions overlap wildly.  For this reason we cannot clamp the accesses
     * here.
     *
     * If the length is small (as is the case for address_space_ldl/stl),
     * everything works fine.  If the incoming length is large, however,
     * the caller really has to do the clamping through memory_access_size.
     */
    if (memory_region_is_ram(mr)) {
        diff = int128_sub(section->size, int128_make64(addr));
        *plen = int128_get64(int128_min(diff, int128_make64(*plen)));
    }
    return section;
}

static MemoryRegionSection flatview_do_translate(FlatView *fv,
                                                 hwaddr addr,
                                                 hwaddr *xlat,
                                                 hwaddr *plen,
                                                 bool is_write,
                                                 bool is_mmio,
                                                 AddressSpace **target_as)
{
    IOMMUTLBEntry iotlb;
    MemoryRegionSection *section;
    MemoryRegion *mr;
    MemoryRegionSection failure_section = {0};
    AddressSpaceDispatch *d = flatview_to_dispatch(fv);

    for (;;) {
        section = address_space_translate_internal(
                flatview_to_dispatch(fv), addr, &addr,
                plen, is_mmio);
        mr = section->mr;

        if (!mr->iommu_ops) {
            break;
        }

        iotlb = mr->iommu_ops->translate(mr, addr, is_write ?
                                         IOMMU_WO : IOMMU_RO);
        addr = ((iotlb.translated_addr & ~iotlb.addr_mask)
                | (addr & iotlb.addr_mask));
        *plen = MIN(*plen, (addr | iotlb.addr_mask) - addr + 1);
        if (!(iotlb.perm & (1 << is_write))) {
            goto translate_fail;
        }

        fv = address_space_to_flatview(iotlb.target_as);
        *target_as = iotlb.target_as;
    }

    *xlat = addr;

    return *section;

translate_fail:
    failure_section.mr = &d->uc->io_mem_unassigned;
    return failure_section;
}

IOMMUTLBEntry address_space_get_iotlb_entry(AddressSpace *as, hwaddr addr,
                                            bool is_write)
{
    MemoryRegionSection section;
    hwaddr xlat, plen;
    IOMMUTLBEntry result = {0};

    /* Try to get maximum page mask during translation. */
    plen = (hwaddr)-1;

    /* This can never be MMIO. */
    section = flatview_do_translate(address_space_to_flatview(as), addr,
                                    &xlat, &plen, is_write, false, &as);

    /* Illegal translation */
    if (section.mr == &as->uc->io_mem_unassigned) {
        goto iotlb_fail;
    }

    /* Convert memory region offset into address space offset */
    xlat += section.offset_within_address_space -
        section.offset_within_region;

    if (plen == (hwaddr)-1) {
        /*
         * We use default page size here. Logically it only happens
         * for identity mappings.
         */
        plen = TARGET_PAGE_SIZE;
    }

    /* Convert to address mask */
    plen -= 1;

    result.target_as = as;
    result.iova = addr & ~plen;
    result.translated_addr = xlat & ~plen;
    result.addr_mask = plen;
    /* IOTLBs are for DMAs, and DMA only allows on RAMs. */
    result.perm = IOMMU_RW;
    return result;

iotlb_fail:
    return result;
}

/* Called from RCU critical section */
MemoryRegion *flatview_translate(FlatView *fv, hwaddr addr, hwaddr *xlat,
                                 hwaddr *plen, bool is_write)
{
    MemoryRegion *mr;
    MemoryRegionSection section;
    AddressSpace *as = NULL;

    /* This can be MMIO, so setup MMIO bit. */
    section = flatview_do_translate(fv, addr, xlat, plen, is_write, true, &as);
    mr = section.mr;

    // Unicorn: if'd out
#if 0
    if (xen_enabled() && memory_access_is_direct(mr, is_write)) {
        hwaddr page = ((addr & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE) - addr;
        *plen = MIN(page, *plen);
    }
#endif

    return mr;
}

MemoryRegionSection *
address_space_translate_for_iotlb(CPUState *cpu, int asidx, hwaddr addr,
                                  hwaddr *xlat, hwaddr *plen,
                                  MemTxAttrs attrs, int *prot)
{
    MemoryRegionSection *section;
    // Unicorn: qatomic_read used instead of qatomic_rcu_read
    AddressSpaceDispatch *d = qatomic_read(&cpu->cpu_ases[asidx].memory_dispatch);

    section = address_space_translate_internal(d, addr, xlat, plen, false);

    assert(!section->mr->iommu_ops);
    return section;
}
#endif

CPUState *qemu_get_cpu(struct uc_struct *uc, int index)
{
    CPUState *cpu = uc->cpu;
    if (cpu->cpu_index == index) {
        return cpu;
    }
    return NULL;
}

#if !defined(CONFIG_USER_ONLY)
void cpu_address_space_init(CPUState *cpu, int asidx,
                            const char *prefix, MemoryRegion *mr)
{
    CPUAddressSpace *newas;
    AddressSpace *as = g_new0(AddressSpace, 1);
    char *as_name;

    assert(mr);
    as_name = g_strdup_printf("%s-%d", prefix, cpu->cpu_index);
    address_space_init(cpu->uc, as, mr, as_name);
    g_free(as_name);

    /* Target code should have set num_ases before calling us */
    assert(asidx < cpu->num_ases);

    if (asidx == 0) {
        /* address space 0 gets the convenience alias */
        cpu->as = as;
    }

    /* KVM cannot currently support multiple address spaces. */
    // Unicorn: commented out
    //assert(asidx == 0 || !kvm_enabled());

    if (!cpu->cpu_ases) {
        cpu->cpu_ases = g_new0(CPUAddressSpace, cpu->num_ases);
    }

    newas = &cpu->cpu_ases[asidx];
    newas->cpu = cpu;
    newas->as = as;
    if (tcg_enabled(as->uc)) {
        newas->tcg_as_listener.commit = tcg_commit;
        memory_listener_register(as->uc, &newas->tcg_as_listener, as);
    }
}

AddressSpace *cpu_get_address_space(CPUState *cpu, int asidx)
{
    /* Return the AddressSpace corresponding to the specified index */
    return cpu->cpu_ases[asidx].as;
}
#endif

#ifndef CONFIG_USER_ONLY
static int cpu_get_free_index(Error **errp)
{
    // Unicorn: if'd out
#if 0
    int cpu = find_first_zero_bit(cpu_index_map, MAX_CPUMASK_BITS);

    if (cpu >= MAX_CPUMASK_BITS) {
        error_setg(errp, "Trying to use more CPUs than max of %d",
                   MAX_CPUMASK_BITS);
        return -1;
    }

    bitmap_set(cpu_index_map, cpu, 1);
    return cpu;
#endif
    return 0;
}

void cpu_exec_exit(CPUState *cpu)
{
    if (cpu->cpu_index == -1) {
        /* cpu_index was never allocated by this @cpu or was already freed. */
        return;
    }

    // Unicorn: if'd out
#if 0
    bitmap_clear(cpu_index_map, cpu->cpu_index, 1);
#endif
    cpu->cpu_index = -1;
}
#else

static int cpu_get_free_index(Error **errp)
{
    // Unicorn: if'd out
#if 0
    CPUState *some_cpu;
    int cpu_index = 0;

    CPU_FOREACH(some_cpu) {
        cpu_index++;
    }
    return cpu_index;
#endif
    return 0;
}

void cpu_exec_exit(CPUState *cpu)
{
}
#endif

void cpu_exec_init(CPUState *cpu, Error **errp, void *opaque)
{
    struct uc_struct *uc = opaque;
    CPUClass *cc = CPU_GET_CLASS(uc, cpu);
    CPUArchState *env = cpu->env_ptr;
    Error *local_err = NULL;

    cpu->as = NULL;
    cpu->num_ases = 0;
    cpu->uc = uc;
    env->uc = uc;

    cpu->cpu_index = cpu_get_free_index(&local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    // TODO: assert uc does not already have a cpu?
    uc->cpu = cpu;

    // Unicorn: Required to clean-slate TLB state
    tlb_flush(cpu);

#ifdef CONFIG_TCG
    if (tcg_enabled(uc) && !cc->tcg_initialized) {
        cc->tcg_initialized = true;
        cc->tcg_ops.initialize(uc);
    }
    tlb_init(cpu);
#endif /* CONFIG_TCG */

#ifndef CONFIG_USER_ONLY

    // Unicorn: commented out
    /* This is a softmmu CPU object, so create a property for it
     * so users can wire up its memory. (This can't go in qom/cpu.c
     * because that file is compiled only once for both user-mode
     * and system builds.) The default if no link is set up is to use
     * the system address space.
     */
    /*object_property_add_link(OBJECT(cpu), "memory", TYPE_MEMORY_REGION,
                             (Object **)&cpu->memory,
                             qdev_prop_allow_set_link_before_realize,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE,
                             &error_abort);*/
    cpu->memory = uc->system_memory;
    // Unicorn: commented out
    /*object_ref(OBJECT(cpu->memory)); */
#endif
}

const char *parse_cpu_model(struct uc_struct *uc, const char *cpu_model)
{
    ObjectClass *oc;
    CPUClass *cc;
    gchar **model_pieces;
    const char *cpu_type;

    model_pieces = g_strsplit(cpu_model, ",", 2);

    oc = cpu_class_by_name(uc, CPU_RESOLVING_TYPE, model_pieces[0]);
    if (oc == NULL) {
        fprintf(stderr, "unable to find CPU model '%s'", model_pieces[0]);
        g_strfreev(model_pieces);
        return NULL;
    }

    cpu_type = object_class_get_name(oc);
    cc = CPU_CLASS(uc, oc);
    cc->parse_features(uc, cpu_type, model_pieces[1], &error_fatal);
    g_strfreev(model_pieces);
    return cpu_type;
}

#if defined(CONFIG_USER_ONLY)
static void breakpoint_invalidate(CPUState *cpu, target_ulong pc)
{
    /* Flush the whole TB as this will not have race conditions
     * even if we don't have proper locking yet.
     * Ideally we would just invalidate the TBs for the
     * specified PC.
     */
    tb_flush(cpu);
}
#else
static void breakpoint_invalidate(CPUState *cpu, target_ulong pc)
{
    tb_flush(cpu); return; // SNPS added
    MemTxAttrs attrs;
    hwaddr phys = cpu_get_phys_page_attrs_debug(cpu, pc, &attrs);
    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    if (phys != -1) {
        /* Locks grabbed by tb_invalidate_phys_addr */
        tb_invalidate_phys_addr(cpu->cpu_ases[asidx].as,
                                phys | (pc & ~TARGET_PAGE_MASK));
    }
}
#endif

#if defined(CONFIG_USER_ONLY)
void cpu_watchpoint_remove_all(CPUState *cpu, int mask)

{
}

int cpu_watchpoint_remove(CPUState *cpu, vaddr addr, vaddr len,
        int flags)
{
    return -ENOSYS;
}

void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{
}

int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
        int flags, CPUWatchpoint **watchpoint)
{
    return -ENOSYS;
}

void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len,
                          MemTxAttrs atr, int fl, uintptr_t ra)
{
}

int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len)
{
    return 0;
}
#else
/* Add a watchpoint.  */
int cpu_watchpoint_insert(CPUState *cpu, vaddr addr, vaddr len,
        int flags, CPUWatchpoint **watchpoint)
{
    CPUWatchpoint *wp;

    /* forbid ranges which are empty or run off the end of the address space */
    if (len == 0 || (addr + len - 1) < addr) {
        return -EINVAL;
    }
    wp = g_malloc(sizeof(*wp));

    wp->vaddr = addr;
    wp->len = len;
    wp->flags = flags;

    /* keep all GDB-injected watchpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->watchpoints, wp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->watchpoints, wp, entry);
    }

    tlb_flush_page(cpu, addr);

    if (watchpoint)
        *watchpoint = wp;
    return 0;
}

/* Remove a specific watchpoint.  */
int cpu_watchpoint_remove(CPUState *cpu, vaddr addr, vaddr len,
        int flags)
{
    CPUWatchpoint *wp;

    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (addr == wp->vaddr && len == wp->len
                && flags == (wp->flags & ~BP_WATCHPOINT_HIT)) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific watchpoint by reference.  */
void cpu_watchpoint_remove_by_ref(CPUState *cpu, CPUWatchpoint *watchpoint)
{
    QTAILQ_REMOVE(&cpu->watchpoints, watchpoint, entry);

    tlb_flush_page(cpu, watchpoint->vaddr);

    g_free(watchpoint);
}

/* Remove all matching watchpoints.  */
void cpu_watchpoint_remove_all(CPUState *cpu, int mask)
{
    CPUWatchpoint *wp, *next;

    QTAILQ_FOREACH_SAFE(wp, &cpu->watchpoints, entry, next) {
        if (wp->flags & mask) {
            cpu_watchpoint_remove_by_ref(cpu, wp);
        }
    }
}

/* Return true if this watchpoint address matches the specified
 * access (ie the address range covered by the watchpoint overlaps
 * partially or completely with the address range covered by the
 * access).
 */
static inline bool watchpoint_address_matches(CPUWatchpoint *wp,
                                              vaddr addr, vaddr len)
{
    /* We know the lengths are non-zero, but a little caution is
     * required to avoid errors in the case where the range ends
     * exactly at the top of the address space and so addr + len
     * wraps round to zero.
     */
    vaddr wpend = wp->vaddr + wp->len - 1;
    vaddr addrend = addr + len - 1;

    return !(addr > wpend || wp->vaddr > addrend);
}

/* Return flags for watchpoints that match addr + prot.  */
int cpu_watchpoint_address_matches(CPUState *cpu, vaddr addr, vaddr len)
{
    CPUWatchpoint *wp;
    int ret = 0;

    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (watchpoint_address_matches(wp, addr, TARGET_PAGE_SIZE)) {
            ret |= wp->flags;
        }
    }
    return ret;
}
#endif

/* Generate a debug exception if a watchpoint has been hit.  */
void cpu_check_watchpoint(CPUState *cpu, vaddr addr, vaddr len,
                          MemTxAttrs attrs, int flags, uintptr_t ra,
                          uint64_t data) { // SNPS changed
    CPUClass *cc = CPU_GET_CLASS(cpu->uc, cpu);
    CPUWatchpoint *wp;

    struct CPUWatchpointCallInfo *info, *next;
    QTAILQ_HEAD(callwp_head, CPUWatchpointCallInfo) calls;
    QTAILQ_INIT(&calls);

    assert(tcg_enabled(cpu->uc));
    if (cpu->watchpoint_hit) {
        /*
         * We re-entered the check after replacing the TB.
         * Now raise the debug interrupt so that it will
         * trigger after the current instruction.
         */
        //qemu_mutex_lock_iothread();
        cpu_interrupt(cpu, CPU_INTERRUPT_DEBUG);
        //qemu_mutex_unlock_iothread();
        return;
    }

    addr = cc->tcg_ops.adjust_watchpoint_address(cpu, addr, len);
    QTAILQ_FOREACH(wp, &cpu->watchpoints, entry) {
        if (watchpoint_address_matches(wp, addr, len)
            && (wp->flags & flags)) {
            if (flags == BP_MEM_READ) {
                wp->flags |= BP_WATCHPOINT_HIT_READ;
            } else {
                wp->flags |= BP_WATCHPOINT_HIT_WRITE;
            }
            wp->hitaddr = MAX(addr, wp->vaddr);
            wp->hitattrs = attrs;
            // SNPS added
            if (wp->flags & BP_CALL) {
                struct CPUWatchpointCallInfo *info
                    = g_malloc(sizeof(struct CPUWatchpointCallInfo));
                info->addr = wp->vaddr;
                info->len = wp->len;
                QTAILQ_INSERT_TAIL(&calls, info, entry);

                wp->flags &= ~BP_WATCHPOINT_HIT;
                continue;
            }
            if (!cpu->watchpoint_hit) {
                if (wp->flags & BP_CPU && cc->tcg_ops.debug_check_watchpoint &&
                    !cc->tcg_ops.debug_check_watchpoint(cpu, wp)) {
                    wp->flags &= ~BP_WATCHPOINT_HIT;
                    continue;
                }
                cpu->watchpoint_hit = wp;

                mmap_lock();
                tb_check_watchpoint(cpu);
                if (wp->flags & BP_STOP_BEFORE_ACCESS) {
                    cpu->exception_index = EXCP_DEBUG;
                    mmap_unlock();
                    cpu_loop_exit_restore(cpu, ra);
                } else {
                    /* Force execution of one insn next time.  */
                    cpu->cflags_next_tb = 1 | curr_cflags(cpu->uc);
                    mmap_unlock();
                    if (ra) {
                        cpu_restore_state(cpu, ra, true);
                    }
                    cpu_loop_exit_noexc(cpu);
                }
            }
        } else {
            wp->flags &= ~BP_WATCHPOINT_HIT;
        }
    }

    // SNPS added
    QTAILQ_FOREACH_SAFE(info, &calls, entry, next) {
        struct uc_struct* uc = cpu->uc;
        void* opaque = uc->uc_watchpoint_opaque;
        bool iswr = flags & BP_MEM_WRITE;
        cpu->uc->uc_watchpoint_func(opaque, info->addr, info->len, data, iswr);
        g_free(info);
    }
}

/* Add a breakpoint.  */
int cpu_breakpoint_insert(CPUState *cpu, vaddr pc, int flags,
        CPUBreakpoint **breakpoint)
{
    CPUBreakpoint *bp;

    bp = g_malloc(sizeof(*bp));

    bp->pc = pc;
    bp->flags = flags;

    /* keep all GDB-injected breakpoints in front */
    if (flags & BP_GDB) {
        QTAILQ_INSERT_HEAD(&cpu->breakpoints, bp, entry);
    } else {
        QTAILQ_INSERT_TAIL(&cpu->breakpoints, bp, entry);
    }

    breakpoint_invalidate(cpu, pc);

    if (breakpoint) {
        *breakpoint = bp;
    }
    return 0;
}

/* Remove a specific breakpoint.  */
int cpu_breakpoint_remove(CPUState *cpu, vaddr pc, int flags)
{
    CPUBreakpoint *bp;

    QTAILQ_FOREACH(bp, &cpu->breakpoints, entry) {
        if (bp->pc == pc && bp->flags == flags) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
            return 0;
        }
    }
    return -ENOENT;
}

/* Remove a specific breakpoint by reference.  */
void cpu_breakpoint_remove_by_ref(CPUState *cpu, CPUBreakpoint *breakpoint)
{
    QTAILQ_REMOVE(&cpu->breakpoints, breakpoint, entry);

    breakpoint_invalidate(cpu, breakpoint->pc);

    g_free(breakpoint);
}

/* Remove all matching breakpoints. */
void cpu_breakpoint_remove_all(CPUState *cpu, int mask)
{
    CPUBreakpoint *bp, *next;

    QTAILQ_FOREACH_SAFE(bp, &cpu->breakpoints, entry, next) {
        if (bp->flags & mask) {
            cpu_breakpoint_remove_by_ref(cpu, bp);
        }
    }
}

/* enable or disable single step mode. EXCP_DEBUG is returned by the
   CPU loop after each instruction */
void cpu_single_step(CPUState *cpu, int enabled)
{
    if (cpu->singlestep_enabled != enabled) {
        cpu->singlestep_enabled = enabled;
        /* must flush all the translated code to avoid inconsistencies */
        /* XXX: only flush what is necessary */
        tb_flush(cpu);
    }
}

void cpu_abort(CPUState *cpu, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    fprintf(stderr, "qemu: fatal: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    cpu_dump_state(cpu, stderr, fprintf, CPU_DUMP_FPU | CPU_DUMP_CCOP);
    if (qemu_log_enabled()) {
        qemu_log("qemu: fatal: ");
        qemu_log_vprintf(fmt, ap2);
        qemu_log("\n");
        log_cpu_state(cpu, CPU_DUMP_FPU | CPU_DUMP_CCOP);
        qemu_log_flush();
        qemu_log_close();
    }
    va_end(ap2);
    va_end(ap);
#if defined(CONFIG_USER_ONLY)
    {
        struct sigaction act;
        sigfillset(&act.sa_mask);
        act.sa_handler = SIG_DFL;
        act.sa_flags = 0;
        sigaction(SIGABRT, &act, NULL);
    }
#endif
    abort();
}

#if !defined(CONFIG_USER_ONLY)
static RAMBlock *qemu_get_ram_block(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block;

    /* The list is protected by the iothread lock here.  */
    block = uc->ram_list.mru_block;
    if (block && addr - block->offset < block->max_length) {
        return block;
    }
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (addr - block->offset < block->max_length) {
            goto found;
        }
    }

    fprintf(stderr, "Bad ram offset %" PRIx64 "\n", (uint64_t)addr);
    abort();

found:
    uc->ram_list.mru_block = block;
    return block;
}

hwaddr memory_region_section_get_iotlb(CPUState *cpu,
        MemoryRegionSection *section,
        target_ulong vaddr,
        hwaddr paddr, hwaddr xlat,
        int prot,
        target_ulong *address)
{
    hwaddr iotlb;

    if (memory_region_is_ram(section->mr)) {
        /* Normal RAM.  */
        iotlb = (memory_region_get_ram_addr(section->mr) & TARGET_PAGE_MASK)
            + xlat;
        if (!section->readonly) {
            iotlb |= PHYS_SECTION_NOTDIRTY;
        } else {
            iotlb |= PHYS_SECTION_ROM;
        }
    } else {
        AddressSpaceDispatch *d;

        d = flatview_to_dispatch(section->fv);
        iotlb = section - d->map.sections;
        iotlb += xlat;
    }

    return iotlb;
}
#endif /* defined(CONFIG_USER_ONLY) */

#if !defined(CONFIG_USER_ONLY)

static int subpage_register(subpage_t *mmio, uint32_t start, uint32_t end,
                            uint16_t section);
static subpage_t *subpage_init(FlatView *fv, hwaddr base);

static void *(*phys_mem_alloc)(size_t size, uint64_t *align) =
qemu_anon_ram_alloc;

/*
 * Set a custom physical guest memory alloator.
 * Accelerators with unusual needs may need this.  Hopefully, we can
 * get rid of it eventually.
 */
void phys_mem_set_alloc(void *(*alloc)(size_t, uint64_t *align))
{
    phys_mem_alloc = alloc;
}

static uint16_t phys_section_add(PhysPageMap *map,
        MemoryRegionSection *section)
{
    /* The physical section number is ORed with a page-aligned
     * pointer to produce the iotlb entries.  Thus it should
     * never overflow into the page-aligned value.
     */
    assert(map->sections_nb < TARGET_PAGE_SIZE);

    if (map->sections_nb == map->sections_nb_alloc) {
        map->sections_nb_alloc = MAX(map->sections_nb_alloc * 2, 16);
        map->sections = g_renew(MemoryRegionSection, map->sections,
                map->sections_nb_alloc);
    }
    map->sections[map->sections_nb] = *section;
    memory_region_ref(section->mr);
    return map->sections_nb++;
}

static void phys_section_destroy(MemoryRegion *mr)
{
    bool have_sub_page = mr->subpage;

    memory_region_unref(mr);

    if (have_sub_page) {
        subpage_t *subpage = container_of(mr, subpage_t, iomem);
        object_unref(mr->uc, OBJECT(&subpage->iomem));
        g_free(subpage);
    }
}

static void phys_sections_free(PhysPageMap *map)
{
    while (map->sections_nb > 0) {
        MemoryRegionSection *section = &map->sections[--map->sections_nb];
        phys_section_destroy(section->mr);
    }
    g_free(map->sections);
    g_free(map->nodes);
}

static void register_subpage(FlatView *fv, MemoryRegionSection *section)
{
    AddressSpaceDispatch *d = flatview_to_dispatch(fv);
    subpage_t *subpage;
    hwaddr base = section->offset_within_address_space
        & TARGET_PAGE_MASK;
    MemoryRegionSection *existing = phys_page_find(d, base);
    hwaddr start, end;
    MemoryRegionSection subsection = MemoryRegionSection_make(NULL, NULL, 0, int128_make64(TARGET_PAGE_SIZE), base, false);
    struct uc_struct *uc = d->uc;

    assert(existing->mr->subpage || existing->mr == &uc->io_mem_unassigned);

    if (!(existing->mr->subpage)) {
        subpage = subpage_init(fv, base);
        subsection.fv = fv;
        subsection.mr = &subpage->iomem;
        phys_page_set(d, base >> TARGET_PAGE_BITS, 1,
                      phys_section_add(&d->map, &subsection));
    } else {
        subpage = container_of(existing->mr, subpage_t, iomem);
    }
    start = section->offset_within_address_space & ~TARGET_PAGE_MASK;
    end = start + int128_get64(section->size) - 1;
    subpage_register(subpage, start, end,
                     phys_section_add(&d->map, section));
    //g_free(subpage);
}


static void register_multipage(FlatView *fv,
                               MemoryRegionSection *section)
{
    AddressSpaceDispatch *d = flatview_to_dispatch(fv);
    hwaddr start_addr = section->offset_within_address_space;
    uint16_t section_index = phys_section_add(&d->map, section);
    uint64_t num_pages = int128_get64(int128_rshift(section->size,
                TARGET_PAGE_BITS));

    assert(num_pages);
    phys_page_set(d, start_addr >> TARGET_PAGE_BITS, num_pages, section_index);
}

/*
 * The range in *section* may look like this:
 *
 *      |s|PPPPPPP|s|
 *
 * where s stands for subpage and P for page.
 */
void flatview_add_to_dispatch(FlatView *fv, MemoryRegionSection *section)
{
    MemoryRegionSection remain = *section;
    Int128 page_size = int128_make64(TARGET_PAGE_SIZE);

    /* register first subpage */
    if (remain.offset_within_address_space & ~TARGET_PAGE_MASK) {
        uint64_t left = TARGET_PAGE_ALIGN(remain.offset_within_address_space)
                        - remain.offset_within_address_space;

        MemoryRegionSection now = remain;
        now.size = int128_min(int128_make64(left), now.size);
        register_subpage(fv, &now);
        if (int128_eq(remain.size, now.size)) {
            return;
        }
        remain.size = int128_sub(remain.size, now.size);
        remain.offset_within_address_space += int128_get64(now.size);
        remain.offset_within_region += int128_get64(now.size);
    }

    /* register whole pages */
    if (int128_ge(remain.size, page_size)) {
        MemoryRegionSection now = remain;
        now.size = int128_and(now.size, int128_neg(page_size));
        register_multipage(fv, &now);
        if (int128_eq(remain.size, now.size)) {
            return;
        }
        remain.size = int128_sub(remain.size, now.size);
        remain.offset_within_address_space += int128_get64(now.size);
        remain.offset_within_region += int128_get64(now.size);
    }

    /* register last subpage */
    register_subpage(fv, &remain);
}

#ifdef __linux__

#include <sys/vfs.h>

#define HUGETLBFS_MAGIC       0x958458f6

#endif

static ram_addr_t find_ram_offset(struct uc_struct *uc, ram_addr_t size)
{
    RAMBlock *block, *next_block;
    ram_addr_t offset = RAM_ADDR_MAX, mingap = RAM_ADDR_MAX;

    assert(size != 0); /* it would hand out same offset multiple times */

    if (QLIST_EMPTY(&uc->ram_list.blocks)) {
        return 0;
    }

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        ram_addr_t end, next = RAM_ADDR_MAX;

        end = block->offset + block->max_length;

        QLIST_FOREACH(next_block, &uc->ram_list.blocks, next) {
            if (next_block->offset >= end) {
                next = MIN(next, next_block->offset);
            }
        }
        if (next - end >= size && next - end < mingap) {
            offset = end;
            mingap = next - end;
        }
    }

    if (offset == RAM_ADDR_MAX) {
        fprintf(stderr, "Failed to find gap of requested size: %" PRIu64 "\n",
                (uint64_t)size);
        abort();
    }

    return offset;
}

ram_addr_t last_ram_offset(struct uc_struct *uc)
{
    RAMBlock *block;
    ram_addr_t last = 0;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        last = MAX(last, block->offset + block->max_length);
    }
    return last;
}

static void qemu_ram_setup_dump(void *addr, ram_addr_t size)
{
}

const char *qemu_ram_get_idstr(RAMBlock *rb)
{
    return rb->idstr;
}

bool qemu_ram_is_shared(RAMBlock *rb)
{
    return rb->flags & RAM_SHARED;
}

void qemu_ram_unset_idstr(struct uc_struct *uc, RAMBlock *block)
{
    if (block) {
        memset(block->idstr, 0, sizeof(block->idstr));
    }
}

static int memory_try_enable_merging(void *addr, size_t len)
{
    return 0;
}

/* Only legal before guest might have detected the memory size: e.g. on
 * incoming migration, or right after reset.
 *
 * As memory core doesn't know how is memory accessed, it is up to
 * resize callback to update device state and/or add assertions to detect
 * misuse, if necessary.
 */
int qemu_ram_resize(struct uc_struct *uc, RAMBlock *block, ram_addr_t newsize, Error **errp)
{
    assert(block);

    newsize = TARGET_PAGE_ALIGN(newsize);

    if (block->used_length == newsize) {
        return 0;
    }

    if (!(block->flags & RAM_RESIZEABLE)) {
        error_setg_errno(errp, EINVAL,
                         "Length mismatch: %s: 0x" RAM_ADDR_FMT
                         " in != 0x" RAM_ADDR_FMT, block->idstr,
                         newsize, block->used_length);
        return -EINVAL;
    }

    if (block->max_length < newsize) {
        error_setg_errno(errp, EINVAL,
                         "Length too large: %s: 0x" RAM_ADDR_FMT
                         " > 0x" RAM_ADDR_FMT, block->idstr,
                         newsize, block->max_length);
        return -EINVAL;
    }

    block->used_length = newsize;

    memory_region_set_size(block->mr, newsize);
    if (block->resized) {
        block->resized(block->idstr, newsize, block->host);
    }
    return 0;
}

/*
 * Trigger sync on the given ram block for range [start, start + length]
 * with the backing store if one is available.
 * Otherwise no-op.
 * @Note: this is supposed to be a synchronous op.
 */
void qemu_ram_writeback(struct uc_struct *uc, RAMBlock *block, ram_addr_t start, ram_addr_t length)
{
    void *addr = ramblock_ptr(block, start);

    /* The requested range should fit in within the block range */
    g_assert((start + length) <= block->used_length);

#ifdef CONFIG_LIBPMEM
    /* The lack of support for pmem should not block the sync */
    if (ramblock_is_pmem(block)) {
        pmem_persist(addr, length);
        return;
    }
#endif
    if (block->fd >= 0) {
        /**
         * Case there is no support for PMEM or the memory has not been
         * specified as persistent (or is not one) - use the msync.
         * Less optimal but still achieves the same goal
         */
        if (qemu_msync(uc, addr, length, block->fd)) {
            //warn_report("%s: failed to sync memory range: start: "
            //        RAM_ADDR_FMT " length: " RAM_ADDR_FMT,
            //        __func__, start, length);
        }
    }
}

static void ram_block_add(struct uc_struct *uc, RAMBlock *new_block, Error **errp)
{
    RAMBlock *block;
    RAMBlock *last_block = NULL;
    ram_addr_t old_ram_size, new_ram_size;

    old_ram_size = last_ram_offset(uc) >> TARGET_PAGE_BITS;

    new_block->offset = find_ram_offset(uc, new_block->max_length);

    if (!new_block->host) {
        new_block->host = phys_mem_alloc(new_block->max_length,
                                         &new_block->mr->align);
        if (!new_block->host) {
            error_setg_errno(errp, errno,
                             "cannot set up guest memory '%s'",
                             memory_region_name(new_block->mr));
            return;
        }
        memory_try_enable_merging(new_block->host, new_block->max_length);
    }

    new_ram_size = MAX(old_ram_size,
              (new_block->offset + new_block->max_length) >> TARGET_PAGE_BITS);

    /* Keep the list sorted from biggest to smallest block.  Unlike QTAILQ,
     * QLIST (which has an RCU-friendly variant) does not have insertion at
     * tail, so save the last element in last_block.
     */
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        last_block = block;
        if (block->max_length < new_block->max_length) {
            break;
        }
    }
    if (block) {
        QLIST_INSERT_BEFORE(block, new_block, next);
    } else if (last_block) {
        QLIST_INSERT_AFTER(last_block, new_block, next);
    } else { /* list is empty */
        QLIST_INSERT_HEAD(&uc->ram_list.blocks, new_block, next);
    }
    uc->ram_list.mru_block = NULL;

    /* Write list before version */
    smp_wmb();
    uc->ram_list.version++;

    if (new_block->host) {
        qemu_ram_setup_dump(new_block->host, new_block->max_length);
        // Unicorn: commented out
        //qemu_madvise(new_block->host, new_block->max_length, QEMU_MADV_HUGEPAGE);
        //qemu_madvise(new_block->host, new_block->max_length, QEMU_MADV_DONTFORK);
        //if (kvm_enabled()) {
        //    kvm_setup_guest_memory(new_block->host, new_block->max_length);
        //}
    }
}

static
RAMBlock *qemu_ram_alloc_internal(ram_addr_t size, ram_addr_t max_size,
                                   void (*resized)(const char*,
                                                   uint64_t length,
                                                   void *host),
                                   void *host, bool resizeable,
                                   MemoryRegion *mr, Error **errp)
{
    RAMBlock *new_block;
    Error *local_err = NULL;

    size = TARGET_PAGE_ALIGN(size);
    max_size = TARGET_PAGE_ALIGN(max_size);
    new_block = g_malloc0(sizeof(*new_block));
    if (new_block == NULL) {
        return NULL;
    }
    new_block->mr = mr;
    new_block->resized = resized;
    new_block->used_length = size;
    new_block->max_length = max_size;
    assert(max_size >= size);
    new_block->fd = -1;
    new_block->host = host;
    if (host) {
        new_block->flags |= RAM_PREALLOC;
    }
    if (resizeable) {
        new_block->flags |= RAM_RESIZEABLE;
    }
    ram_block_add(mr->uc, new_block, &local_err);
    if (local_err) {
        g_free(new_block);
        error_propagate(errp, local_err);
        return NULL;
    }
    return new_block;
}

RAMBlock *qemu_ram_alloc_from_ptr(ram_addr_t size, void *host,
                                  MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, size, NULL, host, false, mr, errp);
}

RAMBlock *qemu_ram_alloc(ram_addr_t size, MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, size, NULL, NULL, false, mr, errp);
}

RAMBlock *qemu_ram_alloc_resizeable(ram_addr_t size, ram_addr_t maxsz,
                                    void (*resized)(const char*,
                                                    uint64_t length,
                                                    void *host),
                                    MemoryRegion *mr, Error **errp)
{
    return qemu_ram_alloc_internal(size, maxsz, resized, NULL, true, mr, errp);
}

static void reclaim_ramblock(RAMBlock *block)
{
    if (block->flags & RAM_PREALLOC) {
        ;
#ifndef _WIN32
    } else if (block->fd >= 0) {
        munmap(block->host, block->max_length);
        close(block->fd);
#endif
    } else {
        qemu_anon_ram_free(block->host, block->max_length);
    }
    g_free(block);
}

void qemu_ram_free(struct uc_struct *uc, ram_addr_t addr)
{
    RAMBlock *block;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (addr == block->offset) {
            QLIST_REMOVE(block, next);
            uc->ram_list.mru_block = NULL;
             /* Write list before version */
            smp_wmb();
            uc->ram_list.version++;
            // Unicorn: call directly instead of via call_rcu
            reclaim_ramblock(block);
            break;
        }
    }
}

#ifndef _WIN32
void qemu_ram_remap(struct uc_struct *uc, ram_addr_t addr, ram_addr_t length)
{
    RAMBlock *block;
    ram_addr_t offset;
    int flags;
    void *area, *vaddr;

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        offset = addr - block->offset;
        if (offset < block->max_length) {
            vaddr = ramblock_ptr(block, offset);
            if (block->flags & RAM_PREALLOC) {
                ;
            } else {
                flags = MAP_FIXED;
                if (block->fd >= 0) {
                    flags |= (block->flags & RAM_SHARED ?
                            MAP_SHARED : MAP_PRIVATE);
                    area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                            flags, block->fd, offset);
                } else {
                    /*
                     * Remap needs to match alloc.  Accelerators that
                     * set phys_mem_alloc never remap.  If they did,
                     * we'd need a remap hook here.
                     */
                    assert(phys_mem_alloc == qemu_anon_ram_alloc);

                    flags |= MAP_PRIVATE | MAP_ANONYMOUS;
                    area = mmap(vaddr, length, PROT_READ | PROT_WRITE,
                            flags, -1, 0);
                }
                if (area != vaddr) {
                    fprintf(stderr, "Could not remap addr: "
                            RAM_ADDR_FMT "@" RAM_ADDR_FMT "\n",
                            length, addr);
                    exit(1);
                }
                memory_try_enable_merging(vaddr, length);
                qemu_ram_setup_dump(vaddr, length);
            }
        }
    }
}
#endif /* !_WIN32 */

/* Return a host pointer to ram allocated with qemu_ram_alloc.
   With the exception of the softmmu code in this file, this should
   only be used for local memory (e.g. video ram) that the device owns,
   and knows it isn't going to access beyond the end of the block.

   It should not be used for general purpose DMA.
   Use cpu_physical_memory_map/cpu_physical_memory_rw instead.
   */
void *qemu_map_ram_ptr(struct uc_struct *uc, RAMBlock *ram_block,
                       ram_addr_t addr)
{
    RAMBlock *block = ram_block;

    if (block == NULL) {
        block = qemu_get_ram_block(uc, addr);
        addr -= block->offset;
    }

    return ramblock_ptr(block, addr);
}

/* Return a host pointer to guest's ram. Similar to qemu_map_ram_ptr
 * but takes a size argument */
static void *qemu_ram_ptr_length(struct uc_struct *uc, RAMBlock *ram_block,
                                 ram_addr_t addr, hwaddr *size, bool lock)
{
    RAMBlock *block = ram_block;
    if (*size == 0) {
        return NULL;
    }

    if (block == NULL) {
        block = qemu_get_ram_block(uc, addr);
        addr -= block->offset;
    }
    *size = MIN(*size, block->max_length - addr);

    // Unicorn: Commented out
    //if (xen_enabled() && block->host == NULL) {
    //    /* We need to check if the requested address is in the RAM
    //     * because we don't want to map the entire memory in QEMU.
    //     * In that case just map the requested area.
    //     */
    //    if (block->offset == 0) {
    //        return xen_map_cache(addr, *size, 1);
    //    }
    //
    //    block->host = xen_map_cache(block->offset, block->max_length, 1);
    //}

    return ramblock_ptr(block, addr);
}

/*
 * Translates a host ptr back to a RAMBlock, a ram_addr and an offset
 * in that RAMBlock.
 *
 * ptr: Host pointer to look up
 * round_offset: If true round the result offset down to a page boundary
 * *ram_addr: set to result ram_addr
 * *offset: set to result offset within the RAMBlock
 *
 * Returns: RAMBlock (or NULL if not found)
 *
 *
 * By the time this function returns, the returned pointer is not protected
 * by RCU anymore.  If the caller is not within an RCU critical section and
 * does not hold the iothread lock, it must have other means of protecting the
 * pointer, such as a reference to the region that includes the incoming
 * ram_addr_t.
 */
RAMBlock *qemu_ram_block_from_host(struct uc_struct* uc, void *ptr, bool round_offset,
                                   ram_addr_t *offset)
{
    RAMBlock *block;
    uint8_t *host = ptr;

    block = uc->ram_list.mru_block;
    if (block && block->host && host - block->host < block->max_length) {
        goto found;
    }

    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        /* This case append when the block is not mapped. */
        if (block->host == NULL) {
            continue;
        }
        if (host - block->host < block->max_length) {
            goto found;
        }
    }

    return NULL;

found:
    *offset = (host - block->host);
    if (round_offset) {
        *offset &= TARGET_PAGE_MASK;
    }
    return block;
}

/*
 * Finds the named RAMBlock
 *
 * name: The name of RAMBlock to find
 *
 * Returns: RAMBlock (or NULL if not found)
 */
RAMBlock *qemu_ram_block_by_name(struct uc_struct* uc, const char *name)
{
    RAMBlock *block;

    // Unicorn: Changed from QLIST_FOREACH_RCU to QLIST_FOREACH
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        if (!strcmp(name, block->idstr)) {
            return block;
        }
    }

    return NULL;
}

/* Some of the softmmu routines need to translate from a host pointer
   (typically a TLB entry) back to a ram offset.  */
ram_addr_t qemu_ram_addr_from_host(struct uc_struct* uc, void *ptr)
{
    RAMBlock *block;
    ram_addr_t offset;

    block = qemu_ram_block_from_host(uc, ptr, false, &offset);
    if (!block) {
        return RAM_ADDR_INVALID;
    }

    return block->offset + offset;
}

static MemTxResult flatview_write(FlatView *fv, hwaddr addr, MemTxAttrs attrs,
                                  const uint8_t *buf, int len);
static bool flatview_access_valid(FlatView *fv, hwaddr addr, int len,
                                  bool is_write);

static MemTxResult subpage_read(struct uc_struct* uc, void *opaque, hwaddr addr,
                                uint64_t *data, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];
    MemTxResult res;

#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %u addr " TARGET_FMT_plx "\n", __func__,
            subpage, len, addr);
#endif
    res = flatview_read(subpage->fv, addr + subpage->base, attrs, buf, len);
    if (res) {
        return res;
    }
    *data = ldn_p(buf, len);
    return MEMTX_OK;
}

static MemTxResult subpage_write(struct uc_struct* uc, void *opaque, hwaddr addr,
                                 uint64_t value, unsigned len, MemTxAttrs attrs)
{
    subpage_t *subpage = opaque;
    uint8_t buf[8];

#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p len %u addr " TARGET_FMT_plx
            " value %"PRIx64"\n",
            __func__, subpage, len, addr, value);
#endif
    stn_p(buf, len, value);
    return flatview_write(subpage->fv, addr + subpage->base, attrs, buf, len);
}

static bool subpage_accepts(void *opaque, hwaddr addr,
        unsigned len, bool is_write)
{
    subpage_t *subpage = opaque;
#if defined(DEBUG_SUBPAGE)
    printf("%s: subpage %p %c len %u addr " TARGET_FMT_plx "\n",
            __func__, subpage, is_write ? 'w' : 'r', len, addr);
#endif

    return flatview_access_valid(subpage->fv, addr + subpage->base,
                                 len, is_write);
}

static const MemoryRegionOps subpage_ops = {
    NULL,
    NULL,
    subpage_read,
    subpage_write,
    DEVICE_NATIVE_ENDIAN,
    {
        1, 8, false, subpage_accepts,
    },
    {
        1, 8, false,
    }
};

static int subpage_register(subpage_t *mmio, uint32_t start, uint32_t end,
                            uint16_t section)
{
    int idx, eidx;

    if (start >= TARGET_PAGE_SIZE || end >= TARGET_PAGE_SIZE)
        return -1;
    idx = SUBPAGE_IDX(start);
    eidx = SUBPAGE_IDX(end);
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p start %08x end %08x idx %08x eidx %08x section %d\n",
            __func__, mmio, start, end, idx, eidx, section);
#endif
    for (; idx <= eidx; idx++) {
        mmio->sub_section[idx] = section;
    }

    return 0;
}

static void notdirty_mem_write(struct uc_struct* uc, void *opaque, hwaddr ram_addr,
                               uint64_t val, unsigned size)
{
    switch (size) {
    case 1:
        stb_p(qemu_map_ram_ptr(uc, NULL, ram_addr), val);
        break;
    case 2:
        stw_p(qemu_map_ram_ptr(uc, NULL, ram_addr), val);
        break;
    case 4:
        stl_p(qemu_map_ram_ptr(uc, NULL, ram_addr), val);
        break;
    default:
        abort();
    }
}

static bool notdirty_mem_accepts(void *opaque, hwaddr addr,
                                 unsigned size, bool is_write)
{
    return is_write;
}

static const MemoryRegionOps notdirty_mem_ops = {
    NULL,
    notdirty_mem_write,
    NULL,
    NULL,
    DEVICE_NATIVE_ENDIAN,
    {
        0, 0, false, notdirty_mem_accepts,
    },
};

static void io_mem_init(struct uc_struct* uc)
{
    memory_region_init_io(uc, &uc->io_mem_rom, NULL, &unassigned_mem_ops, NULL, NULL, UINT64_MAX);
    memory_region_init_io(uc, &uc->io_mem_unassigned, NULL, &unassigned_mem_ops, NULL,
                          NULL, UINT64_MAX);
    memory_region_init_io(uc, &uc->io_mem_notdirty, NULL, &notdirty_mem_ops, NULL,
                          NULL, UINT64_MAX);
}

static subpage_t *subpage_init(FlatView *fv, hwaddr base)
{
    AddressSpaceDispatch *d = flatview_to_dispatch(fv);
    subpage_t *mmio;

    /* mmio->sub_section is set to PHYS_SECTION_UNASSIGNED with g_malloc0 */
    mmio = g_malloc0(sizeof(subpage_t) + TARGET_PAGE_SIZE * sizeof(uint16_t));

    mmio->fv = fv;
    mmio->base = base;
    memory_region_init_io(d->uc, &mmio->iomem, NULL, &subpage_ops, mmio,
            NULL, TARGET_PAGE_SIZE);
    mmio->iomem.subpage = true;
#if defined(DEBUG_SUBPAGE)
    printf("%s: %p base " TARGET_FMT_plx " len %08x\n", __func__,
            mmio, base, TARGET_PAGE_SIZE);
#endif

    return mmio;
}

static uint16_t dummy_section(PhysPageMap *map, FlatView *fv, MemoryRegion *mr)
{
    MemoryRegionSection section = MemoryRegionSection_make(
        mr, fv, 0,
        int128_2_64(),
        false,
        0
    );

    assert(fv);

    return phys_section_add(map, &section);
}

MemoryRegionSection *iotlb_to_section(CPUState *cpu,
                                      hwaddr index, MemTxAttrs attrs)

{
    int asidx = cpu_asidx_from_attrs(cpu, attrs);
    CPUAddressSpace *cpuas = &cpu->cpu_ases[asidx];
    // Unicorn: uses qatomic_read instead of qatomic_rcu_read
    AddressSpaceDispatch *d = qatomic_read(&cpuas->memory_dispatch);
    MemoryRegionSection *sections = d->map.sections;

    return &sections[index & ~TARGET_PAGE_MASK];
}

AddressSpaceDispatch *address_space_dispatch_new(struct uc_struct *uc, FlatView *fv)
{
    AddressSpaceDispatch *d = g_new0(AddressSpaceDispatch, 1);
    uint16_t n;
    PhysPageEntry ppe = { 1, PHYS_MAP_NODE_NIL };

    d->uc = uc;

    n = dummy_section(&d->map, fv, &uc->io_mem_unassigned);
    assert(n == PHYS_SECTION_UNASSIGNED);
    n = dummy_section(&d->map, fv, &uc->io_mem_notdirty);
    assert(n == PHYS_SECTION_NOTDIRTY);
    n = dummy_section(&d->map, fv, &uc->io_mem_rom);
    assert(n == PHYS_SECTION_ROM);

    d->phys_map = ppe;

    return d;
}

void address_space_dispatch_free(AddressSpaceDispatch *d)
{
    phys_sections_free(&d->map);
    g_free(d);
}

static void tcg_commit(MemoryListener *listener)
{
    CPUAddressSpace *cpuas;
    AddressSpaceDispatch *d;

    /* since each CPU stores ram addresses in its TLB cache, we must
       reset the modified entries */
    cpuas = container_of(listener, CPUAddressSpace, tcg_as_listener);

    /* The CPU and TLB are protected by the iothread lock.
     * We reload the dispatch pointer now because cpu_reloading_memory_map()
     * may have split the RCU critical section.
     */
    d = address_space_to_dispatch(cpuas->as);
    // Unicorn: qatomic_set used instead of qatomic_rcu_set
    qatomic_set(&cpuas->memory_dispatch, d);
    tlb_flush(cpuas->cpu);
}

static void memory_map_init(struct uc_struct *uc)
{
    uc->system_memory = g_malloc(sizeof(*(uc->system_memory)));

    memory_region_init(uc, uc->system_memory, NULL, "system", UINT64_MAX);
    address_space_init(uc, &uc->as, uc->system_memory, "memory");
}

void cpu_exec_init_all(struct uc_struct *uc)
{
    /* The data structures we set up here depend on knowing the page size,
     * so no more changes can be made after this point.
     * In an ideal world, nothing we did before we had finished the
     * machine setup would care about the target page size, and we could
     * do this much later, rather than requiring board models to state
     * up front what their requirements are.
     */
    finalize_target_page_bits(uc);
    io_mem_init(uc);
#if !defined(CONFIG_USER_ONLY)
    memory_map_init(uc);
#endif
}

MemoryRegion *get_system_memory(struct uc_struct *uc)
{
    return uc->system_memory;
}

#endif /* !defined(CONFIG_USER_ONLY) */

/* physical memory access (slow version, mainly for debug) */
#if defined(CONFIG_USER_ONLY)
int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr,
        uint8_t *buf, int len, int is_write)
{
    int l, flags;
    target_ulong page;
    void * p;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        flags = page_get_flags(page);
        if (!(flags & PAGE_VALID))
            return -1;
        if (is_write) {
            if (!(flags & PAGE_WRITE))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_WRITE, addr, l, 0)))
                return -1;
            memcpy(p, buf, l);
            unlock_user(p, addr, l);
        } else {
            if (!(flags & PAGE_READ))
                return -1;
            /* XXX: this code should not depend on lock_user */
            if (!(p = lock_user(VERIFY_READ, addr, l, 1)))
                return -1;
            memcpy(buf, p, l);
            unlock_user(p, addr, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

#else

static int memory_access_size(MemoryRegion *mr, unsigned l, hwaddr addr)
{
    unsigned access_size_max = mr->ops->valid.max_access_size;

    /* Regions are assumed to support 1-4 byte accesses unless
       otherwise specified.  */
    if (access_size_max == 0) {
        access_size_max = 4;
    }

    /* Bound the maximum access by the alignment of the address.  */
    if (!mr->ops->impl.unaligned) {
        unsigned align_size_max = addr & (0-addr);
        if (align_size_max != 0 && align_size_max < access_size_max) {
            access_size_max = align_size_max;
        }
    }

    /* Don't attempt accesses larger than the maximum.  */
    if (l > access_size_max) {
        l = access_size_max;
    }
    l = pow2floor(l);

    return l;
}

static MemTxResult flatview_write_continue(FlatView *fv, hwaddr addr,
                                           MemTxAttrs attrs,
                                           const uint8_t *buf,
                                           int len, hwaddr addr1,
                                           hwaddr l, MemoryRegion *mr)
{
    uint8_t *ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    // Unicorn: commented out
    //bool release_lock = false;

    for (;;) {
        if (!mr)
            return true;

        if (!memory_access_is_direct(mr, true)) {
            // Unicorn: commented out
            //release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            val = ldn_he_p(buf, l);
            result |= memory_region_dispatch_write(mr, addr1, val,
                                                   size_memop(l), attrs);
        } else {
            /* RAM case */
            ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, addr1);
            memcpy(ptr, buf, l);
        }

        /* Unicorn: commented out
        if (release_lock) {
            qemu_mutex_unlock_iothread();
            release_lock = false;
        }*/

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = flatview_translate(fv, addr, &addr1, &l, true);
    }
    // Unicorn: commented out
    //rcu_read_unlock();

    return result;
}

static MemTxResult flatview_write(FlatView *fv, hwaddr addr, MemTxAttrs attrs,
                                  const uint8_t *buf, int len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    if (len > 0) {
        // Unicorn: commented out
        //rcu_read_lock();
        l = len;
        mr = flatview_translate(fv, addr, &addr1, &l, true);
        result = flatview_write_continue(fv, addr, attrs, buf, len,
                                         addr1, l, mr);
        // Unicorn: commented out
        //rcu_read_unlock();
    }

    return result;
}

MemTxResult address_space_write(AddressSpace *as, hwaddr addr,
                                              MemTxAttrs attrs,
                                              const uint8_t *buf, int len)
{
    return flatview_write(address_space_to_flatview(as), addr, attrs, buf, len);
}

MemTxResult flatview_read_continue(FlatView *fv, hwaddr addr,
                                   MemTxAttrs attrs, uint8_t *buf,
                                   int len, hwaddr addr1, hwaddr l,
                                   MemoryRegion *mr)
{
    uint8_t *ptr;
    uint64_t val;
    MemTxResult result = MEMTX_OK;
    // Unicorn: commented out
    //bool release_lock = false;

    for (;;) {
        if (!memory_access_is_direct(mr, false)) {
            /* I/O case */
            // Unicorn: commented out
            //release_lock |= prepare_mmio_access(mr);
            l = memory_access_size(mr, l, addr1);
            result |= memory_region_dispatch_read(mr, addr1, &val,
                                                  size_memop(l), attrs);
            stn_he_p(buf, l, val);
        } else {
            /* RAM case */
            ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, addr1);
            memcpy(buf, ptr, l);
        }

        /* Unicorn: Commented out
        if (release_lock) {
            qemu_mutex_unlock_iothread();
            release_lock = false;
        }*/

        len -= l;
        buf += l;
        addr += l;

        if (!len) {
            break;
        }

        l = len;
        mr = flatview_translate(fv, addr, &addr1, &l, false);
    }

    return result;
}

MemTxResult flatview_read_full(FlatView *fv, hwaddr addr,
                               MemTxAttrs attrs, uint8_t *buf, int len)
{
    hwaddr l;
    hwaddr addr1;
    MemoryRegion *mr;
    MemTxResult result = MEMTX_OK;

    if (len > 0) {
        // Unicorn: commented out
        //rcu_read_lock();
        l = len;
        mr = flatview_translate(fv, addr, &addr1, &l, false);
        result = flatview_read_continue(fv, addr, attrs, buf, len,
                                        addr1, l, mr);
        // Unicorn: commented out
        //rcu_read_unlock();
    }
    return result;
}

static MemTxResult flatview_rw(FlatView *fv, hwaddr addr, MemTxAttrs attrs,
                               uint8_t *buf, int len, bool is_write)
{
    if (is_write) {
        return flatview_write(fv, addr, attrs, (uint8_t *)buf, len);
    } else {
        return flatview_read(fv, addr, attrs, (uint8_t *)buf, len);
    }
}

MemTxResult address_space_rw(AddressSpace *as, hwaddr addr,
                             MemTxAttrs attrs, uint8_t *buf,
                             int len, bool is_write)
{
    return flatview_rw(address_space_to_flatview(as),
                       addr, attrs, buf, len, is_write);
}

bool cpu_physical_memory_rw(AddressSpace *as, hwaddr addr, uint8_t *buf,
                            int len, int is_write)
{
    return address_space_rw(as, addr, MEMTXATTRS_UNSPECIFIED,
                            buf, len, is_write) == MEMTX_OK;
}

enum write_rom_type {
    WRITE_DATA,
    FLUSH_CACHE,
};

static inline void cpu_physical_memory_write_rom_internal(AddressSpace *as,
        hwaddr addr, const uint8_t *buf, int len, enum write_rom_type type)
{
    hwaddr l;
    uint8_t *ptr;
    hwaddr addr1;
    MemoryRegion *mr;

    while (len > 0) {
        l = len;
        mr = address_space_translate(as, addr, &addr1, &l, true);

        if (!(memory_region_is_ram(mr) ||
              memory_region_is_romd(mr))) {
            l = memory_access_size(mr, l, addr1);
        } else {
            /* ROM/RAM case */
            ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, addr1);
            switch (type) {
                case WRITE_DATA:
                    memcpy(ptr, buf, l);
                    break;
                case FLUSH_CACHE:
                    flush_icache_range((uintptr_t)ptr, (uintptr_t)ptr + l);
                    break;
            }
        }
        len -= l;
        buf += l;
        addr += l;
    }
}

/* used for ROM loading : can write in RAM and ROM */
DEFAULT_VISIBILITY
void cpu_physical_memory_write_rom(AddressSpace *as, hwaddr addr,
        const uint8_t *buf, int len)
{
    cpu_physical_memory_write_rom_internal(as, addr, buf, len, WRITE_DATA);
}

void cpu_flush_icache_range(AddressSpace *as, hwaddr start, int len)
{
    /*
     * This function should do the same thing as an icache flush that was
     * triggered from within the guest. For TCG we are always cache coherent,
     * so there is no need to flush anything. For KVM / Xen we need to flush
     * the host's instruction cache at least.
     */
    if (tcg_enabled(as->uc)) {
        return;
    }

    cpu_physical_memory_write_rom_internal(as,
            start, NULL, len, FLUSH_CACHE);
}

static bool flatview_access_valid(FlatView *fv, hwaddr addr, int len,
                                  bool is_write)
{
    MemoryRegion *mr;
    hwaddr l, xlat;

    while (len > 0) {
        l = len;
        mr = flatview_translate(fv, addr, &xlat, &l, is_write);
        if (!memory_access_is_direct(mr, is_write)) {
            l = memory_access_size(mr, l, addr);
            if (!memory_region_access_valid(mr, xlat, l, is_write)) {
                // Unicorn: commented out
                //rcu_read_unlock();
                return false;
            }
        }

        len -= l;
        addr += l;
    }
    return true;
}

bool address_space_access_valid(AddressSpace *as, hwaddr addr,
                                int len, bool is_write)
{
    return flatview_access_valid(address_space_to_flatview(as),
                                 addr, len, is_write);
}

static hwaddr
flatview_extend_translation(FlatView *fv, hwaddr addr,
                            hwaddr target_len,
                            MemoryRegion *mr, hwaddr base, hwaddr len,
                            bool is_write)
{
    hwaddr done = 0;
    hwaddr xlat;
    MemoryRegion *this_mr;

    for (;;) {
        target_len -= len;
        addr += len;
        done += len;
        if (target_len == 0) {
            return done;
        }

        len = target_len;
        this_mr = flatview_translate(fv, addr, &xlat,
                                     &len, is_write);
        if (this_mr != mr || xlat != base + done) {
            return done;
        }
    }
}

/* Map a physical memory region into a host virtual address.
 * May map a subset of the requested range, given by and returned in *plen.
 * May return NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 * Use cpu_register_map_client() to know when retrying the map operation is
 * likely to succeed.
 */
void *address_space_map(AddressSpace *as,
                        hwaddr addr,
                        hwaddr *plen,
                        bool is_write)
{
    hwaddr len = *plen;
    hwaddr l, xlat;
    MemoryRegion *mr;
    void *ptr;
    FlatView *fv = address_space_to_flatview(as);

    if (len == 0) {
        return NULL;
    }

    l = len;
    mr = flatview_translate(fv, addr, &xlat, &l, is_write);
    if (!memory_access_is_direct(mr, is_write)) {
        if (qatomic_xchg(&as->uc->bounce.in_use, true)) {
            return NULL;
        }
        /* Avoid unbounded allocations */
        l = MIN(l, TARGET_PAGE_SIZE);
        as->uc->bounce.buffer = qemu_memalign(TARGET_PAGE_SIZE, l);
        as->uc->bounce.addr = addr;
        as->uc->bounce.len = l;

        memory_region_ref(mr);
        as->uc->bounce.mr = mr;
        if (!is_write) {
            flatview_read(fv, addr, MEMTXATTRS_UNSPECIFIED,
                          as->uc->bounce.buffer, l);
        }

        *plen = l;
        return as->uc->bounce.buffer;
    }

    memory_region_ref(mr);
    *plen = flatview_extend_translation(fv, addr, len, mr, xlat,
                                        l, is_write);
    ptr = qemu_ram_ptr_length(mr->uc, mr->ram_block, xlat, plen, true);
    return ptr;
}

/* Unmaps a memory region previously mapped by address_space_map().
 * Will also mark the memory as dirty if is_write == 1.  access_len gives
 * the amount of memory that was actually read or written by the caller.
 */
void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
        int is_write, hwaddr access_len)
{
    if (buffer != as->uc->bounce.buffer) {
        MemoryRegion *mr;
        ram_addr_t addr1;

        mr = memory_region_from_host(as->uc, buffer, &addr1);
        assert(mr != NULL);
        memory_region_unref(mr);
        return;
    }
    if (is_write) {
        address_space_write(as, as->uc->bounce.addr, MEMTXATTRS_UNSPECIFIED,
                            as->uc->bounce.buffer, access_len);
    }
    qemu_vfree(as->uc->bounce.buffer);
    as->uc->bounce.buffer = NULL;
    memory_region_unref(as->uc->bounce.mr);
    qatomic_mb_set(&as->uc->bounce.in_use, false);
}

void *cpu_physical_memory_map(AddressSpace *as, hwaddr addr,
        hwaddr *plen,
        int is_write)
{
    return address_space_map(as, addr, plen, is_write);
}

void cpu_physical_memory_unmap(AddressSpace *as, void *buffer, hwaddr len,
        int is_write, hwaddr access_len)
{
    address_space_unmap(as, buffer, len, is_write, access_len);
}

#define ARG1_DECL                AddressSpace *as
#define ARG1                     as
#define SUFFIX
#define TRANSLATE(...)           address_space_translate(as, __VA_ARGS__)
#define INVALIDATE(mr, ofs, len)
#define RCU_READ_LOCK(...)       rcu_read_lock()
#define RCU_READ_UNLOCK(...)     rcu_read_unlock()
#include "memory_ldst.inc.c"

int64_t address_space_cache_init(MemoryRegionCache *cache,
                                 AddressSpace *as,
                                 hwaddr addr,
                                 hwaddr len,
                                 bool is_write)
{
    cache->len = len;
    cache->as = as;
    cache->xlat = addr;
    return len;
}

void address_space_cache_invalidate(MemoryRegionCache *cache,
                                    hwaddr addr,
                                    hwaddr access_len)
{
}

void address_space_cache_destroy(MemoryRegionCache *cache)
{
    // Unicorn: If'd out
#if 0
    if (xen_enabled()) {
        xen_invalidate_map_cache_entry(cache->ptr);
    }
#endif
    cache->as = NULL;
}

// Unicorn: Necessary due to the fantastic way duplicate
//          symbol errors are avoided.
//          When appending the "_cache" suffix, the preprocessor
//          replaces the names in the glue macros with the target's
//          equivalent, resulting in names like "address_space_ldl_be_aarch64_cached"
//          which is incorrect. Therefore undef all the offending macros beforehand.
#undef address_space_ldl
#undef address_space_ldl_be
#undef address_space_ldl_le
#undef address_space_ldq
#undef address_space_ldq_be
#undef address_space_ldq_le
#undef address_space_ldub
#undef address_space_lduw
#undef address_space_lduw_be
#undef address_space_lduw_le
#undef address_space_stb
#undef address_space_stl
#undef address_space_stl_be
#undef address_space_stl_le
#undef address_space_stl_notdirty
#undef address_space_stq
#undef address_space_stq_be
#undef address_space_stq_le
#undef address_space_stw
#undef address_space_stw_be
#undef address_space_stw_le
#undef ldl_be_phys
#undef ldl_le_phys
#undef ldl_phys
#undef ldq_be_phys
#undef ldq_le_phys
#undef ldq_phys
#undef ldub_phys
#undef lduw_be_phys
#undef lduw_le_phys
#undef lduw_phys
#undef stb_phys
#undef stl_be_phys
#undef stl_le_phys
#undef stl_phys
#undef stl_phys_notdirty
#undef stq_be_phys
#undef stq_le_phys
#undef stq_phys
#undef stw_be_phys
#undef stw_le_phys
#undef stw_phys

#define ARG1_DECL                MemoryRegionCache *cache
#define ARG1                     cache
#define SUFFIX                   _cached
#define TRANSLATE(addr, ...)     \
    address_space_translate(cache->as, cache->xlat + (addr), __VA_ARGS__)
#define IS_DIRECT(mr, is_write)  true
#define MAP_RAM(mr, ofs)         qemu_map_ram_ptr((mr)->uc, (mr)->ram_block, ofs)
#define INVALIDATE(mr, ofs, len)
#define RCU_READ_LOCK()          //rcu_read_lock()
#define RCU_READ_UNLOCK()        //rcu_read_unlock()
#include "memory_ldst.inc.c"

/* virtual memory access for debug (includes writing to ROM) */
int cpu_memory_rw_debug(CPUState *cpu, target_ulong addr,
        uint8_t *buf, int len, int is_write)
{
    int l;
    hwaddr phys_addr;
    target_ulong page;

    while (len > 0) {
        int asidx;
        MemTxAttrs attrs;

        page = addr & TARGET_PAGE_MASK;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, page, &attrs);
        asidx = cpu_asidx_from_attrs(cpu, attrs);
        /* if no physical page mapped, return an error */
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        phys_addr += (addr & ~TARGET_PAGE_MASK);
        if (is_write) {
            cpu_physical_memory_write_rom(cpu->cpu_ases[asidx].as,
                                          phys_addr, buf, l);
        } else {
            address_space_rw(cpu->cpu_ases[asidx].as, phys_addr,
                             attrs, buf, l, 0);
        }
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}
#endif

/*
 * A helper function for the _utterly broken_ virtio device model to find out if
 * it's running on a big endian machine. Don't do this at home kids!
 */
bool target_words_bigendian(void);
bool target_words_bigendian(void)
{
#if defined(TARGET_WORDS_BIGENDIAN)
    return true;
#else
    return false;
#endif
}

#ifndef CONFIG_USER_ONLY
bool cpu_physical_memory_is_io(AddressSpace *as, hwaddr phys_addr)
{
    MemoryRegion*mr;
    hwaddr l = 1;

    mr = address_space_translate(as, phys_addr, &phys_addr, &l, false);

    return !(memory_region_is_ram(mr) ||
            memory_region_is_romd(mr));
}

int qemu_ram_foreach_block(struct uc_struct *uc, RAMBlockIterFunc func, void *opaque)
{
    RAMBlock *block;
    int ret = 0;

    // Unicorn: commented out
    //rcu_read_lock();
    QLIST_FOREACH(block, &uc->ram_list.blocks, next) {
        ret = func(block->idstr, block->host, block->offset,
                   block->used_length, opaque);
        if (ret) {
            break;
        }
    }
    // Unicorn: commented out
    //rcu_read_unlock();
    return ret;
}
#endif

void page_size_init(struct uc_struct *uc)
{
    /* NOTE: we can always suppose that qemu_host_page_size >=
       TARGET_PAGE_SIZE */
    uc->qemu_real_host_page_size = getpagesize();
    uc->qemu_real_host_page_mask = -(intptr_t)uc->qemu_real_host_page_size;
    if (uc->qemu_host_page_size == 0) {
        uc->qemu_host_page_size = uc->qemu_real_host_page_size;
    }
    if (uc->qemu_host_page_size < TARGET_PAGE_SIZE) {
        uc->qemu_host_page_size = TARGET_PAGE_SIZE;
    }
    uc->qemu_host_page_mask = -(intptr_t)uc->qemu_host_page_size;
}
