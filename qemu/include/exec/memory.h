/*
 * Physical memory management API
 *
 * Copyright 2011 Red Hat, Inc. and/or its affiliates
 *
 * Authors:
 *  Avi Kivity <avi@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef MEMORY_H
#define MEMORY_H

#ifndef CONFIG_USER_ONLY

#include "unicorn/platform.h"
#include "exec/cpu-common.h"
#include "exec/hwaddr.h"
#include "exec/memattrs.h"
#include "exec/memop.h"
#include "qemu/queue.h"
#include "qemu/int128.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "qemu/typedefs.h"

#define RAM_ADDR_INVALID (~(ram_addr_t)0)

#define MAX_PHYS_ADDR_SPACE_BITS 62
#define MAX_PHYS_ADDR            (((hwaddr)1 << MAX_PHYS_ADDR_SPACE_BITS) - 1)

#define TYPE_MEMORY_REGION "qemu:memory-region"
#define MEMORY_REGION(uc, obj) \
        OBJECT_CHECK(uc, MemoryRegion, (obj), TYPE_MEMORY_REGION)

typedef struct MemoryRegionOps MemoryRegionOps;
typedef struct MemoryRegionMmio MemoryRegionMmio;

struct MemoryRegionMmio {
    CPUReadMemoryFunc *read[3];
    CPUWriteMemoryFunc *write[3];
};

typedef struct IOMMUTLBEntry IOMMUTLBEntry;

/* See address_space_translate: bit 0 is read, bit 1 is write.  */
typedef enum {
    IOMMU_NONE = 0,
    IOMMU_RO   = 1,
    IOMMU_WO   = 2,
    IOMMU_RW   = 3,
} IOMMUAccessFlags;

struct IOMMUTLBEntry {
    AddressSpace    *target_as;
    hwaddr           iova;
    hwaddr           translated_addr;
    hwaddr           addr_mask;  /* 0xfff = 4k translation */
    IOMMUAccessFlags perm;
};

/* RAM is pre-allocated and passed into qemu_ram_alloc_from_ptr */
#define RAM_PREALLOC   (1 << 0)

/* RAM is mmap-ed with MAP_SHARED */
#define RAM_SHARED     (1 << 1)

/* Only a portion of RAM (used_length) is actually used, and migrated.
 * This used_length size can change across reboots.
 */
#define RAM_RESIZEABLE (1 << 2)

/* UFFDIO_ZEROPAGE is available on this RAMBlock to atomically
 * zero the page and wake waiting processes.
 * (Set during postcopy)
 */
#define RAM_UF_ZEROPAGE (1 << 3)

/* RAM can be migrated */
#define RAM_MIGRATABLE (1 << 4)

/*
 * Memory region callbacks
 */
struct MemoryRegionOps {
    /* Read from the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    uint64_t (*read)(struct uc_struct* uc, void *opaque,
                     hwaddr addr,
                     unsigned size);
    /* Write to the memory region. @addr is relative to @mr; @size is
     * in bytes. */
    void (*write)(struct uc_struct* uc, void *opaque,
                  hwaddr addr,
                  uint64_t data,
                  unsigned size);

    MemTxResult (*read_with_attrs)(struct uc_struct* uc, void *opaque,
                                   hwaddr addr,
                                   uint64_t *data,
                                   unsigned size,
                                   MemTxAttrs attrs);
    MemTxResult (*write_with_attrs)(struct uc_struct* uc, void *opaque,
                                    hwaddr addr,
                                    uint64_t data,
                                    unsigned size,
                                    MemTxAttrs attrs);

    enum device_endian endianness;
    /* Guest-visible constraints: */
    struct {
        /* If nonzero, specify bounds on access sizes beyond which a machine
         * check is thrown.
         */
        unsigned min_access_size;
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise unaligned
         * accesses throw machine checks.
         */
         bool unaligned;
        /*
         * If present, and returns #false, the transaction is not accepted
         * by the device (and results in machine dependent behaviour such
         * as a machine check exception).
         */
        bool (*accepts)(void *opaque, hwaddr addr,
                        unsigned size, bool is_write);
    } valid;
    /* Internal implementation constraints: */
    struct {
        /* If nonzero, specifies the minimum size implemented.  Smaller sizes
         * will be rounded upwards and a partial result will be returned.
         */
        unsigned min_access_size;
        /* If nonzero, specifies the maximum size implemented.  Larger sizes
         * will be done as a series of accesses with smaller sizes.
         */
        unsigned max_access_size;
        /* If true, unaligned accesses are supported.  Otherwise all accesses
         * are converted to (possibly multiple) naturally aligned accesses.
         */
        bool unaligned;
    } impl;
};

typedef struct MemoryRegionIOMMUOps MemoryRegionIOMMUOps;

struct MemoryRegionIOMMUOps {
    /*
     * Return a TLB entry that contains a given address. Flag should
     * be the access permission of this translation operation. We can
     * set flag to IOMMU_NONE to mean that we don't need any
     * read/write permission checks, like, when for region replay.
     */
    IOMMUTLBEntry (*translate)(MemoryRegion *iommu, hwaddr addr,
                               IOMMUAccessFlags flag);
    /* Returns minimum supported page size */
    uint64_t (*get_min_page_size)(MemoryRegion *iommu);
    /* Called when the first notifier is set */
    void (*notify_started)(MemoryRegion *iommu);
    /* Called when the last notifier is removed */
    void (*notify_stopped)(MemoryRegion *iommu);
};

struct MemoryRegion {
    Object parent_obj;

    /* All fields are private - violators will be prosecuted */
    /* The following fields should fit in a cache line */
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool nonvolatile;
    bool rom_device;
    bool flush_coalesced_mmio;
    bool global_locking;
    uint8_t dirty_log_mask;
    RAMBlock *ram_block;
    const MemoryRegionIOMMUOps *iommu_ops;
    Object *owner;

    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    MemoryRegion *alias;
    hwaddr alias_offset;
    int32_t priority;
    QTAILQ_HEAD(subregions, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    const char *name;
    struct uc_struct *uc;
    uint32_t perms;   //all perms, partially redundant with readonly
    uint64_t end;
};

/**
 * MemoryListener: callbacks structure for updates to the physical memory map
 *
 * Allows a component to adjust to changes in the guest-visible memory map.
 * Use with memory_listener_register() and memory_listener_unregister().
 */
struct MemoryListener {
    void (*begin)(MemoryListener *listener);
    void (*commit)(MemoryListener *listener);
    void (*region_add)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_del)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_nop)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_start)(MemoryListener *listener, MemoryRegionSection *section,
                      int old, int new);
    void (*log_stop)(MemoryListener *listener, MemoryRegionSection *section,
                     int old, int new);
    void (*log_sync)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_global_start)(MemoryListener *listener);
    void (*log_global_stop)(MemoryListener *listener);
    /* Lower = earlier (during add), later (during del) */
    unsigned priority;
    AddressSpace *address_space;
    QTAILQ_ENTRY(MemoryListener) link;
    QTAILQ_ENTRY(MemoryListener) link_as;
};

/**
 * AddressSpace: describes a mapping of addresses to #MemoryRegion objects
 */
struct AddressSpace {
    /* All fields are private. */
    char *name;
    MemoryRegion *root;

    /* Accessed via RCU.  */
    struct FlatView *current_map;

    struct uc_struct* uc;

    QTAILQ_HEAD(memory_listeners_as, MemoryListener) listeners;
    QTAILQ_ENTRY(AddressSpace) address_spaces_link;
};

FlatView *address_space_to_flatview(AddressSpace *as);

/**
 * MemoryRegionSection: describes a fragment of a #MemoryRegion
 *
 * @mr: the region, or %NULL if empty
 * @address_space: the address space the region is mapped in
 * @offset_within_region: the beginning of the section, relative to @mr's start
 * @size: the size of the section; will not exceed @mr's boundaries
 * @offset_within_address_space: the address of the first byte of the section
 *     relative to the region's address space
 * @readonly: writes to this section are ignored
 * @nonvolatile: this section is non-volatile
 */
struct MemoryRegionSection {
    Int128 size;
    MemoryRegion *mr;
    FlatView *fv;
    hwaddr offset_within_region;
    hwaddr offset_within_address_space;
    bool readonly;
    bool nonvolatile;
};

static inline bool MemoryRegionSection_eq(MemoryRegionSection *a,
                                          MemoryRegionSection *b)
{
    return a->mr == b->mr &&
           a->fv == b->fv &&
           a->offset_within_region == b->offset_within_region &&
           a->offset_within_address_space == b->offset_within_address_space &&
           int128_eq(a->size, b->size) &&
           a->readonly == b->readonly &&
           a->nonvolatile == b->nonvolatile;
}

static inline MemoryRegionSection MemoryRegionSection_make(MemoryRegion *mr, FlatView *fv,
    hwaddr offset_within_region, Int128 size, hwaddr offset_within_address_space, bool readonly)
{
    MemoryRegionSection section;
    section.mr = mr;
    section.fv = fv;
    section.offset_within_region = offset_within_region;
    section.size = size;
    section.offset_within_address_space = offset_within_address_space;
    section.readonly = readonly;
    return section;
}

/**
 * memory_region_init: Initialize a memory region
 *
 * The region typically acts as a container for other memory regions.  Use
 * memory_region_add_subregion() to add subregions.
 *
 * @mr: the #MemoryRegion to be initialized
 * @owner: the object that tracks the region's reference count
 * @name: used for debugging; not visible to the user or ABI
 * @size: size of the region; any subregions beyond this size will be clipped
 */
void memory_region_init(struct uc_struct *uc, MemoryRegion *mr,
                        struct Object *owner,
                        const char *name,
                        uint64_t size);

/**
 * memory_region_ref: Add 1 to a memory region's reference count
 *
 * Whenever memory regions are accessed outside the BQL, they need to be
 * preserved against hot-unplug.  MemoryRegions actually do not have their
 * own reference count; they piggyback on a QOM object, their "owner".
 * This function adds a reference to the owner.
 *
 * All MemoryRegions must have an owner if they can disappear, even if the
 * device they belong to operates exclusively under the BQL.  This is because
 * the region could be returned at any time by memory_region_find, and this
 * is usually under guest control.
 *
 * @mr: the #MemoryRegion
 */
void memory_region_ref(MemoryRegion *mr);

/**
 * memory_region_unref: Remove 1 to a memory region's reference count
 *
 * Whenever memory regions are accessed outside the BQL, they need to be
 * preserved against hot-unplug.  MemoryRegions actually do not have their
 * own reference count; they piggyback on a QOM object, their "owner".
 * This function removes a reference to the owner and possibly destroys it.
 *
 * @mr: the #MemoryRegion
 */
void memory_region_unref(MemoryRegion *mr);

/**
 * memory_region_init_io: Initialize an I/O memory region.
 *
 * Accesses into the region will cause the callbacks in @ops to be called.
 * if @size is nonzero, subregions will be clipped to @size.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @ops: a structure containing read and write callbacks to be used when
 *       I/O is performed on the region.
 * @opaque: passed to to the read and write callbacks of the @ops structure.
 * @name: used for debugging; not visible to the user or ABI
 * @size: size of the region.
 */
void memory_region_init_io(struct uc_struct *uc,
                           MemoryRegion *mr,
                           struct Object *owner,
                           const MemoryRegionOps *ops,
                           void *opaque,
                           const char *name,
                           uint64_t size);

/**
 * memory_region_init_ram_nomigrate:  Initialize RAM memory region.  Accesses
 *                                    into the region will modify memory
 *                                    directly.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @name: Region name, becomes part of RAMBlock name used in migration stream
 *        must be unique within any device
 * @size: size of the region.
 * @perms: permissions on the region (UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC).
 * @errp: pointer to Error*, to store an error if it happens.
 *
 * Note that this function does not do anything to cause the data in the
 * RAM memory region to be migrated; that is the responsibility of the caller.
 */
void memory_region_init_ram_nomigrate(struct uc_struct *uc,
                                      MemoryRegion *mr,
                                      struct Object *owner,
                                      const char *name,
                                      uint64_t size,
                                      uint32_t perms,
                                      Error **errp);

/**
 * memory_region_init_ram_ptr:  Initialize RAM memory region from a
 *                              user-provided pointer.  Accesses into the
 *                              region will modify memory directly.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @name: Region name, becomes part of RAMBlock name used in migration stream
 *        must be unique within any device
 * @size: size of the region.
 * @ptr: memory to be mapped; must contain at least @size bytes.
 *
 * Note that this function does not do anything to cause the data in the
 * RAM memory region to be migrated; that is the responsibility of the caller.
 */
void memory_region_init_ram_ptr(struct uc_struct *uc,
                                MemoryRegion *mr,
                                struct Object *owner,
                                const char *name,
                                uint64_t size,
                                void *ptr);

/**
 * memory_region_init_ram_device_ptr:  Initialize RAM device memory region from
 *                                     a user-provided pointer.
 *
 * A RAM device represents a mapping to a physical device, such as to a PCI
 * MMIO BAR of an vfio-pci assigned device.  The memory region may be mapped
 * into the VM address space and access to the region will modify memory
 * directly.  However, the memory region should not be included in a memory
 * dump (device may not be enabled/mapped at the time of the dump), and
 * operations incompatible with manipulating MMIO should be avoided.  Replaces
 * skip_dump flag.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @name: Region name, becomes part of RAMBlock name used in migration stream
 *        must be unique within any device
 * @size: size of the region.
 * @ptr: memory to be mapped; must contain at least @size bytes.
 *
 * Note that this function does not do anything to cause the data in the
 * RAM memory region to be migrated; that is the responsibility of the caller.
 * (For RAM device memory regions, migrating the contents rarely makes sense.)
 */
void memory_region_init_ram_device_ptr(struct uc_struct *uc,
                                       MemoryRegion *mr,
                                       struct Object *owner,
                                       const char *name,
                                       uint64_t size,
                                       void *ptr);

/**
 * memory_region_init_alias: Initialize a memory region that aliases all or a
 *                           part of another memory region.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @name: used for debugging; not visible to the user or ABI
 * @orig: the region to be referenced; @mr will be equivalent to
 *        @orig between @offset and @offset + @size - 1.
 * @offset: start of the section in @orig to be referenced.
 * @size: size of the region.
 */
void memory_region_init_alias(struct uc_struct *uc,
                              MemoryRegion *mr,
                              struct Object *owner,
                              const char *name,
                              MemoryRegion *orig,
                              hwaddr offset,
                              uint64_t size);

/**
 * memory_region_init_rom_nomigrate: Initialize a ROM memory region.
 *
 * This has the same effect as calling memory_region_init_ram_nomigrate()
 * and then marking the resulting region read-only with
 * memory_region_set_readonly().
 *
 * Note that this function does not do anything to cause the data in the
 * RAM side of the memory region to be migrated; that is the responsibility
 * of the caller.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @name: Region name, becomes part of RAMBlock name used in migration stream
 *        must be unique within any device
 * @size: size of the region.
 * @errp: pointer to Error*, to store an error if it happens.
 */
void memory_region_init_rom_nomigrate(struct uc_struct *uc,
                                      MemoryRegion *mr,
                                      struct Object *owner,
                                      const char *name,
                                      uint64_t size,
                                      Error **errp);

/**
 * memory_region_init_rom_device_nomigrate:  Initialize a ROM memory region.
 *                                 Writes are handled via callbacks.
 *
 * Note that this function does not do anything to cause the data in the
 * RAM side of the memory region to be migrated; that is the responsibility
 * of the caller.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @ops: callbacks for write access handling (must not be NULL).
 * @name: Region name, becomes part of RAMBlock name used in migration stream
 *        must be unique within any device
 * @size: size of the region.
 * @errp: pointer to Error*, to store an error if it happens.
 */
void memory_region_init_rom_device_nomigrate(struct uc_struct *uc,
                                             MemoryRegion *mr,
                                             struct Object *owner,
                                             const MemoryRegionOps *ops,
                                             void *opaque,
                                             const char *name,
                                             uint64_t size,
                                             Error **errp);

/**
 * memory_region_init_resizeable_ram:  Initialize memory region with resizeable
 *                                     RAM.  Accesses into the region will
 *                                     modify memory directly.  Only an initial
 *                                     portion of this RAM is actually used.
 *                                     The used size can change across reboots.
 *
 * @mr: the #MemoryRegion to be initialized.
 * @owner: the object that tracks the region's reference count
 * @name: Region name, becomes part of RAMBlock name used in migration stream
 *        must be unique within any device
 * @size: used size of the region.
 * @max_size: max size of the region.
 * @resized: callback to notify owner about used size change.
 * @errp: pointer to Error*, to store an error if it happens.
 *
 * Note that this function does not do anything to cause the data in the
 * RAM memory region to be migrated; that is the responsibility of the caller.
 */
void memory_region_init_resizeable_ram(struct uc_struct *uc,
                                       MemoryRegion *mr,
                                       struct Object *owner,
                                       const char *name,
                                       uint64_t size,
                                       uint64_t max_size,
                                       void (*resized)(const char*,
                                                       uint64_t length,
                                                       void *host),
                                       Error **errp);

/**
 * memory_region_init_reservation: Initialize a memory region that reserves
 *                                 I/O space.
 *
 * A reservation region primariy serves debugging purposes.  It claims I/O
 * space that is not supposed to be handled by QEMU itself.  Any access via
 * the memory API will cause an abort().
 * This function is deprecated. Use memory_region_init_io() with NULL
 * callbacks instead.
 *
 * @mr: the #MemoryRegion to be initialized
 * @owner: the object that tracks the region's reference count
 * @name: used for debugging; not visible to the user or ABI
 * @size: size of the region.
 */
static inline void memory_region_init_reservation(struct uc_struct *uc, MemoryRegion *mr,
                                                  Object *owner,
                                                  const char *name,
                                                  uint64_t size)
{
    memory_region_init_io(uc, mr, owner, NULL, mr, name, size);
}

/**
 * memory_region_init_iommu: Initialize a memory region that translates
 * addresses
 *
 * An IOMMU region translates addresses and forwards accesses to a target
 * memory region.
 *
 * @mr: the #MemoryRegion to be initialized
 * @owner: the object that tracks the region's reference count
 * @ops: a function that translates addresses into the @target region
 * @name: used for debugging; not visible to the user or ABI
 * @size: size of the region.
 */
void memory_region_init_iommu(MemoryRegion *mr,
                              struct Object *owner,
                              const MemoryRegionIOMMUOps *ops,
                              const char *name,
                              uint64_t size);

/**
 * memory_region_size: get a memory region's size.
 *
 * @mr: the memory region being queried.
 */
uint64_t memory_region_size(MemoryRegion *mr);

/**
 * memory_region_is_ram: check whether a memory region is random access
 *
 * Returns %true if a memory region is random access.
 *
 * @mr: the memory region being queried
 */
static inline bool memory_region_is_ram(MemoryRegion *mr)
{
    return mr->ram;
}

/**
 * memory_region_is_ram_device: check whether a memory region is a ram device
 *
 * Returns %true if a memory region is a device backed ram region
 *
 * @mr: the memory region being queried
 */
bool memory_region_is_ram_device(MemoryRegion *mr);

/**
 * memory_region_is_romd: check whether a memory region is in ROMD mode
 *
 * Returns %true if a memory region is a ROM device and currently set to allow
 * direct reads.
 *
 * @mr: the memory region being queried
 */
static inline bool memory_region_is_romd(MemoryRegion *mr)
{
    return mr->rom_device && mr->romd_mode;
}

/**
 * memory_region_is_iommu: check whether a memory region is an iommu
 *
 * Returns %true is a memory region is an iommu.
 *
 * @mr: the memory region being queried
 */
static inline bool memory_region_is_iommu(MemoryRegion *mr)
{
    if (mr->alias) {
        return memory_region_is_iommu(mr->alias);
    }
    return mr->iommu_ops;
}

/**
 * memory_region_notify_iommu: notify a change in an IOMMU translation entry.
 *
 * @mr: the memory region that was changed
 * @entry: the new entry in the IOMMU translation table.  The entry
 *         replaces all old entries for the same virtual I/O address range.
 *         Deleted entries have .@perm == 0.
 */
void memory_region_notify_iommu(MemoryRegion *mr,
                                IOMMUTLBEntry entry);

/**
 * memory_region_name: get a memory region's name
 *
 * Returns the string that was used to initialize the memory region.
 *
 * @mr: the memory region being queried
 */
const char *memory_region_name(const MemoryRegion *mr);

/**
 * memory_region_is_logging: return whether a memory region is logging writes
 *
 * Returns %true if the memory region is logging writes
 *
 * @mr: the memory region being queried
 * @client: the client being queried
 */
bool memory_region_is_logging(MemoryRegion *mr, uint8_t client);

/**
 * memory_region_get_dirty_log_mask: return the clients for which a
 * memory region is logging writes.
 *
 * Returns a bitmap of clients, in which the DIRTY_MEMORY_* constants
 * are the bit indices.
 *
 * @mr: the memory region being queried
 */
uint8_t memory_region_get_dirty_log_mask(MemoryRegion *mr);

/**
 * memory_region_is_rom: check whether a memory region is ROM
 *
 * Returns %true if a memory region is read-only memory.
 *
 * @mr: the memory region being queried
 */
static inline bool memory_region_is_rom(MemoryRegion *mr)
{
    return mr->ram && mr->readonly;
}

/**
 * memory_region_is_nonvolatile: check whether a memory region is non-volatile
 *
 * Returns %true is a memory region is non-volatile memory.
 *
 * @mr: the memory region being queried
 */
static inline bool memory_region_is_nonvolatile(MemoryRegion *mr)
{
    return mr->nonvolatile;
}

/**
 * memory_region_get_fd: Get a file descriptor backing a RAM memory region.
 *
 * Returns a file descriptor backing a file-based RAM memory region,
 * or -1 if the region is not a file-based RAM memory region.
 *
 * @mr: the RAM or alias memory region being queried.
 */
int memory_region_get_fd(MemoryRegion *mr);

/**
 * memory_region_from_host: Convert a pointer into a RAM memory region
 * and an offset within it.
 *
 * Given a host pointer inside a RAM memory region (created with
 * memory_region_init_ram() or memory_region_init_ram_ptr()), return
 * the MemoryRegion and the offset within it.
 *
 * Use with care; by the time this function returns, the returned pointer is
 * not protected by RCU anymore.  If the caller is not within an RCU critical
 * section and does not hold the iothread lock, it must have other means of
 * protecting the pointer, such as a reference to the region that includes
 * the incoming ram_addr_t.
 *
 * @mr: the memory region being queried.
 */
MemoryRegion *memory_region_from_host(struct uc_struct *uc, void *ptr, ram_addr_t *offset);

/**
 * memory_region_get_ram_ptr: Get a pointer into a RAM memory region.
 *
 * Returns a host pointer to a RAM memory region (created with
 * memory_region_init_ram() or memory_region_init_ram_ptr()).  Use with
 * care.
 *
 * @mr: the memory region being queried.
 */
void *memory_region_get_ram_ptr(MemoryRegion *mr);

/**
 * memory_region_do_writeback: Trigger writeback for selected address range
 * [addr, addr + size]
 *
 */
void memory_region_do_writeback(MemoryRegion *mr, hwaddr addr, hwaddr size);

/**
 * memory_region_set_readonly: Turn a memory region read-only (or read-write)
 *
 * Allows a memory region to be marked as read-only (turning it into a ROM).
 * only useful on RAM regions.
 *
 * @mr: the region being updated.
 * @readonly: whether rhe region is to be ROM or RAM.
 */
void memory_region_set_readonly(MemoryRegion *mr, bool readonly);

/**
 * memory_region_set_nonvolatile: Turn a memory region non-volatile
 *
 * Allows a memory region to be marked as non-volatile.
 * only useful on RAM regions.
 *
 * @mr: the region being updated.
 * @nonvolatile: whether rhe region is to be non-volatile.
 */
void memory_region_set_nonvolatile(MemoryRegion *mr, bool nonvolatile);

/**
 * memory_region_clear_global_locking: Declares that access processing does
 *                                     not depend on the QEMU global lock.
 *
 * By clearing this property, accesses to the memory region will be processed
 * outside of QEMU's global lock (unless the lock is held on when issuing the
 * access request). In this case, the device model implementing the access
 * handlers is responsible for synchronization of concurrency.
 *
 * @mr: the memory region to be updated.
 */
void memory_region_clear_global_locking(MemoryRegion *mr);

/**
 * memory_region_rom_device_set_romd: enable/disable ROMD mode
 *
 * Allows a ROM device (initialized with memory_region_init_rom_device() to
 * set to ROMD mode (default) or MMIO mode.  When it is in ROMD mode, the
 * device is mapped to guest memory and satisfies read access directly.
 * When in MMIO mode, reads are forwarded to the #MemoryRegion.read function.
 * Writes are always handled by the #MemoryRegion.write function.
 *
 * @mr: the memory region to be updated
 * @romd_mode: %true to put the region into ROMD mode
 */
void memory_region_rom_device_set_romd(MemoryRegion *mr, bool romd_mode);

/**
 * memory_region_add_subregion: Add a subregion to a container.
 *
 * Adds a subregion at @offset.  The subregion may not overlap with other
 * subregions (except for those explicitly marked as overlapping).  A region
 * may only be added once as a subregion (unless removed with
 * memory_region_del_subregion()); use memory_region_init_alias() if you
 * want a region to be a subregion in multiple locations.
 *
 * @mr: the region to contain the new subregion; must be a container
 *      initialized with memory_region_init().
 * @offset: the offset relative to @mr where @subregion is added.
 * @subregion: the subregion to be added.
 */
void memory_region_add_subregion(MemoryRegion *mr,
                                 hwaddr offset,
                                 MemoryRegion *subregion);
/**
 * memory_region_add_subregion_overlap: Add a subregion to a container
 *                                      with overlap.
 *
 * Adds a subregion at @offset.  The subregion may overlap with other
 * subregions.  Conflicts are resolved by having a higher @priority hide a
 * lower @priority. Subregions without priority are taken as @priority 0.
 * A region may only be added once as a subregion (unless removed with
 * memory_region_del_subregion()); use memory_region_init_alias() if you
 * want a region to be a subregion in multiple locations.
 *
 * @mr: the region to contain the new subregion; must be a container
 *      initialized with memory_region_init().
 * @offset: the offset relative to @mr where @subregion is added.
 * @subregion: the subregion to be added.
 * @priority: used for resolving overlaps; highest priority wins.
 */
void memory_region_add_subregion_overlap(MemoryRegion *mr,
                                         hwaddr offset,
                                         MemoryRegion *subregion,
                                         int priority);

/**
 * memory_region_get_ram_addr: Get the ram address associated with a memory
 *                             region
 */
ram_addr_t memory_region_get_ram_addr(MemoryRegion *mr);

uint64_t memory_region_get_alignment(const MemoryRegion *mr);

/**
 * memory_region_del_subregion: Remove a subregion.
 *
 * Removes a subregion from its container.
 *
 * @mr: the container to be updated.
 * @subregion: the region being removed; must be a current subregion of @mr.
 */
void memory_region_del_subregion(MemoryRegion *mr,
                                 MemoryRegion *subregion);

/*
 * memory_region_set_enabled: dynamically enable or disable a region
 *
 * Enables or disables a memory region.  A disabled memory region
 * ignores all accesses to itself and its subregions.  It does not
 * obscure sibling subregions with lower priority - it simply behaves as
 * if it was removed from the hierarchy.
 *
 * Regions default to being enabled.
 *
 * @mr: the region to be updated
 * @enabled: whether to enable or disable the region
 */
void memory_region_set_enabled(MemoryRegion *mr, bool enabled);

/*
 * memory_region_set_address: dynamically update the address of a region
 *
 * Dynamically updates the address of a region, relative to its container.
 * May be used on regions are currently part of a memory hierarchy.
 *
 * @mr: the region to be updated
 * @addr: new address, relative to container region
 */
void memory_region_set_address(MemoryRegion *mr, hwaddr addr);

/*
 * memory_region_set_size: dynamically update the size of a region.
 *
 * Dynamically updates the size of a region.
 *
 * @mr: the region to be updated
 * @size: used size of the region.
 */
void memory_region_set_size(MemoryRegion *mr, uint64_t size);

/*
 * memory_region_set_alias_offset: dynamically update a memory alias's offset
 *
 * Dynamically updates the offset into the target region that an alias points
 * to, as if the fourth argument to memory_region_init_alias() has changed.
 *
 * @mr: the #MemoryRegion to be updated; should be an alias.
 * @offset: the new offset into the target memory region
 */
void memory_region_set_alias_offset(MemoryRegion *mr,
                                    hwaddr offset);

/**
 * memory_region_present: checks if an address relative to a @container
 * translates into #MemoryRegion within @container
 *
 * Answer whether a #MemoryRegion within @container covers the address
 * @addr.
 *
 * @container: a #MemoryRegion within which @addr is a relative address
 * @addr: the area within @container to be searched
 */
bool memory_region_present(MemoryRegion *container, hwaddr addr);

/**
 * memory_region_is_mapped: returns true if #MemoryRegion is mapped
 * into any address space.
 *
 * @mr: a #MemoryRegion which should be checked if it's mapped
 */
bool memory_region_is_mapped(MemoryRegion *mr);

/**
 * memory_region_find: translate an address/size relative to a
 * MemoryRegion into a #MemoryRegionSection.
 *
 * Locates the first #MemoryRegion within @mr that overlaps the range
 * given by @addr and @size.
 *
 * Returns a #MemoryRegionSection that describes a contiguous overlap.
 * It will have the following characteristics:
 *    .@size = 0 iff no overlap was found
 *    .@mr is non-%NULL iff an overlap was found
 *
 * Remember that in the return value the @offset_within_region is
 * relative to the returned region (in the .@mr field), not to the
 * @mr argument.
 *
 * Similarly, the .@offset_within_address_space is relative to the
 * address space that contains both regions, the passed and the
 * returned one.  However, in the special case where the @mr argument
 * has no container (and thus is the root of the address space), the
 * following will hold:
 *    .@offset_within_address_space >= @addr
 *    .@offset_within_address_space + .@size <= @addr + @size
 *
 * @mr: a MemoryRegion within which @addr is a relative address
 * @addr: start of the area within @as to be searched
 * @size: size of the area to be searched
 */
MemoryRegionSection memory_region_find(MemoryRegion *mr,
                                       hwaddr addr, uint64_t size);

/**
 * memory_region_transaction_begin: Start a transaction.
 *
 * During a transaction, changes will be accumulated and made visible
 * only when the transaction ends (is committed).
 */
void memory_region_transaction_begin(struct uc_struct*);

/**
 * memory_region_transaction_commit: Commit a transaction and make changes
 *                                   visible to the guest.
 */
void memory_region_transaction_commit(struct uc_struct*);

/**
 * memory_listener_register: register callbacks to be called when memory
 *                           sections are mapped or unmapped into an address
 *                           space
 *
 * @listener: an object containing the callbacks to be called
 * @filter: if non-%NULL, only regions in this address space will be observed
 */
void memory_listener_register(struct uc_struct* uc, MemoryListener *listener, AddressSpace *filter);

/**
 * memory_listener_unregister: undo the effect of memory_listener_register()
 *
 * @listener: an object containing the callbacks to be removed
 */
void memory_listener_unregister(struct uc_struct* uc, MemoryListener *listener);

/**
 * memory_region_dispatch_read: perform a read directly to the specified
 * MemoryRegion.
 *
 * @mr: #MemoryRegion to access
 * @addr: address within that region
 * @pval: pointer to uint64_t which the data is written to
 * @op: size, sign, and endianness of the memory operation
 * @attrs: memory transaction attributes to use for the access
 */
MemTxResult memory_region_dispatch_read(MemoryRegion *mr,
                                        hwaddr addr,
                                        uint64_t *pval,
                                        MemOp op,
                                        MemTxAttrs attrs);
/**
 * memory_region_dispatch_write: perform a write directly to the specified
 * MemoryRegion.
 *
 * @mr: #MemoryRegion to access
 * @addr: address within that region
 * @data: data to write
 * @op: size, sign, and endianness of the memory operation
 * @attrs: memory transaction attributes to use for the access
 */
MemTxResult memory_region_dispatch_write(MemoryRegion *mr,
                                         hwaddr addr,
                                         uint64_t data,
                                         MemOp op,
                                         MemTxAttrs attrs);

/**
 * address_space_init: initializes an address space
 *
 * @as: an uninitialized #AddressSpace
 * @root: a #MemoryRegion that routes addesses for the address space
 * @name: an address space name.  The name is only used for debugging
 *        output.
 */
void address_space_init(struct uc_struct *uc, AddressSpace *as, MemoryRegion *root, const char *name);

/**
 * address_space_destroy: destroy an address space
 *
 * Releases all resources associated with an address space.  After an address space
 * is destroyed, its root memory region (given by address_space_init()) may be destroyed
 * as well.
 *
 * @as: address space to be destroyed
 */
void address_space_destroy(AddressSpace *as);

/**
 * address_space_rw: read from or write to an address space.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 * @is_write: indicates the transfer direction
 */
MemTxResult address_space_rw(AddressSpace *as, hwaddr addr,
                             MemTxAttrs attrs, uint8_t *buf,
                             int len, bool is_write);

/**
 * address_space_write: write to address space.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 */
MemTxResult address_space_write(AddressSpace *as, hwaddr addr,
                                MemTxAttrs attrs,
                                const uint8_t *buf, int len);

/**
 * address_space_ld*: load from an address space
 * address_space_st*: store to an address space
 *
 * These functions perform a load or store of the byte, word,
 * longword or quad to the specified address within the AddressSpace.
 * The _le suffixed functions treat the data as little endian;
 * _be indicates big endian; no suffix indicates "same endianness
 * as guest CPU".
 *
 * The "guest CPU endianness" accessors are deprecated for use outside
 * target-* code; devices should be CPU-agnostic and use either the LE
 * or the BE accessors.
 *
 * @as #AddressSpace to be accessed
 * @addr: address within that address space
 * @val: data value, for stores
 * @attrs: memory transaction attributes
 * @result: location to write the success/failure of the transaction;
 *   if NULL, this information is discarded
 */
uint32_t address_space_ldub(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_lduw_le(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_lduw_be(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_ldl_le(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_ldl_be(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint64_t address_space_ldq_le(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint64_t address_space_ldq_be(AddressSpace *as, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stb(AddressSpace *as, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stw_le(AddressSpace *as, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stw_be(AddressSpace *as, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stl_le(AddressSpace *as, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stl_be(AddressSpace *as, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stq_le(AddressSpace *as, hwaddr addr, uint64_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stq_be(AddressSpace *as, hwaddr addr, uint64_t val,
                            MemTxAttrs attrs, MemTxResult *result);

uint32_t ldub_phys(AddressSpace *as, hwaddr addr);
uint32_t lduw_le_phys(AddressSpace *as, hwaddr addr);
uint32_t lduw_be_phys(AddressSpace *as, hwaddr addr);
uint32_t ldl_le_phys(AddressSpace *as, hwaddr addr);
uint32_t ldl_be_phys(AddressSpace *as, hwaddr addr);
uint64_t ldq_le_phys(AddressSpace *as, hwaddr addr);
uint64_t ldq_be_phys(AddressSpace *as, hwaddr addr);
void stb_phys(AddressSpace *as, hwaddr addr, uint32_t val);
void stw_le_phys(AddressSpace *as, hwaddr addr, uint32_t val);
void stw_be_phys(AddressSpace *as, hwaddr addr, uint32_t val);
void stl_le_phys(AddressSpace *as, hwaddr addr, uint32_t val);
void stl_be_phys(AddressSpace *as, hwaddr addr, uint32_t val);
void stq_le_phys(AddressSpace *as, hwaddr addr, uint64_t val);
void stq_be_phys(AddressSpace *as, hwaddr addr, uint64_t val);

struct MemoryRegionCache {
    hwaddr xlat;
    hwaddr len;
    AddressSpace *as;
};

/* address_space_cache_init: prepare for repeated access to a physical
 * memory region
 *
 * @cache: #MemoryRegionCache to be filled
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @len: length of buffer
 * @is_write: indicates the transfer direction
 *
 * Will only work with RAM, and may map a subset of the requested range by
 * returning a value that is less than @len.  On failure, return a negative
 * errno value.
 *
 * Because it only works with RAM, this function can be used for
 * read-modify-write operations.  In this case, is_write should be %true.
 *
 * Note that addresses passed to the address_space_*_cached functions
 * are relative to @addr.
 */
int64_t address_space_cache_init(MemoryRegionCache *cache,
                                 AddressSpace *as,
                                 hwaddr addr,
                                 hwaddr len,
                                 bool is_write);

/**
 * address_space_cache_invalidate: complete a write to a #MemoryRegionCache
 *
 * @cache: The #MemoryRegionCache to operate on.
 * @addr: The first physical address that was written, relative to the
 * address that was passed to @address_space_cache_init.
 * @access_len: The number of bytes that were written starting at @addr.
 */
void address_space_cache_invalidate(MemoryRegionCache *cache,
                                    hwaddr addr,
                                    hwaddr access_len);

/**
 * address_space_cache_destroy: free a #MemoryRegionCache
 *
 * @cache: The #MemoryRegionCache whose memory should be released.
 */
void address_space_cache_destroy(MemoryRegionCache *cache);

/* address_space_ld*_cached: load from a cached #MemoryRegion
 * address_space_st*_cached: store into a cached #MemoryRegion
 *
 * These functions perform a load or store of the byte, word,
 * longword or quad to the specified address.  The address is
 * a physical address in the AddressSpace, but it must lie within
 * a #MemoryRegion that was mapped with address_space_cache_init.
 *
 * The _le suffixed functions treat the data as little endian;
 * _be indicates big endian; no suffix indicates "same endianness
 * as guest CPU".
 *
 * The "guest CPU endianness" accessors are deprecated for use outside
 * target-* code; devices should be CPU-agnostic and use either the LE
 * or the BE accessors.
 *
 * @cache: previously initialized #MemoryRegionCache to be accessed
 * @addr: address within the address space
 * @val: data value, for stores
 * @attrs: memory transaction attributes
 * @result: location to write the success/failure of the transaction;
 *   if NULL, this information is discarded
 */
uint32_t address_space_ldub_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_lduw_le_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_lduw_be_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_ldl_le_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint32_t address_space_ldl_be_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint64_t address_space_ldq_le_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
uint64_t address_space_ldq_be_cached(MemoryRegionCache *cache, hwaddr addr,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stb_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stw_le_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stw_be_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stl_le_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stl_be_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stq_le_cached(MemoryRegionCache *cache, hwaddr addr, uint64_t val,
                            MemTxAttrs attrs, MemTxResult *result);
void address_space_stq_be_cached(MemoryRegionCache *cache, hwaddr addr, uint64_t val,
                            MemTxAttrs attrs, MemTxResult *result);

uint32_t ldub_phys_cached(MemoryRegionCache *cache, hwaddr addr);
uint32_t lduw_le_phys_cached(MemoryRegionCache *cache, hwaddr addr);
uint32_t lduw_be_phys_cached(MemoryRegionCache *cache, hwaddr addr);
uint32_t ldl_le_phys_cached(MemoryRegionCache *cache, hwaddr addr);
uint32_t ldl_be_phys_cached(MemoryRegionCache *cache, hwaddr addr);
uint64_t ldq_le_phys_cached(MemoryRegionCache *cache, hwaddr addr);
uint64_t ldq_be_phys_cached(MemoryRegionCache *cache, hwaddr addr);
void stb_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val);
void stw_le_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val);
void stw_be_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val);
void stl_le_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val);
void stl_be_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint32_t val);
void stq_le_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint64_t val);
void stq_be_phys_cached(MemoryRegionCache *cache, hwaddr addr, uint64_t val);
/* address_space_get_iotlb_entry: translate an address into an IOTLB
 * entry. Should be called from an RCU critical section.
 */
IOMMUTLBEntry address_space_get_iotlb_entry(AddressSpace *as, hwaddr addr,
                                            bool is_write);

/* address_space_translate: translate an address range into an address space
 * into a MemoryRegion and an address range into that section
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @xlat: pointer to address within the returned memory region section's
 * #MemoryRegion.
 * @len: pointer to length
 * @is_write: indicates the transfer direction
 */
MemoryRegion *flatview_translate(FlatView *fv,
                                 hwaddr addr, hwaddr *xlat,
                                 hwaddr *len, bool is_write);

static inline MemoryRegion *address_space_translate(AddressSpace *as,
                                                    hwaddr addr, hwaddr *xlat,
                                                    hwaddr *len, bool is_write)
{
    return flatview_translate(address_space_to_flatview(as),
                              addr, xlat, len, is_write);
}

/* address_space_access_valid: check for validity of accessing an address
 * space range
 *
 * Check whether memory is assigned to the given address space range, and
 * access is permitted by any IOMMU regions that are active for the address
 * space.
 *
 * For now, addr and len should be aligned to a page size.  This limitation
 * will be lifted in the future.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @len: length of the area to be checked
 * @is_write: indicates the transfer direction
 */
bool address_space_access_valid(AddressSpace *as, hwaddr addr, int len, bool is_write);

/* address_space_map: map a physical memory region into a host virtual address
 *
 * May map a subset of the requested range, given by and returned in @plen.
 * May return %NULL if resources needed to perform the mapping are exhausted.
 * Use only for reads OR writes - not for read-modify-write operations.
 * Use cpu_register_map_client() to know when retrying the map operation is
 * likely to succeed.
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @plen: pointer to length of buffer; updated on return
 * @is_write: indicates the transfer direction
 */
void *address_space_map(AddressSpace *as, hwaddr addr,
                        hwaddr *plen, bool is_write);

/* address_space_unmap: Unmaps a memory region previously mapped by address_space_map()
 *
 * Will also mark the memory as dirty if @is_write == %true.  @access_len gives
 * the amount of memory that was actually read or written by the caller.
 *
 * @as: #AddressSpace used
 * @addr: address within that address space
 * @len: buffer length as returned by address_space_map()
 * @access_len: amount of data actually transferred
 * @is_write: indicates the transfer direction
 */
void address_space_unmap(AddressSpace *as, void *buffer, hwaddr len,
                         int is_write, hwaddr access_len);

void memory_register_types(struct uc_struct *uc);

MemoryRegion *memory_map(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms);
MemoryRegion *memory_map_ptr(struct uc_struct *uc, hwaddr begin, size_t size, uint32_t perms, void *ptr);
MemoryRegion *memory_map_io(struct uc_struct *uc, hwaddr begin, size_t size, void *opaque); // SNPS added
void memory_unmap(struct uc_struct *uc, MemoryRegion *mr);
int memory_free(struct uc_struct *uc);

/* Internal functions, part of the implementation of address_space_read.  */
MemTxResult flatview_read_continue(FlatView *fv, hwaddr addr,
                                   MemTxAttrs attrs, uint8_t *buf,
                                   int len, hwaddr addr1, hwaddr l,
                                   MemoryRegion *mr);

MemTxResult flatview_read_full(FlatView *fv, hwaddr addr,
                               MemTxAttrs attrs, uint8_t *buf, int len);
void *qemu_map_ram_ptr(struct uc_struct *uc, RAMBlock *ram_block,
                       ram_addr_t addr);

static inline bool memory_access_is_direct(MemoryRegion *mr, bool is_write)
{
    if (is_write) {
        return memory_region_is_ram(mr) && !mr->readonly &&
               !mr->rom_device && !memory_region_is_ram_device(mr);
    } else {
        return (memory_region_is_ram(mr) && !memory_region_is_ram_device(mr)) ||
               memory_region_is_romd(mr);
    }
}

/**
 * address_space_read: read from an address space.
 *
 * Return a MemTxResult indicating whether the operation succeeded
 * or failed (eg unassigned memory, device rejected the transaction,
 * IOMMU fault).
 *
 * @as: #AddressSpace to be accessed
 * @addr: address within that address space
 * @attrs: memory transaction attributes
 * @buf: buffer with the data transferred
 */
static inline
MemTxResult flatview_read(FlatView *fv, hwaddr addr, MemTxAttrs attrs,
                          uint8_t *buf, int len)
{
    MemTxResult result = MEMTX_OK;
    /* Unicorn: commented out
    hwaddr l, addr1;
    void *ptr;
    MemoryRegion *mr;

    if (__builtin_constant_p(len)) {
        if (len) {
            // Unicorn: commented out
            //rcu_read_lock();
            l = len;
            mr = flatview_translate(fv, addr, &addr1, &l, false);
            if (len == l && memory_access_is_direct(mr, false)) {
                ptr = qemu_map_ram_ptr(mr->uc, mr->ram_block, addr1);
                memcpy(buf, ptr, len);
            } else {
                result = flatview_read_continue(fv, addr, attrs, buf, len,
                                                addr1, l, mr);
            }
            // Unicorn: commented out
            //rcu_read_unlock();
        }
    } else {*/
        result = flatview_read_full(fv, addr, attrs, buf, len);
    //}
    return result;
}

static inline MemTxResult address_space_read(AddressSpace *as, hwaddr addr,
                                             MemTxAttrs attrs, uint8_t *buf,
                                             int len)
{
    return flatview_read(address_space_to_flatview(as), addr, attrs, buf, len);
}

/**
 * address_space_read_cached: read from a cached RAM region
 *
 * @cache: Cached region to be addressed
 * @addr: address relative to the base of the RAM region
 * @buf: buffer with the data transferred
 * @len: length of the data transferred
 */
static inline void
address_space_read_cached(MemoryRegionCache *cache, hwaddr addr,
                          void *buf, int len)
{
    assert(addr < cache->len && len <= cache->len - addr);
    address_space_read(cache->as, cache->xlat + addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

/**
 * address_space_write_cached: write to a cached RAM region
 *
 * @cache: Cached region to be addressed
 * @addr: address relative to the base of the RAM region
 * @buf: buffer with the data transferred
 * @len: length of the data transferred
 */
static inline void
address_space_write_cached(MemoryRegionCache *cache, hwaddr addr,
                           void *buf, int len)
{
    assert(addr < cache->len && len <= cache->len - addr);
    address_space_write(cache->as, cache->xlat + addr, MEMTXATTRS_UNSPECIFIED, buf, len);
}

void unicorn_free_empty_flat_view(struct uc_struct *uc);

/* enum device_endian to MemOp.  */
MemOp devend_memop(enum device_endian end);

#endif

#endif
