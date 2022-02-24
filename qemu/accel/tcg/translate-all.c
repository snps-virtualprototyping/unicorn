/*
 *  Host code generation
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
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <sys/mman.h>
#endif
#include "qemu/osdep.h"
#include "unicorn/platform.h"

#include "qemu-common.h"
#define NO_CPU_IO_DEFS
#include "cpu.h"
#include "exec/exec-all.h"
#include "tcg.h"
#if defined(CONFIG_USER_ONLY)
#include "qemu.h"
#include "exec/exec-all.h"
#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__)
#include <sys/param.h>
#if __FreeBSD_version >= 700104
#define HAVE_KINFO_GETVMMAP
#define sigqueue sigqueue_freebsd  /* avoid redefinition */
#include <sys/proc.h>
#include <machine/profile.h>
#define _KERNEL
#include <sys/user.h>
#undef _KERNEL
#undef sigqueue
#include <libutil.h>
#endif
#endif
#else
#include "exec/address-spaces.h"
#endif

#include "exec/cputlb.h"
#include "exec/tb-hash.h"
#include "translate-all.h"
#include "qemu/timer.h"

#include "uc_priv.h"

/* #define DEBUG_TB_INVALIDATE */
/* #define DEBUG_TB_FLUSH */
/* make various TB consistency checks */
/* #define DEBUG_TB_CHECK */

#ifdef DEBUG_TB_INVALIDATE
#define DEBUG_TB_INVALIDATE_GATE 1
#else
#define DEBUG_TB_INVALIDATE_GATE 0
#endif

#ifdef DEBUG_TB_FLUSH
#define DEBUG_TB_FLUSH_GATE 1
#else
#define DEBUG_TB_FLUSH_GATE 0
#endif

#if !defined(CONFIG_USER_ONLY)
/* TB consistency checks only implemented for usermode emulation.  */
#undef DEBUG_TB_CHECK
#endif

#ifdef DEBUG_TB_CHECK
#define DEBUG_TB_CHECK_GATE 1
#else
#define DEBUG_TB_CHECK_GATE 0
#endif

/* Access to the various translations structures need to be serialised via locks
 * for consistency. This is automatic for SoftMMU based system
 * emulation due to its single threaded nature. In user-mode emulation
 * access to the memory related structures are protected with the
 * mmap_lock.
 */
#ifdef CONFIG_SOFTMMU
#define assert_memory_lock() tcg_debug_assert(have_tb_lock)
#else
#define assert_memory_lock() tcg_debug_assert(have_mmap_lock())
#endif

#define SMC_BITMAP_USE_THRESHOLD 10

typedef struct PageDesc {
    /* list of TBs intersecting this ram page */
    TranslationBlock *first_tb;
#ifdef CONFIG_SOFTMMU
    /* in order to optimize self modifying code, we count the number
       of lookups we do to a given page to use a bitmap */
    unsigned int code_write_count;
    uint8_t *code_bitmap;
#else
    unsigned long flags;
#endif
} PageDesc;

/* In system mode we want L1_MAP to be based on ram offsets,
   while in user mode we want it to be based on virtual addresses.  */
#if !defined(CONFIG_USER_ONLY)
#if HOST_LONG_BITS < TARGET_PHYS_ADDR_SPACE_BITS
# define L1_MAP_ADDR_SPACE_BITS  HOST_LONG_BITS
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_PHYS_ADDR_SPACE_BITS
#endif
#else
# define L1_MAP_ADDR_SPACE_BITS  TARGET_VIRT_ADDR_SPACE_BITS
#endif

/* Size of the L2 (and L3, etc) page tables.  */
#define V_L2_BITS 10
#define V_L2_SIZE (1 << V_L2_BITS)

/* The bottom level has pointers to PageDesc, and is indexed by
 * anything from 4 to (V_L2_BITS + 3) bits, depending on target page size.
 */
#define V_L1_MIN_BITS 4
#define V_L1_MAX_BITS (V_L2_BITS + 3)
#define V_L1_MAX_SIZE (1 << V_L1_MAX_BITS)

static TranslationBlock *tb_find_pc(struct uc_struct *uc, uintptr_t tc_ptr);

// Unicorn: for cleaning up memory later.
void free_code_gen_buffer(struct uc_struct *uc);

static void page_table_config_init(struct uc_struct *uc)
{
    uint32_t v_l1_bits;

    assert(TARGET_PAGE_BITS);
    /* The bits remaining after N lower levels of page tables.  */
    v_l1_bits = (L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS) % V_L2_BITS;
    if (v_l1_bits < V_L1_MIN_BITS) {
        v_l1_bits += V_L2_BITS;
    }

    uc->v_l1_size = 1 << v_l1_bits;
    uc->v_l1_shift = L1_MAP_ADDR_SPACE_BITS - TARGET_PAGE_BITS - v_l1_bits;
    uc->v_l2_levels = uc->v_l1_shift / V_L2_BITS - 1;

    assert(v_l1_bits <= V_L1_MAX_BITS);
    assert(uc->v_l1_shift % V_L2_BITS == 0);
    assert(uc->v_l2_levels >= 0);
}


static void cpu_gen_init(struct uc_struct *uc)
{
    uc->tcg_ctx = g_malloc0(sizeof(TCGContext));
    tcg_context_init(uc->tcg_ctx);
}

static void tb_clean_internal(void **p, int x)
{
    if (x <= 1) {
        for (int i = 0; i < V_L2_SIZE; i++) {
            void **q = p[i];
            if (q) {
                g_free(q);
            }
        }
        g_free(p);
    } else {
        for (int i = 0; i < V_L2_SIZE; i++) {
            void **q = p[i];
            if (q) {
                tb_clean_internal(q, x - 1);
            }
        }
        g_free(p);
    }
}

void tb_cleanup(struct uc_struct *uc)
{
    if (!uc) {
        return;
    }

    if (!uc->l1_map) {
        return;
    }

    int x = uc->v_l1_shift / V_L2_BITS;
    if (x <= 1) {
        for (int i = 0; i < uc->v_l1_size; i++) {
            void **p = uc->l1_map[i];
            if (p) {
                g_free(p);
                uc->l1_map[i] = NULL;
            }
        }
    } else {
        for (int i = 0; i < uc->v_l1_size; i++) {
            void **p = uc->l1_map[i];
            if (p) {
                tb_clean_internal(p, x - 1);
                uc->l1_map[i] = NULL;
            }
        }
    }
}

/* Encode VAL as a signed leb128 sequence at P.
   Return P incremented past the encoded value.  */
static uint8_t *encode_sleb128(uint8_t *p, target_long val)
{
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0)
                 || (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

/* Decode a signed leb128 sequence at *PP; increment *PP past the
   decoded value.  Return the decoded value.  */
static target_long decode_sleb128(uint8_t **pp)
{
    uint8_t *p = *pp;
    target_long val = 0;
    int byte, shift = 0;

    do {
        byte = *p++;
        val |= (target_ulong)(byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < TARGET_LONG_BITS && (byte & 0x40)) {
        val |= -(target_ulong)1 << shift;
    }

    *pp = p;
    return val;
}

/* Encode the data collected about the instructions while compiling TB.
   Place the data at BLOCK, and return the number of bytes consumed.

   The logical table consists of TARGET_INSN_START_WORDS target_ulong's,
   which come from the target's insn_start data, followed by a uintptr_t
   which comes from the host pc of the end of the code implementing the insn.

   Each line of the table is encoded as sleb128 deltas from the previous
   line.  The seed for the first line is { tb->pc, 0..., tb->tc.ptr }.
   That is, the first column is seeded with the guest pc, the last column
   with the host pc, and the middle columns with zeros.  */

static int encode_search(TCGContext *tcg_ctx, TranslationBlock *tb, uint8_t *block)
{
    uint8_t *highwater = tcg_ctx->code_gen_highwater;
    uint8_t *p = block;
    int i, j, n;

    tb->tc.search = block;

    for (i = 0, n = tb->icount; i < n; ++i) {
        target_ulong prev;

        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            if (i == 0) {
                prev = (j == 0 ? tb->pc : 0);
            } else {
                prev = tcg_ctx->gen_insn_data[i - 1][j];
            }
            p = encode_sleb128(p, tcg_ctx->gen_insn_data[i][j] - prev);
        }
        prev = (i == 0 ? 0 : tcg_ctx->gen_insn_end_off[i - 1]);
        p = encode_sleb128(p, tcg_ctx->gen_insn_end_off[i] - prev);

        /* Test for (pending) buffer overflow.  The assumption is that any
           one row beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           encoding a row without having to check during encoding.  */
        if (unlikely(p > highwater)) {
            return -1;
        }
    }

    return p - block;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 * Called with tb_lock held.
 * When reset_icount is true, current TB will be interrupted and
 * icount should be recalculated.
 */
static int cpu_restore_state_from_tb(CPUState *cpu, TranslationBlock *tb,
                                     uintptr_t searched_pc, bool reset_icount)
{
    target_ulong data[TARGET_INSN_START_WORDS] = { tb->pc };
    uintptr_t host_pc = (uintptr_t)tb->tc.ptr;
    CPUArchState *env = cpu->env_ptr;
    uint8_t *p = tb->tc.search;
    int i, j, num_insns = tb->icount;
#ifdef CONFIG_PROFILER
    int64_t ti = profile_getclock();
#endif

    searched_pc -= GETPC_ADJ;

    if (searched_pc < host_pc) {
        return -1;
    }

    /* Reconstruct the stored insn data while looking for the point at
       which the end of the insn exceeds the searched_pc.  */
    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        host_pc += decode_sleb128(&p);
        if (host_pc > searched_pc) {
            goto found;
        }
    }
    return -1;

found:
    // UNICORN: If'd out
#if 0
    if (reset_icount && (tb_cflags(tb) & CF_USE_ICOUNT)) {
        assert(use_icount);
        /* Reset the cycle counter to the start of the block
           and shift if to the number of actually executed instructions */
        cpu_neg(cpu)->icount_decr.u16.low += num_insns - i;
    }
#endif
    restore_state_to_opc(env, tb, data);

#ifdef CONFIG_PROFILER
    s->restore_time += profile_getclock() - ti;
    s->restore_count++;
#endif
    return 0;
}

bool cpu_restore_state(CPUState *cpu, uintptr_t host_pc, bool will_exit)
{
    TranslationBlock *tb;
    CPUArchState *env = cpu->env_ptr;
    TCGContext* tcg_ctx = env->uc->tcg_ctx;
    bool r = false;
    uintptr_t check_offset;

    /* The host_pc has to be in the region of current code buffer. If
     * it is not we will not be able to resolve it here. The two cases
     * where host_pc will not be correct are:
     *
     *  - fault during translation (instruction fetch)
     *  - fault from helper (not using GETPC() macro)
     *
     * Either way we need return early to avoid blowing up on a
     * recursive tb_lock() as we can't resolve it here.
     *
     * We are using unsigned arithmetic so if host_pc <
     * tcg_init_ctx.code_gen_buffer check_offset will wrap to way
     * above the code_gen_buffer_size
     */
    check_offset = host_pc - (uintptr_t) tcg_ctx->code_gen_buffer;

    if (check_offset < tcg_ctx->code_gen_buffer_size) {
        tb = tb_find_pc(env->uc, host_pc);
        if (tb) {
            cpu_restore_state_from_tb(cpu, tb, host_pc, will_exit);
            if (tb_cflags(tb) & CF_NOCACHE) {
                /* one-shot translation, invalidate it immediately */
                tb_phys_invalidate(cpu->uc, tb, -1);
                tb_free(cpu->uc, tb);
            }
            r = true;
        }
    }

    return r;
}

static void page_init(struct uc_struct *uc)
{
    page_size_init(uc);
    page_table_config_init(uc);
#if defined(CONFIG_BSD) && defined(CONFIG_USER_ONLY)
    {
#ifdef HAVE_KINFO_GETVMMAP
        struct kinfo_vmentry *freep;
        int i, cnt;

        freep = kinfo_getvmmap(getpid(), &cnt);
        if (freep) {
            mmap_lock();
            for (i = 0; i < cnt; i++) {
                unsigned long startaddr, endaddr;

                startaddr = freep[i].kve_start;
                endaddr = freep[i].kve_end;
                if (h2g_valid(startaddr)) {
                    startaddr = h2g(startaddr) & TARGET_PAGE_MASK;

                    if (h2g_valid(endaddr)) {
                        endaddr = h2g(endaddr);
                        page_set_flags(startaddr, endaddr, PAGE_RESERVED);
                    } else {
#if TARGET_ABI_BITS <= L1_MAP_ADDR_SPACE_BITS
                        endaddr = ~0ul;
                        page_set_flags(startaddr, endaddr, PAGE_RESERVED);
#endif
                    }
                }
            }
            free(freep);
            mmap_unlock();
        }
#else
        FILE *f;

        last_brk = (unsigned long)sbrk(0);

        f = fopen("/compat/linux/proc/self/maps", "r");
        if (f) {
            mmap_lock();

            do {
                unsigned long startaddr, endaddr;
                int n;

                n = fscanf(f, "%lx-%lx %*[^\n]\n", &startaddr, &endaddr);

                if (n == 2 && h2g_valid(startaddr)) {
                    startaddr = h2g(startaddr) & TARGET_PAGE_MASK;

                    if (h2g_valid(endaddr)) {
                        endaddr = h2g(endaddr);
                    } else {
                        endaddr = ~0ul;
                    }
                    page_set_flags(startaddr, endaddr, PAGE_RESERVED);
                }
            } while (!feof(f));

            fclose(f);
            mmap_unlock();
        }
#endif
    }
#endif
}

/* If alloc=1:
 * Called with tb_lock held for system emulation.
 * Called with mmap_lock held for user-mode emulation.
 */
static PageDesc *page_find_alloc(struct uc_struct *uc, tb_page_addr_t index, int alloc)
{
    PageDesc *pd;
    void **lp;
    int i;

    if (uc->l1_map == NULL) {
        uc->l1_map_size = uc->v_l1_size * sizeof(uc->l1_map);
        uc->l1_map = g_new0(void*, uc->l1_map_size);
    }

    /* Level 1.  Always allocated.  */
    lp = uc->l1_map + ((index >> uc->v_l1_shift) & (uc->v_l1_size - 1));

    /* Level 2..N-1.  */
    for (i = uc->v_l2_levels; i > 0; i--) {
        void **p = qatomic_read(lp);

        if (p == NULL) {
            if (!alloc) {
                return NULL;
            }
            p = g_new0(void *, V_L2_SIZE);
            qatomic_set(lp, p);
        }

        lp = p + ((index >> (i * V_L2_BITS)) & (V_L2_SIZE - 1));
    }

    pd = qatomic_read(lp);
    if (pd == NULL) {
        if (!alloc) {
            return NULL;
        }
        pd = g_new0(PageDesc, V_L2_SIZE);
        qatomic_set(lp, pd);
    }

    return pd + (index & (V_L2_SIZE - 1));
}

static inline PageDesc *page_find(struct uc_struct *uc, tb_page_addr_t index)
{
    return page_find_alloc(uc, index, 0);
}

#if defined(CONFIG_USER_ONLY)
/* Currently it is not recommended to allocate big chunks of data in
   user mode. It will change when a dedicated libc will be used.  */
/* ??? 64-bit hosts ought to have no problem mmaping data outside the
   region in which the guest needs to run.  Revisit this.  */
#define USE_STATIC_CODE_GEN_BUFFER
#endif

/* Minimum size of the code gen buffer.  This number is randomly chosen,
   but not so small that we can't have a fair number of TB's live.  */
#define MIN_CODE_GEN_BUFFER_SIZE     (1024u * 1024)

/* Maximum size of the code gen buffer we'd like to use.  Unless otherwise
   indicated, this is constrained by the range of direct branches on the
   host cpu, as used by the TCG implementation of goto_tb.  */
#if defined(__x86_64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2ul * 1024 * 1024 * 1024)
#elif defined(__sparc__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2ul * 1024 * 1024 * 1024)
#elif defined(__powerpc64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2ul * 1024 * 1024 * 1024)
#elif defined(__aarch64__)
# define MAX_CODE_GEN_BUFFER_SIZE  (2ul * 1024 * 1024 * 1024)
#elif defined(__s390x__)
  /* We have a +- 4GB range on the branches; leave some slop.  */
# define MAX_CODE_GEN_BUFFER_SIZE  (3ul * 1024 * 1024 * 1024)
#elif defined(__mips__)
  /* We have a 256MB branch region, but leave room to make sure the
     main executable is also within that region.  */
# define MAX_CODE_GEN_BUFFER_SIZE  (128ul * 1024 * 1024)
#else
# define MAX_CODE_GEN_BUFFER_SIZE  ((size_t)-1)
#endif

#define DEFAULT_CODE_GEN_BUFFER_SIZE_1 (8 * 1024 * 1024)

#define DEFAULT_CODE_GEN_BUFFER_SIZE \
  (DEFAULT_CODE_GEN_BUFFER_SIZE_1 < MAX_CODE_GEN_BUFFER_SIZE \
   ? DEFAULT_CODE_GEN_BUFFER_SIZE_1 : MAX_CODE_GEN_BUFFER_SIZE)

static inline size_t size_code_gen_buffer(size_t tb_size)
{
    /* Size the buffer.  */
    if (tb_size == 0) {
#ifdef USE_STATIC_CODE_GEN_BUFFER
        tb_size = DEFAULT_CODE_GEN_BUFFER_SIZE;
#else
        /* ??? Needs adjustments.  */
        /* ??? If we relax the requirement that CONFIG_USER_ONLY use the
           static buffer, we could size this on RESERVED_VA, on the text
           segment size of the executable, or continue to use the default.  */
        tb_size = (unsigned long)DEFAULT_CODE_GEN_BUFFER_SIZE;
#endif
    }
    if (tb_size < MIN_CODE_GEN_BUFFER_SIZE) {
        tb_size = MIN_CODE_GEN_BUFFER_SIZE;
    }
    if (tb_size > MAX_CODE_GEN_BUFFER_SIZE) {
        tb_size = MAX_CODE_GEN_BUFFER_SIZE;
    }
    return tb_size;
}

#ifdef __mips__
/* In order to use J and JAL within the code_gen_buffer, we require
   that the buffer not cross a 256MB boundary.  */
static inline bool cross_256mb(void *addr, size_t size)
{
    return ((uintptr_t)addr ^ ((uintptr_t)addr + size)) & ~0x0ffffffful;
}

/* We weren't able to allocate a buffer without crossing that boundary,
   so make do with the larger portion of the buffer that doesn't cross.
   Returns the new base of the buffer, and adjusts code_gen_buffer_size.  */
static inline void *split_cross_256mb(struct uc_struct *uc, void *buf1, size_t size1)
{
    void *buf2 = (void *)(((uintptr_t)buf1 + size1) & ~0x0ffffffful);
    size_t size2 = buf1 + size1 - buf2;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    size1 = buf2 - buf1;
    if (size1 < size2) {
        size1 = size2;
        buf1 = buf2;
    }

    tcg_ctx->code_gen_buffer_size = size1;
    return buf1;
}
#endif

#ifdef USE_STATIC_CODE_GEN_BUFFER
static uint8_t QEMU_ALIGNED(CODE_GEN_ALIGN, static_code_gen_buffer[DEFAULT_CODE_GEN_BUFFER_SIZE]);

void free_code_gen_buffer(struct uc_struct *uc)
{
    // Do nothing, we use a static buffer.
}

# ifdef _WIN32
static inline void do_protect(struct uc_struct *uc, void *addr, long size, int prot)
{
    DWORD old_protect;
    VirtualProtect(addr, size, prot, &old_protect);
}

static inline void map_exec(struct uc_struct *uc, void *addr, long size)
{
    do_protect(uc, addr, size, PAGE_EXECUTE_READWRITE);
}

static inline void map_none(struct uc_struct *uc, void *addr, long size)
{
    do_protect(uc, addr, size, PAGE_NOACCESS);
}
# else
static inline void do_protect(struct uc_struct *uc, void *addr, long size, int prot)
{
    uintptr_t start, end;

    start = (uintptr_t)addr;
    start &= uc->qemu_real_host_page_mask;

    end = (uintptr_t)addr + size;
    end = ROUND_UP(end, uc->qemu_real_host_page_size);

    mprotect((void *)start, end - start, prot);
}

static inline void map_exec(struct uc_struct *uc, void *addr, long size)
{
    do_protect(uc, addr, size, PROT_READ | PROT_WRITE | PROT_EXEC);
}

static inline void map_none(struct uc_struct *uc, void *addr, long size)
{
    do_protect(uc, addr, size, PROT_NONE);
}
# endif /* WIN32 */

static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    void *buf = static_code_gen_buffer;
    size_t full_size, size;

    /* The size of the buffer, rounded down to end on a page boundary.  */
    full_size = (((uintptr_t)buf + sizeof(static_code_gen_buffer))
                 & uc->qemu_real_host_page_mask) - (uintptr_t)buf;

    /* Reserve a guard page.  */
    size = full_size - uc->qemu_real_host_page_size;

    /* Honor a command-line option limiting the size of the buffer.  */
    if (size > tcg_ctx->code_gen_buffer_size) {
        size = (((uintptr_t)buf + tcg_ctx->code_gen_buffer_size)
                & uc->qemu_real_host_page_mask) - (uintptr_t)buf;
    }
    tcg_ctx->code_gen_buffer_size = size;

#ifdef __mips__
    if (cross_256mb(buf, size)) {
        buf = split_cross_256mb(buf, size);
        size = tcg_ctx->code_gen_buffer_size;
    }
#endif
    map_exec(uc, buf, size);
    map_none(uc, buf + size, uc->qemu_real_host_page_size);
    // Unicorn: commented out
    //qemu_madvise(buf, size, QEMU_MADV_HUGEPAGE);

    return buf;
}
#elif defined(_WIN32)
static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    size_t size = tcg_ctx->code_gen_buffer_size;
    void *buf1, *buf2;

    /* Perform the allocation in two steps, so that the guard page
       is reserved but uncommitted.  */
    buf1 = VirtualAlloc(NULL, size + uc->qemu_real_host_page_size,
                        MEM_RESERVE, PAGE_NOACCESS);
    if (buf1 != NULL) {
        buf2 = VirtualAlloc(buf1, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        assert(buf1 == buf2);
    }

    return buf1;
}

void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    void *prologue = tcg_ctx->code_gen_prologue;

    if (!prologue) {
        return;
    }

    // Unicorn: Free the prologue rather than the buffer directly, as the prologue
    //          has the starting address of the same memory block that the code
    //          buffer is within. As the prologue is generated at the beginning of
    //          the memory block, the code buffer itself has the size of the prologue
    //          decremented from it. If the buffer was freed, then the address would
    //          be off by whatever size the prologue data is.
    //
    //          See tcg_prologue_init in tcg.c for more info.
    //
    VirtualFree(prologue, 0, MEM_RELEASE);
}
#else
static inline void *alloc_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    size_t size = tcg_ctx->code_gen_buffer_size;
    void *buf;

    buf = mmap(NULL, size + uc->qemu_real_host_page_size, PROT_NONE, flags, -1, 0);
    if (buf == MAP_FAILED) {
        return NULL;
    }

#ifdef __mips__
    if (cross_256mb(buf, size)) {
        /*
         * Try again, with the original still mapped, to avoid re-acquiring
         * the same 256mb crossing.
         */
        size_t size2;
        void *buf2 = mmap(NULL, size + uc->qemu_real_host_page_size,
                          PROT_NONE, flags, -1, 0);
        switch ((int)(buf2 != MAP_FAILED)) {
        case 1:
            if (!cross_256mb(buf2, size)) {
                /* Success!  Use the new buffer.  */
                munmap(buf, size + uc->qemu_real_host_page_size);
                break;
            }
            /* Failure.  Work with what we had.  */
            munmap(buf2, size + uc->qemu_real_host_page_size);
            /* fallthru */
        default:
            /* Split the original buffer.  Free the smaller half.  */
            buf2 = split_cross_256mb(buf, size);
            size2 = tcg_ctx->code_gen_buffer_size;
            if (buf == buf2) {
                munmap(buf + size2 + uc->qemu_real_host_page_size, size - size2);
            } else {
                munmap(buf, size - size2);
            }
            size = size2;
            break;
        }

        buf = buf2;
    }
#endif

    /* Make the final buffer accessible.  The guard page at the end
       will remain inaccessible with PROT_NONE.  */
    mprotect(buf, size, PROT_WRITE | PROT_READ | PROT_EXEC);

    /* Request large pages for the buffer.  */
    // Unicorn: Commented out
    //qemu_madvise(buf, size, QEMU_MADV_HUGEPAGE);

    return buf;
}

void free_code_gen_buffer(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    void *prologue = tcg_ctx->code_gen_prologue;

    if (!prologue) {
        return;
    }

    // Unicorn: Free the prologue rather than the buffer directly, as the prologue
    //          has the starting address of the same memory block that the code
    //          buffer is within. As the prologue is generated at the beginning of
    //          the memory block, the code buffer itself has the size of the prologue
    //          decremented from it. If the buffer was freed, then the address would
    //          be off by whatever size the prologue data is.
    //
    //          See tcg_prologue_init in tcg.c for more info.
    //
    munmap(prologue, tcg_ctx->code_gen_buffer_size);
}
#endif /* USE_STATIC_CODE_GEN_BUFFER, USE_MMAP */

static inline void code_gen_alloc(struct uc_struct *uc, size_t tb_size)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;

    tcg_ctx->code_gen_buffer_size = size_code_gen_buffer(tb_size);
    tcg_ctx->code_gen_buffer = alloc_code_gen_buffer(uc);
    if (tcg_ctx->code_gen_buffer == NULL) {
        fprintf(stderr, "Could not allocate dynamic translator buffer\n");
        exit(1);
    }

    // Unicorn: Commented out
    //qemu_madvise(tcg_ctx->code_gen_buffer, tcg_ctx->code_gen_buffer_size,
    //             QEMU_MADV_HUGEPAGE);

    /* Estimate a good size for the number of TBs we can support.  We
       still haven't deducted the prologue from the buffer size here,
       but that's minimal and won't affect the estimate much.  */
    /* size this conservatively -- realloc later if needed */
    tcg_ctx->tb_ctx.tbs_size =
        tcg_ctx->code_gen_buffer_size / CODE_GEN_AVG_BLOCK_SIZE / 8;
    if (unlikely(!tcg_ctx->tb_ctx.tbs_size)) {
        tcg_ctx->tb_ctx.tbs_size = 64 * 1024;
    }
    tcg_ctx->tb_ctx.tbs = g_new(TranslationBlock *, tcg_ctx->tb_ctx.tbs_size);
}

/* Must be called before using the QEMU cpus. 'tb_size' is the size
   (in bytes) allocated to the translation buffer. Zero means default
   size. */
void tcg_exec_init(struct uc_struct *uc, unsigned long tb_size)
{
    TCGContext *tcg_ctx;

    cpu_gen_init(uc);
    tcg_ctx = uc->tcg_ctx;
    tcg_ctx->uc = uc;
    page_init(uc);
    code_gen_alloc(uc, tb_size);
#if !defined(CONFIG_USER_ONLY) || !defined(CONFIG_USE_GUEST_BASE)
    /* There's no guest base to take into account, so go ahead and
       initialize the prologue now.  */
    tcg_prologue_init(tcg_ctx);
#endif
}

bool tcg_enabled(struct uc_struct *uc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    return tcg_ctx->code_gen_buffer != NULL;
}

/*
 * Allocate a new translation block. Flush the translation buffer if
 * too many translation blocks or too much generated code.
 *
 * Called with tb_lock held.
 */
static TranslationBlock *tb_alloc(struct uc_struct *uc, target_ulong pc)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    TranslationBlock *tb;
    TBContext *ctx;

    tb = tcg_tb_alloc(tcg_ctx);
    if (unlikely(tb == NULL)) {
        return NULL;
    }
    ctx = &tcg_ctx->tb_ctx;
    if (unlikely(ctx->nb_tbs == ctx->tbs_size)) {
        ctx->tbs_size *= 2;
        ctx->tbs = g_renew(TranslationBlock *, ctx->tbs, ctx->tbs_size);
    }
    ctx->tbs[ctx->nb_tbs++] = tb;
    return tb;
}

/* Called with tb_lock held.  */
void tb_free(struct uc_struct *uc, TranslationBlock *tb)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;

    /* In practice this is mostly used for single use temporary TB
       Ignore the hard cases and just back up if this TB happens to
       be the last one generated.  */
    if (tcg_ctx->tb_ctx.nb_tbs > 0 &&
            tb == tcg_ctx->tb_ctx.tbs[tcg_ctx->tb_ctx.nb_tbs - 1]) {
        size_t struct_size = ROUND_UP(sizeof(*tb), uc->qemu_icache_linesize);

        tcg_ctx->code_gen_ptr = tb->tc.ptr - struct_size;
        tcg_ctx->tb_ctx.nb_tbs--;
    }
}

static inline void invalidate_page_bitmap(PageDesc *p)
{
#ifdef CONFIG_SOFTMMU
    g_free(p->code_bitmap);
    p->code_bitmap = NULL;
    p->code_write_count = 0;
#endif
}

/* Set to NULL all the 'first_tb' fields in all PageDescs. */
static void page_flush_tb_1(int level, void **lp)
{
    int i;

    if (*lp == NULL) {
        return;
    }
    if (level == 0) {
        PageDesc *pd = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            pd[i].first_tb = NULL;
            invalidate_page_bitmap(pd + i);
        }
    } else {
        void **pp = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            page_flush_tb_1(level - 1, pp + i);
        }
    }
}

static void page_flush_tb(struct uc_struct *uc)
{
    int i, l1_sz = uc->v_l1_size;

    if (uc->l1_map == NULL) {
        return;
    }

    for (i = 0; i < l1_sz; i++) {
        page_flush_tb_1(uc->v_l2_levels, uc->l1_map + i);
    }
}

/* flush all the translation blocks */
/* XXX: tb_flush is currently not thread safe */
void tb_flush(CPUState *cpu)
{
    struct uc_struct* uc = cpu->uc;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    if (DEBUG_TB_FLUSH_GATE) {
        printf("qemu: flush code_size=%td nb_tbs=%d avg_tb_size=%td\n",
               tcg_ctx->code_gen_ptr - tcg_ctx->code_gen_buffer,
               tcg_ctx->tb_ctx.nb_tbs, tcg_ctx->tb_ctx.nb_tbs > 0 ?
               (tcg_ctx->code_gen_ptr - tcg_ctx->code_gen_buffer) /
               tcg_ctx->tb_ctx.nb_tbs : 0);
    }
    if ((unsigned long)((char*)tcg_ctx->code_gen_ptr - (char*)tcg_ctx->code_gen_buffer)
        > tcg_ctx->code_gen_buffer_size) {
        cpu_abort(cpu, "Internal error: code buffer overflow\n");
    }

    cpu_tb_jmp_cache_clear(cpu);
    qatomic_mb_set(&cpu->tb_flushed, true);

    tcg_ctx->tb_ctx.nb_tbs = 0;
    memset(tcg_ctx->tb_ctx.tb_phys_hash, 0, sizeof(tcg_ctx->tb_ctx.tb_phys_hash));
    page_flush_tb(uc);

    tcg_ctx->code_gen_ptr = tcg_ctx->code_gen_buffer;
    /* XXX: flush processor icache at this point if cache flush is
       expensive */
    tcg_ctx->tb_ctx.tb_flush_count++;
}

/*
 * Formerly ifdef DEBUG_TB_CHECK. These debug functions are user-mode-only,
 * so in order to prevent bit rot we compile them unconditionally in user-mode,
 * and let the optimizer get rid of them by wrapping their user-only callers
 * with if (DEBUG_TB_CHECK_GATE).
 */
#ifdef CONFIG_USER_ONLY

/* verify that all the pages have correct rights for code
 *
 * Called with tb_lock held.
 */
static void tb_invalidate_check(target_ulong address)
{
    TranslationBlock *tb;
    int i;

    address &= TARGET_PAGE_MASK;
    for (i = 0; i < CODE_GEN_PHYS_HASH_SIZE; i++) {
        for (tb = tcg_ctx->tb_ctx.tb_phys_hash[i]; tb != NULL;
             tb = tb->phys_hash_next) {
            if (!(address + TARGET_PAGE_SIZE <= tb->pc ||
                  address >= tb->pc + tb->size)) {
                printf("ERROR invalidate: address=" TARGET_FMT_lx
                       " PC=%08lx size=%04x\n",
                       address, (long)tb->pc, tb->size);
            }
        }
    }
}

/* verify that all the pages have correct rights for code */
static void tb_page_check(struct uc_struct *uc)
{
    TranslationBlock *tb;
    int i, flags1, flags2;
    TCGContext *tcg_ctx = uc->tcg_ctx;

    for (i = 0; i < CODE_GEN_PHYS_HASH_SIZE; i++) {
        for (tb = tcg_ctx->tb_ctx.tb_phys_hash[i]; tb != NULL;
                tb = tb->phys_hash_next) {
            flags1 = page_get_flags(tb->pc);
            flags2 = page_get_flags(tb->pc + tb->size - 1);
            if ((flags1 & PAGE_WRITE) || (flags2 & PAGE_WRITE)) {
                printf("ERROR page flags: PC=%08lx size=%04x f1=%x f2=%x\n",
                       (long)tb->pc, tb->size, flags1, flags2);
            }
        }
    }
}

#endif /* CONFIG_USER_ONLY */

static inline void tb_hash_remove(TranslationBlock **ptb, TranslationBlock *tb)
{
    TranslationBlock *tb1;

    for (;;) {
        tb1 = *ptb;
        if (tb1 == tb) {
            *ptb = tb1->phys_hash_next;
            break;
        }
        ptb = &tb1->phys_hash_next;
    }
}

static inline void tb_page_remove(TranslationBlock **ptb, TranslationBlock *tb)
{
    TranslationBlock *tb1;
    unsigned int n1;

    for (;;) {
        tb1 = *ptb;
        n1 = (uintptr_t)tb1 & 3;
        tb1 = (TranslationBlock *)((uintptr_t)tb1 & ~3);
        if (tb1 == tb) {
            *ptb = tb1->page_next[n1];
            break;
        }
        ptb = &tb1->page_next[n1];
    }
}

/* remove the TB from a list of TBs jumping to the n-th jump target of the TB */
static inline void tb_remove_from_jmp_list(TranslationBlock *tb, int n)
{
    TranslationBlock *tb1;
    uintptr_t *ptb, ntb;
    unsigned int n1;

    ptb = &tb->jmp_list_next[n];
    if (*ptb) {
        /* find tb(n) in circular list */
        for (;;) {
            ntb = *ptb;
            n1 = ntb & 3;
            tb1 = (TranslationBlock *)(ntb & ~3);
            if (n1 == n && tb1 == tb) {
                break;
            }
            if (n1 == 2) {
                ptb = &tb1->jmp_list_first;
            } else {
                ptb = &tb1->jmp_list_next[n1];
            }
        }
        /* now we can suppress tb(n) from the list */
        *ptb = tb->jmp_list_next[n];

        tb->jmp_list_next[n] = (uintptr_t)NULL;
    }
}

/* reset the jump entry 'n' of a TB so that it is not chained to
   another TB */
static inline void tb_reset_jump(TranslationBlock *tb, int n)
{
    uintptr_t addr = (uintptr_t)(tb->tc.ptr + tb->jmp_reset_offset[n]);
    tb_set_jmp_target(tb, n, addr);
}

/* remove any jumps to the TB */
static inline void tb_jmp_unlink(TranslationBlock *tb)
{
    TranslationBlock *tb1;
    uintptr_t *ptb, ntb;
    unsigned int n1;

    ptb = &tb->jmp_list_first;
    for (;;) {
        ntb = *ptb;
        n1 = ntb & 3;
        tb1 = (TranslationBlock *)(ntb & ~3);
        if (n1 == 2) {
            break;
        }
        tb_reset_jump(tb1, n1);
        *ptb = tb1->jmp_list_next[n1];
        tb1->jmp_list_next[n1] = (uintptr_t)NULL;
    }
}

/* invalidate one TB
 *
 * Called with tb_lock held.
 */
void tb_phys_invalidate(struct uc_struct *uc,
    TranslationBlock *tb, tb_page_addr_t page_addr)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    CPUState *cpu = uc->cpu;
    PageDesc *p;
    uint32_t h;
    tb_page_addr_t phys_pc;

    qatomic_set(&tb->cflags, tb->cflags | CF_INVALID);

    /* remove the TB from the hash list */
    phys_pc = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
    h = tb_hash_func(phys_pc, tb->pc, tb->flags, tb->cflags & CF_HASH_MASK);
    tb_hash_remove(&tcg_ctx->tb_ctx.tb_phys_hash[h], tb);

    /* remove the TB from the page list */
    if (tb->page_addr[0] != page_addr) {
        p = page_find(uc, tb->page_addr[0] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }
    if (tb->page_addr[1] != -1 && tb->page_addr[1] != page_addr) {
        p = page_find(uc, tb->page_addr[1] >> TARGET_PAGE_BITS);
        tb_page_remove(&p->first_tb, tb);
        invalidate_page_bitmap(p);
    }

    /* remove the TB from the hash list */
    h = tb_jmp_cache_hash_func(tb->pc);
    if (qatomic_read(&cpu->tb_jmp_cache[h]) == tb) {
        qatomic_set(&cpu->tb_jmp_cache[h], NULL);
    }

    /* suppress this TB from the two jump lists */
    tb_remove_from_jmp_list(tb, 0);
    tb_remove_from_jmp_list(tb, 1);

    /* suppress any remaining jumps to this TB */
    tb_jmp_unlink(tb);

    tcg_ctx->tb_ctx.tb_phys_invalidate_count++;
}

static inline void set_bits(uint8_t *tab, int start, int len)
{
    int end, mask, end1;

    end = start + len;
    tab += start >> 3;
    mask = 0xff << (start & 7);
    if ((start & ~7) == (end & ~7)) {
        if (start < end) {
            mask &= ~(0xff << (end & 7));
            *tab |= mask;
        }
    } else {
        *tab++ |= mask;
        start = (start + 8) & ~7;
        end1 = end & ~7;
        while (start < end1) {
            *tab++ = 0xff;
            start += 8;
        }
        if (start < end) {
            mask = ~(0xff << (end & 7));
            *tab |= mask;
        }
    }
}

#ifdef CONFIG_SOFTMMU
static void build_page_bitmap(PageDesc *p)
{
    int n, tb_start, tb_end;
    TranslationBlock *tb;

    p->code_bitmap = g_malloc0(TARGET_PAGE_SIZE / 8);

    tb = p->first_tb;
    while (tb != NULL) {
        n = (uintptr_t)tb & 3;
        tb = (TranslationBlock *)((uintptr_t)tb & ~3);
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->pc & ~TARGET_PAGE_MASK;
            tb_end = tb_start + tb->size;
            if (tb_end > TARGET_PAGE_SIZE) {
                tb_end = TARGET_PAGE_SIZE;
            }
        } else {
            tb_start = 0;
            tb_end = ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        set_bits(p->code_bitmap, tb_start, tb_end - tb_start);
        tb = tb->page_next[n];
    }
}
#endif

/* add the tb in the target page and protect it if necessary */
static inline void tb_alloc_page(struct uc_struct *uc, TranslationBlock *tb,
                                 unsigned int n, tb_page_addr_t page_addr)
{
    PageDesc *p;
#ifndef CONFIG_USER_ONLY
    bool page_already_protected;
#endif

    tb->page_addr[n] = page_addr;
    p = page_find_alloc(uc, page_addr >> TARGET_PAGE_BITS, 1);
    tb->page_next[n] = p->first_tb;
#ifndef CONFIG_USER_ONLY
    page_already_protected = p->first_tb != NULL;
#endif
    p->first_tb = (TranslationBlock *)((uintptr_t)tb | n);
    invalidate_page_bitmap(p);

#if defined(CONFIG_USER_ONLY)
    if (p->flags & PAGE_WRITE) {
        target_ulong addr;
        PageDesc *p2;
        int prot;

        /* force the host page as non writable (writes will have a
           page fault + mprotect overhead) */
        page_addr &= uc->qemu_host_page_mask;
        prot = 0;
        for (addr = page_addr; addr < page_addr + uc->qemu_host_page_size;
            addr += TARGET_PAGE_SIZE) {

            p2 = page_find(addr >> TARGET_PAGE_BITS);
            if (!p2) {
                continue;
            }
            prot |= p2->flags;
            p2->flags &= ~PAGE_WRITE;
          }
        mprotect(g2h(page_addr), uc->qemu_host_page_size,
                 (prot & PAGE_BITS) & ~PAGE_WRITE);
        if (DEBUG_TB_INVALIDATE_GATE) {
            printf("protecting code page: 0x" TB_PAGE_ADDR_FMT "\n", page_addr);
        }
    }
#endif
}

/* add a new TB and link it to the physical page tables. phys_page2 is
 *  (-1) to indicate that only one page contains the TB.
 *
 * Called with mmap_lock held for user-mode emulation.
 */
static void tb_link_page(struct uc_struct *uc,
    TranslationBlock *tb, tb_page_addr_t phys_pc, tb_page_addr_t phys_page2)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    uint32_t h;
    TranslationBlock **ptb;

    /* add in the page list */
    tb_alloc_page(uc, tb, 0, phys_pc & TARGET_PAGE_MASK);
    if (phys_page2 != -1) {
        tb_alloc_page(uc, tb, 1, phys_page2);
    } else {
        tb->page_addr[1] = -1;
    }

    /* add in the hash table */
    h = tb_hash_func(phys_pc, tb->pc, tb->flags, tb->cflags & CF_HASH_MASK);
    ptb = &tcg_ctx->tb_ctx.tb_phys_hash[h];
    tb->phys_hash_next = *ptb;
    *ptb = tb;

#ifdef CONFIG_USER_ONLY
    if (DEBUG_TB_CHECK_GATE) {
        tb_page_check();
    }
#endif
}

TranslationBlock *tb_gen_code(CPUState *cpu,
                              target_ulong pc, target_ulong cs_base,
                              uint32_t flags, int cflags)
{
    CPUArchState *env = cpu->env_ptr;
    TCGContext *tcg_ctx = env->uc->tcg_ctx;
    TranslationBlock *tb;
    tb_page_addr_t phys_pc, phys_page2;
    tcg_insn_unit *gen_code_buf;
    int gen_code_size, search_size, max_insns;
#ifdef CONFIG_PROFILER
    int64_t ti;
#endif

    phys_pc = get_page_addr_code(env, pc);

    /* Instruction counting */
    max_insns = cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }
    if (max_insns > TCG_MAX_INSNS) {
        max_insns = TCG_MAX_INSNS;
    }
    // Unicorn: commented out
    if (cpu->singlestep_enabled /*|| singlestep*/) {
        max_insns = 1;
    }

    tb = tb_alloc(env->uc, pc);
    if (unlikely(!tb)) {
 buffer_overflow:
        /* flush must be done */
        tb_flush(cpu);
        /* cannot fail at this point */
        tb = tb_alloc(env->uc, pc);
        assert(tb != NULL);
    }
    gen_code_buf = tcg_ctx->code_gen_ptr;
    tb->tc.ptr = gen_code_buf;
    tb->pc = pc;
    tb->cs_base = cs_base;
    tb->flags = flags;
    tb->cflags = cflags;
    tcg_ctx->tb_cflags = cflags;
    assert(cflags & CF_PARALLEL); // SNPS added
 tb_overflow:

#ifdef CONFIG_PROFILER
    tcg_ctx->tb_count1++; /* includes aborted translations because of
                       exceptions */
    ti = profile_getclock();
#endif

    gen_code_size = sigsetjmp(tcg_ctx->jmp_trans, 0);
    if (unlikely(gen_code_size != 0)) {
        goto error_return;
    }

    tcg_func_start(tcg_ctx);

    tcg_ctx->cpu = env_cpu(env);
    gen_intermediate_code(cpu, tb, max_insns);
    tcg_ctx->cpu = NULL;
    max_insns = tb->icount;

    // Unicorn: FIXME: Needs to be amended to work with new TCG
#if 0
    // Unicorn: when tracing block, patch block size operand for callback
    if (env->uc->size_arg != -1 && HOOK_EXISTS_BOUNDED(env->uc, UC_HOOK_BLOCK, tb->pc)) {
        if (env->uc->block_full)    // block size is unknown
            *(tcg_ctx->gen_opparam_buf + env->uc->size_arg) = 0;
        else
            *(tcg_ctx->gen_opparam_buf + env->uc->size_arg) = tb->size;
    }
#endif

    // UNICORN: Commented out
    //trace_translate_block(tb, tb->pc, tb->tc.ptr);

    /* generate machine code */
    tb->jmp_reset_offset[0] = TB_JMP_RESET_OFFSET_INVALID;
    tb->jmp_reset_offset[1] = TB_JMP_RESET_OFFSET_INVALID;
    tcg_ctx->tb_jmp_reset_offset = tb->jmp_reset_offset;

    if (TCG_TARGET_HAS_direct_jump) {
        tcg_ctx->tb_jmp_insn_offset = tb->jmp_target_arg;
        tcg_ctx->tb_jmp_target_addr = NULL;
    } else {
        tcg_ctx->tb_jmp_insn_offset = NULL;
        tcg_ctx->tb_jmp_target_addr = tb->jmp_target_arg;
    }

#ifdef CONFIG_PROFILER
    tcg_ctx->tb_count++;
    tcg_ctx->interm_time += profile_getclock() - ti;
    tcg_ctx->code_time -= profile_getclock();
#endif

    gen_code_size = tcg_gen_code(tcg_ctx, tb);
    if (unlikely(gen_code_size < 0)) {
 error_return:
        switch (gen_code_size) {
        case -1:
            /*
             * Overflow of code_gen_buffer, or the current slice of it.
             *
             * TODO: We don't need to re-do gen_intermediate_code, nor
             * should we re-do the tcg optimization currently hidden
             * inside tcg_gen_code.  All that should be required is to
             * flush the TBs, allocate a new TB, re-initialize it per
             * above, and re-do the actual code generation.
             */
            qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                          "Restarting code generation for "
                          "code_gen_buffer overflow\n");
            goto buffer_overflow;

        case -2:
            /*
             * The code generated for the TranslationBlock is too large.
             * The maximum size allowed by the unwind info is 64k.
             * There may be stricter constraints from relocations
             * in the tcg backend.
             *
             * Try again with half as many insns as we attempted this time.
             * If a single insn overflows, there's a bug somewhere...
             */
            assert(max_insns > 1);
            max_insns /= 2;
            qemu_log_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT,
                          "Restarting code generation with "
                          "smaller translation block (max %d insns)\n",
                          max_insns);
            goto tb_overflow;

        default:
            g_assert_not_reached();
        }
    }
    search_size = encode_search(tcg_ctx, tb, (unsigned char *)gen_code_buf + gen_code_size);
    if (unlikely(search_size < 0)) {
        goto buffer_overflow;
    }

#ifdef CONFIG_PROFILER
    tcg_ctx.code_time += profile_getclock();
    tcg_ctx.code_in_len += tb->size;
    tcg_ctx.code_out_len += gen_code_size;
    tcg_ctx.search_out_len += search_size;
#endif

/* UNICORN: Commented out
#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_OUT_ASM) &&
        qemu_log_in_addr_range(tb->pc)) {
        qemu_log("OUT: [size=%d]\n", gen_code_size);
        if (tcg_ctx->data_gen_ptr) {
            size_t code_size = tcg_ctx->data_gen_ptr - tb->tc.ptr;
            size_t data_size = gen_code_size - code_size;
            size_t i;

            log_disas(tb->tc.ptr, code_size);

            for (i = 0; i < data_size; i += sizeof(tcg_target_ulong)) {
                if (sizeof(tcg_target_ulong) == 8) {
                    qemu_log("0x%08" PRIxPTR ":  .quad  0x%016" PRIx64 "\n",
                             (uintptr_t)tcg_ctx->data_gen_ptr + i,
                             *(uint64_t *)(tcg_ctx->data_gen_ptr + i));
                } else {
                    qemu_log("0x%08" PRIxPTR ":  .long  0x%08x\n",
                             (uintptr_t)tcg_ctx->data_gen_ptr + i,
                             *(uint32_t *)(tcg_ctx->data_gen_ptr + i));
                }
            }
        } else {
            log_disas(tb->tc.ptr, gen_code_size);
        }
        qemu_log("\n");
        qemu_log_flush();
    }
#endif*/

    tcg_ctx->code_gen_ptr = (void *)
        ROUND_UP((uintptr_t)gen_code_buf + gen_code_size + search_size,
                 CODE_GEN_ALIGN);

    /* init jump list */
    assert(((uintptr_t)tb & 3) == 0);
    tb->jmp_list_first = (uintptr_t)tb | 2;
    tb->jmp_list_next[0] = (uintptr_t)NULL;
    tb->jmp_list_next[1] = (uintptr_t)NULL;

    /* init original jump addresses wich has been set during tcg_gen_code() */
    if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 0);
    }
    if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
        tb_reset_jump(tb, 1);
    }

    phys_page2 = -1;
    /* check next page if needed */
    if (tb->size) {
        target_ulong virt_page2 = (pc + tb->size - 1) & TARGET_PAGE_MASK;
        if ((pc & TARGET_PAGE_MASK) != virt_page2) {
            phys_page2 = get_page_addr_code(env, virt_page2);
        }
    }
    /* As long as consistency of the TB stuff is provided by tb_lock in user
     * mode and is implicit in single-threaded softmmu emulation, no explicit
     * memory barrier is required before tb_link_page() makes the TB visible
     * through the physical hash table and physical page list.
     */
    tb_link_page(cpu->uc, tb, phys_pc, phys_page2);
    return tb;
}

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end may refer to *different* physical pages.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 *
 * Called with mmap_lock held for user-mode emulation, grabs tb_lock
 * Called with tb_lock held for system-mode emulation
 */
static void tb_invalidate_phys_range_1(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end)
{
    while (start < end) {
        tb_invalidate_phys_page_range(uc, start, end, 0);
        start &= TARGET_PAGE_MASK;
        start += TARGET_PAGE_SIZE;
    }
}

#ifdef CONFIG_SOFTMMU
void tb_invalidate_phys_range(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end)
{
    // Unicorn: commented out
    //assert_tb_lock();
    tb_invalidate_phys_range_1(uc, start, end);
}
#else
void tb_invalidate_phys_range(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end)
{
    // Unicorn: commented out
    //assert_memory_lock();
    //tb_lock();
    tb_invalidate_phys_range_1(uc, start, end);
    //tb_unlock();
}
#endif

/*
 * Invalidate all TBs which intersect with the target physical address range
 * [start;end[. NOTE: start and end must refer to the *same* physical page.
 * 'is_cpu_write_access' should be true if called from a real cpu write
 * access: the virtual CPU will exit the current TB if code is modified inside
 * this TB.
 *
 * Called with tb_lock/mmap_lock held for user-mode emulation
 * Called with tb_lock held for system-mode emulation
 */
void tb_invalidate_phys_page_range(struct uc_struct *uc, tb_page_addr_t start, tb_page_addr_t end,
                                   int is_cpu_write_access)
{
    TranslationBlock *tb, *tb_next;
    tb_page_addr_t tb_start, tb_end;
    PageDesc *p;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    CPUArchState *env = NULL;
    int current_tb_not_found = is_cpu_write_access;
    TranslationBlock *current_tb = NULL;
    int current_tb_modified = 0;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    uint32_t current_flags = 0;
#endif /* TARGET_HAS_PRECISE_SMC */

    // Unicorn: commented out
    //assert_memory_lock();
    //assert_tb_lock();

    p = page_find(uc, start >> TARGET_PAGE_BITS);
    if (!p) {
        return;
    }
#if defined(TARGET_HAS_PRECISE_SMC)
    if (uc->cpu != NULL) {
        env = uc->cpu->env_ptr;
    }
#endif

    /* we remove all the TBs in the range [start, end[ */
    /* XXX: see if in some cases it could be faster to invalidate all
       the code */
    tb = p->first_tb;
    while (tb != NULL) {
        n = (uintptr_t)tb & 3;
        tb = (TranslationBlock *)((uintptr_t)tb & ~3);
        tb_next = tb->page_next[n];
        /* NOTE: this is subtle as a TB may span two physical pages */
        if (n == 0) {
            /* NOTE: tb_end may be after the end of the page, but
               it is not a problem */
            tb_start = tb->page_addr[0] + (tb->pc & ~TARGET_PAGE_MASK);
            tb_end = tb_start + tb->size;
        } else {
            tb_start = tb->page_addr[1];
            tb_end = tb_start + ((tb->pc + tb->size) & ~TARGET_PAGE_MASK);
        }
        if (!(tb_end <= start || tb_start >= end)) {
#ifdef TARGET_HAS_PRECISE_SMC
            if (current_tb_not_found) {
                current_tb_not_found = 0;
                current_tb = NULL;
                if (uc->cpu->mem_io_pc) {
                    /* now we have a real cpu fault */
                    current_tb = tb_find_pc(uc, uc->cpu->mem_io_pc);
                }
            }
            if (current_tb == tb &&
                (tb_cflags(current_tb) & CF_COUNT_MASK) != 1) {
                /* If we are modifying the current TB, we must stop
                its execution. We could be more precise by checking
                that the modification is after the current PC, but it
                would require a specialized function to partially
                restore the CPU state */

                current_tb_modified = 1;
                // self-modifying code will restore state from TB
                cpu_restore_state_from_tb(uc->cpu, current_tb,
                                          uc->cpu->mem_io_pc, true);
                cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
                                     &current_flags);
            }
#endif /* TARGET_HAS_PRECISE_SMC */
            tb_phys_invalidate(uc, tb, -1);
        }
        tb = tb_next;
    }
#if !defined(CONFIG_USER_ONLY)
    /* if no code remaining, no need to continue to use slow writes */
    if (!p->first_tb) {
        invalidate_page_bitmap(p);
    }
#endif
#ifdef TARGET_HAS_PRECISE_SMC
    if (current_tb_modified) {
        /* Force execution of one insn next time.  */
        uc->cpu->cflags_next_tb = 1 | curr_cflags(uc);
        cpu_loop_exit_noexc(uc->cpu);
    }
#endif
}

#ifdef CONFIG_SOFTMMU
/* len must be <= 8 and start must be a multiple of len.
 * Called via softmmu_template.h when code areas are written to with
 * tb_lock held.
 */
void tb_invalidate_phys_page_fast(struct uc_struct* uc, tb_page_addr_t start, int len)
{
    PageDesc *p;

#if 0
    if (1) {
        qemu_log("modifying code at 0x%x size=%d EIP=%x PC=%08x\n",
                  cpu_single_env->mem_io_vaddr, len,
                  cpu_single_env->eip,
                  cpu_single_env->eip +
                  (intptr_t)cpu_single_env->segs[R_CS].base);
    }
#endif
    p = page_find(uc, start >> TARGET_PAGE_BITS);
    if (!p) {
        return;
    }
    if (!p->code_bitmap &&
        ++p->code_write_count >= SMC_BITMAP_USE_THRESHOLD) {
        /* build code bitmap.  FIXME: writes should be protected by
         * tb_lock, reads by tb_lock or RCU.
         */
        build_page_bitmap(p);
    }
    if (p->code_bitmap) {
        unsigned int nr;
        unsigned long b;

        nr = start & ~TARGET_PAGE_MASK;
        b = p->code_bitmap[BIT_WORD(nr)] >> ((nr & (BITS_PER_LONG - 1)) & 0x1f);
        if (b & ((1 << len) - 1)) {
            goto do_invalidate;
        }
    } else {
    do_invalidate:
        tb_invalidate_phys_page_range(uc, start, start + len, 1);
    }
}
#else
/* Called with mmap_lock held. If pc is not 0 then it indicates the
 * host PC of the faulting store instruction that caused this invalidate.
 * Returns true if the caller needs to abort execution of the current
 * TB (because it was modified by this store and the guest CPU has
 * precise-SMC semantics).
 */
static bool tb_invalidate_phys_page(struct uc_struct *uc, tb_page_addr_t addr, uintptr_t pc)
{
    TranslationBlock *tb;
    PageDesc *p;
    int n;
#ifdef TARGET_HAS_PRECISE_SMC
    TranslationBlock *current_tb = NULL;
    CPUState *cpu = uc->current_cpu;
    CPUArchState *env = NULL;
    int current_tb_modified = 0;
    target_ulong current_pc = 0;
    target_ulong current_cs_base = 0;
    uint32_t current_flags = 0;
#endif

    addr &= TARGET_PAGE_MASK;
    p = page_find(addr >> TARGET_PAGE_BITS);
    if (!p) {
        return false;
    }
    tb = p->first_tb;
#ifdef TARGET_HAS_PRECISE_SMC
    if (tb && pc != 0) {
        current_tb = tb_find_pc(uc, pc);
    }
    if (cpu != NULL) {
        env = cpu->env_ptr;
    }
#endif
    while (tb != NULL) {
        n = (uintptr_t)tb & 3;
        tb = (TranslationBlock *)((uintptr_t)tb & ~3);
#ifdef TARGET_HAS_PRECISE_SMC
        if (current_tb == tb &&
            (tb_cflags(current_tb) & CF_COUNT_MASK) != 1) {
                /* If we are modifying the current TB, we must stop
                   its execution. We could be more precise by checking
                   that the modification is after the current PC, but it
                   would require a specialized function to partially
                   restore the CPU state */

            current_tb_modified = 1;
            cpu_restore_state_from_tb(cpu, current_tb, pc, true);
            cpu_get_tb_cpu_state(env, &current_pc, &current_cs_base,
                                 &current_flags);
        }
#endif /* TARGET_HAS_PRECISE_SMC */
        tb_phys_invalidate(uc, tb, addr);
        tb = tb->page_next[n];
    }
    p->first_tb = NULL;
#ifdef TARGET_HAS_PRECISE_SMC
    if (current_tb_modified) {
        /* Force execution of one insn next time.  */
        cpu->cflags_next_tb = 1 | curr_cflags(uc);
        return true;
    }
#endif
    return false;
}
#endif

/* find the TB 'tb' such that tb[0].tc.ptr <= tc_ptr <
   tb[1].tc.ptr. Return NULL if not found */
static TranslationBlock *tb_find_pc(struct uc_struct *uc, uintptr_t tc_ptr)
{
    TCGContext *tcg_ctx = uc->tcg_ctx;
    int m_min, m_max, m;
    uintptr_t v;
    TranslationBlock *tb;

    if (tcg_ctx->tb_ctx.nb_tbs <= 0) {
        return NULL;
    }
    if (tc_ptr < (uintptr_t)tcg_ctx->code_gen_buffer ||
        tc_ptr >= (uintptr_t)tcg_ctx->code_gen_ptr) {
        return NULL;
    }
    /* binary search (cf Knuth) */
    m_min = 0;
    m_max = tcg_ctx->tb_ctx.nb_tbs - 1;
    while (m_min <= m_max) {
        m = (m_min + m_max) >> 1;
        tb = tcg_ctx->tb_ctx.tbs[m];
        v = (uintptr_t)tb->tc.ptr;
        if (v == tc_ptr) {
            return tb;
        } else if (tc_ptr < v) {
            m_max = m - 1;
        } else {
            m_min = m + 1;
        }
    }
    return tcg_ctx->tb_ctx.tbs[m_max];
}

#if !defined(CONFIG_USER_ONLY)
void tb_invalidate_phys_addr(AddressSpace *as, hwaddr addr)
{
    ram_addr_t ram_addr;
    MemoryRegion *mr;
    hwaddr l = 1;

    mr = address_space_translate(as, addr, &addr, &l, false);
    if (!(memory_region_is_ram(mr)
          || memory_region_is_romd(mr))) {
        return;
    }
    ram_addr = memory_region_get_ram_addr(mr) + addr;
    tb_invalidate_phys_page_range(as->uc, ram_addr, ram_addr + 1, 0);
}
#endif /* !defined(CONFIG_USER_ONLY) */

/* Called with tb_lock held.  */
void tb_check_watchpoint(CPUState *cpu)
{
    TranslationBlock *tb;
    CPUArchState *env = cpu->env_ptr;

    tb = tb_find_pc(env->uc, cpu->mem_io_pc);
    if (tb) {
        /* We can use retranslation to find the PC.  */
        cpu_restore_state_from_tb(cpu, tb, cpu->mem_io_pc, true);
        tb_phys_invalidate(cpu->uc, tb, -1);
    } else {
        /* The exception probably happened in a helper.  The CPU state should
           have been saved before calling it. Fetch the PC from there.  */
        target_ulong pc, cs_base;
        tb_page_addr_t addr;
        uint32_t flags;

        cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        addr = get_page_addr_code(env, pc);
        tb_invalidate_phys_range(cpu->uc, addr, addr + 1);
    }

    cpu_restore_state_from_tb(cpu, tb, cpu->mem_io_pc, true);
    tb_phys_invalidate(cpu->uc, tb, -1);
}

#ifndef CONFIG_USER_ONLY
/* in deterministic execution mode, instructions doing device I/Os
   must be at the end of the TB */
void cpu_io_recompile(CPUState *cpu, uintptr_t retaddr)
{
    CPUArchState *env = cpu->env_ptr;
    TranslationBlock *tb;
    uint32_t n;

    tb = tb_find_pc(env->uc, retaddr);
    if (!tb) {
        cpu_abort(cpu, "cpu_io_recompile: could not find TB for pc=%p",
                  (void *)retaddr);
    }
    n = cpu_neg(cpu)->icount_decr.u16.low + tb->icount;
    cpu_restore_state_from_tb(cpu, tb, retaddr, true);
    /* Calculate how many instructions had been executed before the fault
       occurred.  */
    n = n - cpu_neg(cpu)->icount_decr.u16.low;
    /* Generate a new TB ending on the I/O insn.  */
    n++;
    /* On MIPS and SH, delay slot instructions can only be restarted if
       they were already the first instruction in the TB.  If this is not
       the first instruction in a TB then re-execute the preceding
       branch.  */
#if defined(TARGET_MIPS)
    if ((env->hflags & MIPS_HFLAG_BMASK) != 0 && n > 1) {
        env->active_tc.PC -= (env->hflags & MIPS_HFLAG_B16 ? 2 : 4);
        cpu_neg(cpu)->icount_decr.u16.low++;
        env->hflags &= ~MIPS_HFLAG_BMASK;
    }
#elif defined(TARGET_SH4)
    if ((env->flags & ((DELAY_SLOT | DELAY_SLOT_CONDITIONAL))) != 0
            && n > 1) {
        env->pc -= 2;
        cpu_neg(cpu)->icount_decr.u16.low++;
        env->flags &= ~(DELAY_SLOT | DELAY_SLOT_CONDITIONAL);
    }
#endif
    /* This should never happen.  */
    if (n > CF_COUNT_MASK) {
        cpu_abort(cpu, "TB too big during recompile");
    }

    /* Adjust the execution state of the next TB.  */
    cpu->cflags_next_tb = curr_cflags(cpu->uc) | CF_LAST_IO | n;

    if (tb_cflags(tb) & CF_NOCACHE) {
        if (tb->orig_tb) {
            /* Invalidate original TB if this TB was generated in
             * cpu_exec_nocache() */
            tb_phys_invalidate(cpu->uc, tb->orig_tb, -1);
        }
        tb_free(env->uc, tb);
    }

    /* TODO: If env->pc != tb->pc (i.e. the faulting instruction was not
       the first in the TB) then we end up generating a whole new TB and
       repeating the fault, which is horribly inefficient.
       Better would be to execute just this insn uncached, or generate a
       second new TB.  */
    cpu_loop_exit_noexc(cpu);
}

static void tb_jmp_cache_clear_page(CPUState *cpu, target_ulong page_addr)
{
    unsigned int i, i0 = tb_jmp_cache_hash_page(page_addr);

    for (i = 0; i < TB_JMP_PAGE_SIZE; i++) {
        qatomic_set(&cpu->tb_jmp_cache[i0 + i], NULL);
    }
}


void tb_flush_jmp_cache(CPUState *cpu, target_ulong addr)
{
    /* Discard jump cache entries for any tb which might potentially
       overlap the flushed page.  */
    tb_jmp_cache_clear_page(cpu, addr - TARGET_PAGE_SIZE);
    tb_jmp_cache_clear_page(cpu, addr);
}

#if 0
void dump_exec_info(FILE *f, fprintf_function cpu_fprintf)
{
    int i, target_code_size, max_target_code_size;
    int direct_jmp_count, direct_jmp2_count, cross_page;
    TranslationBlock *tb;

    target_code_size = 0;
    max_target_code_size = 0;
    cross_page = 0;
    direct_jmp_count = 0;
    direct_jmp2_count = 0;
    for (i = 0; i < tcg_ctx.tb_ctx.nb_tbs; i++) {
        tb = &tcg_ctx.tb_ctx.tbs[i];
        target_code_size += tb->size;
        if (tb->size > max_target_code_size) {
            max_target_code_size = tb->size;
        }
        if (tb->page_addr[1] != -1) {
            cross_page++;
        }
        if (tb->jmp_reset_offset[0] != TB_JMP_RESET_OFFSET_INVALID) {
            direct_jmp_count++;
            if (tb->jmp_reset_offset[1] != TB_JMP_RESET_OFFSET_INVALID) {
                direct_jmp2_count++;
            }
        }
    }
    /* XXX: avoid using doubles ? */
    cpu_fprintf(f, "Translation buffer state:\n");
    cpu_fprintf(f, "gen code size       %td/%zd\n",
                tcg_ctx->code_gen_ptr - tcg_ctx->code_gen_buffer,
                tcg_ctx->code_gen_highwater - tcg_ctx->code_gen_buffer);
    cpu_fprintf(f, "TB count            %d\n", tcg_ctx.tb_ctx.nb_tbs);
    cpu_fprintf(f, "TB avg target size  %d max=%d bytes\n",
            tcg_ctx.tb_ctx.nb_tbs ? target_code_size /
                    tcg_ctx.tb_ctx.nb_tbs : 0,
            max_target_code_size);
    cpu_fprintf(f, "TB avg host size    %td bytes (expansion ratio: %0.1f)\n",
            tcg_ctx.tb_ctx.nb_tbs ? (tcg_ctx.code_gen_ptr -
                                     tcg_ctx.code_gen_buffer) /
                                     tcg_ctx.tb_ctx.nb_tbs : 0,
                target_code_size ? (double) (tcg_ctx.code_gen_ptr -
                                             tcg_ctx.code_gen_buffer) /
                                             target_code_size : 0);
    cpu_fprintf(f, "cross page TB count %d (%d%%)\n", cross_page,
            tcg_ctx.tb_ctx.nb_tbs ? (cross_page * 100) /
                                    tcg_ctx.tb_ctx.nb_tbs : 0);
    cpu_fprintf(f, "direct jump count   %d (%d%%) (2 jumps=%d %d%%)\n",
                direct_jmp_count,
                tcg_ctx.tb_ctx.nb_tbs ? (direct_jmp_count * 100) /
                        tcg_ctx.tb_ctx.nb_tbs : 0,
                direct_jmp2_count,
                tcg_ctx.tb_ctx.nb_tbs ? (direct_jmp2_count * 100) /
                        tcg_ctx.tb_ctx.nb_tbs : 0);
    cpu_fprintf(f, "\nStatistics:\n");
    cpu_fprintf(f, "TB flush count      %d\n", tcg_ctx.tb_ctx.tb_flush_count);
    cpu_fprintf(f, "TB invalidate count %d\n",
            tcg_ctx.tb_ctx.tb_phys_invalidate_count);
    //cpu_fprintf(f, "TLB flush count     %d\n", tlb_flush_count);
    tcg_dump_info(f, cpu_fprintf);
}
#endif

#else /* CONFIG_USER_ONLY */

void cpu_interrupt(CPUState *cpu, int mask)
{
    cpu->interrupt_request |= mask;
    cpu->tcg_exit_req = 1;
    qatomic_set(&cpu_neg(cpu)->icount_decr.u16.high, -1);
}

#if 0
/*
 * Walks guest process memory "regions" one by one
 * and calls callback function 'fn' for each region.
 */
struct walk_memory_regions_data {
    walk_memory_regions_fn fn;
    void *priv;
    target_ulong start;
    int prot;
};

static int walk_memory_regions_end(struct walk_memory_regions_data *data,
                                   target_ulong end, int new_prot)
{
    if (data->start != -1u) {
        int rc = data->fn(data->priv, data->start, end, data->prot);
        if (rc != 0) {
            return rc;
        }
    }

    data->start = (new_prot ? end : -1u);
    data->prot = new_prot;

    return 0;
}

static int walk_memory_regions_1(struct walk_memory_regions_data *data,
                                 target_ulong base, int level, void **lp)
{
    target_ulong pa;
    int i, rc;

    if (*lp == NULL) {
        return walk_memory_regions_end(data, base, 0);
    }

    if (level == 0) {
        PageDesc *pd = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            int prot = pd[i].flags;

            pa = base | (i << TARGET_PAGE_BITS);
            if (prot != data->prot) {
                rc = walk_memory_regions_end(data, pa, prot);
                if (rc != 0) {
                    return rc;
                }
            }
        }
    } else {
        void **pp = *lp;

        for (i = 0; i < V_L2_SIZE; ++i) {
            pa = base | ((target_ulong)i <<
                (TARGET_PAGE_BITS + V_L2_BITS * level));
            rc = walk_memory_regions_1(data, pa, level - 1, pp + i);
            if (rc != 0) {
                return rc;
            }
        }
    }

    return 0;
}

typedef int (*walk_memory_regions_fn)(void *, target_ulong,
        target_ulong, unsigned long);

static int walk_memory_regions(void *priv, walk_memory_regions_fn fn)
{
    struct walk_memory_regions_data data;
    uintptr_t i, l1_sz = v_l1_size;

    data.fn = fn;
    data.priv = priv;
    data.start = -1u;
    data.prot = 0;

    for (i = 0; i < l1_sz; i++) {
        target_ulong base = i << (v_l1_shift + TARGET_PAGE_BITS);
        int rc = walk_memory_regions_1(&data, base, v_l2_levels, l1_map + i);
        if (rc != 0) {
            return rc;
        }
    }

    return walk_memory_regions_end(&data, 0, 0);
}

static int dump_region(void *priv, target_ulong start,
    target_ulong end, unsigned long prot)
{
    FILE *f = (FILE *)priv;

    (void) fprintf(f, TARGET_FMT_lx"-"TARGET_FMT_lx
        " "TARGET_FMT_lx" %c%c%c\n",
        start, end, end - start,
        ((prot & PAGE_READ) ? 'r' : '-'),
        ((prot & PAGE_WRITE) ? 'w' : '-'),
        ((prot & PAGE_EXEC) ? 'x' : '-'));

    return 0;
}

/* dump memory mappings */
void page_dump(FILE *f)
{
    const int length = sizeof(target_ulong) * 2;
    (void) fprintf(f, "%-*s %-*s %-*s %s\n",
            length, "start", length, "end", length, "size", "prot");
    walk_memory_regions(f, dump_region);
}

#endif

int page_get_flags(target_ulong address)
{
    PageDesc *p;

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p) {
        return 0;
    }
    return p->flags;
}

/* Modify the flags of a page and invalidate the code if necessary.
   The flag PAGE_WRITE_ORG is positioned automatically depending
   on PAGE_WRITE.  The mmap_lock should already be held.  */
static void page_set_flags(struct uc_struct *uc, target_ulong start, target_ulong end, int flags)
{
    target_ulong addr, len;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(end <= ((target_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif
    assert(start < end);

    start = start & TARGET_PAGE_MASK;
    end = TARGET_PAGE_ALIGN(end);

    if (flags & PAGE_WRITE) {
        flags |= PAGE_WRITE_ORG;
    }

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
        PageDesc *p = page_find_alloc(uc, addr >> TARGET_PAGE_BITS, 1);

        /* If the write protection bit is set, then we invalidate
           the code inside.  */
        if (!(p->flags & PAGE_WRITE) &&
            (flags & PAGE_WRITE) &&
            p->first_tb) {
            tb_invalidate_phys_page(uc, addr, 0);
        }
        p->flags = flags;
    }
}

static int page_check_range(target_ulong start, target_ulong len, int flags)
{
    PageDesc *p;
    target_ulong end;
    target_ulong addr;

    /* This function should never be called with addresses outside the
       guest address space.  If this assert fires, it probably indicates
       a missing call to h2g_valid.  */
#if TARGET_ABI_BITS > L1_MAP_ADDR_SPACE_BITS
    assert(start < ((target_ulong)1 << L1_MAP_ADDR_SPACE_BITS));
#endif

    if (len == 0) {
        return 0;
    }
    if (start + len - 1 < start) {
        /* We've wrapped around.  */
        return -1;
    }

    /* must do before we loose bits in the next step */
    end = TARGET_PAGE_ALIGN(start + len);
    start = start & TARGET_PAGE_MASK;

    for (addr = start, len = end - start;
         len != 0;
         len -= TARGET_PAGE_SIZE, addr += TARGET_PAGE_SIZE) {
        p = page_find(addr >> TARGET_PAGE_BITS);
        if (!p) {
            return -1;
        }
        if (!(p->flags & PAGE_VALID)) {
            return -1;
        }

        if ((flags & PAGE_READ) && !(p->flags & PAGE_READ)) {
            return -1;
        }
        if (flags & PAGE_WRITE) {
            if (!(p->flags & PAGE_WRITE_ORG)) {
                return -1;
            }
            /* unprotect the page if it was put read-only because it
               contains translated code */
            if (!(p->flags & PAGE_WRITE)) {
                if (!page_unprotect(addr, 0)) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

/* called from signal handler: invalidate the code and unprotect the
 * page. Return 0 if the fault was not handled, 1 if it was handled,
 * and 2 if it was handled but the caller must cause the TB to be
 * immediately exited. (We can only return 2 if the 'pc' argument is
 * non-zero.)
 */
int page_unprotect(struct uc_struct *uc, target_ulong address, uintptr_t pc)
{
    unsigned int prot;
    bool current_tb_invalidated;
    PageDesc *p;
    target_ulong host_start, host_end, addr;

    /* Technically this isn't safe inside a signal handler.  However we
       know this only ever happens in a synchronous SEGV handler, so in
       practice it seems to be ok.  */
    mmap_lock();

    p = page_find(address >> TARGET_PAGE_BITS);
    if (!p) {
        mmap_unlock();
        return 0;
    }

    /* if the page was really writable, then we change its
       protection back to writable */
    if ((p->flags & PAGE_WRITE_ORG) && !(p->flags & PAGE_WRITE)) {
        host_start = address & uc->qemu_host_page_mask;
        host_end = host_start + uc->qemu_host_page_size;

        prot = 0;
        current_tb_invalidated = false;
        for (addr = host_start ; addr < host_end ; addr += TARGET_PAGE_SIZE) {
            p = page_find(addr >> TARGET_PAGE_BITS);
            p->flags |= PAGE_WRITE;
            prot |= p->flags;

            /* and since the content will be modified, we must invalidate
               the corresponding translated code. */
            current_tb_invalidated |= tb_invalidate_phys_page(uc, addr, pc);
#ifdef CONFIG_USER_ONLY
            if (DEBUG_TB_CHECK_GATE) {
                tb_invalidate_check(addr);
            }
#endif
        }
        mprotect((void *)g2h(host_start), uc->qemu_host_page_size,
                 prot & PAGE_BITS);

        mmap_unlock();
        /* If current TB was invalidated return to main loop */
        return current_tb_invalidated ? 2 : 1;
    }
    mmap_unlock();
    return 0;
}
#endif /* CONFIG_USER_ONLY */

/* This is a wrapper for common code that can not use CONFIG_SOFTMMU */
void tcg_flush_softmmu_tlb(CPUState *cs)
{
#ifdef CONFIG_SOFTMMU
    tlb_flush(cs);
#endif
}
