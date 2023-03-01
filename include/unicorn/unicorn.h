/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2017 */
/* This file is released under LGPL2.
   See COPYING.LGPL2 in root directory for more details
*/

#ifndef UNICORN_ENGINE_H
#define UNICORN_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"
#include <stdarg.h>

#if defined(UNICORN_HAS_OSXKERNEL)
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#include <stdio.h>
#endif

struct uc_struct;
typedef struct uc_struct uc_engine;

typedef size_t uc_hook;

#include "m68k.h"
#include "x86.h"
#include "arm.h"
#include "arm64.h"
#include "mips.h"
#include "riscv.h"
#include "sparc.h"

#ifdef __GNUC__
#define DEFAULT_VISIBILITY __attribute__((visibility("default")))
#else
#define DEFAULT_VISIBILITY
#endif

#ifdef _MSC_VER
#pragma warning(disable:4201)
#pragma warning(disable:4100)
#ifdef UNICORN_SHARED
#define UNICORN_EXPORT __declspec(dllexport)
#else    // defined(UNICORN_STATIC)
#define UNICORN_EXPORT
#endif
#else
#ifdef __GNUC__
#define UNICORN_EXPORT __attribute__((visibility("default")))
#else
#define UNICORN_EXPORT
#endif
#endif

#ifdef __GNUC__
#define UNICORN_DEPRECATED __attribute__((deprecated))
#elif defined(_MSC_VER)
#define UNICORN_DEPRECATED __declspec(deprecated)
#else
#pragma message("WARNING: You need to implement UNICORN_DEPRECATED for this compiler")
#define UNICORN_DEPRECATED
#endif

// Unicorn API version
#define UC_API_MAJOR 1
#define UC_API_MINOR 0

// Unicorn package version
#define UC_VERSION_MAJOR UC_API_MAJOR
#define UC_VERSION_MINOR UC_API_MINOR
#define UC_VERSION_EXTRA 2


/*
  Macro to create combined version which can be compared to
  result of uc_version() API.
*/
#define UC_MAKE_VERSION(major, minor) ((major << 8) + minor)

// Scales to calculate timeout on microsecond unit
// 1 second = 1000,000 microseconds
#define UC_SECOND_SCALE 1000000
// 1 milisecond = 1000 nanoseconds
#define UC_MILISECOND_SCALE 1000

// Architecture type
typedef enum uc_arch {
    UC_ARCH_ARM = 1,    // ARM architecture (including Thumb, Thumb-2)
    UC_ARCH_ARM64,      // ARM-64, also called AArch64
    UC_ARCH_MIPS,       // Mips architecture
    UC_ARCH_X86,        // X86 architecture (including x86 & x86-64)
    UC_ARCH_PPC,        // PowerPC architecture (currently unsupported)
    UC_ARCH_SPARC,      // Sparc architecture
    UC_ARCH_M68K,       // M68K architecture
    UC_ARCH_RISCV,      // RISC-V architecture
    UC_ARCH_MAX,
} uc_arch;

// Mode type
typedef enum uc_mode {
    UC_MODE_LITTLE_ENDIAN = 0,    // little-endian mode (default mode)
    UC_MODE_BIG_ENDIAN = 1 << 30, // big-endian mode

    // arm / arm64
    UC_MODE_ARM = 0,              // ARM mode
    UC_MODE_THUMB = 1 << 4,       // THUMB mode (including Thumb-2)
    UC_MODE_MCLASS = 1 << 5,      // ARM's Cortex-M series (currently unsupported)
    UC_MODE_V8 = 1 << 6,          // ARMv8 A32 encodings for ARM (currently unsupported)

    // arm (32bit) cpu types
    UC_MODE_ARM926 = 1 << 7,    // ARM926 CPU type
    UC_MODE_ARM946 = 1 << 8,    // ARM946 CPU type
    UC_MODE_ARM1176 = 1 << 9,   // ARM1176 CPU type

    // mips
    UC_MODE_MICRO = 1 << 4,       // MicroMips mode (currently unsupported)
    UC_MODE_MIPS3 = 1 << 5,       // Mips III ISA (currently unsupported)
    UC_MODE_MIPS32R6 = 1 << 6,    // Mips32r6 ISA (currently unsupported)
    UC_MODE_MIPS32 = 1 << 2,      // Mips32 ISA
    UC_MODE_MIPS64 = 1 << 3,      // Mips64 ISA

    // x86 / x64
    UC_MODE_16 = 1 << 1,          // 16-bit mode
    UC_MODE_32 = 1 << 2,          // 32-bit mode
    UC_MODE_64 = 1 << 3,          // 64-bit mode

    // ppc
    UC_MODE_PPC32 = 1 << 2,       // 32-bit mode (currently unsupported)
    UC_MODE_PPC64 = 1 << 3,       // 64-bit mode (currently unsupported)
    UC_MODE_QPX = 1 << 4,         // Quad Processing eXtensions mode (currently unsupported)

    // sparc
    UC_MODE_SPARC32 = 1 << 2,     // 32-bit mode
    UC_MODE_SPARC64 = 1 << 3,     // 64-bit mode
    UC_MODE_V9 = 1 << 4,          // SparcV9 mode (currently unsupported)

    // m68k
    // No flags for M68K yet

    // RISC-V
    UC_MODE_RISCV32 = 1 << 2,     // 32-bit mode
    UC_MODE_RISCV64 = 1 << 3,     // 64-bit mode
} uc_mode;

// All type of errors encountered by Unicorn API.
// These are values returned by uc_errno()
typedef enum uc_err {
    UC_ERR_OK = 0,   // No error: everything was fine
    UC_ERR_NOMEM,      // Out-Of-Memory error: uc_open(), uc_emulate()
    UC_ERR_ARCH,     // Unsupported architecture: uc_open()
    UC_ERR_HANDLE,   // Invalid handle
    UC_ERR_MODE,     // Invalid/unsupported mode: uc_open()
    UC_ERR_VERSION,  // Unsupported version (bindings)
    UC_ERR_READ_UNMAPPED, // Quit emulation due to READ on unmapped memory: uc_emu_start()
    UC_ERR_WRITE_UNMAPPED, // Quit emulation due to WRITE on unmapped memory: uc_emu_start()
    UC_ERR_FETCH_UNMAPPED, // Quit emulation due to FETCH on unmapped memory: uc_emu_start()
    UC_ERR_HOOK,    // Invalid hook type: uc_hook_add()
    UC_ERR_INSN_INVALID, // Quit emulation due to invalid instruction: uc_emu_start()
    UC_ERR_MAP, // Invalid memory mapping: uc_mem_map()
    UC_ERR_WRITE_PROT, // Quit emulation due to UC_MEM_WRITE_PROT violation: uc_emu_start()
    UC_ERR_READ_PROT, // Quit emulation due to UC_MEM_READ_PROT violation: uc_emu_start()
    UC_ERR_FETCH_PROT, // Quit emulation due to UC_MEM_FETCH_PROT violation: uc_emu_start()
    UC_ERR_ARG,     // Invalid argument provided to uc_xxx function (See specific function API)
    UC_ERR_READ_UNALIGNED,  // Unaligned read
    UC_ERR_WRITE_UNALIGNED,  // Unaligned write
    UC_ERR_FETCH_UNALIGNED,  // Unaligned fetch
    UC_ERR_HOOK_EXIST,  // hook for this event already existed
    UC_ERR_RESOURCE,    // Insufficient resource: uc_emu_start()
    UC_ERR_EXCEPTION, // Unhandled CPU exception
    UC_ERR_BREAKPOINT, // SNPS added: Simulation reached a breakpoint
    UC_ERR_WATCHPOINT, // SNPS added: Simulation triggered a watchpoint
    UC_ERR_YIELD,      // SNPS added: Simulator wants to yield
    UC_ERR_INTERNAL,   // SNPS added: Internal error
    UC_ERR_TIMEOUT // Emulation timed out
} uc_err;


/*
  Callback function for tracing code (UC_HOOK_CODE & UC_HOOK_BLOCK)

  @address: address where the code is being executed
  @size: size of machine instruction(s) being executed, or 0 when size is unknown
  @user_data: user data passed to tracing APIs.
*/
typedef void (*uc_cb_hookcode_t)(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);

/*
  Callback function for tracing interrupts (for uc_hook_intr())

  @intno: interrupt number
  @user_data: user data passed to tracing APIs.
*/
typedef void (*uc_cb_hookintr_t)(uc_engine *uc, uint32_t intno, void *user_data);

/*
  Callback function for tracing invalid instructions

  @user_data: user data passed to tracing APIs.

  @return: return true to continue, or false to stop program (due to invalid instruction).
*/
typedef bool (*uc_cb_hookinsn_invalid_t)(uc_engine *uc, void *user_data);

/*
  Callback function for tracing IN instruction of X86

  @port: port number
  @size: data size (1/2/4) to be read from this port
  @user_data: user data passed to tracing APIs.
*/
typedef uint32_t (*uc_cb_insn_in_t)(uc_engine *uc, uint32_t port, int size, void *user_data);

/*
  Callback function for OUT instruction of X86

  @port: port number
  @size: data size (1/2/4) to be written to this port
  @value: data value to be written to this port
*/
typedef void (*uc_cb_insn_out_t)(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data);

// All type of memory accesses for UC_HOOK_MEM_*
typedef enum uc_mem_type {
    UC_MEM_READ = 16,   // Memory is read from
    UC_MEM_WRITE,       // Memory is written to
    UC_MEM_FETCH,       // Memory is fetched
    UC_MEM_READ_UNMAPPED,    // Unmapped memory is read from
    UC_MEM_WRITE_UNMAPPED,   // Unmapped memory is written to
    UC_MEM_FETCH_UNMAPPED,   // Unmapped memory is fetched
    UC_MEM_WRITE_PROT,  // Write to write protected, but mapped, memory
    UC_MEM_READ_PROT,   // Read from read protected, but mapped, memory
    UC_MEM_FETCH_PROT,  // Fetch from non-executable, but mapped, memory
    UC_MEM_READ_AFTER,   // Memory is read from (successful access)
} uc_mem_type;

// All type of hooks for uc_hook_add() API.
typedef enum uc_hook_type {
    // Hook all interrupt/syscall events
    UC_HOOK_INTR = 1 << 0,
    // Hook a particular instruction - only a very small subset of instructions supported here
    UC_HOOK_INSN = 1 << 1,
    // Hook a range of code
    UC_HOOK_CODE = 1 << 2,
    // Hook basic blocks
    UC_HOOK_BLOCK = 1 << 3,
    // Hook for memory read on unmapped memory
    UC_HOOK_MEM_READ_UNMAPPED = 1 << 4,
    // Hook for invalid memory write events
    UC_HOOK_MEM_WRITE_UNMAPPED = 1 << 5,
    // Hook for invalid memory fetch for execution events
    UC_HOOK_MEM_FETCH_UNMAPPED = 1 << 6,
    // Hook for memory read on read-protected memory
    UC_HOOK_MEM_READ_PROT = 1 << 7,
    // Hook for memory write on write-protected memory
    UC_HOOK_MEM_WRITE_PROT = 1 << 8,
    // Hook for memory fetch on non-executable memory
    UC_HOOK_MEM_FETCH_PROT = 1 << 9,
    // Hook memory read events.
    UC_HOOK_MEM_READ = 1 << 10,
    // Hook memory write events.
    UC_HOOK_MEM_WRITE = 1 << 11,
    // Hook memory fetch for execution events
    UC_HOOK_MEM_FETCH = 1 << 12,
    // Hook memory read events, but only successful access.
    // The callback will be triggered after successful read.
    UC_HOOK_MEM_READ_AFTER = 1 << 13,
    // Hook invalid instructions exceptions.
    UC_HOOK_INSN_INVALID = 1 << 14,
} uc_hook_type;

// Hook type for all events of unmapped memory access
#define UC_HOOK_MEM_UNMAPPED (UC_HOOK_MEM_READ_UNMAPPED + UC_HOOK_MEM_WRITE_UNMAPPED + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal protected memory access
#define UC_HOOK_MEM_PROT (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_FETCH_PROT)
// Hook type for all events of illegal read memory access
#define UC_HOOK_MEM_READ_INVALID (UC_HOOK_MEM_READ_PROT + UC_HOOK_MEM_READ_UNMAPPED)
// Hook type for all events of illegal write memory access
#define UC_HOOK_MEM_WRITE_INVALID (UC_HOOK_MEM_WRITE_PROT + UC_HOOK_MEM_WRITE_UNMAPPED)
// Hook type for all events of illegal fetch memory access
#define UC_HOOK_MEM_FETCH_INVALID (UC_HOOK_MEM_FETCH_PROT + UC_HOOK_MEM_FETCH_UNMAPPED)
// Hook type for all events of illegal memory access
#define UC_HOOK_MEM_INVALID (UC_HOOK_MEM_UNMAPPED + UC_HOOK_MEM_PROT)
// Hook type for all events of valid memory access
// NOTE: UC_HOOK_MEM_READ is triggered before UC_HOOK_MEM_READ_PROT and UC_HOOK_MEM_READ_UNMAPPED, so
//       this hook may technically trigger on some invalid reads.
#define UC_HOOK_MEM_VALID (UC_HOOK_MEM_READ + UC_HOOK_MEM_WRITE + UC_HOOK_MEM_FETCH)

/*
  Callback function for hooking memory (READ, WRITE & FETCH)

  @type: this memory is being READ, or WRITE
  @address: address where the code is being executed
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs
*/
typedef void (*uc_cb_hookmem_t)(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data);

/*
  Callback function for handling invalid memory access events (UNMAPPED and
    PROT events)

  @type: this memory is being READ, or WRITE
  @address: address where the code is being executed
  @size: size of data being read or written
  @value: value of data being written to memory, or irrelevant if type = READ.
  @user_data: user data passed to tracing APIs

  @return: return true to continue, or false to stop program (due to invalid memory).
           NOTE: returning true to continue execution will only work if if the accessed
           memory is made accessible with the correct permissions during the hook.

           In the event of a UC_MEM_READ_UNMAPPED or UC_MEM_WRITE_UNMAPPED callback,
           the memory should be uc_mem_map()-ed with the correct permissions, and the
           instruction will then read or write to the address as it was supposed to.

           In the event of a UC_MEM_FETCH_UNMAPPED callback, the memory can be mapped
           in as executable, in which case execution will resume from the fetched address.
           The instruction pointer may be written to in order to change where execution resumes,
           but the fetch must succeed if execution is to resume.
*/
typedef bool (*uc_cb_eventmem_t)(uc_engine *uc, uc_mem_type type,
        uint64_t address, int size, int64_t value, void *user_data);

/*
  Memory region mapped by uc_mem_map() and uc_mem_map_ptr()
  Retrieve the list of memory regions with uc_mem_regions()
*/
typedef struct uc_mem_region {
    uint64_t begin; // begin address of the region (inclusive)
    uint64_t end;   // end address of the region (inclusive)
    uint32_t perms; // memory permissions of the region
} uc_mem_region;

// All type of queries for uc_query() API.
typedef enum uc_query_type {
    // Dynamically query current hardware mode.
    UC_QUERY_MODE = 1,
    UC_QUERY_PAGE_SIZE,
    UC_QUERY_ARCH,
} uc_query_type;

// SNPS added
typedef struct uc_mmio_tx {
    uint64_t addr;
    size_t   size;
    void*    data;

    bool is_read;
    bool is_secure; // adapted from MemAttrs
    bool is_user;
    bool is_io;

    unsigned int cpuid;
} uc_mmio_tx_t;

typedef enum uc_tx_result {
    UC_TX_OK = 0,
    UC_TX_ERROR = 1,
    UC_TX_ADDRESS_ERROR = 2,
} uc_tx_result_t;

typedef uc_tx_result_t (*uc_cb_mmio_t)(uc_engine* uc, void* opaque,
                                       uc_mmio_tx_t* tx);

typedef enum uc_dmi_prot {
    UC_DMI_PROT_READ  = 1 << 0,
    UC_DMI_PROT_WRITE = 1 << 1,
    UC_DMI_PROT_EXEC  = 1 << 2,
} uc_dmi_prot_t;

typedef bool (*uc_cb_dmiptr_t)(void* opaque, uint64_t page_addr,
                               unsigned char** dmiptr, int* prot);

typedef void (*uc_cb_pgprot_t)(void* opaque, unsigned char* dmiptr,
                               uint64_t page_addr);

typedef uint64_t (*uc_timer_timefunc_t)(void* opaque, uint64_t clock);
typedef void     (*uc_timer_irqfunc_t )(void* opaque, int idx, int set);
typedef void     (*uc_timer_schedule_t)(void* opaque, int idx, uint64_t clock,
                                        uint64_t ticks);

typedef void (*uc_tlb_cluster_flush_t)(void* opaque);
typedef void (*uc_tlb_cluster_flush_page_t)(void* opaque, uint64_t addr);
typedef void (*uc_tlb_cluster_flush_mmuidx_t)(void* opaque, uint16_t idxmap);
typedef void (*uc_tlb_cluster_flush_page_mmuidx_t)(void* opaque, uint64_t addr,
                                                   uint16_t idxmap);

typedef void (*uc_breakpoint_hit_t)(void* opaque, uint64_t addr);
typedef void (*uc_watchpoint_hit_t)(void* opaque, uint64_t addr, uint64_t size,
                                    uint64_t data, bool iswr);

typedef void (*uc_trace_basic_block_t)(void* opaque, uint64_t addr);

typedef const char* (*uc_get_config_t)(void* opaque, const char* config);

// Opaque storage for CPU context, used with uc_context_*()
struct uc_context;
typedef struct uc_context uc_context;

/*
 Return combined API version & major and minor version numbers.

 @major: major number of API version
 @minor: minor number of API version

 @return hexical number as (major << 8 | minor), which encodes both
     major & minor versions.
     NOTE: This returned value can be compared with version number made
     with macro UC_MAKE_VERSION

 For example, second API version would return 1 in @major, and 1 in @minor
 The return value would be 0x0101

 NOTE: if you only care about returned value, but not major and minor values,
 set both @major & @minor arguments to NULL.
*/
UNICORN_EXPORT
unsigned int uc_version(unsigned int *major, unsigned int *minor);


/*
 Determine if the given architecture is supported by this library.

 @arch: architecture type (UC_ARCH_*)

 @return True if this library supports the given arch.
*/
UNICORN_EXPORT
bool uc_arch_supported(uc_arch arch);


/*
 Create new instance of unicorn engine.

 @arch: architecture type (UC_ARCH_*)
 @mode: hardware mode. This is combined of UC_MODE_*
 @uc: pointer to uc_engine, which will be updated at return time

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_open(const char* model, void *cfg_opaque, uc_get_config_t cfg_func,
               uc_engine **result); // SNPS changed

/*
 Close a Unicorn engine instance.
 NOTE: this must be called only when there is no longer any
 usage of @uc. This API releases some of @uc's cached memory, thus
 any use of the Unicorn API with @uc after it has been closed may
 crash your application. After this, @uc is invalid, and is no
 longer usable.

 @uc: pointer to a handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_close(uc_engine *uc);

/*
 Query internal status of engine.

 @uc: handle returned by uc_open()
 @type: query type. See uc_query_type

 @result: save the internal status queried

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*/
UNICORN_EXPORT
uc_err uc_query(uc_engine *uc, uc_query_type type, size_t *result);

/*
 Report the last error number when some API function fail.
 Like glibc's errno, uc_errno might not retain its old value once accessed.

 @uc: handle returned by uc_open()

 @return: error code of uc_err enum type (UC_ERR_*, see above)
*/
UNICORN_EXPORT
uc_err uc_errno(uc_engine *uc);

/*
 Return a string describing given error code.

 @code: error code (see UC_ERR_* above)

 @return: returns a pointer to a string that describes the error code
   passed in the argument @code
 */
UNICORN_EXPORT
const char *uc_strerror(uc_err code);

/*
 Write to register.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be modified.
 @value:  pointer to the value that will set to register @regid

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_reg_write(uc_engine *uc, int regid, const void *value);

/*
 Read register value.

 @uc: handle returned by uc_open()
 @regid:  register ID that is to be retrieved.
 @value:  pointer to a variable storing the register value.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_reg_read(uc_engine *uc, int regid, void *value);

/*
 Write multiple register values.

 @uc: handle returned by uc_open()
 @rges:  array of register IDs to store
 @value: pointer to array of register values
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_reg_write_batch(uc_engine *uc, int *regs, void *const *vals, int count);

/*
 Read multiple register values.

 @uc: handle returned by uc_open()
 @rges:  array of register IDs to retrieve
 @value: pointer to array of values to hold registers
 @count: length of both *regs and *vals

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_reg_read_batch(uc_engine *uc, int *regs, void **vals, int count);

/*
 Write to a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to set.
 @bytes:   pointer to a variable containing data to be written to memory.
 @size:   size of memory to write to.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_write(uc_engine *uc, uint64_t address, const void *bytes, size_t size);

/*
 Read a range of bytes in memory.

 @uc: handle returned by uc_open()
 @address: starting memory address of bytes to get.
 @bytes:   pointer to a variable containing data copied from memory.
 @size:   size of memory to read.

 NOTE: @bytes must be big enough to contain @size bytes.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_read(uc_engine *uc, uint64_t address, void *bytes, size_t size);

/*
 Emulate machine code in a specific duration of time.

 @uc: handle returned by uc_open()
 @begin: address where emulation starts
 @until: address where emulation stops (i.e when this address is hit)
 @timeout: duration to emulate the code (in microseconds). When this value is 0,
        we will emulate the code in infinite time, until the code is finished.
 @count: the number of instructions to be emulated. When this value is 0,
        we will emulate all the code available, until the code is finished.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_emu_start(uc_engine *uc, uint64_t begin, uint64_t until, uint64_t timeout, size_t count);

/*
 Stop emulation (which was started by uc_emu_start() API.
 This is typically called from callback functions registered via tracing APIs.

 @uc: handle returned by uc_open()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_emu_stop(uc_engine *uc);

/*
 Register callback for a hook event.
 The callback will be run when the hook event is hit.

 @uc: handle returned by uc_open()
 @hh: hook handle returned from this registration. To be used in uc_hook_del() API
 @type: hook type
 @callback: callback to be run when instruction is hit
 @user_data: user-defined data. This will be passed to callback function in its
      last argument @user_data
 @begin: start address of the area where the callback is effect (inclusive)
 @end: end address of the area where the callback is effect (inclusive)
   NOTE 1: the callback is called only if related address is in range [@begin, @end]
   NOTE 2: if @begin > @end, callback is called whenever this hook type is triggered
 @...: variable arguments (depending on @type)
   NOTE: if @type = UC_HOOK_INSN, this is the instruction ID (ex: UC_X86_INS_OUT)

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_hook_add(uc_engine *uc, uc_hook *hh, int type, void *callback,
        void *user_data, uint64_t begin, uint64_t end, ...);

/*
 Unregister (remove) a hook callback.
 This API removes the hook callback registered by uc_hook_add().
 NOTE: this should be called only when you no longer want to trace.
 After this, @hh is invalid, and nolonger usable.

 @uc: handle returned by uc_open()
 @hh: handle returned by uc_hook_add()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_hook_del(uc_engine *uc, uc_hook hh);

typedef enum uc_prot {
   UC_PROT_NONE = 0,
   UC_PROT_READ = 1,
   UC_PROT_WRITE = 2,
   UC_PROT_EXEC = 4,
   UC_PROT_ALL = 7,
} uc_prot;

/*
 Map memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the new memory region to be mapped in.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_map(uc_engine *uc, uint64_t address, size_t size, uint32_t perms);

/*
 Map existing host memory in for emulation.
 This API adds a memory region that can be used by emulation.

 @uc: handle returned by uc_open()
 @address: starting address of the new memory region to be mapped in.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the new memory region to be mapped in.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: Permissions for the newly mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.
 @ptr: pointer to host memory backing the newly mapped memory. This host memory is
    expected to be an equal or larger size than provided, and be mapped with at
    least PROT_READ | PROT_WRITE. If it is not, the resulting behavior is undefined.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_map_ptr(uc_engine *uc, uint64_t address, size_t size, uint32_t perms, void *ptr);

// SNPS added
UNICORN_EXPORT
uc_err uc_mem_map_io(uc_engine *uc, uint64_t addr, size_t size, uc_cb_mmio_t callback, void* opaque);

// SNPS added
UNICORN_EXPORT
uc_err uc_mem_map_portio(uc_engine *uc, uc_cb_mmio_t callback, void *opaque);

/*
 Unmap a region of emulation memory.
 This API deletes a memory mapping from the emulation memory space.

 @uc: handle returned by uc_open()
 @address: starting address of the memory region to be unmapped.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the memory region to be modified.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_unmap(uc_engine *uc, uint64_t address, size_t size);

/*
 Set memory permissions for emulation memory.
 This API changes permissions on an existing memory region.

 @uc: handle returned by uc_open()
 @address: starting address of the memory region to be modified.
    This address must be aligned to 4KB, or this will return with UC_ERR_ARG error.
 @size: size of the memory region to be modified.
    This size must be multiple of 4KB, or this will return with UC_ERR_ARG error.
 @perms: New permissions for the mapped region.
    This must be some combination of UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC,
    or this will return with UC_ERR_ARG error.

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_protect(uc_engine *uc, uint64_t address, size_t size, uint32_t perms);

/*
 Retrieve all memory regions mapped by uc_mem_map() and uc_mem_map_ptr()
 This API allocates memory for @regions, and user must free this memory later
 by free() to avoid leaking memory.
 NOTE: memory regions may be splitted by uc_mem_unmap()

 @uc: handle returned by uc_open()
 @regions: pointer to an array of uc_mem_region struct. This is allocated by
   Unicorn, and must be freed by user later with uc_free()
 @count: pointer to number of struct uc_mem_region contained in @regions

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_mem_regions(uc_engine *uc, uc_mem_region **regions, uint32_t *count);

/*
 Allocate a region that can be used with uc_context_{save,restore} to perform
 quick save/rollback of the CPU context, which includes registers and some
 internal metadata. Contexts may not be shared across engine instances with
 differing arches or modes.

 @uc: handle returned by uc_open()
 @context: pointer to a uc_engine*. This will be updated with the pointer to
   the new context on successful return of this function.
   Later, this allocated memory must be freed with uc_free().

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_alloc(uc_engine *uc, uc_context **context);

/*
 Free the memory allocated by uc_context_alloc & uc_mem_regions.

 @mem: memory allocated by uc_context_alloc (returned in *context), or
       by uc_mem_regions (returned in *regions)

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_free(void *mem);

/*
 Save a copy of the internal CPU context.
 This API should be used to efficiently make or update a saved copy of the
 internal CPU state.

 @uc: handle returned by uc_open()
 @context: handle returned by uc_context_alloc()

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_save(uc_engine *uc, uc_context *context);

/*
 Restore the current CPU context from a saved copy.
 This API should be used to roll the CPU context back to a previous
 state saved by uc_context_save().

 @uc: handle returned by uc_open()
 @buffer: handle returned by uc_context_alloc that has been used with uc_context_save

 @return UC_ERR_OK on success, or other value on failure (refer to uc_err enum
   for detailed error).
*/
UNICORN_EXPORT
uc_err uc_context_restore(uc_engine *uc, uc_context *context);

/*
  Return the size needed to store the cpu context. Can be used to allocate a buffer
  to contain the cpu context and directly call uc_context_save.

  @uc: handle returned by uc_open()

  @return the size for needed to store the cpu context as as size_t.
*/
UNICORN_EXPORT
size_t uc_context_size(uc_engine *uc);

UNICORN_EXPORT // SNPS added
size_t uc_instruction_count(uc_engine *uc);

UNICORN_EXPORT // SNPS added
uc_err uc_tb_flush(uc_engine *uc);

UNICORN_EXPORT // SNPS added
uc_err uc_tb_flush_page(uc_engine *uc, uint64_t start, uint64_t end);

UNICORN_EXPORT // SNPS added
uc_err uc_tlb_flush(uc_engine *uc);

UNICORN_EXPORT // SNPS added
uc_err uc_tlb_flush_page(uc_engine *uc, uint64_t addr);

UNICORN_EXPORT // SNPS added
uc_err uc_tlb_flush_mmuidx(uc_engine *uc, uint16_t idxmap);

UNICORN_EXPORT // SNPS added
uc_err uc_tlb_flush_page_mmuidx(uc_engine *uc, uint64_t addr, uint16_t idxmap);

UNICORN_EXPORT // SNPS added
uc_err uc_register_tlb_cluster(uc_engine *uc, void *opaque,
        uc_tlb_cluster_flush_t             tlb_cluster_flush_fn,
        uc_tlb_cluster_flush_page_t        tlb_cluster_flush_page_fn,
        uc_tlb_cluster_flush_mmuidx_t      tlb_cluster_flush_mmuidx_fn,
        uc_tlb_cluster_flush_page_mmuidx_t tlb_cluster_flush_page_mmuidx_fn);

UNICORN_EXPORT // SNPS added
uc_err uc_breakpoint_insert(uc_engine *uc, uint64_t addr);

UNICORN_EXPORT // SNPS added
uc_err uc_breakpoint_remove(uc_engine *uc, uint64_t addr);

UNICORN_EXPORT // SNPS added
uc_err uc_cbbreakpoint_setup(uc_engine *uc, void *ptr, uc_breakpoint_hit_t fn);

UNICORN_EXPORT // SNPS added
uc_err uc_cbbreakpoint_insert(uc_engine *uc, uint64_t addr);

UNICORN_EXPORT // SNPS added
uc_err uc_cbbreakpoint_remove(uc_engine *uc, uint64_t addr);

typedef enum uc_wpflags { // SNPS added
    UC_WP_READ   = 1 << 0,
    UC_WP_WRITE  = 1 << 1,
    UC_WP_ACCESS = UC_WP_READ | UC_WP_WRITE,
    UC_WP_BEFORE = 1 << 2, /* stop on instruction before watchpoint */
    UC_WP_CALL   = 1 << 3, /* invoke a callback before watchpoint */
} uc_wpflags_t;

UNICORN_EXPORT // SNPS added
uc_err uc_watchpoint_insert(uc_engine *uc, uint64_t addr, size_t sz, int flags);

UNICORN_EXPORT // SNPS added
uc_err uc_watchpoint_remove(uc_engine *uc, uint64_t addr, size_t sz, int flags);

UNICORN_EXPORT // SNPS added
uc_err uc_cbwatchpoint_setup(uc_engine *uc, void *ptr, uc_watchpoint_hit_t fn);

UNICORN_EXPORT // SNPS added
uc_err uc_cbwatchpoint_insert(uc_engine *uc, uint64_t addr, size_t sz, int flags);

UNICORN_EXPORT // SNPS added
uc_err uc_cbwatchpoint_remove(uc_engine *uc, uint64_t addr, size_t sz, int flags);

#define UC_IRQID_AARCH64_NIRQ 0 // SNPS added
#define UC_IRQID_AARCH64_FIRQ 1 // SNPS added
#define UC_IRQID_AARCH64_VIRQ 2 // SNPS added
#define UC_IRQID_AARCH64_VFIQ 3 // SNPS added

#define UC_IRQID_RISCV_USW    0  // SNPS added
#define UC_IRQID_RISCV_SSW    1  // SNPS added
#define UC_IRQID_RISCV_MSW    3  // SNPS added
#define UC_IRQID_RISCV_UTIMER 4  // SNPS added
#define UC_IRQID_RISCV_STIMER 5  // SNPS added
#define UC_IRQID_RISCV_MTIMER 7  // SNPS added
#define UC_IRQID_RISCV_UEXT   8  // SNPS added
#define UC_IRQID_RISCV_SEXT   9  // SNPS added
#define UC_IRQID_RISCV_MEXT   11 // SNPS added

UNICORN_EXPORT // SNPS added
uc_err uc_interrupt(uc_engine *uc, int irq_id, int set);

UNICORN_EXPORT // SNPS added
uc_err uc_va2pa(uc_engine *uc, uint64_t va, uint64_t *pa);

UNICORN_EXPORT // SNPS added
uc_err uc_setup_timer(uc_engine *uc, void *opaque, uc_timer_timefunc_t timefn,
                      uc_timer_irqfunc_t irqfn, uc_timer_schedule_t schedfn);

UNICORN_EXPORT // SNPS added
uc_err uc_update_timer(uc_engine *uc, int timeridx);

UNICORN_EXPORT // SNPS added
bool uc_is_idle(uc_engine *uc);

UNICORN_EXPORT // SNPS added
bool uc_is_debug(uc_engine *uc);

UNICORN_EXPORT // SNPS added
bool uc_is_excl(uc_engine *uc);

UNICORN_EXPORT // SNPS added
uc_err uc_clear_excl(uc_engine *uc);

UNICORN_EXPORT // SNPS added
uc_err uc_setup_dmi(uc_engine *uc, void *opaque, uc_cb_dmiptr_t dmifn,
                    uc_cb_pgprot_t protfn);

UNICORN_EXPORT // SNPS added
uc_err uc_dmi_invalidate(uc_engine *uc, uint64_t start, uint64_t end);

 // SNPS added
typedef enum uc_hint {
    UC_HINT_NOP, /* unused! NOP currently generates no code! */
    UC_HINT_YIELD,
    UC_HINT_WFE,
    UC_HINT_WFI,
    UC_HINT_SEV,
    UC_HINT_SEVL,
    UC_HINT_HINT, /* unused! reserved for architectural extensions */
} uc_hint_t;

typedef void (*uc_hintfunc_t)(void*, uc_hint_t); // SNPS added

UNICORN_EXPORT // SNPS added
uc_err uc_setup_hint(uc_engine *uc, void *opaque, uc_hintfunc_t hintfn);

typedef uint64_t (*uc_shfunc_t)(void* opaque, uint32_t call); // SNPS added

UNICORN_EXPORT // SNPS added
uc_err uc_setup_semihosting(uc_engine *uc, void *opaque, uc_shfunc_t fn);

UNICORN_EXPORT // SNPS added
uc_err uc_setup_basic_block_trace(uc_engine *uc, void *opaque,
                                  uc_trace_basic_block_t fn);

UNICORN_EXPORT // SNPS added
uc_err uc_reset_cpu(uc_engine *uc);

UNICORN_EXPORT // SNPS added
bool uc_is_running(uc_engine *uc);

UNICORN_EXPORT // SNPS added
const char* uc_gitrev(void);

#ifdef __cplusplus
}
#endif

#endif
