#ifndef QEMU_TYPEDEFS_H
#define QEMU_TYPEDEFS_H

/*
 * This header is for selectively avoiding #include just to get a
 * typedef name.
 *
 * Declaring a typedef name in its "obvious" place can result in
 * inclusion cycles, in particular for complete struct and union
 * types that need more types for their members.  It can also result
 * in headers pulling in many more headers, slowing down builds.
 *
 * You can break such cycles and unwanted dependencies by declaring
 * the typedef name here.
 *
 * For struct types used in only a few headers, judicious use of the
 * struct tag instead of the typedef name is commonly preferable.
 */

/*
 * Incomplete struct types
 * Please keep this list in case-insensitive alphabetical order.
 */

typedef struct AdapterInfo AdapterInfo;
typedef struct AddressSpace AddressSpace;
typedef struct AioContext AioContext;
typedef struct AudioState AudioState;
typedef struct BlockBackend BlockBackend;
typedef struct BlockDriverState BlockDriverState;
typedef struct BusClass BusClass;
typedef struct BusState BusState;
typedef struct CharDriverState CharDriverState;
typedef struct CompatProperty CompatProperty;
typedef struct CPUAddressSpace CPUAddressSpace;
typedef struct CPUState CPUState;
typedef struct DeviceState DeviceState;
typedef struct DisplayChangeListener DisplayChangeListener;
typedef struct DisplayState DisplayState;
typedef struct DisplaySurface DisplaySurface;
typedef struct DriveInfo DriveInfo;
typedef struct Error Error;
typedef struct EventNotifier EventNotifier;
typedef struct FlatView FlatView;
typedef struct FWCfgState FWCfgState;
typedef struct HCIInfo HCIInfo;
typedef struct I2CBus I2CBus;
typedef struct I2SCodec I2SCodec;
typedef struct ISABus ISABus;
typedef struct ISADevice ISADevice;
typedef struct MACAddr MACAddr;
typedef struct MSIMessage MSIMessage;
typedef struct MachineClass MachineClass;
typedef struct MachineState MachineState;
typedef struct MemoryListener MemoryListener;
typedef struct MemoryMappingList MemoryMappingList;
typedef struct MemoryRegion MemoryRegion;
typedef struct MemoryRegionCache MemoryRegionCache;
typedef struct MemoryRegionSection MemoryRegionSection;
typedef struct MigrationParams MigrationParams;
typedef struct MouseTransformInfo MouseTransformInfo;
typedef struct NICInfo NICInfo;
typedef struct NetClientState NetClientState;
typedef struct ObjectClass ObjectClass;
typedef struct PCIBridge PCIBridge;
typedef struct PCIBus PCIBus;
typedef struct PCIDevice PCIDevice;
typedef struct PCIEAERErr PCIEAERErr;
typedef struct PCIEAERLog PCIEAERLog;
typedef struct PCIEAERMsg PCIEAERMsg;
typedef struct PCIEPort PCIEPort;
typedef struct PCIESlot PCIESlot;
typedef struct PCIExpressDevice PCIExpressDevice;
typedef struct PCIExpressHost PCIExpressHost;
typedef struct PCIHostState PCIHostState;
typedef struct PCMCIACardState PCMCIACardState;
typedef struct PCMachineClass PCMachineClass;
typedef struct PCMachineState PCMachineState;
typedef struct PixelFormat PixelFormat;
typedef struct Property Property;
typedef struct PropertyInfo PropertyInfo;
typedef struct QEMUBH QEMUBH;
typedef struct QEMUFile QEMUFile;
typedef struct QEMUSGList QEMUSGList;
typedef struct QEMUSizedBuffer QEMUSizedBuffer;
typedef struct QEMUTimer QEMUTimer;
typedef struct QEMUTimerListGroup QEMUTimerListGroup;
typedef struct QemuConsole QemuConsole;
typedef struct QBool QBool;
typedef struct QDict QDict;
typedef struct QList QList;
typedef struct QNum QNum;
typedef struct QNull QNull;
typedef struct QObject QObject;
typedef struct QString QString;
typedef struct RAMBlock RAMBlock;
typedef struct Range Range;
typedef struct SHPCDevice SHPCDevice;
typedef struct SMBusDevice SMBusDevice;
typedef struct SSIBus SSIBus;
typedef struct SerialState SerialState;
typedef struct VirtIODevice VirtIODevice;
typedef struct Visitor Visitor;
typedef struct uWireSlave uWireSlave;

/*
 * Function types
 */

#endif /* QEMU_TYPEDEFS_H */
