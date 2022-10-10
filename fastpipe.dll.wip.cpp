// Insomnyawolf here
// (?) means that i'm not sure
//
#include <stdbool.h>

typedef unsigned char undefined;

typedef unsigned long long GUID;
typedef unsigned int ImageBaseOffset32;
typedef unsigned char bool;
typedef unsigned char byte;
typedef unsigned int dword;
typedef long long longlong;
typedef unsigned long long qword;
typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef unsigned char undefined1;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef unsigned short ushort;
typedef unsigned short word;
typedef struct _s__RTTIClassHierarchyDescriptor _s__RTTIClassHierarchyDescriptor, *P_s__RTTIClassHierarchyDescriptor;

typedef struct _s__RTTIClassHierarchyDescriptor RTTIClassHierarchyDescriptor;

struct _s__RTTIClassHierarchyDescriptor
{
    dword signature;
    dword attributes;                  // bit flags
    dword numBaseClasses;              // number of base classes (i.e. rtti1Count)
    ImageBaseOffset32 pBaseClassArray; // ref to BaseClassArray (RTTI 2)
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct
{
    dword OffsetToDirectory;
    dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion
{
    dword OffsetToData;
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _s_FuncInfo _s_FuncInfo, *P_s_FuncInfo;

typedef struct _s_FuncInfo FuncInfo;

typedef int __ehstate_t;

struct _s_FuncInfo
{
    uint magicNumber_and_bbtFlags;
    __ehstate_t maxState;
    ImageBaseOffset32 dispUnwindMap;
    uint nTryBlocks;
    ImageBaseOffset32 dispTryBlockMap;
    uint nIPMapEntries;
    ImageBaseOffset32 dispIPToStateMap;
    int dispUnwindHelp;
    ImageBaseOffset32 dispESTypeList;
    int EHFlags;
};

typedef struct _s__RTTIBaseClassDescriptor _s__RTTIBaseClassDescriptor, *P_s__RTTIBaseClassDescriptor;

typedef struct PMD PMD, *PPMD;

struct PMD
{
    int mdisp;
    int pdisp;
    int vdisp;
};

struct _s__RTTIBaseClassDescriptor
{
    ImageBaseOffset32 pTypeDescriptor;           // ref to TypeDescriptor (RTTI 0) for class
    dword numContainedBases;                     // count of extended classes in BaseClassArray (RTTI 2)
    struct PMD where;                            // member displacement structure
    dword attributes;                            // bit flags
    ImageBaseOffset32 pClassHierarchyDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3) for class
};

typedef struct _s_UnwindMapEntry _s_UnwindMapEntry, *P_s_UnwindMapEntry;

struct _s_UnwindMapEntry
{
    __ehstate_t toState;
    ImageBaseOffset32 action;
};

typedef struct _s__RTTIBaseClassDescriptor RTTIBaseClassDescriptor;

typedef struct _s__RTTICompleteObjectLocator _s__RTTICompleteObjectLocator, *P_s__RTTICompleteObjectLocator;

struct _s__RTTICompleteObjectLocator
{
    dword signature;
    dword offset;                       // offset of vbtable within class
    dword cdOffset;                     // constructor displacement offset
    ImageBaseOffset32 pTypeDescriptor;  // ref to TypeDescriptor (RTTI 0) for class
    ImageBaseOffset32 pClassDescriptor; // ref to ClassHierarchyDescriptor (RTTI 3)
};

typedef struct TypeDescriptor TypeDescriptor, *PTypeDescriptor;

struct TypeDescriptor
{
    void *pVFTable;
    void *spare;
    char name[0];
};

typedef struct _s__RTTICompleteObjectLocator RTTICompleteObjectLocator;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY _IMAGE_RUNTIME_FUNCTION_ENTRY, *P_IMAGE_RUNTIME_FUNCTION_ENTRY;

struct _IMAGE_RUNTIME_FUNCTION_ENTRY
{
    ImageBaseOffset32 BeginAddress;
    ImageBaseOffset32 EndAddress;
    ImageBaseOffset32 UnwindInfoAddressOrData;
};

typedef struct _s_IPToStateMapEntry _s_IPToStateMapEntry, *P_s_IPToStateMapEntry;

struct _s_IPToStateMapEntry
{
    ImageBaseOffset32 Ip;
    __ehstate_t state;
};

typedef ulonglong __uint64;

typedef struct _s_IPToStateMapEntry IPToStateMapEntry;

typedef struct _s_UnwindMapEntry UnwindMapEntry;

typedef struct exception exception, *Pexception;

struct exception
{ // PlaceHolder Class Structure
};

typedef struct _SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES, *P_SECURITY_ATTRIBUTES;

typedef ulong DWORD;

typedef void *LPVOID;

typedef int BOOL;

struct _SECURITY_ATTRIBUTES
{
    DWORD nLength;
    LPVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
};

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, *P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION *PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, *P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG *PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef void *HANDLE;

typedef ulonglong ULONG_PTR;

typedef ushort WORD;

typedef struct _LIST_ENTRY _LIST_ENTRY, *P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION
{
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};

struct _LIST_ENTRY
{
    struct _LIST_ENTRY *Flink;
    struct _LIST_ENTRY *Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG
{
    WORD Type;
    WORD CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION *CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD CreatorBackTraceIndexHigh;
    WORD SpareWORD;
};

typedef DWORD (*PTHREAD_START_ROUTINE)(LPVOID);

typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, *P_EXCEPTION_POINTERS;

typedef LONG (*PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS *);

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, *P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD *PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, *P_CONTEXT;

typedef struct _CONTEXT *PCONTEXT;

typedef void *PVOID;

typedef ulonglong DWORD64;

typedef union _union_54 _union_54, *P_union_54;

typedef struct _M128A _M128A, *P_M128A;

typedef struct _M128A M128A;

typedef struct _XSAVE_FORMAT _XSAVE_FORMAT, *P_XSAVE_FORMAT;

typedef struct _XSAVE_FORMAT XSAVE_FORMAT;

typedef XSAVE_FORMAT XMM_SAVE_AREA32;

typedef struct _struct_55 _struct_55, *P_struct_55;

typedef ulonglong ULONGLONG;

typedef longlong LONGLONG;

typedef uchar BYTE;

struct _M128A
{
    ULONGLONG Low;
    LONGLONG High;
};

struct _XSAVE_FORMAT
{
    WORD ControlWord;
    WORD StatusWord;
    BYTE TagWord;
    BYTE Reserved1;
    WORD ErrorOpcode;
    DWORD ErrorOffset;
    WORD ErrorSelector;
    WORD Reserved2;
    DWORD DataOffset;
    WORD DataSelector;
    WORD Reserved3;
    DWORD MxCsr;
    DWORD MxCsr_Mask;
    M128A FloatRegisters[8];
    M128A XmmRegisters[16];
    BYTE Reserved4[96];
};

struct _struct_55
{
    M128A Header[2];
    M128A Legacy[8];
    M128A Xmm0;
    M128A Xmm1;
    M128A Xmm2;
    M128A Xmm3;
    M128A Xmm4;
    M128A Xmm5;
    M128A Xmm6;
    M128A Xmm7;
    M128A Xmm8;
    M128A Xmm9;
    M128A Xmm10;
    M128A Xmm11;
    M128A Xmm12;
    M128A Xmm13;
    M128A Xmm14;
    M128A Xmm15;
};

union _union_54
{
    XMM_SAVE_AREA32 FltSave;
    struct _struct_55 s;
};

struct _CONTEXT
{
    DWORD64 P1Home;
    DWORD64 P2Home;
    DWORD64 P3Home;
    DWORD64 P4Home;
    DWORD64 P5Home;
    DWORD64 P6Home;
    DWORD ContextFlags;
    DWORD MxCsr;
    WORD SegCs;
    WORD SegDs;
    WORD SegEs;
    WORD SegFs;
    WORD SegGs;
    WORD SegSs;
    DWORD EFlags;
    DWORD64 Dr0;
    DWORD64 Dr1;
    DWORD64 Dr2;
    DWORD64 Dr3;
    DWORD64 Dr6;
    DWORD64 Dr7;
    DWORD64 Rax;
    DWORD64 Rcx;
    DWORD64 Rdx;
    DWORD64 Rbx;
    DWORD64 Rsp;
    DWORD64 Rbp;
    DWORD64 Rsi;
    DWORD64 Rdi;
    DWORD64 R8;
    DWORD64 R9;
    DWORD64 R10;
    DWORD64 R11;
    DWORD64 R12;
    DWORD64 R13;
    DWORD64 R14;
    DWORD64 R15;
    DWORD64 Rip;
    union _union_54 u;
    M128A VectorRegister[26];
    DWORD64 VectorControl;
    DWORD64 DebugControl;
    DWORD64 LastBranchToRip;
    DWORD64 LastBranchFromRip;
    DWORD64 LastExceptionToRip;
    DWORD64 LastExceptionFromRip;
};

struct _EXCEPTION_RECORD
{
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    struct _EXCEPTION_RECORD *ExceptionRecord;
    PVOID ExceptionAddress;
    DWORD NumberParameters;
    ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS
{
    PEXCEPTION_RECORD ExceptionRecord;
    PCONTEXT ContextRecord;
};

typedef struct _SECURITY_ATTRIBUTES *LPSECURITY_ATTRIBUTES;

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef char CHAR;

typedef union _LARGE_INTEGER _LARGE_INTEGER, *P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, *P_struct_19;

typedef struct _struct_20 _struct_20, *P_struct_20;

struct _struct_20
{
    DWORD LowPart;
    LONG HighPart;
};

struct _struct_19
{
    DWORD LowPart;
    LONG HighPart;
};

union _LARGE_INTEGER
{
    struct _struct_19 s;
    struct _struct_20 u;
    LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef struct _struct_314 _struct_314, *P_struct_314;

struct _struct_314
{
    ULONGLONG Alignment;
    ULONGLONG Region;
};

typedef struct _struct_317 _struct_317, *P_struct_317;

struct _struct_317
{
    ULONGLONG Depth : 16;
    ULONGLONG Sequence : 48;
    ULONGLONG HeaderType : 1;
    ULONGLONG Reserved : 3;
    ULONGLONG NextEntry : 60;
};

typedef struct _struct_316 _struct_316, *P_struct_316;

struct _struct_316
{
    ULONGLONG Depth : 16;
    ULONGLONG Sequence : 48;
    ULONGLONG HeaderType : 1;
    ULONGLONG Init : 1;
    ULONGLONG Reserved : 2;
    ULONGLONG NextEntry : 60;
};

typedef struct _struct_315 _struct_315, *P_struct_315;

struct _struct_315
{
    ULONGLONG Depth : 16;
    ULONGLONG Sequence : 9;
    ULONGLONG NextEntry : 39;
    ULONGLONG HeaderType : 1;
    ULONGLONG Init : 1;
    ULONGLONG Reserved : 59;
    ULONGLONG Region : 3;
};

typedef struct _RUNTIME_FUNCTION _RUNTIME_FUNCTION, *P_RUNTIME_FUNCTION;

struct _RUNTIME_FUNCTION
{
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
};

typedef struct _RUNTIME_FUNCTION *PRUNTIME_FUNCTION;

typedef enum _EXCEPTION_DISPOSITION
{
    ExceptionContinueExecution = 0,
    ExceptionContinueSearch = 1,
    ExceptionNestedException = 2,
    ExceptionCollidedUnwind = 3
} _EXCEPTION_DISPOSITION;

typedef enum _EXCEPTION_DISPOSITION EXCEPTION_DISPOSITION;

typedef EXCEPTION_DISPOSITION(EXCEPTION_ROUTINE)(struct _EXCEPTION_RECORD *, PVOID, struct _CONTEXT *, PVOID);

typedef union _SLIST_HEADER _SLIST_HEADER, *P_SLIST_HEADER;

union _SLIST_HEADER
{
    struct _struct_314 s;
    struct _struct_315 Header8;
    struct _struct_316 Header16;
    struct _struct_317 HeaderX64;
};

typedef struct _M128A *PM128A;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY _UNWIND_HISTORY_TABLE_ENTRY, *P_UNWIND_HISTORY_TABLE_ENTRY;

typedef struct _UNWIND_HISTORY_TABLE_ENTRY UNWIND_HISTORY_TABLE_ENTRY;

struct _UNWIND_HISTORY_TABLE_ENTRY
{
    DWORD64 ImageBase;
    PRUNTIME_FUNCTION FunctionEntry;
};

typedef union _union_61 _union_61, *P_union_61;

typedef struct _struct_62 _struct_62, *P_struct_62;

struct _struct_62
{
    PM128A Xmm0;
    PM128A Xmm1;
    PM128A Xmm2;
    PM128A Xmm3;
    PM128A Xmm4;
    PM128A Xmm5;
    PM128A Xmm6;
    PM128A Xmm7;
    PM128A Xmm8;
    PM128A Xmm9;
    PM128A Xmm10;
    PM128A Xmm11;
    PM128A Xmm12;
    PM128A Xmm13;
    PM128A Xmm14;
    PM128A Xmm15;
};

union _union_61
{
    PM128A FloatingContext[16];
    struct _struct_62 s;
};

typedef union _union_63 _union_63, *P_union_63;

typedef ulonglong *PDWORD64;

typedef struct _struct_64 _struct_64, *P_struct_64;

struct _struct_64
{
    PDWORD64 Rax;
    PDWORD64 Rcx;
    PDWORD64 Rdx;
    PDWORD64 Rbx;
    PDWORD64 Rsp;
    PDWORD64 Rbp;
    PDWORD64 Rsi;
    PDWORD64 Rdi;
    PDWORD64 R8;
    PDWORD64 R9;
    PDWORD64 R10;
    PDWORD64 R11;
    PDWORD64 R12;
    PDWORD64 R13;
    PDWORD64 R14;
    PDWORD64 R15;
};

union _union_63
{
    PDWORD64 IntegerContext[16];
    struct _struct_64 s;
};

typedef struct _UNWIND_HISTORY_TABLE _UNWIND_HISTORY_TABLE, *P_UNWIND_HISTORY_TABLE;

typedef struct _UNWIND_HISTORY_TABLE *PUNWIND_HISTORY_TABLE;

struct _UNWIND_HISTORY_TABLE
{
    DWORD Count;
    BYTE LocalHint;
    BYTE GlobalHint;
    BYTE Search;
    BYTE Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
    UNWIND_HISTORY_TABLE_ENTRY Entry[12];
};

typedef union _SLIST_HEADER *PSLIST_HEADER;

typedef CHAR *LPCSTR;

typedef CHAR *LPSTR;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS _KNONVOLATILE_CONTEXT_POINTERS, *P_KNONVOLATILE_CONTEXT_POINTERS;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS *PKNONVOLATILE_CONTEXT_POINTERS;

struct _KNONVOLATILE_CONTEXT_POINTERS
{
    union _union_61 u;
    union _union_63 u2;
};

typedef EXCEPTION_ROUTINE *PEXCEPTION_ROUTINE;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER
{
    char e_magic[2];     // Magic number
    word e_cblp;         // Bytes of last page
    word e_cp;           // Pages in file
    word e_crlc;         // Relocations
    word e_cparhdr;      // Size of header in paragraphs
    word e_minalloc;     // Minimum extra paragraphs needed
    word e_maxalloc;     // Maximum extra paragraphs needed
    word e_ss;           // Initial (relative) SS value
    word e_sp;           // Initial SP value
    word e_csum;         // Checksum
    word e_ip;           // Initial IP value
    word e_cs;           // Initial (relative) CS value
    word e_lfarlc;       // File address of relocation table
    word e_ovno;         // Overlay number
    word e_res[4][4];    // Reserved words
    word e_oemid;        // OEM identifier (for e_oeminfo)
    word e_oeminfo;      // OEM information; e_oemid specific
    word e_res2[10][10]; // Reserved words
    dword e_lfanew;      // File address of new exe header
    byte e_program[64];  // Actual DOS program
};

typedef struct _DISPATCHER_CONTEXT _DISPATCHER_CONTEXT, *P_DISPATCHER_CONTEXT;

struct _DISPATCHER_CONTEXT
{
};

typedef ULONG_PTR SIZE_T;

typedef struct DotNetPdbInfo DotNetPdbInfo, *PDotNetPdbInfo;

struct DotNetPdbInfo
{
    char signature[4];
    GUID guid;
    dword age;
    char pdbname[12];
};

typedef struct _FILETIME _FILETIME, *P_FILETIME;

typedef struct _FILETIME *LPFILETIME;

struct _FILETIME
{
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
};

typedef struct HINSTANCE__ HINSTANCE__, *PHINSTANCE__;

typedef struct HINSTANCE__ *HINSTANCE;

struct HINSTANCE__
{
    int unused;
};

typedef struct HWND__ HWND__, *PHWND__;

typedef struct HWND__ *HWND;

struct HWND__
{
    int unused;
};

typedef HINSTANCE HMODULE;

typedef DWORD *LPDWORD;

typedef uint UINT;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct
{
    dword NameOffset;
    dword NameIsString;
};

typedef struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY IMAGE_LOAD_CONFIG_CODE_INTEGRITY, *PIMAGE_LOAD_CONFIG_CODE_INTEGRITY;

struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY
{
    word Flags;
    word Catalog;
    dword CatalogOffset;
    dword Reserved;
};

typedef struct IMAGE_DEBUG_DIRECTORY IMAGE_DEBUG_DIRECTORY, *PIMAGE_DEBUG_DIRECTORY;

struct IMAGE_DEBUG_DIRECTORY
{
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Type;
    dword SizeOfData;
    dword AddressOfRawData;
    dword PointerToRawData;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER
{
    word Machine; // 34404
    word NumberOfSections;
    dword TimeDateStamp;
    dword PointerToSymbolTable;
    dword NumberOfSymbols;
    word SizeOfOptionalHeader;
    word Characteristics;
};

typedef struct IMAGE_LOAD_CONFIG_DIRECTORY64 IMAGE_LOAD_CONFIG_DIRECTORY64, *PIMAGE_LOAD_CONFIG_DIRECTORY64;

typedef enum IMAGE_GUARD_FLAGS
{
    IMAGE_GUARD_CF_INSTRUMENTED = 256,
    IMAGE_GUARD_CFW_INSTRUMENTED = 512,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT = 1024,
    IMAGE_GUARD_SECURITY_COOKIE_UNUSED = 2048,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT = 4096,
    IMAGE_GUARD_DELAYLOAD_IAT_IN_ITS_OWN_SECTION = 8192,
    IMAGE_GUARD_CF_EXPORT_SUPPRESSION_INFO_PRESENT = 16384,
    IMAGE_GUARD_CF_ENABLE_EXPORT_SUPPRESSION = 32768,
    IMAGE_GUARD_CF_LONGJUMP_TABLE_PRESENT = 65536,
    IMAGE_GUARD_RF_INSTRUMENTED = 131072,
    IMAGE_GUARD_RF_ENABLE = 262144,
    IMAGE_GUARD_RF_STRICT = 524288,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_1 = 268435456,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_2 = 536870912,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_4 = 1073741824,
    IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK_8 = 2147483648
} IMAGE_GUARD_FLAGS;

struct IMAGE_LOAD_CONFIG_DIRECTORY64
{
    dword Size;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword GlobalFlagsClear;
    dword GlobalFlagsSet;
    dword CriticalSectionDefaultTimeout;
    qword DeCommitFreeBlockThreshold;
    qword DeCommitTotalFreeThreshold;
    pointer64 LockPrefixTable;
    qword MaximumAllocationSize;
    qword VirtualMemoryThreshold;
    qword ProcessAffinityMask;
    dword ProcessHeapFlags;
    word CsdVersion;
    word DependentLoadFlags;
    pointer64 EditList;
    pointer64 SecurityCookie;
    pointer64 SEHandlerTable;
    qword SEHandlerCount;
    pointer64 GuardCFCCheckFunctionPointer;
    pointer64 GuardCFDispatchFunctionPointer;
    pointer64 GuardCFFunctionTable;
    qword GuardCFFunctionCount;
    enum IMAGE_GUARD_FLAGS GuardFlags;
    struct IMAGE_LOAD_CONFIG_CODE_INTEGRITY CodeIntegrity;
    pointer64 GuardAddressTakenIatEntryTable;
    qword GuardAddressTakenIatEntryCount;
    pointer64 GuardLongJumpTargetTable;
    qword GuardLongJumpTargetCount;
    pointer64 DynamicValueRelocTable;
    pointer64 CHPEMetadataPointer;
    pointer64 GuardRFFailureRoutine;
    pointer64 GuardRFFailureRoutineFunctionPointer;
    dword DynamicValueRelocTableOffset;
    word DynamicValueRelocTableSection;
    word Reserved1;
    pointer64 GuardRFVerifyStackPointerFunctionPointer;
    dword HotPatchTableOffset;
    dword Reserved2;
    qword Reserved3;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, *PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, *PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion
{
    struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
    dword Name;
    word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY
{
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
    union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY
{
    ImageBaseOffset32 VirtualAddress;
    dword Size;
};

struct IMAGE_OPTIONAL_HEADER64
{
    word Magic;
    byte MajorLinkerVersion;
    byte MinorLinkerVersion;
    dword SizeOfCode;
    dword SizeOfInitializedData;
    dword SizeOfUninitializedData;
    ImageBaseOffset32 AddressOfEntryPoint;
    ImageBaseOffset32 BaseOfCode;
    pointer64 ImageBase;
    dword SectionAlignment;
    dword FileAlignment;
    word MajorOperatingSystemVersion;
    word MinorOperatingSystemVersion;
    word MajorImageVersion;
    word MinorImageVersion;
    word MajorSubsystemVersion;
    word MinorSubsystemVersion;
    dword Win32VersionValue;
    dword SizeOfImage;
    dword SizeOfHeaders;
    dword CheckSum;
    word Subsystem;
    word DllCharacteristics;
    qword SizeOfStackReserve;
    qword SizeOfStackCommit;
    qword SizeOfHeapReserve;
    qword SizeOfHeapCommit;
    dword LoaderFlags;
    dword NumberOfRvaAndSizes;
    struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef union Misc Misc, *PMisc;

typedef enum SectionFlags
{
    IMAGE_SCN_TYPE_NO_PAD = 8,
    IMAGE_SCN_RESERVED_0001 = 16,
    IMAGE_SCN_CNT_CODE = 32,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 128,
    IMAGE_SCN_LNK_OTHER = 256,
    IMAGE_SCN_LNK_INFO = 512,
    IMAGE_SCN_RESERVED_0040 = 1024,
    IMAGE_SCN_LNK_REMOVE = 2048,
    IMAGE_SCN_LNK_COMDAT = 4096,
    IMAGE_SCN_GPREL = 32768,
    IMAGE_SCN_MEM_16BIT = 131072,
    IMAGE_SCN_MEM_PURGEABLE = 131072,
    IMAGE_SCN_MEM_LOCKED = 262144,
    IMAGE_SCN_MEM_PRELOAD = 524288,
    IMAGE_SCN_ALIGN_1BYTES = 1048576,
    IMAGE_SCN_ALIGN_2BYTES = 2097152,
    IMAGE_SCN_ALIGN_4BYTES = 3145728,
    IMAGE_SCN_ALIGN_8BYTES = 4194304,
    IMAGE_SCN_ALIGN_16BYTES = 5242880,
    IMAGE_SCN_ALIGN_32BYTES = 6291456,
    IMAGE_SCN_ALIGN_64BYTES = 7340032,
    IMAGE_SCN_ALIGN_128BYTES = 8388608,
    IMAGE_SCN_ALIGN_256BYTES = 9437184,
    IMAGE_SCN_ALIGN_512BYTES = 10485760,
    IMAGE_SCN_ALIGN_1024BYTES = 11534336,
    IMAGE_SCN_ALIGN_2048BYTES = 12582912,
    IMAGE_SCN_ALIGN_4096BYTES = 13631488,
    IMAGE_SCN_ALIGN_8192BYTES = 14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL = 16777216,
    IMAGE_SCN_MEM_DISCARDABLE = 33554432,
    IMAGE_SCN_MEM_NOT_CACHED = 67108864,
    IMAGE_SCN_MEM_NOT_PAGED = 134217728,
    IMAGE_SCN_MEM_SHARED = 268435456,
    IMAGE_SCN_MEM_EXECUTE = 536870912,
    IMAGE_SCN_MEM_READ = 1073741824,
    IMAGE_SCN_MEM_WRITE = 2147483648
} SectionFlags;

union Misc
{
    dword PhysicalAddress;
    dword VirtualSize;
};

struct IMAGE_SECTION_HEADER
{
    char Name[8];
    union Misc Misc;
    ImageBaseOffset32 VirtualAddress;
    dword SizeOfRawData;
    dword PointerToRawData;
    dword PointerToRelocations;
    dword PointerToLinenumbers;
    word NumberOfRelocations;
    word NumberOfLinenumbers;
    enum SectionFlags Characteristics;
};

typedef struct IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

struct IMAGE_NT_HEADERS64
{
    char Signature[4];
    struct IMAGE_FILE_HEADER FileHeader;
    struct IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, *PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY
{
    dword OffsetToData;
    dword Size;
    dword CodePage;
    dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, *PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY
{
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    word NumberOfNamedEntries;
    word NumberOfIdEntries;
};

typedef struct IMAGE_DIRECTORY_ENTRY_EXPORT IMAGE_DIRECTORY_ENTRY_EXPORT, *PIMAGE_DIRECTORY_ENTRY_EXPORT;

struct IMAGE_DIRECTORY_ENTRY_EXPORT
{
    dword Characteristics;
    dword TimeDateStamp;
    word MajorVersion;
    word MinorVersion;
    dword Name;
    dword Base;
    dword NumberOfFunctions;
    dword NumberOfNames;
    dword AddressOfFunctions;
    dword AddressOfNames;
    dword AddressOfNameOrdinals;
};

typedef int PMFN;

typedef struct _s_ThrowInfo _s_ThrowInfo, *P_s_ThrowInfo;

struct _s_ThrowInfo
{
    uint attributes;
    PMFN pmfnUnwind;
    int pForwardCompat;
    int pCatchableTypeArray;
};

typedef struct _s_ThrowInfo ThrowInfo;

typedef int (*_onexit_t)(void);

typedef ulonglong size_t;

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_180001030(void)

{
    _onexit_t p_Var1;

    memset(&DAT_18000d078, 0, 0x80);
    _DAT_18000d048 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0, 0, 0, (LPCSTR)0x0);
    DAT_18000d120 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0, 0, 0, (LPCSTR)0x0);
    InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18000d0f8);
    p_Var1 = _onexit((_onexit_t)&LAB_180008190);
    return (p_Var1 != (_onexit_t)0x0) - 1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

int FUN_1800010a0(void)

{
    _onexit_t p_Var1;
    undefined *puVar2;

    puVar2 = &DAT_18000d878;
    InitializeCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    DAT_18000d8a0 = 0;
    _DAT_18000d8a8 = 0;
    DAT_18000d8a0 = FUN_180005680(puVar2, (void **)0x0, (void **)0x0);
    DAT_18000d870 = 0;
    DAT_18000d8b0 = CreateEventA((LPSECURITY_ATTRIBUTES)0x0, 1, 0, (LPCSTR)0x0);
    p_Var1 = _onexit(FUN_1800081d0);
    return (p_Var1 != (_onexit_t)0x0) - 1;
}

undefined8 FUN_180001120(HMODULE param_1, int param_2)

{
    DWORD DVar1;
    uint nSize;
    LPSTR local_res20;

    if (param_2 != 0)
    {
        if (param_2 == 1)
        {
            DisableThreadLibraryCalls(param_1);
            nSize = 0x80;
            local_res20 = (LPSTR)0x0;
            do
            {
                nSize = nSize * 2;
                RTStrReallocTag(&local_res20, (longlong)(int)nSize, "h:\\gpu\\fastpipe-6.1.36\\main.cpp");
                DVar1 = GetModuleFileNameA(param_1, local_res20, nSize);
            } while (nSize <= DVar1);
            RTPathStripFilename(local_res20);
            DAT_18000d840 = local_res20;
            return 1;
        }
        if (1 < param_2 - 2U)
        {
            return 1;
        }
    }
    RTStrFree(DAT_18000d840);
    DAT_18000d840 = (LPSTR)0x0;
    return 1;
}

undefined *FUN_1800011e0(void)

{
    return &DAT_180013a10;
}

// Library Function - Single Match
//  snprintf
//
// Library: Visual Studio 2019 Release

int snprintf(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4)

{
    int iVar1;
    ulonglong *puVar2;
    undefined8 local_res20;

    local_res20 = param_4;
    puVar2 = (ulonglong *)FUN_1800011e0();
    iVar1 = __stdio_common_vsprintf(*puVar2 | 1, param_1, param_2, param_3, 0, &local_res20);
    if (iVar1 < 0)
    {
        iVar1 = -1;
    }
    return iVar1;
}

void FUN_180001250(int param_1, undefined8 param_2, char *param_3, undefined4 param_4)

{
    char *pcVar1;
    undefined auStack1112[32];
    char *local_438;
    undefined4 local_430;
    CHAR local_428[1023];
    undefined local_29;
    ulonglong local_28;

    if (param_1 == 0)
    {
        local_28 = DAT_18000d010 ^ (ulonglong)auStack1112;
        pcVar1 = strrchr(param_3, 0x5c);
        if (pcVar1 != (char *)0x0)
        {
            param_3 = pcVar1 + 1;
        }
        local_438 = param_3;
        local_430 = param_4;
        snprintf(local_428, 0x3ff, "%s %s:%d", param_2);
        local_29 = 0;
        MessageBoxA((HWND)0x0, local_428, "Error", 0);
        FUN_180006f40(local_28 ^ (ulonglong)auStack1112);
    }
    return;
}

undefined4 FUN_180001300(longlong param_1)

{
    return *(undefined4 *)(param_1 + 8);
}

void FUN_180001310(longlong param_1, longlong *param_2)

{
    int *piVar1;
    bool bVar2;
    char cVar3;
    uint uVar4;
    longlong lVar5;
    longlong lVar6;
    undefined auStack3208[32];
    char *local_c68;
    undefined4 local_c60;
    char local_c58[8];
    undefined local_c50[4];
    int local_c4c;
    int local_c48;
    CHAR local_c38[1023];
    undefined local_839;
    CHAR local_838[1023];
    undefined local_439;
    CHAR local_438[1023];
    undefined local_39;
    ulonglong local_38;

    piVar1 = *(int **)(param_1 + 0x10);
    local_38 = DAT_18000d010 ^ (ulonglong)auStack3208;
    FUN_180006e70((longlong)param_2, 0);
    if (piVar1[2] != 0)
    {
        local_c68 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
        if (local_c68 == (char *)0x0)
        {
            local_c68 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
        }
        else
        {
            local_c68 = local_c68 + 1;
        }
        local_c60 = 0x133;
        snprintf(local_c38, 0x3ff, "%s %s:%d", "!m_bUseBufRefMode");
        local_839 = 0;
        MessageBoxA((HWND)0x0, local_c38, "Error", 0);
        if (piVar1[2] != 0)
            goto LAB_1800065c9;
    }
    cVar3 = FUN_180001b20(piVar1);
    if (cVar3 != '\0')
    {
        do
        {
            lVar5 = FUN_180002260(piVar1);
            if (*(int *)(lVar5 + 4) != 0)
            {
                lVar6 = FUN_180002330(piVar1);
                if (lVar6 == 0)
                {
                    local_c68 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                    if (local_c68 == (char *)0x0)
                    {
                        local_c68 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                    }
                    else
                    {
                        local_c68 = local_c68 + 1;
                    }
                    local_c60 = 0x143;
                    snprintf(local_838, 0x3ff, "%s %s:%d", "pRingBuf != NULL");
                    local_439 = 0;
                    MessageBoxA((HWND)0x0, local_838, "Error", 0);
                }
                if ((*(uint *)(lVar6 + 8) & 3) != 0)
                {
                    local_c68 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                    if (local_c68 == (char *)0x0)
                    {
                        local_c68 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                    }
                    else
                    {
                        local_c68 = local_c68 + 1;
                    }
                    local_c60 = 0x144;
                    snprintf(local_438, 0x3ff, "%s %s:%d", "(pRingBuf->dataStartPos & 3) == 0");
                    local_39 = 0;
                    MessageBoxA((HWND)0x0, local_438, "Error", 0);
                }
                if ((0 < *(int *)(lVar6 + 0xc)) && (0xc < *(uint *)(lVar6 + 0xc)))
                {
                    FUN_1800056e0(lVar6, local_c50, 0xc);
                    *(int *)(lVar6 + 8) = *(int *)(lVar6 + 8) + 0xc;
                    uVar4 = *(uint *)(lVar6 + 8) & 0x800fffff;
                    if ((int)uVar4 < 0)
                    {
                        uVar4 = (uVar4 - 1 | 0xfff00000) + 1;
                    }
                    *(uint *)(lVar6 + 8) = uVar4;
                    *(int *)(lVar6 + 0xc) = *(int *)(lVar6 + 0xc) + -0xc;
                    FUN_180001d50(piVar1);
                    lVar5 = FUN_180006ca0((longlong)param_2, local_c4c);
                    cVar3 = FUN_180005800(piVar1, lVar5, local_c4c);
                    if (cVar3 != '\0')
                    {
                        FUN_180006e70((longlong)param_2, local_c48);
                    }
                    break;
                }
            }
            *(undefined4 *)(lVar5 + 0xc) = 1;
            FUN_180002530(piVar1);
            FUN_180001d50(piVar1);
            local_c58[0] = '\0';
            cVar3 = FUN_180001fe0(piVar1, *(HANDLE *)(&DAT_18000d8c8 + (longlong)*piVar1 * 0x18), local_c58);
            if ((cVar3 == '\0') || (local_c58[0] != '\0'))
            {
                bVar2 = false;
            }
            else
            {
                bVar2 = true;
            }
            *(undefined4 *)(lVar5 + 0xc) = 0;
            if ((!bVar2) || (cVar3 = FUN_180001b20(piVar1), cVar3 == '\0'))
                break;
        } while (true);
    }
    (**(code **)(*param_2 + 0x18))(param_2);
LAB_1800065c9:
    FUN_180006f40(local_38 ^ (ulonglong)auStack3208);
    return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180001320(longlong param_1, longlong **param_2)

{
    int *piVar1;
    bool bVar2;
    int iVar3;
    char cVar4;
    uint uVar5;
    longlong lVar6;
    longlong lVar7;
    void *_Memory;
    undefined auStack3224[32];
    char *local_c78;
    undefined4 local_c70;
    char local_c68[8];
    undefined local_c60[4];
    int local_c5c;
    int local_c58;
    int local_c50;
    int local_c4c;
    int local_c48;
    CHAR local_c38[1023];
    undefined local_839;
    CHAR local_838[1023];
    undefined local_439;
    CHAR local_438[1023];
    undefined local_39;
    ulonglong local_38;

    piVar1 = *(int **)(param_1 + 0x10);
    local_38 = DAT_18000d010 ^ (ulonglong)auStack3224;
    *param_2 = (longlong *)0x0;
    cVar4 = FUN_180001b20(piVar1);
    do
    {
        if (cVar4 == '\0')
        {
        LAB_180005eff:
            FUN_180006f40(local_38 ^ (ulonglong)auStack3224);
            return;
        }
        lVar6 = FUN_180002260(piVar1);
        if (*(int *)(lVar6 + 4) != 0)
        {
            lVar7 = FUN_180002330(piVar1);
            if (lVar7 == 0)
            {
                local_c78 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                if (local_c78 == (char *)0x0)
                {
                    local_c78 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                }
                else
                {
                    local_c78 = local_c78 + 1;
                }
                local_c70 = 0x9f;
                snprintf(local_c38, 0x3ff, "%s %s:%d", "pRingBuf != NULL");
                local_839 = 0;
                MessageBoxA((HWND)0x0, local_c38, "Error", 0);
            }
            if ((*(uint *)(lVar7 + 8) & 3) != 0)
            {
                local_c78 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                if (local_c78 == (char *)0x0)
                {
                    local_c78 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                }
                else
                {
                    local_c78 = local_c78 + 1;
                }
                local_c70 = 0xa0;
                snprintf(local_838, 0x3ff, "%s %s:%d", "(pRingBuf->dataStartPos & 3) == 0");
                local_439 = 0;
                MessageBoxA((HWND)0x0, local_838, "Error", 0);
            }
            if (0xc < *(uint *)(lVar7 + 0xc))
            {
                FUN_1800056e0(lVar7, &local_c50, 0xc);
                if (((longlong)local_c4c + 0xcU <= (ulonglong)(longlong) * (int *)(lVar7 + 0xc)) &&
                    ((ulonglong)((longlong)local_c4c + 0xc + (longlong) * (int *)(lVar7 + 8)) < 0x100001))
                {
                    lVar6 = FUN_180002170(lVar7);
                    *(longlong *)(piVar1 + 4) = lVar6 + 0xc + (longlong) * (int *)(lVar7 + 8);
                    piVar1[6] = local_c48;
                    if (local_c50 != 0x19810202)
                    {
                        local_c78 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                        if (local_c78 == (char *)0x0)
                        {
                            local_c78 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                        }
                        else
                        {
                            local_c78 = local_c78 + 1;
                        }
                        local_c70 = 0xb0;
                        snprintf(local_438, 0x3ff, "%s %s:%d", "head.verify == 0x19810202");
                        local_39 = 0;
                        MessageBoxA((HWND)0x0, local_438, "Error", 0);
                    }
                    *param_2 = (longlong *)(piVar1 + 4);
                    piVar1[8] = 1;
                    FUN_180001d50(piVar1);
                    goto LAB_180005eff;
                }
            }
            if ((0 < *(int *)(lVar7 + 0xc)) && (0xc < *(uint *)(lVar7 + 0xc)))
            {
                FUN_1800056e0(lVar7, local_c60, 0xc);
                *(int *)(lVar7 + 8) = *(int *)(lVar7 + 8) + 0xc;
                uVar5 = *(uint *)(lVar7 + 8) & 0x800fffff;
                if ((int)uVar5 < 0)
                {
                    uVar5 = (uVar5 - 1 | 0xfff00000) + 1;
                }
                *(uint *)(lVar7 + 8) = uVar5;
                *(int *)(lVar7 + 0xc) = *(int *)(lVar7 + 0xc) + -0xc;
                FUN_180001d50(piVar1);
                iVar3 = DAT_1800139fc;
                uVar5 = local_c5c + 0xfffffU & 0xfff00000;
                if (((int)uVar5 < 0x4000001) && (DAT_1800139fc = 1, iVar3 == 0))
                {
                    if (((int)_DAT_180013a08 < (int)uVar5) ||
                        (_Memory = DAT_180013a00, DAT_180013a00 == (void *)0x0))
                    {
                        _Memory = operator_new((longlong)(int)uVar5);
                        if (_Memory == (void *)0x0)
                        {
                            DAT_1800139fc = 0;
                            _Memory = (void *)0x0;
                        }
                        else
                        {
                            free(DAT_180013a00);
                            DAT_180013a00 = _Memory;
                            _DAT_180013a08 = uVar5;
                        }
                    }
                }
                else
                {
                    _Memory = operator_new((longlong)(int)uVar5);
                }
                cVar4 = FUN_180005800(piVar1, (longlong)_Memory, local_c5c);
                if (cVar4 == '\0')
                {
                    if ((_Memory == (void *)0x0) || (_Memory != DAT_180013a00))
                    {
                        free(_Memory);
                    }
                    else
                    {
                        DAT_1800139fc = 0;
                    }
                }
                else
                {
                    *(void **)(piVar1 + 4) = _Memory;
                    piVar1[6] = local_c58;
                    *param_2 = (longlong *)(piVar1 + 4);
                    piVar1[8] = 0;
                }
                goto LAB_180005eff;
            }
        }
        *(undefined4 *)(lVar6 + 0xc) = 1;
        FUN_180002530(piVar1);
        FUN_180001d50(piVar1);
        local_c68[0] = '\0';
        cVar4 = FUN_180001fe0(piVar1, *(HANDLE *)(&DAT_18000d8c8 + (longlong)*piVar1 * 0x18), local_c68);
        if ((cVar4 == '\0') || (local_c68[0] != '\0'))
        {
            bVar2 = false;
        }
        else
        {
            bVar2 = true;
        }
        *(undefined4 *)(lVar6 + 0xc) = 0;
        if (!bVar2)
            goto LAB_180005eff;
        cVar4 = FUN_180001b20(piVar1);
    } while (true);
}

// WARNING: Function: _alloca_probe replaced with injection: alloca_probe

void FUN_180001330(longlong param_1, void **param_2)

{
    int *piVar1;
    void *_Memory;
    bool bVar2;
    char cVar3;
    uint uVar4;
    longlong lVar5;
    longlong lVar6;
    bool bVar7;
    undefined auStack4208[32];
    char *local_1050;
    undefined4 local_1048;
    int local_1040;
    int local_103c;
    CHAR local_1030[1023];
    undefined local_c31;
    CHAR local_c30[1023];
    undefined local_831;
    CHAR local_830[1023];
    undefined local_431;
    CHAR local_430[1023];
    undefined local_31;
    ulonglong local_30;

    piVar1 = *(int **)(param_1 + 0x10);
    local_30 = DAT_18000d010 ^ (ulonglong)auStack4208;
    if (param_2 != (void **)(piVar1 + 4))
    {
        local_1050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
        if (local_1050 == (char *)0x0)
        {
            local_1050 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
        }
        else
        {
            local_1050 = local_1050 + 1;
        }
        local_1048 = 0xf3;
        snprintf(local_1030, 0x3ff, "%s %s:%d", "pReadBufRef == &m_ReadBufRef");
        local_c31 = 0;
        MessageBoxA((HWND)0x0, local_1030, "Error", 0);
    }
    bVar2 = false;
    bVar7 = false;
    if (piVar1[8] == 0)
    {
        _Memory = *(void **)(piVar1 + 4);
        if ((_Memory == (void *)0x0) || (_Memory != DAT_180013a00))
        {
            free(_Memory);
        }
        else
        {
            DAT_1800139fc = 0;
        }
    }
    else
    {
        cVar3 = FUN_180001b20(piVar1);
        if (cVar3 != '\0')
        {
            lVar5 = FUN_180002260(piVar1);
            lVar6 = FUN_180002330(piVar1);
            if (lVar6 == 0)
            {
                local_1050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                if (local_1050 == (char *)0x0)
                {
                    local_1050 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                }
                else
                {
                    local_1050 = local_1050 + 1;
                }
                local_1048 = 0xfe;
                snprintf(local_c30, 0x3ff, "%s %s:%d", "pRingBuf != NULL");
                local_831 = 0;
                MessageBoxA((HWND)0x0, local_c30, "Error", 0);
            }
            FUN_1800056e0(lVar6, &local_1040, 0xc);
            if (local_1040 != 0x19810202)
            {
                local_1050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                if (local_1050 == (char *)0x0)
                {
                    local_1050 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                }
                else
                {
                    local_1050 = local_1050 + 1;
                }
                local_1048 = 0x102;
                snprintf(local_830, 0x3ff, "%s %s:%d", "head.verify == 0x19810202");
                local_431 = 0;
                MessageBoxA((HWND)0x0, local_830, "Error", 0);
            }
            *(int *)(lVar6 + 8) = *(int *)(lVar6 + 8) + 0xc;
            *(int *)(lVar6 + 8) = *(int *)(lVar6 + 8) + local_103c;
            uVar4 = *(uint *)(lVar6 + 8) & 0x800fffff;
            if ((int)uVar4 < 0)
            {
                uVar4 = (uVar4 - 1 | 0xfff00000) + 1;
            }
            *(uint *)(lVar6 + 8) = uVar4;
            *(int *)(lVar6 + 0xc) = *(int *)(lVar6 + 0xc) + -0xc;
            *(int *)(lVar6 + 0xc) = *(int *)(lVar6 + 0xc) - local_103c;
            if (*(int *)(lVar6 + 0xc) < 0)
            {
                local_1050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                if (local_1050 == (char *)0x0)
                {
                    local_1050 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                }
                else
                {
                    local_1050 = local_1050 + 1;
                }
                local_1048 = 0x10a;
                snprintf(local_430, 0x3ff, "%s %s:%d", "pRingBuf->dataLen >= 0");
                local_31 = 0;
                MessageBoxA((HWND)0x0, local_430, "Error", 0);
            }
            bVar7 = *(int *)(lVar5 + 8) != 0;
            if (*(int *)(lVar6 + 0xc) == 0)
            {
                FUN_180001250((uint)(*(int *)(lVar6 + 4) == 0), "pRingBuf->prepareWriteDontFree == 0",
                              "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x113);
                bVar2 = false;
                if (*(int *)(lVar6 + 4) == 0)
                {
                    bVar2 = true;
                }
            }
            FUN_180001d50(piVar1);
        }
    }
    *(undefined8 *)(piVar1 + 4) = 0;
    piVar1[6] = 0;
    piVar1[8] = 0;
    if (bVar2)
    {
        FUN_180003be0();
    }
    if (bVar7)
    {
        FUN_180002680(piVar1);
    }
    FUN_180006f40(local_30 ^ (ulonglong)auStack4208);
    return;
}

// WARNING: Function: _alloca_probe replaced with injection: alloca_probe

void FUN_180001340(longlong param_1, longlong param_2, int param_3)

{
    undefined4 uVar1;
    int *piVar2;
    bool bVar3;
    bool bVar4;
    char cVar5;
    int iVar6;
    int iVar7;
    BOOL BVar8;
    longlong lVar9;
    longlong lVar10;
    uint uVar11;
    uint uVar12;
    uint uVar13;
    undefined auStack6320[32];
    char *local_1890;
    undefined4 local_1888;
    char local_1880[4];
    uint local_187c;
    int local_1878;
    undefined4 local_1874[3];
    longlong local_1868;
    undefined4 local_1860;
    uint local_185c;
    int local_1858;
    CHAR local_1850[1031];
    undefined local_1449;
    CHAR local_1448[1023];
    undefined local_1049;
    CHAR local_1048[1023];
    undefined local_c49;
    CHAR local_c48[1023];
    undefined local_849;
    CHAR local_848[1023];
    undefined local_449;
    CHAR local_448[1023];
    undefined local_49;
    ulonglong local_48;

    piVar2 = *(int **)(param_1 + 0x18);
    local_48 = DAT_18000d010 ^ (ulonglong)auStack6320;
    local_1878 = param_3;
    local_1868 = param_2;
    if (param_3 < 1)
    {
        local_1890 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp", 0x5c);
        if (local_1890 == (char *)0x0)
        {
            local_1890 = "h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp";
        }
        else
        {
            local_1890 = local_1890 + 1;
        }
        local_1888 = 5;
        snprintf(local_1850, 0x3ff, "%s %s:%d", "len > 0");
        local_1449 = 0;
        MessageBoxA((HWND)0x0, local_1850, "Error", 0);
    }
    else
    {
        uVar11 = 0;
        uVar12 = param_3 + 3U & 0xfffffffc;
        uVar13 = 0;
        local_187c = 0;
        local_1874[0] = 0;
        local_1860 = 0x19810202;
        local_185c = uVar12;
        local_1858 = param_3;
        cVar5 = FUN_180001b20(piVar2);
        if (cVar5 != '\0')
        {
            do
            {
                lVar9 = FUN_180002260(piVar2);
                if (*(int *)(lVar9 + 4) == 0)
                {
                    FUN_180001d50(piVar2);
                    cVar5 = FUN_180003230(piVar2);
                    if ((cVar5 == '\0') || (cVar5 = FUN_180001b20(piVar2), cVar5 == '\0'))
                        break;
                }
                lVar10 = FUN_180002330(piVar2);
                if (lVar10 == 0)
                {
                    local_1890 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp", 0x5c);
                    if (local_1890 == (char *)0x0)
                    {
                        local_1890 = "h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp";
                    }
                    else
                    {
                        local_1890 = local_1890 + 1;
                    }
                    local_1888 = 0x2e;
                    snprintf(local_1448, 0x3ff, "%s %s:%d", "pRingBuf != NULL");
                    local_1049 = 0;
                    MessageBoxA((HWND)0x0, local_1448, "Error", 0);
                }
                if ((*(uint *)(lVar10 + 8) & 3) != 0)
                {
                    local_1890 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp", 0x5c);
                    if (local_1890 == (char *)0x0)
                    {
                        local_1890 = "h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp";
                    }
                    else
                    {
                        local_1890 = local_1890 + 1;
                    }
                    local_1888 = 0x2f;
                    snprintf(local_1048, 0x3ff, "%s %s:%d", "(pRingBuf->dataStartPos & 3) == 0");
                    local_c49 = 0;
                    MessageBoxA((HWND)0x0, local_1048, "Error", 0);
                }
                if ((*(uint *)(lVar10 + 0xc) & 3) != 0)
                {
                    local_1890 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp", 0x5c);
                    if (local_1890 == (char *)0x0)
                    {
                        local_1890 = "h:\\gpu\\fastpipe-6.1.36\\pipewriter.cpp";
                    }
                    else
                    {
                        local_1890 = local_1890 + 1;
                    }
                    local_1888 = 0x30;
                    snprintf(local_c48, 0x3ff, "%s %s:%d", "(pRingBuf->dataLen & 3) == 0");
                    local_849 = 0;
                    MessageBoxA((HWND)0x0, local_c48, "Error", 0);
                }
                bVar3 = false;
                if (uVar11 < 0xc)
                {
                    iVar6 = FUN_1800065f0(lVar10, (void *)((longlong)&local_1860 + (longlong)(int)uVar11),
                                          0xc - uVar11);
                    bVar3 = 0 < iVar6;
                    if (bVar3)
                    {
                        uVar11 = uVar11 + iVar6;
                        *(int *)(lVar10 + 0xc) = *(int *)(lVar10 + 0xc) + iVar6;
                        local_187c = uVar11;
                    }
                }
                iVar6 = local_1878;
                if (uVar11 == 0xc)
                {
                    if ((int)uVar13 < local_1878)
                    {
                        iVar7 = FUN_1800065f0(lVar10, (void *)((int)uVar13 + local_1868), local_1878 - uVar13);
                        if (0 < iVar7)
                        {
                            bVar3 = true;
                            *(int *)(lVar10 + 0xc) = *(int *)(lVar10 + 0xc) + iVar7;
                            uVar13 = uVar13 + iVar7;
                        }
                        if ((int)uVar13 < iVar6)
                            goto LAB_180006a65;
                    }
                    if (((int)uVar13 < (int)uVar12) &&
                        (iVar6 = FUN_1800065f0(lVar10, local_1874, uVar12 - uVar13), 0 < iVar6))
                    {
                        bVar3 = true;
                        *(int *)(lVar10 + 0xc) = *(int *)(lVar10 + 0xc) + iVar6;
                        uVar13 = uVar13 + iVar6;
                    }
                }
            LAB_180006a65:
                bVar4 = false;
                if (bVar3)
                {
                    *(undefined4 *)(lVar10 + 4) = 0;
                    bVar4 = false;
                    if (*(int *)(lVar9 + 0xc) != 0)
                    {
                        bVar4 = true;
                    }
                }
                if (uVar13 == uVar12)
                {
                    uVar1 = *(undefined4 *)(DAT_1800139e8 + 4);
                    *(int *)(DAT_1800139e8 + 4) = *(int *)(DAT_1800139e8 + 4) + 1;
                    *(undefined4 *)(lVar10 + 0x10) = uVar1;
                    FUN_180001d50(piVar2);
                    if (bVar4)
                    {
                        FUN_180002790(piVar2);
                    }
                    break;
                }
                *(undefined4 *)(lVar9 + 8) = 1;
                iVar6 = *piVar2;
                if (0x3fe < iVar6 - 1U)
                {
                    local_1890 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_1890 == (char *)0x0)
                    {
                        local_1890 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_1890 = local_1890 + 1;
                    }
                    local_1888 = 0x1ed;
                    snprintf(local_848, 0x3ff, "%s %s:%d",
                             "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
                    local_449 = 0;
                    MessageBoxA((HWND)0x0, local_848, "Error", 0);
                    iVar6 = *piVar2;
                }
                if ((iVar6 - 1U < 0x3ff) &&
                    (BVar8 = ResetEvent(*(HANDLE *)(&DAT_18000d8c0 + (longlong)iVar6 * 0x18)), BVar8 == 0))
                {
                    local_1890 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_1890 == (char *)0x0)
                    {
                        local_1890 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_1890 = local_1890 + 1;
                    }
                    local_1888 = 0x1f2;
                    snprintf(local_448, 0x3ff, "%s %s:%d", &DAT_1800093dc);
                    local_49 = 0;
                    MessageBoxA((HWND)0x0, local_448, "Error", 0);
                }
                FUN_180001d50(piVar2);
                if (bVar4)
                {
                    FUN_180002790(piVar2);
                }
                local_1880[0] = '\0';
                cVar5 = FUN_180001fe0(piVar2, *(HANDLE *)(&DAT_18000d8c0 + (longlong)*piVar2 * 0x18),
                                      local_1880);
                if ((cVar5 == '\0') || (local_1880[0] != '\0'))
                {
                    bVar3 = false;
                }
                else
                {
                    bVar3 = true;
                }
                *(undefined4 *)(lVar9 + 8) = 0;
                if ((!bVar3) || (cVar5 = FUN_180001b20(piVar2), uVar11 = local_187c, cVar5 == '\0'))
                    break;
            } while (true);
        }
    }
    FUN_180006f40(local_48 ^ (ulonglong)auStack6320);
    return;
}

void FUN_180001350(longlong *param_1)

{
    if (param_1 != (longlong *)0x0)
    {
        // WARNING: Could not recover jumptable at 0x00018000135d. Too many branches
        // WARNING: Treating indirect jump as call
        (**(code **)(*param_1 + 0x30))(param_1, 1);
        return;
    }
    return;
}

void FUN_180001370(undefined8 *param_1, uint param_2)

{
    int *piVar1;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    piVar1 = (int *)param_1[2];
    *param_1 = CFastPipeImpl::vftable;
    if (piVar1 != (int *)0x0)
    {
        if ((*(longlong *)(piVar1 + 4) != 0) || (piVar1[8] != 0))
        {
            local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.h", 0x5c);
            if (local_428 == (char *)0x0)
            {
                local_428 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.h";
            }
            else
            {
                local_428 = local_428 + 1;
            }
            local_420 = 0x17;
            snprintf(local_418, 0x3ff, "%s %s:%d", &DAT_1800093dc);
            local_19 = 0;
            MessageBoxA((HWND)0x0, local_418, "Error", 0);
        }
        FUN_180003590(piVar1);
        *piVar1 = 0;
        free(piVar1);
    }
    piVar1 = (int *)param_1[3];
    if (piVar1 != (int *)0x0)
    {
        FUN_180003590(piVar1);
        *piVar1 = 0;
        free(piVar1);
    }
    param_1[2] = 0;
    param_1[3] = 0;
    if ((param_2 & 1) != 0)
    {
        free(param_1);
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)

{
    // WARNING: Could not recover jumptable at 0x0001800014b0. Too many branches
    // WARNING: Treating indirect jump as call
    DeleteCriticalSection(lpCriticalSection);
    return;
}

// WARNING: Function: _alloca_probe replaced with injection: alloca_probe
// WARNING: Could not reconcile some variable overlaps

void FUN_1800014c0(char *param_1)

{
    code *pcVar1;
    int iVar2;
    DWORD DVar3;
    ulonglong uVar4;
    code **ppcVar5;
    undefined auStack67696[32];
    undefined8 uStack67664;
    undefined8 uStack67656;
    uint auStack67648[2];
    HANDLE pvStack67640;
    undefined8 uStack67632;
    CHAR aCStack67616[1023];
    undefined uStack66593;
    CHAR aCStack66592[1023];
    undefined uStack65569;
    undefined auStack65568[65560];

    uVar4 = DAT_18000d010 ^ (ulonglong)auStack67696;
    pvStack67640 = *(HANDLE *)(param_1 + 8);
    uStack67632 = DAT_1800139f0;
    DVar3 = WaitForMultipleObjects(2, &pvStack67640, 0, 0xffffffff);
    while (DVar3 == 0)
    {
        if (*param_1 != '\0')
            goto LAB_180001716;
        ppcVar5 = (code **)(param_1 + 0x38);
        auStack67648[0] = 0;
        pcVar1 = *ppcVar5;
        while (pcVar1 != (code *)0x0)
        {
            uStack67656 = auStack67648;
            uStack67664 = (char *)CONCAT44((int)((ulonglong)uStack67664 >> 0x20), 0x10000);
            (**ppcVar5)(*(undefined4 *)(DAT_1800139e8 + 0x1c158), DAT_1800139e8 + 0x1c164,
                        *(undefined4 *)(DAT_1800139e8 + 0x1c160), auStack65568);
            ppcVar5 = ppcVar5 + 1;
            pcVar1 = *ppcVar5;
        }
        if (0xffff < auStack67648[0])
        {
            uStack67664 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (uStack67664 == (char *)0x0)
            {
                uStack67664 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                uStack67664 = uStack67664 + 1;
            }
            uStack67656 = (uint *)CONCAT44(uStack67656._4_4_, 0x96);
            snprintf(aCStack67616, 0x3ff, "%s %s:%d", "nReplyLen < sizeof(g_pPipeMemHead->serialToHost.buf)");
            uStack66593 = 0;
            MessageBoxA((HWND)0x0, aCStack67616, "Error", 0);
        }
        *(uint *)(DAT_1800139e8 + 0x1c160) = auStack67648[0];
        if (0 < (int)auStack67648[0])
        {
            memcpy((void *)(DAT_1800139e8 + 0x1c164), auStack65568, (longlong)(int)auStack67648[0]);
        }
        *(undefined4 *)(DAT_1800139e8 + 0x1c15c) = 1;
        iVar2 = DAT_1800139f8;
        DAT_1800139f8 = 1;
        if (iVar2 == 0)
        {
            (**(code **)(*(longlong *)(*(longlong *)(DAT_18000d8b8 + 0x18) + 0x10) + 0x6f8))(*(longlong *)(DAT_18000d8b8 + 0x18), 0, 0, 1);
        }
        DVar3 = WaitForMultipleObjects(2, &pvStack67640, 0, 0xffffffff);
    }
    if (*param_1 == '\0')
    {
        uStack67664 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (uStack67664 == (char *)0x0)
        {
            uStack67664 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            uStack67664 = uStack67664 + 1;
        }
        uStack67656 = (uint *)CONCAT44(uStack67656._4_4_, 0xa0);
        snprintf(aCStack66592, 0x3ff, "%s %s:%d", "m_isStoped");
        uStack65569 = 0;
        MessageBoxA((HWND)0x0, aCStack66592, "Error", 0);
    }
LAB_180001716:
    FUN_180006f40(uVar4 ^ (ulonglong)auStack67696);
    return;
}

void FUN_180001740(undefined8 param_1, undefined4 param_2, void *param_3, int param_4, void *param_5, int param_6)
{
    int iVar1;
    undefined auStack2152[32];
    char *fileName;
    undefined4 local_840;
    HANDLE local_838;
    undefined8 local_830;
    CHAR message[1023];
    undefined local_429;
    CHAR local_428[1023];
    undefined local_29;
    ulonglong local_28;

    local_28 = DAT_18000d010 ^ (ulonglong)auStack2152;
    if (65536 < (ulonglong)(longlong)param_4)
    {
        fileName = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", '\\');
        if (fileName == (char *)0x0)
        {
            fileName = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            fileName = fileName + 1;
        }
        local_840 = 0xa6;
        snprintf(message, 0x3ff, "%s %s:%d", "len <= sizeof(g_pPipeMemHead->serialToGuest.buf)");
        local_429 = 0;
        MessageBoxA((HWND)0x0, message, "Error", 0);
    }
    if (DAT_18000d040 == '\0')
    {
        EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18000d0f8);
        ResetEvent(DAT_18000d120);
        *(undefined4 *)(DAT_1800139e8 + 0xc14c) = param_2;
        memcpy((void *)(DAT_1800139e8 + 0xc158), param_3, (longlong)param_4);
        *(int *)(DAT_1800139e8 + 0xc154) = param_4;
        *(int *)(DAT_1800139e8 + 0xc148) = *(int *)(DAT_1800139e8 + 0xc148) + 1;
        iVar1 = DAT_1800139f8;
        DAT_1800139f8 = 1;
        if (iVar1 == 0)
        {
            (**(code **)(*(longlong *)(*(longlong *)(DAT_18000d8b8 + 0x18) + 0x10) + 0x6f8))(*(longlong *)(DAT_18000d8b8 + 0x18), 0, 0, 1);
        }
        local_838 = DAT_18000d120;
        local_830 = DAT_1800139f0;
        WaitForMultipleObjects(2, &local_838, 0, 0xffffffff);
        if (param_5 != (void *)0)
        {
            if (param_6 < *(int *)(DAT_1800139e8 + 0xc154))
            {
                fileName = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (fileName == (char *)0x0)
                {
                    fileName = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    fileName = fileName + 1;
                }
                local_840 = 0xba;
                snprintf(local_428, 0x3ff, "%s %s:%d", "sizeReplyBuf >= g_pPipeMemHead->serialToGuest.len");
                local_29 = 0;
                MessageBoxA((HWND)0x0, local_428, "Error", 0);
            }
            memcpy(param_5, (void *)(DAT_1800139e8 + 0xc158), (longlong) * (int *)(DAT_1800139e8 + 0xc154));
        }
        LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18000d0f8);
    }
    FUN_180006f40(local_28 ^ (ulonglong)auStack2152);
    return;
}

void FUN_1800019b0(undefined8 param_1, void *param_2, int param_3, void *param_4, int param_5)
{
    FUN_180001740(param_1, (int)param_1, param_2, param_3, param_4, param_5);
    return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800019e0(undefined8 param_1, int param_2)

{
    longlong **pplVar1;
    bool bVar2;
    longlong **pplVar3;
    longlong **_Memory;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    bVar2 = false;
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    _Memory = (longlong **)*DAT_18000d8a0;
    pplVar3 = DAT_18000d8a0;
    if (_Memory != DAT_18000d8a0)
    {
        do
        {
            pplVar1 = (longlong **)*_Memory;
            if (*(int *)(_Memory + 2) == param_2)
            {
                *_Memory[1] = (longlong)pplVar1;
                (*_Memory)[1] = (longlong)_Memory[1];
                _DAT_18000d8a8 = _DAT_18000d8a8 + -1;
                free(_Memory);
                if (bVar2)
                {
                    local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_428 == (char *)0x0)
                    {
                        local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_428 = local_428 + 1;
                    }
                    local_420 = 0x118;
                    snprintf(local_418, 0x3ff, "%s %s:%d", "!bFound");
                    local_19 = 0;
                    MessageBoxA((HWND)0x0, local_418, "Error", 0);
                }
                bVar2 = true;
                pplVar3 = DAT_18000d8a0;
            }
            _Memory = pplVar1;
        } while (pplVar1 != pplVar3);
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_180001b20(int *param_1)

{
    int iVar1;
    longlong lVar2;
    int iVar3;
    undefined auStack3144[32];
    char *local_c28;
    undefined4 local_c20;
    CHAR local_c18[1023];
    undefined local_819;
    CHAR local_818[1023];
    undefined local_419;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack3144;
    iVar1 = *param_1;
    if (0x3fe < iVar1 - 1U)
    {
        local_c28 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_c28 == (char *)0x0)
        {
            local_c28 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_c28 = local_c28 + 1;
        }
        local_c20 = 0x13c;
        snprintf(local_c18, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_819 = 0;
        MessageBoxA((HWND)0x0, local_c18, "Error", 0);
        iVar1 = *param_1;
    }
    iVar3 = 0;
    lVar2 = (longlong)iVar1 * 0x30 + DAT_1800139e8;
    iVar1 = *(int *)(lVar2 + 8);
    *(int *)(lVar2 + 8) = 1;
    do
    {
        if (iVar1 != 1)
        {
        LAB_180001c2a:
            FUN_180006f40(local_18 ^ (ulonglong)auStack3144);
            return;
        }
        if (*(int *)(lVar2 + 0x2c) != param_1[1])
        {
            if (*(int *)(lVar2 + 0x28) == 1)
            {
                local_c28 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (local_c28 == (char *)0x0)
                {
                    local_c28 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    local_c28 = local_c28 + 1;
                }
                local_c20 = 0x144;
                snprintf(local_818, 0x3ff, "%s %s:%d", "pPipeHandle->state != eUsing");
                local_419 = 0;
                MessageBoxA((HWND)0x0, local_818, "Error", 0);
            }
        LAB_180001ccb:
            if (*(int *)(lVar2 + 8) != 1)
            {
                local_c28 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (local_c28 == (char *)0x0)
                {
                    local_c28 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    local_c28 = local_c28 + 1;
                }
                local_c20 = 0x15b;
                snprintf(local_418, 0x3ff, "%s %s:%d", "pPipeHandle->mainLock == 1");
                local_19 = 0;
                MessageBoxA((HWND)0x0, local_418, "Error", 0);
            }
            *(undefined4 *)(lVar2 + 8) = 0;
            goto LAB_180001c2a;
        }
        if (DAT_1800139d8 != '\0')
            goto LAB_180001ccb;
        if (iVar3 == 10)
        {
            SwitchToThread();
        }
        iVar1 = 0;
        if (iVar3 != 10)
        {
            iVar1 = iVar3;
        }
        iVar3 = iVar1 + 1;
        iVar1 = *(int *)(lVar2 + 8);
        *(int *)(lVar2 + 8) = 1;
    } while (true);
}

void FUN_180001d50(int *param_1)

{
    int iVar1;
    longlong lVar2;
    undefined auStack2120[32];
    char *local_828;
    undefined4 local_820;
    CHAR local_818[1023];
    undefined local_419;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack2120;
    iVar1 = *param_1;
    if (0x3fe < iVar1 - 1U)
    {
        local_828 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_828 == (char *)0x0)
        {
            local_828 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_828 = local_828 + 1;
        }
        local_820 = 0x164;
        snprintf(local_818, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_419 = 0;
        MessageBoxA((HWND)0x0, local_818, "Error", 0);
        iVar1 = *param_1;
    }
    lVar2 = (longlong)iVar1 * 0x30 + DAT_1800139e8;
    if (*(int *)(lVar2 + 8) != 1)
    {
        local_828 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_828 == (char *)0x0)
        {
            local_828 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_828 = local_828 + 1;
        }
        local_820 = 0x167;
        snprintf(local_418, 0x3ff, "%s %s:%d", "pPipeHandle->mainLock == 1");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
    }
    *(undefined4 *)(lVar2 + 8) = 0;
    FUN_180006f40(local_18 ^ (ulonglong)auStack2120);
    return;
}

void FUN_180001ea0(int param_1)
{
    longlong lVar1;
    undefined auStack2120[32];
    char *local_828;
    undefined4 local_820;
    CHAR local_818[1023];
    undefined local_419;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack2120;
    if (0x3fe < param_1 - 1U)
    {
        local_828 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_828 == (char *)0x0)
        {
            local_828 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_828 = local_828 + 1;
        }
        local_820 = 0x16e;
        snprintf(local_818, 0x3ff, "%s %s:%d", "nPipeId > 0 && nPipeId < MAX_PIPE_COUNT");
        local_419 = 0;
        MessageBoxA((HWND)0x0, local_818, "Error", 0);
    }
    lVar1 = (longlong)param_1 * 0x30 + DAT_1800139e8;
    if (*(int *)(lVar1 + 8) != 1)
    {
        local_828 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_828 == (char *)0x0)
        {
            local_828 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_828 = local_828 + 1;
        }
        local_820 = 0x171;
        snprintf(local_418, 0x3ff, "%s %s:%d", "pPipeHandle->mainLock == 1");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
    }
    *(undefined4 *)(lVar1 + 8) = 0;
    FUN_180006f40(local_18 ^ (ulonglong)auStack2120);
    return;
}

void FUN_180001fe0(int *param_1, HANDLE param_2, undefined *param_3)

{
    DWORD DVar1;
    int iVar2;
    longlong lVar3;
    undefined auStack1128[32];
    char *local_448;
    undefined4 local_440;
    HANDLE local_438;
    undefined8 local_430;
    CHAR local_428[1023];
    undefined local_29;
    ulonglong local_28;

    local_28 = DAT_18000d010 ^ (ulonglong)auStack1128;
    *param_3 = 1;
    iVar2 = *param_1;
    if (0x3fe < iVar2 - 1U)
    {
        local_448 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_448 == (char *)0x0)
        {
            local_448 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_448 = local_448 + 1;
        }
        local_440 = 0x187;
        snprintf(local_428, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_29 = 0;
        MessageBoxA((HWND)0x0, local_428, "Error", 0);
        iVar2 = *param_1;
    }
    if ((iVar2 - 1U < 0x3ff) &&
        (lVar3 = (longlong)iVar2 * 0x30 + DAT_1800139e8, *(int *)(lVar3 + 0x2c) == param_1[1]))
    {
        local_430 = *(undefined8 *)(&DAT_18000d8d0 + (longlong)*param_1 * 0x18);
        local_438 = param_2;
        DVar1 = WaitForMultipleObjects(2, &local_438, 0, 0xffffffff);
        if ((DVar1 == 0) && (*(int *)(lVar3 + 0x2c) == param_1[1]))
        {
            *param_3 = 0;
        }
        if (*(int *)(lVar3 + 0x2c) != param_1[1])
        {
            FUN_180001250((uint)(*(int *)(DAT_1800139e8 + 0x28 + (longlong)*param_1 * 0x30) != 1),
                          "g_pPipeMemHead->arPipe[pipeDisp.nPipeId].state != eUsing",
                          "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x19c);
        }
    }
    FUN_180006f40(local_28 ^ (ulonglong)auStack1128);
    return;
}

void FUN_180002170(longlong param_1)

{
    int iVar1;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    iVar1 = 1;
    do
    {
        if (param_1 == DAT_1800139e8 + ((longlong)iVar1 + 0x99a) * 0x14)
        {
            if (DAT_1800139e8 + 0x100000 + (longlong)(iVar1 * 0x100000 + -0x100000) != 0)
                goto LAB_180002243;
            break;
        }
        iVar1 = iVar1 + 1;
    } while (iVar1 < 0x10);
    local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
    if (local_428 == (char *)0x0)
    {
        local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
    }
    else
    {
        local_428 = local_428 + 1;
    }
    local_420 = 0x1b1;
    snprintf(local_418, 0x3ff, "%s %s:%d", "ret != NULL");
    local_19 = 0;
    MessageBoxA((HWND)0x0, local_418, "Error", 0);
LAB_180002243:
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_180002260(int *param_1)

{
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    if (0x3fe < *param_1 - 1U)
    {
        local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_428 == (char *)0x0)
        {
            local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_428 = local_428 + 1;
        }
        local_420 = 0x1b7;
        snprintf(local_418, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_180002330(int *param_1)

{
    int iVar1;
    undefined auStack3144[32];
    char *local_c28;
    undefined4 local_c20;
    CHAR local_c18[1023];
    undefined local_819;
    CHAR local_818[1023];
    undefined local_419;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack3144;
    iVar1 = *param_1;
    if (0x3fe < iVar1 - 1U)
    {
        local_c28 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_c28 == (char *)0x0)
        {
            local_c28 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_c28 = local_c28 + 1;
        }
        local_c20 = 0x1c5;
        snprintf(local_c18, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_819 = 0;
        MessageBoxA((HWND)0x0, local_c18, "Error", 0);
        iVar1 = *param_1;
    }
    if (iVar1 - 1U < 0x3ff)
    {
        iVar1 = *(int *)(DAT_1800139e8 + 0xc + (longlong)iVar1 * 0x30);
        if (0xe < iVar1 - 1U)
        {
            local_c28 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_c28 == (char *)0x0)
            {
                local_c28 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_c28 = local_c28 + 1;
            }
            local_c20 = 0x1cb;
            snprintf(local_818, 0x3ff, "%s %s:%d", "nBufId > 0 && nBufId < RING_BUF_COUNT");
            local_419 = 0;
            MessageBoxA((HWND)0x0, local_818, "Error", 0);
        }
        if (*(int *)(((longlong)iVar1 + 0x99a) * 0x14 + DAT_1800139e8) != *param_1)
        {
            local_c28 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_c28 == (char *)0x0)
            {
                local_c28 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_c28 = local_c28 + 1;
            }
            local_c20 = 0x1cc;
            snprintf(local_418, 0x3ff, "%s %s:%d",
                     "g_pPipeMemHead->arBufHead[nBufId].usingPipeId == pipeDisp.nPipeId");
            local_19 = 0;
            MessageBoxA((HWND)0x0, local_418, "Error", 0);
        }
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack3144);
    return;
}

void FUN_180002530(int *param_1)

{
    int iVar1;
    BOOL BVar2;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    iVar1 = *param_1;
    if (0x3fe < iVar1 - 1U)
    {
        local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_428 == (char *)0x0)
        {
            local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_428 = local_428 + 1;
        }
        local_420 = 0x1e3;
        snprintf(local_418, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
        iVar1 = *param_1;
    }
    if (iVar1 - 1U < 0x3ff)
    {
        BVar2 = ResetEvent(*(HANDLE *)(&DAT_18000d8c8 + (longlong)iVar1 * 0x18));
        if (BVar2 == 0)
        {
            local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_428 == (char *)0x0)
            {
                local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_428 = local_428 + 1;
            }
            local_420 = 0x1e8;
            snprintf(local_418, 0x3ff, "%s %s:%d", &DAT_1800093dc);
            local_19 = 0;
            MessageBoxA((HWND)0x0, local_418, "Error", 0);
        }
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_180002680(int *param_1)

{
    int iVar1;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    iVar1 = *param_1;
    if (0x3fe < iVar1 - 1U)
    {
        local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_428 == (char *)0x0)
        {
            local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_428 = local_428 + 1;
        }
        local_420 = 0x1f8;
        snprintf(local_418, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
        iVar1 = *param_1;
    }
    if (iVar1 - 1U < 0x3ff)
    {
        *(undefined4 *)(DAT_1800139e8 + 0x20 + (longlong)iVar1 * 0x30) = 1;
        iVar1 = DAT_1800139f8;
        DAT_1800139f8 = 1;
        if (iVar1 == 0)
        {
            (**(code **)(*(longlong *)(*(longlong *)(DAT_18000d8b8 + 0x18) + 0x10) + 0x6f8))(*(longlong *)(DAT_18000d8b8 + 0x18), 0, 0, 1);
        }
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_180002790(int *param_1)

{
    int iVar1;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    iVar1 = *param_1;
    if (0x3fe < iVar1 - 1U)
    {
        local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_428 == (char *)0x0)
        {
            local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_428 = local_428 + 1;
        }
        local_420 = 0x203;
        snprintf(local_418, 0x3ff, "%s %s:%d", "pipeDisp.nPipeId > 0 && pipeDisp.nPipeId < MAX_PIPE_COUNT");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
        iVar1 = *param_1;
    }
    if (iVar1 - 1U < 0x3ff)
    {
        *(undefined4 *)(DAT_1800139e8 + 0x1c + (longlong)iVar1 * 0x30) = 1;
        iVar1 = DAT_1800139f8;
        DAT_1800139f8 = 1;
        if (iVar1 == 0)
        {
            (**(code **)(*(longlong *)(*(longlong *)(DAT_18000d8b8 + 0x18) + 0x10) + 0x6f8))(*(longlong *)(DAT_18000d8b8 + 0x18), 0, 0, 1);
        }
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_1800028a0(undefined4 *param_1, undefined4 *param_2)

{
    undefined4 uVar1;
    undefined4 uVar2;
    undefined4 uVar3;
    undefined4 uVar4;
    undefined4 uVar5;
    undefined4 uVar6;

    uVar1 = *param_1;
    uVar2 = param_1[1];
    uVar3 = param_1[2];
    uVar4 = param_1[3];
    uVar5 = param_1[4];
    uVar6 = param_1[5];
    *param_1 = *param_2;
    param_1[1] = param_2[1];
    param_1[2] = param_2[2];
    param_1[3] = param_2[3];
    param_1[4] = param_2[4];
    param_1[5] = param_2[5];
    *param_2 = uVar1;
    param_2[1] = uVar2;
    param_2[2] = uVar3;
    param_2[3] = uVar4;
    param_2[4] = uVar5;
    param_2[5] = uVar6;
    return;
}

void FUN_180002920(undefined4 *param_1, ulonglong param_2)

{
    int iVar1;
    undefined4 *puVar2;
    ulonglong uVar3;
    undefined4 *puVar4;
    undefined4 *puVar5;
    int iVar6;
    int iVar7;
    int iVar8;
    ulonglong uVar9;
    ulonglong uVar10;

    iVar8 = (uint)param_2 * 0x18;
    iVar7 = ((int)(param_2 >> 1) + ((uint)param_2 & 0xfffffffe)) * 8 + -0x18;
    if (-1 < iVar7)
    {
        uVar9 = (ulonglong)iVar8;
        uVar10 = (longlong)(iVar7 * 2) + 0x18;
        do
        {
            if (uVar10 < uVar9)
            {
                iVar1 = iVar7;
                do
                {
                    iVar6 = iVar1 * 2 + 0x18;
                    uVar3 = (ulonglong)iVar6;
                    if (((uVar3 < uVar9 - 0x18) &&
                         (*(uint *)(uVar3 + 0x10 + (longlong)param_1) <=
                          *(uint *)(uVar3 + 0x28 + (longlong)param_1))) &&
                        (*(uint *)(uVar3 + 0x10 + (longlong)param_1) <
                         *(uint *)(uVar3 + 0x28 + (longlong)param_1)))
                    {
                        iVar6 = iVar1 * 2 + 0x30;
                    }
                    puVar2 = (undefined4 *)((longlong)iVar1 + (longlong)param_1);
                    puVar4 = (undefined4 *)((longlong)iVar6 + (longlong)param_1);
                    if (((uint)puVar4[4] < (uint)puVar2[4]) || ((uint)puVar4[4] <= (uint)puVar2[4]))
                        break;
                    FUN_1800028a0(puVar2, puVar4);
                    iVar1 = iVar6;
                } while ((longlong)(iVar6 * 2) + 0x18U < uVar9);
            }
            uVar10 = uVar10 - 0x30;
            iVar7 = iVar7 + -0x18;
        } while (-1 < iVar7);
    }
    if (0 < iVar8 + -0x18)
    {
        uVar9 = (ulonglong)(iVar8 + -0x18);
        puVar2 = (undefined4 *)(uVar9 + (longlong)param_1);
        uVar10 = (ulonglong)((iVar8 - 0x19U) / 0x18 + 1);
        do
        {
            FUN_1800028a0(param_1, puVar2);
            if (0x18 < uVar9)
            {
                iVar7 = 0;
                do
                {
                    iVar8 = iVar7 * 2 + 0x18;
                    uVar3 = (ulonglong)iVar8;
                    if (((uVar3 < uVar9 - 0x18) &&
                         (*(uint *)(uVar3 + 0x10 + (longlong)param_1) <=
                          *(uint *)(uVar3 + 0x28 + (longlong)param_1))) &&
                        (*(uint *)(uVar3 + 0x10 + (longlong)param_1) <
                         *(uint *)(uVar3 + 0x28 + (longlong)param_1)))
                    {
                        iVar8 = iVar7 * 2 + 0x30;
                    }
                    puVar4 = (undefined4 *)((longlong)iVar7 + (longlong)param_1);
                    puVar5 = (undefined4 *)((longlong)iVar8 + (longlong)param_1);
                    if (((uint)puVar5[4] < (uint)puVar4[4]) || ((uint)puVar5[4] <= (uint)puVar4[4]))
                        break;
                    FUN_1800028a0(puVar4, puVar5);
                    iVar7 = iVar8;
                } while ((longlong)(iVar8 * 2) + 0x18U < uVar9);
            }
            uVar9 = uVar9 - 0x18;
            puVar2 = puVar2 + -6;
            uVar10 = uVar10 - 1;
        } while (uVar10 != 0);
    }
    return;
}

// WARNING: Function: _alloca_probe replaced with injection: alloca_probe

void FUN_180002ae0(int param_1)

{
    longlong lVar1;
    int iVar2;
    bool bVar3;
    int *piVar4;
    longlong lVar5;
    int iVar6;
    int iVar7;
    longlong lVar8;
    longlong lVar9;
    int *piVar10;
    undefined auStack9728[32];
    char *local_25e0;
    undefined4 local_25d8;
    int local_25d0;
    ulonglong local_25c8;
    undefined4 local_25c0;
    int local_25bc[97];
    CHAR local_2438[1023];
    undefined local_2039;
    CHAR local_2038[1023];
    undefined local_1c39;
    CHAR local_1c38[1023];
    undefined local_1839;
    CHAR local_1838[1023];
    undefined local_1439;
    CHAR local_1438[1023];
    undefined local_1039;
    CHAR local_1038[1023];
    undefined local_c39;
    CHAR local_c38[1023];
    undefined local_839;
    CHAR local_838[1023];
    undefined local_439;
    CHAR local_438[1023];
    undefined local_39;
    ulonglong local_38;
    undefined8 uStack48;

    uStack48 = 0x180002af9;
    local_38 = DAT_18000d010 ^ (ulonglong)auStack9728;
    local_25d0 = param_1;
    if (0x3fe < param_1 - 1U)
    {
        local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_25e0 == (char *)0x0)
        {
            local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_25e0 = local_25e0 + 1;
        }
        local_25d8 = 0x252;
        snprintf(local_2438, 0x3ff, "%s %s:%d", "nPipeId > 0 && nPipeId < MAX_PIPE_COUNT");
        local_2039 = 0;
        MessageBoxA((HWND)0x0, local_2438, "Error", 0);
    }
    lVar8 = 0xc01c;
    iVar6 = 1;
    lVar5 = 0xc01c;
    do
    {
        if (*(int *)(lVar5 + DAT_1800139e8) == param_1)
        {
            local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_25e0 == (char *)0x0)
            {
                local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_25e0 = local_25e0 + 1;
            }
            local_25d8 = 0x259;
            snprintf(local_2038, 0x3ff, "%s %s:%d", "g_pPipeMemHead->arBufHead[i].usingPipeId != nPipeId");
            local_1c39 = 0;
            MessageBoxA((HWND)0x0, local_2038, "Error", 0);
        }
        if (*(int *)(lVar5 + DAT_1800139e8) == 0)
        {
            lVar5 = (longlong)iVar6 * 0x14;
            if (*(int *)(lVar5 + 0xc014 + DAT_1800139e8) != 0)
            {
                local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (local_25e0 == (char *)0x0)
                {
                    local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    local_25e0 = local_25e0 + 1;
                }
                local_25d8 = 0x25d;
                snprintf(local_838, 0x3ff, "%s %s:%d", "g_pPipeMemHead->arBufHead[i].dataLen == 0");
                local_439 = 0;
                MessageBoxA((HWND)0x0, local_838, "Error", 0);
            }
            if (*(int *)(lVar5 + 0xc00c + DAT_1800139e8) != 0)
            {
                local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (local_25e0 == (char *)0x0)
                {
                    local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    local_25e0 = local_25e0 + 1;
                }
                local_25d8 = 0x25e;
                snprintf(local_438, 0x3ff, "%s %s:%d", "g_pPipeMemHead->arBufHead[i].prepareWriteDontFree == 0");
                local_39 = 0;
                MessageBoxA((HWND)0x0, local_438, "Error", 0);
            }
            *(int *)(lVar5 + 0xc008 + DAT_1800139e8) = param_1;
            *(int *)(lVar5 + 0xc00c + DAT_1800139e8) = param_1;
            *(undefined4 *)(lVar5 + 0xc010 + DAT_1800139e8) = 0;
            *(undefined4 *)(lVar5 + 0xc014 + DAT_1800139e8) = 0;
            *(int *)(DAT_1800139e8 + 0xc + (longlong)param_1 * 0x30) = iVar6;
            goto LAB_180003035;
        }
        iVar6 = iVar6 + 1;
        lVar5 = lVar5 + 0x14;
    } while (lVar5 < 0xc148);
    local_25c0 = 0;
    memset(local_25bc, 0, 0x17c);
    iVar7 = 0;
    piVar10 = local_25bc + 4;
    iVar6 = 1;
    do
    {
        if (*(int *)(lVar8 + DAT_1800139e8) == 0)
        {
            local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_25e0 == (char *)0x0)
            {
                local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_25e0 = local_25e0 + 1;
            }
            local_25d8 = 0x277;
            snprintf(local_1c38, 0x3ff, "%s %s:%d", "g_pPipeMemHead->arBufHead[i].usingPipeId != 0");
            local_1839 = 0;
            MessageBoxA((HWND)0x0, local_1c38, "Error", 0);
        }
        if (*(int *)(lVar8 + 0xc + DAT_1800139e8) == 0)
        {
            piVar4 = (int *)(DAT_1800139e8 + lVar8);
            lVar5 = (longlong)iVar7;
            iVar7 = iVar7 + 1;
            local_25bc[lVar5 * 6 + -1] = *piVar4;
            local_25bc[lVar5 * 6] = piVar4[1];
            local_25bc[lVar5 * 6 + 1] = piVar4[2];
            local_25bc[lVar5 * 6 + 2] = piVar4[3];
            local_25bc[lVar5 * 6 + 3] = piVar4[4];
            *piVar10 = iVar6;
            piVar10 = piVar10 + 6;
        }
        iVar6 = iVar6 + 1;
        lVar8 = lVar8 + 0x14;
    } while (iVar6 < 0x10);
    if (0 < iVar7)
    {
        local_25c8 = (ulonglong)iVar7;
        FUN_180002920(&local_25c0, local_25c8);
        if (0 < iVar7)
        {
            piVar10 = local_25bc + 4;
            lVar5 = 0;
            do
            {
                iVar6 = *piVar10;
                if (0xe < iVar6 - 1U)
                {
                    local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_25e0 == (char *)0x0)
                    {
                        local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_25e0 = local_25e0 + 1;
                    }
                    local_25d8 = 0x28a;
                    snprintf(local_1838, 0x3ff, "%s %s:%d",
                             "nRingBufIdTest > 0 && nRingBufIdTest < RING_BUF_COUNT");
                    local_1439 = 0;
                    MessageBoxA((HWND)0x0, local_1838, "Error", 0);
                }
                lVar8 = (longlong)iVar6 * 0x14 + 0xc008;
                iVar7 = *(int *)(DAT_1800139e8 + lVar8);
                lVar9 = (longlong)iVar7;
                if (0x3fe < iVar7 - 1U)
                {
                    local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_25e0 == (char *)0x0)
                    {
                        local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_25e0 = local_25e0 + 1;
                    }
                    local_25d8 = 0x28e;
                    snprintf(local_1438, 0x3ff, "%s %s:%d", "nPipeIdTest > 0 && nPipeIdTest < MAX_PIPE_COUNT");
                    local_1039 = 0;
                    MessageBoxA((HWND)0x0, local_1438, "Error", 0);
                }
                if ((*(int *)(DAT_1800139e8 + 0x28 + lVar9 * 0x30) == 1) ||
                    (*(int *)(DAT_1800139e8 + 0x28 + lVar9 * 0x30) == 2))
                {
                    bVar3 = true;
                }
                else
                {
                    bVar3 = false;
                }
                if (!bVar3)
                {
                    local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_25e0 == (char *)0x0)
                    {
                        local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_25e0 = local_25e0 + 1;
                    }
                    local_25d8 = 0x290;
                    snprintf(local_1038, 0x3ff, "%s %s:%d",
                             "g_pPipeMemHead->arPipe[nPipeIdTest].state == eUsing || g_pPipeMemHead->arPipe[nPipeIdTest].state == eClosing");
                    local_c39 = 0;
                    MessageBoxA((HWND)0x0, local_1038, "Error", 0);
                }
                if (*(int *)(DAT_1800139e8 + 0xc + lVar9 * 0x30) != iVar6)
                {
                    local_25e0 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_25e0 == (char *)0x0)
                    {
                        local_25e0 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_25e0 = local_25e0 + 1;
                    }
                    local_25d8 = 0x291;
                    snprintf(local_c38, 0x3ff, "%s %s:%d",
                             "g_pPipeMemHead->arPipe[nPipeIdTest].ringBufId == nRingBufIdTest");
                    local_839 = 0;
                    MessageBoxA((HWND)0x0, local_c38, "Error", 0);
                }
                piVar4 = (int *)(DAT_1800139e8 + 8 + lVar9 * 0x30);
                iVar2 = *piVar4;
                *piVar4 = 1;
                if (iVar2 == 0)
                {
                    lVar1 = (longlong)iVar6 * 0x14;
                    if ((*(int *)(lVar1 + 0xc014 + DAT_1800139e8) == 0) &&
                        (*(int *)(lVar1 + 0xc00c + DAT_1800139e8) == 0))
                    {
                        *(int *)(DAT_1800139e8 + lVar8) = local_25d0;
                        *(int *)(lVar1 + 0xc00c + DAT_1800139e8) = local_25d0;
                        *(undefined4 *)(lVar1 + 0xc010 + DAT_1800139e8) = 0;
                        *(undefined4 *)(lVar1 + 0xc014 + DAT_1800139e8) = 0;
                        *(undefined4 *)(DAT_1800139e8 + 0xc + lVar9 * 0x30) = 0;
                        *(int *)(DAT_1800139e8 + 0xc + (longlong)local_25d0 * 0x30) = iVar6;
                        FUN_180001ea0(iVar7);
                        break;
                    }
                    FUN_180001ea0(iVar7);
                }
                lVar5 = lVar5 + 1;
                piVar10 = piVar10 + 6;
            } while (lVar5 < (longlong)local_25c8);
        }
    }
LAB_180003035:
    FUN_180006f40(local_38 ^ (ulonglong)auStack9728);
    return;
}

void FUN_180003230(int *param_1)

{
    int iVar1;
    char cVar2;
    DWORD DVar3;
    BOOL BVar4;
    DWORD DVar5;
    longlong lVar6;
    undefined auStack3208[32];
    char *local_c68;
    undefined4 local_c60;
    HANDLE local_c58;
    undefined8 local_c50;
    undefined8 local_c48;
    HANDLE local_c40;
    undefined8 local_c38;
    undefined8 local_c30;
    CHAR local_c28[1023];
    undefined local_829;
    CHAR local_828[1023];
    undefined local_429;
    CHAR local_428[1023];
    undefined local_29;
    ulonglong local_28;

    local_28 = DAT_18000d010 ^ (ulonglong)auStack3208;
    iVar1 = *param_1;
    lVar6 = (longlong)iVar1;
    if (0x3fe < iVar1 - 1U)
    {
        local_c68 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_c68 == (char *)0x0)
        {
            local_c68 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_c68 = local_c68 + 1;
        }
        local_c60 = 0x2be;
        snprintf(local_c28, 0x3ff, "%s %s:%d", "nPipeId > 0 && nPipeId < MAX_PIPE_COUNT");
        local_829 = 0;
        MessageBoxA((HWND)0x0, local_c28, "Error", 0);
        if (0x3fe < iVar1 - 1U)
            goto LAB_180003560;
    }
    local_c58 = DAT_1800139e0;
    local_c50 = DAT_1800139f0;
    local_c48 = *(undefined8 *)(&DAT_18000d8d0 + lVar6 * 0x18);
    DVar3 = WaitForMultipleObjects(3, &local_c58, 0, 0xffffffff);
    if ((DVar3 == 0) && (DAT_1800139d8 == '\0'))
    {
        *DAT_1800139e8 = iVar1;
        EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18000d848);
        if (param_1[1] == DAT_1800139e8[lVar6 * 0xc + 0xb])
        {
            while (true)
            {
                cVar2 = FUN_180002ae0(iVar1);
                if (cVar2 != '\0')
                    break;
                BVar4 = ResetEvent(DAT_1800139c8);
                if (BVar4 == 0)
                {
                    local_c68 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_c68 == (char *)0x0)
                    {
                        local_c68 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_c68 = local_c68 + 1;
                    }
                    local_c60 = 0x2e4;
                    snprintf(local_828, 0x3ff, "%s %s:%d", &DAT_1800093dc);
                    local_429 = 0;
                    MessageBoxA((HWND)0x0, local_828, "Error", 0);
                }
                LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18000d848);
                local_c40 = DAT_1800139c8;
                local_c38 = DAT_1800139f0;
                local_c30 = *(undefined8 *)(&DAT_18000d8d0 + lVar6 * 0x18);
                DVar5 = WaitForMultipleObjects(3, &local_c40, 0, 0xffffffff);
                if (((DVar5 != 0) || (DAT_1800139d8 != '\0')) ||
                    (param_1[1] != DAT_1800139e8[lVar6 * 0xc + 0xb]))
                    goto LAB_180003531;
                if (*DAT_1800139e8 != iVar1)
                {
                    local_c68 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                    if (local_c68 == (char *)0x0)
                    {
                        local_c68 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                    }
                    else
                    {
                        local_c68 = local_c68 + 1;
                    }
                    local_c60 = 0x2f3;
                    snprintf(local_428, 0x3ff, "%s %s:%d", "g_pPipeMemHead->requestWaiting == nPipeId");
                    local_29 = 0;
                    MessageBoxA((HWND)0x0, local_428, "Error", 0);
                }
                EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18000d848);
                if (param_1[1] != DAT_1800139e8[lVar6 * 0xc + 0xb])
                    break;
            }
        }
        LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18000d848);
    LAB_180003531:
        *DAT_1800139e8 = 0;
    }
    if (DVar3 == 0)
    {
        ReleaseMutex(DAT_1800139e0);
    }
LAB_180003560:
    FUN_180006f40(local_28 ^ (ulonglong)auStack3208);
    return;
}

// WARNING: Function: _alloca_probe replaced with injection: alloca_probe

void FUN_180003590(int *param_1)

{
    longlong lVar1;
    int *piVar2;
    int iVar3;
    int iVar4;
    bool bVar5;
    bool bVar6;
    DWORD DVar7;
    DWORD DVar8;
    DWORD DVar9;
    HANDLE pvVar10;
    int iVar11;
    longlong lVar12;
    undefined auStack8304[32];
    char *local_2050;
    undefined4 local_2048;
    CHAR local_2040[1031];
    undefined local_1c39;
    CHAR local_1c38[1023];
    undefined local_1839;
    CHAR local_1838[1023];
    undefined local_1439;
    CHAR local_1438[1023];
    undefined local_1039;
    CHAR local_1038[1023];
    undefined local_c39;
    CHAR local_c38[1023];
    undefined local_839;
    CHAR local_838[1023];
    undefined local_439;
    CHAR local_438[1023];
    undefined local_39;
    ulonglong local_38;

    local_38 = DAT_18000d010 ^ (ulonglong)auStack8304;
    iVar3 = *param_1;
    lVar12 = (longlong)iVar3;
    if (0x3fe < iVar3 - 1U)
    {
        local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_2050 == (char *)0x0)
        {
            local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_2050 = local_2050 + 1;
        }
        local_2048 = 0x306;
        snprintf(local_2040, 0x3ff, "%s %s:%d", "nPipeId > 0 && nPipeId < MAX_PIPE_COUNT");
        local_1c39 = 0;
        MessageBoxA((HWND)0x0, local_2040, "Error", 0);
        if (0x3fe < iVar3 - 1U)
            goto LAB_180003bbd;
    }
    if (*(int *)(DAT_1800139e8 + 0x28 + lVar12 * 0x30) == 0)
    {
        local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_2050 == (char *)0x0)
        {
            local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_2050 = local_2050 + 1;
        }
        local_2048 = 0x30a;
        snprintf(local_1c38, 0x3ff, "%s %s:%d", "g_pPipeMemHead->arPipe[nPipeId].state != eNotUse");
        local_1839 = 0;
        MessageBoxA((HWND)0x0, local_1c38, "Error", 0);
    }
    bVar5 = true;
    DVar7 = GetTickCount();
    DVar8 = GetTickCount();
    iVar11 = 0;
    piVar2 = (int *)(DAT_1800139e8 + 8 + lVar12 * 0x30);
    iVar4 = *piVar2;
    *piVar2 = 1;
    while (iVar4 == 1)
    {
        if (DAT_1800139d8 != '\0')
        {
        LAB_18000377a:
            bVar5 = false;
            break;
        }
        if (iVar11 == 100000)
        {
            DVar9 = GetTickCount();
            if ((1000 < DVar9 - DVar7) && (*(int *)(DAT_1800139e8 + 0x30 + lVar12 * 0x30) != 0))
                goto LAB_18000377a;
            if (10 < DVar9 - DVar8)
            {
                Sleep(100);
                DVar8 = DVar9;
            }
            iVar11 = 0;
        }
        iVar11 = iVar11 + 1;
        piVar2 = (int *)(DAT_1800139e8 + 8 + lVar12 * 0x30);
        iVar4 = *piVar2;
        *piVar2 = 1;
    }
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18000d848);
    lVar1 = lVar12 * 0x18;
    pvVar10 = *(HANDLE *)(&DAT_18000d8c0 + lVar1);
    if (pvVar10 != (HANDLE)0x0)
    {
        if (*(longlong *)(&DAT_18000d8c8 + lVar1) != 0)
        {
            local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_2050 == (char *)0x0)
            {
                local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_2050 = local_2050 + 1;
            }
            local_2048 = 0x332;
            snprintf(local_1838, 0x3ff, "%s %s:%d", "g_arEvent[nPipeId].evRecvEnable == NULL");
            local_1439 = 0;
            MessageBoxA((HWND)0x0, local_1838, "Error", 0);
            pvVar10 = *(HANDLE *)(&DAT_18000d8c0 + lVar1);
        }
        CloseHandle(pvVar10);
        *(undefined8 *)(&DAT_18000d8c0 + lVar1) = 0;
        if (*(longlong *)(&DAT_18000d8d0 + lVar1) == 0)
        {
            local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_2050 == (char *)0x0)
            {
                local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_2050 = local_2050 + 1;
            }
            local_2048 = 0x336;
            snprintf(local_1438, 0x3ff, "%s %s:%d", "g_arEvent[nPipeId].evClose != NULL");
            local_1039 = 0;
            MessageBoxA((HWND)0x0, local_1438, "Error", 0);
        }
        *(undefined8 *)(&DAT_18000d8d0 + lVar1) = 0;
    }
    pvVar10 = *(HANDLE *)(&DAT_18000d8c8 + lVar1);
    if (pvVar10 != (HANDLE)0x0)
    {
        if (*(longlong *)(&DAT_18000d8c0 + lVar1) != 0)
        {
            local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_2050 == (char *)0x0)
            {
                local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_2050 = local_2050 + 1;
            }
            local_2048 = 0x33c;
            snprintf(local_1038, 0x3ff, "%s %s:%d", "g_arEvent[nPipeId].evSendEnable == NULL");
            local_c39 = 0;
            MessageBoxA((HWND)0x0, local_1038, "Error", 0);
            pvVar10 = *(HANDLE *)(&DAT_18000d8c8 + lVar1);
        }
        CloseHandle(pvVar10);
        pvVar10 = *(HANDLE *)(&DAT_18000d8d0 + lVar1);
        *(undefined8 *)(&DAT_18000d8c8 + lVar1) = 0;
        if (pvVar10 == (HANDLE)0x0)
        {
            local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_2050 == (char *)0x0)
            {
                local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_2050 = local_2050 + 1;
            }
            local_2048 = 0x340;
            snprintf(local_c38, 0x3ff, "%s %s:%d", "g_arEvent[nPipeId].evClose != NULL");
            local_839 = 0;
            MessageBoxA((HWND)0x0, local_c38, "Error", 0);
            pvVar10 = *(HANDLE *)(&DAT_18000d8d0 + lVar1);
        }
        CloseHandle(pvVar10);
        *(undefined8 *)(&DAT_18000d8d0 + lVar1) = 0;
    }
    bVar6 = false;
    if (DAT_1800139d8 == '\0')
    {
        if (*(int *)(DAT_1800139e8 + 0xc + lVar12 * 0x30) != 0)
        {
            iVar4 = *(int *)(DAT_1800139e8 + 0xc + lVar12 * 0x30);
            if (0xe < iVar4 - 1U)
            {
                local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (local_2050 == (char *)0x0)
                {
                    local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    local_2050 = local_2050 + 1;
                }
                local_2048 = 0x34c;
                snprintf(local_838, 0x3ff, "%s %s:%d", "ringBufId > 0 && ringBufId < RING_BUF_COUNT");
                local_439 = 0;
                MessageBoxA((HWND)0x0, local_838, "Error", 0);
            }
            lVar1 = (longlong)iVar4 * 0x14 + 0xc008;
            if (*(int *)(lVar1 + DAT_1800139e8) != iVar3)
            {
                local_2050 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
                if (local_2050 == (char *)0x0)
                {
                    local_2050 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
                }
                else
                {
                    local_2050 = local_2050 + 1;
                }
                local_2048 = 0x34d;
                snprintf(local_438, 0x3ff, "%s %s:%d",
                         "g_pPipeMemHead->arBufHead[ringBufId].usingPipeId == nPipeId");
                local_39 = 0;
                MessageBoxA((HWND)0x0, local_438, "Error", 0);
            }
            if (*(int *)(lVar1 + DAT_1800139e8) == iVar3)
            {
                *(undefined4 *)(lVar1 + DAT_1800139e8) = 0;
                lVar1 = (longlong)iVar4 * 0x14;
                *(undefined4 *)(lVar1 + 0xc010 + DAT_1800139e8) = 0;
                *(undefined4 *)(lVar1 + 0xc014 + DAT_1800139e8) = 0;
                *(undefined4 *)(lVar1 + 0xc00c + DAT_1800139e8) = 0;
            }
            bVar6 = true;
            *(undefined4 *)(DAT_1800139e8 + 0xc + lVar12 * 0x30) = 0;
        }
        *(undefined4 *)(DAT_1800139e8 + 0x28 + lVar12 * 0x30) = 0;
        LOCK();
        piVar2 = (int *)(DAT_1800139e8 + 0x2c + lVar12 * 0x30);
        *piVar2 = *piVar2 + 1;
    }
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18000d848);
    if (bVar5)
    {
        FUN_180001d50(param_1);
    }
    if (bVar6)
    {
        FUN_180003be0();
    }
LAB_180003bbd:
    FUN_180006f40(local_38 ^ (ulonglong)auStack8304);
    return;
}

void FUN_180003be0(void)

{
    BOOL BVar1;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    if (*DAT_1800139e8 != 0)
    {
        BVar1 = SetEvent(DAT_1800139c8);
        if (BVar1 == 0)
        {
            local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
            if (local_428 == (char *)0x0)
            {
                local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
            }
            else
            {
                local_428 = local_428 + 1;
            }
            local_420 = 0x370;
            snprintf(local_418, 0x3ff, "%s %s:%d", &DAT_1800093dc);
            local_19 = 0;
            MessageBoxA((HWND)0x0, local_418, "Error", 0);
        }
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

undefined8 FUN_180004890(void)

{
    longlong lVar1;
    undefined4 *in_R9;

    lVar1 = DAT_18000d8b8;
    *in_R9 = 1;
    (**(code **)(*(longlong *)(*(longlong *)(lVar1 + 0x18) + 0x10) + 0x6f8))(*(longlong *)(lVar1 + 0x18), 0, 0, 0);
    DAT_1800139f8 = 0;
    return 0;
}

uint FUN_1800048d0(longlong param_1, undefined8 param_2, undefined8 param_3, ulonglong param_4)

{
    uint uVar1;
    longlong pointerToLoggerInstance;
    char *in_stack_ffffffffffffffd8;
    undefined4 uVar3;

    if (param_4 == 0xffffffffffffffff)
    {
        uVar1 = (**(code **)(*(longlong *)(param_1 + 0x10) + 0x18))(param_1, **(undefined8 **)(param_1 + 0x18));
        if (-1 < (int)uVar1)
        {
            return uVar1;
        }
        pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
        if (pointerToLoggerInstance == 0)
            goto LAB_180004991;
        uVar3 = 0x454;
    }
    else
    {
        uVar1 = (**(code **)(*(longlong *)(param_1 + 0x10) + 0x10))(param_1, **(undefined8 **)(param_1 + 0x18), param_4 & 0xffff);
        if (-1 < (int)uVar1)
        {
            return uVar1;
        }
        pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
        if (pointerToLoggerInstance == 0)
            goto LAB_180004991;
        uVar3 = 0x44f;
    }
    in_stack_ffffffffffffffd8 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
    RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, "AssertLogRel %s(%d) %s: %s\n",
                  "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", uVar3,
                  "int __cdecl myIOPortRegionMap(struct PDMDEVINSR3 *,struct PDMPCIDEV *,unsigned int,unsigned __int64,unsigned __int64,enum PCIADDRESSSPACE)", "RT_SUCCESS_NP(rc)");
LAB_180004991:
    pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
    if (pointerToLoggerInstance != 0)
    {
        RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, "%Rra\n",
                      (ulonglong)in_stack_ffffffffffffffd8 & 0xffffffff00000000 | (ulonglong)uVar1);
    }
    return uVar1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800049d0(void)

{
    DWORD DVar1;
    longlong lVar2;
    longlong **pplVar3;
    uint uVar4;
    longlong lVar5;
    HANDLE *ppvVar6;
    longlong **pplVar7;
    uint uVar8;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    DAT_1800139d8 = 1;
    DAT_18000d040 = 1;
    SetEvent(DAT_1800139f0);
    EnterCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    uVar8 = 0;
    pplVar3 = (longlong **)*DAT_18000d8a0;
    *DAT_18000d8a0 = (longlong *)DAT_18000d8a0;
    DAT_18000d8a0[1] = (longlong *)DAT_18000d8a0;
    _DAT_18000d8a8 = 0;
    if (pplVar3 != DAT_18000d8a0)
    {
        do
        {
            pplVar7 = (longlong **)*pplVar3;
            free(pplVar3);
            pplVar3 = pplVar7;
        } while (pplVar7 != DAT_18000d8a0);
    }
    DAT_18000d870 = 1;
    SetEvent(DAT_18000d8b0);
    LeaveCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    ppvVar6 = (HANDLE *)&DAT_18000d900;
    lVar2 = 0x60;
    lVar5 = 0x3fe;
    do
    {
        *(undefined4 *)(lVar2 + 0x28 + DAT_1800139e8) = 2;
        *(undefined4 *)(lVar2 + 0x30 + DAT_1800139e8) = 1;
        if (*ppvVar6 != (HANDLE)0x0)
        {
            SetEvent(*ppvVar6);
        }
        lVar2 = lVar2 + 0x30;
        ppvVar6 = ppvVar6 + 3;
        lVar5 = lVar5 + -1;
    } while (lVar5 != 0);
    DVar1 = WaitForSingleObject(DAT_1800139d0, 0xffffffff);
    if (DVar1 != 0)
    {
        local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x5c);
        if (local_428 == (char *)0x0)
        {
            local_428 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        }
        else
        {
            local_428 = local_428 + 1;
        }
        local_420 = 0x472;
        snprintf(local_418, 0x3ff, "%s %s:%d",
                 "::WaitForSingleObject(g_hGuestRingBufRequestThread, INFINITE) == WAIT_OBJECT_0");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
    }
    CloseHandle(DAT_1800139d0);
    pplVar3 = (longlong **)&DAT_1800138c0;
    pplVar7 = (longlong **)&DAT_1800138c0;
    uVar4 = uVar8;
    do
    {
        if (*pplVar7 != (longlong *)0x0)
        {
            (**(code **)(**pplVar7 + 8))();
        }
        uVar4 = uVar4 + 1;
        pplVar7 = pplVar7 + 1;
    } while (uVar4 < 0x20);
    do
    {
        if (*pplVar3 != (longlong *)0x0)
        {
            (**(code **)(**pplVar3 + 0x10))();
        }
        uVar8 = uVar8 + 1;
        pplVar3 = pplVar3 + 1;
    } while (uVar8 < 0x20);
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

// WARNING: Could not reconcile some variable overlaps

void LoadLibrary(undefined8 fileName, undefined8 param_2, undefined8 param_3, undefined8 param_4)
{
    char *message;

    undefined auStack1128[32];
    ulonglong local_28;
    local_28 = DAT_18000d010 ^ (ulonglong)auStack1128;

    char *moduleHandle[2];
    moduleHandle[0] = (char *)0x0;
    longlong pointerErrorInfo = RTErrInfoAlloc(0x100);

    char *filePath;
    char *imageFilename;
    imageFilename = (char *)RTPathJoinA(currentDirectory(?), fileName);

    // https://www.virtualbox.org/svn/vbox/trunk/src/VBox/Runtime/common/ldr/ldrNative.cpp
    int loadStatus = RTLdrLoadEx(imageFilename, moduleHandle, 0, pointerErrorInfo);

    // https://www.virtualbox.org/svn/vbox/trunk/include/iprt/log.h
    longlong pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
    if (pointerToLoggerInstance != 0)
    {
        char *logMessage;
        if (loadStatus < 0)
        {
            message = *(char **)(pointerErrorInfo + 16);
            logMessage = "fastpipe: load host failed path=%s, err=%s\n";
            filePath = imageFilename;
        }
        else
        {
            logMessage = "fastpipe: load host successs mod=%p, path=%s\n";
            filePath = moduleHandle[0];
            message = imageFilename;
        }
        RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, logMessage);
    }

    RTStrFree(imageFilename);
    RTErrInfoFree(pointerErrorInfo);

    filePath = strrchr("h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", '\\'); // => \fastpipeapi.cpp
    if (filePath == (char *)0)
    {
        filePath = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
    }
    else
    {
        filePath = filePath + 1;
    }

    pcVar3 = moduleHandle[0];
    if (moduleHandle[0] == (char *)0)
    {
        message = (char *)CONCAT44(message._4_4_, 0x4c4);
        CHAR errorMessage[1023];
        snprintf(errorMessage, 0x3ff, "%s %s:%d", &DAT_1800093dc);
        MessageBoxA((HWND)0x0, errorMessage, "Error", 0);
    }
    else
    {
        // https://www.virtualbox.org/svn/vbox/trunk/src/VBox/Runtime/common/ldr/ldr.cpp
        code *functionPointer;
        functionPointer = (code *)RTLdrGetFunction(moduleHandle[0], "OnLoad");
        if (functionPointer == (code *)0)
        {
            longlong pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
            if (pointerToLoggerInstance != 0)
            {
                message = "OnLoad";
                local_448 = pcVar3;
                RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, "fastpipe: GetFunctionAddr failed mod=%p, lpszFuncName=%s\n");
            }
            message = (char *)CONCAT44(message._4_4_, 0x4bf);
            CHAR errorMessage[1023];
            snprintf(errorMessage, 0x3ff, "%s %s:%d", &DAT_1800093dc);
            MessageBoxA((HWND)0x0, errorMessage, "Error", 0);
        }
        else
        {
            longlong pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx();
            if (pointerToLoggerInstance != 0)
            {
                message = "OnLoad";
                local_448 = pcVar3;
                RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, "fastpipe: GetFunctionAddr success mod=%p, lpszFuncName=%s\n");
            }
            zº = (char *)moduleHandle;
            moduleHandle[0] = (char *)0x0;
            (*functionPointer)(DAT_1800139c0, 0x10000, param_4, FUN_1800019b0);
            if (moduleHandle[0] != (char *)0x0)
            {
                uint index = 0;
                if (DAT_18000d078 != 0)
                {
                    longlong *offset;
                    offset = &DAT_18000d078;
                    index = 0;
                    do
                    {
                        index = index + 1;
                        offset++;
                    } while (*offset != 0);
                    if (14 < index)
                    {
                        goto LAB_180004e80;
                    }
                }
                (&DAT_18000d078)[(int)index] = (longlong)moduleHandle[0];
            }
        }
    }
LAB_180004e80:
    FUN_180006f40(local_28 ^ (ulonglong)auStack1128);
    return;
}

undefined8 VBoxDevicesRegister(uint *param_1, uint param_2)

{
    longlong pointerToLoggerInstance;
    undefined8 uVar2;
    char *in_stack_ffffffffffffffd8;

    // 0x54b0  1  VBoxDevicesRegister
    pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
    if (pointerToLoggerInstance != 0)
    {
        in_stack_ffffffffffffffd8 =
            (char *)((ulonglong)in_stack_ffffffffffffffd8 & 0xffffffff00000000 | (ulonglong)param_2);
        RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20,
                      "fastpipe::VBoxDevicesRegister: u32Version=%#x pCallbacks->u32Version=%#x\n",
                      in_stack_ffffffffffffffd8, *param_1);
    }
    RTEnvSet("VBOX_HWVIRTEX_IGNORE_SVM_IN_USE", &DAT_18000a15c);
    if (*param_1 == 0xffe30010)
    {
        // WARNING: Could not recover jumptable at 0x000180005528. Too many branches
        // WARNING: Treating indirect jump as call
        uVar2 = (**(code **)(param_1 + 2))(param_1, &DAT_18000a220);
        return uVar2;
    }
    pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx(0x200010);
    if (pointerToLoggerInstance != 0)
    {
        in_stack_ffffffffffffffd8 = "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp";
        RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, "AssertLogRel %s(%d) %s: %s\n",
                      "h:\\gpu\\fastpipe-6.1.36\\fastpipeapi.cpp", 0x575,
                      "int __cdecl VBoxDevicesRegister(struct PDMDEVREGCB *,unsigned int)",
                      "pCallbacks->u32Version == PDM_DEVREG_CB_VERSION");
    }
    pointerToLoggerInstance = RTLogRelGetDefaultInstanceEx();
    if (pointerToLoggerInstance != 0)
    {
        RTLogLoggerEx(pointerToLoggerInstance, 0x10, 0x20, "%#x, expected %#x\n",
                      (ulonglong)in_stack_ffffffffffffffd8 & 0xffffffff00000000 | (ulonglong)*param_1,
                      0xffe30010);
    }
    return 0xfffffff5;
}

ulonglong FUN_1800055d0(LPVOID param_1, undefined8 param_2)

{
    HANDLE pvVar1;
    bool bVar2;

    pvVar1 = *(HANDLE *)((longlong)param_1 + 0x10);
    *(undefined8 *)((longlong)param_1 + 0x18) = param_2;
    bVar2 = pvVar1 == (HANDLE)0x0;
    if (bVar2)
    {
        pvVar1 = CreateThread((LPSECURITY_ATTRIBUTES)0x0, 0, (LPTHREAD_START_ROUTINE)&LAB_180005670,
                              param_1, 0, (LPDWORD)((longlong)param_1 + 8));
        *(HANDLE *)((longlong)param_1 + 0x10) = pvVar1;
        bVar2 = pvVar1 == (HANDLE)0x0;
    }
    return (ulonglong)pvVar1 & 0xffffffffffffff00 | (ulonglong)!bVar2;
}

undefined8 *FUN_180005620(undefined8 *param_1, ulonglong param_2)

{
    *param_1 = TThread<class_SerialCall>::vftable;
    if ((HANDLE)param_1[2] != (HANDLE)0x0)
    {
        CloseHandle((HANDLE)param_1[2]);
    }
    param_1[2] = 0;
    *(undefined4 *)(param_1 + 1) = 0;
    if ((param_2 & 1) != 0)
    {
        free(param_1);
    }
    return param_1;
}

void FUN_180005680(undefined8 param_1, void **param_2, void **param_3)

{
    void **ppvVar1;

    ppvVar1 = (void **)operator_new(0x18);
    if (param_2 == (void **)0x0)
    {
        param_2 = ppvVar1;
        param_3 = ppvVar1;
    }
    *ppvVar1 = param_2;
    ppvVar1[1] = param_3;
    return;
}

void FUN_1800056c0(undefined8 param_1, void **param_2, void **param_3, undefined8 *param_4)

{
    longlong lVar1;

    lVar1 = FUN_180005680(param_1, param_2, param_3);
    *(undefined8 *)(lVar1 + 0x10) = *param_4;
    return;
}

void FUN_1800056e0(longlong param_1, void *param_2, int param_3)

{
    void *_Src;
    int iVar1;
    undefined auStack1128[32];
    char *local_448;
    undefined4 local_440;
    CHAR local_438[1023];
    undefined local_39;
    ulonglong local_38;

    local_38 = DAT_18000d010 ^ (ulonglong)auStack1128;
    if ((0x100000 < param_3) || (*(int *)(param_1 + 0xc) < param_3))
    {
        local_448 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.h", 0x5c);
        if (local_448 == (char *)0x0)
        {
            local_448 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.h";
        }
        else
        {
            local_448 = local_448 + 1;
        }
        local_440 = 0x2b;
        snprintf(local_438, 0x3ff, "%s %s:%d", "len <= RING_BUF_SIZE && len <= pRingBuf->dataLen");
        local_39 = 0;
        MessageBoxA((HWND)0x0, local_438, "Error", 0);
    }
    _Src = (void *)FUN_180002170(param_1);
    iVar1 = param_3;
    if (0x100000 - *(int *)(param_1 + 8) <= param_3)
    {
        iVar1 = 0x100000 - *(int *)(param_1 + 8);
    }
    if (0 < iVar1)
    {
        memcpy(param_2, (void *)((longlong) * (int *)(param_1 + 8) + (longlong)_Src), (longlong)iVar1);
    }
    if (iVar1 < param_3)
    {
        memcpy((void *)((longlong)iVar1 + (longlong)param_2), _Src, (longlong)(param_3 - iVar1));
    }
    FUN_180006f40(local_38 ^ (ulonglong)auStack1128);
    return;
}

void FUN_180005800(int *param_1, longlong param_2, int param_3)

{
    bool bVar1;
    char cVar2;
    uint uVar3;
    longlong lVar4;
    longlong lVar5;
    int iVar6;
    int iVar7;
    bool bVar8;
    undefined auStack2184[32];
    char *local_868;
    undefined4 local_860;
    char local_858[16];
    CHAR local_848[1023];
    undefined local_449;
    CHAR local_448[1023];
    undefined local_49;
    ulonglong local_48;

    local_48 = DAT_18000d010 ^ (ulonglong)auStack2184;
    iVar7 = 0;
    cVar2 = FUN_180001b20(param_1);
    do
    {
        if (cVar2 == '\0')
        {
        LAB_180005a42:
            FUN_180006f40(local_48 ^ (ulonglong)auStack2184);
            return;
        }
        lVar4 = FUN_180002260(param_1);
        bVar1 = false;
        bVar8 = false;
        if (*(int *)(lVar4 + 4) != 0)
        {
            lVar5 = FUN_180002330(param_1);
            if (lVar5 == 0)
            {
                local_868 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                if (local_868 == (char *)0x0)
                {
                    local_868 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                }
                else
                {
                    local_868 = local_868 + 1;
                }
                local_860 = 0x4c;
                snprintf(local_848, 0x3ff, "%s %s:%d", "pRingBuf != NULL");
                local_449 = 0;
                MessageBoxA((HWND)0x0, local_848, "Error", 0);
            }
            bVar1 = false;
            bVar8 = false;
            if (0 < *(int *)(lVar5 + 0xc))
            {
                iVar6 = param_3 - iVar7;
                if (*(int *)(lVar5 + 0xc) < iVar6)
                {
                    iVar6 = *(int *)(lVar5 + 0xc);
                }
                FUN_1800056e0(lVar5, (void *)(iVar7 + param_2), iVar6);
                *(int *)(lVar5 + 8) = *(int *)(lVar5 + 8) + iVar6;
                uVar3 = *(uint *)(lVar5 + 8) & 0x800fffff;
                if ((int)uVar3 < 0)
                {
                    uVar3 = (uVar3 - 1 | 0xfff00000) + 1;
                }
                *(uint *)(lVar5 + 8) = uVar3;
                iVar7 = iVar7 + iVar6;
                bVar1 = false;
                *(int *)(lVar5 + 0xc) = *(int *)(lVar5 + 0xc) - iVar6;
                if (*(int *)(lVar5 + 0xc) == 0)
                {
                    if (*(int *)(lVar5 + 4) != 0)
                    {
                        local_868 = strrchr("h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp", 0x5c);
                        if (local_868 == (char *)0x0)
                        {
                            local_868 = "h:\\gpu\\fastpipe-6.1.36\\pipereader.cpp";
                        }
                        else
                        {
                            local_868 = local_868 + 1;
                        }
                        local_860 = 0x5b;
                        snprintf(local_448, 0x3ff, "%s %s:%d", "pRingBuf->prepareWriteDontFree == 0");
                        local_49 = 0;
                        MessageBoxA((HWND)0x0, local_448, "Error", 0);
                    }
                    bVar1 = false;
                    if (*(int *)(lVar5 + 4) == 0)
                    {
                        bVar1 = true;
                    }
                }
                bVar8 = *(int *)(lVar4 + 8) != 0;
                if (iVar7 == param_3)
                {
                    FUN_180001d50(param_1);
                    if (bVar1)
                    {
                        FUN_180003be0();
                    }
                    if (bVar8)
                    {
                        FUN_180002680(param_1);
                    }
                    goto LAB_180005a42;
                }
            }
        }
        *(undefined4 *)(lVar4 + 0xc) = 1;
        FUN_180002530(param_1);
        FUN_180001d50(param_1);
        if (bVar1)
        {
            FUN_180003be0();
        }
        if (bVar8)
        {
            FUN_180002680(param_1);
        }
        local_858[0] = '\0';
        cVar2 = FUN_180001fe0(param_1, *(HANDLE *)(&DAT_18000d8c8 + (longlong)*param_1 * 0x18), local_858);
        if ((cVar2 == '\0') || (local_858[0] != '\0'))
        {
            bVar1 = false;
        }
        else
        {
            bVar1 = true;
        }
        *(undefined4 *)(lVar4 + 0xc) = 0;
        if (!bVar1)
            goto LAB_180005a42;
        cVar2 = FUN_180001b20(param_1);
    } while (true);
}

int FUN_1800065f0(longlong param_1, void *param_2, int param_3)

{
    longlong lVar1;
    int iVar2;
    int iVar3;
    int iVar4;
    uint uVar5;

    iVar2 = 0;
    iVar3 = iVar2;
    if ((*(int *)(param_1 + 0xc) < 0x100000) && (iVar3 = 0, 0 < param_3))
    {
        if (*(int *)(param_1 + 0xc) + *(int *)(param_1 + 8) < 0x100000)
        {
            iVar2 = param_3;
            if ((0x100000 - *(int *)(param_1 + 8)) - *(int *)(param_1 + 0xc) < param_3)
            {
                iVar2 = (0x100000 - *(int *)(param_1 + 8)) - *(int *)(param_1 + 0xc);
            }
            lVar1 = FUN_180002170(param_1);
            memcpy((void *)((longlong) * (int *)(param_1 + 8) + lVar1 + *(int *)(param_1 + 0xc)), param_2,
                   (longlong)iVar2);
        }
        iVar3 = iVar2;
        if ((iVar2 < param_3) && (iVar4 = 0x100000 - iVar2, 0 < iVar4 - *(int *)(param_1 + 0xc)))
        {
            iVar3 = param_3 - iVar2;
            if (iVar4 - *(int *)(param_1 + 0xc) < iVar3)
            {
                iVar3 = iVar4 - *(int *)(param_1 + 0xc);
            }
            lVar1 = FUN_180002170(param_1);
            uVar5 = *(int *)(param_1 + 0xc) + *(int *)(param_1 + 8) + iVar2 & 0x800fffff;
            if ((int)uVar5 < 0)
            {
                uVar5 = (uVar5 - 1 | 0xfff00000) + 1;
            }
            memcpy((void *)((int)uVar5 + lVar1), (void *)((longlong)iVar2 + (longlong)param_2),
                   (longlong)iVar3);
            iVar3 = iVar3 + iVar2;
        }
    }
    return iVar3;
}

void FUN_180006ca0(longlong param_1, int param_2)

{
    void *pvVar1;
    uint uVar2;
    longlong lVar3;
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    lVar3 = 0;
    *(undefined4 *)(param_1 + 0x10) = 0;
    if (*(int *)(param_1 + 0x18) < param_2)
    {
        pvVar1 = *(void **)(param_1 + 8);
        uVar2 = param_2 + 0xfffffU & 0xfff00000;
        if (*(uint *)(param_1 + 0x14) == uVar2)
        {
            if (pvVar1 == (void *)0x0)
            {
                local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\readbufimpl.cpp", 0x5c);
                if (local_428 == (char *)0x0)
                {
                    local_428 = "h:\\gpu\\fastpipe-6.1.36\\readbufimpl.cpp";
                }
                else
                {
                    local_428 = local_428 + 1;
                }
                local_420 = 0x37;
                snprintf(local_418, 0x3ff, "%s %s:%d", "m_buf != NULL");
                local_19 = 0;
                MessageBoxA((HWND)0x0, local_418, "Error", 0);
            }
        }
        else
        {
            if (pvVar1 != (void *)0x0)
            {
                free(pvVar1);
                *(undefined8 *)(param_1 + 8) = 0;
                *(undefined4 *)(param_1 + 0x14) = 0;
            }
            pvVar1 = operator_new((longlong)(int)uVar2);
            *(void **)(param_1 + 8) = pvVar1;
            *(uint *)(param_1 + 0x14) = uVar2;
        }
    }
    else
    {
        if (*(int *)(param_1 + 0x18) < (int)*(uint *)(param_1 + 0x14))
        {
            pvVar1 = *(void **)(param_1 + 8);
            if (pvVar1 == (void *)0x0)
            {
                local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\readbufimpl.cpp", 0x5c);
                if (local_428 == (char *)0x0)
                {
                    local_428 = "h:\\gpu\\fastpipe-6.1.36\\readbufimpl.cpp";
                }
                else
                {
                    local_428 = local_428 + 1;
                }
                local_420 = 0x22;
                snprintf(local_418, 0x3ff, "%s %s:%d", "m_buf != NULL");
                local_19 = 0;
                MessageBoxA((HWND)0x0, local_418, "Error", 0);
                pvVar1 = *(void **)(param_1 + 8);
            }
            free(pvVar1);
            *(undefined8 *)(param_1 + 8) = 0;
            *(undefined4 *)(param_1 + 0x14) = 0;
        }
        else
        {
            lVar3 = *(longlong *)(param_1 + 8);
        }
        if (lVar3 == 0)
        {
            pvVar1 = operator_new((longlong) * (int *)(param_1 + 0x18));
            *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x18);
            *(void **)(param_1 + 8) = pvVar1;
        }
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

void FUN_180006e70(longlong param_1, int param_2)

{
    undefined auStack1096[32];
    char *local_428;
    undefined4 local_420;
    CHAR local_418[1023];
    undefined local_19;
    ulonglong local_18;

    local_18 = DAT_18000d010 ^ (ulonglong)auStack1096;
    if (*(int *)(param_1 + 0x14) < param_2)
    {
        local_428 = strrchr("h:\\gpu\\fastpipe-6.1.36\\readbufimpl.cpp", 0x5c);
        if (local_428 == (char *)0x0)
        {
            local_428 = "h:\\gpu\\fastpipe-6.1.36\\readbufimpl.cpp";
        }
        else
        {
            local_428 = local_428 + 1;
        }
        local_420 = 0x4c;
        snprintf(local_418, 0x3ff, "%s %s:%d", "nDataLen <= m_nBufSize");
        local_19 = 0;
        MessageBoxA((HWND)0x0, local_418, "Error", 0);
        *(int *)(param_1 + 0x10) = param_2;
    }
    else
    {
        *(int *)(param_1 + 0x10) = param_2;
    }
    FUN_180006f40(local_18 ^ (ulonglong)auStack1096);
    return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180006f40(longlong param_1)

{
    code *pcVar1;
    BOOL BVar2;
    undefined *puVar3;
    undefined auStack56[8];
    undefined auStack48[48];

    if ((param_1 == DAT_18000d010) && ((short)((ulonglong)param_1 >> 0x30) == 0))
    {
        return;
    }
    puVar3 = auStack56;
    BVar2 = IsProcessorFeaturePresent(0x17);
    if (BVar2 != 0)
    {
        pcVar1 = (code *)swi(0x29);
        (*pcVar1)(2);
        puVar3 = auStack48;
    }
    *(undefined8 *)(puVar3 + -8) = 0x180006fc2;
    capture_previous_context((PCONTEXT)&DAT_18000d2f0);
    _DAT_18000d260 = *(undefined8 *)(puVar3 + 0x38);
    _DAT_18000d388 = puVar3 + 0x40;
    _DAT_18000d370 = *(undefined8 *)(puVar3 + 0x40);
    _DAT_18000d250 = 0xc0000409;
    _DAT_18000d254 = 1;
    _DAT_18000d268 = 1;
    DAT_18000d270 = 2;
    *(longlong *)(puVar3 + 0x20) = DAT_18000d010;
    *(undefined8 *)(puVar3 + 0x28) = DAT_18000d008;
    *(undefined8 *)(puVar3 + -8) = 0x180007064;
    DAT_18000d3e8 = _DAT_18000d260;
    __raise_securityfailure((_EXCEPTION_POINTERS *)&PTR_DAT_1800092d0);
    return;
}

// Library Function - Single Match
//  __raise_securityfailure
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void __raise_securityfailure(_EXCEPTION_POINTERS *param_1)

{
    HANDLE hProcess;

    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
    UnhandledExceptionFilter(param_1);
    hProcess = GetCurrentProcess();
    // WARNING: Could not recover jumptable at 0x000180006f91. Too many branches
    // WARNING: Treating indirect jump as call
    TerminateProcess(hProcess, 0xc0000409);
    return;
}

// Library Function - Single Match
//  capture_previous_context
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release, Visual Studio 2019 Release

void capture_previous_context(PCONTEXT param_1)

{
    DWORD64 ControlPc;
    PRUNTIME_FUNCTION FunctionEntry;
    int iVar1;
    DWORD64 local_res8;
    ulonglong local_res10;
    PVOID local_res18[2];

    RtlCaptureContext();
    ControlPc = param_1->Rip;
    iVar1 = 0;
    do
    {
        FunctionEntry = RtlLookupFunctionEntry(ControlPc, &local_res8, (PUNWIND_HISTORY_TABLE)0x0);
        if (FunctionEntry == (PRUNTIME_FUNCTION)0x0)
        {
            return;
        }
        RtlVirtualUnwind(0, local_res8, ControlPc, FunctionEntry, param_1, local_res18, &local_res10,
                         (PKNONVOLATILE_CONTEXT_POINTERS)0x0);
        iVar1 = iVar1 + 1;
    } while (iVar1 < 2);
    return;
}

// Library Function - Single Match
//  void * __ptr64 __cdecl operator new(unsigned __int64)
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void *operator_new(__uint64 param_1)

{
    code *pcVar1;
    int iVar2;
    void *pvVar3;

    do
    {
        pvVar3 = malloc(param_1);
        if (pvVar3 != (void *)0x0)
        {
            return pvVar3;
        }
        iVar2 = _callnewh(param_1);
    } while (iVar2 != 0);
    if (param_1 == 0xffffffffffffffff)
    {
        FUN_180007a1c();
        pcVar1 = (code *)swi(3);
        pvVar3 = (void *)(*pcVar1)();
        return pvVar3;
    }
    FUN_1800079fc();
    pcVar1 = (code *)swi(3);
    pvVar3 = (void *)(*pcVar1)();
    return pvVar3;
}

// Library Function - Single Match
//  __scrt_acquire_startup_lock
//
// Library: Visual Studio 2017 Release

ulonglong __scrt_acquire_startup_lock(void)

{
    ulonglong uVar1;
    bool bVar2;
    undefined7 extraout_var;
    longlong in_GS_OFFSET;
    ulonglong uVar3;

    bVar2 = __scrt_is_ucrt_dll_in_use();
    uVar3 = CONCAT71(extraout_var, bVar2);
    if ((int)uVar3 == 0)
    {
    LAB_18000714a:
        uVar3 = uVar3 & 0xffffffffffffff00;
    }
    else
    {
        uVar1 = *(ulonglong *)(*(longlong *)(in_GS_OFFSET + 0x30) + 8);
        do
        {
            LOCK();
            bVar2 = DAT_18000d7c8 == 0;
            DAT_18000d7c8 = DAT_18000d7c8 ^ (ulonglong)bVar2 * (DAT_18000d7c8 ^ uVar1);
            uVar3 = !bVar2 * DAT_18000d7c8;
            if (bVar2)
                goto LAB_18000714a;
        } while (uVar1 != uVar3);
        uVar3 = CONCAT71((int7)(uVar3 >> 8), 1);
    }
    return uVar3;
}

// Library Function - Single Match
//  __scrt_dllmain_after_initialize_c
//
// Library: Visual Studio 2017 Release

undefined8 __scrt_dllmain_after_initialize_c(void)

{
    bool bVar1;
    undefined7 extraout_var;
    undefined8 uVar2;
    ulonglong uVar3;

    bVar1 = __scrt_is_ucrt_dll_in_use();
    if ((int)CONCAT71(extraout_var, bVar1) == 0)
    {
        uVar3 = FUN_180007bcc();
        uVar3 = _configure_narrow_argv(uVar3 & 0xffffffff);
        if ((int)uVar3 != 0)
        {
            return uVar3 & 0xffffffffffffff00;
        }
        uVar2 = _initialize_narrow_environment();
    }
    else
    {
        uVar2 = __isa_available_init();
    }
    return CONCAT71((int7)((ulonglong)uVar2 >> 8), 1);
}

// Library Function - Single Match
//  __scrt_dllmain_before_initialize_c
//
// Library: Visual Studio 2017 Release

ulonglong __scrt_dllmain_before_initialize_c(void)

{
    ulonglong uVar1;

    uVar1 = __scrt_initialize_onexit_tables(0);
    return uVar1 & 0xffffffffffffff00 | (ulonglong)((char)uVar1 != '\0');
}

// Library Function - Single Match
//  __scrt_dllmain_crt_thread_attach
//
// Library: Visual Studio 2017 Release

undefined __scrt_dllmain_crt_thread_attach(void)

{
    char cVar1;

    cVar1 = FUN_180007f30();
    if (cVar1 != '\0')
    {
        cVar1 = FUN_180007f30();
        if (cVar1 != '\0')
        {
            return 1;
        }
        FUN_180007f30();
    }
    return 0;
}

// Library Function - Single Match
//  __scrt_dllmain_crt_thread_detach
//
// Library: Visual Studio 2017 Release

undefined __scrt_dllmain_crt_thread_detach(void)

{
    FUN_180007f30();
    FUN_180007f30();
    return 1;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall

void FUN_1800071e4(undefined8 param_1, int param_2, undefined8 param_3, undefined *param_4,
                   undefined4 param_5, undefined8 param_6)

{
    bool bVar1;
    undefined7 extraout_var;

    bVar1 = __scrt_is_ucrt_dll_in_use();
    if (((int)CONCAT71(extraout_var, bVar1) == 0) && (param_2 == 1))
    {
        (*(code *)param_4)();
    }
    // WARNING: Could not recover jumptable at 0x000180007ee6. Too many branches
    // WARNING: Treating indirect jump as call
    _seh_filter_dll(param_5, param_6);
    return;
}

void FUN_180007244(void)

{
    bool bVar1;
    undefined7 extraout_var;
    undefined8 uVar2;

    bVar1 = __scrt_is_ucrt_dll_in_use();
    if ((int)CONCAT71(extraout_var, bVar1) != 0)
    {
        // WARNING: Could not recover jumptable at 0x000180007f04. Too many branches
        // WARNING: Treating indirect jump as call
        _execute_onexit_table(&DAT_18000d7d8);
        return;
    }
    uVar2 = FUN_180007f34();
    if ((int)uVar2 == 0)
    {
        _cexit();
    }
    return;
}

// Library Function - Single Match
//  __scrt_dllmain_uninitialize_critical
//
// Library: Visual Studio 2017 Release

void __scrt_dllmain_uninitialize_critical(void)

{
    FUN_180007f30();
    FUN_180007f30();
    return;
}

// Library Function - Single Match
//  __scrt_initialize_crt
//
// Library: Visual Studio 2017 Release

ulonglong __scrt_initialize_crt(int param_1)

{
    ulonglong uVar1;

    if (param_1 == 0)
    {
        DAT_18000d7d0 = 1;
    }
    __isa_available_init();
    uVar1 = FUN_180007f30();
    if ((char)uVar1 != '\0')
    {
        uVar1 = FUN_180007f30();
        if ((char)uVar1 != '\0')
        {
            return uVar1 & 0xffffffffffffff00 | 1;
        }
        uVar1 = FUN_180007f30();
    }
    return uVar1 & 0xffffffffffffff00;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_initialize_onexit_tables
//
// Library: Visual Studio 2017 Release

undefined8 __scrt_initialize_onexit_tables(uint param_1)

{
    code *pcVar1;
    byte bVar2;
    bool bVar3;
    ulonglong in_RAX;
    undefined7 extraout_var;
    undefined8 uVar4;
    undefined4 local_28;
    undefined4 uStack36;

    if (DAT_18000d7d1 == '\0')
    {
        if (1 < param_1)
        {
            __scrt_fastfail(5);
            pcVar1 = (code *)swi(3);
            uVar4 = (*pcVar1)();
            return uVar4;
        }
        bVar3 = __scrt_is_ucrt_dll_in_use();
        if (((int)CONCAT71(extraout_var, bVar3) == 0) || (param_1 != 0))
        {
            bVar2 = 0x40 - ((byte)DAT_18000d010 & 0x3f) & 0x3f;
            in_RAX = (0xffffffffffffffffU >> bVar2 | -1 << 0x40 - bVar2) ^ DAT_18000d010;
            local_28 = (undefined4)in_RAX;
            uStack36 = (undefined4)(in_RAX >> 0x20);
            _DAT_18000d7d8 = local_28;
            uRam000000018000d7dc = uStack36;
            uRam000000018000d7e0 = local_28;
            uRam000000018000d7e4 = uStack36;
            _DAT_18000d7f0 = local_28;
            uRam000000018000d7f4 = uStack36;
            uRam000000018000d7f8 = local_28;
            uRam000000018000d7fc = uStack36;
            _DAT_18000d7e8 = in_RAX;
            _DAT_18000d800 = in_RAX;
        }
        else
        {
            in_RAX = _initialize_onexit_table(&DAT_18000d7d8);
            if (((int)in_RAX != 0) ||
                (in_RAX = _initialize_onexit_table(&DAT_18000d7f0), (int)in_RAX != 0))
            {
                return in_RAX & 0xffffffffffffff00;
            }
        }
        DAT_18000d7d1 = '\x01';
    }
    return CONCAT71((int7)(in_RAX >> 8), 1);
}

// WARNING: Removing unreachable block (ram,0x00018000743a)
// Library Function - Single Match
//  __scrt_is_nonwritable_in_current_image
//
// Library: Visual Studio 2017 Release

ulonglong __scrt_is_nonwritable_in_current_image(longlong param_1)

{
    ulonglong uVar1;
    uint7 uVar2;
    IMAGE_SECTION_HEADER *pIVar3;

    uVar1 = 0;
    for (pIVar3 = &IMAGE_SECTION_HEADER_180000208; pIVar3 != (IMAGE_SECTION_HEADER *)&DAT_1800002f8;
         pIVar3 = pIVar3 + 1)
    {
        if (((ulonglong)(uint)pIVar3->VirtualAddress <= param_1 - 0x180000000U) &&
            (uVar1 = (ulonglong)(uint)(pIVar3->Misc + pIVar3->VirtualAddress),
             param_1 - 0x180000000U < uVar1))
            goto LAB_180007423;
    }
    pIVar3 = (IMAGE_SECTION_HEADER *)0x0;
LAB_180007423:
    if (pIVar3 == (IMAGE_SECTION_HEADER *)0x0)
    {
        uVar1 = uVar1 & 0xffffffffffffff00;
    }
    else
    {
        uVar2 = (uint7)(uVar1 >> 8);
        if ((int)pIVar3->Characteristics < 0)
        {
            uVar1 = (ulonglong)uVar2 << 8;
        }
        else
        {
            uVar1 = CONCAT71(uVar2, 1);
        }
    }
    return uVar1;
}

// Library Function - Single Match
//  __scrt_release_startup_lock
//
// Library: Visual Studio 2017 Release

void __scrt_release_startup_lock(char param_1)

{
    bool bVar1;
    undefined3 extraout_var;

    bVar1 = __scrt_is_ucrt_dll_in_use();
    if ((CONCAT31(extraout_var, bVar1) != 0) && (param_1 == '\0'))
    {
        DAT_18000d7c8 = 0;
    }
    return;
}

// Library Function - Single Match
//  __scrt_uninitialize_crt
//
// Library: Visual Studio 2017 Release

undefined __scrt_uninitialize_crt(undefined8 param_1, char param_2)

{
    if ((DAT_18000d7d0 == '\0') || (param_2 == '\0'))
    {
        FUN_180007f30();
        FUN_180007f30();
    }
    return 1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  _onexit
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

_onexit_t _onexit(_onexit_t _Func)

{
    int iVar1;
    byte bVar2;
    _onexit_t p_Var3;

    bVar2 = (byte)DAT_18000d010 & 0x3f;
    if (((DAT_18000d010 ^ _DAT_18000d7d8) >> bVar2 | (DAT_18000d010 ^ _DAT_18000d7d8) << 0x40 - bVar2) == 0xffffffffffffffff)
    {
        iVar1 = _crt_atexit();
    }
    else
    {
        iVar1 = _register_onexit_function(&DAT_18000d7d8, _Func);
    }
    p_Var3 = (_onexit_t)0x0;
    if (iVar1 == 0)
    {
        p_Var3 = _Func;
    }
    return p_Var3;
}

void free(void *_Memory)

{
    free(_Memory);
    return;
}

undefined8 *FUN_180007508(undefined8 *param_1, ulonglong param_2)

{
    *param_1 = type_info::vftable;
    if ((param_2 & 1) != 0)
    {
        free(param_1);
    }
    return param_1;
}

void *operator_new(__uint64 param_1)

{
    code *pcVar1;
    int iVar2;
    void *pvVar3;

    do
    {
        pvVar3 = malloc(param_1);
        if (pvVar3 != (void *)0x0)
        {
            return pvVar3;
        }
        iVar2 = _callnewh(param_1);
    } while (iVar2 != 0);
    if (param_1 == 0xffffffffffffffff)
    {
        FUN_180007a1c();
        pcVar1 = (code *)swi(3);
        pvVar3 = (void *)(*pcVar1)();
        return pvVar3;
    }
    FUN_1800079fc();
    pcVar1 = (code *)swi(3);
    pvVar3 = (void *)(*pcVar1)();
    return pvVar3;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  int __cdecl dllmain_crt_dispatch(struct HINSTANCE__ * __ptr64 const,unsigned long,void * __ptr64
// const)
//
// Library: Visual Studio 2017 Release

int dllmain_crt_dispatch(HINSTANCE__ *param_1, ulong param_2, void *param_3)

{
    code *pcVar1;
    bool bVar2;
    byte bVar3;
    char cVar4;
    int iVar5;
    uint uVar6;
    ulonglong uVar7;
    ulonglong uVar8;
    undefined8 uVar9;
    code **ppcVar10;

    if (param_2 == 0)
    {
        uVar7 = (ulonglong)param_1 & 0xffffffffffffff00;
        if (DAT_18000d808 < 1)
        {
            uVar6 = 0;
        }
        else
        {
            DAT_18000d808 = DAT_18000d808 + -1;
            uVar8 = __scrt_acquire_startup_lock();
            if (_DAT_18000d7c0 != 2)
            {
                __scrt_fastfail(7);
                pcVar1 = (code *)swi(3);
                iVar5 = (*pcVar1)();
                return iVar5;
            }
            FUN_180007244();
            FUN_180007dfc();
            FID_conflict__RTC_Initialize();
            _DAT_18000d7c0 = 0;
            __scrt_dllmain_uninitialize_critical();
            uVar7 = uVar7 & 0xffffffffffffff00;
            __scrt_release_startup_lock((char)uVar8);
            cVar4 = __scrt_uninitialize_crt(uVar7 & 0xffffffffffffff00 | (ulonglong)(param_3 != (void *)0x0), '\0');
            uVar6 = (uint)(cVar4 != '\0');
        }
        return uVar6;
    }
    if (param_2 != 1)
    {
        if (param_2 == 2)
        {
            bVar3 = __scrt_dllmain_crt_thread_attach();
        }
        else
        {
            if (param_2 != 3)
            {
                return 1;
            }
            bVar3 = __scrt_dllmain_crt_thread_detach();
        }
        return (int)bVar3;
    }
    uVar7 = __scrt_initialize_crt(0);
    if ((char)uVar7 != '\0')
    {
        uVar7 = __scrt_acquire_startup_lock();
        bVar2 = true;
        if (_DAT_18000d7c0 != 0)
        {
            __scrt_fastfail(7);
            pcVar1 = (code *)swi(3);
            iVar5 = (*pcVar1)();
            return iVar5;
        }
        _DAT_18000d7c0 = 1;
        uVar8 = __scrt_dllmain_before_initialize_c();
        if ((char)uVar8 != '\0')
        {
            FID_conflict__RTC_Initialize();
            FUN_180007dec();
            __scrt_initialize_default_local_stdio_options();
            iVar5 = _initterm_e(&DAT_180009298, &DAT_1800092a0);
            if ((iVar5 == 0) && (uVar9 = __scrt_dllmain_after_initialize_c(), (char)uVar9 != '\0'))
            {
                _initterm(&DAT_180009270, &DAT_180009290);
                _DAT_18000d7c0 = 2;
                bVar2 = false;
            }
        }
        __scrt_release_startup_lock((char)uVar7);
        if (!bVar2)
        {
            ppcVar10 = (code **)FUN_180007e2c();
            if ((*ppcVar10 != (code *)0x0) &&
                (uVar7 = __scrt_is_nonwritable_in_current_image((longlong)ppcVar10), (char)uVar7 != '\0'))
            {
                (**ppcVar10)();
            }
            DAT_18000d808 = DAT_18000d808 + 1;
            return 1;
        }
    }
    return 0;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// WARNING: Removing unreachable block (ram,0x0001800077fc)
// WARNING: Removing unreachable block (ram,0x00018000778b)
// WARNING: Removing unreachable block (ram,0x00018000783f)

ulonglong entry(HINSTANCE__ *param_1, ulong param_2, void *param_3)

{
    uint uVar1;
    ulonglong uVar2;
    ulonglong uVar3;

    if (param_2 == 1)
    {
        __security_init_cookie();
    }
    if ((param_2 == 0) && (DAT_18000d808 < 1))
    {
        uVar2 = 0;
    }
    else
    {
        if (param_2 - 1 < 2)
        {
            uVar1 = dllmain_crt_dispatch(param_1, param_2, param_3);
            if (uVar1 == 0)
            {
                return (ulonglong)uVar1;
            }
        }
        uVar3 = FUN_180001120(param_1, param_2);
        uVar2 = uVar3 & 0xffffffff;
        if ((param_2 == 1) && ((int)uVar3 == 0))
        {
            FUN_180001120(param_1, 0);
            dllmain_crt_dispatch(param_1, 0, param_3);
        }
        if ((param_2 == 0) || (param_2 == 3))
        {
            uVar1 = dllmain_crt_dispatch(param_1, param_2, param_3);
            uVar2 = (ulonglong)uVar1;
            if (uVar1 != 0)
            {
                uVar2 = 1;
            }
        }
    }
    return uVar2;
}

undefined8 *FUN_1800078ac(undefined8 *param_1, longlong param_2)

{
    *param_1 = std::exception::vftable;
    param_1[1] = 0;
    param_1[2] = 0;
    __std_exception_copy(param_2 + 8);
    *param_1 = std::bad_alloc::vftable;
    return param_1;
}

undefined8 *FUN_1800078ec(undefined8 *param_1)

{
    param_1[2] = 0;
    param_1[1] = "bad allocation";
    *param_1 = std::bad_alloc::vftable;
    return param_1;
}

undefined8 *FUN_18000790c(undefined8 *param_1, longlong param_2)

{
    *param_1 = std::exception::vftable;
    param_1[1] = 0;
    param_1[2] = 0;
    __std_exception_copy(param_2 + 8);
    *param_1 = std::bad_array_new_length::vftable;
    return param_1;
}

undefined8 *FUN_18000794c(undefined8 *param_1)

{
    param_1[2] = 0;
    param_1[1] = "bad array new length";
    *param_1 = std::bad_array_new_length::vftable;
    return param_1;
}

// Library Function - Single Match
//  public: __cdecl std::exception::exception(class std::exception const & __ptr64) __ptr64
//
// Libraries: Visual Studio 2015 Release, Visual Studio 2017 Release

exception *__thiscall std::exception::exception(exception *this, exception *param_1)

{
    *(undefined ***)this = vftable;
    *(undefined8 *)(this + 8) = 0;
    *(undefined8 *)(this + 0x10) = 0;
    __std_exception_copy(param_1 + 8);
    return this;
}

undefined8 *FUN_1800079b8(undefined8 *param_1, ulonglong param_2)

{
    *param_1 = std::exception::vftable;
    __std_exception_destroy(param_1 + 1);
    if ((param_2 & 1) != 0)
    {
        free(param_1);
    }
    return param_1;
}

void FUN_1800079fc(void)

{
    undefined8 local_28[5];

    FUN_1800078ec(local_28);
    // WARNING: Subroutine does not return
    _CxxThrowException(local_28, (ThrowInfo *)&DAT_18000b610);
}

void FUN_180007a1c(void)

{
    undefined8 local_28[5];

    FUN_18000794c(local_28);
    // WARNING: Subroutine does not return
    _CxxThrowException(local_28, (ThrowInfo *)&DAT_18000b698);
}

char *FUN_180007a3c(longlong param_1)

{
    char *pcVar1;

    pcVar1 = "Unknown exception";
    if (*(longlong *)(param_1 + 8) != 0)
    {
        pcVar1 = *(char **)(param_1 + 8);
    }
    return pcVar1;
}

// WARNING: Removing unreachable block (ram,0x000180007b1e)
// WARNING: Removing unreachable block (ram,0x000180007a9c)
// WARNING: Removing unreachable block (ram,0x000180007a77)
// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __isa_available_init
//
// Library: Visual Studio 2017 Release

undefined8 __isa_available_init(void)

{
    int *piVar1;
    uint *puVar2;
    longlong lVar3;
    uint uVar4;
    uint uVar5;
    uint uVar6;
    byte in_XCR0;

    DAT_18000d01c = 2;
    _DAT_18000d018 = 1;
    piVar1 = (int *)cpuid_basic_info(0);
    uVar6 = 0;
    puVar2 = (uint *)cpuid_Version_info(1);
    uVar4 = puVar2[3];
    if ((piVar1[1] ^ 0x756e6547U | piVar1[3] ^ 0x6c65746eU | piVar1[2] ^ 0x49656e69U) == 0)
    {
        _DAT_18000d020 = 0xffffffffffffffff;
        uVar5 = *puVar2 & 0xfff3ff0;
        if ((((uVar5 == 0x106c0) || (uVar5 == 0x20660)) || (uVar5 == 0x20670)) ||
            ((uVar5 - 0x30650 < 0x21 &&
              ((0x100010001U >> ((ulonglong)(uVar5 - 0x30650) & 0x3f) & 1) != 0))))
        {
            DAT_18000d80c = DAT_18000d80c | 1;
        }
    }
    if (6 < *piVar1)
    {
        lVar3 = cpuid_Extended_Feature_Enumeration_info(7);
        uVar6 = *(uint *)(lVar3 + 4);
        if ((uVar6 >> 9 & 1) != 0)
        {
            DAT_18000d80c = DAT_18000d80c | 2;
        }
    }
    if ((uVar4 >> 0x14 & 1) != 0)
    {
        _DAT_18000d018 = 2;
        DAT_18000d01c = 6;
        if ((((uVar4 >> 0x1b & 1) != 0) && ((uVar4 >> 0x1c & 1) != 0)) && ((in_XCR0 & 6) == 6))
        {
            DAT_18000d01c = 0xe;
            _DAT_18000d018 = 3;
            if ((uVar6 & 0x20) != 0)
            {
                _DAT_18000d018 = 5;
                DAT_18000d01c = 0x2e;
            }
        }
    }
    return 0;
}

undefined8 FUN_180007bcc(void)

{
    return 1;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address
// Library Function - Single Match
//  __scrt_is_ucrt_dll_in_use
//
// Library: Visual Studio 2017 Release

bool __scrt_is_ucrt_dll_in_use(void)

{
    return _DAT_18000d030 != 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_180007be0(void)

{
    _DAT_18000d810 = 0;
    return;
}

// Library Function - Single Match
//  __scrt_fastfail
//
// Library: Visual Studio 2017 Release

void __scrt_fastfail(undefined4 param_1)

{
    code *pcVar1;
    BOOL BVar2;
    LONG LVar3;
    PRUNTIME_FUNCTION FunctionEntry;
    undefined *puVar4;
    undefined8 in_stack_00000000;
    DWORD64 local_res10;
    undefined local_res18[8];
    undefined local_res20[8];
    undefined auStack1480[8];
    undefined auStack1472[232];
    undefined local_4d8[152];
    undefined *local_440;
    DWORD64 local_3e0;

    puVar4 = auStack1480;
    BVar2 = IsProcessorFeaturePresent(0x17);
    if (BVar2 != 0)
    {
        pcVar1 = (code *)swi(0x29);
        (*pcVar1)(param_1);
        puVar4 = auStack1472;
    }
    *(undefined8 *)(puVar4 + -8) = 0x180007c1b;
    FUN_180007be0();
    *(undefined8 *)(puVar4 + -8) = 0x180007c2c;
    memset(local_4d8, 0, 0x4d0);
    *(undefined8 *)(puVar4 + -8) = 0x180007c36;
    RtlCaptureContext(local_4d8);
    *(undefined8 *)(puVar4 + -8) = 0x180007c50;
    FunctionEntry = RtlLookupFunctionEntry(local_3e0, &local_res10, (PUNWIND_HISTORY_TABLE)0x0);
    if (FunctionEntry != (PRUNTIME_FUNCTION)0x0)
    {
        *(undefined8 *)(puVar4 + 0x38) = 0;
        *(undefined **)(puVar4 + 0x30) = local_res18;
        *(undefined **)(puVar4 + 0x28) = local_res20;
        *(undefined **)(puVar4 + 0x20) = local_4d8;
        *(undefined8 *)(puVar4 + -8) = 0x180007c91;
        RtlVirtualUnwind(0, local_res10, local_3e0, FunctionEntry, *(PCONTEXT *)(puVar4 + 0x20),
                         *(PVOID **)(puVar4 + 0x28), *(PDWORD64 *)(puVar4 + 0x30),
                         *(PKNONVOLATILE_CONTEXT_POINTERS *)(puVar4 + 0x38));
    }
    local_440 = &stack0x00000008;
    *(undefined8 *)(puVar4 + -8) = 0x180007cc3;
    memset(puVar4 + 0x50, 0, 0x98);
    *(undefined8 *)(puVar4 + 0x60) = in_stack_00000000;
    *(undefined4 *)(puVar4 + 0x50) = 0x40000015;
    *(undefined4 *)(puVar4 + 0x54) = 1;
    *(undefined8 *)(puVar4 + -8) = 0x180007ce5;
    BVar2 = IsDebuggerPresent();
    *(undefined **)(puVar4 + 0x40) = puVar4 + 0x50;
    *(undefined **)(puVar4 + 0x48) = local_4d8;
    *(undefined8 *)(puVar4 + -8) = 0x180007d06;
    SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)0x0);
    *(undefined8 *)(puVar4 + -8) = 0x180007d11;
    LVar3 = UnhandledExceptionFilter((_EXCEPTION_POINTERS *)(puVar4 + 0x40));
    if ((LVar3 == 0) && (BVar2 != 1))
    {
        *(undefined8 *)(puVar4 + -8) = 0x180007d21;
        FUN_180007be0();
    }
    return;
}

void _guard_check_icall(void)

{
    return;
}

void free(void *_Memory)

{
    // WARNING: Could not recover jumptable at 0x000180007f22. Too many branches
    // WARNING: Treating indirect jump as call
    free(_Memory);
    return;
}

// Library Function - Single Match
//  __security_init_cookie
//
// Library: Visual Studio 2017 Release

void __security_init_cookie(void)

{
    DWORD DVar1;
    _FILETIME local_res8;
    _FILETIME local_res10;
    uint local_res18;
    undefined4 uStackX28;

    if (DAT_18000d010 == 0x2b992ddfa232)
    {
        local_res10 = (_FILETIME)0x0;
        GetSystemTimeAsFileTime(&local_res10);
        local_res8 = local_res10;
        DVar1 = GetCurrentThreadId();
        local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
        DVar1 = GetCurrentProcessId();
        local_res8 = (_FILETIME)((ulonglong)local_res8 ^ (ulonglong)DVar1);
        QueryPerformanceCounter((LARGE_INTEGER *)&local_res18);
        DAT_18000d010 =
            ((ulonglong)local_res18 << 0x20 ^ CONCAT44(uStackX28, local_res18) ^ (ulonglong)local_res8 ^
             (ulonglong)&local_res8) &
            0xffffffffffff;
        if (DAT_18000d010 == 0x2b992ddfa232)
        {
            DAT_18000d010 = 0x2b992ddfa233;
        }
    }
    DAT_18000d008 = ~DAT_18000d010;
    return;
}

void FUN_180007dec(void)

{
    // WARNING: Could not recover jumptable at 0x000180007df3. Too many branches
    // WARNING: Treating indirect jump as call
    InitializeSListHead((PSLIST_HEADER)&DAT_18000d820);
    return;
}

void FUN_180007dfc(void)

{
    // WARNING: Could not recover jumptable at 0x000180007ed4. Too many branches
    // WARNING: Treating indirect jump as call
    __std_type_info_destroy_list(&DAT_18000d820);
    return;
}

undefined *FUN_180007e08(void)

{
    return &DAT_18000d830;
}

// Library Function - Single Match
//  __scrt_initialize_default_local_stdio_options
//
// Library: Visual Studio 2017 Release

void __scrt_initialize_default_local_stdio_options(void)

{
    ulonglong *puVar1;

    puVar1 = (ulonglong *)FUN_1800011e0();
    *puVar1 = *puVar1 | 4;
    puVar1 = (ulonglong *)FUN_180007e08();
    *puVar1 = *puVar1 | 2;
    return;
}

undefined *FUN_180007e2c(void)

{
    return &DAT_180013a18;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Multiple Matches With Different Base Names
//  _RTC_Initialize
//  _RTC_Terminate
//
// Library: Visual Studio 2017 Release

void FID_conflict__RTC_Initialize(void)

{
    code **ppcVar1;

    for (ppcVar1 = (code **)&DAT_18000ad88; ppcVar1 < &DAT_18000ad88; ppcVar1 = ppcVar1 + 1)
    {
        if (*ppcVar1 != (code *)0x0)
        {
            (**ppcVar1)();
        }
    }
    return;
}

// WARNING: Function: _guard_dispatch_icall replaced with injection: guard_dispatch_icall
// Library Function - Multiple Matches With Different Base Names
//  _RTC_Initialize
//  _RTC_Terminate
//
// Library: Visual Studio 2017 Release

void FID_conflict__RTC_Initialize(void)

{
    code **ppcVar1;

    for (ppcVar1 = (code **)&DAT_18000ad98; ppcVar1 < &DAT_18000ad98; ppcVar1 = ppcVar1 + 1)
    {
        if (*ppcVar1 != (code *)0x0)
        {
            (**ppcVar1)();
        }
    }
    return;
}

// WARNING: Exceeded maximum restarts with more pending

void __CxxFrameHandler3(void)

{
    // WARNING: Could not recover jumptable at 0x000180007eb0. Too many branches
    // WARNING: Treating indirect jump as call
    __CxxFrameHandler3();
    return;
}

void __std_exception_copy(void)

{
    // WARNING: Could not recover jumptable at 0x000180007ebc. Too many branches
    // WARNING: Treating indirect jump as call
    __std_exception_copy();
    return;
}

void __std_exception_destroy(void)

{
    // WARNING: Could not recover jumptable at 0x000180007ec2. Too many branches
    // WARNING: Treating indirect jump as call
    __std_exception_destroy();
    return;
}

// WARNING: Exceeded maximum restarts with more pending

void _CxxThrowException(void *pExceptionObject, ThrowInfo *pThrowInfo)

{
    // WARNING: Could not recover jumptable at 0x000180007ec8. Too many branches
    // WARNING: Treating indirect jump as call
    _CxxThrowException();
    return;
}

void *memset(void *_Dst, int _Val, size_t _Size)

{
    void *pvVar1;

    // WARNING: Could not recover jumptable at 0x000180007ece. Too many branches
    // WARNING: Treating indirect jump as call
    pvVar1 = memset(_Dst, _Val, _Size);
    return pvVar1;
}

int _callnewh(size_t _Size)

{
    int iVar1;

    // WARNING: Could not recover jumptable at 0x000180007eda. Too many branches
    // WARNING: Treating indirect jump as call
    iVar1 = _callnewh(_Size);
    return iVar1;
}

void *malloc(size_t _Size)

{
    void *pvVar1;

    // WARNING: Could not recover jumptable at 0x000180007ee0. Too many branches
    // WARNING: Treating indirect jump as call
    pvVar1 = malloc(_Size);
    return pvVar1;
}

void _configure_narrow_argv(void)

{
    // WARNING: Could not recover jumptable at 0x000180007eec. Too many branches
    // WARNING: Treating indirect jump as call
    _configure_narrow_argv();
    return;
}

void _initialize_narrow_environment(void)

{
    // WARNING: Could not recover jumptable at 0x000180007ef2. Too many branches
    // WARNING: Treating indirect jump as call
    _initialize_narrow_environment();
    return;
}

void _initialize_onexit_table(void)

{
    // WARNING: Could not recover jumptable at 0x000180007ef8. Too many branches
    // WARNING: Treating indirect jump as call
    _initialize_onexit_table();
    return;
}

void _register_onexit_function(void)

{
    // WARNING: Could not recover jumptable at 0x000180007efe. Too many branches
    // WARNING: Treating indirect jump as call
    _register_onexit_function();
    return;
}

void _crt_atexit(void)

{
    // WARNING: Could not recover jumptable at 0x000180007f0a. Too many branches
    // WARNING: Treating indirect jump as call
    _crt_atexit();
    return;
}

void _cexit(void)

{
    // WARNING: Could not recover jumptable at 0x000180007f10. Too many branches
    // WARNING: Treating indirect jump as call
    _cexit();
    return;
}

void _initterm(void)

{
    // WARNING: Could not recover jumptable at 0x000180007f16. Too many branches
    // WARNING: Treating indirect jump as call
    _initterm();
    return;
}

void _initterm_e(void)

{
    // WARNING: Could not recover jumptable at 0x000180007f1c. Too many branches
    // WARNING: Treating indirect jump as call
    _initterm_e();
    return;
}

void free(void *_Memory)

{
    // WARNING: Could not recover jumptable at 0x000180007f22. Too many branches
    // WARNING: Treating indirect jump as call
    free(_Memory);
    return;
}

BOOL IsProcessorFeaturePresent(DWORD ProcessorFeature)

{
    BOOL BVar1;

    // WARNING: Could not recover jumptable at 0x000180007f28. Too many branches
    // WARNING: Treating indirect jump as call
    BVar1 = IsProcessorFeaturePresent(ProcessorFeature);
    return BVar1;
}

undefined FUN_180007f30(void)

{
    return 1;
}

undefined8 FUN_180007f34(void)

{
    return 0;
}

// Library Function - Single Match
//  __GSHandlerCheckCommon
//
// Libraries: Visual Studio 2017 Release, Visual Studio 2019 Release

void __GSHandlerCheckCommon(ulonglong param_1, longlong param_2, uint *param_3)

{
    ulonglong uVar1;
    ulonglong uVar2;

    uVar2 = param_1;
    if ((*(byte *)param_3 & 4) != 0)
    {
        uVar2 = (longlong)(int)param_3[1] + param_1 & (longlong)(int)-param_3[2];
    }
    uVar1 = (ulonglong) * (uint *)(*(longlong *)(param_2 + 0x10) + 8);
    if ((*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xf) != 0)
    {
        param_1 = param_1 + (*(byte *)(uVar1 + 3 + *(longlong *)(param_2 + 8)) & 0xfffffff0);
    }
    FUN_180006f40(param_1 ^ *(ulonglong *)((longlong)(int)(*param_3 & 0xfffffff8) + uVar2));
    return;
}

// WARNING: This is an inlined function
// Library Function - Single Match
//  _alloca_probe
//
// Libraries: Visual Studio 2015, Visual Studio 2017, Visual Studio 2019

void _alloca_probe(void)

{
    undefined *in_RAX;
    undefined *puVar1;
    undefined *puVar2;
    longlong in_GS_OFFSET;
    undefined local_res8[32];

    puVar1 = local_res8 + -(longlong)in_RAX;
    if (local_res8 < in_RAX)
    {
        puVar1 = (undefined *)0x0;
    }
    puVar2 = *(undefined **)(in_GS_OFFSET + 0x10);
    if (puVar1 < puVar2)
    {
        do
        {
            puVar2 = puVar2 + -0x1000;
            *puVar2 = 0;
        } while ((undefined *)((ulonglong)puVar1 & 0xfffffffffffff000) != puVar2);
    }
    return;
}

void *memcpy(void *_Dst, void *_Src, size_t _Size)

{
    void *pvVar1;

    // WARNING: Could not recover jumptable at 0x0001800080a1. Too many branches
    // WARNING: Treating indirect jump as call
    pvVar1 = memcpy(_Dst, _Src, _Size);
    return pvVar1;
}

// WARNING: This is an inlined function

void _guard_dispatch_icall(void)

{
    code *UNRECOVERED_JUMPTABLE;

    // WARNING: Could not recover jumptable at 0x0001800080c0. Too many branches
    // WARNING: Treating indirect jump as call
    (*UNRECOVERED_JUMPTABLE)();
    return;
}

void Unwind_1800080d0(LPCRITICAL_SECTION lpCriticalSection)

{
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    return;
}

void Unwind_1800080e0(undefined8 param_1, longlong param_2)

{
    free(*(void **)(param_2 + 0x58));
    return;
}

void FUN_180008115(undefined8 param_1, longlong param_2)

{
    __scrt_release_startup_lock(*(char *)(param_2 + 0x40));
    return;
}

void FUN_18000812c(undefined8 param_1, longlong param_2)

{
    __scrt_dllmain_uninitialize_critical();
    __scrt_release_startup_lock(*(char *)(param_2 + 0x38));
    return;
}

void FUN_180008148(undefined8 *param_1, longlong param_2)

{
    FUN_1800071e4(*(undefined8 *)(param_2 + 0x60), *(int *)(param_2 + 0x68),
                  *(undefined8 *)(param_2 + 0x70), dllmain_crt_dispatch, *(undefined4 *)*param_1, param_1);
    return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void FUN_1800081d0(void)

{
    longlong **pplVar1;
    longlong **_Memory;

    CloseHandle(DAT_18000d8b0);
    _Memory = (longlong **)*DAT_18000d8a0;
    *DAT_18000d8a0 = (longlong *)DAT_18000d8a0;
    DAT_18000d8a0[1] = (longlong *)DAT_18000d8a0;
    _DAT_18000d8a8 = 0;
    if (_Memory != DAT_18000d8a0)
    {
        do
        {
            pplVar1 = (longlong **)*_Memory;
            free(_Memory);
            _Memory = pplVar1;
        } while (pplVar1 != DAT_18000d8a0);
    }
    free(DAT_18000d8a0);
    // WARNING: Could not recover jumptable at 0x000180008259. Too many branches
    // WARNING: Treating indirect jump as call
    DeleteCriticalSection((LPCRITICAL_SECTION)&DAT_18000d878);
    return;
}
