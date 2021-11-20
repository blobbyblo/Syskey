#pragma once

#include <cstdint>

typedef struct _UNICODE_STRING
{
    std::uint16_t Length;
    std::uint16_t MaximumLength;
    const wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LINKED_LIST_ENTRY
{
    struct _LINKED_LIST_ENTRY* Flink;
    struct _LINKED_LIST_ENTRY* Blink;
} LINKED_LIST_ENTRY, * PLINKED_LIST_ENTRY, PRLINKED_LIST_ENTRY;

typedef struct _PEB_LDR_DATA
{
    std::uint8_t    Reserved1[8];
    void* Reserved2[3];
    LINKED_LIST_ENTRY      InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LINKED_LIST_ENTRY InLoadOrderLinks;
    LINKED_LIST_ENTRY InMemoryOrderModuleList;
    LINKED_LIST_ENTRY InInitializationOrderModuleList;
    void* DllBase;
    void* EntryPoint;
    std::uint32_t SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    std::uint32_t Flags;
    std::uint16_t LoadCount;
    std::uint16_t TlsIndex;
    union
    {
        LINKED_LIST_ENTRY HashLinks;
        void* SectionPointer;
    };
    std::uint32_t CheckSum;
    union
    {
        std::uint32_t TimeDateStamp;
        void* LoadedImports;
    };
    void* EntryPointActivationContext;
    void* PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

#define IMAGE_DOS_SIGNATURE 0x5A4D     // MZ

typedef struct _IMAGE_DOS_HEADERS
{
    std::uint16_t e_magic;
    std::uint16_t e_cblp;
    std::uint16_t e_cp;
    std::uint16_t e_crlc;
    std::uint16_t e_cparhdr;
    std::uint16_t e_minalloc;
    std::uint16_t e_maxalloc;
    std::uint16_t e_ss;
    std::uint16_t e_sp;
    std::uint16_t e_csum;
    std::uint16_t e_ip;
    std::uint16_t e_cs;
    std::uint16_t e_lfarlc;
    std::uint16_t e_ovno;
    std::uint16_t e_res[4];
    std::uint16_t e_oemid;
    std::uint16_t e_oeminfo;
    std::uint16_t e_res2[10];
    std::int32_t e_lfanew;
} IMAGE_DOS_HEADERS, * PIMAGE_DOS_HEADERS;

typedef struct _IMAGE_FILE_HEADERS
{
    std::uint16_t Machine;
    std::uint16_t NumberOfSections;
    std::uint32_t TimeDateStamp;
    std::uint32_t PointerToSymbolTable;
    std::uint32_t NumberOfSymbols;
    std::uint16_t SizeOfOptionalHeader;
    std::uint16_t Characteristics;
} IMAGE_FILE_HEADERS, * PIMAGE_FILE_HEADERS;

typedef struct _IMAGE_DATA_DIRECTORYS
{
    std::uint32_t VirtualAddress;
    std::uint32_t Size;
} IMAGE_DATA_DIRECTORYS, * PIMAGE_DATA_DIRECTORYS;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER64S
{
    std::uint16_t Magic;
    std::uint8_t MajorLinkerVersion;
    std::uint8_t MinorLinkerVersion;
    std::uint32_t SizeOfCode;
    std::uint32_t SizeOfInitializedData;
    std::uint32_t SizeOfUninitializedData;
    std::uint32_t AddressOfEntryPoint;
    std::uint32_t BaseOfCode;
    std::uint64_t ImageBase;
    std::uint32_t SectionAlignment;
    std::uint32_t FileAlignment;
    std::uint16_t MajorOperatingSystemVersion;
    std::uint16_t MinorOperatingSystemVersion;
    std::uint16_t MajorImageVersion;
    std::uint16_t MinorImageVersion;
    std::uint16_t MajorSubsystemVersion;
    std::uint16_t MinorSubsystemVersion;
    std::uint32_t Win32VersionValue;
    std::uint32_t SizeOfImage;
    std::uint32_t SizeOfHeaders;
    std::uint32_t CheckSum;
    std::uint16_t Subsystem;
    std::uint16_t DllCharacteristics;
    std::uint64_t SizeOfStackReserve;
    std::uint64_t SizeOfStackCommit;
    std::uint64_t SizeOfHeapReserve;
    std::uint64_t SizeOfHeapCommit;
    std::uint32_t LoaderFlags;
    std::uint32_t NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORYS DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64S, * PIMAGE_OPTIONAL_HEADER64S;

#define IMAGE_NT_SIGNATURE 0x00004550  // PE00

typedef struct _IMAGE_NT_HEADERS64S
{
    std::uint32_t Signature;
    struct _IMAGE_FILE_HEADERS FileHeader;
    struct _IMAGE_OPTIONAL_HEADER64S OptionalHeader;
} IMAGE_NT_HEADERS64S, * PIMAGE_NT_HEADERS64S;

#define IMAGE_DIRECTORY_ENTRY_EXPORT 0     // Export Directory

typedef struct _IMAGE_EXPORT_DIRECTORYS
{
    std::uint32_t Characteristics;
    std::uint32_t TimeDateStamp;
    std::uint16_t MajorVersion;
    std::uint16_t MinorVersion;
    std::uint32_t Name;
    std::uint32_t Base;
    std::uint32_t NumberOfFunctions;
    std::uint32_t NumberOfNames;
    std::uint32_t AddressOfFunctions;     // RVA from base of image
    std::uint32_t AddressOfNames;         // RVA from base of image
    std::uint32_t AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORYS, * PIMAGE_EXPORT_DIRECTORYS;
