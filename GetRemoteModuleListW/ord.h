#pragma once

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

#ifndef ORD3_HEADER_H_
#define ORD3_HEADER_H_

#include <windows.h>

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#define ORD3_SEED 0xC7E207E6
#define ORD3_ROL8(v) (v << 8 | v >> 24)
#define ORD3_ROR8(v) (v >> 8 | v << 24)
#define ORD3_ROX8(v) ((ORD3_SEED % 2) ? ORD3_ROL8(v) : ORD3_ROR8(v))
#define ORD3_MAX_ENTRIES 600
#define ORD3_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

// Typedefs are prefixed to avoid pollution.

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;


// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
typedef struct _ORD3_FULL_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        struct
        {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} ORD3_FULL_LDR_DATA_TABLE_ENTRY, * PORD3_FULL_LDR_DATA_TABLE_ENTRY;

typedef struct _ORD3_SYSCALL_ENTRY
{
    DWORD Hash;
    DWORD Address;
    PVOID SyscallAddress;
} ORD3_SYSCALL_ENTRY, * PORD3_SYSCALL_ENTRY;

typedef struct _ORD3_SYSCALL_LIST
{
    DWORD Count;
    ORD3_SYSCALL_ENTRY Entries[ORD3_MAX_ENTRIES];
} ORD3_SYSCALL_LIST, * PORD3_SYSCALL_LIST;

typedef struct _ORD3_PEB_LDR_DATA {
    BYTE Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} ORD3_PEB_LDR_DATA, * PORD3_PEB_LDR_DATA;

typedef struct _ORD3_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
} ORD3_LDR_DATA_TABLE_ENTRY, * PORD3_LDR_DATA_TABLE_ENTRY;

typedef struct _ORD3_PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PORD3_PEB_LDR_DATA Ldr;
} ORD3_PEB, * PORD3_PEB;

DWORD ORD3_HashSyscall(PCSTR FunctionName);
BOOL ORD3_PopulateSyscallList();
EXTERN_C DWORD ORD3_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID ORD3_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);

typedef struct _ORD3_PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    SHORT BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} ORD3_PROCESS_BASIC_INFORMATION;

EXTERN_C NTSTATUS OrdNtQueryInformationProcess(
    IN HANDLE ProcessHandle,
    IN UINT ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN ULONG ProcessInformationLength,
    OUT PULONG ReturnLength OPTIONAL);

#endif
