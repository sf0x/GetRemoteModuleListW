#include "pch.h"

#include "ord.h"
#include <stdio.h>

//#define DEBUG

// JUMPER

#ifdef _M_IX86

EXTERN_C PVOID internal_cleancall_wow64_gate(VOID) {
    return (PVOID)__readfsdword(0xC0);
}

__declspec(naked) BOOL local_is_wow64(void)
{
    __asm {
        mov eax, fs: [0xc0]
        test eax, eax
        jne wow64
        mov eax, 0
        ret
        wow64 :
        mov eax, 1
            ret
    }
}


#endif

// Code below is adapted from @modexpblog. Read linked article for more details.
// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams

ORD3_SYSCALL_LIST ORD3_SyscallList;

// SEARCH_AND_REPLACE
#ifdef SEARCH_AND_REPLACE
// THIS IS NOT DEFINED HERE; don't know if I'll add it in a future release
EXTERN void SearchAndReplace(unsigned char[], unsigned char[]);
#endif

DWORD ORD3_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = ORD3_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + ORD3_ROR8(Hash);
    }

    return Hash;
}

#ifndef JUMPER
PVOID SC_Address(PVOID NtApiAddress)
{
    return NULL;
}
#else
PVOID SC_Address(PVOID NtApiAddress)
{
    DWORD searchLimit = 512;
    PVOID SyscallAddress;

#ifdef _WIN64
    // If the process is 64-bit on a 64-bit OS, we need to search for syscall
    BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
    ULONG distance_to_syscall = 0x12;
#else
    // If the process is 32-bit on a 32-bit OS, we need to search for sysenter
    BYTE syscall_code[] = { 0x0f, 0x34, 0xc3 };
    ULONG distance_to_syscall = 0x0f;
#endif

#ifdef _M_IX86
    // If the process is 32-bit on a 64-bit OS, we need to jump to WOW32Reserved
    if (local_is_wow64())
    {
#ifdef DEBUG
        printf("[+] Running 32-bit app on x64 (WOW64)\n");
#endif
        return NULL;
    }
#endif

    // we don't really care if there is a 'jmp' between
    // NtApiAddress and the 'syscall; ret' instructions
    SyscallAddress = ORD3_RVA2VA(PVOID, NtApiAddress, distance_to_syscall);

    if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
    {
        // we can use the original code for this system call :)
#if defined(DEBUG)
        printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
        return SyscallAddress;
    }

    // the 'syscall; ret' intructions have not been found,
    // we will try to use one near it, similarly to HalosGate

    for (ULONG32 num_jumps = 1; num_jumps < searchLimit; num_jumps++)
    {
        // let's try with an Nt* API below our syscall
        SyscallAddress = ORD3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall + num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
#if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
            return SyscallAddress;
        }

        // let's try with an Nt* API above our syscall
        SyscallAddress = ORD3_RVA2VA(
            PVOID,
            NtApiAddress,
            distance_to_syscall - num_jumps * 0x20);
        if (!memcmp((PVOID)syscall_code, SyscallAddress, sizeof(syscall_code)))
        {
#if defined(DEBUG)
            printf("Found Syscall Opcodes at address 0x%p\n", SyscallAddress);
#endif
            return SyscallAddress;
        }
    }

#ifdef DEBUG
    printf("Syscall Opcodes not found!\n");
#endif

    return NULL;
}
#endif


BOOL ORD3_PopulateSyscallList()
{
    // Return early if the list is already populated.
    if (ORD3_SyscallList.Count) return TRUE;

#ifdef _WIN64
    PORD3_PEB Peb = (PORD3_PEB)__readgsqword(0x60);
#else
    PORD3_PEB Peb = (PORD3_PEB)__readfsdword(0x30);
#endif
    PORD3_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // Get the DllBase address of NTDLL.dll. NTDLL is not guaranteed to be the second
    // in the list, so it's safer to loop through the full list and find it.
    PORD3_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PORD3_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PORD3_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = ORD3_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)ORD3_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // If this is NTDLL.dll, exit loop.
        PCHAR DllName = ORD3_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = ORD3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = ORD3_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = ORD3_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // Populate ORD3_SyscallList with unsorted Zw* entries.
    DWORD i = 0;
    PORD3_SYSCALL_ENTRY Entries = ORD3_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = ORD3_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = ORD3_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(ORD3_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == ORD3_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system calls found.
    ORD3_SyscallList.Count = i;

    // Sort the list by address in ascending order.
    for (DWORD i = 0; i < ORD3_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < ORD3_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries.
                ORD3_SYSCALL_ENTRY TempEntry;

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD ORD3_GetSyscallNumber(DWORD FunctionHash)
{
    // Ensure ORD3_SyscallList is populated.
    if (!ORD3_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < ORD3_SyscallList.Count; i++)
    {
        if (FunctionHash == ORD3_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

EXTERN_C PVOID ORD3_GetSyscallAddress(DWORD FunctionHash)
{
    // Ensure ORD3_SyscallList is populated.
    if (!ORD3_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < ORD3_SyscallList.Count; i++)
    {
        if (FunctionHash == ORD3_SyscallList.Entries[i].Hash)
        {
            return ORD3_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

EXTERN_C PVOID ORD3_GetRandomSyscallAddress(DWORD FunctionHash)
{
    // Ensure ORD3_SyscallList is populated.
    if (!ORD3_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD)rand()) % ORD3_SyscallList.Count;

    while (FunctionHash == ORD3_SyscallList.Entries[index].Hash) {
        // Spoofing the syscall return address
        index = ((DWORD)rand()) % ORD3_SyscallList.Count;
    }
    return ORD3_SyscallList.Entries[index].SyscallAddress;
}
