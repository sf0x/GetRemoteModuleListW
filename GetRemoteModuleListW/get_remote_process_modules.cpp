#include "pch.h"

#include "get_remote_process_modules.h"
#include "ord.h"

#include <Windows.h>
#include <iostream>

BOOL fnGetRemoteModuleListW(HANDLE hProcess, wchar_t aModules[MAXIMUM_MODULES][MAX_PATH * 2]) {
	ORD3_PROCESS_BASIC_INFORMATION procBasicInfo;
	NTSTATUS status = OrdNtQueryInformationProcess(hProcess, 0, &procBasicInfo, sizeof(procBasicInfo), nullptr);
	if (!status) {
		if (hProcess) {
			ORD3_PEB peb = { 0 };
			ORD3_PEB_LDR_DATA ldr = { 0 };
			ORD3_FULL_LDR_DATA_TABLE_ENTRY ldrEntry = { 0 };
			size_t dwRead = 0;
			if (ReadProcessMemory(hProcess, procBasicInfo.PebBaseAddress, &peb, sizeof(ORD3_PEB), &dwRead)) {
				if (ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(ORD3_PEB_LDR_DATA), &dwRead)) {
					LIST_ENTRY moduleList = ldr.InMemoryOrderModuleList;
					LIST_ENTRY* pNextModule = moduleList.Flink;
					if (ReadProcessMemory(hProcess, CONTAINING_RECORD(pNextModule, ORD3_FULL_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList), &ldrEntry, sizeof(ORD3_FULL_LDR_DATA_TABLE_ENTRY), &dwRead)) {
						int i = 0;
						while (TRUE) {
							if (ldrEntry.DllBase == NULL) {
								break;
							}
							if (ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, &aModules[i], ldrEntry.FullDllName.MaximumLength, &dwRead)) {
								pNextModule = ldrEntry.InMemoryOrderModuleList.Flink;
								if (ReadProcessMemory(hProcess, CONTAINING_RECORD(pNextModule, ORD3_FULL_LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList), &ldrEntry, sizeof(ORD3_FULL_LDR_DATA_TABLE_ENTRY), &dwRead)) {
									i++;
									continue;
								}
							}
						}
					}
				}
			}
		}
	}
	return TRUE;
}
