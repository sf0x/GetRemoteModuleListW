#include "pch.h"

#include "get_remote_process_modules.h"
#include "ord.h"

#include <Windows.h>
#include <iostream>

int main()
{
    DWORD dwTargetPid = 4396;
    wchar_t aModules[MAXIMUM_MODULES][MAX_PATH * 2];

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPid);

    fnGetRemoteModuleListW(hProcess, aModules);

    int i = 0;
    while (aModules[i][0] == L'C') {
        wprintf(L"Module: %s\n", aModules[i]);
        i++;
    }

    CloseHandle(hProcess);
    return 0;
}
