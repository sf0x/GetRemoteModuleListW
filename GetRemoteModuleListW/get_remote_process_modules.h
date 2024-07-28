#pragma once

#include <Windows.h>

#define MAXIMUM_MODULES 0x100

BOOL fnGetRemoteModuleListW(HANDLE hProcess, wchar_t aModules[MAXIMUM_MODULES][MAX_PATH * 2]);