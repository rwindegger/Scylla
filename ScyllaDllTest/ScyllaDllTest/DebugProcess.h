#pragma once
#include <windows.h>
#include <stdbool.h>
#include <stdint.h>

// Opaque handle for this API.
typedef HANDLE DBG_PROC_HANDLE;

typedef struct DEBUG_PROCESS_INFOS_T_
{
	uintptr_t ExeBaseAddress;
	uintptr_t ExeEntryPoint;
	size_t	  ProcessPID;

} DEBUG_PROCESS_INFOS;

// Launch a process and break it before executing any of it's code.
bool FreezeProcessOnStartup(const TCHAR *tExePath, DBG_PROC_HANDLE *phDbgProc);

// Get Basic informations about debugged process
bool GetProcessInfos(DBG_PROC_HANDLE hDbgProc, DEBUG_PROCESS_INFOS *pDbgProcInfos);

// Stop debugging process and kill it.
bool StopProcess(DBG_PROC_HANDLE hDbgProc);