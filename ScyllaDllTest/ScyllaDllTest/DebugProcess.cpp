#include "DebugProcess.h"
#include <psapi.h>
#include <tlhelp32.h>
#include <tchar.h>

typedef struct DEBUG_PROCESS_T_
{
	HANDLE hDebuggedProc;
	HANDLE hDebuggedThread;
	size_t DebuggedPID;

} DEBUG_PROCESS_T;

// Return the target executable module base address
DWORD_PTR PrivateGetExeModuleBase(size_t dwProcessId)
{
	MODULEENTRY32 lpModuleEntry = { 0 };	
	HANDLE hProcessSnapShot = 0x00;
	DWORD_PTR ModuleBaseAddress = 0x00;

	hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, (DWORD) dwProcessId);
	if (INVALID_HANDLE_VALUE == hProcessSnapShot)
		return 0x00;

	// Executable is always the first module loaded
	lpModuleEntry.dwSize = sizeof(lpModuleEntry);
	if (Module32First(hProcessSnapShot, &lpModuleEntry))
	{
		ModuleBaseAddress = (DWORD_PTR)lpModuleEntry.modBaseAddr;
	}

	CloseHandle(hProcessSnapShot);
	return ModuleBaseAddress;
}

// Return the target executable entry point (if it does exist)
uintptr_t PrivateGetExeEntryPoint(size_t dwProcessId)
{
	HANDLE hProcess = NULL;
	HMODULE hMods[1024];
	DWORD cbNeeded;
	MODULEINFO ModuleInfo;
	uintptr_t EntryPoint = NULL;
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD) dwProcessId);
	if (!hProcess)
	{
		goto PrivateGetExeEntryPoint_END;
	}

	// Executable is always the first module loaded
	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		goto PrivateGetExeEntryPoint_END;
	}
	
	if (!GetModuleInformation(hProcess, hMods[0], &ModuleInfo, sizeof(MODULEINFO)))
	{
		goto PrivateGetExeEntryPoint_END;
	}

	EntryPoint = (uintptr_t) ModuleInfo.EntryPoint;

PrivateGetExeEntryPoint_END:
	if (hProcess) 
	{
		CloseHandle(hProcess);
	}
	
	return EntryPoint;
}

bool FreezeProcessOnStartup(const TCHAR *tExePath, DBG_PROC_HANDLE *phDbgProc)
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	DEBUG_EVENT debugEvent = { 0 };
	DEBUG_PROCESS_T* pPrivateDbgProc = 0;

	// allocate private memory for returned handle
	pPrivateDbgProc = (DEBUG_PROCESS_T*) calloc (1, sizeof(DEBUG_PROCESS_T));
	if (!pPrivateDbgProc)
		return false;


	// Create target process
	si.cb = sizeof(STARTUPINFO);
	if (!CreateProcess(0, (TCHAR*) tExePath, 0, 0, TRUE, DEBUG_PROCESS, 0, 0, &si, &pi))
	{
		goto FreezeProcessOnStartup_ERROR;
	}

	// Check whether calling and debugged process have the same arch
	// In theory x64 process can debug x86 process, but to do so we need
	// to handle the Wow64 emulation layer (EXCEPTION_DEBUG_EVENT will fire 
	// when all x64 dll are loaded, but x86 aren't) and it's a major hassle.
	BOOL bTargetProcessArch = FALSE;
	BOOL bCallerProcessArch = FALSE;
	IsWow64Process(pi.hProcess, &bTargetProcessArch);
	IsWow64Process(GetCurrentProcess(), &bCallerProcessArch);
	if (bTargetProcessArch != bCallerProcessArch)
	{
		// Indicating the error type for the caller to understand why it failed.
		SetLastError(ERROR_BAD_EXE_FORMAT);
		goto FreezeProcessOnStartup_ERROR;
	}		

	pPrivateDbgProc-> hDebuggedProc = pi.hProcess;
	pPrivateDbgProc-> hDebuggedThread = pi.hThread;
	pPrivateDbgProc-> DebuggedPID = pi.dwProcessId;

	// Monitoring debug events for EXECPTION_DEBUG_EVENT,
	// indicating our process has loaded all the needed dll and resources
	// and it's ready to go.
	DebugSetProcessKillOnExit(TRUE);
	DebugActiveProcess(pi.dwProcessId);

	do {
		if (!WaitForDebugEvent(&debugEvent, 10*1000 /*INFINITE*/))
		{
			// Timeout => go on error;
			goto FreezeProcessOnStartup_ERROR;
		}

		// Stop on debug exception
		switch (debugEvent.dwDebugEventCode)
		{
		case EXCEPTION_DEBUG_EVENT:
			goto FreezeProcessOnStartup_SUCCESS;

		case UNLOAD_DLL_DEBUG_EVENT:
			// Allow the x64 system dlls to be unloaded when dealing with a x86 process
			// To be really clean, we need to check if the currently unloaded dll is a 
			// well-known DLL. Unfortunately, there is no easy way to do so.
			if (!bTargetProcessArch )
			{
				goto FreezeProcessOnStartup_ERROR;
			}
			
		case LOAD_DLL_DEBUG_EVENT:
		case CREATE_THREAD_DEBUG_EVENT:
		case CREATE_PROCESS_DEBUG_EVENT:
			ContinueDebugEvent(
					debugEvent.dwProcessId,
					debugEvent.dwThreadId,
					DBG_CONTINUE);
			break;

		default:
			goto FreezeProcessOnStartup_ERROR;
		} 	
		
	} while (true);


	// return a null handle on error => the caller need to check it.
FreezeProcessOnStartup_ERROR:
	
	StopProcess((DBG_PROC_HANDLE) pPrivateDbgProc); // mem free is done here
	pPrivateDbgProc = NULL;
	
	return false;

	
FreezeProcessOnStartup_SUCCESS:
	*phDbgProc = (DBG_PROC_HANDLE) pPrivateDbgProc;
	return true;
}

// Get Basic informations about debugged process
bool GetProcessInfos(DBG_PROC_HANDLE hDbgProc, DEBUG_PROCESS_INFOS *pDbgProcInfos)
{
	DEBUG_PROCESS_T* pPrivateDbgProc = (DEBUG_PROCESS_T*) hDbgProc;

	if (!pPrivateDbgProc)
		return false;

	memset(pDbgProcInfos, 0, sizeof (DEBUG_PROCESS_INFOS));
	
	pDbgProcInfos->ExeBaseAddress = PrivateGetExeModuleBase(pPrivateDbgProc->DebuggedPID);
	// No module can be mapped at null address
	if (!pDbgProcInfos->ExeBaseAddress)
		return false;

	pDbgProcInfos->ExeEntryPoint = PrivateGetExeEntryPoint(pPrivateDbgProc->DebuggedPID);
	// No entry point => is it a dll ?
	if (!pDbgProcInfos->ExeEntryPoint)
		return false;

	pDbgProcInfos->ProcessPID = pPrivateDbgProc->DebuggedPID;
	return true;
}

bool StopProcess(DBG_PROC_HANDLE hDbgProc)
{
	DEBUG_PROCESS_T* pPrivateDbgProc = (DEBUG_PROCESS_T*) hDbgProc;

	if (!pPrivateDbgProc)
		return false;

	// Kill target process
	DebugActiveProcessStop((DWORD) pPrivateDbgProc->DebuggedPID);
	TerminateProcess(pPrivateDbgProc->hDebuggedProc, 0);

	// Cleanup
	CloseHandle(pPrivateDbgProc->hDebuggedProc);
	CloseHandle(pPrivateDbgProc->hDebuggedThread);
	free(pPrivateDbgProc);

	return true;
}