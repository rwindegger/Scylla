
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include "ScyllaLoad.h"


void testGui(SCYLLA_DLL ScyllaDllObject);
bool testIatSearch(TCHAR *TargetProcess, SCYLLA_DLL ScyllaDllObject, uintptr_t TargetIATOffset, size_t TargetIATSize);
DWORD_PTR GetExeModuleBase(DWORD dwProcessId);
uintptr_t GetExeEntryPoint(DWORD dwProcessId);


TCHAR default_target[] = "ScyllaTestExe.exe";

HMODULE hScylla = 0;

DWORD GetCreatedProcessPID(DWORD ControllerPID)
{
	DWORD UniquePID = NULL;
	HANDLE  hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 ProcessInformation;
	ProcessInformation.dwSize = sizeof(PROCESSENTRY32);


	Process32First(hProcessSnap, &ProcessInformation);
	while (ProcessInformation.th32ParentProcessID != ControllerPID)
	{
		Process32Next(hProcessSnap, &ProcessInformation);

		// Found child process
		if (ProcessInformation.th32ParentProcessID == ControllerPID)
		{
			UniquePID = ProcessInformation.th32ProcessID;
		}
	}

	CloseHandle(hProcessSnap);
	return UniquePID;
}

int _tmain(int argc, TCHAR *argv[])
{
	SCYLLA_DLL ScyllaDll;

	// Target Executable to analyze
	TCHAR *target = default_target;
	uintptr_t target_iat_offset = 0x00;
	size_t target_iat_size = 0x00;
	if (argc >= 4)
	{
		target = argv[1];
		target_iat_offset = _tcstoumax( argv[2], NULL, 16);
		target_iat_size = _tcstoumax(argv[3], NULL, 16);
	}
	else
		return false;


#ifdef _WIN64
	TCHAR *ScyllaDllPath = _T("ScyllaDllx64.dll");
#else
	TCHAR *ScyllaDllPath = _T("ScyllaDllx86.dll");
#endif
	
	if (!ScyllaLoadDll(ScyllaDllPath, &ScyllaDll))
	{
		_tprintf(_T("Error while loading ScyllaDll : %d\n"), GetLastError());
		return 0x01;
	}

	if (!testIatSearch(target, ScyllaDll, target_iat_offset, target_iat_size))
		return 0x01;

	return 0x00;
}

void testGui(SCYLLA_DLL ScyllaDllObject)
{
	printf("----------------\nGUI TEST\n----------------\n");

	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFO);

	if (CreateProcessW(0, (WCHAR*) default_target, 0, 0, TRUE, CREATE_SUSPENDED, 0, 0, &si, &pi))
	{
		//Sleep(1000);


		DWORD_PTR hMod = GetExeModuleBase(pi.dwProcessId);
		_tprintf(_T("GetExeModuleBase %p\n"), (void*) hMod);

		ScyllaDllObject.ScyllaStartGui(pi.dwProcessId, 0);

		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}


bool testIatSearch(TCHAR *TargetProcess, SCYLLA_DLL ScyllaDllObject, uintptr_t TargetIATOffset, size_t TargetIATSize)
{
	printf("----------------\nIAT Search Test\n----------------\n");

	
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFO);

	if (!CreateProcess(0, TargetProcess, 0, 0, TRUE, DEBUG_PROCESS, 0, 0, &si, &pi))
	{
		_tprintf(_T("Error while creating process : %s\n"), TargetProcess);
		return false;
	}

	DebugSetProcessKillOnExit(TRUE);
	DebugActiveProcess(pi.dwProcessId);
	
	DEBUG_EVENT debugEvent = { 0 };
	do {
		if (!WaitForDebugEvent(&debugEvent, 10*1000 /*INFINITE*/))
		{
			goto DEBUG_TIMEOUT;
		}

		// Stop on debug exception
		if (debugEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT)
			ContinueDebugEvent(debugEvent.dwProcessId,
				debugEvent.dwThreadId,
				DBG_CONTINUE);

	} while (debugEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT || debugEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT || debugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT);


DEBUG_TIMEOUT:

	DWORD TargetPID = /*GetCreatedProcessPID(pi.dwProcessId)*/ pi.dwProcessId;
	DWORD_PTR iatStart = 0;
	DWORD iatSize = 0;

	DWORD_PTR BaseAddress = GetExeModuleBase(TargetPID);
	uintptr_t EntryPoint = GetExeEntryPoint(TargetPID);
	_tprintf(_T("GetExeModuleBase %p EntryPoint %p\n"), (void*)BaseAddress, (void*)EntryPoint);
	
	uintptr_t RefIATStart = BaseAddress + TargetIATOffset;
	size_t RefIATSize = TargetIATSize;

	int error = ScyllaDllObject.ScyllaIatSearch(TargetPID, &iatStart, &iatSize, EntryPoint, FALSE);
	_tprintf(_T("error %d iatStart %p iatSize %X\n"), error, (void*)iatStart, iatSize);
	if (!error)
	{
		bool bIATCorrectlyRetrieved = (iatStart <= RefIATStart) && (iatStart + iatSize >= RefIATStart + RefIATSize);
		_tprintf(_T("IAT Correctly retrieved : %d \n"), bIATCorrectlyRetrieved);

		if (!bIATCorrectlyRetrieved)
			error = 0x01;
	}

	DebugActiveProcessStop(pi.dwProcessId);
	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return error == 0;
}

DWORD_PTR GetExeModuleBase(DWORD dwProcessId)
{
	MODULEENTRY32 lpModuleEntry = { 0 };	
	HANDLE hProcessSnapShot = 0x00;
	DWORD_PTR ModuleBaseAddress = 0x00;

	hProcessSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);
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

uintptr_t GetExeEntryPoint(DWORD dwProcessId)
{
	HANDLE hProcess = NULL;
	HMODULE hMods[1024];
	DWORD cbNeeded;
	MODULEINFO ModuleInfo;
	uintptr_t EntryPoint = NULL;
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
	{
		goto GetExeEntryPoint_END;
	}

	if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		goto GetExeEntryPoint_END;
	}
	
	if (!GetModuleInformation(hProcess, hMods[0], &ModuleInfo, sizeof(MODULEINFO)))
	{
		goto GetExeEntryPoint_END;
	}

	EntryPoint = (uintptr_t) ModuleInfo.EntryPoint;

GetExeEntryPoint_END:
	if (hProcess) 
	{
		CloseHandle(hProcess);
	}
	
	return EntryPoint;
}