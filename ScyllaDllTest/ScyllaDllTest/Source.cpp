
#include <windows.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <psapi.h>
#include "ScyllaLoad.h"
#include "DebugProcess.h"


//void testGui(SCYLLA_DLL ScyllaDllObject);
bool testIatSearch(TCHAR *TargetProcess, SCYLLA_DLL ScyllaDllObject, uintptr_t TargetIATOffset, size_t TargetIATSize);


TCHAR default_target[] = "ScyllaTestExe.exe";

HMODULE hScylla = 0;

/*DWORD GetCreatedProcessPID(DWORD ControllerPID)
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
}*/

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
		return GetLastError();
	

	return 0x00;
}

//void testGui(SCYLLA_DLL ScyllaDllObject)
//{
//	printf("----------------\nGUI TEST\n----------------\n");
//
//	STARTUPINFOW si = { 0 };
//	PROCESS_INFORMATION pi = { 0 };
//	si.cb = sizeof(STARTUPINFO);
//
//	if (CreateProcessW(0, (WCHAR*) default_target, 0, 0, TRUE, CREATE_SUSPENDED, 0, 0, &si, &pi))
//	{
//		//Sleep(1000);
//
//
//		DWORD_PTR hMod = GetExeModuleBase(pi.dwProcessId);
//		_tprintf(_T("GetExeModuleBase %p\n"), (void*) hMod);
//
//		ScyllaDllObject.ScyllaStartGui(pi.dwProcessId, 0);
//
//		TerminateProcess(pi.hProcess, 0);
//		CloseHandle(pi.hThread);
//		CloseHandle(pi.hProcess);
//	}
//}


bool testIatSearch(TCHAR *TargetProcess, SCYLLA_DLL ScyllaDllObject, uintptr_t TargetIATOffset, size_t TargetIATSize)
{
	_tprintf(("----------------\n"));
	_tprintf(("IAT Search Test : \n"));
	_tprintf(("\t Executable : %s \n"), TargetProcess);
	_tprintf(("----------------\n"));


	bool bIATCorrectlyRetrieved = false;
	DBG_PROC_HANDLE hDbgProcess = 0;
	DEBUG_PROCESS_INFOS DbgProcInfos = {0};
	SCY_HANDLE hScyContext = NULL;

	if (!FreezeProcessOnStartup(TargetProcess, &hDbgProcess))
	{
		_tprintf(_T("[x] Error while creating process %s  : %d \n"), TargetProcess, GetLastError());
		return false;
	}
	
	if (!GetProcessInfos(hDbgProcess, &DbgProcInfos))
	{
		_tprintf(_T("[x] Could not retrieve informations about process %s  : %d \n"), TargetProcess, GetLastError());
		goto testIatSearch_END;
	}

	uintptr_t RefIATStart = DbgProcInfos.ExeBaseAddress + TargetIATOffset;
	size_t RefIATSize = TargetIATSize;
	

	uintptr_t CalcIatStartAddress = 0x00;
	size_t CalcIatSize = 0x00;

	if (!ScyllaDllObject.ScyllaInitContext(&hScyContext, (DWORD)DbgProcInfos.ProcessPID))
	{
		_tprintf(_T("[x] Could not init a scylla contexty on process %s  : %d \n"), TargetProcess, GetLastError());
		goto testIatSearch_END;
	}

	// Starting a IAT automatic search on exe entry point.
	if (!ScyllaDllObject.ScyllaIatSearch(hScyContext, (DWORD_PTR*)&CalcIatStartAddress, (DWORD*)&CalcIatSize, (DWORD_PTR)DbgProcInfos.ExeEntryPoint, FALSE))
	{
		bIATCorrectlyRetrieved = true;

		// Checking that the calculated IAT at least contains the origin IAT (surjective mapping).
		bool bContainsOrigIAT = (CalcIatStartAddress <= RefIATStart) && (CalcIatStartAddress + CalcIatSize >= RefIATStart + RefIATSize);
		
		if (!bContainsOrigIAT)
			bIATCorrectlyRetrieved = false;
	}
	
	_tprintf(_T("[.] Reference IAT address: %p - %p \n"), (void*) RefIATStart, (void*) (RefIATStart + RefIATSize));
	_tprintf(_T("[.] Reference IAT Size: %zx \n"), RefIATSize);
	_tprintf(_T("[.] Computed  IAT address: %p - %p \n"), (void*) CalcIatStartAddress, (void*)(CalcIatStartAddress + CalcIatSize));
	_tprintf(_T("[.] Computed  IAT Size: %zx \n"), CalcIatSize);
	_tprintf(_T("[.] IAT Correctly retrieved : %s \n"), bIATCorrectlyRetrieved ? _T("true") : _T("false"));

testIatSearch_END:
	ScyllaDllObject.ScyllaUnInitContext(hScyContext);
	StopProcess(hDbgProcess);
	return bIATCorrectlyRetrieved;
}

