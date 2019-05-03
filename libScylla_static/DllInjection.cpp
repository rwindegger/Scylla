#include "DllInjection.h"
#include <Psapi.h>
#include "Scylla.h"

#include "NativeWinApi.h"
#include "ProcessAccessHelp.h"



	HMODULE DllInjection::dllInjection(HANDLE hProcess, const WCHAR * filename)
	{
		LPVOID remoteMemory = 0;
		SIZE_T memorySize = 0;
		HANDLE hThread = 0;
		HMODULE hModule = 0;

		memorySize = (wcslen(filename) + 1) * sizeof(WCHAR);

		if (memorySize < 7)
		{
			Scylla::debugLog.log(L"dllInjection :: memorySize invalid");
			return 0;
		}

		remoteMemory = VirtualAllocEx(hProcess, NULL, memorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (remoteMemory == 0)
		{
			Scylla::debugLog.log(L"dllInjection :: VirtualAllocEx failed 0x%X", GetLastError());
			return 0;
		}

		if (WriteProcessMemory(hProcess, remoteMemory, filename, memorySize, &memorySize))
		{
			hThread = startRemoteThread(hProcess,LoadLibraryW,remoteMemory);

			if (hThread)
			{
				WaitForSingleObject(hThread, INFINITE);

#ifdef _WIN64

				hModule = getModuleHandleByFilename(hProcess, filename);

#else
				//returns only 32 bit values -> design bug by microsoft
				if (!GetExitCodeThread(hThread, (LPDWORD) &hModule))
				{
					Scylla::debugLog.log(L"dllInjection :: GetExitCodeThread failed 0x%X", GetLastError());
					hModule = 0;
				}
#endif

				CloseHandle(hThread);
			}
			else
			{
				Scylla::debugLog.log(L"dllInjection :: CreateRemoteThread failed 0x%X", GetLastError());
			}
		}
		else
		{
			Scylla::debugLog.log(L"dllInjection :: WriteProcessMemory failed 0x%X", GetLastError());
		}


		VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

		return hModule;
	}

	bool DllInjection::unloadDllInProcess(HANDLE hProcess, HMODULE hModule)
	{
		HANDLE hThread = 0;
		DWORD lpThreadId = 0;
		BOOL freeLibraryRet = 0;

		
		hThread = startRemoteThread(hProcess,FreeLibrary,hModule);

		if (hThread)
		{
			WaitForSingleObject(hThread, INFINITE);

			if (!GetExitCodeThread(hThread, (LPDWORD) &freeLibraryRet))
			{
				Scylla::debugLog.log(L"unloadDllInProcess :: GetExitCodeThread failed 0x%X", GetLastError());
				freeLibraryRet = 0;
			}

			CloseHandle(hThread);
		}
		else
		{
			Scylla::debugLog.log(L"unloadDllInProcess :: CreateRemoteThread failed 0x%X", GetLastError());
		}

		return freeLibraryRet != 0;
	}

	HMODULE DllInjection::getModuleHandleByFilename( HANDLE hProcess, const WCHAR * filename )
	{
		HMODULE * hMods = 0;
		HMODULE hModResult = 0;
		WCHAR target[MAX_PATH];

		DWORD numHandles = ProcessAccessHelp::getModuleHandlesFromProcess(hProcess, &hMods);
		if (numHandles == 0)
		{
			return 0;
		}

		for (DWORD i = 0; i < numHandles; i++)
		{
			if (GetModuleFileNameExW(hProcess, hMods[i], target, _countof(target)))
			{
				if (!_wcsicmp(target, filename))
				{
					hModResult = hMods[i];
					break;
				}
			}
			else
			{
				Scylla::debugLog.log(L"DllInjection::getModuleHandle :: GetModuleFileNameExW failed 0x%X", GetLastError());
			}
		}

		if (!hModResult)
		{
			Scylla::debugLog.log(L"DllInjection::getModuleHandle :: Handle not found");
		}

		delete [] hMods;

		return hModResult;
	}

	void DllInjection::specialThreadSettings( HANDLE hThread )
	{
		if (hThread)
		{
			if (!SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL))
			{
				Scylla::debugLog.log(L"specialThreadSettings :: SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL) failed 0x%X", GetLastError());
			}

			if (NativeWinApi::NtSetInformationThread)
			{
				if (NativeWinApi::NtSetInformationThread(hThread, ThreadHideFromDebugger, 0, 0) != STATUS_SUCCESS)
				{
					Scylla::debugLog.log(L"specialThreadSettings :: NtSetInformationThread ThreadHideFromDebugger failed");
				}
			}
		}
	}

	HANDLE DllInjection::startRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
	{
		HANDLE hThread = 0;

		hThread = customCreateRemoteThread(hProcess, lpStartAddress, lpParameter);

		if (hThread)
		{
			specialThreadSettings(hThread);
			ResumeThread(hThread);
		}

		return hThread;
	}

	HANDLE DllInjection::customCreateRemoteThread(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter)
	{
		DWORD lpThreadId = 0;
		HANDLE hThread = 0;
		NTSTATUS ntStatus = 0;

		if (NativeWinApi::NtCreateThreadEx)
		{
			#define THREAD_ALL_ACCESS_VISTA_7 (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

			//for windows vista/7
			ntStatus = NativeWinApi::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS_VISTA_7, 0, hProcess, (LPTHREAD_START_ROUTINE)lpStartAddress, (LPVOID)lpParameter, NtCreateThreadExFlagCreateSuspended|NtCreateThreadExFlagHideFromDebugger, 0, 0, 0, 0);
			if (NT_SUCCESS(ntStatus))
			{
				return hThread;
			}
			else
			{
				Scylla::debugLog.log(L"customCreateRemoteThread :: NtCreateThreadEx failed 0x%X", NativeWinApi::RtlNtStatusToDosError(ntStatus));
				return 0;
			}
		}
		else
		{
			return CreateRemoteThread(hProcess,NULL,NULL,(LPTHREAD_START_ROUTINE)lpStartAddress,lpParameter,CREATE_SUSPENDED,&lpThreadId);
		}
	}
