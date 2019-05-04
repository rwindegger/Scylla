#include "DllInjection.h"
#include <Psapi.h>
#include "Scylla.h"

#include "NativeWinApi.h"
#include "ProcessAccessHelp.h"

HMODULE DllInjection::dllInjection(HANDLE hProcess, LPCTSTR filename)
{
    SIZE_T memorySize;
    HMODULE hModule = nullptr;

    memorySize = (_tcslen(filename) + 1) * sizeof(TCHAR);

    if (memorySize < 7)
    {
        Scylla::debugLog.log(TEXT("dllInjection :: memorySize invalid"));
        return nullptr;
    }

    const LPCVOID remoteMemory = VirtualAllocEx(hProcess, nullptr, memorySize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (remoteMemory == nullptr)
    {
        Scylla::debugLog.log(TEXT("dllInjection :: VirtualAllocEx failed 0x%X"), GetLastError());
        return nullptr;
    }

    if (WriteProcessMemory(hProcess, const_cast<LPVOID>(remoteMemory), filename, memorySize, &memorySize))
    {
        const auto hThread = startRemoteThread(hProcess, reinterpret_cast<LPVOID>(LoadLibraryW), remoteMemory);

        if (hThread)
        {
            WaitForSingleObject(hThread, INFINITE);

#ifdef _WIN64

            hModule = getModuleHandleByFilename(hProcess, filename);

#else
            //returns only 32 bit values -> design bug by microsoft
            if (!GetExitCodeThread(hThread, (LPDWORD)&hModule))
            {
                Scylla::debugLog.log(TEXT("dllInjection :: GetExitCodeThread failed 0x%X"), GetLastError());
                hModule = 0;
            }
#endif

            CloseHandle(hThread);
        }
        else
        {
            Scylla::debugLog.log(TEXT("dllInjection :: CreateRemoteThread failed 0x%X"), GetLastError());
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("dllInjection :: WriteProcessMemory failed 0x%X"), GetLastError());
    }


    VirtualFreeEx(hProcess, const_cast<LPVOID>(remoteMemory), 0, MEM_RELEASE);

    return hModule;
}

bool DllInjection::unloadDllInProcess(HANDLE hProcess, HMODULE hModule)
{
    BOOL freeLibraryRet;

    const auto hThread = startRemoteThread(hProcess, reinterpret_cast<LPVOID>(FreeLibrary), hModule);

    if (hThread)
    {
        WaitForSingleObject(hThread, INFINITE);

        if (!GetExitCodeThread(hThread, reinterpret_cast<LPDWORD>(&freeLibraryRet)))
        {
            Scylla::debugLog.log(TEXT("unloadDllInProcess :: GetExitCodeThread failed 0x%X"), GetLastError());
            freeLibraryRet = 0;
        }

        CloseHandle(hThread);
    }
    else
    {
        Scylla::debugLog.log(TEXT("unloadDllInProcess :: CreateRemoteThread failed 0x%X"), GetLastError());
    }

    return freeLibraryRet != 0;
}

HMODULE DllInjection::getModuleHandleByFilename(HANDLE hProcess, LPCTSTR filename)
{
    HMODULE * hMods = nullptr;
    HMODULE hModResult = nullptr;
    TCHAR target[MAX_PATH];

    const DWORD numHandles = ProcessAccessHelp::getModuleHandlesFromProcess(hProcess, &hMods);
    if (numHandles == 0)
    {
        return nullptr;
    }

    for (DWORD i = 0; i < numHandles; i++)
    {
        if (GetModuleFileNameEx(hProcess, hMods[i], target, _countof(target)))
        {
            if (!_tcsicmp(target, filename))
            {
                hModResult = hMods[i];
                break;
            }
        }
        else
        {
            Scylla::debugLog.log(TEXT("DllInjection::getModuleHandle :: GetModuleFileNameExW failed 0x%X"), GetLastError());
        }
    }

    if (!hModResult)
    {
        Scylla::debugLog.log(TEXT("DllInjection::getModuleHandle :: Handle not found"));
    }

    delete[] hMods;

    return hModResult;
}

void DllInjection::specialThreadSettings(HANDLE hThread)
{
    if (hThread)
    {
        if (!SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL))
        {
            Scylla::debugLog.log(TEXT("specialThreadSettings :: SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL) failed 0x%X"), GetLastError());
        }

        if (NativeWinApi::NtSetInformationThread)
        {
            if (NativeWinApi::NtSetInformationThread(hThread, ThreadHideFromDebugger, nullptr, 0) != STATUS_SUCCESS)
            {
                Scylla::debugLog.log(TEXT("specialThreadSettings :: NtSetInformationThread ThreadHideFromDebugger failed"));
            }
        }
    }
}

HANDLE DllInjection::startRemoteThread(HANDLE hProcess, LPCVOID lpStartAddress, LPCVOID lpParameter)
{
    const auto hThread = customCreateRemoteThread(hProcess, lpStartAddress, lpParameter);

    if (hThread)
    {
        specialThreadSettings(hThread);
        ResumeThread(hThread);
    }

    return hThread;
}

HANDLE DllInjection::customCreateRemoteThread(HANDLE hProcess, LPCVOID lpStartAddress, LPCVOID lpParameter)
{
    DWORD lpThreadId = 0;
    HANDLE hThread = nullptr;

    if (NativeWinApi::NtCreateThreadEx)
    {
#define THREAD_ALL_ACCESS_VISTA_7 (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

        //for windows vista/7
        const NTSTATUS ntStatus = NativeWinApi::NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS_VISTA_7, nullptr, hProcess, reinterpret_cast<LPTHREAD_START_ROUTINE>(const_cast<LPVOID>(lpStartAddress)), const_cast<LPVOID>(lpParameter), NtCreateThreadExFlagCreateSuspended | NtCreateThreadExFlagHideFromDebugger, 0, nullptr, nullptr, nullptr);
        if (NT_SUCCESS(ntStatus))
        {
            return hThread;
        }
        Scylla::debugLog.log(TEXT("customCreateRemoteThread :: NtCreateThreadEx failed 0x%X"), NativeWinApi::RtlNtStatusToDosError(ntStatus));
        return nullptr;
    }
    return CreateRemoteThread(hProcess, nullptr, NULL, reinterpret_cast<LPTHREAD_START_ROUTINE>(const_cast<LPVOID>(lpStartAddress)), const_cast<LPVOID>(lpParameter), CREATE_SUSPENDED, &lpThreadId);
}
