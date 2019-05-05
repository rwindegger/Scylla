#include "ProcessLister.h"
#include <algorithm>

#include "ProcessAccessHelp.h"
#include "Scylla.h"
#include "StringConversion.h"


def_IsWow64Process ProcessLister::_IsWow64Process = nullptr;

std::vector<Process>& ProcessLister::getProcessList()
{
    return processList;
}

bool ProcessLister::isWindows64()
{
#ifdef _WIN64
    //compiled 64bit application
    return true;
#else
    //32bit exe, check wow64
    BOOL bIsWow64 = FALSE;

    //not available in all windows operating systems
    //Minimum supported client: Windows Vista, Windows XP with SP2
    //Minimum supported server: Windows Server 2008, Windows Server 2003 with SP1

    if (_IsWow64Process)
    {
        _IsWow64Process(GetCurrentProcess(), &bIsWow64);
        return bIsWow64 != FALSE;
    }
    else
    {
        return false;
    }
#endif	
}

//only needed in windows xp
DWORD ProcessLister::setDebugPrivileges()
{
    HANDLE hToken = nullptr;
    TOKEN_PRIVILEGES Debug_Privileges{};

    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &Debug_Privileges.Privileges[0].Luid))
    {
        return GetLastError();
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        const DWORD err = GetLastError();
        if (hToken) CloseHandle(hToken);
        return err;
    }

    Debug_Privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    Debug_Privileges.PrivilegeCount = 1;

    AdjustTokenPrivileges(hToken, false, &Debug_Privileges, 0, nullptr, nullptr);

    CloseHandle(hToken);
    return GetLastError();
}


/************************************************************************/
/* Check if a process is 32 or 64bit                                    */
/************************************************************************/
ProcessType ProcessLister::checkIsProcess64(HANDLE hProcess)
{
    BOOL bIsWow64 = FALSE;

    if (!hProcess)
    {
        return PROCESS_MISSING_RIGHTS;
    }

    if (!isWindows64())
    {
        //32bit win can only run 32bit process
        return PROCESS_32;
    }

    _IsWow64Process(hProcess, &bIsWow64);

    if (bIsWow64 == FALSE)
    {
        //process not running under wow
        return PROCESS_64;
    }
    else
    {
        //process running under wow -> 32bit
        return PROCESS_32;
    }
}

bool ProcessLister::getAbsoluteFilePath(HANDLE hProcess, Process * process) const
{
    TCHAR processPath[MAX_PATH];
    bool retVal = false;

    _tcscpy_s(process->fullPath, TEXT("Unknown path"));

    if (!hProcess)
    {
        //missing rights
        return false;
    }

    if (GetProcessImageFileName(hProcess, processPath, _countof(processPath)) > 0)
    {
        if (!deviceNameResolver->resolveDeviceLongNameToShort(processPath, process->fullPath))
        {
            //some virtual volumes
            Scylla::debugLog.log(TEXT("getAbsoluteFilePath :: resolveDeviceLongNameToShort failed with path %s"), processPath);
            if (GetModuleFileNameEx(hProcess, nullptr, process->fullPath, _countof(process->fullPath)) != 0)
            {
                retVal = true;
            }
        }
        else
        {
            retVal = true;
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("getAbsoluteFilePath :: GetProcessImageFileName failed %u"), GetLastError());
        if (GetModuleFileNameEx(hProcess, nullptr, process->fullPath, _countof(process->fullPath)) != 0)
        {
            retVal = true;
        }
    }

    return retVal;
}

std::vector<Process>& ProcessLister::getProcessListSnapshotNative()
{
    ULONG retLength = 0;
    ULONG bufferLength = 1;
    auto pBuffer = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(malloc(bufferLength));
    if (!processList.empty())
    {
        //clear elements, but keep reversed memory
        processList.clear();
    }
    else
    {
        //first time, reserve memory
        processList.reserve(34);
    }

    if (NativeWinApi::NtQuerySystemInformation(SystemProcessInformation, pBuffer, bufferLength, &retLength) == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(pBuffer);
        bufferLength = retLength + sizeof(SYSTEM_PROCESS_INFORMATION);
        pBuffer = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(malloc(bufferLength));
        if (!pBuffer)
            return processList;

        if (NativeWinApi::NtQuerySystemInformation(SystemProcessInformation, pBuffer, bufferLength, &retLength) != STATUS_SUCCESS)
        {
            return processList;
        }
    }
    else
    {
        return processList;
    }

    PSYSTEM_PROCESS_INFORMATION pIter = pBuffer;

    while (TRUE)
    {
        if (pIter->UniqueProcessId > reinterpret_cast<HANDLE>(4)) //small filter
        {
            handleProcessInformationAndAddToList(pIter);
        }

        if (pIter->NextEntryOffset == 0)
        {
            break;
        }
        else
        {
            pIter = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<DWORD_PTR>(pIter) + static_cast<DWORD_PTR>(pIter->
                NextEntryOffset));
        }
    }

    std::reverse(processList.begin(), processList.end()); //reverse process list

    free(pBuffer);
    return processList;
}

void ProcessLister::handleProcessInformationAndAddToList(PSYSTEM_PROCESS_INFORMATION pProcess)
{
    Process process;

    process.PID = reinterpret_cast<size_t>(pProcess->UniqueProcessId);

    const auto hProcess = ProcessAccessHelp::NativeOpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, process.PID);

    if (hProcess)
    {
        const ProcessType processType = checkIsProcess64(hProcess);

#ifdef _WIN64
        if (processType == PROCESS_64)
#else
        if (processType == PROCESS_32)
#endif
        {
            process.sessionId = pProcess->SessionId;

            StringConversion::ToTStr(pProcess->ImageName.Buffer, process.filename, MAX_PATH);

            getAbsoluteFilePath(hProcess, &process);
            process.pebAddress = getPebAddressFromProcess(hProcess);
            getProcessImageInformation(hProcess, &process);

            processList.push_back(process);
        }
        CloseHandle(hProcess);
    }
}

void ProcessLister::getProcessImageInformation(HANDLE hProcess, Process* process)
{
    DWORD_PTR readImagebase = 0;
    process->imageBase = 0;
    process->imageSize = 0;

    if (hProcess && process->pebAddress)
    {
        const auto peb = reinterpret_cast<PEB_CURRENT *>(process->pebAddress);

        if (ReadProcessMemory(hProcess, &peb->ImageBaseAddress, &readImagebase, sizeof(DWORD_PTR), nullptr))
        {
            process->imageBase = readImagebase;
            process->imageSize = static_cast<DWORD>(ProcessAccessHelp::getSizeOfImageProcess(hProcess, process->imageBase));
        }
    }
}

DWORD_PTR ProcessLister::getPebAddressFromProcess(HANDLE hProcess)
{
    if (hProcess)
    {
        ULONG RequiredLen = 0;
        void * PebAddress = nullptr;
        PROCESS_BASIC_INFORMATION myProcessBasicInformation[5]{};

        if (NativeWinApi::NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen) == STATUS_SUCCESS)
        {
            PebAddress = reinterpret_cast<void*>(myProcessBasicInformation->PebBaseAddress);
        }
        else
        {
            if (NativeWinApi::NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == STATUS_SUCCESS)
            {
                PebAddress = reinterpret_cast<void*>(myProcessBasicInformation->PebBaseAddress);
            }
        }

        return reinterpret_cast<DWORD_PTR>(PebAddress);
    }

    return 0;
}
