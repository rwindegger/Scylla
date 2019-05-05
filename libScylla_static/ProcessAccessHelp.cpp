
#include "ProcessAccessHelp.h"

#include "Scylla.h"
#include "NativeWinApi.h"
#include "PeParser.h"

HANDLE ProcessAccessHelp::hProcess = nullptr;

ModuleInfo * ProcessAccessHelp::selectedModule;
DWORD_PTR ProcessAccessHelp::targetImageBase = 0;
DWORD_PTR ProcessAccessHelp::targetSizeOfImage = 0;
DWORD_PTR ProcessAccessHelp::maxValidAddress = 0;

std::vector<ModuleInfo> ProcessAccessHelp::moduleList; //target process module list
std::vector<ModuleInfo> ProcessAccessHelp::ownModuleList; //own module list

_DInst ProcessAccessHelp::decomposerResult[MAX_INSTRUCTIONS];
unsigned int ProcessAccessHelp::decomposerInstructionsCount = 0;
_CodeInfo ProcessAccessHelp::decomposerCi{};

_DecodedInst  ProcessAccessHelp::decodedInstructions[MAX_INSTRUCTIONS];
unsigned int  ProcessAccessHelp::decodedInstructionsCount = 0;

BYTE ProcessAccessHelp::fileHeaderFromDisk[PE_HEADER_BYTES_COUNT];

bool ProcessAccessHelp::openProcessHandle(size_t szPID)
{
    MODULEENTRY32  ModInfo{};

    if (szPID > 0)
    {
        if (hProcess)
        {
            Scylla::debugLog.log(TEXT("openProcessHandle :: There is already a process handle, HANDLE %X"), hProcess);
            return false;
        }
        else
        {
            hProcess = NativeOpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE, szPID);

            if (hProcess)
            {
                const auto hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, szPID);

                ModInfo.dwSize = sizeof(MODULEENTRY32);
                if (Module32First(hSnapShot, &ModInfo))
                {
                    ProcessAccessHelp::targetImageBase = reinterpret_cast<uintptr_t>(ModInfo.modBaseAddr);
                    ProcessAccessHelp::targetSizeOfImage = ModInfo.modBaseSize;
                    CloseHandle(hSnapShot);
                    return true;
                }
                CloseHandle(hSnapShot);

                Scylla::debugLog.log(TEXT("openProcessHandle :: Failed to enumerate first module, PID %X LastError : %x"), szPID, GetLastError());
                return false;
            }

            else
            {
                Scylla::debugLog.log(TEXT("openProcessHandle :: Failed to open handle, PID %X"), szPID);
                return false;
            }
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("openProcessHandle :: Wrong PID, PID %X"), szPID);

        return false;
    }

}

HANDLE ProcessAccessHelp::NativeOpenProcess(DWORD dwDesiredAccess, size_t szProcessId)
{
    HANDLE hProcess;
    CLIENT_ID cid{};
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, nullptr, nullptr);
    cid.UniqueProcess = reinterpret_cast<HANDLE>(szProcessId);

    const NTSTATUS ntStatus = NativeWinApi::NtOpenProcess(&hProcess, dwDesiredAccess, &ObjectAttributes, &cid);

    if (NT_SUCCESS(ntStatus))
    {
        return hProcess;
    }
    else
    {
        Scylla::debugLog.log(TEXT("NativeOpenProcess :: Failed to open handle, PID %X Error 0x%X"), szProcessId, NativeWinApi::RtlNtStatusToDosError(ntStatus));
        return nullptr;
    }
}

void ProcessAccessHelp::closeProcessHandle()
{
    if (hProcess)
    {
        CloseHandle(hProcess);
        hProcess = nullptr;
    }

    moduleList.clear();
    targetImageBase = 0;
    selectedModule = nullptr;
}

bool ProcessAccessHelp::readMemoryPartlyFromProcess(DWORD_PTR address, SIZE_T size, LPVOID dataBuffer)
{
    DWORD_PTR readBytes = 0;
    MEMORY_BASIC_INFORMATION memBasic{};
    bool returnValue = false;

    if (!hProcess)
    {
        Scylla::debugLog.log(TEXT("readMemoryPartlyFromProcess :: hProcess == NULL"));
        return returnValue;
    }

    if (!readMemoryFromProcess(address, size, dataBuffer))
    {
        DWORD_PTR addressPart = address;

        do
        {
            if (!VirtualQueryEx(ProcessAccessHelp::hProcess, reinterpret_cast<LPCVOID>(addressPart), &memBasic, sizeof memBasic))
            {
                Scylla::debugLog.log(TEXT("readMemoryPartlyFromProcess :: Error VirtualQueryEx %X %X err: %u"), addressPart, size, GetLastError());
                break;
            }

            DWORD_PTR bytesToRead = memBasic.RegionSize;

            if (readBytes + bytesToRead > size)
            {
                bytesToRead = size - readBytes;
            }

            if (memBasic.State == MEM_COMMIT)
            {
                if (!readMemoryFromProcess(addressPart, bytesToRead, reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(dataBuffer) + readBytes)))
                {
                    break;
                }
            }
            else
            {
                ZeroMemory(reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(dataBuffer) + readBytes), bytesToRead);
            }


            readBytes += bytesToRead;

            addressPart += memBasic.RegionSize;

        } while (readBytes < size);

        if (readBytes == size)
        {
            returnValue = true;
        }

    }
    else
    {
        returnValue = true;
    }

    return returnValue;
}

bool ProcessAccessHelp::writeMemoryToProcess(DWORD_PTR address, SIZE_T size, LPVOID dataBuffer)
{
    SIZE_T lpNumberOfBytesWritten = 0;
    if (!hProcess)
    {
        Scylla::debugLog.log(TEXT("readMemoryFromProcess :: hProcess == NULL"));
        return false;
    }


    return WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), dataBuffer, size, &lpNumberOfBytesWritten) != FALSE;
}

bool ProcessAccessHelp::readMemoryFromProcess(DWORD_PTR address, SIZE_T size, LPVOID dataBuffer)
{
    SIZE_T lpNumberOfBytesRead = 0;
    DWORD dwProtect = 0;
    bool returnValue = false;

    if (!hProcess)
    {
        Scylla::debugLog.log(TEXT("readMemoryFromProcess :: hProcess == NULL"));
        return returnValue;
    }

    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), dataBuffer, size, &lpNumberOfBytesRead))
    {
        Scylla::debugLog.log(TEXT("readMemoryFromProcess :: Error ReadProcessMemory %X %X err: %u"), address, size, GetLastError());

        if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(address), size, PAGE_READWRITE, &dwProtect))
        {
            Scylla::debugLog.log(TEXT("readMemoryFromProcess :: Error VirtualProtectEx %X %X err: %u"), address, size, GetLastError());
            returnValue = false;
        }
        else
        {
            if (!ReadProcessMemory(hProcess, reinterpret_cast<LPVOID>(address), dataBuffer, size, &lpNumberOfBytesRead))
            {
                Scylla::debugLog.log(TEXT("readMemoryFromProcess :: Error ReadProcessMemory %X %X err: %u"), address, size, GetLastError());
                returnValue = false;
            }
            else
            {
                returnValue = true;
            }
            VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(address), size, dwProtect, &dwProtect);
        }
    }
    else
    {
        returnValue = true;
    }

    if (returnValue)
    {
        if (size != lpNumberOfBytesRead)
        {
            Scylla::debugLog.log(TEXT("readMemoryFromProcess :: Error ReadProcessMemory read %d bytes requested %d bytes"), lpNumberOfBytesRead, size);
            returnValue = false;
        }
        else
        {
            returnValue = true;
        }
    }

    return returnValue;
}

bool ProcessAccessHelp::decomposeMemory(const BYTE * dataBuffer, SIZE_T bufferSize, DWORD_PTR startAddress)
{

    ZeroMemory(&decomposerCi, sizeof(_CodeInfo));
    decomposerCi.code = dataBuffer;
    decomposerCi.codeLen = static_cast<int>(bufferSize);
    decomposerCi.dt = dt;
    decomposerCi.codeOffset = startAddress;

    decomposerInstructionsCount = 0;

    if (distorm_decompose(&decomposerCi, decomposerResult, sizeof decomposerResult / sizeof decomposerResult[0], &decomposerInstructionsCount) == DECRES_INPUTERR)
    {
        Scylla::debugLog.log(TEXT("decomposeMemory :: distorm_decompose == DECRES_INPUTERR"));
        return false;
    }
    else
    {
        return true;
    }
}

bool ProcessAccessHelp::disassembleMemory(BYTE * dataBuffer, SIZE_T bufferSize, DWORD_PTR startOffset)
{
    // next is used for instruction's offset synchronization.
    // decodedInstructionsCount holds the count of filled instructions' array by the decoder.

    decodedInstructionsCount = 0;

    const _OffsetType offset = startOffset;

    const _DecodeResult res = distorm_decode(offset, dataBuffer, static_cast<int>(bufferSize), dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    /*	for (unsigned int i = 0; i < decodedInstructionsCount; i++) {
    #ifdef SUPPORT_64BIT_OFFSET
            printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
    #else
            printf("%08x (%02d) %-24s %s%s%s\n", decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
    #endif

        }*/

    if (res == DECRES_INPUTERR)
    {
        Scylla::debugLog.log(TEXT("disassembleMemory :: res == DECRES_INPUTERR"));
        return false;
    }
    else if (res == DECRES_SUCCESS)
    {
        //printf("disassembleMemory :: res == DECRES_SUCCESS\n");
        return true;
    }
    else
    {
        Scylla::debugLog.log(TEXT("disassembleMemory :: res == %d"), res);
        return true; //not all instructions fit in buffer
    }
}

DWORD_PTR ProcessAccessHelp::findPattern(DWORD_PTR startOffset, DWORD size, const BYTE * pattern, const char * mask)
{
    DWORD pos = 0;
    const size_t searchLen = strlen(mask) - 1;

    for (DWORD_PTR retAddress = startOffset; retAddress < startOffset + size; retAddress++)
    {
        if (*reinterpret_cast<BYTE*>(retAddress) == pattern[pos] || mask[pos] == '?')
        {
            if (mask[pos + 1] == 0x00)
            {
                return retAddress - searchLen;
            }
            pos++;
        }
        else {
            pos = 0;
        }
    }
    return 0;
}

bool ProcessAccessHelp::readHeaderFromCurrentFile(LPCTSTR filePath)
{
    return readHeaderFromFile(fileHeaderFromDisk, sizeof fileHeaderFromDisk, filePath);
}

LONGLONG ProcessAccessHelp::getFileSize(LPCTSTR filePath)
{
    LONGLONG fileSize = 0;

    const auto hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        fileSize = getFileSize(hFile);
        CloseHandle(hFile);
    }

    return fileSize;
}

LONGLONG ProcessAccessHelp::getFileSize(HANDLE hFile)
{
    LARGE_INTEGER lpFileSize{};

    if (hFile != INVALID_HANDLE_VALUE && hFile != nullptr)
    {
        if (!GetFileSizeEx(hFile, &lpFileSize))
        {
            Scylla::debugLog.log(TEXT("ProcessAccessHelp::getFileSize :: GetFileSizeEx failed %u"), GetLastError());
            return 0;
        }
        else
        {
            return lpFileSize.QuadPart;
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("ProcessAccessHelp::getFileSize hFile invalid"));
        return 0;
    }
}


bool ProcessAccessHelp::readMemoryFromFile(HANDLE hFile, LONG offset, DWORD size, LPVOID dataBuffer)
{
    DWORD lpNumberOfBytesRead = 0;

    if (hFile != INVALID_HANDLE_VALUE)
    {
        const DWORD retValue = SetFilePointer(hFile, offset, nullptr, FILE_BEGIN);
        const DWORD dwError = GetLastError();

        if (retValue == INVALID_SET_FILE_POINTER && dwError != NO_ERROR)
        {
            Scylla::debugLog.log(TEXT("readMemoryFromFile :: SetFilePointer failed error %u"), dwError);
            return false;
        }
        else
        {
            if (ReadFile(hFile, dataBuffer, size, &lpNumberOfBytesRead, nullptr))
            {
                return true;
            }
            else
            {
                Scylla::debugLog.log(TEXT("readMemoryFromFile :: ReadFile failed - size %d - error %u"), size, GetLastError());
                return false;
            }
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("readMemoryFromFile :: hFile invalid"));
        return false;
    }
}

bool ProcessAccessHelp::writeMemoryToNewFile(LPCTSTR file, DWORD size, LPCVOID dataBuffer)
{
    const auto hFile = CreateFile(file, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        const bool resultValue = writeMemoryToFile(hFile, 0, size, dataBuffer);
        CloseHandle(hFile);
        return resultValue;
    }
    else
    {
        return false;
    }
}

bool ProcessAccessHelp::writeMemoryToFile(HANDLE hFile, LONG offset, DWORD size, LPCVOID dataBuffer)
{
    DWORD lpNumberOfBytesWritten = 0;

    if (hFile != INVALID_HANDLE_VALUE && dataBuffer)
    {
        const DWORD retValue = SetFilePointer(hFile, offset, nullptr, FILE_BEGIN);
        const DWORD dwError = GetLastError();

        if (retValue == INVALID_SET_FILE_POINTER && dwError != NO_ERROR)
        {
            Scylla::debugLog.log(TEXT("writeMemoryToFile :: SetFilePointer failed error %u"), dwError);
            return false;
        }
        else
        {
            if (WriteFile(hFile, dataBuffer, size, &lpNumberOfBytesWritten, nullptr))
            {
                return true;
            }
            else
            {
                Scylla::debugLog.log(TEXT("writeMemoryToFile :: WriteFile failed - size %d - error %u"), size, GetLastError());
                return false;
            }
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("writeMemoryToFile :: hFile invalid"));
        return false;
    }
}

bool ProcessAccessHelp::writeMemoryToFileEnd(HANDLE hFile, DWORD size, LPCVOID dataBuffer)
{
    DWORD lpNumberOfBytesWritten = 0;

    if (hFile != INVALID_HANDLE_VALUE && hFile != nullptr)
    {
        SetFilePointer(hFile, 0, nullptr, FILE_END);

        if (WriteFile(hFile, dataBuffer, size, &lpNumberOfBytesWritten, nullptr))
        {
            return true;
        }
        else
        {
            Scylla::debugLog.log(TEXT("writeMemoryToFileEnd :: WriteFile failed - size %d - error %u"), size, GetLastError());
            return false;
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("writeMemoryToFileEnd :: hFile invalid"));

        return false;
    }
}

bool ProcessAccessHelp::readHeaderFromFile(BYTE * buffer, DWORD bufferSize, LPCTSTR filePath)
{
    DWORD dwSize;
    bool returnValue = false;

    const auto hFile = CreateFile(filePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        Scylla::debugLog.log(TEXT("readHeaderFromFile :: INVALID_HANDLE_VALUE %u"), GetLastError());
        returnValue = false;
    }
    else
    {
        const LONGLONG fileSize = getFileSize(hFile);

        if (fileSize > 0)
        {
            if (fileSize > bufferSize)
            {
                dwSize = bufferSize;
            }
            else
            {
                dwSize = static_cast<DWORD>(fileSize - 1);
            }

            returnValue = readMemoryFromFile(hFile, 0, dwSize, buffer);
        }

        CloseHandle(hFile);
    }

    return returnValue;
}

LPVOID ProcessAccessHelp::createFileMappingViewRead(LPCTSTR filePath)
{
    return createFileMappingView(filePath, GENERIC_READ, PAGE_READONLY | SEC_IMAGE, FILE_MAP_READ);
}

LPVOID ProcessAccessHelp::createFileMappingViewFull(LPCTSTR filePath)
{
    return createFileMappingView(filePath, GENERIC_ALL, PAGE_EXECUTE_READWRITE, FILE_MAP_ALL_ACCESS);
}

LPVOID ProcessAccessHelp::createFileMappingView(LPCTSTR filePath, DWORD accessFile, DWORD flProtect, DWORD accessMap)
{
    const auto hFile = CreateFile(filePath, accessFile, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        Scylla::debugLog.log(TEXT("createFileMappingView :: INVALID_HANDLE_VALUE %u"), GetLastError());
        return nullptr;
    }

    const auto hMappedFile = CreateFileMapping(hFile, nullptr, flProtect, 0, 0, nullptr);
    CloseHandle(hFile);

    if (hMappedFile == nullptr)
    {
        Scylla::debugLog.log(TEXT("createFileMappingView :: hMappedFile == NULL"));
        return nullptr;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        Scylla::debugLog.log(TEXT("createFileMappingView :: GetLastError() == ERROR_ALREADY_EXISTS"));
        CloseHandle(hMappedFile);
        return nullptr;
    }

    const auto addrMappedDll = MapViewOfFile(hMappedFile, accessMap, 0, 0, 0);

    if (addrMappedDll == nullptr)
    {
        Scylla::debugLog.log(TEXT("createFileMappingView :: addrMappedDll == NULL"));
        CloseHandle(hMappedFile);
        return nullptr;
    }

    CloseHandle(hMappedFile);

    return addrMappedDll;
}

DWORD ProcessAccessHelp::getProcessByName(LPCTSTR processName)
{
    DWORD dwPID = 0;
    const auto hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        Scylla::debugLog.log(TEXT("getProcessByName :: Error getting first Process"));
        CloseHandle(hProcessSnap);
        return 0;
    }

    do
    {
        if (!_tcsicmp(pe32.szExeFile, processName))
        {
            dwPID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return dwPID;
}

bool ProcessAccessHelp::getProcessModules(HANDLE hProcess, std::vector<ModuleInfo> &moduleList)
{
    ModuleInfo module;
    TCHAR filename[MAX_PATH * 2] = { 0 };
    DWORD cbNeeded = 0;
    bool retVal = false;
    DeviceNameResolver deviceNameResolver;

    moduleList.reserve(20);

    EnumProcessModules(hProcess, nullptr, 0, &cbNeeded);

    const auto hMods = static_cast<HMODULE*>(malloc(cbNeeded * sizeof(HMODULE)));

    if (hMods)
    {
        if (EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded))
        {
            for (unsigned int i = 1; i < cbNeeded / sizeof(HMODULE); i++) //skip first module!
            {
                module.modBaseAddr = reinterpret_cast<DWORD_PTR>(hMods[i]);
                module.modBaseSize = static_cast<DWORD>(getSizeOfImageProcess(hProcess, module.modBaseAddr));
                module.isAlreadyParsed = false;
                module.parsing = false;

                filename[0] = 0;
                module.fullPath[0] = 0;

                if (GetMappedFileName(hProcess, reinterpret_cast<LPVOID>(module.modBaseAddr), filename, _countof(filename)) > 0)
                {
                    if (!deviceNameResolver.resolveDeviceLongNameToShort(filename, module.fullPath))
                    {
                        if (!GetModuleFileNameEx(hProcess, reinterpret_cast<HMODULE>(module.modBaseAddr), module.fullPath, _countof(module.fullPath)))
                        {
                            _tcscpy_s(module.fullPath, filename);
                        }
                    }
                }
                else
                {
                    GetModuleFileNameEx(hProcess, reinterpret_cast<HMODULE>(module.modBaseAddr), module.fullPath, _countof(module.fullPath));
                }

                moduleList.push_back(module);
            }

            retVal = true;
        }

        free(hMods);
    }

    return retVal;
}

bool ProcessAccessHelp::getMemoryRegionFromAddress(DWORD_PTR address, DWORD_PTR * memoryRegionBase, SIZE_T * memoryRegionSize)
{
    MEMORY_BASIC_INFORMATION memBasic;

    if (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
    {
        Scylla::debugLog.log(TEXT("getMemoryRegionFromAddress :: VirtualQueryEx error %u"), GetLastError());
        return false;
    }
    else
    {
        *memoryRegionBase = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress);
        *memoryRegionSize = memBasic.RegionSize;
        return true;
    }
}

bool ProcessAccessHelp::getSizeOfImageCurrentProcess()
{
    const DWORD_PTR newSizeOfImage = getSizeOfImageProcess(ProcessAccessHelp::hProcess, ProcessAccessHelp::targetImageBase);

    if (newSizeOfImage != 0)
    {
        ProcessAccessHelp::targetSizeOfImage = newSizeOfImage;
        return true;
    }
    else
    {
        return false;
    }
}

SIZE_T ProcessAccessHelp::getSizeOfImageProcess(HANDLE processHandle, DWORD_PTR moduleBase)
{
    SIZE_T sizeOfImage = 0;
    MEMORY_BASIC_INFORMATION lpBuffer{};

    const SIZE_T sizeOfImageNative = getSizeOfImageProcessNative(processHandle, moduleBase);

    if (sizeOfImageNative)
    {
        return sizeOfImageNative;
    }

    TCHAR filenameOriginal[MAX_PATH * 2] = { 0 };
    TCHAR filenameTest[MAX_PATH * 2] = { 0 };

    GetMappedFileName(processHandle, reinterpret_cast<LPVOID>(moduleBase), filenameOriginal, _countof(filenameOriginal));

    do
    {
        moduleBase = static_cast<DWORD_PTR>(static_cast<SIZE_T>(moduleBase) + lpBuffer.RegionSize);
        sizeOfImage += lpBuffer.RegionSize;


        if (!VirtualQueryEx(processHandle, reinterpret_cast<LPCVOID>(moduleBase), &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION)))
        {
            Scylla::debugLog.log(TEXT("getSizeOfImageProcess :: VirtualQuery failed %X"), GetLastError());

            lpBuffer.Type = 0;
            sizeOfImage = 0;
        }

        GetMappedFileName(processHandle, reinterpret_cast<LPVOID>(moduleBase), filenameTest, _countof(filenameTest));

        if (_tcsicmp(filenameOriginal, filenameTest) != 0)//problem: 2 modules without free space
        {
            break;
        }

    } while (lpBuffer.Type == MEM_IMAGE);


    //if (sizeOfImage != sizeOfImageNative)
    //{
    //    WCHAR temp[1000] = {0};
    //    wsprintfW(temp, L"0x%X sizeofimage\n0x%X sizeOfImageNative", sizeOfImage, sizeOfImageNative);
    //    MessageBoxW(0, temp, L"Test", 0);
    //}

    return sizeOfImage;
}

DWORD ProcessAccessHelp::getEntryPointFromFile(LPCTSTR filePath)
{
    PeParser peFile(filePath, false);

    return peFile.getEntryPoint();
}

bool ProcessAccessHelp::createBackupFile(LPCTSTR filePath)
{
    const size_t fileNameLength = _tcslen(filePath) + 5; //.bak + null

    const auto backupFile = new TCHAR[fileNameLength];

    _tcscpy_s(backupFile, fileNameLength, filePath);
    _tcscat_s(backupFile, fileNameLength, TEXT(".bak"));
    const BOOL retValue = CopyFile(filePath, backupFile, FALSE);

    if (!retValue)
    {
        Scylla::debugLog.log(TEXT("createBackupFile :: CopyFile failed with error 0x%X"), GetLastError());
    }

    delete[] backupFile;

    return retValue != 0;
}

DWORD ProcessAccessHelp::getModuleHandlesFromProcess(HANDLE hProcess, HMODULE ** hMods)
{
    DWORD count = 30;
    DWORD cbNeeded = 0;
    bool notEnough = true;

    *hMods = new HMODULE[count];

    do
    {
        if (!EnumProcessModules(hProcess, *hMods, count * sizeof(HMODULE), &cbNeeded))
        {
            Scylla::debugLog.log(TEXT("getModuleHandlesFromProcess :: EnumProcessModules failed count %d"), count);

            delete[] * hMods;
            return 0;
        }

        if (count * sizeof(HMODULE) < cbNeeded)
        {
            delete[] * hMods;
            count = cbNeeded / sizeof(HMODULE);
            *hMods = new HMODULE[count];
        }
        else
        {
            notEnough = false;
        }
    } while (notEnough);

    return cbNeeded / sizeof(HMODULE);
}

void ProcessAccessHelp::setCurrentProcessAsTarget()
{
    ProcessAccessHelp::hProcess = GetCurrentProcess();
}

bool ProcessAccessHelp::suspendProcess()
{
    if (NativeWinApi::NtSuspendProcess)
    {
        if (NT_SUCCESS(NativeWinApi::NtSuspendProcess(ProcessAccessHelp::hProcess)))
        {
            return true;
        }
    }

    return false;
}

bool ProcessAccessHelp::resumeProcess()
{
    if (NativeWinApi::NtResumeProcess)
    {
        if (NT_SUCCESS(NativeWinApi::NtResumeProcess(ProcessAccessHelp::hProcess)))
        {
            return true;
        }
    }

    return false;
}

bool ProcessAccessHelp::terminateProcess()
{
    if (NativeWinApi::NtTerminateProcess)
    {
        if (NT_SUCCESS(NativeWinApi::NtTerminateProcess(ProcessAccessHelp::hProcess, 0)))
        {
            return true;
        }
    }

    return false;
}

bool ProcessAccessHelp::isPageAccessable(DWORD Protect)
{
    if (Protect & PAGE_NOCACHE) Protect ^= PAGE_NOCACHE;
    if (Protect & PAGE_GUARD) Protect ^= PAGE_GUARD;
    if (Protect & PAGE_WRITECOMBINE) Protect ^= PAGE_WRITECOMBINE;

    return Protect != PAGE_NOACCESS;
}

bool ProcessAccessHelp::isPageExecutable(DWORD Protect)
{
    if (Protect & PAGE_NOCACHE) Protect ^= PAGE_NOCACHE;
    if (Protect & PAGE_GUARD) Protect ^= PAGE_GUARD;
    if (Protect & PAGE_WRITECOMBINE) Protect ^= PAGE_WRITECOMBINE;

    switch (Protect)
    {
    case PAGE_EXECUTE:
    {
        return true;
    }
    case PAGE_EXECUTE_READ:
    {
        return true;
    }
    case PAGE_EXECUTE_READWRITE:
    {
        return true;
    }
    case PAGE_EXECUTE_WRITECOPY:
    {
        return true;
    }
    default:
        return false;
    }

}

SIZE_T ProcessAccessHelp::getSizeOfImageProcessNative(HANDLE processHandle, DWORD_PTR moduleBase)
{
    MEMORY_REGION_INFORMATION memRegion{};
    SIZE_T retLen = 0;
    if (NativeWinApi::NtQueryVirtualMemory(processHandle, reinterpret_cast<PVOID>(moduleBase), MemoryRegionInformation, &memRegion, sizeof(MEMORY_REGION_INFORMATION), &retLen) == STATUS_SUCCESS)
    {
        return memRegion.RegionSize;
    }

    return 0;
}
