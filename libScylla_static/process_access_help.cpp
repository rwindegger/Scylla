#include "process_access_help.h"
#include "libscylla.h"
#include "native_win_api.h"
#include "module_info.h"
#include <tchar.h>
#include <cstdlib>
#include <psapi.h>
#include "DeviceNameResolver.h"
#include <tlhelp32.h>

process_access_help::process_access_help(const std::shared_ptr<libscylla>& context)
    : context_{context}
{
    open_process(context_->target_pid());
}

process_access_help::process_access_help(const std::shared_ptr<libscylla>& context, pid_t target_pid)
    : context_{context}
{
    open_process(target_pid);
}

#include "ProcessAccessHelp.h"

bool process_access_help::get_process_modules(std::vector<std::shared_ptr<module_info>> &moduleList)
{
    DWORD cbNeeded = 0;
    bool retVal = false;
    DeviceNameResolver deviceNameResolver;

    moduleList.reserve(20);

    EnumProcessModules(process_, nullptr, 0, &cbNeeded);

    HMODULE *hMods = new HMODULE[cbNeeded / sizeof(HMODULE)];
    
    if (hMods)
    {
        if (EnumProcessModules(process_, hMods, cbNeeded, &cbNeeded))
        {
            for (unsigned int i = 1; i < cbNeeded / sizeof(HMODULE); i++) //skip first module!
            {
                std::shared_ptr<module_info> module = std::make_shared<module_info>(context_);
                module->base_address(reinterpret_cast<uintptr_t>(hMods[i]));
                module->base_size(static_cast<size_t>(get_size_of_image_process(module->base_address())));
                module->is_already_parsed(false);
                module->is_parsing(false);

                TCHAR filename[MAX_PATH]{};
                TCHAR buffer[MAX_PATH]{};
                if (GetMappedFileName(process_, reinterpret_cast<LPVOID>(module->base_address()), filename, _countof(filename)) > 0)
                {
                    if (!deviceNameResolver.resolveDeviceLongNameToShort(filename, buffer))
                    {
                        if (!GetModuleFileNameEx(process_, reinterpret_cast<HMODULE>(module->base_address()), buffer, _countof(buffer)))
                        {
                            _tcscpy_s(buffer, filename);
                        }
                    }
                }
                else
                {
                    GetModuleFileNameEx(process_, reinterpret_cast<HMODULE>(module->base_address()), buffer, _countof(buffer));
                }
                module->full_path(buffer);

                moduleList.push_back(module);
            }

            retVal = true;
        }

        delete[] hMods;
    }

    return retVal;
}

size_t process_access_help::get_size_of_image_process(uintptr_t moduleBase)
{
    SIZE_T sizeOfImage = 0;
    MEMORY_BASIC_INFORMATION lpBuffer{};

    const SIZE_T sizeOfImageNative = get_size_of_image_process_native(moduleBase);

    if (sizeOfImageNative)
    {
        return sizeOfImageNative;
    }

    TCHAR filenameOriginal[MAX_PATH * 2] = { 0 };
    TCHAR filenameTest[MAX_PATH * 2] = { 0 };

    GetMappedFileName(process_, reinterpret_cast<LPVOID>(moduleBase), filenameOriginal, _countof(filenameOriginal));

    do
    {
        moduleBase = static_cast<DWORD_PTR>(static_cast<SIZE_T>(moduleBase) + lpBuffer.RegionSize);
        sizeOfImage += lpBuffer.RegionSize;

        if (!VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(moduleBase), &lpBuffer, sizeof(MEMORY_BASIC_INFORMATION)))
        {
            context_->log(scylla_severity::debug, TEXT("getSizeOfImageProcess :: VirtualQuery failed %X"), GetLastError());

            lpBuffer.Type = 0;
            sizeOfImage = 0;
        }

        GetMappedFileName(process_, reinterpret_cast<LPVOID>(moduleBase), filenameTest, _countof(filenameTest));

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

size_t process_access_help::get_size_of_image_process_native(uintptr_t moduleBase)
{
    MEMORY_REGION_INFORMATION memRegion{};
    SIZE_T retLen = 0;
    if (libscylla::windows_api()->NtQueryVirtualMemory(process_, reinterpret_cast<PVOID>(moduleBase), MemoryRegionInformation, &memRegion, sizeof(MEMORY_REGION_INFORMATION), &retLen) == STATUS_SUCCESS)
    {
        return memRegion.RegionSize;
    }

    return 0;
}

bool process_access_help::read_remote_memory(uintptr_t address, LPVOID dataBuffer, size_t size)
{
    SIZE_T lpNumberOfBytesRead = 0;
    DWORD dwProtect = 0;
    bool returnValue = false;

    if (!process_)
    {
        context_->log(scylla_severity::debug, TEXT("readMemoryFromProcess :: hProcess == NULL"));
        return returnValue;
    }

    if (!ReadProcessMemory(process_, reinterpret_cast<LPVOID>(address), dataBuffer, size, &lpNumberOfBytesRead))
    {
        context_->log(scylla_severity::debug, TEXT("readMemoryFromProcess :: Error ReadProcessMemory %X %X err: %u"), address, size, GetLastError());

        if (!VirtualProtectEx(process_, reinterpret_cast<LPVOID>(address), size, PAGE_READWRITE, &dwProtect))
        {
            context_->log(scylla_severity::debug, TEXT("readMemoryFromProcess :: Error VirtualProtectEx %X %X err: %u"), address, size, GetLastError());
            returnValue = false;
        }
        else
        {
            if (!ReadProcessMemory(process_, reinterpret_cast<LPVOID>(address), dataBuffer, size, &lpNumberOfBytesRead))
            {
                context_->log(scylla_severity::debug, TEXT("readMemoryFromProcess :: Error ReadProcessMemory %X %X err: %u"), address, size, GetLastError());
                returnValue = false;
            }
            else
            {
                returnValue = true;
            }
            VirtualProtectEx(process_, reinterpret_cast<LPVOID>(address), size, dwProtect, &dwProtect);
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
            context_->log(scylla_severity::debug, TEXT("readMemoryFromProcess :: Error ReadProcessMemory read %d bytes requested %d bytes"), lpNumberOfBytesRead, size);
            returnValue = false;
        }
        else
        {
            returnValue = true;
        }
    }

    return returnValue;
}

bool process_access_help::write_remote_memory(uintptr_t address, LPVOID dataBuffer, size_t size)
{
    SIZE_T lpNumberOfBytesWritten = 0;
    if (!process_)
    {
        context_->log(scylla_severity::debug, TEXT("readMemoryFromProcess :: hProcess == NULL"));
        return false;
    }

    return WriteProcessMemory(process_, reinterpret_cast<LPVOID>(address), dataBuffer, size, &lpNumberOfBytesWritten) != FALSE;
}

decompose_state process_access_help::decompose_memory(uintptr_t address, LPVOID dataBuffer, size_t bufferSize)
{
    decompose_state state{};
    unsigned int instruction_count = 0;
    state.code_info = _CodeInfo{};
    state.code_info.code = reinterpret_cast<uint8_t*>(dataBuffer);
    state.code_info.codeLen = static_cast<int>(bufferSize);
    state.code_info.dt = SCYLLA_DECODE_TYPE;
    state.code_info.codeOffset = address;

    _DInst result[MAX_INSTRUCTIONS];
    if (distorm_decompose(&state.code_info, result, _countof(result), &instruction_count) == DECRES_INPUTERR)
    {
        context_->log(scylla_severity::debug, TEXT("decomposeMemory :: distorm_decompose == DECRES_INPUTERR"));
        state.status = decompose_status::error;
        return state;
    }
    state.instructions = std::vector<_DInst>(result, result + instruction_count);
    state.status = decompose_status::success;
    return state;
}

bool process_access_help::open_process(pid_t pid)
{
    MODULEENTRY32  ModInfo{};
    if (pid > 0)
    {
        if (process_)
        {
            context_->log(scylla_severity::debug, TEXT("open_process :: There is already a process handle, HANDLE %X"), process_);
            return false;
        }

        process_ = open_process_native(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE, pid);

        if (process_)
        {
            const auto hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);

            ModInfo.dwSize = sizeof(MODULEENTRY32);
            if (Module32First(hSnapShot, &ModInfo))
            {
                target_image_base_ = reinterpret_cast<uintptr_t>(ModInfo.modBaseAddr);
                target_image_size_ = ModInfo.modBaseSize;
                CloseHandle(hSnapShot);
                return true;
            }
            CloseHandle(hSnapShot);

            context_->log(scylla_severity::debug, TEXT("open_process :: Failed to enumerate first module, PID %X LastError : %x"), pid, GetLastError());
            return false;
        }
        context_->log(scylla_severity::debug, TEXT("open_process :: Failed to open handle, PID %X"), pid);
        return false;
    }
    context_->log(scylla_severity::debug, TEXT("open_process :: Wrong PID, PID %X"), pid);
    return false;
}

HANDLE process_access_help::open_process_native(DWORD dwDesiredAccess, pid_t szPID) const
{
    HANDLE hProcess;
    CLIENT_ID cid{};
    OBJECT_ATTRIBUTES ObjectAttributes;

    InitializeObjectAttributes(&ObjectAttributes, nullptr, 0, nullptr, nullptr);
    cid.UniqueProcess = reinterpret_cast<HANDLE>(szPID);

    const NTSTATUS ntStatus = libscylla::windows_api()->NtOpenProcess(&hProcess, dwDesiredAccess, &ObjectAttributes, &cid);

    if (NT_SUCCESS(ntStatus))
    {
        return hProcess;
    }
    context_->log(scylla_severity::debug, TEXT("open_process_native :: Failed to open handle, PID %X Error 0x%X"), szPID, libscylla::windows_api()->RtlNtStatusToDosError(ntStatus));
    return nullptr;
}

LPVOID process_access_help::create_file_mapping_view_read(LPCTSTR filePath) const
{
    return create_file_mapping_view(filePath, GENERIC_READ, PAGE_READONLY | SEC_IMAGE, FILE_MAP_READ);
}

LPVOID process_access_help::create_file_mapping_view_full(LPCTSTR filePath) const
{
    return create_file_mapping_view(filePath, GENERIC_ALL, PAGE_EXECUTE_READWRITE, FILE_MAP_ALL_ACCESS);
}

LPVOID process_access_help::create_file_mapping_view(LPCTSTR filePath, DWORD accessFile, DWORD flProtect, DWORD accessMap) const
{
    const auto file = CreateFile(filePath, accessFile, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);

    if (file == INVALID_HANDLE_VALUE)
    {
        context_->log(scylla_severity::debug, TEXT("createFileMappingView :: INVALID_HANDLE_VALUE %u"), GetLastError());
        return nullptr;
    }

    const auto mapped_file = CreateFileMapping(file, nullptr, flProtect, 0, 0, nullptr);
    CloseHandle(file);

    if (mapped_file == nullptr)
    {
        context_->log(scylla_severity::debug, TEXT("createFileMappingView :: hMappedFile == NULL"));
        return nullptr;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        context_->log(scylla_severity::debug, TEXT("createFileMappingView :: GetLastError() == ERROR_ALREADY_EXISTS"));
        CloseHandle(mapped_file);
        return nullptr;
    }

    const auto mapped_dll = MapViewOfFile(mapped_file, accessMap, 0, 0, 0);

    if (mapped_dll == nullptr)
    {
        context_->log(scylla_severity::debug, TEXT("createFileMappingView :: addrMappedDll == NULL"));
        CloseHandle(mapped_file);
        return nullptr;
    }

    CloseHandle(mapped_file);

    return mapped_dll;
}

bool process_access_help::get_memory_region_from_address(uintptr_t address, uintptr_t* memory_region_base,
    size_t* memory_region_size)
{
    MEMORY_BASIC_INFORMATION memBasic;

    if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)) != sizeof(MEMORY_BASIC_INFORMATION))
    {
        context_->log(scylla_severity::debug, TEXT("get_memory_region_from_address :: VirtualQueryEx error %u"), GetLastError());
        return false;
    }
    else
    {
        *memory_region_base = reinterpret_cast<DWORD_PTR>(memBasic.BaseAddress);
        *memory_region_size = memBasic.RegionSize;
        return true;
    }
}

bool process_access_help::is_page_executable(DWORD Protect)
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

bool process_access_help::is_page_accessable(DWORD Protect)
{
    if (Protect & PAGE_NOCACHE) Protect ^= PAGE_NOCACHE;
    if (Protect & PAGE_GUARD) Protect ^= PAGE_GUARD;
    if (Protect & PAGE_WRITECOMBINE) Protect ^= PAGE_WRITECOMBINE;

    return Protect != PAGE_NOACCESS;
}
