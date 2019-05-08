#include "api_reader.h"
#include "module_info.h"
#include "api_info.h"
#include "libscylla.h"
#include "configuration_holder.h"
#include "configuration.h"

#include "Architecture.h"
#include "StringConversion.h"
#include "Thunks.h"

#include <utility>

api_reader::api_reader(const std::shared_ptr<libscylla>& context)
    : process_access_help(context)
    , min_api_address_(0)
    , max_api_address_(0)
{
}

api_reader::api_reader(const std::shared_ptr<libscylla>& context, pid_t target_pid)
    : process_access_help(context, target_pid)
    , min_api_address_(0)
    , max_api_address_(0)
{
}

void api_reader::read_apis_from_module_list(std::vector<std::shared_ptr<module_info>> &modules, std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>> &apis)
{
    for (auto& i : modules)
    {
        i->set_priority();

        if (i->base_address() + i->base_size() > max_valid_address_)
        {
            max_valid_address_ = i->base_address() + i->base_size();
        }

        context_->log(scylla_severity::information, TEXT("Module parsing: %s"), i->full_path().c_str());

        if (!i->is_already_parsed())
        {
            parse_module(apis, i);
        }
    }

    context_->log(scylla_severity::debug, TEXT("Address Min ") PRINTF_DWORD_PTR_FULL TEXT(" Max ") PRINTF_DWORD_PTR_FULL TEXT("\nimagebase ") PRINTF_DWORD_PTR_FULL TEXT(" maxValidAddress ") PRINTF_DWORD_PTR_FULL, min_api_address_, max_api_address_, target_image_base_, max_valid_address_);
}

void api_reader::read_and_parse_iat(uintptr_t addressIAT, size_t sizeIAT, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    const auto dataIat = new uint8_t[sizeIAT];
    if (read_remote_memory(addressIAT, dataIat, sizeIAT))
    {
        parse_iat(addressIAT, dataIat, sizeIAT, module_list_new);
    }
    else
    {
        context_->log(scylla_severity::debug, TEXT("read_and_parse_iat :: error reading iat ") PRINTF_DWORD_PTR_FULL, addressIAT);
    }

    delete[] dataIat;
}

void api_reader::parse_module(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module)
{
    const bool read_export_table_from_disk = (*context_->config())[config_option::APIS_ALWAYS_FROM_DISK].isTrue();

    module->is_parsing(true);

    if (read_export_table_from_disk)
    {
        parse_module_mapping(api_list, module);
    }
    else if (module->is_in_winsxs())
    {
        parse_module_mapping(api_list, module);
    }
    else if (module->is_loaded_local())
    {
        parse_module_local(api_list, module);
    }
    else
    {
        parse_module_remote(api_list, module);
    }

    module->is_already_parsed(true);
}

void api_reader::parse_module_mapping(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module)
{
    LPVOID file_mapping = create_file_mapping_view_read(module->full_path().c_str());

    if (file_mapping == nullptr)
        return;

    const auto pDosHeader = static_cast<PIMAGE_DOS_HEADER>(file_mapping);
    const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(file_mapping) + static_cast<DWORD_PTR>(pDosHeader->e_lfanew));

    if (is_pe_and_export_table_valid(pNtHeader))
    {
        parse_export_table(api_list, module, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(file_mapping) + pNtHeader->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), reinterpret_cast<DWORD_PTR>(file_mapping));
    }

    UnmapViewOfFile(file_mapping);
}

void api_reader::parse_module_local(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module)
{
    HMODULE hModule = GetModuleHandle(module->filename().c_str());

    if (hModule)
    {
        const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(hModule) + static_cast<DWORD_PTR>(pDosHeader->
            e_lfanew));

        if (is_pe_and_export_table_valid(pNtHeader))
        {
            parse_export_table(api_list, module, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(hModule) + pNtHeader->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), reinterpret_cast<DWORD_PTR>(hModule));
        }
    }
    else
    {
        context_->log(scylla_severity::debug, TEXT("parse_module_local :: hModule is NULL"));
    }
}

void api_reader::parse_module_remote(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module)
{
    BYTE *bufferHeader = get_header_from_process(module);

    if (bufferHeader == nullptr)
        return;

    const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(bufferHeader);
    const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(bufferHeader) + static_cast<DWORD_PTR>(pDosHeader->e_lfanew));

    if (is_pe_and_export_table_valid(pNtHeader))
    {
        BYTE *bufferExportTable = get_export_table_from_process(module, pNtHeader);

        if (bufferExportTable)
        {
            parse_export_table(api_list, module, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(bufferExportTable), reinterpret_cast<DWORD_PTR>(bufferExportTable) - pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            delete[] bufferExportTable;
        }
    }
}

bool api_reader::is_pe_and_export_table_valid(PIMAGE_NT_HEADERS pNtHeader)
{
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        context_->log(scylla_severity::information, TEXT("-> IMAGE_NT_SIGNATURE doesn't match."));
        return false;
    }

    if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
        context_->log(scylla_severity::information, TEXT("-> No export table."));
        return false;
    }

    return true;
}

void api_reader::parse_export_table(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& module, PIMAGE_NT_HEADERS pNtHeader,
    PIMAGE_EXPORT_DIRECTORY pExportDir, intptr_t deltaAddress)
{
    TCHAR functionName[MAX_PATH*2];
    intptr_t RVA;
    uintptr_t VA;
    uint16_t ordinal;

    const auto addressOfFunctionsArray = reinterpret_cast<DWORD *>(static_cast<intptr_t>(pExportDir->AddressOfFunctions) + deltaAddress);
    const auto addressOfNamesArray = reinterpret_cast<DWORD *>(static_cast<intptr_t>(pExportDir->AddressOfNames) + deltaAddress);
    const auto addressOfNameOrdinalsArray = reinterpret_cast<WORD *>(static_cast<intptr_t>(pExportDir->AddressOfNameOrdinals) + deltaAddress);

    context_->log(scylla_severity::debug, TEXT("parse_export_table :: module %s NumberOfNames %X"), module->full_path().c_str(), pExportDir->NumberOfNames);
    for (uint16_t i = 0; i < pExportDir->NumberOfNames; i++)
    {
        StringConversion::ToTStr(reinterpret_cast<LPCSTR>(addressOfNamesArray[i] + deltaAddress), functionName, MAX_PATH*2);
        ordinal = static_cast<WORD>(addressOfNameOrdinalsArray[i] + pExportDir->Base);
        RVA = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]];
        VA = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]] + module->base_address();

        context_->log(scylla_severity::debug, TEXT("parse_export_table :: api %s ordinal %d imagebase ") PRINTF_DWORD_PTR_FULL TEXT(" RVA ") PRINTF_DWORD_PTR_FULL TEXT(" VA ") PRINTF_DWORD_PTR_FULL, functionName, ordinal, module->base_address(), RVA, VA);
        if (!api_info::is_api_blacklisted(functionName))
        {
            if (!api_info::is_api_forwarded(RVA, pNtHeader))
            {
                add_api(api_list, module, functionName, i, ordinal, VA, RVA, false);
            }
            else
            {
                handle_forwarded_api(api_list, module, RVA + deltaAddress, functionName, RVA, ordinal);
            }
        }
    }

    /*Exports without name*/
    if (pExportDir->NumberOfNames != pExportDir->NumberOfFunctions)
    {
        for (uint16_t i = 0; i < pExportDir->NumberOfFunctions; i++)
        {
            bool withoutName = true;
            for (uint16_t j = 0; j < pExportDir->NumberOfNames; j++)
            {
                if (addressOfNameOrdinalsArray[j] == i)
                {
                    withoutName = false;
                    break;
                }
            }
            if (withoutName && addressOfFunctionsArray[i] != 0)
            {
                ordinal = static_cast<uint16_t>(i + pExportDir->Base);
                RVA = addressOfFunctionsArray[i];
                VA = addressOfFunctionsArray[i] + module->base_address();

                if (!api_info::is_api_forwarded(RVA, pNtHeader))
                {
                    add_api(api_list, module, ordinal, VA, RVA, false);
                }
                else
                {
                    handle_forwarded_api(api_list, module, RVA + deltaAddress, nullptr, RVA, ordinal);
                }
            }
        }
    }
}

uint8_t* api_reader::get_header_from_process(const std::shared_ptr<module_info>& module)
{
    DWORD readSize;

    if (module->base_size() < PE_HEADER_BYTES_COUNT)
    {
        readSize = module->base_size();
    }
    else
    {
        readSize = PE_HEADER_BYTES_COUNT;
    }

    const auto bufferHeader = new uint8_t[readSize];

    if (!read_remote_memory(module->base_address(), bufferHeader, readSize))
    {
        context_->log(scylla_severity::debug, TEXT("get_header_from_process :: Error reading header"));

        delete[] bufferHeader;
        return nullptr;
    }
    return bufferHeader;
}

uint8_t* api_reader::get_export_table_from_process(const std::shared_ptr<module_info>& module, PIMAGE_NT_HEADERS pNtHeader)
{
    DWORD read_size = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (read_size < sizeof(IMAGE_EXPORT_DIRECTORY) + 8)
    {
        //Something is wrong with the PE Header
        context_->log(scylla_severity::debug, TEXT("get_export_table_from_process :: Something is wrong with the PE Header here Export table size %d"), read_size);
        read_size = sizeof(IMAGE_EXPORT_DIRECTORY) + 100;
    }

    if (read_size)
    {
        const auto buffer_export_table = new uint8_t[read_size];

        if (!buffer_export_table)
        {
            context_->log(scylla_severity::debug, TEXT("get_export_table_from_process :: Something is wrong with the PE Header here Export table size %d"), read_size);
            return nullptr;
        }
        if (!read_remote_memory(module->base_address() + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, buffer_export_table, read_size))
        {
            context_->log(scylla_severity::debug, TEXT("get_export_table_from_process :: Error reading export table from process"));

            delete[] buffer_export_table;
            return nullptr;
        }
        return buffer_export_table;
    }
    return nullptr;
}

bool api_reader::is_api_address_valid(uintptr_t virtual_address) const
{
    return api_list_.count(virtual_address) > 0;
}

void api_reader::set_min_max_api_address(uintptr_t virtual_address)
{
    if (virtual_address == 0 || virtual_address == static_cast<uintptr_t>(-1))
        return;

    if (virtual_address < min_api_address_)
    {
        context_->log(scylla_severity::debug, TEXT("set_min_max_api_address :: virtualAddress %p < minApiAddress %p"), virtual_address, min_api_address_);
        min_api_address_ = virtual_address - 1;
    }
    if (virtual_address > max_api_address_)
    {
        context_->log(scylla_severity::debug, TEXT("set_min_max_api_address :: virtualAddress %p > minApiAddress %p"), virtual_address, min_api_address_);
        max_api_address_ = virtual_address + 1;
    }
}

void api_reader::add_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, std::shared_ptr<module_info> module, LPCTSTR functionName, uint16_t hint, uint16_t ordinal, uintptr_t va, intptr_t rva,
    bool is_forwarded)
{
    std::shared_ptr<api_info> info = std::make_shared<api_info>(module);

    if (functionName != nullptr)
    {
        info->name(functionName);
    }
    else
    {
        info->name(TEXT("\0"));
    }

    info->ordinal(ordinal);
    info->is_forwarded(is_forwarded);
    info->rva(rva);
    info->va(va);
    info->hint(hint);

    set_min_max_api_address(va);

    module->append(info);

    api_list.insert(api_pair(va, info));
}

void api_reader::add_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, std::shared_ptr<module_info> module, uint16_t ordinal, uintptr_t va, intptr_t rva, bool is_forwarded)
{
    add_api(api_list, std::move(module), nullptr, 0, ordinal, va, rva, is_forwarded);
}

void api_reader::handle_forwarded_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>& api_list, const std::shared_ptr<module_info>& parent_module, uintptr_t vaStringPointer, LPCTSTR functionNameParent, intptr_t rvaParent, uint16_t ordinalParent)
{

    std::shared_ptr<module_info> module;
    uint16_t ordinal{};
    uintptr_t vaApi{};
    intptr_t rvaApi{};
    TCHAR dllName[100]{};
    const auto forwardedString = reinterpret_cast<LPCTSTR>(vaStringPointer);
    LPCTSTR searchFunctionName = _tcschr(forwardedString, TEXT('.'));

    if (!searchFunctionName)
        return;

    const size_t dllNameLength = searchFunctionName - forwardedString;

    if (dllNameLength >= 99)
        return;

    _tcsncpy_s(dllName, forwardedString, dllNameLength);

    searchFunctionName++;

    if (_tcschr(searchFunctionName, '#'))
    {
        searchFunctionName++;
        ordinal = static_cast<WORD>(_ttol(searchFunctionName));
    }

    //Since Windows 7
    if (!_tcsnicmp(dllName, TEXT("API-"), 4) || !_tcsnicmp(dllName, TEXT("EXT-"), 4)) //API_SET_PREFIX_NAME, API_SET_EXTENSION
    {
        /*
            Info: http://www.nirsoft.net/articles/windows_7_kernel_architecture_changes.html
        */
        FARPROC addy;
        HMODULE hModTemp = GetModuleHandle(dllName);
        if (hModTemp == nullptr)
        {
            hModTemp = LoadLibrary(dllName);
        }

        if (ordinal)
        {
            addy = GetProcAddress(hModTemp, reinterpret_cast<LPCSTR>(ordinal));
        }
        else
        {
            char func_name[MAX_PATH];
            StringConversion::ToCStr(searchFunctionName, func_name, MAX_PATH);
            addy = GetProcAddress(hModTemp, func_name);
        }
        context_->log(scylla_severity::debug, TEXT("API_SET_PREFIX_NAME %s %S Module Handle %p addy %p"), parent_module->full_path().c_str(), dllName, hModTemp, addy);

        if (addy != nullptr)
        {
            add_api(api_list, parent_module, functionNameParent, 0, ordinalParent, reinterpret_cast<DWORD_PTR>(addy), reinterpret_cast<DWORD_PTR>(addy) - reinterpret_cast<DWORD_PTR>(hModTemp), true);
        }

        return;
    }

    _tcscat_s(dllName, TEXT(".dll"));

    if (!_tcsicmp(dllName, parent_module->filename().c_str()))
    {
        module = parent_module;
    }
    else
    {
        module = find_module_by_name(dllName);
    }

    if (module != nullptr) // module == 0 -> can be ignored
    {
        /*if ((module->isAlreadyParsed == false) && (module != moduleParent))
        {
            //do API extract

            if (module->parsing == true)
            {
                //some stupid circle dependency
                printf("stupid circle dependency %s\n",module->getFilename());
            }
            else
            {
                parseModule(module);
            }
        }*/

        if (ordinal)
        {
            //forwarding by ordinal
            find_api_by_module(module, ordinal, &vaApi, &rvaApi);
        }
        else
        {
            find_api_by_module(module, searchFunctionName, &vaApi, &rvaApi);
        }

        if (rvaApi == 0)
        {
            context_->log(scylla_severity::debug, TEXT("handle_forwarded_api :: Api not found, this is really BAD! %S"), forwardedString);
        }
        else
        {
            add_api(api_list, parent_module, functionNameParent, 0, ordinalParent, vaApi, rvaApi, true);
        }
    }
}

bool api_reader::is_invalid_memory_for_iat(uintptr_t address) const
{
    if (address == 0)
        return true;

    if (address == static_cast<DWORD_PTR>(-1))
        return true;

    MEMORY_BASIC_INFORMATION memBasic{};

    if (VirtualQueryEx(process_, reinterpret_cast<LPCVOID>(address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        return !(memBasic.State == MEM_COMMIT && is_page_accessable(memBasic.Protect));
    }

    return true;
}

std::shared_ptr<module_info> api_reader::find_module_by_name(LPCTSTR name) const
{
    for (auto& i : *context_->target_modules())
    {
        if (!_tcsicmp(i->filename().c_str(), name))
        {
            return i;
        }
    }
    return nullptr;
}

void api_reader::find_api_by_module(const std::shared_ptr<module_info>& module, uint16_t ordinal, uintptr_t* vaApi, intptr_t* rvaApi)
{
    find_api_by_module(module, nullptr, ordinal, vaApi, rvaApi);
}

void api_reader::find_api_by_module(const std::shared_ptr<module_info>& module, LPCTSTR searchFunctionName, uintptr_t* vaApi, intptr_t* rvaApi)
{
    find_api_by_module(module, searchFunctionName, 0, vaApi, rvaApi);
}

void api_reader::find_api_by_module(const std::shared_ptr<module_info>& module, LPCTSTR searchFunctionName, uint16_t ordinal, uintptr_t * vaApi, intptr_t * rvaApi)
{
    if (module->is_loaded_local())
    {
        HMODULE hModule = GetModuleHandle(module->filename().c_str());

        if (hModule)
        {
            if (vaApi)
            {
                if (ordinal)
                {
                    *vaApi = reinterpret_cast<DWORD_PTR>(GetProcAddress(hModule, reinterpret_cast<LPCSTR>(ordinal)));
                }
                else
                {
                    char func_name[MAX_PATH];
                    StringConversion::ToCStr(searchFunctionName, func_name, MAX_PATH);
                    *vaApi = reinterpret_cast<DWORD_PTR>(GetProcAddress(hModule, func_name));
                }

                *rvaApi = *vaApi - reinterpret_cast<DWORD_PTR>(hModule);
                *vaApi = *rvaApi + module->base_address();
            }
            else
            {
                context_->log(scylla_severity::debug, TEXT("findApiByModule :: vaApi == NULL, should never happen %S"), searchFunctionName);
            }
        }
        else
        {
            context_->log(scylla_severity::debug, TEXT("findApiByModule :: hModule == NULL, should never happen %s"), module->filename().c_str());
        }
    }
    else
    {
        //search api in extern process
        find_api_by_module_remote(module, searchFunctionName, ordinal, vaApi, rvaApi);
    }
}

void api_reader::find_api_by_module_remote(const std::shared_ptr<module_info>& module, LPCTSTR searchFunctionName, uint16_t ordinal, uintptr_t* vaApi, intptr_t* rvaApi)
{
    BYTE *bufferHeader = get_header_from_process(module);

    if (bufferHeader == nullptr)
        return;

    const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(bufferHeader);
    const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(bufferHeader) + static_cast<DWORD_PTR>(pDosHeader->e_lfanew));

    if (is_pe_and_export_table_valid(pNtHeader))
    {
        BYTE *bufferExportTable = get_export_table_from_process(module, pNtHeader);

        if (bufferExportTable)
        {
            find_api_in_export_table(module, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(bufferExportTable), reinterpret_cast<DWORD_PTR>(bufferExportTable) - pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, searchFunctionName, ordinal, vaApi, rvaApi);
            delete[] bufferExportTable;
        }
    }

    delete[] bufferHeader;
}

bool api_reader::find_api_in_export_table(const std::shared_ptr<module_info>& module, PIMAGE_EXPORT_DIRECTORY pExportDir, intptr_t deltaAddress, LPCTSTR searchFunctionName, uint16_t ordinal, uintptr_t * vaApi, intptr_t * rvaApi)
{
    TCHAR functionName[MAX_PATH];

    const auto addressOfFunctionsArray = reinterpret_cast<DWORD *>(static_cast<DWORD_PTR>(pExportDir->AddressOfFunctions) + deltaAddress);
    const auto addressOfNamesArray = reinterpret_cast<DWORD *>(static_cast<DWORD_PTR>(pExportDir->AddressOfNames) + deltaAddress);
    const auto addressOfNameOrdinalsArray = reinterpret_cast<WORD *>(static_cast<DWORD_PTR>(pExportDir->AddressOfNameOrdinals) + deltaAddress);

    if (searchFunctionName)
    {
        for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
        {
            StringConversion::ToTStr(reinterpret_cast<LPCSTR>(addressOfNamesArray[i] + deltaAddress), functionName, MAX_PATH);
            if (!_tcscmp(functionName, searchFunctionName))
            {
                *rvaApi = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]];
                *vaApi = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]] + module->base_address();
                return true;
            }
        }
    }
    else
    {
        for (DWORD i = 0; i < pExportDir->NumberOfFunctions; i++)
        {
            if (ordinal == i + pExportDir->Base)
            {
                *rvaApi = addressOfFunctionsArray[i];
                *vaApi = addressOfFunctionsArray[i] + module->base_address();
                return true;
            }
        }
    }
    return false;
}

void api_reader::parse_iat(uintptr_t addressIAT, uint8_t* iatBuffer, size_t size, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    std::shared_ptr<module_info> module = nullptr;
    bool isSuspect = false;
    int countApiFound = 0, countApiNotFound = 0;
    auto* pIATAddress = reinterpret_cast<DWORD_PTR *>(iatBuffer);
    const SIZE_T sizeIAT = size / sizeof(DWORD_PTR);

    for (SIZE_T i = 0; i < sizeIAT; i++)
    {
        //Scylla::Log->log(L"%08X %08X %d von %d", addressIAT + (DWORD_PTR)&pIATAddress[i] - (DWORD_PTR)iatBuffer, pIATAddress[i],i,sizeIAT);

        if (!is_invalid_memory_for_iat(pIATAddress[i]))
        {
            context_->log(scylla_severity::debug, TEXT("min %p max %p address %p"), min_api_address_, max_api_address_, pIATAddress[i]);
            if (pIATAddress[i] > min_api_address_ && pIATAddress[i] < max_api_address_)
            {

                std::shared_ptr<api_info> apiFound = get_api_by_virtual_address(pIATAddress[i], &isSuspect);

                if (apiFound && 0 == _tcscmp(apiFound->name(), TEXT("EnableWindow")))
                    countApiFound = countApiFound;

                context_->log(scylla_severity::debug, TEXT("apiFound %p address %p"), apiFound.get(), pIATAddress[i]);
                if (apiFound == nullptr)
                {
                    context_->log(scylla_severity::debug, TEXT("getApiByVirtualAddress :: No Api found ") PRINTF_DWORD_PTR_FULL, pIATAddress[i]);
                }
                if (apiFound.get() == reinterpret_cast<api_info*>(1))
                {
                    context_->log(scylla_severity::debug, TEXT("apiFound == (ApiInfo *)1 -> ") PRINTF_DWORD_PTR_FULL, pIATAddress[i]);
                }
                else if (apiFound)
                {
                    countApiFound++;
                    context_->log(scylla_severity::debug, PRINTF_DWORD_PTR_FULL TEXT(" %s %d %s"), apiFound->va(), apiFound->module()->filename().c_str(), apiFound->ordinal(), apiFound->name());
                    if (module != apiFound->module())
                    {
                        module = apiFound->module();
                        add_found_api_to_module_list(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), apiFound, true, isSuspect, module_list_new);
                    }
                    else
                    {
                        add_found_api_to_module_list(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), apiFound, false, isSuspect, module_list_new);
                    }

                }
                else
                {
                    countApiNotFound++;
                    add_not_found_api_to_module_list(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), pIATAddress[i], module_list_new);
                    //printf("parseIAT :: API not found %08X\n", pIATAddress[i]);
                }
            }
            else
            {
                //printf("parseIAT :: API not found %08X\n", pIATAddress[i]);
                countApiNotFound++;
                add_not_found_api_to_module_list(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), pIATAddress[i], module_list_new);
            }
        }

    }

    context_->log(scylla_severity::debug, TEXT("IAT parsing finished, found %d valid APIs, missed %d APIs"), countApiFound, countApiNotFound);
}

std::shared_ptr<api_info> api_reader::get_api_by_virtual_address(uintptr_t virtualAddress, bool * isSuspect)
{
    std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>::const_iterator it1, it2;

    const size_t countDuplicates = context_->target_apis()->count(virtualAddress);

    if (countDuplicates == 0)
    {
        return nullptr;
    }

    if (countDuplicates == 1)
    {
        //API is 100% correct
        *isSuspect = false;
        it1 = context_->target_apis()->find(virtualAddress); // Find first match.
        return it1->second;
    }

    it1 = context_->target_apis()->find(virtualAddress); // Find first match.

    //any high priority with a name
    std::shared_ptr<api_info> apiFound = get_scored_api(it1, countDuplicates, true, false, false, true, false, false, false, false);

    if (apiFound)
        return apiFound;

    *isSuspect = true;

    //high priority with a name and ansi/unicode name
    apiFound = get_scored_api(it1, countDuplicates, true, true, false, true, false, false, false, false);

    if (apiFound)
        return apiFound;

    //priority 2 with no underline in name
    apiFound = get_scored_api(it1, countDuplicates, true, false, true, false, false, false, true, false);

    if (apiFound)
        return apiFound;

    //priority 1 with a name
    apiFound = get_scored_api(it1, countDuplicates, true, false, false, false, false, true, false, false);

    if (apiFound)
        return apiFound;

    //With a name
    apiFound = get_scored_api(it1, countDuplicates, true, false, false, false, false, false, false, false);

    if (apiFound)
        return apiFound;

    //any with priority, name, ansi/unicode
    apiFound = get_scored_api(it1, countDuplicates, true, true, false, true, false, false, false, true);

    if (apiFound)
        return apiFound;

    //any with priority
    apiFound = get_scored_api(it1, countDuplicates, false, false, false, true, false, false, false, true);

    if (apiFound)
        return apiFound;

    //has prio 0 and name
    apiFound = get_scored_api(it1, countDuplicates, false, false, false, false, true, false, false, true);

    if (apiFound)
        return apiFound;

    // There is a equal number of legit imports going by the same virtual address => log every one of them and return the last one.
    context_->log(scylla_severity::warning, TEXT("getApiByVirtualAddress :: There is a api resolving bug, VA: ") PRINTF_DWORD_PTR_FULL, virtualAddress);
    for (size_t c = 0; c < countDuplicates; c++, it1++)
    {
        apiFound = it1->second;
        context_->log(scylla_severity::warning, TEXT("-> Possible API: %S ord: %d "), apiFound->name(), apiFound->ordinal());
    }

    return apiFound;
}

std::shared_ptr<api_info> api_reader::get_scored_api(std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>>::const_iterator it1, size_t count_duplicates, bool has_name, bool has_unicode_ansi_name, bool has_no_underline_in_name, bool has_prio_dll, bool has_prio0_dll, bool has_prio1_dll, bool has_prio2_dll, bool first_win)
{
    std::shared_ptr<api_info> found_matching_api = nullptr;
    int count_found_apis = 0;
    int score_needed = 0;

    if (has_unicode_ansi_name || has_no_underline_in_name)
    {
        has_name = true;
    }

    if (has_name)
        score_needed++;

    if (has_unicode_ansi_name)
        score_needed++;

    if (has_no_underline_in_name)
        score_needed++;

    if (has_prio_dll)
        score_needed++;

    if (has_prio0_dll)
        score_needed++;

    if (has_prio1_dll)
        score_needed++;

    if (has_prio2_dll)
        score_needed++;

    for (size_t c = 0; c < count_duplicates; c++, it1++)
    {
        std::shared_ptr<api_info> foundApi = it1->second;
        int scoreValue = 0;

        if (has_name)
        {
            if (foundApi->name()[0] != 0x00)
            {
                scoreValue++;

                if (has_unicode_ansi_name)
                {
                    const size_t apiNameLength = _tcslen(foundApi->name());

                    if ((foundApi->name()[apiNameLength - 1] == TEXT('W')) || (foundApi->name()[apiNameLength - 1] == TEXT('A')))
                    {
                        scoreValue++;
                    }
                }

                if (has_no_underline_in_name)
                {
                    if (!_tcsrchr(foundApi->name(), '_'))
                    {
                        scoreValue++;
                    }
                }
            }
        }

        if (has_prio_dll)
        {
            if (foundApi->module()->priority() >= 1)
            {
                scoreValue++;
            }
        }

        if (has_prio0_dll)
        {
            if (foundApi->module()->priority() == 0)
            {
                scoreValue++;
            }
        }

        if (has_prio1_dll)
        {
            if (foundApi->module()->priority() == 1)
            {
                scoreValue++;
            }
        }

        if (has_prio2_dll)
        {
            if (foundApi->module()->priority() == 2)
            {
                scoreValue++;
            }
        }


        if (scoreValue == score_needed)
        {
            found_matching_api = foundApi;
            count_found_apis++;

            if (first_win)
            {
                return found_matching_api;
            }
        }
    }

    if (count_found_apis == 1)
    {
        return found_matching_api;
    }
    return nullptr;
}

void api_reader::add_found_api_to_module_list(uintptr_t iatAddress, const std::shared_ptr<api_info>& api_found, bool isNewModule, bool isSuspect, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    if (isNewModule)
    {
        add_module_to_module_list(api_found->module()->filename().c_str(), iatAddress - target_image_base_, module_list_new);
    }
    add_function_to_module_list(api_found, iatAddress, iatAddress - target_image_base_, api_found->ordinal(), true, isSuspect, module_list_new);
}

bool api_reader::add_not_found_api_to_module_list(uintptr_t iatAddressVA, uintptr_t apiAddress, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    ImportThunk import;
    ImportModuleThunk  * module = nullptr;
    DWORD_PTR rva = iatAddressVA - target_image_base_;

    if (!module_list_new.empty())
    {
        std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1 = module_list_new.begin();
        while (iterator1 != module_list_new.end())
        {
            if (rva >= iterator1->second.firstThunk)
            {
                iterator1++;
                if (iterator1 == module_list_new.end())
                {
                    iterator1--;
                    //new unknown module
                    if (iterator1->second.moduleName[0] == L'?')
                    {
                        module = &(iterator1->second);
                    }
                    else
                    {
                        add_unknown_module_to_module_list(rva, module_list_new);
                        module = &(module_list_new.find(rva)->second);
                    }

                    break;
                }
                else if (rva < iterator1->second.firstThunk)
                {
                    iterator1--;
                    module = &(iterator1->second);
                    break;
                }
            }
            else
            {
                context_->log(scylla_severity::debug, TEXT("add_not_found_api_to_module_list :: Error iterator1 != (*moduleThunkList).end()\r\n"));
                break;
            }
        }
    }
    else
    {
        //new unknown module
        add_unknown_module_to_module_list(rva, module_list_new);
        module = &(module_list_new.find(rva)->second);
    }

    if (!module)
    {
        context_->log(scylla_severity::debug, TEXT("add_not_found_api_to_module_list :: module not found rva ") PRINTF_DWORD_PTR_FULL, rva);
        return false;
    }

    import.suspect = true;
    import.valid = false;
    import.va = iatAddressVA;
    import.rva = rva;
    import.apiAddressVA = apiAddress;
    import.ordinal = 0;

    _tcscpy_s(import.moduleName, TEXT("?"));
    _tcscpy_s(import.name, TEXT("?"));

    module->thunkList.insert(std::pair<DWORD_PTR, ImportThunk>(import.rva, import));

    return true;
}

void api_reader::add_module_to_module_list(LPCTSTR moduleName, uintptr_t firstThunk, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    if (_tcslen(moduleName) < MAX_PATH)
        _tcscpy_s(module.moduleName, moduleName);

    module_list_new.insert(std::pair<uintptr_t, ImportModuleThunk>(firstThunk, module));
}

void api_reader::add_unknown_module_to_module_list(uintptr_t firstThunk, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    _tcscpy_s(module.moduleName, TEXT("?"));

    module_list_new.insert(std::pair<uintptr_t, ImportModuleThunk>(firstThunk, module));
}

bool api_reader::add_function_to_module_list(const std::shared_ptr<api_info>& api_found, uintptr_t va, intptr_t rva, uint16_t ordinal, bool valid, bool suspect, std::map<DWORD_PTR, ImportModuleThunk>& module_list_new)
{
    ImportThunk import;
    ImportModuleThunk  * module = 0;
    std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;

    if (module_list_new.size() > 1)
    {
        iterator1 = module_list_new.begin();
        while (iterator1 != module_list_new.end())
        {
            if (rva >= iterator1->second.firstThunk)
            {
                iterator1++;
                if (iterator1 == module_list_new.end())
                {
                    iterator1--;
                    module = &(iterator1->second);
                    break;
                }

                if (rva < iterator1->second.firstThunk)
                {
                    iterator1--;
                    module = &(iterator1->second);
                    break;
                }
            }
            else
            {
                context_->log(scylla_severity::debug, TEXT("add_function_to_module_list :: Error iterator1 != (*moduleThunkList).end()"));
                break;
            }
        }
    }
    else
    {
        iterator1 = module_list_new.begin();
        module = &(iterator1->second);
    }

    if (!module)
    {
        context_->log(scylla_severity::debug, TEXT("add_function_to_module_list :: module not found rva ") PRINTF_DWORD_PTR_FULL, rva);
        return false;
    }

    import.suspect = suspect;
    import.valid = valid;
    import.va = va;
    import.rva = rva;
    import.apiAddressVA = api_found->va();
    import.ordinal = ordinal;
    import.hint = api_found->hint();

    if (_tcslen(api_found->module()->filename().c_str()) < MAX_PATH)
        _tcscpy_s(import.moduleName, api_found->module()->filename().c_str());
    _tcscpy_s(import.name, api_found->name());

    module->thunkList.insert(std::pair<DWORD_PTR, ImportThunk>(import.rva, import));

    return true;
}
