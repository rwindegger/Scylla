
#include "ApiReader.h"
#include <VersionHelpers.h>

#include "Scylla.h"
#include "Architecture.h"
#include "StringConversion.h"
#include "PeParser.h"

//stdext::hash_multimap<DWORD_PTR, ApiInfo *> ApiReader::apiList; //api look up table
std::unordered_multimap<DWORD_PTR, ApiInfo *> ApiReader::apiList; //api look up table
std::map<DWORD_PTR, ImportModuleThunk> *  ApiReader::moduleThunkList; //store found apis

DWORD_PTR ApiReader::minApiAddress = static_cast<DWORD_PTR>(-1);
DWORD_PTR ApiReader::maxApiAddress = 0;

void ApiReader::readApisFromModuleList()
{
    if (Scylla::config[APIS_ALWAYS_FROM_DISK].isTrue())
    {
        readExportTableAlwaysFromDisk = true;
    }
    else
    {
        readExportTableAlwaysFromDisk = false;
    }

    for (auto& i : moduleList)
    {
        setModulePriority(&i);

        if (i.modBaseAddr + i.modBaseSize > maxValidAddress)
        {
            maxValidAddress = i.modBaseAddr + i.modBaseSize;
        }

        Scylla::Log->log(TEXT("Module parsing: %s"), i.fullPath);

        if (!i.isAlreadyParsed)
        {
            parseModule(&i);
        }
    }

    Scylla::debugLog.log(TEXT("Address Min ") PRINTF_DWORD_PTR_FULL TEXT(" Max ") PRINTF_DWORD_PTR_FULL TEXT("\nimagebase ") PRINTF_DWORD_PTR_FULL TEXT(" maxValidAddress ") PRINTF_DWORD_PTR_FULL, minApiAddress, maxApiAddress, targetImageBase, maxValidAddress);
}

void ApiReader::parseModule(ModuleInfo *module) const
{
    module->parsing = true;

    if (isWinSxSModule(module))
    {
        parseModuleWithMapping(module);
    }
    else if (isModuleLoadedInOwnProcess(module)) //this is always ok
    {
        parseModuleWithOwnProcess(module);
    }
    else
    {
        if (readExportTableAlwaysFromDisk)
        {
            parseModuleWithMapping(module);
        }
        else
        {
            parseModuleWithProcess(module);
        }
    }

    module->isAlreadyParsed = true;
}

void ApiReader::parseModuleWithMapping(ModuleInfo *moduleInfo) const
{
    LPVOID fileMapping = createFileMappingViewRead(moduleInfo->fullPath);

    if (fileMapping == nullptr)
        return;

    const auto pDosHeader = static_cast<PIMAGE_DOS_HEADER>(fileMapping);
    const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(fileMapping) + static_cast<DWORD_PTR>(pDosHeader->e_lfanew));

    if (isPeAndExportTableValid(pNtHeader))
    {
        parseExportTable(moduleInfo, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(fileMapping) + pNtHeader->OptionalHeader.DataDirectory[
            IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), reinterpret_cast<DWORD_PTR>(fileMapping));
    }

    UnmapViewOfFile(fileMapping);
}

inline bool ApiReader::isApiForwarded(DWORD_PTR rva, PIMAGE_NT_HEADERS pNtHeader)
{
    return rva > pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress &&
        rva < pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress +
        pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
}

void ApiReader::handleForwardedApi(DWORD_PTR vaStringPointer, LPCTSTR functionNameParent, DWORD_PTR rvaParent, WORD ordinalParent, ModuleInfo *moduleParent) const
{
    WORD ordinal = 0;
    ModuleInfo *module;
    DWORD_PTR vaApi = 0;
    DWORD_PTR rvaApi = 0;
    TCHAR dllName[100] = { 0 };
    const auto forwardedString = reinterpret_cast<LPCTSTR>(vaStringPointer);
    LPCTSTR searchFunctionName = _tcschr(forwardedString, TEXT('.'));

    if (!searchFunctionName)
        return;

    const size_t dllNameLength = searchFunctionName - forwardedString;

    if (dllNameLength >= 99)
    {
        return;
    }
    else
    {
        _tcsncpy_s(dllName, forwardedString, dllNameLength);
    }

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
        Scylla::debugLog.log(TEXT("API_SET_PREFIX_NAME %s %S Module Handle %p addy %p"), moduleParent->fullPath, dllName, hModTemp, addy);

        if (addy != nullptr)
        {
            addApi(functionNameParent, 0, ordinalParent, reinterpret_cast<DWORD_PTR>(addy), reinterpret_cast<DWORD_PTR>(addy) - reinterpret_cast<DWORD_PTR>(hModTemp), true, moduleParent);
        }

        return;
    }

    _tcscat_s(dllName, TEXT(".dll"));

    if (!_tcsicmp(dllName, moduleParent->getFilename()))
    {
        module = moduleParent;
    }
    else
    {
        module = findModuleByName(dllName);
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
            findApiByModuleAndOrdinal(module, ordinal, &vaApi, &rvaApi);
        }
        else
        {
            findApiByModuleAndName(module, searchFunctionName, &vaApi, &rvaApi);
        }

        if (rvaApi == 0)
        {
            Scylla::debugLog.log(TEXT("handleForwardedApi :: Api not found, this is really BAD! %S"), forwardedString);
        }
        else
        {
            addApi(functionNameParent, 0, ordinalParent, vaApi, rvaApi, true, moduleParent);
        }
    }

}

ModuleInfo * ApiReader::findModuleByName(LPTSTR name) const
{
    for (auto& i : moduleList)
    {
        if (!_tcsicmp(i.getFilename(), name))
        {
            return &i;
        }
    }

    return nullptr;
}

void ApiReader::addApiWithoutName(WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo *moduleInfo) const
{
    addApi(nullptr, 0, ordinal, va, rva, isForwarded, moduleInfo);
}

void ApiReader::addApi(LPCTSTR functionName, WORD hint, WORD ordinal, DWORD_PTR va, DWORD_PTR rva, bool isForwarded, ModuleInfo *moduleInfo) const
{
    auto apiInfo = new ApiInfo();

    if (functionName != nullptr && _tcslen(functionName) < _countof(apiInfo->name))
    {
        _tcscpy_s(apiInfo->name, functionName);
    }
    else
    {
        apiInfo->name[0] = TEXT('\0');
    }

    apiInfo->ordinal = ordinal;
    apiInfo->isForwarded = isForwarded;
    apiInfo->module = moduleInfo;
    apiInfo->rva = rva;
    apiInfo->va = va;
    apiInfo->hint = hint;

    setMinMaxApiAddress(va);

    moduleInfo->apiList.push_back(apiInfo);

    apiList.insert(API_Pair(va, apiInfo));
}

BYTE * ApiReader::getHeaderFromProcess(ModuleInfo * module)
{
    DWORD readSize;

    if (module->modBaseSize < PE_HEADER_BYTES_COUNT)
    {
        readSize = module->modBaseSize;
    }
    else
    {
        readSize = PE_HEADER_BYTES_COUNT;
    }

    const auto bufferHeader = new BYTE[readSize];

    if (!readMemoryFromProcess(module->modBaseAddr, readSize, bufferHeader))
    {
        Scylla::debugLog.log(TEXT("getHeaderFromProcess :: Error reading header"));

        delete[] bufferHeader;
        return nullptr;
    }
    else
    {
        return bufferHeader;
    }
}

BYTE * ApiReader::getExportTableFromProcess(ModuleInfo * module, PIMAGE_NT_HEADERS pNtHeader)
{
    DWORD readSize = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    if (readSize < sizeof(IMAGE_EXPORT_DIRECTORY) + 8)
    {
        //Something is wrong with the PE Header
        Scylla::debugLog.log(TEXT("Something is wrong with the PE Header here Export table size %d"), readSize);
        readSize = sizeof(IMAGE_EXPORT_DIRECTORY) + 100;
    }

    if (readSize)
    {
        const auto bufferExportTable = new BYTE[readSize];

        if (!bufferExportTable)
        {
            Scylla::debugLog.log(TEXT("Something is wrong with the PE Header here Export table size %d"), readSize);
            return nullptr;
        }

        if (!readMemoryFromProcess(module->modBaseAddr + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, readSize, bufferExportTable))
        {
            Scylla::debugLog.log(TEXT("getExportTableFromProcess :: Error reading export table from process"));

            delete[] bufferExportTable;
            return nullptr;
        }
        else
        {
            return bufferExportTable;
        }
    }
    else
    {
        return nullptr;
    }
}

void ApiReader::parseModuleWithProcess(ModuleInfo * module) const
{
    PeParser peParser(module->modBaseAddr, false);

    if (!peParser.isValidPeFile())
        return;

    const PIMAGE_NT_HEADERS pNtHeader = peParser.getCurrentNtHeader();

    if (peParser.hasExportDirectory())
    {
        BYTE *bufferExportTable = getExportTableFromProcess(module, pNtHeader);

        if (bufferExportTable)
        {
            parseExportTable(module, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(bufferExportTable), reinterpret_cast<DWORD_PTR>(bufferExportTable) - pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            delete[] bufferExportTable;
        }
    }
}

void ApiReader::parseExportTable(ModuleInfo *module, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress) const
{
    TCHAR functionName[MAX_PATH];
    DWORD_PTR RVA, VA;
    WORD ordinal;

    const auto addressOfFunctionsArray = reinterpret_cast<DWORD *>(static_cast<DWORD_PTR>(pExportDir->AddressOfFunctions) + deltaAddress);
    const auto addressOfNamesArray = reinterpret_cast<DWORD *>(static_cast<DWORD_PTR>(pExportDir->AddressOfNames) + deltaAddress);
    const auto addressOfNameOrdinalsArray = reinterpret_cast<WORD *>(static_cast<DWORD_PTR>(pExportDir->AddressOfNameOrdinals) + deltaAddress);

    Scylla::debugLog.log(TEXT("parseExportTable :: module %s NumberOfNames %X"), module->fullPath, pExportDir->NumberOfNames);
    for (WORD i = 0; i < pExportDir->NumberOfNames; i++)
    {
        StringConversion::ToTStr(reinterpret_cast<LPCSTR>(addressOfNamesArray[i] + deltaAddress), functionName, MAX_PATH);
        ordinal = static_cast<WORD>(addressOfNameOrdinalsArray[i] + pExportDir->Base);
        RVA = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]];
        VA = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]] + module->modBaseAddr;

        Scylla::debugLog.log(TEXT("parseExportTable :: api %S ordinal %d imagebase ") PRINTF_DWORD_PTR_FULL TEXT(" RVA ") PRINTF_DWORD_PTR_FULL TEXT(" VA ") PRINTF_DWORD_PTR_FULL, functionName, ordinal, module->modBaseAddr, RVA, VA);
        if (!isApiBlacklisted(functionName))
        {
            if (!isApiForwarded(RVA, pNtHeader))
            {
                addApi(functionName, i, ordinal, VA, RVA, false, module);
            }
            else
            {
                //printf("Forwarded: %s\n",functionName);
                handleForwardedApi(RVA + deltaAddress, functionName, RVA, ordinal, module);
            }
        }

    }

    /*Exports without name*/
    if (pExportDir->NumberOfNames != pExportDir->NumberOfFunctions)
    {
        for (WORD i = 0; i < pExportDir->NumberOfFunctions; i++)
        {
            bool withoutName = true;
            for (WORD j = 0; j < pExportDir->NumberOfNames; j++)
            {
                if (addressOfNameOrdinalsArray[j] == i)
                {
                    withoutName = false;
                    break;
                }
            }
            if (withoutName && addressOfFunctionsArray[i] != 0)
            {
                ordinal = static_cast<WORD>(i + pExportDir->Base);
                RVA = addressOfFunctionsArray[i];
                VA = addressOfFunctionsArray[i] + module->modBaseAddr;

                if (!isApiForwarded(RVA, pNtHeader))
                {
                    addApiWithoutName(ordinal, VA, RVA, false, module);
                }
                else
                {
                    handleForwardedApi(RVA + deltaAddress, nullptr, RVA, ordinal, module);
                }
            }
        }
    }
}

void ApiReader::findApiByModuleAndOrdinal(ModuleInfo * module, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const
{
    findApiByModule(module, nullptr, ordinal, vaApi, rvaApi);
}

void ApiReader::findApiByModuleAndName(ModuleInfo * module, LPCTSTR searchFunctionName, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const
{
    findApiByModule(module, searchFunctionName, 0, vaApi, rvaApi);
}

void ApiReader::findApiByModule(ModuleInfo * module, LPCTSTR searchFunctionName, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const
{
    if (isModuleLoadedInOwnProcess(module))
    {
        HMODULE hModule = GetModuleHandle(module->getFilename());

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
                *vaApi = *rvaApi + module->modBaseAddr;
            }
            else
            {
                Scylla::debugLog.log(TEXT("findApiByModule :: vaApi == NULL, should never happen %S"), searchFunctionName);
            }
        }
        else
        {
            Scylla::debugLog.log(TEXT("findApiByModule :: hModule == NULL, should never happen %s"), module->getFilename());
        }
    }
    else
    {
        //search api in extern process
        findApiInProcess(module, searchFunctionName, ordinal, vaApi, rvaApi);
    }
}

bool ApiReader::isModuleLoadedInOwnProcess(ModuleInfo * module) const
{
    for (auto& i : ownModuleList)
    {
        if (!_tcsicmp(module->fullPath, i.fullPath))
        {
            //printf("isModuleLoadedInOwnProcess :: %s %s\n",module->fullPath,ownModuleList[i].fullPath);
            return true;
        }
    }
    return false;
}

void ApiReader::parseModuleWithOwnProcess(ModuleInfo * module) const
{
    HMODULE hModule = GetModuleHandle(module->getFilename());

    if (hModule)
    {
        const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(hModule) + static_cast<DWORD_PTR>(pDosHeader->
            e_lfanew));

        if (isPeAndExportTableValid(pNtHeader))
        {
            parseExportTable(module, pNtHeader, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<DWORD_PTR>(hModule) + pNtHeader->OptionalHeader.DataDirectory[
                IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress), reinterpret_cast<DWORD_PTR>(hModule));
        }
    }
    else
    {
        Scylla::debugLog.log(TEXT("parseModuleWithOwnProcess :: hModule is NULL"));
    }
}

bool ApiReader::isPeAndExportTableValid(PIMAGE_NT_HEADERS pNtHeader)
{
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        Scylla::Log->log(TEXT("-> IMAGE_NT_SIGNATURE doesn't match."));
        return false;
    }

    if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
    {
        Scylla::Log->log(TEXT("-> No export table."));
        return false;
    }

    return true;
}

void ApiReader::findApiInProcess(ModuleInfo * module, LPCTSTR searchFunctionName, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const
{
    BYTE *bufferHeader = getHeaderFromProcess(module);

    if (bufferHeader == nullptr)
        return;

    const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(bufferHeader);
    const auto pNtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(bufferHeader) + static_cast<DWORD_PTR>(pDosHeader->e_lfanew));

    if (isPeAndExportTableValid(pNtHeader))
    {
        BYTE *bufferExportTable = getExportTableFromProcess(module, pNtHeader);

        if (bufferExportTable)
        {
            findApiInExportTable(module, reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(bufferExportTable), reinterpret_cast<DWORD_PTR>(bufferExportTable) - pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, searchFunctionName, ordinal, vaApi, rvaApi);
            delete[] bufferExportTable;
        }
    }

    delete[] bufferHeader;
}

bool ApiReader::findApiInExportTable(ModuleInfo *module, PIMAGE_EXPORT_DIRECTORY pExportDir, DWORD_PTR deltaAddress, LPCTSTR searchFunctionName, WORD ordinal, DWORD_PTR * vaApi, DWORD_PTR * rvaApi) const
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
                *vaApi = addressOfFunctionsArray[addressOfNameOrdinalsArray[i]] + module->modBaseAddr;
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
                *vaApi = addressOfFunctionsArray[i] + module->modBaseAddr;
                return true;
            }
        }
    }

    return false;
}

void ApiReader::setModulePriority(ModuleInfo * module)
{
    const LPCTSTR moduleFileName = module->getFilename();

    //imports by kernelbase don't exist
    if (!_tcsicmp(moduleFileName, TEXT("kernelbase.dll")))
    {
        module->priority = -1;
    }
    else if (!_tcsicmp(moduleFileName, TEXT("ntdll.dll")))
    {
        module->priority = 0;
    }
    else if (!_tcsicmp(moduleFileName, TEXT("shlwapi.dll")))
    {
        module->priority = 0;
    }
    else if (!_tcsicmp(moduleFileName, TEXT("ShimEng.dll")))
    {
        module->priority = 0;
    }
    else if (!_tcsicmp(moduleFileName, TEXT("kernel32.dll")))
    {
        module->priority = 2;
    }
    else if (!_tcsnicmp(moduleFileName, TEXT("API-"), 4) || !_tcsnicmp(moduleFileName, TEXT("EXT-"), 4)) //API_SET_PREFIX_NAME, API_SET_EXTENSION
    {
        module->priority = 0;
    }
    else
    {
        module->priority = 1;
    }
}

bool ApiReader::isApiAddressValid(DWORD_PTR virtualAddress) const
{
    return apiList.count(virtualAddress) > 0;
}

ApiInfo * ApiReader::getApiByVirtualAddress(DWORD_PTR virtualAddress, bool * isSuspect)
{
    //stdext::hash_multimap<DWORD_PTR, ApiInfo *>::iterator it1, it2;
    std::unordered_multimap<DWORD_PTR, ApiInfo *>::iterator it1, it2;
    const size_t countDuplicates = apiList.count(virtualAddress);
    ApiInfo *apiFound;

    if (countDuplicates == 0)
    {
        return nullptr;
    }
    else if (countDuplicates == 1)
    {
        //API is 100% correct
        *isSuspect = false;
        it1 = apiList.find(virtualAddress); // Find first match.
        return const_cast<ApiInfo *>((*it1).second);
    }
    else
    {
        it1 = apiList.find(virtualAddress); // Find first match.

        //any high priority with a name
        apiFound = getScoredApi(it1, countDuplicates, true, false, false, true, false, false, false, false);

        if (apiFound)
            return apiFound;

        *isSuspect = true;

        //high priority with a name and ansi/unicode name
        apiFound = getScoredApi(it1, countDuplicates, true, true, false, true, false, false, false, false);

        if (apiFound)
            return apiFound;

        //priority 2 with no underline in name
        apiFound = getScoredApi(it1, countDuplicates, true, false, true, false, false, false, true, false);

        if (apiFound)
            return apiFound;

        //priority 1 with a name
        apiFound = getScoredApi(it1, countDuplicates, true, false, false, false, false, true, false, false);

        if (apiFound)
            return apiFound;

        //With a name
        apiFound = getScoredApi(it1, countDuplicates, true, false, false, false, false, false, false, false);

        if (apiFound)
            return apiFound;

        //any with priority, name, ansi/unicode
        apiFound = getScoredApi(it1, countDuplicates, true, true, false, true, false, false, false, true);

        if (apiFound)
            return apiFound;

        //any with priority
        apiFound = getScoredApi(it1, countDuplicates, false, false, false, true, false, false, false, true);

        if (apiFound)
            return apiFound;

        //has prio 0 and name
        apiFound = getScoredApi(it1, countDuplicates, false, false, false, false, true, false, false, true);

        if (apiFound)
            return apiFound;
    }

    // There is a equal number of legit imports going by the same virtual address => log every one of them and return the last one.
    Scylla::Log->log(TEXT("getApiByVirtualAddress :: There is a api resolving bug, VA: ") PRINTF_DWORD_PTR_FULL, virtualAddress);
    for (size_t c = 0; c < countDuplicates; c++, it1++)
    {
        apiFound = const_cast<ApiInfo *>((*it1).second);
        Scylla::Log->log(TEXT("-> Possible API: %S ord: %d "), apiFound->name, apiFound->ordinal);
    }

    return apiFound;
}

//ApiInfo * ApiReader::getScoredApi(stdext::hash_multimap<DWORD_PTR, ApiInfo *>::iterator it1,size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll,bool hasPrio0Dll,bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin )
ApiInfo * ApiReader::getScoredApi(std::unordered_multimap<DWORD_PTR, ApiInfo *>::iterator it1, size_t countDuplicates, bool hasName, bool hasUnicodeAnsiName, bool hasNoUnderlineInName, bool hasPrioDll, bool hasPrio0Dll, bool hasPrio1Dll, bool hasPrio2Dll, bool firstWin)
{
    ApiInfo *foundMatchingApi = nullptr;
    int countFoundApis = 0;
    int scoreNeeded = 0;

    if (hasUnicodeAnsiName || hasNoUnderlineInName)
    {
        hasName = true;
    }

    if (hasName)
        scoreNeeded++;

    if (hasUnicodeAnsiName)
        scoreNeeded++;

    if (hasNoUnderlineInName)
        scoreNeeded++;

    if (hasPrioDll)
        scoreNeeded++;

    if (hasPrio0Dll)
        scoreNeeded++;

    if (hasPrio1Dll)
        scoreNeeded++;

    if (hasPrio2Dll)
        scoreNeeded++;

    for (size_t c = 0; c < countDuplicates; c++, it1++)
    {
        auto foundApi = const_cast<ApiInfo *>((*it1).second);
        int scoreValue = 0;

        if (hasName)
        {
            if (foundApi->name[0] != 0x00)
            {
                scoreValue++;

                if (hasUnicodeAnsiName)
                {
                    const size_t apiNameLength = _tcslen(foundApi->name);

                    if ((foundApi->name[apiNameLength - 1] == TEXT('W')) || (foundApi->name[apiNameLength - 1] == TEXT('A')))
                    {
                        scoreValue++;
                    }
                }

                if (hasNoUnderlineInName)
                {
                    if (!_tcsrchr(foundApi->name, '_'))
                    {
                        scoreValue++;
                    }
                }
            }
        }

        if (hasPrioDll)
        {
            if (foundApi->module->priority >= 1)
            {
                scoreValue++;
            }
        }

        if (hasPrio0Dll)
        {
            if (foundApi->module->priority == 0)
            {
                scoreValue++;
            }
        }

        if (hasPrio1Dll)
        {
            if (foundApi->module->priority == 1)
            {
                scoreValue++;
            }
        }

        if (hasPrio2Dll)
        {
            if (foundApi->module->priority == 2)
            {
                scoreValue++;
            }
        }


        if (scoreValue == scoreNeeded)
        {
            foundMatchingApi = foundApi;
            countFoundApis++;

            if (firstWin)
            {
                return foundMatchingApi;
            }
        }
    }

    if (countFoundApis == 1)
    {
        return foundMatchingApi;
    }
    else
    {
        return nullptr;
    }
}

void ApiReader::setMinMaxApiAddress(DWORD_PTR virtualAddress)
{
    if (virtualAddress == 0 || virtualAddress == static_cast<DWORD_PTR>(-1))
        return;

    if (virtualAddress < minApiAddress)
    {
        Scylla::debugLog.log(TEXT("virtualAddress %p < minApiAddress %p"), virtualAddress, minApiAddress);

        minApiAddress = virtualAddress - 1;
    }
    if (virtualAddress > maxApiAddress)
    {
        maxApiAddress = virtualAddress + 1;
    }
}

void  ApiReader::readAndParseIAT(DWORD_PTR addressIAT, DWORD sizeIAT, std::map<DWORD_PTR, ImportModuleThunk> &moduleListNew)
{
    moduleThunkList = &moduleListNew;
    const auto dataIat = new BYTE[sizeIAT];
    if (readMemoryFromProcess(addressIAT, sizeIAT, dataIat))
    {
        parseIAT(addressIAT, dataIat, sizeIAT);
    }
    else
    {
        Scylla::debugLog.log(TEXT("ApiReader::readAndParseIAT :: error reading iat ") PRINTF_DWORD_PTR_FULL, addressIAT);
    }

    delete[] dataIat;
}

void ApiReader::parseIAT(DWORD_PTR addressIAT, BYTE * iatBuffer, SIZE_T size)
{
    ModuleInfo *module = nullptr;
    bool isSuspect = false;
    int countApiFound = 0, countApiNotFound = 0;
    auto* pIATAddress = reinterpret_cast<DWORD_PTR *>(iatBuffer);
    const SIZE_T sizeIAT = size / sizeof(DWORD_PTR);

    for (SIZE_T i = 0; i < sizeIAT; i++)
    {
        //Scylla::Log->log(L"%08X %08X %d von %d", addressIAT + (DWORD_PTR)&pIATAddress[i] - (DWORD_PTR)iatBuffer, pIATAddress[i],i,sizeIAT);

        if (!isInvalidMemoryForIat(pIATAddress[i]))
        {
            Scylla::debugLog.log(TEXT("min %p max %p address %p"), minApiAddress, maxApiAddress, pIATAddress[i]);
            if (pIATAddress[i] > minApiAddress && pIATAddress[i] < maxApiAddress)
            {

                ApiInfo *apiFound = getApiByVirtualAddress(pIATAddress[i], &isSuspect);

                if (apiFound && 0 == _tcscmp(apiFound->name, TEXT("EnableWindow")))
                    countApiFound = countApiFound;

                Scylla::debugLog.log(TEXT("apiFound %p address %p"), apiFound, pIATAddress[i]);
                if (apiFound == nullptr)
                {
                    Scylla::Log->log(TEXT("getApiByVirtualAddress :: No Api found ") PRINTF_DWORD_PTR_FULL, pIATAddress[i]);
                }
                if (apiFound == reinterpret_cast<ApiInfo *>(1))
                {
                    Scylla::debugLog.log(TEXT("apiFound == (ApiInfo *)1 -> ") PRINTF_DWORD_PTR_FULL, pIATAddress[i]);
                }
                else if (apiFound)
                {
                    countApiFound++;
                    Scylla::debugLog.log(PRINTF_DWORD_PTR_FULL TEXT(" %s %d %s"), apiFound->va, apiFound->module->getFilename(), apiFound->ordinal, apiFound->name);
                    if (module != apiFound->module)
                    {
                        module = apiFound->module;
                        addFoundApiToModuleList(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), apiFound, true, isSuspect);
                    }
                    else
                    {
                        addFoundApiToModuleList(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), apiFound, false, isSuspect);
                    }

                }
                else
                {
                    countApiNotFound++;
                    addNotFoundApiToModuleList(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), pIATAddress[i]);
                    //printf("parseIAT :: API not found %08X\n", pIATAddress[i]);
                }
            }
            else
            {
                //printf("parseIAT :: API not found %08X\n", pIATAddress[i]);
                countApiNotFound++;
                addNotFoundApiToModuleList(addressIAT + reinterpret_cast<DWORD_PTR>(&pIATAddress[i]) - reinterpret_cast<DWORD_PTR>(iatBuffer), pIATAddress[i]);
            }
        }

    }

    Scylla::Log->log(TEXT("IAT parsing finished, found %d valid APIs, missed %d APIs"), countApiFound, countApiNotFound);
}

void ApiReader::addFoundApiToModuleList(DWORD_PTR iatAddress, ApiInfo * apiFound, bool isNewModule, bool isSuspect)
{
    if (isNewModule)
    {
        addModuleToModuleList(apiFound->module->getFilename(), iatAddress - targetImageBase);
    }
    addFunctionToModuleList(apiFound, iatAddress, iatAddress - targetImageBase, apiFound->ordinal, true, isSuspect);
}

bool ApiReader::addModuleToModuleList(LPCTSTR moduleName, DWORD_PTR firstThunk)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    if (_tcslen(moduleName) < MAX_PATH)
        _tcscpy_s(module.moduleName, moduleName);

    (*moduleThunkList).insert(std::pair<DWORD_PTR, ImportModuleThunk>(firstThunk, module));

    return true;
}

void ApiReader::addUnknownModuleToModuleList(DWORD_PTR firstThunk)
{
    ImportModuleThunk module;

    module.firstThunk = firstThunk;
    _tcscpy_s(module.moduleName, TEXT("?"));

    (*moduleThunkList).insert(std::pair<DWORD_PTR, ImportModuleThunk>(firstThunk, module));
}

bool ApiReader::addFunctionToModuleList(ApiInfo * apiFound, DWORD_PTR va, DWORD_PTR rva, WORD ordinal, bool valid, bool suspect)
{
    ImportThunk import;
    ImportModuleThunk  * module = 0;
    std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1;

    if ((*moduleThunkList).size() > 1)
    {
        iterator1 = (*moduleThunkList).begin();
        while (iterator1 != (*moduleThunkList).end())
        {
            if (rva >= iterator1->second.firstThunk)
            {
                iterator1++;
                if (iterator1 == (*moduleThunkList).end())
                {
                    iterator1--;
                    module = &(iterator1->second);
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
                Scylla::debugLog.log(TEXT("Error iterator1 != (*moduleThunkList).end()"));
                break;
            }
        }
    }
    else
    {
        iterator1 = (*moduleThunkList).begin();
        module = &(iterator1->second);
    }

    if (!module)
    {
        Scylla::debugLog.log(TEXT("ImportsHandling::addFunction module not found rva ") PRINTF_DWORD_PTR_FULL, rva);
        return false;
    }


    import.suspect = suspect;
    import.valid = valid;
    import.va = va;
    import.rva = rva;
    import.apiAddressVA = apiFound->va;
    import.ordinal = ordinal;
    import.hint = static_cast<WORD>(apiFound->hint);

    if (_tcslen(apiFound->module->getFilename()) < MAX_PATH)
        _tcscpy_s(import.moduleName, apiFound->module->getFilename());
    _tcscpy_s(import.name, apiFound->name);

    module->thunkList.insert(std::pair<DWORD_PTR, ImportThunk>(import.rva, import));

    return true;
}

void ApiReader::clearAll() const
{
    minApiAddress = static_cast<DWORD_PTR>(-1);
    maxApiAddress = 0;

    //for ( stdext::hash_map<DWORD_PTR, ApiInfo *>::iterator it = apiList.begin(); it != apiList.end(); ++it )
    for (auto& it : apiList)
    {
        delete it.second;
    }
    apiList.clear();

    if (moduleThunkList != nullptr)
    {
        (*moduleThunkList).clear();
    }
}

bool ApiReader::addNotFoundApiToModuleList(DWORD_PTR iatAddressVA, DWORD_PTR apiAddress)
{
    ImportThunk import;
    ImportModuleThunk  * module = nullptr;
    DWORD_PTR rva = iatAddressVA - targetImageBase;

    if (!(*moduleThunkList).empty())
    {
        std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1 = (*moduleThunkList).begin();
        while (iterator1 != (*moduleThunkList).end())
        {
            if (rva >= iterator1->second.firstThunk)
            {
                iterator1++;
                if (iterator1 == (*moduleThunkList).end())
                {
                    iterator1--;
                    //new unknown module
                    if (iterator1->second.moduleName[0] == L'?')
                    {
                        module = &(iterator1->second);
                    }
                    else
                    {
                        addUnknownModuleToModuleList(rva);
                        module = &((*moduleThunkList).find(rva)->second);
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
                Scylla::debugLog.log(TEXT("Error iterator1 != (*moduleThunkList).end()\r\n"));
                break;
            }
        }
    }
    else
    {
        //new unknown module
        addUnknownModuleToModuleList(rva);
        module = &((*moduleThunkList).find(rva)->second);
    }

    if (!module)
    {
        Scylla::debugLog.log(TEXT("ImportsHandling::addFunction module not found rva ") PRINTF_DWORD_PTR_FULL, rva);
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

bool ApiReader::isApiBlacklisted(LPCTSTR functionName)
{
    if (!IsWindowsVistaOrGreater())
    {
        return 0 != _tcscmp(functionName, TEXT("RestoreLastError"));
    }

    return false;
}

bool ApiReader::isWinSxSModule(ModuleInfo * module) const
{

    if (_tcsstr(module->fullPath, TEXT("\\WinSxS\\")))
    {
        return true;
    }

    if (_tcsstr(module->fullPath, TEXT("\\winsxs\\")))
    {
        return true;
    }

    return false;
}

bool ApiReader::isInvalidMemoryForIat(DWORD_PTR address)
{
    if (address == 0)
        return true;

    if (address == static_cast<DWORD_PTR>(-1))
        return true;

    MEMORY_BASIC_INFORMATION memBasic{};

    if (VirtualQueryEx(ProcessAccessHelp::hProcess, reinterpret_cast<LPCVOID>(address), &memBasic, sizeof(MEMORY_BASIC_INFORMATION)))
    {
        return !(memBasic.State == MEM_COMMIT && ProcessAccessHelp::isPageAccessable(memBasic.Protect));
    }
    else
    {
        return true;
    }
}
