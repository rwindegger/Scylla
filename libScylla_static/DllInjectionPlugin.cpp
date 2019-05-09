#include "DllInjectionPlugin.h"

#include "libscylla.h"
#include "iat_searcher.h"
#include "module_info.h"
#include "api_info.h"

#include "Scylla.h"
#include "StringConversion.h"

LPCTSTR DllInjectionPlugin::FILE_MAPPING_NAME = TEXT("ScyllaPluginExchange");

HANDLE DllInjectionPlugin::hProcess = nullptr;

void DllInjectionPlugin::injectPlugin(Plugin & plugin, std::map<DWORD_PTR, ImportModuleThunk> & moduleList, DWORD_PTR imageBase, DWORD_PTR imageSize)
{
    const DWORD_PTR numberOfUnresolvedImports = getNumberOfUnresolvedImports(moduleList);

    if (numberOfUnresolvedImports == 0)
    {
        context->log(scylla_severity::information, TEXT("No unresolved Imports"));
        return;
    }

    if (!createFileMapping(static_cast<DWORD>(sizeof(SCYLLA_EXCHANGE) + sizeof(UNRESOLVED_IMPORT) + sizeof(UNRESOLVED_IMPORT) *
        numberOfUnresolvedImports)))
    {
        Scylla::debugLog.log(TEXT("injectPlugin :: createFileMapping %X failed"), sizeof(SCYLLA_EXCHANGE) + sizeof(UNRESOLVED_IMPORT) + sizeof(UNRESOLVED_IMPORT) * numberOfUnresolvedImports);
        return;
    }

    auto scyllaExchange = static_cast<PSCYLLA_EXCHANGE>(lpViewOfFile);
    scyllaExchange->status = 0xFF;
    scyllaExchange->imageBase = imageBase;
    scyllaExchange->imageSize = imageSize;
    scyllaExchange->numberOfUnresolvedImports = numberOfUnresolvedImports;
    scyllaExchange->offsetUnresolvedImportsArray = sizeof(SCYLLA_EXCHANGE);

    const auto unresImp = reinterpret_cast<PUNRESOLVED_IMPORT>(reinterpret_cast<DWORD_PTR>(lpViewOfFile) + sizeof(SCYLLA_EXCHANGE));

    addUnresolvedImports(unresImp, moduleList);

    UnmapViewOfFile(lpViewOfFile);
    lpViewOfFile = nullptr;

    const HMODULE hDll = dllInjection(hProcess, plugin.fullpath);
    if (hDll)
    {
        context->log(scylla_severity::information, TEXT("Plugin injection was successful"));
        if (!unloadDllInProcess(hProcess, hDll))
        {
            context->log(scylla_severity::information, TEXT("Plugin unloading failed"));
        }
        lpViewOfFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

        if (lpViewOfFile)
        {
            scyllaExchange = static_cast<PSCYLLA_EXCHANGE>(lpViewOfFile);
            handlePluginResults(scyllaExchange, moduleList);
        }

    }
    else
    {
        context->log(scylla_severity::information, TEXT("Plugin injection failed"));
    }

    closeAllHandles();
}

void DllInjectionPlugin::injectImprecPlugin(Plugin & plugin, std::map<DWORD_PTR, ImportModuleThunk> & moduleList, DWORD_PTR imageBase, DWORD_PTR imageSize)
{
    Plugin newPlugin{};
    const size_t mapSize = (_tcslen(plugin.fullpath) + 1) * sizeof(TCHAR);

    const auto hImprecMap = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_COMMIT, 0, static_cast<DWORD>(mapSize), TEXT(PLUGIN_IMPREC_EXCHANGE_DLL_PATH));

    if (hImprecMap == nullptr)
    {
        Scylla::debugLog.log(TEXT("injectImprecPlugin :: CreateFileMapping failed 0x%X"), GetLastError());
        return;
    }

    const auto lpImprecViewOfFile = MapViewOfFile(hImprecMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (lpImprecViewOfFile == nullptr)
    {
        Scylla::debugLog.log(TEXT("injectImprecPlugin :: MapViewOfFile failed 0x%X"), GetLastError());
        CloseHandle(hImprecMap);
        return;
    }

    CopyMemory(lpImprecViewOfFile, plugin.fullpath, mapSize);

    UnmapViewOfFile(lpImprecViewOfFile);

    newPlugin.fileSize = plugin.fileSize;
    _tcscpy_s(newPlugin.pluginName, plugin.pluginName);
    _tcscpy_s(newPlugin.fullpath, Scylla::plugins.imprecWrapperDllPath);

    injectPlugin(newPlugin, moduleList, imageBase, imageSize);

    CloseHandle(hImprecMap);
}

bool DllInjectionPlugin::createFileMapping(DWORD mappingSize)
{
    hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_COMMIT, 0, mappingSize, FILE_MAPPING_NAME);

    if (hMapFile == nullptr)
    {
        Scylla::debugLog.log(TEXT("createFileMapping :: CreateFileMapping failed 0x%X"), GetLastError());
        return false;
    }

    lpViewOfFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    if (lpViewOfFile == nullptr)
    {
        Scylla::debugLog.log(TEXT("createFileMapping :: MapViewOfFile failed 0x%X"), GetLastError());
        CloseHandle(hMapFile);
        hMapFile = nullptr;
        return false;
    }
    else
    {
        return true;
    }
}

void DllInjectionPlugin::closeAllHandles()
{
    if (lpViewOfFile)
    {
        UnmapViewOfFile(lpViewOfFile);
        lpViewOfFile = nullptr;
    }
    if (hMapFile)
    {
        CloseHandle(hMapFile);
        hMapFile = nullptr;
    }
}

DWORD_PTR DllInjectionPlugin::getNumberOfUnresolvedImports(std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
    DWORD_PTR dwNumber = 0;

    std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1 = moduleList.begin();

    while (iterator1 != moduleList.end())
    {
        ImportModuleThunk * moduleThunk = &(iterator1->second);

        std::map<DWORD_PTR, ImportThunk>::iterator iterator2 = moduleThunk->thunkList.begin();

        while (iterator2 != moduleThunk->thunkList.end())
        {
            ImportThunk * importThunk = &(iterator2->second);

            if (!importThunk->valid)
            {
                dwNumber++;
            }

            iterator2++;
        }

        iterator1++;
    }

    return dwNumber;
}

void DllInjectionPlugin::addUnresolvedImports(PUNRESOLVED_IMPORT firstUnresImp, std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
    std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1 = moduleList.begin();

    while (iterator1 != moduleList.end())
    {
        ImportModuleThunk * moduleThunk = &(iterator1->second);

        std::map<DWORD_PTR, ImportThunk>::iterator iterator2 = moduleThunk->thunkList.begin();

        while (iterator2 != moduleThunk->thunkList.end())
        {
            ImportThunk * importThunk = &(iterator2->second);

            if (!importThunk->valid)
            {
                firstUnresImp->InvalidApiAddress = importThunk->apiAddressVA;
                firstUnresImp->ImportTableAddressPointer = importThunk->va;
                firstUnresImp++;
            }

            iterator2++;
        }

        iterator1++;
    }

    firstUnresImp->InvalidApiAddress = 0;
    firstUnresImp->ImportTableAddressPointer = 0;
}

void DllInjectionPlugin::handlePluginResults(PSCYLLA_EXCHANGE scyllaExchange, std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
    const auto unresImp = reinterpret_cast<PUNRESOLVED_IMPORT>(reinterpret_cast<DWORD_PTR>(scyllaExchange) + scyllaExchange->offsetUnresolvedImportsArray);;

    switch (scyllaExchange->status)
    {
    case SCYLLA_STATUS_SUCCESS:
        context->log(scylla_severity::information, TEXT("Plugin was successful"));
        updateImportsWithPluginResult(unresImp, moduleList);
        break;
    case SCYLLA_STATUS_UNKNOWN_ERROR:
        context->log(scylla_severity::information, TEXT("Plugin reported Unknown Error"));
        break;
    case SCYLLA_STATUS_UNSUPPORTED_PROTECTION:
        context->log(scylla_severity::information, TEXT("Plugin detected unknown protection"));
        updateImportsWithPluginResult(unresImp, moduleList);
        break;
    case SCYLLA_STATUS_IMPORT_RESOLVING_FAILED:
        context->log(scylla_severity::information, TEXT("Plugin import resolving failed"));
        updateImportsWithPluginResult(unresImp, moduleList);
        break;
    case SCYLLA_STATUS_MAPPING_FAILED:
        context->log(scylla_severity::information, TEXT("Plugin file mapping failed"));
        break;
    default:
        context->log(scylla_severity::information, TEXT("Plugin failed without reason"));
    }
}

void DllInjectionPlugin::updateImportsWithPluginResult(PUNRESOLVED_IMPORT firstUnresImp, std::map<DWORD_PTR, ImportModuleThunk> & moduleList)
{
    bool isSuspect;

    std::map<DWORD_PTR, ImportModuleThunk>::iterator iterator1 = moduleList.begin();

    while (iterator1 != moduleList.end())
    {
        ImportModuleThunk * moduleThunk = &(iterator1->second);

        std::map<DWORD_PTR, ImportThunk>::iterator iterator2 = moduleThunk->thunkList.begin();

        while (iterator2 != moduleThunk->thunkList.end())
        {
            ImportThunk * importThunk = &(iterator2->second);

            if (!importThunk->valid)
            {
                if (context->target_api_reader()->is_api_address_valid(firstUnresImp->InvalidApiAddress))
                {
                    auto apiInfo = context->target_api_reader()->get_api_by_virtual_address(firstUnresImp->InvalidApiAddress, &isSuspect);

                    importThunk->suspect = isSuspect;
                    importThunk->valid = true;
                    importThunk->apiAddressVA = firstUnresImp->InvalidApiAddress;
                    importThunk->hint = static_cast<WORD>(apiInfo->hint());
                    importThunk->ordinal = apiInfo->ordinal();
                    _tcscpy_s(importThunk->name, apiInfo->name());
                    StringConversion::ToTStr(apiInfo->module()->filename().c_str(), importThunk->moduleName, _countof(importThunk->moduleName));

                    if (moduleThunk->moduleName[0] == TEXT('?'))
                    {
                        StringConversion::ToTStr(apiInfo->module()->filename().c_str(), moduleThunk->moduleName, _countof(moduleThunk->moduleName));
                    }
                }

                firstUnresImp++;
            }

            iterator2++;
        }

        iterator1++;
    }
}
