#include "ScyllaLoad.h"


#if _WIN64
#define DecorateSymbolName(s)   s
#else
#define DecorateSymbolName(s)   s
//#define DecorateSymbolName(s)   "_" ## s
#endif

bool ScyllaLoadDll(LPCTSTR ScyllaDllPath, SCYLLA_DLL *pScyllaDllObject)
{
    memset(pScyllaDllObject, 0, sizeof(SCYLLA_DLL));

    // Loading Test
    const HMODULE hScylla = LoadLibrary(ScyllaDllPath);
    if (!hScylla)
        return false;

    pScyllaDllObject->hScyllaDll = hScylla;

    bool bScyllaProcAddressSuccessful = true;
    pScyllaDllObject->VersionInformationW = reinterpret_cast<def_ScyllaVersionInformationW>(GetProcAddress(
        hScylla, DecorateSymbolName("ScyllaVersionInformationW")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->VersionInformationW != nullptr);

    pScyllaDllObject->VersionInformationA = reinterpret_cast<def_ScyllaVersionInformationA>(GetProcAddress(
        hScylla, DecorateSymbolName("ScyllaVersionInformationA")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->VersionInformationA != nullptr);

    pScyllaDllObject->VersionInformationDword = reinterpret_cast<def_ScyllaVersionInformationDword>(GetProcAddress(
        hScylla, DecorateSymbolName("ScyllaVersionInformationDword")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->VersionInformationDword != nullptr);

    pScyllaDllObject->ScyllaIatSearch = reinterpret_cast<def_ScyllaIatSearch>(GetProcAddress(hScylla, DecorateSymbolName("ScyllaIatSearch")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaIatSearch != nullptr);

    pScyllaDllObject->ScyllaStartGui = reinterpret_cast<def_ScyllaStartGui>(GetProcAddress(hScylla, DecorateSymbolName("ScyllaStartGui")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaStartGui != nullptr);

    pScyllaDllObject->ScyllaInitContext = reinterpret_cast<def_ScyllaInitContext>(GetProcAddress(hScylla, DecorateSymbolName("ScyllaInitContext")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaInitContext != nullptr);

    pScyllaDllObject->ScyllaUnInitContext = reinterpret_cast<def_ScyllaUnInitContext>(GetProcAddress(hScylla, DecorateSymbolName("ScyllaUnInitContext")));
    bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaUnInitContext != nullptr);

    // Test if every GetProcAddress was successful
    if (!bScyllaProcAddressSuccessful)
    {
        ScyllaUnloadDll(pScyllaDllObject);
        return false;
    }

    return true;
}

void ScyllaUnloadDll(SCYLLA_DLL *pScyllaDllObject)
{
    FreeLibrary(pScyllaDllObject->hScyllaDll);
    memset(pScyllaDllObject, 0, sizeof(SCYLLA_DLL));
}