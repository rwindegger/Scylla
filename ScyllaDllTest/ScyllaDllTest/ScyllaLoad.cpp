#include "ScyllaLoad.h"


#if _WIN64
#define DecorateSymbolName(s)   s
#else
#define DecorateSymbolName(s)   s
//#define DecorateSymbolName(s)   "_" ## s
#endif

bool ScyllaLoadDll(TCHAR *ScyllaDllPath, SCYLLA_DLL *pScyllaDllObject)
{
	HMODULE hScylla;
	bool bScyllaProcAddressSuccessful;

	memset(pScyllaDllObject, 0, sizeof(SCYLLA_DLL));
	
	// Loading Test
	hScylla = LoadLibrary(ScyllaDllPath);
	if (!hScylla)
		return false;

	pScyllaDllObject->hScyllaDll = hScylla;

	bScyllaProcAddressSuccessful = true;
	pScyllaDllObject->VersionInformationW = (def_ScyllaVersionInformationW) GetProcAddress(hScylla, DecorateSymbolName("ScyllaVersionInformationW"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->VersionInformationW != NULL);
	
	pScyllaDllObject->VersionInformationA = (def_ScyllaVersionInformationA) GetProcAddress(hScylla, DecorateSymbolName("ScyllaVersionInformationA"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->VersionInformationA != NULL);

	pScyllaDllObject->VersionInformationDword = (def_ScyllaVersionInformationDword) GetProcAddress(hScylla, DecorateSymbolName("ScyllaVersionInformationDword"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->VersionInformationDword != NULL);

	pScyllaDllObject->ScyllaIatSearch = (def_ScyllaIatSearch) GetProcAddress(hScylla, DecorateSymbolName("ScyllaIatSearch"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaIatSearch != NULL);

	pScyllaDllObject->ScyllaStartGui = (def_ScyllaStartGui) GetProcAddress(hScylla, DecorateSymbolName("ScyllaStartGui"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaStartGui != NULL);

	pScyllaDllObject->ScyllaInitContext = (def_ScyllaInitContext)GetProcAddress(hScylla, DecorateSymbolName("ScyllaInitContext"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaInitContext != NULL);

	pScyllaDllObject->ScyllaUnInitContext = (def_ScyllaUnInitContext)GetProcAddress(hScylla, DecorateSymbolName("ScyllaUnInitContext"));
	bScyllaProcAddressSuccessful &= (pScyllaDllObject->ScyllaUnInitContext != NULL);

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