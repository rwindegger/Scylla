#include "PluginLoader.h"
#include "Scylla.h"

#include "ProcessAccessHelp.h"
#include "StringConversion.h"
#include <shlwapi.h>

#include "PeParser.h"

const TCHAR PluginLoader::PLUGIN_DIR[] = TEXT("Plugins\\");
const TCHAR PluginLoader::PLUGIN_SEARCH_STRING[] = TEXT("*.dll");
const TCHAR PluginLoader::PLUGIN_IMPREC_DIR[] = TEXT("ImpRec_Plugins\\");
const TCHAR PluginLoader::PLUGIN_IMPREC_WRAPPER_DLL[] = TEXT("Imprec_Wrapper_DLL.dll");

std::vector<Plugin> & PluginLoader::getScyllaPluginList()
{
	return scyllaPluginList;
}

std::vector<Plugin> & PluginLoader::getImprecPluginList()
{
	return imprecPluginList;
}

bool PluginLoader::findAllPlugins()
{

	if (!scyllaPluginList.empty())
	{
		scyllaPluginList.clear();
	}

	if (!imprecPluginList.empty())
	{
		imprecPluginList.clear();
	}

	if (!buildSearchString())
	{
		return false;
	}

	if (!searchForPlugin(scyllaPluginList, dirSearchString, true))
	{
		return false;
	}

#ifndef _WIN64
	if (!buildSearchStringImprecPlugins())
	{
		return false;
	}

	if (!searchForPlugin(imprecPluginList, dirSearchString, false))
	{
		return false;
	}
#endif

	return true;
}

bool PluginLoader::searchForPlugin(std::vector<Plugin> & newPluginList, LPCTSTR searchPath, bool isScyllaPlugin)
{
	WIN32_FIND_DATA ffd;
	HANDLE hFind = 0;
	DWORD dwError = 0;
	Plugin pluginData;

	hFind = FindFirstFile(searchPath, &ffd);

	dwError = GetLastError();

	if (dwError == ERROR_FILE_NOT_FOUND)
	{
		Scylla::debugLog.log(TEXT("findAllPlugins :: No files found"));
		return true;
	}

	if (hFind == INVALID_HANDLE_VALUE)
	{
		Scylla::debugLog.log(TEXT("findAllPlugins :: FindFirstFile failed %d"), dwError);
		return false;
	}

	do
	{
		if ( !(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) )
		{

			if ((ffd.nFileSizeHigh != 0) || (ffd.nFileSizeLow < 200))
			{
				Scylla::debugLog.log(TEXT("findAllPlugins :: Plugin invalid file size: %s"), ffd.cFileName);

			}
			else
			{
				pluginData.fileSize = ffd.nFileSizeLow;
				_tcscpy_s(pluginData.fullpath, baseDirPath);
				_tcscat_s(pluginData.fullpath, ffd.cFileName);

				Scylla::debugLog.log(TEXT("findAllPlugins :: Plugin %s"), pluginData.fullpath);

				if (isValidDllFile(pluginData.fullpath))
				{
					if (isScyllaPlugin)
					{
						if (getScyllaPluginName(&pluginData))
						{
							//add valid plugin
							newPluginList.push_back(pluginData);
						}
						else
						{
							Scylla::debugLog.log(TEXT("Cannot get scylla plugin name %s"), pluginData.fullpath);
						}
					}
					else
					{
						if (isValidImprecPlugin(pluginData.fullpath))
						{
							_tcscpy_s(pluginData.pluginName, ffd.cFileName);
							newPluginList.push_back(pluginData);
						}
					}

				}

			}

		}
	}
	while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();

	FindClose(hFind);

	return (dwError == ERROR_NO_MORE_FILES);
}

bool PluginLoader::getScyllaPluginName(Plugin *pluginData) const
{
	bool retValue = false;
	char * pluginName = 0;
    def_ScyllaPluginName ScyllaPluginName = 0;
    const HMODULE hModule = LoadLibraryEx(pluginData->fullpath, 0, DONT_RESOLVE_DLL_REFERENCES); //do not call DllMain

	if (hModule)
	{
		ScyllaPluginName = (def_ScyllaPluginName)GetProcAddress(hModule, "ScyllaPluginName");

		if (ScyllaPluginName)
		{
			_tcscpy_s(pluginData->pluginName, ScyllaPluginName());

			Scylla::debugLog.log(TEXT("getPluginName :: Plugin name %s"), pluginData->pluginName);
			retValue = true;
		}
		
		FreeLibrary(hModule);

		return retValue;
	}
	else
	{
		Scylla::debugLog.log(TEXT("getPluginName :: LoadLibraryEx failed %s"), pluginData->fullpath);
		return false;
	}
}

bool PluginLoader::buildSearchString()
{
	ZeroMemory(dirSearchString, sizeof(dirSearchString));
	ZeroMemory(baseDirPath, sizeof(baseDirPath));

	if (!GetModuleFileName(NULL, dirSearchString, _countof(dirSearchString)))
	{
		Scylla::debugLog.log(TEXT("buildSearchString :: GetModuleFileName failed %d"), GetLastError());
		return false;
	}

	//wprintf(L"dirSearchString 1 %s\n\n", dirSearchString);
	PathRemoveFileSpec(dirSearchString);
	//wprintf(L"dirSearchString 2 %s\n\n", dirSearchString);
	PathAppend(dirSearchString, PLUGIN_DIR);

	_tcscpy_s(baseDirPath, dirSearchString);
	_tcscat_s(dirSearchString, PLUGIN_SEARCH_STRING);

	//wprintf(L"dirSearchString 3 %s\n\n", dirSearchString);

	Scylla::debugLog.log(TEXT("dirSearchString final %s"), dirSearchString);
	return true;
}

bool PluginLoader::isValidDllFile(LPCTSTR fullpath )
{
	PeParser peFile(fullpath, false);

	return (peFile.isTargetFileSamePeFormat() && peFile.hasExportDirectory());
}

bool PluginLoader::isValidImprecPlugin(LPCTSTR fullpath)
{
	def_Imprec_Trace Imprec_Trace = 0;
	bool retValue = false;

	HMODULE hModule = LoadLibraryEx(fullpath, NULL, DONT_RESOLVE_DLL_REFERENCES); //do not call DllMain

	if (hModule)
	{
		Imprec_Trace = (def_Imprec_Trace)GetProcAddress(hModule, "Trace");
		if (Imprec_Trace)
		{
			retValue = true;
		}
		else
		{
			retValue = false;
		}

		FreeLibrary(hModule);
		return retValue;
	}
	else
	{
		Scylla::debugLog.log(TEXT("isValidImprecPlugin :: LoadLibraryEx failed %s"), fullpath);
		return false;
	}
}

bool PluginLoader::buildSearchStringImprecPlugins()
{
	_tcscpy_s(dirSearchString, baseDirPath);

	_tcscat_s(dirSearchString, PLUGIN_IMPREC_DIR);
    
	_tcscpy_s(baseDirPath, dirSearchString);

	//build imprec wrapper dll path
	_tcscpy_s(imprecWrapperDllPath, dirSearchString);
	_tcscat_s(imprecWrapperDllPath, PLUGIN_IMPREC_WRAPPER_DLL);

	if (!fileExists(imprecWrapperDllPath))
	{
		return false;
	}

	_tcscat_s(dirSearchString, PLUGIN_SEARCH_STRING);

	return true;
}

bool PluginLoader::fileExists(LPCTSTR fileName)
{
	return (GetFileAttributes(fileName) != INVALID_FILE_ATTRIBUTES);
}
