#pragma once

#include <windows.h>
#include <vector>

class Plugin {
public:
    DWORD fileSize;
    TCHAR fullpath[MAX_PATH];
    TCHAR pluginName[MAX_PATH];
};

typedef LPCTSTR(__cdecl * def_ScyllaPluginName)();

typedef DWORD(*def_Imprec_Trace)(DWORD hFileMap, DWORD dwSizeMap, DWORD dwTimeOut, DWORD dwToTrace, DWORD dwExactCall);

class PluginLoader {
public:
    TCHAR imprecWrapperDllPath[MAX_PATH];

    bool findAllPlugins();

    std::vector<Plugin> & getScyllaPluginList();
    std::vector<Plugin> & getImprecPluginList();

private:

    static const TCHAR PLUGIN_DIR[];
    static const TCHAR PLUGIN_SEARCH_STRING[];
    static const TCHAR PLUGIN_IMPREC_DIR[];
    static const TCHAR PLUGIN_IMPREC_WRAPPER_DLL[];

    std::vector<Plugin> scyllaPluginList;
    std::vector<Plugin> imprecPluginList;

    TCHAR dirSearchString[MAX_PATH]{};
    TCHAR baseDirPath[MAX_PATH]{};

    bool buildSearchString();
    bool buildSearchStringImprecPlugins();

    bool getScyllaPluginName(Plugin * pluginData) const;
    bool searchForPlugin(std::vector<Plugin> & newPluginList, LPCTSTR searchPath, bool isScyllaPlugin);

    static bool fileExists(LPCTSTR fileName);
    static bool isValidDllFile(LPCTSTR fullpath);
    static bool isValidImprecPlugin(LPCTSTR fullpath);
};
