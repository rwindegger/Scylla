#include "Scylla.h"

#include "NativeWinApi.h"
#include "ProcessAccessHelp.h"
#include "FunctionExport.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "Architecture.h"

ConfigurationHolder Scylla::config(TEXT("Scylla.ini"));
PluginLoader Scylla::plugins;

ProcessLister Scylla::processLister;

#ifndef DEBUG_COMMENTS
DummyLogger Scylla::debugLog;
# else
FileLog Scylla::debugLog(DEBUG_LOG_FILENAME);
#endif /* DEBUG_COMMENTS */

const TCHAR Scylla::DEBUG_LOG_FILENAME[] = TEXT("Scylla_debug.log");
Logger* Scylla::Log;

// Internal structure of a SCY_HANDLE
typedef struct SCY_CONTEXT_T_
{
    size_t targetProcId{};
    ApiReader apiReader;
} SCY_CONTEXT_T;

LPCTSTR Scylla::get_version_information()
{
    return APPNAME TEXT(" ") ARCHITECTURE TEXT(" ") APPVERSION;
}

DWORD Scylla::get_version()
{
    return APPVERSIONDWORD;
}

void Scylla::initialize(Logger *log, bool isStandalone)
{
    Log = log;

    if(isStandalone)
    {
        config.loadConfiguration();
        plugins.findAllPlugins();
    }
    else
    {
        ProcessAccessHelp::ownModuleList.clear();
    }

    NativeWinApi::initialize();

    if (isStandalone && config[DEBUG_PRIVILEGE].isTrue())
    {
        ProcessLister::setDebugPrivileges();
    }

    ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
}

bool Scylla::initialize_context(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid)
{
    *phCtxt = NULL;

    auto pPrivScyContext = reinterpret_cast<SCY_CONTEXT_T*>(calloc(1, sizeof(SCY_CONTEXT_T)));
    if (nullptr == pPrivScyContext)
        return FALSE;
    memset(pPrivScyContext, 0, sizeof(SCY_CONTEXT_T));

    // Open target process
    if (!ProcessAccessHelp::openProcessHandle(TargetProcessPid))
    {
        return FALSE;
    }
    pPrivScyContext->apiReader.readApisFromModuleList();

    *phCtxt = reinterpret_cast<SCY_HANDLE>(pPrivScyContext);
    return TRUE;
}

bool Scylla::deinitialize_context(SCY_HANDLE hCtxt)
{
    const auto pPrivScyContext = reinterpret_cast<SCY_CONTEXT_T*>(hCtxt);

    if (!pPrivScyContext)
        return FALSE;

    // Close process handle
    ProcessAccessHelp::closeProcessHandle();
    pPrivScyContext->apiReader.clearAll();

    free(pPrivScyContext);
    return TRUE;
}

int Scylla::iat_search(SCY_HANDLE hScyllaContext, DWORD_PTR* iatStart, size_t* iatSize, DWORD_PTR searchStart,
    int advancedSearch)
{
    //ApiReader apiReader;
    ProcessLister processLister;
    //Process *processPtr = 0;
    IATSearch iatSearch;
    auto pPrivScyContext = reinterpret_cast<SCY_CONTEXT_T*>(hScyllaContext);

    if (!pPrivScyContext)
        return SCY_ERROR_PIDNOTFOUND;

    // Close previous context. FIX ME : use a dedicated structure to store Scylla's context instead of globals
    //ProcessAccessHelp::closeProcessHandle();
    //apiReader.clearAll();

    //if (!ProcessAccessHelp::openProcessHandle(dwProcessId))
    //{
    //	return SCY_ERROR_PROCOPEN;
    //}

    ProcessAccessHelp::getProcessModules(ProcessAccessHelp::hProcess, ProcessAccessHelp::moduleList);
    ProcessAccessHelp::selectedModule = nullptr;


    pPrivScyContext->apiReader.readApisFromModuleList();

    int retVal = SCY_ERROR_IATNOTFOUND;
    if (iatSearch.searchImportAddressTableInProcess(searchStart, iatStart, iatSize, TRUE == advancedSearch))
    {
        retVal = SCY_ERROR_SUCCESS;
    }

    //ProcessAccessHelp::closeProcessHandle();
    //apiReader.clearAll();

    return retVal;
}
