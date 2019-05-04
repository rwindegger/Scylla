#include "Scylla.h"

#include "NativeWinApi.h"
#include "ProcessAccessHelp.h"
#include "FunctionExport.h"
#include "ApiReader.h"
#include "IATSearch.h"
#include "Architecture.h"

ConfigurationHolder Scylla::config(L"Scylla.ini");
PluginLoader Scylla::plugins;

ProcessLister Scylla::processLister;

#ifndef DEBUG_COMMENTS
DummyLogger Scylla::debugLog;
# else
FileLog Scylla::debugLog(DEBUG_LOG_FILENAME);
#endif /* DEBUG_COMMENTS */

const WCHAR Scylla::DEBUG_LOG_FILENAME[] = L"Scylla_debug.log";
Logger* Scylla::Log;

// Internal structure of a SCY_HANDLE
typedef struct SCY_CONTEXT_T_
{
    size_t targetProcId;
    ApiReader apiReader;
} SCY_CONTEXT_T;

const wchar_t* Scylla::get_version_w()
{
    return APPNAME L" " ARCHITECTURE L" " APPVERSION;
}

const char* Scylla::get_version_a()
{
    return APPNAME_S " " ARCHITECTURE_S " " APPVERSION_S;
}

const DWORD Scylla::get_version()
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
        processLister.setDebugPrivileges();
    }

    ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
}

bool Scylla::initialize_context(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid)
{
    SCY_CONTEXT_T* pPrivScyContext = NULL;

    *phCtxt = NULL;

    pPrivScyContext = (SCY_CONTEXT_T*)calloc(1, sizeof(SCY_CONTEXT_T));
    if (NULL == pPrivScyContext)
        return FALSE;
    memset(pPrivScyContext, 0, sizeof(SCY_CONTEXT_T));

    // Open target process
    if (!ProcessAccessHelp::openProcessHandle(TargetProcessPid))
    {
        return FALSE;
    }
    pPrivScyContext->apiReader.readApisFromModuleList();

    *phCtxt = (SCY_HANDLE)pPrivScyContext;
    return TRUE;
}

bool Scylla::deinitialize_context(SCY_HANDLE hCtxt)
{
    SCY_CONTEXT_T* pPrivScyContext = (SCY_CONTEXT_T*)hCtxt;

    if (!pPrivScyContext)
        return FALSE;

    // Close process handle
    ProcessAccessHelp::closeProcessHandle();
    pPrivScyContext->apiReader.clearAll();

    free(pPrivScyContext);
    return TRUE;
}

int Scylla::iat_search(SCY_HANDLE hScyllaContext, DWORD_PTR* iatStart, DWORD* iatSize, DWORD_PTR searchStart,
    int advancedSearch)
{
    //ApiReader apiReader;
    ProcessLister processLister;
    //Process *processPtr = 0;
    IATSearch iatSearch;
    SCY_CONTEXT_T* pPrivScyContext = (SCY_CONTEXT_T*)hScyllaContext;

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
    ProcessAccessHelp::selectedModule = 0;


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
