#pragma once

#include "ConfigurationHolder.h"
#include "PluginLoader.h"
#include "ProcessLister.h"
#include "Logger.h"

#define APPNAME_S "Scylla"
#define APPVERSION_S "v0.10.0"
#define APPVERSIONDWORD 0x00010000

#define DONATE_BTC_ADDRESS "1C6NN81V9pA6jq9r2HYBZkbrXPTTc7qTXq"

#define APPNAME TEXT(APPNAME_S)
#define APPVERSION TEXT(APPVERSION_S)

/* Scylla current context. */
typedef size_t SCY_HANDLE, *PSCY_HANDLE;

class Scylla
{
public:
    static const wchar_t* get_version_w();
    static const char* get_version_a();
    static const DWORD get_version();
    static void initialize(Logger *log, bool isStandalone);
    static bool initialize_context(PSCY_HANDLE phCtxt, DWORD_PTR TargetProcessPid);
    static bool deinitialize_context(SCY_HANDLE hCtxt);
    static int iat_search(SCY_HANDLE hScyllaContext, DWORD_PTR * iatStart, DWORD * iatSize, DWORD_PTR searchStart, BOOL advancedSearch);
    
    static ConfigurationHolder config;
    static PluginLoader plugins;

    static ProcessLister processLister;

    static Logger *Log;

#ifndef DEBUG_COMMENTS
    static DummyLogger debugLog;
# else
    static FileLog debugLog(DEBUG_LOG_FILENAME);
#endif /* DEBUG_COMMENTS */

private:

    static const WCHAR DEBUG_LOG_FILENAME[];
};
