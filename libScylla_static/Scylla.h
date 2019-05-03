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

#define CONSOLE_LOG

class Scylla
{
public:
    static void initAsGuiApp();
    static void initAsDll();

    static ConfigurationHolder config;
    static PluginLoader plugins;

    static ProcessLister processLister;
#ifndef CONSOLE_LOG    
    static ListboxLog windowLog;
#else
    static ConsoleLogger windowLog;
#endif

#ifndef DEBUG_COMMENTS
    static DummyLogger debugLog;
# else
    static FileLog debugLog(DEBUG_LOG_FILENAME);
#endif /* DEBUG_COMMENTS */

private:

    static const WCHAR DEBUG_LOG_FILENAME[];
};
