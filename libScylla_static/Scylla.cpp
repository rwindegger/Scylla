#include "Scylla.h"
#include "configuration_holder.h"
#include "configuration.h"

configuration_holder Scylla::config(TEXT("Scylla.ini"));
PluginLoader Scylla::plugins;

ProcessLister Scylla::processLister;

#ifndef DEBUG_COMMENTS
DummyLogger Scylla::debugLog;
# else
FileLog Scylla::debugLog(DEBUG_LOG_FILENAME);
#endif /* DEBUG_COMMENTS */

const TCHAR Scylla::DEBUG_LOG_FILENAME[] = TEXT("Scylla_debug.log");
Logger* Scylla::Log;


void Scylla::initialize(Logger *log, bool isStandalone)
{
    Log = log;

    if (isStandalone)
    {
        config.loadConfiguration();
        plugins.findAllPlugins();
    }

    if (isStandalone && config[config_option::DEBUG_PRIVILEGE].isTrue())
    {
        ProcessLister::setDebugPrivileges();
    }
}
