#include "Scylla.h"

#include "NativeWinApi.h"
#include "ProcessAccessHelp.h"

ConfigurationHolder Scylla::config(L"Scylla.ini");
PluginLoader Scylla::plugins;

ProcessLister Scylla::processLister;


#ifndef DEBUG_COMMENTS
	DummyLogger Scylla::debugLog;
# else
	FileLog Scylla::debugLog(DEBUG_LOG_FILENAME);
#endif /* DEBUG_COMMENTS */
const WCHAR Scylla::DEBUG_LOG_FILENAME[] = L"Scylla_debug.log";
ListboxLog Scylla::windowLog;




void Scylla::initAsGuiApp()
{
	config.loadConfiguration();
	plugins.findAllPlugins();

	NativeWinApi::initialize();

	if(config[DEBUG_PRIVILEGE].isTrue())
	{
		processLister.setDebugPrivileges();
	}

	ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
}

void Scylla::initAsDll()
{
	ProcessAccessHelp::ownModuleList.clear();

	NativeWinApi::initialize();
	ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);
}