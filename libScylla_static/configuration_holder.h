#pragma once
#include "scylla_types.h"

#include <windows.h>
#include <map>

enum class config_option
{
	USE_PE_HEADER_FROM_DISK,
	DEBUG_PRIVILEGE,
	CREATE_BACKUP,
	DLL_INJECTION_AUTO_UNLOAD,
	IAT_SECTION_NAME,
	UPDATE_HEADER_CHECKSUM,
	REMOVE_DOS_HEADER_STUB,
	IAT_FIX_AND_OEP_FIX,
	SUSPEND_PROCESS_FOR_DUMPING,
	OriginalFirstThunk_SUPPORT,
	USE_ADVANCED_IAT_SEARCH,
	SCAN_DIRECT_IMPORTS,
	FIX_DIRECT_IMPORTS_NORMAL,
	FIX_DIRECT_IMPORTS_UNIVERSAL,
	CREATE_NEW_IAT_IN_SECTION,
    DONT_CREATE_NEW_SECTION,
    APIS_ALWAYS_FROM_DISK
};

class configuration_holder
{
public:

	configuration_holder(LPCTSTR fileName);

	bool loadConfiguration();
	bool saveConfiguration() const;

	configuration& operator[](config_option option);
	const configuration& operator[](config_option option) const;

private:

	static const TCHAR CONFIG_FILE_SECTION_NAME[];

	TCHAR configPath[MAX_PATH]{};
	std::map<config_option, configuration> config;

	bool buildConfigFilePath(LPCTSTR fileName);

	bool readStringFromConfigFile(configuration & configObject) const;
	bool readBooleanFromConfigFile(configuration & configObject) const;
	bool readNumericFromConfigFile(configuration & configObject, int nBase) const;

	bool saveStringToConfigFile(const configuration & configObject) const;
	bool saveBooleanToConfigFile(const configuration & configObject) const;
	bool saveNumericToConfigFile(const configuration & configObject, int nBase) const;

	bool loadConfig(configuration & configObject) const;
	bool saveConfig(const configuration & configObject) const;
};
