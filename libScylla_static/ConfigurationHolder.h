#pragma once

#include <windows.h>
#include <map>
#include "Configuration.h"

enum ConfigOption
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

class ConfigurationHolder
{
public:

	ConfigurationHolder(LPCTSTR fileName);

	bool loadConfiguration();
	bool saveConfiguration() const;

	Configuration& operator[](ConfigOption option);
	const Configuration& operator[](ConfigOption option) const;

private:

	static const TCHAR CONFIG_FILE_SECTION_NAME[];

	TCHAR configPath[MAX_PATH]{};
	std::map<ConfigOption, Configuration> config;

	bool buildConfigFilePath(LPCTSTR fileName);

	bool readStringFromConfigFile(Configuration & configObject) const;
	bool readBooleanFromConfigFile(Configuration & configObject) const;
	bool readNumericFromConfigFile(Configuration & configObject, int nBase) const;

	bool saveStringToConfigFile(const Configuration & configObject) const;
	bool saveBooleanToConfigFile(const Configuration & configObject) const;
	bool saveNumericToConfigFile(const Configuration & configObject, int nBase) const;

	bool loadConfig(Configuration & configObject) const;
	bool saveConfig(const Configuration & configObject) const;
};
